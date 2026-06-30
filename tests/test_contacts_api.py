import re

from fastapi.testclient import TestClient

from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore


def make_client() -> TestClient:
    return TestClient(create_app(SesameStore(), enable_demo_ui=True))


def demo_register(client: TestClient, username: str) -> dict:
    response = client.post("/ui/register", json={"username": username})
    assert response.status_code == 200, response.text
    return response.json()


def test_ui_static_assets_served() -> None:
    client = TestClient(create_app(SesameStore()))

    for path in ("/ui", "/ui/styles.css", "/ui/app.js", "/ui/logo.svg"):
        response = client.get(path)

        assert response.status_code == 200


def test_ui_mentions_brand_and_responsive_breakpoints() -> None:
    client = TestClient(create_app(SesameStore()))

    html = client.get("/ui").text
    css = client.get("/ui/styles.css").text
    js = client.get("/ui/app.js").text
    logo = client.get("/ui/logo.svg").text

    assert "BraidLink" in html
    assert "@media (max-width: 1023px)" in css
    assert "@media (max-width: 719px)" in css
    assert 'viewBox="0 0 64 64"' in logo
    assert "BRAID_ENABLE_DEMO_UI=1" in f"{html}\n{js}"
    assert "Registration is unavailable" in f"{html}\n{js}"
    assert "Chat" in html
    assert "Requests" in html


def test_ui_html_exposes_required_js_targets_and_demo_notice() -> None:
    client = TestClient(create_app(SesameStore()))

    html = client.get("/ui").text
    js = client.get("/ui/app.js").text

    selector_ids = set(re.findall(r'document\.querySelector\("#([^"]+)"\)', js))
    assert selector_ids
    for element_id in selector_ids:
        assert f'id="{element_id}"' in html

    assert "BRAID_ENABLE_DEMO_UI=1" in html


def test_ui_static_js_avoids_unsafe_dom_sinks() -> None:
    client = TestClient(create_app(SesameStore()))

    js = client.get("/ui/app.js").text

    for unsafe_sink in ("innerHTML", "insertAdjacentHTML", "outerHTML", "document.write"):
        assert unsafe_sink not in js


def test_ui_static_js_handles_lookup_races_auth_and_contact_accessibility() -> None:
    client = TestClient(create_app(SesameStore()))

    js = client.get("/ui/app.js").text

    assert "function isCurrentLookup(requestId)" in js
    assert js.count("isCurrentLookup(requestId)") >= 5
    assert "setBusy(els.searchForm, true)" in js
    assert js.count("response.status === 401") >= 3
    assert "aria-pressed" in js
    assert "aria-label" in js
    assert "loadContactRequests" in js
    assert "acceptContactRequest" in js
    assert "denyContactRequest" in js
    assert "showView(\"chat\")" in js


def test_ui_html_exposes_chat_and_request_targets() -> None:
    client = TestClient(create_app(SesameStore()))

    html = client.get("/ui").text

    for element_id in (
        "nav-chat",
        "chat-panel",
        "request-list",
        "request-count",
        "chat-thread",
        "chat-contact-list",
        "chat-composer",
        "chat-send-button",
    ):
        assert f'id="{element_id}"' in html


def test_demo_register_disabled_by_default() -> None:
    store = SesameStore()
    client = TestClient(create_app(store))

    valid_response = client.post("/ui/register", json={"username": "Alice.42"})
    empty_body_response = client.post("/ui/register", json={})

    assert valid_response.status_code == 404
    assert empty_body_response.status_code == 404
    assert "/ui/register" not in client.get("/openapi.json").json()["paths"]
    assert store.find_device_by_username("Alice.42") is None


def test_demo_register_enabled_app_exposes_route() -> None:
    client = make_client()

    assert "/ui/register" in client.get("/openapi.json").json()["paths"]


def test_demo_register_enforces_case_insensitive_username_hash() -> None:
    client = make_client()

    response = client.post("/ui/register", json={"username": "Alice.42"})

    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "Alice.42"
    assert body["device_id"] == 1
    assert body["auth_token"]

    duplicate = client.post("/ui/register", json={"username": "alice.42"})

    assert duplicate.status_code == 409


def test_demo_register_rejects_invalid_signal_username() -> None:
    client = make_client()

    response = client.post("/ui/register", json={"username": "Ali"})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "missing_separator"


def test_demo_register_empty_username_uses_stable_validation_detail() -> None:
    client = make_client()

    response = client.post("/ui/register", json={"username": ""})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "missing_separator"


def test_exact_username_lookup_no_prefix_directory() -> None:
    client = make_client()
    demo_register(client, "Alice.42")

    response = client.get("/users/by-username/Alice.42")

    assert response.status_code == 200
    body = response.json()
    assert body["username_display"] == "Alice.42"
    assert body["device_id"] == 1

    lowercase = client.get("/users/by-username/alice.42")

    assert lowercase.status_code == 200
    assert lowercase.json()["username_display"] == "Alice.42"

    invalid = client.get("/users/by-username/Ali")

    assert invalid.status_code == 422

    missing = client.get("/users/by-username/Bob.42")

    assert missing.status_code == 404


def test_contact_request_accepts_before_contact_book_entry() -> None:
    client = make_client()
    alice = demo_register(client, "Alice.42")
    bob = demo_register(client, "Bob.1042")
    alice_headers = {"Authorization": f"Bearer {alice['auth_token']}"}
    bob_headers = {"Authorization": f"Bearer {bob['auth_token']}"}

    response = client.post(
        "/contacts",
        json={
            "username": "Bob.1042",
            "device_id": bob["device_id"],
            "alias": "Bob",
        },
        headers=alice_headers,
    )

    assert response.status_code == 200
    request = response.json()
    assert request["status"] == "pending"
    assert request["direction"] == "outbound"
    assert request["requester_username"] == "Alice.42"
    assert request["recipient_username"] == "Bob.1042"
    assert request["peer_username_display"] == "Bob.1042"
    assert request["alias"] == "Bob"

    assert client.get("/contacts", headers=alice_headers).json() == []
    assert client.get("/contacts", headers=bob_headers).json() == []

    alice_requests = client.get("/contact-requests", headers=alice_headers)
    bob_requests = client.get("/contact-requests", headers=bob_headers)

    assert alice_requests.status_code == 200
    assert bob_requests.status_code == 200
    assert alice_requests.json()["outbound"] == [request]
    assert alice_requests.json()["inbound"] == []
    assert bob_requests.json()["inbound"][0]["request_id"] == request["request_id"]
    assert bob_requests.json()["inbound"][0]["direction"] == "inbound"
    assert bob_requests.json()["outbound"] == []

    accepted = client.post(
        f"/contact-requests/{request['request_id']}/accept",
        headers=bob_headers,
    )

    assert accepted.status_code == 200
    assert accepted.json()["status"] == "accepted"

    alice_contacts_response = client.get("/contacts", headers=alice_headers)
    bob_contacts_response = client.get("/contacts", headers=bob_headers)

    assert alice_contacts_response.status_code == 200
    assert bob_contacts_response.status_code == 200
    alice_contacts = alice_contacts_response.json()
    bob_contacts = bob_contacts_response.json()
    assert [contact["contact_id"] for contact in alice_contacts] == ["Bob.1042:1"]
    assert alice_contacts[0]["alias"] == "Bob"
    assert [contact["contact_id"] for contact in bob_contacts] == ["Alice.42:1"]
    assert bob_contacts[0]["alias"] is None
    assert client.get("/contact-requests", headers=alice_headers).json() == {
        "inbound": [],
        "outbound": [],
    }

    duplicate = client.post(
        "/contacts",
        json={
            "username": "Bob.1042",
            "device_id": bob["device_id"],
            "alias": "Bob",
        },
        headers=alice_headers,
    )

    assert duplicate.status_code == 409

    delete = client.delete(f"/contacts/{alice_contacts[0]['contact_id']}", headers=alice_headers)

    assert delete.status_code == 200
    assert delete.json() == {"status": "deleted"}
    assert client.get("/contacts", headers=alice_headers).json() == []


def test_contact_request_deny_closes_without_contacts() -> None:
    client = make_client()
    alice = demo_register(client, "Alice.42")
    bob = demo_register(client, "Bob.1042")
    alice_headers = {"Authorization": f"Bearer {alice['auth_token']}"}
    bob_headers = {"Authorization": f"Bearer {bob['auth_token']}"}

    created = client.post(
        "/contacts",
        json={"username": "Bob.1042", "device_id": bob["device_id"]},
        headers=alice_headers,
    )
    request = created.json()

    denied = client.post(
        f"/contact-requests/{request['request_id']}/deny",
        headers=bob_headers,
    )

    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    assert client.get("/contact-requests", headers=alice_headers).json() == {
        "inbound": [],
        "outbound": [],
    }
    assert client.get("/contact-requests", headers=bob_headers).json() == {
        "inbound": [],
        "outbound": [],
    }
    assert client.get("/contacts", headers=alice_headers).json() == []
    assert client.get("/contacts", headers=bob_headers).json() == []


def test_contact_request_recipient_only_accept_or_deny() -> None:
    client = make_client()
    alice = demo_register(client, "Alice.42")
    bob = demo_register(client, "Bob.1042")
    alice_headers = {"Authorization": f"Bearer {alice['auth_token']}"}
    bob_headers = {"Authorization": f"Bearer {bob['auth_token']}"}

    created = client.post(
        "/contacts",
        json={"username": "Bob.1042", "device_id": bob["device_id"]},
        headers=alice_headers,
    )
    request_id = created.json()["request_id"]

    accept_as_sender = client.post(
        f"/contact-requests/{request_id}/accept",
        headers=alice_headers,
    )
    deny_as_sender = client.post(
        f"/contact-requests/{request_id}/deny",
        headers=alice_headers,
    )

    assert accept_as_sender.status_code == 403
    assert deny_as_sender.status_code == 403
    assert client.post(
        f"/contact-requests/{request_id}/accept",
        headers=bob_headers,
    ).status_code == 200


def test_contact_add_rejects_device_not_owned_by_exact_username() -> None:
    store = SesameStore()
    client = TestClient(create_app(store, enable_demo_ui=True))
    alice = demo_register(client, "Alice.42")
    bob = demo_register(client, "Bob.1042")
    other_device_1 = store.register_device(
        username="Carol.77",
        registration_id=1,
        bundle={},
        identity_key=b"carol-key",
    )
    other_device_2 = store.register_device(
        username="Carol.77",
        registration_id=2,
        bundle={},
        identity_key=b"carol-key",
    )
    assert bob["device_id"] == 1
    assert other_device_1.device_id == 1
    assert other_device_2.device_id == 2
    headers = {"Authorization": f"Bearer {alice['auth_token']}"}

    response = client.post(
        "/contacts",
        json={
            "username": "Bob.1042",
            "device_id": other_device_2.device_id,
        },
        headers=headers,
    )

    assert response.status_code == 404
    assert client.get("/contacts", headers=headers).json() == []


def test_contact_empty_username_uses_stable_validation_detail() -> None:
    client = make_client()
    alice = demo_register(client, "Alice.42")
    headers = {"Authorization": f"Bearer {alice['auth_token']}"}

    response = client.post(
        "/contacts",
        json={"username": "", "device_id": 1},
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "missing_separator"


def test_contact_write_auth_required() -> None:
    client = make_client()

    post_response = client.post(
        "/contacts",
        json={"username": "Bob.1042", "device_id": 1},
    )
    delete_response = client.delete("/contacts/Bob.1042:1")
    requests_response = client.get("/contact-requests")
    accept_response = client.post("/contact-requests/req-1/accept")
    deny_response = client.post("/contact-requests/req-1/deny")

    assert post_response.status_code == 401
    assert delete_response.status_code == 401
    assert requests_response.status_code == 401
    assert accept_response.status_code == 401
    assert deny_response.status_code == 401


def test_contact_auth_required() -> None:
    client = make_client()

    response = client.get("/contacts")

    assert response.status_code == 401
