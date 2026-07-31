"""Regression tests for the server-layer findings of the 2026-07-31 chat-protocol audit.

Covered: H1 (OPK depletion), M11 (X-Forwarded-Proto), M12 (registration abuse),
M13 (relay flooding), M14 (circuit relay), L9 (WS bearer transport),
L10 (envelope id collisions), L11 (error-string leakage).

Every test asserts the *attack is rejected*; each one fails against the
pre-fix code.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from ml_kem_braid.client.client import BraidChatClient, HttpTransport
from ml_kem_braid.pqxdh import create_identity, create_prekey_bundle
from ml_kem_braid.server.app import ServerLimits, create_app
from ml_kem_braid.server.decentralized_routes import (
    _CircuitFrameStore,
    build_decentralized_router,
)
from ml_kem_braid.decentralized.services import DecentralizedServices
from ml_kem_braid.sesame.store import SesameStore
from ml_kem_braid.wire import b64e, bundle_to_dict, registration_challenge


def _register(app, name: str, num_one_time: int = 4) -> BraidChatClient:
    client = BraidChatClient(HttpTransport(TestClient(app)), name)
    client.register(num_one_time=num_one_time)
    return client


def _raw_register_payload(username: str, registration_id: int = 1) -> dict:
    identity = create_identity()
    bundle, _ = create_prekey_bundle(identity, num_one_time=0)
    proof = identity.sign_registration_challenge(
        registration_challenge(username, registration_id)
    )
    return {
        "username": username,
        "registration_id": registration_id,
        "bundle": bundle_to_dict(bundle),
        "proof_sig": b64e(proof),
        "one_time_prekeys": {},
    }


# -- H1: unauthenticated one-time-prekey depletion ---------------------------


def test_anonymous_caller_cannot_drain_the_one_time_prekey_pool():
    """An anonymous drain loop must never take the pool to zero (audit H1)."""
    store = SesameStore()
    app = create_app(store)
    bob = _register(app, "bob", num_one_time=4)
    client = TestClient(app)

    saw_bundle_without_opk = False
    for _ in range(30):
        r = client.get(f"/keys/bob/{bob.device_id}")
        assert r.status_code == 200
        bundle = r.json()["bundle"]
        # A bundle is always served — the PQ (ML-KEM) leg is unaffected.
        assert bundle["pqspk_pub"]
        if bundle["opk_id"] is None:
            saw_bundle_without_opk = True

    remaining = store.get_device("bob", bob.device_id).one_time_prekeys
    assert saw_bundle_without_opk
    assert len(remaining) >= 1, "anonymous callers drained the whole OPK pool"
    # Depletion must be observable.
    assert app.state.opk_depletion_events[("bob", bob.device_id)] > 0


def test_authenticated_caller_may_still_consume_one_time_prekeys():
    """Real peers still get OPKs — but never the reserved floor (audit H1/D1)."""
    store = SesameStore()
    app = create_app(store)
    bob = _register(app, "bob", num_one_time=5)
    alice = _register(app, "alice", num_one_time=1)
    client = TestClient(app)

    headers = {"Authorization": f"Bearer {alice.auth_token}"}
    ids = []
    for _ in range(4):
        r = client.get(f"/keys/bob/{bob.device_id}", headers=headers)
        assert r.status_code == 200
        ids.append(r.json()["bundle"]["opk_id"])
    assert None not in ids
    assert len(set(ids)) == 4

    # The floor is NOT a function of "has a token": the reserved prekey is
    # withheld from authenticated callers too.
    last = client.get(f"/keys/bob/{bob.device_id}", headers=headers)
    assert last.status_code == 200
    assert last.json()["bundle"]["opk_id"] is None
    assert len(store.get_device("bob", bob.device_id).one_time_prekeys) == 1


def test_registered_attacker_cannot_drain_the_victim_one_time_prekey_pool():
    """D1: a token minted for free from ``POST /register`` must not bypass the floor.

    ``/register`` is unauthenticated, so "authenticated" is an identity anyone
    can mint at zero cost.  Gating the OPK floor on it made the floor
    decorative.  The floor is now derived from the pool size itself — state the
    attacker can only shrink, never forge or evict.
    """
    store = SesameStore()
    app = create_app(store)
    bob = _register(app, "bob", num_one_time=4)
    client = TestClient(app)

    # The attack: mint an identity for free, then drain with it.
    attacker = client.post("/register", json=_raw_register_payload("mallory.99"))
    assert attacker.status_code == 200
    headers = {"Authorization": f"Bearer {attacker.json()['auth_token']}"}

    saw_bundle_without_opk = False
    for _ in range(30):
        r = client.get(f"/keys/bob/{bob.device_id}", headers=headers)
        assert r.status_code == 200
        bundle = r.json()["bundle"]
        assert bundle["pqspk_pub"]  # PQ leg always served
        if bundle["opk_id"] is None:
            saw_bundle_without_opk = True

    remaining = store.get_device("bob", bob.device_id).one_time_prekeys
    assert saw_bundle_without_opk
    assert len(remaining) >= 1, "a free token drained the whole OPK pool"
    assert app.state.opk_depletion_events[("bob", bob.device_id)] > 0


def test_many_free_accounts_still_cannot_drain_the_pool():
    """Minting a fresh identity per fetch must not reset the floor either."""
    store = SesameStore()
    app = create_app(store)
    bob = _register(app, "bob", num_one_time=4)
    client = TestClient(app)

    for i in range(10):
        reg = client.post("/register", json=_raw_register_payload(f"mallory.{i:02d}"))
        assert reg.status_code == 200
        headers = {"Authorization": f"Bearer {reg.json()['auth_token']}"}
        assert client.get(f"/keys/bob/{bob.device_id}", headers=headers).status_code == 200

    assert len(store.get_device("bob", bob.device_id).one_time_prekeys) >= 1


def test_concurrent_fetches_cannot_race_past_the_floor():
    """The floor is check-then-act; racing fetches must not drain below it."""
    from concurrent.futures import ThreadPoolExecutor

    class _SlowStore(SesameStore):
        """Widens the check-then-act window and reports any overlap."""

        def __init__(self) -> None:
            super().__init__()
            self.inside = 0
            self.overlapped = False

        def take_prekey_bundle(self, username, device_id):
            self.inside += 1
            if self.inside > 1:
                self.overlapped = True
            time.sleep(0.05)
            try:
                return super().take_prekey_bundle(username, device_id)
            finally:
                self.inside -= 1

    store = _SlowStore()
    app = create_app(store)
    bob = _register(app, "bob", num_one_time=2)  # floor 1 → exactly one to give
    path = f"/keys/bob/{bob.device_id}"

    def fetch() -> dict:
        return TestClient(app).get(path).json()["bundle"]

    with ThreadPoolExecutor(max_workers=4) as pool:
        bundles = [f.result() for f in [pool.submit(fetch) for _ in range(4)]]

    assert store.overlapped is False, "floor check and consumption were not atomic"
    served = [b["opk_id"] for b in bundles if b["opk_id"] is not None]
    assert len(served) == 1
    assert len(store.get_device("bob", bob.device_id).one_time_prekeys) == 1


def test_prekey_bundle_endpoint_is_rate_limited():
    """A per-source-IP token bucket caps the drain loop (audit H1)."""
    app = create_app(SesameStore(), limits=ServerLimits(prekey_bundle_rate=(3, 0.0)))
    bob = _register(app, "bob")
    client = TestClient(app)

    codes = [client.get(f"/keys/bob/{bob.device_id}").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429]


# -- M11: X-Forwarded-Proto trust -------------------------------------------


def test_forwarded_proto_is_ignored_from_untrusted_peer():
    """A cleartext client must not defeat the 426 gate with a header."""
    app = create_app(SesameStore(), enforce_tls=True)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/keys/nobody", headers={"X-Forwarded-Proto": "https"})
    assert r.status_code == 426
    # ...and must not be handed an HSTS header over plaintext.
    assert "strict-transport-security" not in r.headers


def test_forwarded_proto_is_honored_from_trusted_proxy():
    app = create_app(SesameStore(), enforce_tls=True, trusted_proxies=("testclient",))
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/keys/nobody", headers={"X-Forwarded-Proto": "https"})
    assert r.status_code == 404  # reached the handler; unknown user
    assert "strict-transport-security" in r.headers


def test_forwarded_proto_chain_uses_client_facing_hop():
    app = create_app(SesameStore(), enforce_tls=True, trusted_proxies=("testclient",))
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/keys/nobody", headers={"X-Forwarded-Proto": "http, https"})
    assert r.status_code == 426


# -- D3: rate-limit keys behind a reverse proxy ------------------------------


def test_rate_limit_keys_on_forwarded_client_behind_trusted_proxy():
    """D3: behind a proxy every request shared one bucket → one global limit."""
    app = create_app(
        SesameStore(),
        trusted_proxies=("testclient",),
        limits=ServerLimits(register_rate=(1, 0.0)),
    )
    c = TestClient(app)
    first = c.post(
        "/register",
        json=_raw_register_payload("alice.42"),
        headers={"X-Forwarded-For": "203.0.113.7"},
    )
    other_client = c.post(
        "/register",
        json=_raw_register_payload("bob.43"),
        headers={"X-Forwarded-For": "198.51.100.9"},
    )
    repeat = c.post(
        "/register",
        json=_raw_register_payload("carol.44"),
        headers={"X-Forwarded-For": "203.0.113.7"},
    )
    assert first.status_code == 200
    # A different real client must not be starved by the first one's spend.
    assert other_client.status_code == 200
    # ...and the first client's own bucket is still exhausted.
    assert repeat.status_code == 429


def test_forwarded_for_is_ignored_from_an_untrusted_peer():
    """Without a trusted-proxy allow-list the header must not mint buckets."""
    app = create_app(SesameStore(), limits=ServerLimits(register_rate=(1, 0.0)))
    c = TestClient(app)
    assert (
        c.post(
            "/register",
            json=_raw_register_payload("alice.42"),
            headers={"X-Forwarded-For": "203.0.113.7"},
        ).status_code
        == 200
    )
    assert (
        c.post(
            "/register",
            json=_raw_register_payload("bob.43"),
            headers={"X-Forwarded-For": "198.51.100.9"},
        ).status_code
        == 429
    )


def test_forwarded_for_uses_rightmost_untrusted_hop():
    """A client-prepended hop must not create a fresh bucket per request."""
    app = create_app(
        SesameStore(),
        trusted_proxies=("testclient", "10.0.0.1"),
        limits=ServerLimits(register_rate=(1, 0.0)),
    )
    c = TestClient(app)
    assert (
        c.post(
            "/register",
            json=_raw_register_payload("alice.42"),
            headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"},
        ).status_code
        == 200
    )
    # Same real client, spoofed extra left-most hop: still the same bucket.
    assert (
        c.post(
            "/register",
            json=_raw_register_payload("bob.43"),
            headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.7, 10.0.0.1"},
        ).status_code
        == 429
    )


def test_prekey_bundle_limiter_is_proxy_aware():
    app = create_app(
        SesameStore(),
        trusted_proxies=("testclient",),
        limits=ServerLimits(prekey_bundle_rate=(1, 0.0)),
    )
    bob = _register(app, "bob")
    c = TestClient(app)
    path = f"/keys/bob/{bob.device_id}"
    assert c.get(path, headers={"X-Forwarded-For": "203.0.113.7"}).status_code == 200
    assert c.get(path, headers={"X-Forwarded-For": "198.51.100.9"}).status_code == 200
    assert c.get(path, headers={"X-Forwarded-For": "203.0.113.7"}).status_code == 429


# -- M12: registration abuse -------------------------------------------------


def test_registration_is_rate_limited_per_source():
    app = create_app(SesameStore(), limits=ServerLimits(register_rate=(1, 0.0)))
    c = TestClient(app)
    assert c.post("/register", json=_raw_register_payload("alice.01")).status_code == 200
    assert c.post("/register", json=_raw_register_payload("bob.02")).status_code == 429


def test_registration_rejects_non_integer_prekey_id_with_400_not_500():
    """``int(k)`` used to raise an uncaught ValueError → 500 (audit M12)."""
    app = create_app(SesameStore())
    payload = _raw_register_payload("carol.03")
    payload["one_time_prekeys"] = {"not-an-int": b64e(b"\x01" * 32)}
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.post("/register", json=payload)
    assert r.status_code == 400


def test_ui_register_shares_the_register_rate_limiter():
    """D2: ``/ui/register`` must not be a limiter-free door to registration."""
    app = create_app(
        SesameStore(), enable_demo_ui=True, limits=ServerLimits(register_rate=(1, 0.0))
    )
    c = TestClient(app)
    assert c.post("/ui/register", json={"username": "alice.42"}).status_code == 200
    assert c.post("/ui/register", json={"username": "bob.43"}).status_code == 429


def test_ui_register_and_register_draw_on_one_bucket():
    """The two doors share one limiter, so they can never diverge again."""
    app = create_app(
        SesameStore(), enable_demo_ui=True, limits=ServerLimits(register_rate=(1, 0.0))
    )
    c = TestClient(app)
    assert c.post("/register", json=_raw_register_payload("alice.42")).status_code == 200
    assert c.post("/ui/register", json={"username": "bob.43"}).status_code == 429


def test_ui_register_conflict_does_not_leak_the_reason():
    """D2/L11: the demo door must use the same generic refusal as ``/register``."""
    app = create_app(SesameStore(), enable_demo_ui=True)
    c = TestClient(app)
    assert c.post("/ui/register", json={"username": "Alice.42"}).status_code == 200
    dup = c.post("/ui/register", json={"username": "alice.42"})
    assert dup.status_code == 403
    detail = dup.json()["detail"]
    assert detail == "registration refused"
    assert "identity" not in detail and "already" not in detail


def test_registration_caps_one_time_prekey_count():
    app = create_app(SesameStore())
    payload = _raw_register_payload("dave.04")
    payload["one_time_prekeys"] = {str(i): b64e(b"\x01" * 32) for i in range(65)}
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.post("/register", json=payload)
    assert r.status_code == 422


# -- M13: relay flooding -----------------------------------------------------


def test_oversized_message_body_is_rejected():
    app = create_app(SesameStore(), limits=ServerLimits(max_message_body_bytes=1024))
    alice = _register(app, "alice")
    bob = _register(app, "bob")
    c = TestClient(app)
    r = c.post(
        "/messages",
        headers={"Authorization": f"Bearer {alice.auth_token}"},
        json={
            "recipient_username": "bob",
            "recipient_device_id": bob.device_id,
            "kind": "chat",
            "body": {"ciphertext": "A" * 4096},
        },
    )
    assert r.status_code == 413


def test_recipient_mailbox_quota_is_enforced():
    store = SesameStore()
    app = create_app(store, limits=ServerLimits(max_mailbox_per_device=2))
    alice = _register(app, "alice")
    bob = _register(app, "bob")
    c = TestClient(app)
    body = {
        "recipient_username": "bob",
        "recipient_device_id": bob.device_id,
        "kind": "chat",
        "body": {"ciphertext": "AA=="},
    }
    headers = {"Authorization": f"Bearer {alice.auth_token}"}
    codes = [c.post("/messages", headers=headers, json=body).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]
    assert store.pending_count("bob", bob.device_id) == 2


def test_send_is_rate_limited_per_token():
    app = create_app(SesameStore(), limits=ServerLimits(send_rate=(2, 0.0)))
    alice = _register(app, "alice")
    bob = _register(app, "bob")
    c = TestClient(app)
    body = {
        "recipient_username": "bob",
        "recipient_device_id": bob.device_id,
        "kind": "chat",
        "body": {"ciphertext": "AA=="},
    }
    headers = {"Authorization": f"Bearer {alice.auth_token}"}
    codes = [c.post("/messages", headers=headers, json=body).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


# -- M14: circuit relay ------------------------------------------------------


def _circuit_app(**router_kwargs) -> FastAPI:
    app = FastAPI()
    app.include_router(build_decentralized_router(DecentralizedServices(), **router_kwargs))
    return app


def _nested(depth: int) -> dict:
    node: dict = {"payload": "x"}
    for _ in range(depth):
        node = {"n": node}
    return node


def test_circuit_frame_rejects_unbounded_nesting_instead_of_500():
    """Deeply nested JSON used to blow the recursive scan → 500 (audit M14)."""
    with TestClient(_circuit_app(), raise_server_exceptions=False) as c:
        r = c.post("/v1/circuits/deep/frames", json=_nested(200))
    assert r.status_code == 422
    # And the frame must not have been queued (fail closed).
    with TestClient(_circuit_app(), raise_server_exceptions=False) as c:
        c.post("/v1/circuits/deep/frames", json=_nested(200))
        assert c.get("/v1/circuits/deep/frames").json() == {"frames": []}


def test_circuit_frame_pathological_nesting_is_a_client_error():
    with TestClient(_circuit_app(), raise_server_exceptions=False) as c:
        raw = json.dumps(_nested(4000))
        r = c.post(
            "/v1/circuits/deep/frames",
            content=raw,
            headers={"content-type": "application/json"},
        )
    assert r.status_code in (400, 413, 422)


def test_circuit_frame_size_is_capped():
    with TestClient(_circuit_app(), raise_server_exceptions=False) as c:
        r = c.post("/v1/circuits/big/frames", json={"payload": "A" * 200_000})
    assert r.status_code == 413


def test_circuit_frames_per_circuit_are_capped():
    store = _CircuitFrameStore(max_circuits=4, max_frames=2)
    with TestClient(_circuit_app(frame_store=store)) as c:
        codes = [
            c.post("/v1/circuits/c1/frames", json={"payload": str(i)}).status_code
            for i in range(4)
        ]
    assert codes == [200, 200, 429, 429]


def test_total_circuit_count_is_bounded_and_fails_closed():
    """D4: at capacity the relay refuses NEW circuits; it never evicts existing ones.

    The round-1 bound evicted the least-recently-touched circuit, which handed
    an unauthenticated attacker a total-denial primitive: post ``max_circuits``
    junk circuits and every other circuit's queued frames vanish.
    """
    store = _CircuitFrameStore(max_circuits=3, max_frames=2)
    with TestClient(_circuit_app(frame_store=store), raise_server_exceptions=False) as c:
        codes = [
            c.post(f"/v1/circuits/c{i}/frames", json={"p": i}).status_code
            for i in range(10)
        ]
        assert codes[:3] == [200, 200, 200]
        assert set(codes[3:]) == {503}, "relay must fail closed, not evict"
        # Memory stays bounded...
        assert len(store._circuits) == 3
        # ...and the first circuits are intact.
        assert c.get("/v1/circuits/c0/frames").json() == {"frames": [{"p": 0}]}
        # Draining frees a slot, so the relay recovers without evicting anyone.
        assert c.post("/v1/circuits/c9/frames", json={"p": 9}).status_code == 200


def test_circuit_flood_cannot_destroy_another_peers_queued_frames():
    """The flood attack itself: fill the map, victim's frames must survive."""
    store = _CircuitFrameStore(max_circuits=4, max_frames=2)
    with TestClient(_circuit_app(frame_store=store), raise_server_exceptions=False) as c:
        assert c.post("/v1/circuits/victim/frames", json={"p": "secret"}).status_code == 200
        flood = [
            c.post(f"/v1/circuits/flood{i}/frames", json={"p": i}).status_code
            for i in range(64)
        ]
        assert 200 not in flood[3:], "attacker kept minting circuits past the cap"
        assert set(flood[3:]) == {503}
        # The original attack (destroying a stranger's circuit) must still fail.
        assert c.get("/v1/circuits/victim/frames").json() == {"frames": [{"p": "secret"}]}


def test_circuit_creation_is_partitioned_per_client():
    """D4: one flooder must exhaust only its own share of the relay."""
    store = _CircuitFrameStore(max_circuits=64, max_frames=2, max_circuits_per_client=2)
    app = _circuit_app(frame_store=store, trusted_proxies=("testclient",))
    attacker = {"X-Forwarded-For": "203.0.113.7"}
    victim = {"X-Forwarded-For": "198.51.100.9"}
    with TestClient(app, raise_server_exceptions=False) as c:
        codes = [
            c.post(f"/v1/circuits/a{i}/frames", json={"p": i}, headers=attacker).status_code
            for i in range(6)
        ]
        assert codes == [200, 200, 429, 429, 429, 429]
        # The victim is unaffected by the flood and its frames survive.
        assert c.post("/v1/circuits/v1/frames", json={"p": "ok"}, headers=victim).status_code == 200
        assert c.get("/v1/circuits/v1/frames", headers=victim).json() == {
            "frames": [{"p": "ok"}]
        }
        # Draining releases the attacker's share (accounting stays consistent).
        c.get("/v1/circuits/a0/frames", headers=attacker)
        assert (
            c.post("/v1/circuits/a9/frames", json={"p": 9}, headers=attacker).status_code
            == 200
        )


def test_circuit_limiter_is_proxy_aware():
    """D3: the circuit limiter must not collapse into one bucket behind a proxy."""
    app = _circuit_app(rate_limit=(1, 0.0), trusted_proxies=("testclient",))
    with TestClient(app, raise_server_exceptions=False) as c:
        a = c.post(
            "/v1/circuits/c/frames",
            json={"p": 1},
            headers={"X-Forwarded-For": "203.0.113.7"},
        )
        b = c.post(
            "/v1/circuits/c2/frames",
            json={"p": 2},
            headers={"X-Forwarded-For": "198.51.100.9"},
        )
        again = c.post(
            "/v1/circuits/c3/frames",
            json={"p": 3},
            headers={"X-Forwarded-For": "203.0.113.7"},
        )
    assert (a.status_code, b.status_code, again.status_code) == (200, 200, 429)


def test_circuit_limiter_ignores_forwarded_for_from_untrusted_peer():
    app = _circuit_app(rate_limit=(1, 0.0))
    with TestClient(app, raise_server_exceptions=False) as c:
        a = c.post(
            "/v1/circuits/c/frames",
            json={"p": 1},
            headers={"X-Forwarded-For": "203.0.113.7"},
        )
        b = c.post(
            "/v1/circuits/c2/frames",
            json={"p": 2},
            headers={"X-Forwarded-For": "198.51.100.9"},
        )
    assert (a.status_code, b.status_code) == (200, 429)


def test_circuit_relay_can_require_a_bearer_token():
    with TestClient(_circuit_app(relay_token="s3cret"), raise_server_exceptions=False) as c:
        assert c.post("/v1/circuits/c/frames", json={"p": 1}).status_code == 401
        assert c.get("/v1/circuits/c/frames").status_code == 401
        ok = c.post(
            "/v1/circuits/c/frames",
            json={"p": 1},
            headers={"Authorization": "Bearer s3cret"},
        )
        assert ok.status_code == 200
        wrong = c.post(
            "/v1/circuits/c/frames",
            json={"p": 1},
            headers={"Authorization": "Bearer s3cre_"},
        )
        assert wrong.status_code == 401


def test_circuit_frame_posts_are_rate_limited():
    with TestClient(_circuit_app(rate_limit=(2, 0.0)), raise_server_exceptions=False) as c:
        codes = [
            c.post("/v1/circuits/c/frames", json={"p": i}).status_code for i in range(3)
        ]
    assert codes == [200, 200, 429]


# -- L9: WebSocket bearer transport -----------------------------------------


def test_websocket_accepts_authorization_header_without_query_token():
    app = create_app(SesameStore())
    alice = _register(app, "alice")
    c = TestClient(app)
    with c.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {alice.auth_token}"}
    ) as ws:
        ws.send_json({"action": "noop"})  # ignored; connection stayed open
    # No exception == the handshake authenticated from the header alone.


def test_websocket_rejects_missing_credentials():
    app = create_app(SesameStore())
    c = TestClient(app)
    with pytest.raises(Exception):
        with c.websocket_connect("/ws"):
            pass


# -- L10: envelope id uniqueness --------------------------------------------


def test_envelope_ids_do_not_collide_after_a_server_restart():
    """A fresh process restarts the counter at 0 — ids must still be unique."""
    store = SesameStore()
    app1 = create_app(store)
    alice = _register(app1, "alice")
    bob = _register(app1, "bob")
    body = {
        "recipient_username": "bob",
        "recipient_device_id": bob.device_id,
        "kind": "chat",
        "body": {"ciphertext": "AA=="},
    }
    headers = {"Authorization": f"Bearer {alice.auth_token}"}
    first = TestClient(app1).post("/messages", headers=headers, json=body).json()

    # Simulate a restart: new app object, same durable store, undrained mailbox.
    app2 = create_app(store)
    second = TestClient(app2).post("/messages", headers=headers, json=body).json()

    assert first["envelope_id"] != second["envelope_id"]
    queued = store.fetch_mailbox("bob", bob.device_id, drain=False)
    assert len({e.envelope_id for e in queued}) == len(queued) == 2


# -- L11: error-string leakage ----------------------------------------------


def test_registration_conflict_does_not_leak_the_reason():
    app = create_app(SesameStore())
    _register(app, "alice")
    c = TestClient(app)
    payload = _raw_register_payload("alice")
    r = c.post("/register", json=payload)
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail == "registration refused"
    assert "identity" not in detail and "already" not in detail


def test_record_publish_error_is_generic():
    app = create_app(SesameStore(), enable_decentralized=True)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.post("/v1/records", json={})
    assert r.status_code == 400
    assert r.json()["detail"] == "malformed record"


def _record_payload(body: dict) -> dict:
    """A structurally valid signed record (signature need not verify)."""
    return {
        "type": "identity.username_record",
        "version": 1,
        "author_identity": "aa" * 32,
        "author_device_id": 1,
        "sequence": 1,
        "created_at": 1_700_000_000_000,
        "expires_at": None,
        "body": body,
        "signature": "bb" * 64,
    }


def test_record_with_float_body_is_a_client_error_not_500():
    """D5: the canonical codec raises TypeError → unauthenticated 500."""
    app = create_app(SesameStore(), enable_decentralized=True)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.post("/v1/records", json=_record_payload({"balance": 1.5}))
    assert r.status_code == 400
    assert r.json()["detail"] == "malformed record"


def test_record_with_nested_float_body_is_a_client_error_not_500():
    app = create_app(SesameStore(), enable_decentralized=True)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.post(
            "/v1/records", json=_record_payload({"nested": [{"ts": 1.0}]})
        )
    assert r.status_code == 400
    assert r.json()["detail"] == "malformed record"


def test_websocket_malformed_frame_error_is_generic():
    app = create_app(SesameStore())
    alice = _register(app, "alice")
    c = TestClient(app)
    with c.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {alice.auth_token}"}
    ) as ws:
        ws.send_json({"action": "send", "recipient_username": "bob"})  # missing fields
        msg = ws.receive_json()
    assert msg["type"] == "error"
    assert msg["detail"] == "invalid frame"
