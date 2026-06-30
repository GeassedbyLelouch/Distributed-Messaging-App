"""FastAPI server + full end-to-end testnet tests."""

import pytest
from fastapi.testclient import TestClient

from ml_kem_braid.client.client import BraidChatClient, HttpTransport, run_until_agreed
from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore
from ml_kem_braid.testnet.demo import run_testnet


@pytest.fixture
def app():
    return create_app(SesameStore())


def test_health(app):
    c = TestClient(app)
    assert c.get("/health").json() == {"status": "ok"}


def test_register_and_fetch_bundle(app):
    c = TestClient(app)
    alice = BraidChatClient(HttpTransport(TestClient(app)), "alice")
    bob = BraidChatClient(HttpTransport(TestClient(app)), "bob")
    alice.register()
    bob.register()

    devices = alice.transport.list_devices("bob")
    assert devices[0]["device_id"] == bob.device_id

    bundle = alice.transport.get_bundle("bob", bob.device_id)["bundle"]
    # One-time prekey must be present and then consumed on a second fetch.
    assert bundle["opk_id"] is not None
    first_opk = bundle["opk_id"]
    bundle2 = alice.transport.get_bundle("bob", bob.device_id)["bundle"]
    assert bundle2["opk_id"] != first_opk  # consumed


def test_mailbox_requires_auth(app):
    c = TestClient(app)
    r = c.get("/messages")  # no bearer token
    assert r.status_code == 401


def test_unknown_user_404(app):
    c = TestClient(app)
    assert c.get("/keys/nobody").status_code == 404


def test_full_testnet_chat_roundtrip():
    result = run_testnet(message="post-quantum hello", verbose=False)
    assert result.alice_epoch_key == result.bob_epoch_key
    assert result.message_received == result.message_sent == "post-quantum hello"
    assert result.agreed_epoch >= 1


def test_minimal_metadata_only(app):
    """The store must capture only username/device/registration metadata."""
    store = SesameStore()
    app2 = create_app(store)
    client = BraidChatClient(HttpTransport(TestClient(app2)), "carol")
    client.register(registration_id=42)
    device = store.get_device("carol", client.device_id)
    fields = set(vars(device))
    # No PII fields like phone/email/realname.
    assert {"username", "device_id", "registration_id"} <= fields
    assert not ({"phone", "email", "real_name", "address"} & fields)
