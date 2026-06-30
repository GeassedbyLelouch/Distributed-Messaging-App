from __future__ import annotations

from fastapi.testclient import TestClient

from ml_kem_braid.client.client import BraidChatClient, HttpTransport, run_until_agreed
from ml_kem_braid.decentralized.services import DecentralizedServices, FederatedRelay
from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore


def test_cross_relay_delivery_preserves_opaque_message_body() -> None:
    relay_a = FederatedRelay("relay-a", DecentralizedServices())
    relay_b = FederatedRelay("relay-b", DecentralizedServices())
    relay_a.add_peer(relay_b)
    envelope = {
        "kind": "pqxdh_init",
        "body": {"kem_ct": "opaque", "ik_sign_pub": "public"},
    }

    relay_a.forward_to_relay(
        "relay-b",
        recipient_identity="b" * 64,
        recipient_device_id=1,
        envelope=envelope,
    )

    assert relay_b.services.fetch_mailbox("b" * 64, 1) == [envelope]


def test_existing_e2ee_chat_still_passes_after_decentralized_modules_exist() -> None:
    app = create_app(SesameStore(), enable_decentralized=True)
    tc = TestClient(app, raise_server_exceptions=True)
    alice = BraidChatClient(HttpTransport(tc), "Alice.42")
    bob = BraidChatClient(HttpTransport(tc), "Bob.42")

    alice.register(num_one_time=8)
    bob.register(num_one_time=8)
    session = alice.start_session("Bob.42")
    bob.poll()
    epoch = run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
    alice.send_chat(session, "hello", epoch=epoch)
    bob.poll()

    assert [message[3] for message in bob.inbox] == ["hello"]
