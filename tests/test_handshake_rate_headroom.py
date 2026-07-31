"""Cross-subsystem: the server's send rate limit must not throttle the handshake.

Audit M13 added a per-auth-token token bucket on ``POST /messages``. The Braid
SCKA negotiates each epoch by pumping ~46 small frames per device through that
same endpoint, so a bucket sized for "chat messages" silently becomes a cap on
how many epochs an honest session may negotiate — and it fails *hard* (the
client raises on 429), it does not back off.

These tests pin both halves of the trade-off:
  * an honest multi-epoch negotiation completes under the DEFAULT limits;
  * an explicitly tight bucket still rejects a flood (the DoS control is intact).
"""

import pytest
from fastapi.testclient import TestClient

from ml_kem_braid.client.client import BraidChatClient, HttpTransport, run_until_agreed
from ml_kem_braid.server.app import ServerLimits, create_app
from ml_kem_braid.sesame.store import SesameStore


def _pair(app):
    alice = BraidChatClient(HttpTransport(TestClient(app)), "alice")
    bob = BraidChatClient(HttpTransport(TestClient(app)), "bob")
    alice.register()
    bob.register()
    return alice, bob


def test_multi_epoch_negotiation_survives_default_send_limit():
    """A 6-epoch honest negotiation must not be rate-limited off the server."""
    app = create_app(SesameStore())  # DEFAULT limits — this is the point
    alice, bob = _pair(app)
    session = alice.start_session("bob", bob.device_id)

    agreed = run_until_agreed(alice, bob, session, target_epochs=6)

    assert agreed >= 6
    assert len(session.epoch_keys) >= 6


def test_sustained_chat_after_handshake_survives_default_send_limit():
    """Post-handshake chat traffic must not exhaust what the handshake left."""
    app = create_app(SesameStore())
    alice, bob = _pair(app)
    session = alice.start_session("bob", bob.device_id)
    run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
    bob.poll()  # drain so Bob's session/ratchet exists for this epoch
    assert bob.sessions.get(("alice", alice.device_id)) is not None

    texts = [f"message-{i:03d}" for i in range(200)]
    for text in texts:
        alice.send_chat(session, text)
    bob.poll()

    assert [entry[3] for entry in bob.inbox] == texts
    assert not bob.dropped


def test_tight_send_bucket_still_rejects_a_flood():
    """Negative: the M13 control is still enforced when configured tightly."""
    import httpx

    app = create_app(SesameStore(), limits=ServerLimits(send_rate=(2, 0.0)))
    alice, bob = _pair(app)

    sent = 0
    with pytest.raises(httpx.HTTPStatusError) as exc:
        for _ in range(10):
            alice.transport.send(
                {
                    "recipient_username": "bob",
                    "recipient_device_id": bob.device_id,
                    "kind": "chat",
                    "body": {"noise": "x"},
                },
                alice.auth_token,
            )
            sent += 1
    assert exc.value.response.status_code == 429
    assert sent <= 2
