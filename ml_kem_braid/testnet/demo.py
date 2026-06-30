"""
End-to-end ML-KEM Braid chat testnet.

Boots the FastAPI server in-process (via an httpx ASGI transport, so no socket is
required), registers two users (Alice, Bob), runs the PQXDH handshake + ML-KEM
Braid key agreement entirely over the server's mailbox, then sends a real
AES-256-GCM-encrypted chat message that the peer decrypts. Every cryptographic
step is real (FIPS-203 ML-KEM, X25519, Ed25519, HKDF-SHA256, AES-256-GCM).

Run with::

    uv run python -m ml_kem_braid.testnet.demo
    # or, after `uv sync`: uv run braid-testnet
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from fastapi.testclient import TestClient

from ml_kem_braid.client.client import BraidChatClient, HttpTransport, run_until_agreed
from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore


@dataclass
class TestnetResult:
    rounds_to_agree: int
    agreed_epoch: int
    alice_epoch_key: bytes
    bob_epoch_key: bytes
    message_sent: str
    message_received: Optional[str]


def _make_client(app, username: str) -> BraidChatClient:
    http = TestClient(app)  # drives the ASGI app in-process, synchronously
    return BraidChatClient(HttpTransport(http), username)


def run_testnet(message: str = "Hello over post-quantum Braid!", verbose: bool = True) -> TestnetResult:
    store = SesameStore()
    app = create_app(store)

    alice = _make_client(app, "alice")
    bob = _make_client(app, "bob")

    a_reg = alice.register(num_one_time=4)
    b_reg = bob.register(num_one_time=4)
    if verbose:
        print(f"[register] alice -> device {a_reg['device_id']}, bob -> device {b_reg['device_id']}")

    # Alice initiates: fetch Bob's bundle, PQXDH, seed Braid, send pqxdh_init.
    session = alice.start_session("bob")
    if verbose:
        print(f"[pqxdh] alice established SK with bob device {session.peer_device_id}")

    # Pump the mailbox until Alice has agreed an epoch key with Bob.
    agreed_epoch = run_until_agreed(alice, bob, session, target_epochs=1)
    bob_session = bob.sessions[("alice", alice.device_id)]

    a_key = session.epoch_keys[agreed_epoch]
    b_key = bob_session.epoch_keys[agreed_epoch]
    if verbose:
        print(f"[braid] agreed epoch {agreed_epoch}: "
              f"alice={a_key.hex()[:16]}... bob={b_key.hex()[:16]}... match={a_key == b_key}")

    # Alice sends an encrypted chat message; Bob polls and decrypts it.
    alice.send_chat(session, message, epoch=agreed_epoch)
    bob.poll()
    received = bob.inbox[-1][3] if bob.inbox else None
    if verbose:
        print(f"[chat] alice sent: {message!r}")
        print(f"[chat] bob received: {received!r}")

    return TestnetResult(
        rounds_to_agree=0,
        agreed_epoch=agreed_epoch,
        alice_epoch_key=a_key,
        bob_epoch_key=b_key,
        message_sent=message,
        message_received=received,
    )


def main() -> None:
    print("=" * 64)
    print("ML-KEM Braid post-quantum chat testnet")
    print("=" * 64)
    result = run_testnet()
    print("-" * 64)
    ok = (
        result.alice_epoch_key == result.bob_epoch_key
        and result.message_received == result.message_sent
    )
    print(f"RESULT: {'SUCCESS' if ok else 'FAILURE'} "
          f"(epoch keys match={result.alice_epoch_key == result.bob_epoch_key}, "
          f"message roundtrip={result.message_received == result.message_sent})")
    if not ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
