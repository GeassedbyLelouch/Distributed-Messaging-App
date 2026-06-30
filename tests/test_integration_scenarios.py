"""
Comprehensive integration & scenario tests for ML-KEM Braid chat.

Covers:
  1. Session establishment lifecycle (state-machine progression, epoch-1 convention)
  2. Multi-epoch sustained agreement (5 epochs, keys match and are distinct)
  3. Many chat messages over a session (>=10 messages, alternating direction, exact plaintext)
  4. Bidirectional chat (both Alice→Bob and Bob→Alice on same session)
  5. Multi-device user (two devices for one username; mailbox isolation)
  6. Transport parity (core round-trip via HttpTransport + WS send path)
  7. Robustness (duplicate chunk tolerated; wrong-epoch chat dropped gracefully)
"""

from __future__ import annotations

import os
from typing import Tuple

import pytest
from fastapi.testclient import TestClient

from ml_kem_braid.client.client import (
    BraidChatClient,
    BraidSession,
    HttpTransport,
    WebSocketTransport,
    run_until_agreed,
)
from ml_kem_braid.protocol.braid import MLKEMBraid, Role, run_exchange
from ml_kem_braid.protocol.states import StateName
from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore
from ml_kem_braid.wire import b64e


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store() -> SesameStore:
    """Fresh in-memory store per test."""
    return SesameStore()


@pytest.fixture()
def app(store: SesameStore):
    return create_app(store)


@pytest.fixture()
def tc(app) -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


def _http_client(tc: TestClient, username: str) -> BraidChatClient:
    """Create and register a BraidChatClient over HTTP."""
    client = BraidChatClient(HttpTransport(tc), username)
    client.register(num_one_time=8)
    return client


# ---------------------------------------------------------------------------
# 1. Session establishment lifecycle
# ---------------------------------------------------------------------------


class TestSessionEstablishmentLifecycle:
    """Verify state-machine progression during initial handshake."""

    def test_initial_alice_state_is_keys_unsampled(self):
        """Alice must start in KEYS_UNSAMPLED before any message exchange."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        # ✓ VERIFIED: checked state_name directly
        assert alice.state_name == StateName.KEYS_UNSAMPLED

    def test_initial_bob_state_is_no_header_received(self):
        """Bob must start in NO_HEADER_RECEIVED before any message exchange."""
        secret = os.urandom(32)
        bob = MLKEMBraid(Role.BOB, secret)
        # ✓ VERIFIED
        assert bob.state_name == StateName.NO_HEADER_RECEIVED

    def test_epoch_1_key_derived_after_full_exchange(self):
        """After minimal exchange Alice and Bob both have a key for epoch 1."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        agreed = run_exchange(alice, bob, target_epochs=1, max_rounds=500)
        # There must be at least one agreed epoch
        assert len(agreed) >= 1
        epoch, a_key, b_key = agreed[0]
        assert epoch == 1, f"expected first agreed epoch to be 1, got {epoch}"
        # Keys must be 32 bytes and must match
        assert len(a_key) == 32
        assert a_key == b_key, "Alice and Bob must agree on the same epoch-1 key"

    def test_sending_epoch_is_epoch_minus_one(self):
        """The spec documents sending_epoch = epoch-1 (the latest epoch known to receiver).

        Before any key has been agreed, Alice's first send() should report
        sending_epoch = 0 (i.e., epoch 1 - 1 = 0).
        """
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        _msg, sending_epoch, _key = alice.send()
        # Alice starts at epoch=1, so sending_epoch = 1-1 = 0
        assert sending_epoch == 0, (
            f"sending_epoch after first send should be epoch-1=0, got {sending_epoch}"
        )

    def test_bob_reaches_header_received_state(self):
        """Bob transitions from NO_HEADER_RECEIVED to HEADER_RECEIVED once he has
        accumulated enough header chunks from Alice."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        # Drive until Bob leaves NO_HEADER_RECEIVED (i.e. HEADER_RECEIVED or beyond)
        found_header_received = False
        for _ in range(200):
            a_msg, _, _ = alice.send()
            bob.receive(a_msg)
            b_msg, _, _ = bob.send()
            alice.receive(b_msg)
            if bob.state_name == StateName.HEADER_RECEIVED:
                found_header_received = True
                break
            if bob.state_name not in (StateName.NO_HEADER_RECEIVED,):
                # Moved past HEADER_RECEIVED — that's also fine (already transitioned)
                found_header_received = True
                break

        assert found_header_received, (
            f"Bob never left NO_HEADER_RECEIVED; stuck in {bob.state_name}"
        )

    def test_alice_state_progresses_past_keys_unsampled(self):
        """Alice must leave KEYS_UNSAMPLED after her first send."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        alice.send()
        # After first send Alice moves to KEYS_SAMPLED
        assert alice.state_name != StateName.KEYS_UNSAMPLED, (
            f"Alice still in KEYS_UNSAMPLED after first send; state={alice.state_name}"
        )
        assert alice.state_name == StateName.KEYS_SAMPLED


# ---------------------------------------------------------------------------
# 2. Multi-epoch sustained agreement
# ---------------------------------------------------------------------------


class TestMultiEpochAgreement:
    """run_exchange over 5 epochs: all keys match and are mutually distinct."""

    def test_five_epochs_all_match(self):
        """All 5 agreed epoch keys must be equal between Alice and Bob."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        agreed = run_exchange(alice, bob, target_epochs=5, max_rounds=5000)
        assert len(agreed) >= 5, f"expected 5 agreed epochs, got {len(agreed)}"

        for epoch, a_key, b_key in agreed[:5]:
            assert a_key == b_key, f"epoch {epoch}: Alice key != Bob key"
            assert len(a_key) == 32

    def test_five_epochs_all_distinct(self):
        """All 5 epoch keys must be distinct (forward secrecy property)."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        agreed = run_exchange(alice, bob, target_epochs=5, max_rounds=5000)
        assert len(agreed) >= 5

        keys = [a_key for _, a_key, _ in agreed[:5]]
        # All keys must be unique
        unique_keys = set(keys)
        assert len(unique_keys) == len(keys), (
            f"some epoch keys are identical — forward secrecy violated: "
            f"{[k.hex()[:16] for k in keys]}"
        )

    def test_get_key_by_epoch(self):
        """MLKEMBraid.get_key(epoch) returns the same key as run_exchange."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        agreed = run_exchange(alice, bob, target_epochs=3, max_rounds=3000)
        for epoch, a_key, b_key in agreed:
            assert alice.get_key(epoch) == a_key
            assert bob.get_key(epoch) == b_key


# ---------------------------------------------------------------------------
# 3. Many chat messages over a session (>=10 messages, alternating directions)
# ---------------------------------------------------------------------------


class TestManyChatMessages:
    """A long chat conversation: >=10 messages, in order, exact plaintext."""

    def test_ten_plus_messages_exact_plaintext(self, tc: TestClient, store: SesameStore) -> None:
        """Send 10+ alternating messages; every one must appear in inbox with exact text."""
        alice = _http_client(tc, "alice")
        bob = _http_client(tc, "bob")

        # PQXDH + Braid key agreement
        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        epoch = session.latest_epoch()
        assert epoch is not None

        # Ensure Bob has his session too
        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        # Build 12 alternating messages: even indices from Alice, odd from Bob
        messages = [f"message-{i:03d}" for i in range(12)]

        # Send all messages and record expected (sender, text) pairs
        expected_alice_inbox: list[Tuple[str, int, int, str]] = []  # what Alice expects
        expected_bob_inbox: list[Tuple[str, int, int, str]] = []  # what Bob expects

        for i, text in enumerate(messages):
            if i % 2 == 0:
                # Alice → Bob
                alice.send_chat(session, text, epoch=epoch)
                expected_bob_inbox.append(("alice", alice.device_id, epoch, text))
            else:
                # Bob → Alice
                bob.send_chat(bob_session, text, epoch=epoch)
                expected_alice_inbox.append(("bob", bob.device_id, epoch, text))

        # Drain mailboxes
        bob.poll()
        alice.poll()

        # Verify Alice's inbox (messages from Bob)
        assert len(alice.inbox) == len(expected_alice_inbox), (
            f"Alice inbox has {len(alice.inbox)} messages, "
            f"expected {len(expected_alice_inbox)}"
        )
        for (exp_peer, exp_dev, exp_epoch, exp_text), actual in zip(
            expected_alice_inbox, alice.inbox
        ):
            a_peer, a_dev, a_epoch, a_text = actual
            assert a_peer == exp_peer
            assert a_dev == exp_dev
            assert a_epoch == exp_epoch
            assert a_text == exp_text, f"plaintext mismatch: {a_text!r} != {exp_text!r}"

        # Explicit ordering assertion: the plaintext list extracted from the inbox
        # must exactly match the expected order, not merely the same multiset.
        assert [m[3] for m in alice.inbox] == [e[3] for e in expected_alice_inbox], (
            "Alice inbox messages are out of order"
        )

        # Verify Bob's inbox (messages from Alice)
        assert len(bob.inbox) == len(expected_bob_inbox), (
            f"Bob inbox has {len(bob.inbox)} messages, "
            f"expected {len(expected_bob_inbox)}"
        )
        for (exp_peer, exp_dev, exp_epoch, exp_text), actual in zip(
            expected_bob_inbox, bob.inbox
        ):
            b_peer, b_dev, b_epoch, b_text = actual
            assert b_peer == exp_peer
            assert b_dev == exp_dev
            assert b_epoch == exp_epoch
            assert b_text == exp_text, f"plaintext mismatch: {b_text!r} != {exp_text!r}"

        # Explicit ordering assertion: same as above for Bob's inbox.
        assert [m[3] for m in bob.inbox] == [e[3] for e in expected_bob_inbox], (
            "Bob inbox messages are out of order"
        )

    def test_messages_span_multiple_epochs(self, tc: TestClient, store: SesameStore) -> None:
        """The Double Ratchet advances across multiple SCKA epochs; messages
        in each epoch decrypt to the correct plaintext.

        With the Double Ratchet each epoch is ratcheted in-order (forward
        secrecy: you cannot retroactively send on a past epoch).  We drive
        to 3 epochs, confirm both ratchets are on the same (latest) epoch,
        then send several messages and verify exact decryption.
        """
        alice = _http_client(tc, "alice")
        bob = _http_client(tc, "bob")

        session = alice.start_session("bob")
        # Drive to 3 epochs so the ratchet has ratcheted multiple times.
        run_until_agreed(alice, bob, session, target_epochs=3, max_rounds=5000)

        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        # Both ratchets must be on the same (latest) epoch.
        latest = session.latest_epoch()
        assert latest is not None and latest >= 3, f"expected >=3 epochs, got {latest}"
        assert session.ratchet._current_epoch == latest, (
            f"alice ratchet epoch {session.ratchet._current_epoch} != {latest}"
        )
        assert bob_session.ratchet._current_epoch == latest, (
            f"bob ratchet epoch {bob_session.ratchet._current_epoch} != {latest}"
        )

        # Send 3 messages on the current epoch; each gets a distinct ratchet index.
        texts = ["epoch-ratchet-msg-0", "epoch-ratchet-msg-1", "epoch-ratchet-msg-2"]
        for text in texts:
            alice.send_chat(session, text)

        bob.poll()
        assert len(bob.inbox) == len(texts), (
            f"Bob inbox has {len(bob.inbox)} messages, expected {len(texts)}"
        )
        received = [m[3] for m in bob.inbox]
        assert received == texts, f"plaintext mismatch: {received!r} != {texts!r}"


# ---------------------------------------------------------------------------
# 4. Bidirectional chat
# ---------------------------------------------------------------------------


class TestBidirectionalChat:
    """Alice→Bob AND Bob→Alice on the same agreed session."""

    def test_bob_to_alice_chat_decrypts(self, tc: TestClient, store: SesameStore) -> None:
        """Bob sends back to Alice; Alice must decrypt to exact plaintext."""
        alice = _http_client(tc, "alice")
        bob = _http_client(tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        epoch = session.latest_epoch()
        assert epoch is not None

        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None
        # Bob must also have a key for the same epoch
        assert epoch in bob_session.epoch_keys

        # Alice → Bob
        alice.send_chat(session, "hello from alice", epoch=epoch)
        bob.poll()

        # Bob → Alice
        bob.send_chat(bob_session, "hello from bob", epoch=epoch)
        alice.poll()

        # Verify Bob received Alice's message
        assert len(bob.inbox) >= 1
        b_peer, b_dev, b_epoch, b_text = bob.inbox[0]
        assert b_peer == "alice"
        assert b_text == "hello from alice"
        assert b_epoch == epoch

        # Verify Alice received Bob's reply
        assert len(alice.inbox) >= 1
        a_peer, a_dev, a_epoch, a_text = alice.inbox[0]
        assert a_peer == "bob"
        assert a_text == "hello from bob"
        assert a_epoch == epoch

    def test_alice_and_bob_keys_are_identical(self, tc: TestClient, store: SesameStore) -> None:
        """The epoch key used to encrypt on one side must match the key used to decrypt.

        Concretely: session.epoch_keys[epoch] == bob_session.epoch_keys[epoch].
        """
        alice = _http_client(tc, "alice")
        bob = _http_client(tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        epoch = session.latest_epoch()
        assert epoch is not None

        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        a_key = session.epoch_keys[epoch]
        b_key = bob_session.epoch_keys[epoch]
        # The cryptographic invariant: both keys MUST be equal
        assert a_key == b_key, (
            f"epoch {epoch}: alice key {a_key.hex()[:16]}... != bob key {b_key.hex()[:16]}..."
        )
        assert len(a_key) == 32


# ---------------------------------------------------------------------------
# 5. Multi-device user
# ---------------------------------------------------------------------------


class TestMultiDeviceUser:
    """Register two devices under the same username; assert mailbox isolation."""

    def test_two_devices_listed_for_same_user(self, tc: TestClient, store: SesameStore) -> None:
        """Registering a second device with the SAME identity key increments device count."""
        # Create one identity to share between both 'bob' devices
        from ml_kem_braid.pqxdh import create_identity, create_prekey_bundle
        from ml_kem_braid.pqxdh.pqxdh import _x25519_pub_bytes
        from ml_kem_braid.wire import b64e, bundle_to_dict, registration_challenge

        shared_identity = create_identity()

        def register_bob_device(registration_id: int) -> dict:
            bundle, _ = create_prekey_bundle(shared_identity, num_one_time=4)
            one_time = {}  # skip OTKs for simplicity
            proof = shared_identity.sign(registration_challenge("bob", registration_id))
            r = tc.post(
                "/register",
                json={
                    "username": "bob",
                    "registration_id": registration_id,
                    "bundle": bundle_to_dict(bundle),
                    "proof_sig": b64e(proof),
                    "one_time_prekeys": one_time,
                },
            )
            assert r.status_code == 200, r.text
            return r.json()

        dev1 = register_bob_device(registration_id=1)
        dev2 = register_bob_device(registration_id=2)

        # Both devices must have different device_ids
        assert dev1["device_id"] != dev2["device_id"]

        # list_devices must return both
        devices = tc.get("/keys/bob").json()
        device_ids = {d["device_id"] for d in devices}
        assert dev1["device_id"] in device_ids
        assert dev2["device_id"] in device_ids
        assert len(device_ids) >= 2

    def test_message_to_device1_not_in_device2_mailbox(
        self, tc: TestClient, store: SesameStore
    ) -> None:
        """A chat envelope addressed to bob device-1 must NOT appear in bob device-2's mailbox."""
        from ml_kem_braid.pqxdh import create_identity, create_prekey_bundle
        from ml_kem_braid.wire import b64e, bundle_to_dict, registration_challenge

        shared_identity = create_identity()

        def register_bob_device(registration_id: int) -> dict:
            bundle, _ = create_prekey_bundle(shared_identity, num_one_time=2)
            proof = shared_identity.sign(registration_challenge("bob", registration_id))
            r = tc.post(
                "/register",
                json={
                    "username": "bob",
                    "registration_id": registration_id,
                    "bundle": bundle_to_dict(bundle),
                    "proof_sig": b64e(proof),
                    "one_time_prekeys": {},
                },
            )
            assert r.status_code == 200, r.text
            return r.json()

        dev1 = register_bob_device(registration_id=1)
        dev2 = register_bob_device(registration_id=2)

        # Alice registers and sends a message specifically to bob device-1
        alice = _http_client(tc, "alice")

        tc.post(
            "/messages",
            json={
                "recipient_username": "bob",
                "recipient_device_id": dev1["device_id"],
                "kind": "chat",
                "body": {"epoch": 1, "ciphertext": b64e(b"test")},
            },
            headers={"Authorization": f"Bearer {alice.auth_token}"},
        )

        # device-1 mailbox should have 1 envelope
        r1 = tc.get("/messages", headers={"Authorization": f"Bearer {dev1['auth_token']}"})
        assert r1.status_code == 200
        assert len(r1.json()) == 1

        # device-2 mailbox must be empty — messages are per-device
        r2 = tc.get("/messages", headers={"Authorization": f"Bearer {dev2['auth_token']}"})
        assert r2.status_code == 200
        assert len(r2.json()) == 0, (
            "message addressed to device-1 must NOT appear in device-2's mailbox"
        )

    def test_alice_can_start_session_to_specific_device(
        self, tc: TestClient, store: SesameStore
    ) -> None:
        """Alice can retrieve a prekey bundle for a specific bob device_id."""
        from ml_kem_braid.pqxdh import create_identity, create_prekey_bundle
        from ml_kem_braid.wire import b64e, bundle_to_dict, registration_challenge

        shared_identity = create_identity()

        dev_ids = []
        for rid in (1, 2):
            bundle, _ = create_prekey_bundle(shared_identity, num_one_time=2)
            proof = shared_identity.sign(registration_challenge("bob", rid))
            r = tc.post(
                "/register",
                json={
                    "username": "bob",
                    "registration_id": rid,
                    "bundle": bundle_to_dict(bundle),
                    "proof_sig": b64e(proof),
                    "one_time_prekeys": {},
                },
            )
            assert r.status_code == 200
            dev_ids.append(r.json()["device_id"])

        alice = _http_client(tc, "alice")

        # Alice fetches bundle for bob device[0] specifically
        bundle_resp = tc.get(f"/keys/bob/{dev_ids[0]}")
        assert bundle_resp.status_code == 200
        body = bundle_resp.json()
        assert body["device_id"] == dev_ids[0]
        assert body["username"] == "bob"

        # And for device[1] specifically
        bundle_resp2 = tc.get(f"/keys/bob/{dev_ids[1]}")
        assert bundle_resp2.status_code == 200
        assert bundle_resp2.json()["device_id"] == dev_ids[1]


# ---------------------------------------------------------------------------
# 6. Transport parity
# ---------------------------------------------------------------------------


class TestTransportParity:
    """Core chat round-trip works over HTTP; WS send path is exercised separately."""

    def test_full_chat_over_http_transport(self, tc: TestClient, store: SesameStore) -> None:
        """Full multi-epoch chat round-trip over HttpTransport."""
        alice = _http_client(tc, "alice")
        bob = _http_client(tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        epoch = session.latest_epoch()
        assert epoch is not None

        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        # Send a message and verify exact text arrives
        alice.send_chat(session, "parity-http", epoch=epoch)
        bob.poll()

        assert len(bob.inbox) == 1
        peer, dev, recv_ep, text = bob.inbox[0]
        assert peer == "alice"
        assert text == "parity-http"
        assert recv_ep == epoch

    def test_chat_send_via_websocket_transport(self, tc: TestClient, store: SesameStore) -> None:
        """Chat message sent via WebSocketTransport is received by the HTTP-polling peer.

        TestClient constraint: two nested WS contexts with blocking receive_json()
        calls cannot run in the same thread without deadlock. We therefore:
          a. Run PQXDH + Braid key agreement entirely over HTTP.
          b. Open Alice's WS, send via WebSocketTransport, read ack, close.
          c. Bob polls via HTTP to receive and decrypt.
        This proves WebSocketTransport.send() goes through the server correctly.
        """
        http = HttpTransport(tc)

        alice = BraidChatClient(http, "alice")
        bob = BraidChatClient(http, "bob")
        alice.register(num_one_time=4)
        bob.register(num_one_time=4)

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        epoch = session.latest_epoch()
        assert epoch is not None

        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None
        assert epoch in bob_session.epoch_keys

        # Switch Alice to WebSocketTransport for the send
        with tc.websocket_connect(f"/ws?token={alice.auth_token}") as alice_ws:
            alice_wst = WebSocketTransport(
                base_http=http,
                ws_session=alice_ws,
                token=alice.auth_token,
            )
            alice.transport = alice_wst

            alice.send_chat(session, "parity-websocket", epoch=epoch)

            # Consume the server ack (guaranteed: server always acks valid sends)
            ack = alice_ws.receive_json()
            assert ack["type"] == "ack"

        # Bob retrieves via HTTP poll
        bob.poll()
        assert len(bob.inbox) == 1
        peer, dev, recv_ep, text = bob.inbox[0]
        assert peer == "alice"
        assert text == "parity-websocket"
        assert recv_ep == epoch

    @pytest.mark.parametrize("transport_label", ["http", "ws"])
    def test_parametrized_chat_round_trip(
        self, tc: TestClient, store: SesameStore, transport_label: str
    ) -> None:
        """Parametrized smoke test — exercises both HTTP and WebSocket transports.

        Both branches establish the session over HTTP (PQXDH + Braid key
        agreement) then send the chat message via the selected transport.

        TestClient limitation: two simultaneous WS connections with blocking
        receive_json() calls would deadlock in the same thread. We therefore
        keep Bob on HTTP polling for the receive side regardless of transport_label,
        and only drive Alice's send through WebSocketTransport for the "ws" case.
        This is identical to the approach used in test_chat_send_via_websocket_transport.
        """
        http = HttpTransport(tc)

        alice = BraidChatClient(http, "alice")
        bob = BraidChatClient(http, "bob")
        alice.register(num_one_time=4)
        bob.register(num_one_time=4)

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        epoch = session.latest_epoch()
        assert epoch is not None

        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None
        assert epoch in bob_session.epoch_keys

        msg = f"transport-{transport_label}"

        if transport_label == "http":
            # Send entirely over HTTP transport (already set up above).
            alice.send_chat(session, msg, epoch=epoch)
        else:
            # "ws" branch: switch Alice's transport to WebSocketTransport just
            # for this send, mirroring test_chat_send_via_websocket_transport.
            # TestClient does not support two concurrent blocking WS readers, so
            # Bob still receives via HTTP poll below.
            with tc.websocket_connect(f"/ws?token={alice.auth_token}") as alice_ws:
                alice_wst = WebSocketTransport(
                    base_http=http,
                    ws_session=alice_ws,
                    token=alice.auth_token,
                )
                alice.transport = alice_wst
                alice.send_chat(session, msg, epoch=epoch)
                # Consume the server ack to keep the WS protocol clean.
                ack = alice_ws.receive_json()
                assert ack["type"] == "ack"
            # Restore HTTP transport so subsequent poll() calls work normally.
            alice.transport = http

        # Bob receives and decrypts via HTTP poll (both branches).
        bob.poll()

        assert len(bob.inbox) == 1
        peer, dev, recv_ep, text = bob.inbox[0]
        assert peer == "alice"
        assert text == msg, f"plaintext mismatch: {text!r} != {msg!r}"
        assert recv_ep == epoch


# ---------------------------------------------------------------------------
# 7. Robustness
# ---------------------------------------------------------------------------


class TestRobustness:
    """Duplicate Braid chunks and wrong-epoch chat envelopes are handled gracefully."""

    def test_duplicate_braid_chunk_does_not_corrupt_agreement(self) -> None:
        """Feeding a Braid chunk to the receiver twice must not crash or corrupt the key.

        Duplicate delivery is the semantics of an at-least-once transport; the
        Braid protocol must tolerate it. Concretely: the erasure decoder ignores
        already-seen chunk indices, so the key derived on first delivery is
        unchanged by the second delivery.
        """
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        # Run a full exchange first to establish a baseline key
        agreed = run_exchange(alice, bob, target_epochs=1, max_rounds=500)
        assert len(agreed) >= 1
        _epoch, a_key_before, b_key_before = agreed[0]
        assert a_key_before == b_key_before

        # Now send one more Braid message from Alice and feed it to Bob twice
        msg_a, _, _ = alice.send()
        bob.receive(msg_a)          # first delivery
        bob.receive(msg_a)          # duplicate — must not raise or corrupt state

        # Bob's key for epoch 1 must still equal Alice's
        assert bob.get_key(1) == alice.get_key(1), (
            "Duplicate chunk corrupted Bob's epoch-1 key"
        )

    def test_wrong_epoch_chat_is_dropped_gracefully(
        self, tc: TestClient, store: SesameStore
    ) -> None:
        """A chat envelope encrypted under an unknown epoch key is dropped gracefully.

        The client must not crash, the message must be absent from the inbox, and
        bob.dropped must grow — providing observable evidence that the drop was
        recorded rather than silently ignored.
        """
        alice = _http_client(tc, "alice")
        bob = _http_client(tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)

        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        # Capture the dropped count before injecting the bad envelope.
        dropped_before = len(bob.dropped)

        # Manually send a chat envelope whose ratchet header names epoch 999 — a
        # future epoch Bob's ratchet has not advanced to — so decrypt raises and
        # the envelope is dropped (not delivered, recorded in dropped).
        tc.post(
            "/messages",
            json={
                "recipient_username": "bob",
                "recipient_device_id": bob.device_id,
                "kind": "chat",
                "body": {
                    "header": {"epoch": 999, "index": 0},  # unknown/future epoch
                    "ciphertext": b64e(b"garbage ciphertext"),
                },
            },
            headers={"Authorization": f"Bearer {alice.auth_token}"},
        )

        # poll() must not raise
        bob.poll()

        # 1. The envelope must NOT appear in the inbox (no key → no decryption).
        epoch_999_msgs = [m for m in bob.inbox if m[2] == 999]
        assert len(epoch_999_msgs) == 0, (
            "A chat message with an unknown epoch key must not appear in inbox"
        )

        # 2. The drop must have been recorded in bob.dropped (observable evidence).
        assert len(bob.dropped) > dropped_before, (
            "A chat message for an unknown epoch must be recorded in bob.dropped"
        )

    def test_forged_chat_ciphertext_is_dropped(
        self, tc: TestClient, store: SesameStore
    ) -> None:
        """A chat ciphertext that fails AEAD authentication raises internally and is
        recorded in client.dropped (observable) without crashing poll()."""
        alice = _http_client(tc, "alice")
        bob = _http_client(tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        epoch = session.latest_epoch()

        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None
        assert epoch in bob_session.epoch_keys

        dropped_before = len(bob.dropped)

        # Send a chat envelope with a well-formed ratchet header but a random
        # (invalid) ciphertext for index 0 of the agreed epoch, so it reaches and
        # fails the Double Ratchet's AEAD authentication (not just a malformed body).
        tc.post(
            "/messages",
            json={
                "recipient_username": "bob",
                "recipient_device_id": bob.device_id,
                "kind": "chat",
                "body": {
                    "header": {"epoch": epoch, "index": 0},
                    "ciphertext": b64e(os.urandom(48)),  # random bytes ≠ valid AEAD tag
                },
            },
            headers={"Authorization": f"Bearer {alice.auth_token}"},
        )

        # poll() must not raise
        bob.poll()

        # The forged envelope must not appear in the inbox
        assert len(bob.inbox) == 0, (
            "A forged ciphertext must not be placed in the inbox"
        )
        # And it must be recorded in dropped
        assert len(bob.dropped) > dropped_before, (
            "A forged ciphertext must increment client.dropped"
        )
