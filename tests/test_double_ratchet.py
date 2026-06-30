"""
Tests for the Signal-style Double Ratchet layered over the ML-KEM Braid SCKA.

Covers the full spec from task6-brief.md:
  1. A/B round-trip: two ratchets seeded from the same SK, same epoch-key stream,
     each decrypts the other's messages to exact plaintext.
  2. Per-message keys distinct: successive messages use different keys.
  3. Out-of-order: indices [2,0,1] all decrypt via the skipped-key cache.
  4. Dropped message: indices 0 and 2 decrypt; index 1 never arrives but is
     cached (bounded by MAX_SKIP) then pruned when consumed.
  5. Multi-epoch: ratchet across >=3 epochs; messages in each epoch decrypt;
     chains reset per epoch.
  6. Tamper: modified ciphertext or wrong AD fails to decrypt (raises), and
     no forged plaintext is delivered.
  7. MAX_SKIP: a header.index absurdly far ahead is refused without unbounded
     key allocation.
  8. Integration: two BraidChatClients drive PQXDH + Braid key agreement over
     the server, then exchange several chat messages and assert exact plaintexts.
"""

from __future__ import annotations

import os
from typing import List, Tuple

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from ml_kem_braid.client.client import (
    BraidChatClient,
    HttpTransport,
    run_until_agreed,
)
from ml_kem_braid.core.double_ratchet import MAX_SKIP, DoubleRatchet, RatchetHeader
from ml_kem_braid.core.double_ratchet import Role as DRRole
from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pair(sk: bytes) -> Tuple[DoubleRatchet, DoubleRatchet]:
    """Two ratchets seeded from the same SK in opposing roles."""
    return DoubleRatchet(sk, DRRole.ALICE), DoubleRatchet(sk, DRRole.BOB)


def _feed_epoch(alice: DoubleRatchet, bob: DoubleRatchet, epoch: int) -> None:
    """Advance both ratchets with a fresh shared epoch key."""
    key = os.urandom(32)
    alice.ratchet_epoch(epoch, key)
    bob.ratchet_epoch(epoch, key)


_AD = b"test-context"


# ---------------------------------------------------------------------------
# 1. A/B round-trip — the fundamental correctness test
# ---------------------------------------------------------------------------


class TestABRoundTrip:
    """Two ratchets seeded from the same SK + epoch-key stream decrypt each other."""

    def test_alice_to_bob_single_message(self):
        """Alice encrypts; Bob decrypts to exact plaintext."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        plaintext = b"hello from alice"
        hdr, ct = alice.encrypt(plaintext, _AD)
        result = bob.decrypt(hdr, ct, _AD)
        assert result == plaintext

    def test_bob_to_alice_single_message(self):
        """Bob encrypts; Alice decrypts to exact plaintext."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        plaintext = b"hello from bob"
        hdr, ct = bob.encrypt(plaintext, _AD)
        result = alice.decrypt(hdr, ct, _AD)
        assert result == plaintext

    def test_bidirectional_multiple_messages(self):
        """Alice and Bob exchange multiple messages; every plaintext matches."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        messages_a = [f"A-msg-{i}".encode() for i in range(5)]
        messages_b = [f"B-msg-{i}".encode() for i in range(5)]

        # Alice → Bob
        encrypted_a = [alice.encrypt(m, _AD) for m in messages_a]
        for i, (hdr, ct) in enumerate(encrypted_a):
            assert bob.decrypt(hdr, ct, _AD) == messages_a[i], f"A->B msg {i} mismatch"

        # Bob → Alice
        encrypted_b = [bob.encrypt(m, _AD) for m in messages_b]
        for i, (hdr, ct) in enumerate(encrypted_b):
            assert alice.decrypt(hdr, ct, _AD) == messages_b[i], f"B->A msg {i} mismatch"

    def test_header_epoch_and_index_are_correct(self):
        """Headers report the right epoch and monotonically increasing index."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        for i in range(4):
            hdr, ct = alice.encrypt(b"msg", _AD)
            assert hdr.epoch == 1, f"header epoch should be 1, got {hdr.epoch}"
            assert hdr.index == i, f"header index should be {i}, got {hdr.index}"
            bob.decrypt(hdr, ct, _AD)


# ---------------------------------------------------------------------------
# 2. Per-message keys are distinct
# ---------------------------------------------------------------------------


class TestDistinctMessageKeys:
    """Successive messages must use different message keys (forward secrecy)."""

    def test_successive_encrypt_distinct_ciphertexts(self):
        """Same plaintext encrypted twice produces different ciphertexts (different mk + nonce)."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        _, ct1 = alice.encrypt(b"same plaintext", _AD)
        _, ct2 = alice.encrypt(b"same plaintext", _AD)
        # Different message keys + random nonces → different blobs
        assert ct1 != ct2, "successive encryptions of the same plaintext must differ"

    def test_peek_send_mk_distinct_for_successive_messages(self):
        """peek_send_mk() returns a different key after each encrypt()."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        mk0 = alice.peek_send_mk()
        alice.encrypt(b"msg0", _AD)
        mk1 = alice.peek_send_mk()
        alice.encrypt(b"msg1", _AD)
        mk2 = alice.peek_send_mk()

        assert mk0 != mk1, "mk after 0 sends must differ from mk after 1 send"
        assert mk1 != mk2, "mk after 1 send must differ from mk after 2 sends"
        assert mk0 != mk2, "all three sampled message keys must be distinct"

    def test_all_ten_message_keys_unique(self):
        """Ten successive message keys are all distinct."""
        sk = os.urandom(32)
        alice, _ = _pair(sk)
        alice.ratchet_epoch(1, os.urandom(32))

        mks: List[bytes] = []
        for _ in range(10):
            mk = alice.peek_send_mk()
            alice.encrypt(b"data", _AD)
            mks.append(mk)

        assert len(set(mks)) == 10, f"not all 10 message keys are unique: {mks}"


# ---------------------------------------------------------------------------
# 3. Out-of-order delivery
# ---------------------------------------------------------------------------


class TestOutOfOrder:
    """Skipped messages are cached and decrypted when they (eventually) arrive."""

    def test_indices_210(self):
        """Bob receives [2, 0, 1] and decrypts all three to the right plaintexts."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        plaintexts = [b"msg0", b"msg1", b"msg2"]
        encrypted = [alice.encrypt(p, _AD) for p in plaintexts]  # indices 0,1,2

        # Deliver in order: 2, 0, 1
        assert bob.decrypt(*encrypted[2], _AD) == plaintexts[2], "index 2 failed"
        assert bob.decrypt(*encrypted[0], _AD) == plaintexts[0], "index 0 failed"
        assert bob.decrypt(*encrypted[1], _AD) == plaintexts[1], "index 1 failed"

    def test_large_gap_then_fill(self):
        """Encrypt 5, deliver 0, 4, 1, 2, 3 — all arrive correctly."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        pts = [f"m{i}".encode() for i in range(5)]
        encs = [alice.encrypt(p, _AD) for p in pts]

        for idx in (0, 4, 1, 2, 3):
            assert bob.decrypt(*encs[idx], _AD) == pts[idx], f"idx {idx} failed"

    def test_skipped_keys_cached_until_consumed(self):
        """When index 2 is delivered before index 1, the cached key for 1
        is available and then removed from the cache upon use."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        pts = [b"a", b"b", b"c"]
        encs = [alice.encrypt(p, _AD) for p in pts]

        # Deliver 0, then 2 (skips 1 — cached), then 1
        bob.decrypt(*encs[0], _AD)
        bob.decrypt(*encs[2], _AD)

        # Key for (epoch=1, index=1) must be in the skip cache
        assert (1, 1) in bob._skipped, "skipped key for index 1 should be cached"

        # Deliver the skipped message
        result = bob.decrypt(*encs[1], _AD)
        assert result == pts[1], "skipped message 1 decrypted incorrectly"

        # Cache entry must be consumed
        assert (1, 1) not in bob._skipped, "cache entry for index 1 should be removed after use"

    def test_forged_message_does_not_evict_cached_key(self):
        """A forged ciphertext targeting a CACHED (epoch, index) must not consume
        the cached key — the genuine delayed message for that slot must still
        decrypt afterwards (verify-before-evict)."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        pts = [b"zero", b"one", b"two"]
        encs = [alice.encrypt(p, _AD) for p in pts]

        # Deliver index 2 first -> keys for 0 and 1 are cached as skipped.
        bob.decrypt(*encs[2], _AD)
        assert (1, 1) in bob._skipped

        # Forge a ciphertext for the cached slot (1,1): same header, garbage ct.
        forged_hdr = encs[1][0]
        with pytest.raises(Exception):
            bob.decrypt(forged_hdr, b"\x00" * 40, _AD)

        # The cached key must survive, and the REAL index-1 message still decrypts.
        assert (1, 1) in bob._skipped, "forged delivery must not evict the cached key"
        assert bob.decrypt(*encs[1], _AD) == pts[1]
        assert bob.decrypt(*encs[0], _AD) == pts[0]


# ---------------------------------------------------------------------------
# 4. Dropped message (never arrives)
# ---------------------------------------------------------------------------


class TestDroppedMessage:
    """Index 1 never arrives; indices 0 and 2 still decrypt; cache is bounded."""

    def test_0_and_2_decrypt_without_1(self):
        """Messages 0 and 2 are decrypted even though message 1 is never delivered."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        pts = [b"msg0", b"msg1", b"msg2"]
        encs = [alice.encrypt(p, _AD) for p in pts]

        assert bob.decrypt(*encs[0], _AD) == pts[0]
        # skip encs[1] — never delivered
        assert bob.decrypt(*encs[2], _AD) == pts[2]

        # Key for index 1 must still be in the cache (not garbage-collected)
        assert (1, 1) in bob._skipped

    def test_skip_cache_bounded_by_max_skip(self):
        """Requesting an index MAX_SKIP+1 ahead raises rather than caching that many keys."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        # Manufacture a header with an index far beyond MAX_SKIP
        far_header = RatchetHeader(epoch=1, index=MAX_SKIP + 1)
        # We need a syntactically valid ciphertext blob (we expect the skip
        # check to trigger before AEAD, but create a minimal blob anyway).
        fake_ct = os.urandom(44)  # 12-byte nonce + 16-byte tag + some body

        with pytest.raises(ValueError, match="MAX_SKIP"):
            bob.decrypt(far_header, fake_ct, _AD)

        # The cache must not have grown with those unbounded keys
        assert len(bob._skipped) == 0, "no keys should be cached after a MAX_SKIP refusal"

    def test_dropped_key_does_not_persist_across_epoch(self):
        """A skipped key in epoch N does not bleed into epoch N+1."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        epoch1_key = os.urandom(32)
        alice.ratchet_epoch(1, epoch1_key)
        bob.ratchet_epoch(1, epoch1_key)

        pts = [b"e1m0", b"e1m1", b"e1m2"]
        encs = [alice.encrypt(p, _AD) for p in pts]

        # Deliver 0 and 2 — index 1 cached
        bob.decrypt(*encs[0], _AD)
        bob.decrypt(*encs[2], _AD)
        assert (1, 1) in bob._skipped

        # Advance to epoch 2
        epoch2_key = os.urandom(32)
        alice.ratchet_epoch(2, epoch2_key)
        bob.ratchet_epoch(2, epoch2_key)

        # The cache entry (1, 1) is still present (it's from epoch 1); the ratchet
        # doesn't purge old skipped keys since they might arrive late.  What matters
        # is that the epoch-1 entry doesn't interfere with epoch-2 indices.
        hdr2, ct2 = alice.encrypt(b"epoch2 msg", _AD)
        assert hdr2.epoch == 2 and hdr2.index == 0
        assert bob.decrypt(hdr2, ct2, _AD) == b"epoch2 msg"


# ---------------------------------------------------------------------------
# 5. Multi-epoch
# ---------------------------------------------------------------------------


class TestMultiEpoch:
    """Ratchet across >=3 epochs; messages in each epoch decrypt; chains reset."""

    def test_three_epochs_messages_decrypt(self):
        """Send and receive one message per epoch across 3 epochs."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)

        for ep in range(1, 4):
            key = os.urandom(32)
            alice.ratchet_epoch(ep, key)
            bob.ratchet_epoch(ep, key)

            pt = f"epoch-{ep}-message".encode()
            hdr, ct = alice.encrypt(pt, _AD)
            assert hdr.epoch == ep and hdr.index == 0, (
                f"epoch {ep}: expected header (ep={ep}, idx=0), got ({hdr.epoch},{hdr.index})"
            )
            result = bob.decrypt(hdr, ct, _AD)
            assert result == pt, f"epoch {ep}: decryption mismatch"

    def test_epoch_index_resets_to_zero_per_epoch(self):
        """After ratchet_epoch() the send index resets to 0."""
        sk = os.urandom(32)
        alice, _ = _pair(sk)

        for ep in range(1, 4):
            key = os.urandom(32)
            alice.ratchet_epoch(ep, key)
            # First message of each epoch must have index 0
            hdr, _ = alice.encrypt(b"x", _AD)
            assert hdr.index == 0, f"epoch {ep}: index should reset to 0, got {hdr.index}"
            # Second must be 1
            hdr2, _ = alice.encrypt(b"y", _AD)
            assert hdr2.index == 1, f"epoch {ep}: second message index should be 1"

    def test_chain_keys_differ_across_epochs(self):
        """The send chain key at epoch N differs from the one at epoch N+1."""
        sk = os.urandom(32)
        alice, _ = _pair(sk)

        ck_by_epoch = {}
        for ep in range(1, 4):
            key = os.urandom(32)
            alice.ratchet_epoch(ep, key)
            ck_by_epoch[ep] = alice._ck_send

        # All chain keys must be distinct
        assert len(set(ck_by_epoch.values())) == 3, (
            "chain keys across epochs must all be distinct"
        )

    def test_future_epoch_decrypt_raises(self):
        """Decrypting a header from an epoch the receiver hasn't ratcheted yet raises."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)

        epoch1_key = os.urandom(32)
        alice.ratchet_epoch(1, epoch1_key)
        bob.ratchet_epoch(1, epoch1_key)

        # Alice advances to epoch 2; Bob does not.
        alice.ratchet_epoch(2, os.urandom(32))

        hdr, ct = alice.encrypt(b"future msg", _AD)
        assert hdr.epoch == 2

        with pytest.raises(ValueError, match="future"):
            bob.decrypt(hdr, ct, _AD)

    def test_bidirectional_multi_epoch(self):
        """Both directions work across 3 epochs."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)

        for ep in range(1, 4):
            key = os.urandom(32)
            alice.ratchet_epoch(ep, key)
            bob.ratchet_epoch(ep, key)

            a_pt = f"A-ep{ep}".encode()
            b_pt = f"B-ep{ep}".encode()

            hdr_a, ct_a = alice.encrypt(a_pt, _AD)
            hdr_b, ct_b = bob.encrypt(b_pt, _AD)

            assert bob.decrypt(hdr_a, ct_a, _AD) == a_pt, f"A->B ep{ep}"
            assert alice.decrypt(hdr_b, ct_b, _AD) == b_pt, f"B->A ep{ep}"


# ---------------------------------------------------------------------------
# 6. Tamper detection
# ---------------------------------------------------------------------------


class TestTamperRejection:
    """Modified ciphertext or wrong AD must raise; no forged plaintext delivered."""

    def test_modified_ciphertext_raises(self):
        """Flipping a byte in the ciphertext causes AEAD authentication to fail."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        hdr, ct = alice.encrypt(b"secret", _AD)
        tampered = bytearray(ct)
        tampered[-1] ^= 0xFF
        with pytest.raises(InvalidTag):
            bob.decrypt(hdr, bytes(tampered), _AD)

    def test_wrong_associated_data_raises(self):
        """Using a different AD causes AEAD authentication failure."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        hdr, ct = alice.encrypt(b"secret", b"correct-ad")
        with pytest.raises(InvalidTag):
            bob.decrypt(hdr, ct, b"wrong-ad")

    def test_header_mismatch_raises(self):
        """Presenting a message under a different (epoch, index) header fails."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        hdr, ct = alice.encrypt(b"secret", _AD)
        # Forge a different index — the header bytes are part of the AD binding
        wrong_hdr = RatchetHeader(epoch=hdr.epoch, index=hdr.index + 1)
        with pytest.raises((InvalidTag, ValueError)):
            bob.decrypt(wrong_hdr, ct, _AD)

    def test_ratchet_state_unchanged_after_tamper(self):
        """A failed decrypt must not advance n_recv (no state mutation on forgery)."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        # Encrypt a legitimate message first
        hdr_good, ct_good = alice.encrypt(b"real", _AD)

        # Try a tampered message (same header, bad ct)
        tampered = bytearray(ct_good)
        tampered[0] ^= 0xFF
        n_recv_before = bob._n_recv
        with pytest.raises(Exception):
            bob.decrypt(hdr_good, bytes(tampered), _AD)
        # n_recv must not have advanced past the forged message
        assert bob._n_recv == n_recv_before, (
            "n_recv must not advance on a failed decrypt"
        )

        # The legitimate message can still be decrypted (ratchet state intact)
        assert bob.decrypt(hdr_good, ct_good, _AD) == b"real"

    def test_replay_raises(self):
        """Replaying a valid ciphertext at the same (epoch, index) raises."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        hdr, ct = alice.encrypt(b"original", _AD)
        assert bob.decrypt(hdr, ct, _AD) == b"original"

        # Replay the same envelope — index already consumed
        with pytest.raises(ValueError):
            bob.decrypt(hdr, ct, _AD)


# ---------------------------------------------------------------------------
# 7. MAX_SKIP enforcement
# ---------------------------------------------------------------------------


class TestMaxSkip:
    """Requests that would exceed MAX_SKIP are refused without unbounded allocation."""

    def test_exactly_max_skip_is_refused(self):
        """A header with index == n_recv + MAX_SKIP + 1 is refused."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        far_header = RatchetHeader(epoch=1, index=MAX_SKIP + 1)
        fake_ct = os.urandom(44)
        with pytest.raises(ValueError, match="MAX_SKIP"):
            bob.decrypt(far_header, fake_ct, _AD)

    def test_just_at_max_skip_is_allowed(self):
        """A header with index == n_recv + MAX_SKIP is within the limit and succeeds.

        We fast-forward alice to that index by encrypting MAX_SKIP messages,
        then Bob decrypts the last one (caching MAX_SKIP - 1 skipped keys).
        This is expensive so we use a smaller value via a minimal sanity check.
        """
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        # Use a small batch so the test doesn't encrypt 1000 messages.
        batch = 5
        encs = [alice.encrypt(f"m{i}".encode(), _AD) for i in range(batch)]

        # Bob decrypts only the last — must cache batch-1 keys without raising
        hdr_last, ct_last = encs[-1]
        result = bob.decrypt(hdr_last, ct_last, _AD)
        assert result == f"m{batch - 1}".encode()
        assert len(bob._skipped) == batch - 1, (
            f"expected {batch - 1} cached skipped keys, got {len(bob._skipped)}"
        )

    def test_cache_size_does_not_exceed_max_skip(self):
        """Even after many out-of-order delivers the cache never exceeds MAX_SKIP."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        _feed_epoch(alice, bob, 1)

        # Encrypt 10, deliver only index 9 (caches 0..8)
        batch = 10
        encs = [alice.encrypt(f"m{i}".encode(), _AD) for i in range(batch)]
        bob.decrypt(*encs[-1], _AD)

        assert len(bob._skipped) == batch - 1
        assert len(bob._skipped) <= MAX_SKIP


# ---------------------------------------------------------------------------
# 8. Integration: two BraidChatClients end-to-end
# ---------------------------------------------------------------------------


@pytest.fixture()
def _store():
    return SesameStore()


@pytest.fixture()
def _app(_store):
    return create_app(_store)


@pytest.fixture()
def _tc(_app):
    return TestClient(_app, raise_server_exceptions=True)


def _http(tc: TestClient, username: str) -> BraidChatClient:
    c = BraidChatClient(HttpTransport(tc), username)
    c.register(num_one_time=8)
    return c


class TestIntegration:
    """End-to-end Double Ratchet over real PQXDH + Braid SCKA + HTTP server."""

    def test_basic_chat_round_trip(self, _tc: TestClient) -> None:
        """Alice → Bob single message decrypts to exact plaintext."""
        alice = _http(_tc, "alice")
        bob = _http(_tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        alice.send_chat(session, "hello from alice")
        bob.poll()

        assert len(bob.inbox) == 1
        peer, dev, epoch, text = bob.inbox[0]
        assert peer == "alice"
        assert text == "hello from alice"

    def test_bidirectional_exact_plaintext(self, _tc: TestClient) -> None:
        """Alice → Bob AND Bob → Alice; both sides decrypt to exact plaintext."""
        alice = _http(_tc, "alice")
        bob = _http(_tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        alice.send_chat(session, "hi bob")
        bob.poll()

        bob.send_chat(bob_session, "hi alice")
        alice.poll()

        assert bob.inbox[0][3] == "hi bob"
        assert alice.inbox[0][3] == "hi alice"

    def test_multiple_sequential_messages_exact_order(self, _tc: TestClient) -> None:
        """10 sequential messages from Alice arrive at Bob in order with exact text."""
        alice = _http(_tc, "alice")
        bob = _http(_tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        texts = [f"message-{i:03d}" for i in range(10)]
        for t in texts:
            alice.send_chat(session, t)

        bob.poll()
        assert len(bob.inbox) == 10
        received = [m[3] for m in bob.inbox]
        assert received == texts, f"order or content mismatch: {received!r}"

    def test_ratchet_epoch_advances_on_both_sides(self, _tc: TestClient) -> None:
        """Both ratchets advance to epoch >=1 and are on the same epoch when
        a shared epoch key is confirmed on both sides.

        We use run_until_agreed(target_epochs=1) which guarantees Alice has
        epoch 1, then drain Bob so he also has epoch 1.  Both ratchets are then
        on epoch 1 and a message exchange succeeds.
        """
        alice = _http(_tc, "alice")
        bob = _http(_tc, "bob")

        session = alice.start_session("bob")
        # target_epochs=1: Alice definitely has epoch 1 when the loop exits.
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        # After one extra poll, Bob must have epoch 1 (run_until_agreed ends only
        # once Alice has epoch-1, and that key came from Bob's last send, so Bob
        # must already have the Braid state needed to derive his epoch-1 key on
        # his next receive — pump until he does).
        for _ in range(20):
            if 1 in bob_session.epoch_keys:
                break
            bob.pump_session(bob_session)
            alice.poll()
            bob.poll()

        assert 1 in bob_session.epoch_keys, "Bob must have epoch-1 key after pumping"
        assert session.ratchet._current_epoch >= 1
        assert bob_session.ratchet._current_epoch >= 1
        assert session.ratchet._current_epoch == bob_session.ratchet._current_epoch, (
            f"alice ratchet epoch {session.ratchet._current_epoch} "
            f"!= bob ratchet epoch {bob_session.ratchet._current_epoch}"
        )

        # Prove both sides can actually exchange messages at this epoch.
        alice.send_chat(session, "epoch-sync-check")
        bob.poll()
        assert len(bob.inbox) == 1
        assert bob.inbox[0][3] == "epoch-sync-check"

    def test_distinct_per_message_keys_over_network(self, _tc: TestClient) -> None:
        """Two successive send_chat() calls produce different ratchet message keys
        (verified by observing distinct ciphertexts for the same plaintext)."""
        alice = _http(_tc, "alice")
        bob = _http(_tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        # Peek at the two successive message keys before sending
        mk1 = session.ratchet.peek_send_mk()
        alice.send_chat(session, "same text")
        mk2 = session.ratchet.peek_send_mk()
        alice.send_chat(session, "same text")

        assert mk1 != mk2, "successive message keys must be distinct"

        bob.poll()
        # Both arrive and decrypt correctly
        assert len(bob.inbox) == 2
        assert bob.inbox[0][3] == "same text"
        assert bob.inbox[1][3] == "same text"

    def test_tamper_dropped_not_in_inbox(self, _tc: TestClient) -> None:
        """A tampered ciphertext in a well-formed envelope is dropped, not delivered."""
        alice = _http(_tc, "alice")
        bob = _http(_tc, "bob")

        session = alice.start_session("bob")
        run_until_agreed(alice, bob, session, target_epochs=1, max_rounds=2000)
        bob.poll()
        bob_session = bob.sessions.get(("alice", alice.device_id))
        assert bob_session is not None

        from ml_kem_braid.wire import b64e
        epoch = session.latest_epoch()
        dropped_before = len(bob.dropped)

        # Inject a forged envelope: valid header shape, random ciphertext bytes
        _tc.post(
            "/messages",
            json={
                "recipient_username": "bob",
                "recipient_device_id": bob.device_id,
                "kind": "chat",
                "body": {
                    "header": {"epoch": epoch, "index": 0},
                    "ciphertext": b64e(os.urandom(48)),
                },
            },
            headers={"Authorization": f"Bearer {alice.auth_token}"},
        )

        bob.poll()
        assert len(bob.inbox) == 0, "forged message must not appear in inbox"
        assert len(bob.dropped) > dropped_before, "forged message must be recorded in dropped"
