"""Skipped-key store bounds and cross-epoch reordering (audit findings M3, L8).

M3: MAX_SKIP capped per-message catch-up, but nothing capped cumulative
    ``_skipped`` growth and a new epoch never pruned stale entries. An
    authenticated peer sending at sparse ascending indices grew it without limit.
L8: a message from epoch N-1 that arrived after ratcheting to epoch N was
    permanently undecryptable, because the previous receive chain was discarded.
"""

import os

import pytest

from ml_kem_braid.core.double_ratchet import (
    MAX_SKIP,
    RETAINED_RECV_EPOCHS,
    DoubleRatchet,
    RatchetHeader,
    Role,
    SkippedKeyLimitError,
)

_AD = b"ad"


def _pair(sk: bytes):
    return DoubleRatchet(sk, Role.ALICE), DoubleRatchet(sk, Role.BOB)


# ---------------------------------------------------------------------------
# M3 — global cap on the skipped-key store
# ---------------------------------------------------------------------------


class TestGlobalSkipCap:
    def test_sparse_ascending_indices_do_not_grow_store_without_bound(self):
        """The historical attack: repeatedly jump ahead by a large-but-legal gap.

        Each individual decrypt stays under MAX_SKIP, but cumulatively the store
        used to grow without limit. The bound still holds — and past the bound the
        receiver REFUSES (D7) rather than discarding cached authentic keys.
        """
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        key = os.urandom(32)
        alice.ratchet_epoch(1, key)
        bob.ratchet_epoch(1, key)

        gap = 400
        refusals = 0
        for _ in range(10):
            for _ in range(gap):
                alice.encrypt(b"x", _AD)
            hdr, ct = alice.encrypt(b"payload", _AD)
            try:
                assert bob.decrypt(hdr, ct, _AD) == b"payload"
            except ValueError as exc:  # SkippedKeyLimitError or the MAX_SKIP gap cap
                refusals += 1
                assert isinstance(exc, SkippedKeyLimitError) or "MAX_SKIP" in str(exc)
            assert len(bob._skipped) <= MAX_SKIP, (
                f"skipped store grew to {len(bob._skipped)} > MAX_SKIP={MAX_SKIP}"
            )

        assert len(bob._skipped) <= MAX_SKIP
        assert refusals > 0, "the store must fail closed once saturated"

    def test_store_fails_closed_instead_of_evicting_authentic_keys(self):
        """D7: the global cap must never destroy a legitimate reordered message.

        Old behaviour evicted ``(1, 0)`` — the key for an authentic, merely
        delayed message — so that message became permanently undecryptable and
        nothing anywhere reported it.
        """
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        key = os.urandom(32)
        alice.ratchet_epoch(1, key)
        bob.ratchet_epoch(1, key)

        # An authentic early message that will be delayed on the wire.
        delayed = alice.encrypt(b"delayed authentic message", _AD)
        assert delayed[0].index == 0

        # Fill the skipped store right up to the cap.
        for _ in range(MAX_SKIP - 1):
            alice.encrypt(b"x", _AD)
        hdr, ct = alice.encrypt(b"first", _AD)
        assert bob.decrypt(hdr, ct, _AD) == b"first"
        assert (1, 0) in bob._skipped
        assert len(bob._skipped) == MAX_SKIP

        # Attacker/peer now jumps further ahead. The receiver must refuse.
        for _ in range(50):
            alice.encrypt(b"x", _AD)
        hdr2, ct2 = alice.encrypt(b"second", _AD)
        with pytest.raises(SkippedKeyLimitError):
            bob.decrypt(hdr2, ct2, _AD)

        assert len(bob._skipped) <= MAX_SKIP
        assert (1, 0) in bob._skipped, "authentic cached key must survive"
        # And the delayed authentic message still decrypts.
        assert bob.decrypt(*delayed, _AD) == b"delayed authentic message"

    def test_skipped_key_limit_error_is_a_value_error(self):
        assert issubclass(SkippedKeyLimitError, ValueError)

    def test_refusal_does_not_mutate_receive_state(self):
        """A refused over-cap message leaves the ratchet exactly as it was."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        key = os.urandom(32)
        alice.ratchet_epoch(1, key)
        bob.ratchet_epoch(1, key)

        for _ in range(MAX_SKIP - 1):
            alice.encrypt(b"x", _AD)
        hdr, ct = alice.encrypt(b"first", _AD)
        bob.decrypt(hdr, ct, _AD)

        before_ck, before_n = bob._ck_recv, bob._n_recv
        before_len = len(bob._skipped)

        for _ in range(5):
            alice.encrypt(b"x", _AD)
        hdr2, ct2 = alice.encrypt(b"second", _AD)
        with pytest.raises(SkippedKeyLimitError):
            bob.decrypt(hdr2, ct2, _AD)

        assert bob._ck_recv == before_ck
        assert bob._n_recv == before_n
        assert len(bob._skipped) == before_len

    def test_epoch_ratchet_frees_the_store_after_saturation(self):
        """The refusal is recoverable: pruning on ratchet restores capacity."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        k1 = os.urandom(32)
        alice.ratchet_epoch(1, k1)
        bob.ratchet_epoch(1, k1)

        for _ in range(MAX_SKIP):
            alice.encrypt(b"x", _AD)
        hdr, ct = alice.encrypt(b"saturate", _AD)
        bob.decrypt(hdr, ct, _AD)
        assert len(bob._skipped) == MAX_SKIP

        # Move two epochs on so epoch-1 keys fall outside the retention window.
        for ep in (2, 3):
            k = os.urandom(32)
            alice.ratchet_epoch(ep, k)
            bob.ratchet_epoch(ep, k)
        assert len(bob._skipped) == 0

        for _ in range(10):
            alice.encrypt(b"x", _AD)
        hdr3, ct3 = alice.encrypt(b"after", _AD)
        assert bob.decrypt(hdr3, ct3, _AD) == b"after"

    def test_stale_epoch_keys_are_pruned_on_ratchet(self):
        sk = os.urandom(32)
        alice, bob = _pair(sk)

        k1 = os.urandom(32)
        alice.ratchet_epoch(1, k1)
        bob.ratchet_epoch(1, k1)
        encs = [alice.encrypt(f"m{i}".encode(), _AD) for i in range(3)]
        bob.decrypt(*encs[2], _AD)  # caches (1,0) and (1,1)
        assert (1, 0) in bob._skipped

        # Advance far enough that epoch 1 falls outside the retention window.
        for ep in range(2, 2 + RETAINED_RECV_EPOCHS + 1):
            key = os.urandom(32)
            alice.ratchet_epoch(ep, key)
            bob.ratchet_epoch(ep, key)

        assert not any(e == 1 for e, _ in bob._skipped), (
            "epoch-1 keys should be pruned once outside the retention window"
        )


# ---------------------------------------------------------------------------
# L8 — bounded cross-epoch reordering window
# ---------------------------------------------------------------------------


class TestCrossEpochReordering:
    def test_previous_epoch_message_still_decrypts_after_ratchet(self):
        sk = os.urandom(32)
        alice, bob = _pair(sk)

        k1 = os.urandom(32)
        alice.ratchet_epoch(1, k1)
        bob.ratchet_epoch(1, k1)
        late_hdr, late_ct = alice.encrypt(b"late epoch-1 message", _AD)

        k2 = os.urandom(32)
        alice.ratchet_epoch(2, k2)
        bob.ratchet_epoch(2, k2)
        hdr2, ct2 = alice.encrypt(b"epoch-2", _AD)
        assert bob.decrypt(hdr2, ct2, _AD) == b"epoch-2"

        # The reordered epoch-1 message must still decrypt.
        assert bob.decrypt(late_hdr, late_ct, _AD) == b"late epoch-1 message"

    def test_previous_epoch_out_of_order_indices(self):
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        k1 = os.urandom(32)
        alice.ratchet_epoch(1, k1)
        bob.ratchet_epoch(1, k1)
        encs = [alice.encrypt(f"e1-{i}".encode(), _AD) for i in range(3)]

        k2 = os.urandom(32)
        alice.ratchet_epoch(2, k2)
        bob.ratchet_epoch(2, k2)

        assert bob.decrypt(*encs[2], _AD) == b"e1-2"
        assert bob.decrypt(*encs[0], _AD) == b"e1-0"
        assert bob.decrypt(*encs[1], _AD) == b"e1-1"

    def test_epoch_beyond_retention_window_is_refused(self):
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        k1 = os.urandom(32)
        alice.ratchet_epoch(1, k1)
        bob.ratchet_epoch(1, k1)
        old_hdr, old_ct = alice.encrypt(b"ancient", _AD)

        for ep in range(2, 2 + RETAINED_RECV_EPOCHS + 1):
            key = os.urandom(32)
            alice.ratchet_epoch(ep, key)
            bob.ratchet_epoch(ep, key)

        with pytest.raises(ValueError, match="no cached key"):
            bob.decrypt(old_hdr, old_ct, _AD)

    def test_previous_epoch_skip_is_bounded(self):
        """Catch-up on the retained previous epoch obeys MAX_SKIP too."""
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        k1 = os.urandom(32)
        alice.ratchet_epoch(1, k1)
        bob.ratchet_epoch(1, k1)

        k2 = os.urandom(32)
        alice.ratchet_epoch(2, k2)
        bob.ratchet_epoch(2, k2)

        forged = RatchetHeader(epoch=1, index=MAX_SKIP + 5)
        with pytest.raises(ValueError, match="MAX_SKIP"):
            bob.decrypt(forged, b"\x00" * 64, _AD)
        assert len(bob._skipped) == 0

    def test_forged_previous_epoch_message_does_not_advance_state(self):
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        k1 = os.urandom(32)
        alice.ratchet_epoch(1, k1)
        bob.ratchet_epoch(1, k1)
        good = alice.encrypt(b"real", _AD)

        k2 = os.urandom(32)
        alice.ratchet_epoch(2, k2)
        bob.ratchet_epoch(2, k2)

        from cryptography.exceptions import InvalidTag

        forged_hdr = RatchetHeader(epoch=1, index=0)
        with pytest.raises(InvalidTag):
            bob.decrypt(forged_hdr, b"\x00" * 64, _AD)

        # State untouched: the genuine message still decrypts.
        assert bob.decrypt(*good, _AD) == b"real"

    def test_previous_epoch_replay_refused(self):
        sk = os.urandom(32)
        alice, bob = _pair(sk)
        k1 = os.urandom(32)
        alice.ratchet_epoch(1, k1)
        bob.ratchet_epoch(1, k1)
        hdr, ct = alice.encrypt(b"once", _AD)
        bob.decrypt(hdr, ct, _AD)

        k2 = os.urandom(32)
        alice.ratchet_epoch(2, k2)
        bob.ratchet_epoch(2, k2)

        with pytest.raises(ValueError):
            bob.decrypt(hdr, ct, _AD)
