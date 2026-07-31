"""
Signal-style Double Ratchet layered over the ML-KEM Braid SCKA.

Construction
-----------
The ML-KEM Braid SCKA already provides a shared 32-byte epoch key to both
parties each epoch (Role.ALICE and Role.BOB). This plays the role of the
Double Ratchet's asymmetric DH ratchet input, but it is SYMMETRIC — both
parties receive the same value. To avoid both parties deriving the same
sending chain (which would cause key/nonce reuse), we split the epoch
material into directional chains via domain-separated HKDF:

    CK_AtoB = HKDF(ikm=chain_seed, info=b"A->B", 32)
    CK_BtoA = HKDF(ikm=chain_seed, info=b"B->A", 32)

Alice (Role.ALICE) sends on CK_AtoB and receives on CK_BtoA; Bob vice-versa.

Within each chain direction, per-message keys follow the Signal chain step:

    mk  = HMAC-SHA256(ck, b"\\x01")   # 32-byte AES-256 message key
    ck' = HMAC-SHA256(ck, b"\\x02")   # advance chain

Forward secrecy: mk is used immediately then discarded; ck is overwritten.
Post-compromise security: a fresh epoch key advances the root key, providing
break-in recovery proportional to the Braid SCKA's PCS guarantees.

Out-of-order / dropped messages: up to MAX_SKIP message keys may be cached in
``skipped[(epoch, index)] -> mk``. MAX_SKIP is BOTH the per-message catch-up bound
and a GLOBAL bound on ``len(skipped)`` across all epochs (audit finding M3). Keys
older than ``RETAINED_RECV_EPOCHS`` epochs are pruned on every ratchet.

Skipped-key store: fail closed, do NOT evict (post-audit hardening D7)
---------------------------------------------------------------------
The first fix for M3 enforced the global bound by evicting the oldest
``(epoch, index)`` entries. That converted a bounded-memory DoS into *permanent,
silent loss of authentic traffic*: an on-path attacker who reorders or delays a
message only has to make the receiver skip ahead ``MAX_SKIP`` more slots and the
genuine delayed message becomes undecryptable forever, with no error anywhere.

The store therefore now **refuses** to create skipped keys once the global bound
would be exceeded, raising :class:`SkippedKeyLimitError` (a ``ValueError``). The
DoS bound is preserved exactly — ``len(skipped) <= MAX_SKIP`` always — but the
failure mode is a loud, recoverable rejection of the *new* message instead of the
silent destruction of an *old* one. The trade-off: a peer that jumps far ahead
while the store is saturated is refused until an epoch ratchet prunes stale
entries (``_prune_stale``) or the cached keys are consumed by the messages they
belong to. Refusing a message the receiver cannot serve without discarding
authentic key material is the correct direction to fail.

Cross-epoch reordering: the previous epoch's receive chain is retained for a bounded
window so legitimately reordered messages from epoch N-1 still decrypt after
ratcheting to epoch N (audit finding L8). Anything older is refused.

Key hygiene (audit finding L5): Python ``bytes`` are immutable, so keys cannot be
wiped in place. This module does a best-effort pass only — references to chain,
root and message keys are dropped with ``del`` as soon as they are consumed, and no
gratuitous copies are made. True zeroization is deferred to the Rust port, where
chain-step functions consume keys by value and keys are ``Zeroizing<[u8; 32]>``.

Reference: Signal Double Ratchet spec, sections 2 and 3.
    https://signal.org/docs/specifications/doubleratchet/
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional, Tuple

from ml_kem_braid.core.kdf import hkdf

# Maximum number of out-of-order message keys cached per ratchet state.
# This is both the per-decrypt catch-up bound AND the global bound on the total
# size of the skipped-key store. Exceeding EITHER bound causes decrypt() to raise
# (fail closed); no cached key is ever evicted to make room. See the module
# docstring, "Skipped-key store: fail closed, do NOT evict".
MAX_SKIP = 1000

# How many *previous* epochs' receive chains / skipped keys are retained so that
# legitimately reordered messages still decrypt (audit finding L8). Keep tight:
# every retained epoch is attacker-reachable state, bounded overall by MAX_SKIP.
RETAINED_RECV_EPOCHS = 1

_HKDF_SALT_ZEROS = b"\x00" * 32
_DR_ROOT_INFO = b"MLKEMBraid-DR-root"
_INFO_ATOB = b"A->B"
_INFO_BTOA = b"B->A"
# Domain separator for the canonical AEAD associated-data encoding (L6).
_AD_DOMAIN = b"MLKEMBraid-DR-ad-v2"


class SkippedKeyLimitError(ValueError):
    """The receiver refuses to cache more out-of-order message keys (D7).

    Raised when honouring a message would push the skipped-key store past
    ``MAX_SKIP``. The alternative — evicting the oldest cached key — silently
    and permanently destroys an authentic message that has merely been delayed,
    so this fails closed instead: the *new* message is rejected and every
    already-cached key survives.

    Subclasses :class:`ValueError` so callers that already handle the MAX_SKIP
    catch-up rejection need no change; catch it specifically to surface
    "too many messages outstanding, resynchronise" to the user.
    """


class Role(Enum):
    """Directional role in the Double Ratchet, mirroring the Braid role."""
    ALICE = auto()  # initiator; send chain = A->B
    BOB = auto()    # responder;  send chain = B->A


@dataclass
class RatchetHeader:
    """Wire header carried in every chat envelope. Bound into AEAD AD."""

    epoch: int
    index: int

    def to_dict(self) -> dict:
        return {"epoch": self.epoch, "index": self.index}

    @classmethod
    def from_dict(cls, d: dict) -> "RatchetHeader":
        return cls(epoch=int(d["epoch"]), index=int(d["index"]))


# ---------------------------------------------------------------------------
# Internal KDF helpers (all use existing library primitives only)
# ---------------------------------------------------------------------------

def _kdf_rk(rk: bytes, epoch_key: bytes) -> Tuple[bytes, bytes]:
    """Root-key ratchet step.

    KDF_RK(rk, epoch_key):
        HKDF-SHA256(ikm=epoch_key, salt=rk, info=b"MLKEMBraid-DR-root", 64)
    Returns (new_root_key, chain_seed), each 32 bytes.
    """
    out = hkdf(ikm=epoch_key, salt=rk, info=_DR_ROOT_INFO, length=64)
    return out[:32], out[32:]


def _derive_directional_chains(chain_seed: bytes) -> Tuple[bytes, bytes]:
    """Split a chain seed into two directional chain keys.

    CK_AtoB = HKDF(chain_seed, salt=0*32, info=b"A->B", 32)
    CK_BtoA = HKDF(chain_seed, salt=0*32, info=b"B->A", 32)

    Returns (ck_atob, ck_btoa).
    """
    ck_atob = hkdf(ikm=chain_seed, salt=_HKDF_SALT_ZEROS, info=_INFO_ATOB, length=32)
    ck_btoa = hkdf(ikm=chain_seed, salt=_HKDF_SALT_ZEROS, info=_INFO_BTOA, length=32)
    return ck_atob, ck_btoa


def _kdf_ck(ck: bytes) -> Tuple[bytes, bytes]:
    """Signal chain step.

    mk  = HMAC-SHA256(ck, b"\\x01")   — 32-byte message key (AES-256)
    ck' = HMAC-SHA256(ck, b"\\x02")   — next chain key

    Returns (new_ck, mk).
    """
    mk  = _hmac.new(ck, b"\x01", hashlib.sha256).digest()
    ck2 = _hmac.new(ck, b"\x02", hashlib.sha256).digest()
    return ck2, mk


# ---------------------------------------------------------------------------
# DoubleRatchet
# ---------------------------------------------------------------------------

class DoubleRatchet:
    """Per-session Double Ratchet state.

    Seed both sides with the same ``sk`` (PQXDH shared secret) and the same
    ``role``. Feed both with the same epoch-key stream via ``ratchet_epoch``.
    Because the two sides use opposite directional chains, A's ``ck_send`` ==
    B's ``ck_recv`` and vice-versa, so they stay in sync automatically.

    Usage::

        alice = DoubleRatchet(sk, Role.ALICE)
        bob   = DoubleRatchet(sk, Role.BOB)

        # When the SCKA agrees epoch 1:
        alice.ratchet_epoch(1, epoch1_key)
        bob.ratchet_epoch(1, epoch1_key)

        hdr, ct = alice.encrypt(b"hello", ad)
        plaintext = bob.decrypt(hdr, ct, ad)   # b"hello"
    """

    def __init__(self, sk: bytes, role: Role) -> None:
        """Initialise from a PQXDH shared secret ``sk`` (32 bytes) and a role.

        The SK is used as the initial root key so that the very first
        ratchet_epoch() call mixes in both the PQXDH entropy and the
        first Braid epoch key.
        """
        if len(sk) != 32:
            raise ValueError(f"sk must be 32 bytes, got {len(sk)}")
        self._role = role
        self._rk: bytes = sk            # root key, initialised from PQXDH SK
        self._ck_send: Optional[bytes] = None
        self._ck_recv: Optional[bytes] = None
        self._n_send: int = 0           # messages sent in current epoch
        self._n_recv: int = 0           # next expected receive index in current epoch
        self._current_epoch: int = -1   # -1 = not yet ratcheted
        # (epoch, index) -> message_key for out-of-order messages.
        # Insertion-ordered so the global cap can evict oldest-first.
        self._skipped: "OrderedDict[Tuple[int, int], bytes]" = OrderedDict()
        # Retained receive chains for recent past epochs (L8):
        # epoch -> (chain_key, next_expected_index)
        self._prev_recv: "OrderedDict[int, Tuple[bytes, int]]" = OrderedDict()

    # -- public API -----------------------------------------------------------

    def ratchet_epoch(self, epoch: int, epoch_key: bytes) -> None:
        """Advance to a new SCKA epoch.

        Both parties MUST call this with the same (epoch, epoch_key) pair.
        The directional split ensures Alice's send chain != Bob's send chain.

        Raises ValueError if ``epoch`` is not strictly greater than the
        current epoch (idempotent calls are rejected to prevent accidental
        epoch rewinds).

        The outgoing epoch's receive chain is retained for RETAINED_RECV_EPOCHS
        so reordered messages still decrypt (L8); anything older, including its
        skipped keys, is pruned (M3).
        """
        if epoch <= self._current_epoch:
            raise ValueError(
                f"ratchet_epoch: epoch {epoch} is not newer than current "
                f"{self._current_epoch}"
            )
        self._rk, chain_seed = _kdf_rk(self._rk, epoch_key)
        ck_atob, ck_btoa = _derive_directional_chains(chain_seed)
        del chain_seed  # best-effort hygiene (L5): drop the reference promptly

        # Retain the outgoing receive chain for the bounded reordering window.
        if self._ck_recv is not None and self._current_epoch >= 0:
            self._prev_recv[self._current_epoch] = (self._ck_recv, self._n_recv)

        if self._role == Role.ALICE:
            self._ck_send = ck_atob
            self._ck_recv = ck_btoa
        else:
            self._ck_send = ck_btoa
            self._ck_recv = ck_atob
        del ck_atob, ck_btoa

        self._n_send = 0
        self._n_recv = 0
        self._current_epoch = epoch
        self._prune_stale(epoch)

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> Tuple[RatchetHeader, bytes]:
        """Encrypt ``plaintext`` and advance the sending chain.

        The header {epoch, index} is bound into the AEAD associated data so
        it cannot be stripped or replayed across different positions.
        Returns (header, ciphertext_blob) where blob = nonce || ciphertext || tag.
        """
        if self._ck_send is None:
            raise RuntimeError("ratchet_epoch() must be called before encrypt()")
        self._ck_send, mk = _kdf_ck(self._ck_send)
        header = RatchetHeader(epoch=self._current_epoch, index=self._n_send)
        self._n_send += 1
        # Bind the header into the AD (canonical, length-prefixed: see _bind_ad)
        full_ad = _bind_ad(associated_data, header)
        from ml_kem_braid.core.aead import aead_encrypt
        ct = aead_encrypt(mk, plaintext, full_ad)
        # Best-effort key hygiene (L5): drop the message key immediately. Python
        # bytes are immutable so the buffer cannot be wiped; see module docstring.
        del mk
        return header, ct

    def decrypt(self, header: RatchetHeader, ciphertext: bytes, associated_data: bytes) -> bytes:
        """Decrypt ``ciphertext`` using the receiving chain.

        Handles out-of-order messages via the skipped-key cache.
        Raises:
          - RuntimeError  : if ratchet_epoch() hasn't been called yet
          - ValueError    : if header.epoch is in the future (caller must
                            ratchet_epoch first once the SCKA agrees it)
          - ValueError    : if MAX_SKIP would be exceeded to catch up to header.index
          - SkippedKeyLimitError : if caching the catch-up keys would push the
                            skipped-key store past its GLOBAL MAX_SKIP bound. The
                            store fails closed (this message is refused); it never
                            evicts an already-cached authentic key (D7).
          - cryptography.exceptions.InvalidTag : on AEAD authentication failure
        """
        if self._ck_recv is None:
            raise RuntimeError("ratchet_epoch() must be called before decrypt()")
        if header.epoch > self._current_epoch:
            raise ValueError(
                f"decrypt: epoch {header.epoch} is in the future "
                f"(current epoch {self._current_epoch}); "
                "call ratchet_epoch() first"
            )
        full_ad = _bind_ad(associated_data, header)

        # Try the skipped-key cache first (out-of-order or previously skipped).
        # Verify the AEAD BEFORE evicting the cached key: a forged ciphertext that
        # targets a cached (epoch, index) must not consume the key, or the genuine
        # delayed message for that slot would be permanently undecryptable.
        key = (header.epoch, header.index)
        if key in self._skipped:
            from ml_kem_braid.core.aead import aead_decrypt
            mk = self._skipped[key]
            plaintext = aead_decrypt(mk, ciphertext, full_ad)  # raises before eviction
            del self._skipped[key]
            del mk  # best-effort hygiene (L5)
            return plaintext

        if header.epoch < self._current_epoch:
            # A retained past epoch (bounded reordering window, L8) can still be
            # caught up; anything older is unrecoverable.
            retained = self._prev_recv.get(header.epoch)
            if retained is None:
                raise ValueError(
                    f"decrypt: no cached key for epoch {header.epoch} "
                    f"index {header.index}"
                )
            ck_start, n_recv = retained
            plaintext, ck_next, new_skipped = self._walk_and_open(
                header.epoch, header.index, n_recv, ck_start, ciphertext, full_ad
            )
            # Commit only after successful authentication.
            self._commit_skipped(new_skipped)
            self._prev_recv[header.epoch] = (ck_next, header.index + 1)
            return plaintext

        # header.epoch == self._current_epoch
        plaintext, ck_next, new_skipped = self._walk_and_open(
            self._current_epoch,
            header.index,
            self._n_recv,
            self._ck_recv,
            ciphertext,
            full_ad,
        )

        # Commit state only after successful authentication.
        self._commit_skipped(new_skipped)
        self._ck_recv = ck_next
        self._n_recv = header.index + 1
        return plaintext

    # -- internal helpers -----------------------------------------------------

    def _walk_and_open(
        self,
        epoch: int,
        index: int,
        n_recv: int,
        ck_start: bytes,
        ciphertext: bytes,
        full_ad: bytes,
    ) -> Tuple[bytes, bytes, Dict[Tuple[int, int], bytes]]:
        """Walk a receive chain to ``index``, staging (not committing) all state.

        Returns ``(plaintext, next_chain_key, staged_skipped_keys)``. Raises before
        any state is committed if the catch-up would exceed MAX_SKIP or if the
        AEAD fails, so a forged message cannot advance ratchet state.
        """
        if index < n_recv:
            raise ValueError(
                f"decrypt: index {index} already consumed (n_recv={n_recv})"
            )
        skip_count = index - n_recv
        if skip_count > MAX_SKIP:
            raise ValueError(
                f"decrypt: would skip {skip_count} messages (MAX_SKIP={MAX_SKIP}); "
                "refusing to cache that many keys"
            )
        # GLOBAL bound, checked before any key material is derived or any AEAD is
        # attempted: fail closed rather than evicting authentic cached keys (D7).
        if len(self._skipped) + skip_count > MAX_SKIP:
            raise SkippedKeyLimitError(
                f"decrypt: caching {skip_count} more skipped keys would exceed the "
                f"global bound (have {len(self._skipped)}, MAX_SKIP={MAX_SKIP}); "
                "refusing rather than discarding already-cached authentic keys — "
                "consume outstanding messages or ratchet to a new epoch first"
            )

        ck = ck_start
        new_skipped: Dict[Tuple[int, int], bytes] = {}
        for i in range(n_recv, index):
            ck, mk_skip = _kdf_ck(ck)
            new_skipped[(epoch, i)] = mk_skip

        ck_next, mk = _kdf_ck(ck)
        del ck

        # Attempt AEAD; raises on tamper — no state has been committed yet.
        from ml_kem_braid.core.aead import aead_decrypt
        plaintext = aead_decrypt(mk, ciphertext, full_ad)
        del mk  # best-effort hygiene (L5)
        return plaintext, ck_next, new_skipped

    def _commit_skipped(self, new_skipped: Dict[Tuple[int, int], bytes]) -> None:
        """Insert staged skipped keys, enforcing the GLOBAL cap (audit M3 / D7).

        MAX_SKIP bounds the per-decrypt catch-up; this bounds the cumulative
        store, which a peer sending at sparse ascending indices otherwise grew
        without limit.

        The cap is enforced by REFUSAL, never by eviction. :meth:`_walk_and_open`
        already rejects a message whose catch-up would overflow the store, so
        reaching the guard here means an invariant broke; raising keeps the
        failure loud instead of silently dropping an authentic cached key.
        """
        if len(self._skipped) + len(new_skipped) > MAX_SKIP:
            raise SkippedKeyLimitError(
                f"skipped-key store would exceed MAX_SKIP={MAX_SKIP}; refusing "
                "to evict authentic cached keys"
            )
        for k, v in new_skipped.items():
            self._skipped[k] = v

    def _prune_stale(self, current_epoch: int) -> None:
        """Drop receive chains and skipped keys outside the retention window."""
        oldest = current_epoch - RETAINED_RECV_EPOCHS
        for ep in [e for e in self._prev_recv if e < oldest]:
            del self._prev_recv[ep]
        for k in [k for k in self._skipped if k[0] < oldest]:
            del self._skipped[k]

    # -- test hook ------------------------------------------------------------

    def peek_send_mk(self) -> bytes:
        """Return the NEXT message key that encrypt() would use, without advancing state.

        Used in tests to verify that successive messages use distinct keys.
        """
        if self._ck_send is None:
            raise RuntimeError("ratchet_epoch() must be called first")
        _, mk = _kdf_ck(self._ck_send)
        return mk


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _header_bytes(header: RatchetHeader) -> bytes:
    """Encode header as canonical bytes for AD binding.

    Fixed-width fields, so this component is self-delimiting.
    """
    return (
        b"hdr:"
        + header.epoch.to_bytes(8, "big")
        + header.index.to_bytes(8, "big")
    )


def _bind_ad(associated_data: bytes, header: RatchetHeader) -> bytes:
    """Canonical AEAD associated-data encoding (audit finding L6).

    Previously ``associated_data + _header_bytes(header)`` — a raw concatenation
    of a caller-controlled variable-length value with a fixed-width suffix. No
    splice is exploitable today, but the encoding is not injective in general, so
    the caller-supplied component is now explicitly length-prefixed:

        AD_DOMAIN || u32(len(associated_data)) || associated_data || header_bytes
    """
    return (
        _AD_DOMAIN
        + len(associated_data).to_bytes(4, "big")
        + associated_data
        + _header_bytes(header)
    )
