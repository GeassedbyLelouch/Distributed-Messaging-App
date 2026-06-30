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
``skipped[(epoch, index)] -> mk``. If more than MAX_SKIP keys would need to be
cached, decryption refuses (prevents unbounded state growth under attack).

Reference: Signal Double Ratchet spec, sections 2 and 3.
    https://signal.org/docs/specifications/doubleratchet/
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional, Tuple

from ml_kem_braid.core.kdf import hkdf

# Maximum number of out-of-order message keys cached per ratchet state.
# Exceeding this bound causes decrypt() to raise rather than allocating further.
MAX_SKIP = 1000

_HKDF_SALT_ZEROS = b"\x00" * 32
_DR_ROOT_INFO = b"MLKEMBraid-DR-root"
_INFO_ATOB = b"A->B"
_INFO_BTOA = b"B->A"


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
        # (epoch, index) -> message_key for out-of-order messages
        self._skipped: Dict[Tuple[int, int], bytes] = {}

    # -- public API -----------------------------------------------------------

    def ratchet_epoch(self, epoch: int, epoch_key: bytes) -> None:
        """Advance to a new SCKA epoch.

        Both parties MUST call this with the same (epoch, epoch_key) pair.
        The directional split ensures Alice's send chain != Bob's send chain.

        Raises ValueError if ``epoch`` is not strictly greater than the
        current epoch (idempotent calls are rejected to prevent accidental
        epoch rewinds).
        """
        if epoch <= self._current_epoch:
            raise ValueError(
                f"ratchet_epoch: epoch {epoch} is not newer than current "
                f"{self._current_epoch}"
            )
        self._rk, chain_seed = _kdf_rk(self._rk, epoch_key)
        ck_atob, ck_btoa = _derive_directional_chains(chain_seed)

        if self._role == Role.ALICE:
            self._ck_send = ck_atob
            self._ck_recv = ck_btoa
        else:
            self._ck_send = ck_btoa
            self._ck_recv = ck_atob

        self._n_send = 0
        self._n_recv = 0
        self._current_epoch = epoch

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
        # Bind the header into the AD
        full_ad = associated_data + _header_bytes(header)
        from ml_kem_braid.core.aead import aead_encrypt
        ct = aead_encrypt(mk, plaintext, full_ad)
        return header, ct

    def decrypt(self, header: RatchetHeader, ciphertext: bytes, associated_data: bytes) -> bytes:
        """Decrypt ``ciphertext`` using the receiving chain.

        Handles out-of-order messages via the skipped-key cache.
        Raises:
          - RuntimeError  : if ratchet_epoch() hasn't been called yet
          - ValueError    : if header.epoch is in the future (caller must
                            ratchet_epoch first once the SCKA agrees it)
          - ValueError    : if MAX_SKIP would be exceeded to catch up to header.index
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
        full_ad = associated_data + _header_bytes(header)

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
            return plaintext

        if header.epoch < self._current_epoch:
            # Past epoch not in the cache — unrecoverable
            raise ValueError(
                f"decrypt: no cached key for epoch {header.epoch} "
                f"index {header.index}"
            )

        # header.epoch == self._current_epoch
        # Skip-ahead: cache intermediate message keys up to header.index
        if header.index < self._n_recv:
            raise ValueError(
                f"decrypt: index {header.index} already consumed "
                f"(n_recv={self._n_recv})"
            )
        skip_count = header.index - self._n_recv
        if skip_count > MAX_SKIP:
            raise ValueError(
                f"decrypt: would skip {skip_count} messages (MAX_SKIP={MAX_SKIP}); "
                "refusing to cache that many keys"
            )

        # Walk the chain from n_recv to header.index, staging all state changes.
        # We commit to _ck_recv / _n_recv / _skipped only AFTER successful AEAD
        # so a forged message cannot advance ratchet state.
        ck = self._ck_recv
        new_skipped: Dict[Tuple[int, int], bytes] = {}
        for i in range(self._n_recv, header.index):
            ck, mk_skip = _kdf_ck(ck)
            new_skipped[(self._current_epoch, i)] = mk_skip

        # Derive the actual message key for header.index
        ck_next, mk = _kdf_ck(ck)

        # Attempt AEAD; raises on tamper — no state has been committed yet.
        from ml_kem_braid.core.aead import aead_decrypt
        plaintext = aead_decrypt(mk, ciphertext, full_ad)

        # Commit state only after successful authentication.
        self._skipped.update(new_skipped)
        self._ck_recv = ck_next
        self._n_recv = header.index + 1
        return plaintext

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
    """Encode header as canonical bytes for AD binding."""
    return (
        b"hdr:"
        + header.epoch.to_bytes(8, "big")
        + header.index.to_bytes(8, "big")
    )
