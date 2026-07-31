"""
Authenticated encryption for chat payloads.

Uses AES-256-GCM from ``cryptography`` (no hand-rolled crypto).

Nonce discipline (audit finding M4)
-----------------------------------
AES-GCM is catastrophically nonce-reuse-brittle: two encryptions under the same
key and nonce leak the GHASH authentication key, which yields universal forgery
under that key — not merely a confidentiality loss for the two colliding
messages. This module therefore offers two disciplined ways to encrypt and no
undisciplined one:

* :func:`aead_encrypt` / :func:`aead_decrypt` — random 96-bit nonce, valid ONLY
  for a single-use key (the Braid/Double-Ratchet message-key model). A second
  encryption attempt under the same key raises :class:`NonceReuseError` instead
  of gambling on the 96-bit birthday bound.
* :func:`aead_encrypt_counter` / :func:`aead_decrypt_counter` and
  :class:`CounterAeadKey` — structurally unique nonces from a monotonic
  ``u64`` counter encoded big-endian into the 12-byte nonce, with EXPLICIT
  rejection at exhaustion (never a silent wrap to 0).

What the single-use-key guard is and is NOT (post-audit hardening D8)
---------------------------------------------------------------------
:func:`claim_single_use` is a **best-effort, process-local, bounded duplicate-use
detector**. It is deliberately NOT advertised as a structural guarantee, because
a hash-set of every key ever used cannot be one. Precisely:

* GUARANTEED — within one process, up to ``single_use_guard_capacity()``
  distinct keys, a second random-nonce encryption under a key already used by
  this process is rejected.
* NOT GUARANTEED — anything across processes, restarts, or machines. Two
  processes holding the same key each believe it unused.
* NOT GUARANTEED — detection beyond the capacity bound. The guard used to evict
  oldest-first there, which silently turned the control OFF after 65536 keys and
  let one session's traffic evict another's record. It now **fails closed**: at
  capacity :func:`claim_single_use` raises :class:`SingleUseGuardExhausted` and
  refuses to encrypt, rather than pretending to a knowledge it no longer has.
  Call :func:`reset_single_use_guard` (only when the key population genuinely
  rotated) or size it with :func:`set_single_use_guard_capacity`.

The ONLY structural nonce-uniqueness guarantee in this module is
:class:`CounterAeadKey` / :func:`aead_encrypt_counter`: uniqueness there follows
from a monotonic counter that cannot wrap, not from remembering anything. Any key
that encrypts more than one message, or that outlives a process, MUST use it.

``associated_data`` is a required argument on every entry point (audit finding
L4) so epoch/header context is always bound into the tag.

The wire format is unchanged: ``nonce || ciphertext || tag``.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
from typing import Set

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96-bit GCM nonce
KEY_SIZE = 32  # AES-256
MAX_COUNTER = (1 << 64) - 1  # monotonic u64 counter nonce space

# Bound on the single-use-key guard. Each entry is a 32-byte fingerprint held in
# a set (no ordering is needed because nothing is ever evicted), so the guard
# costs roughly 20 MiB at capacity. At the bound the guard FAILS CLOSED — see the
# module docstring, "What the single-use-key guard is and is NOT".
DEFAULT_KEY_GUARD_CAPACITY = 1 << 18

# Legacy alias kept for importers that referenced the old constant name.
_KEY_GUARD_CAPACITY = DEFAULT_KEY_GUARD_CAPACITY


class NonceReuseError(ValueError):
    """Raised when an encryption would (or might) repeat an AES-GCM nonce.

    Subclasses ``ValueError`` so existing ``except ValueError`` callers keep
    failing closed.
    """


class SingleUseGuardExhausted(NonceReuseError):
    """The guard can no longer prove this key is unused, so it refuses to encrypt.

    Raised when the bounded single-use-key guard is full. The alternative —
    evicting an older fingerprint — silently disables the control: an unrelated
    session's encryptions push a key's record out and its reuse stops being
    detected. Failing closed keeps the guard honest.

    Recovery: switch the key to :class:`CounterAeadKey` (the structural control),
    size the guard with :func:`set_single_use_guard_capacity`, or — only when the
    key population has genuinely rotated — call :func:`reset_single_use_guard`.
    """


_guard_lock = threading.Lock()
_used_key_fingerprints: Set[bytes] = set()
_guard_capacity: int = DEFAULT_KEY_GUARD_CAPACITY


def _key_fingerprint(key: bytes) -> bytes:
    """Domain-separated fingerprint of a key, so the guard never stores raw keys."""
    return hashlib.blake2b(key, digest_size=32, person=b"MLKEMBraid-1use").digest()


def claim_single_use(key: bytes) -> None:
    """Record ``key`` as consumed by a random-nonce encryption; reject a second use.

    Shared by every random-nonce AEAD entry point in the codebase (including
    :class:`~ml_kem_braid.core.provider.ResearchCryptoProvider`) so one key can
    never produce two independently-nonced ciphertexts *within this process*.

    Scope and limits are stated exactly in the module docstring. In short: this
    is a bounded, process-local duplicate detector, not a structural guarantee.
    It never evicts — at capacity it raises :class:`SingleUseGuardExhausted`.

    Raises:
        NonceReuseError: this key already encrypted under the random-nonce path.
        SingleUseGuardExhausted: the guard is full and cannot make the claim.
    """
    fingerprint = _key_fingerprint(key)
    with _guard_lock:
        # Membership is checked BEFORE capacity, so a saturated guard still
        # rejects every reuse it has already recorded.
        if fingerprint in _used_key_fingerprints:
            raise NonceReuseError(
                "aead_encrypt: this key has already encrypted a message; the "
                "random-nonce path is single-use per key. Use "
                "aead_encrypt_counter()/CounterAeadKey for multi-message keys."
            )
        if len(_used_key_fingerprints) >= _guard_capacity:
            raise SingleUseGuardExhausted(
                "single-use-key guard is full "
                f"({_guard_capacity} keys); it cannot prove this key is unused "
                "and refuses to encrypt rather than silently forgetting an "
                "earlier key. Use CounterAeadKey for long-lived/multi-message "
                "keys, or resize/reset the guard."
            )
        _used_key_fingerprints.add(fingerprint)


def reset_single_use_guard() -> None:
    """Clear the single-use-key guard. Test/process-reset hook only.

    Calling this while any recorded key is still live re-enables reuse of that
    key under a random nonce — only do it when the key population has rotated.
    """
    with _guard_lock:
        _used_key_fingerprints.clear()


def single_use_guard_size() -> int:
    """Number of keys currently recorded by the single-use guard."""
    with _guard_lock:
        return len(_used_key_fingerprints)


def single_use_guard_capacity() -> int:
    """Current capacity of the single-use guard (it fails closed at this bound)."""
    with _guard_lock:
        return _guard_capacity


def set_single_use_guard_capacity(capacity: int) -> None:
    """Resize the single-use guard.

    Shrinking below the number of already-recorded keys does NOT evict anything —
    the guard keeps every record and simply refuses new claims until entries are
    cleared. That is the whole point: the bound limits memory, never knowledge.
    """
    if isinstance(capacity, bool) or not isinstance(capacity, int):
        raise TypeError("capacity must be an int")
    if capacity < 1:
        raise ValueError("capacity must be >= 1")
    global _guard_capacity
    with _guard_lock:
        _guard_capacity = capacity


def _check_key(key: bytes) -> None:
    if len(key) != KEY_SIZE:
        raise ValueError(f"AEAD key must be {KEY_SIZE} bytes, got {len(key)}")


def nonce_from_counter(counter: int) -> bytes:
    """Encode a monotonic ``u64`` counter as a 12-byte big-endian GCM nonce.

    Rejects negatives, non-integers, and — explicitly — exhaustion of the
    counter space. There is no wrap-around path.
    """
    if isinstance(counter, bool) or not isinstance(counter, int):
        raise TypeError("counter must be a non-negative int")
    if counter < 0:
        raise ValueError("counter must be non-negative")
    if counter > MAX_COUNTER:
        raise NonceReuseError(
            f"counter nonce space exhausted (max {MAX_COUNTER}); "
            "rekey instead of wrapping"
        )
    return counter.to_bytes(NONCE_SIZE, "big")


def aead_encrypt(key: bytes, plaintext: bytes, associated_data: bytes) -> bytes:
    """Encrypt ``plaintext`` under a **single-use** 32-byte ``key``.

    Returns ``nonce || ciphertext || tag``. Raises :class:`NonceReuseError` if
    this key has already been used to encrypt *in this process*, and
    :class:`SingleUseGuardExhausted` if the guard is full and can no longer make
    that determination (it fails closed rather than forgetting — see the module
    docstring for exactly what the guard does and does not guarantee).

    Single-use is a property the CALLER must supply; the guard only detects
    violations it happens to remember. For any key that encrypts more than one
    message, use :class:`CounterAeadKey`, whose uniqueness is structural.
    """
    _check_key(key)
    claim_single_use(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def aead_decrypt(key: bytes, blob: bytes, associated_data: bytes) -> bytes:
    """Inverse of :func:`aead_encrypt`. Raises ``InvalidTag`` on tamper/wrong key."""
    _check_key(key)
    if len(blob) < NONCE_SIZE:
        raise ValueError("ciphertext too short to contain a nonce")
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, associated_data)


def aead_encrypt_counter(
    key: bytes, counter: int, plaintext: bytes, associated_data: bytes
) -> bytes:
    """Encrypt with a caller-sequenced counter nonce; returns ``nonce || ct || tag``.

    The caller owns monotonicity of ``counter`` for a given ``key`` — use
    :class:`CounterAeadKey` when you want the module to own it.
    """
    _check_key(key)
    nonce = nonce_from_counter(counter)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, associated_data)


def aead_decrypt_counter(
    key: bytes, counter: int, blob: bytes, associated_data: bytes
) -> bytes:
    """Inverse of :func:`aead_encrypt_counter`.

    The nonce carried in ``blob`` must equal the nonce implied by ``counter``;
    a mismatch is rejected before any decryption is attempted, so the embedded
    nonce can never override the caller's expected sequence position.
    """
    _check_key(key)
    if len(blob) < NONCE_SIZE:
        raise ValueError("ciphertext too short to contain a nonce")
    expected = nonce_from_counter(counter)
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    if not hmac.compare_digest(nonce, expected):
        raise ValueError("counter nonce mismatch: framed nonce != expected counter")
    return AESGCM(key).decrypt(nonce, ct, associated_data)


class CounterAeadKey:
    """A key bound to a module-owned monotonic counter nonce sequence.

    This is the module's only *structural* nonce-uniqueness control: uniqueness
    follows from a counter that cannot repeat or wrap, so it needs no memory of
    past encryptions, cannot be flooded, and survives process boundaries as long
    as ``next_counter`` is persisted with the key. Prefer it over the
    random-nonce path for every key that encrypts more than one message.

    >>> k = CounterAeadKey(os.urandom(32))
    >>> ctr, blob = k.seal(b"hello", b"ad")
    >>> k.open(ctr, blob, b"ad")
    b'hello'

    ``seal`` raises :class:`NonceReuseError` once the ``u64`` space is exhausted;
    the counter never wraps.
    """

    __slots__ = ("_key", "_next")

    def __init__(self, key: bytes, next_counter: int = 0):
        _check_key(key)
        nonce_from_counter(next_counter)  # validates type/range
        self._key = key
        self._next = next_counter

    @property
    def next_counter(self) -> int:
        """The counter that the next :meth:`seal` will use."""
        return self._next

    def seal(self, plaintext: bytes, associated_data: bytes) -> tuple[int, bytes]:
        """Encrypt at the next counter; returns ``(counter, nonce || ct || tag)``."""
        counter = self._next
        blob = aead_encrypt_counter(self._key, counter, plaintext, associated_data)
        # Advance only after a successful encryption so a failed call never burns
        # a counter slot; the next seal() past MAX_COUNTER is rejected by
        # nonce_from_counter rather than wrapping.
        self._next = counter + 1
        return counter, blob

    def open(self, counter: int, blob: bytes, associated_data: bytes) -> bytes:
        """Decrypt a blob produced at ``counter`` under this key."""
        return aead_decrypt_counter(self._key, counter, blob, associated_data)

    def __repr__(self) -> str:  # pragma: no cover - never leaks the key
        return f"CounterAeadKey(next_counter={self._next})"
