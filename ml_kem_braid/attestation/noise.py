"""Minimal Noise machinery (symmetric state, cipher state, channel) for NKhfs.

Implements exactly the pieces the NKhfs handshake (Task 4) needs, on top of the
project's existing primitives: ChaCha20-Poly1305 AEAD + SHA-256. Not a general
Noise library; one pattern only.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from ml_kem_braid.attestation.errors import HandshakeError

_HASHLEN = 32
MAX_NONCE = 2**64 - 1


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def noise_hkdf(ck: bytes, ikm: bytes, num: int) -> tuple[bytes, ...]:
    """Noise HKDF: returns `num` (2 or 3) 32-byte outputs chained from ck, ikm."""
    if num not in (2, 3):
        raise ValueError("noise_hkdf supports 2 or 3 outputs")
    temp = _hmac(ck, ikm)
    o1 = _hmac(temp, b"\x01")
    o2 = _hmac(temp, o1 + b"\x02")
    if num == 2:
        return (o1, o2)
    o3 = _hmac(temp, o2 + b"\x03")
    return (o1, o2, o3)


class _CipherState:
    """A one-directional AEAD keyed by a 32-byte key with a 64-bit nonce counter."""

    def __init__(self, key: bytes) -> None:
        self._aead = ChaCha20Poly1305(key)
        self._n = 0

    def _nonce(self) -> bytes:
        if self._n > MAX_NONCE:
            raise HandshakeError("nonce exhausted")
        return b"\x00\x00\x00\x00" + self._n.to_bytes(8, "little")

    def encrypt_with_ad(self, ad: bytes, pt: bytes) -> bytes:
        ct = self._aead.encrypt(self._nonce(), pt, ad)
        self._n += 1
        return ct

    def decrypt_with_ad(self, ad: bytes, ct: bytes) -> bytes:
        try:
            pt = self._aead.decrypt(self._nonce(), ct, ad)
        except InvalidTag as exc:
            raise HandshakeError("AEAD authentication failed") from exc
        self._n += 1
        return pt


class _SymmetricState:
    """Noise SymmetricState over SHA-256 + ChaCha20-Poly1305."""

    def __init__(self, protocol_name: bytes) -> None:
        if len(protocol_name) <= _HASHLEN:
            self._h = protocol_name + b"\x00" * (_HASHLEN - len(protocol_name))
        else:
            self._h = hashlib.sha256(protocol_name).digest()
        self._ck = self._h
        self._cs: _CipherState | None = None

    @property
    def handshake_hash(self) -> bytes:
        return self._h

    def mix_hash(self, data: bytes) -> None:
        self._h = hashlib.sha256(self._h + data).digest()

    def mix_key(self, ikm: bytes) -> None:
        self._ck, k = noise_hkdf(self._ck, ikm, 2)
        self._cs = _CipherState(k)

    def encrypt_and_hash(self, pt: bytes) -> bytes:
        if self._cs is None:
            self.mix_hash(pt)
            return pt
        ct = self._cs.encrypt_with_ad(self._h, pt)
        self.mix_hash(ct)
        return ct

    def decrypt_and_hash(self, ct: bytes) -> bytes:
        if self._cs is None:
            self.mix_hash(ct)
            return ct
        pt = self._cs.decrypt_with_ad(self._h, ct)
        self.mix_hash(ct)
        return pt

    def split(self) -> tuple[_CipherState, _CipherState]:
        k1, k2 = noise_hkdf(self._ck, b"", 2)
        return _CipherState(k1), _CipherState(k2)


@dataclass
class SecureChannel:
    """A bidirectional attested channel: one send + one recv AEAD state, plus the
    final handshake hash (usable as a channel-binding value)."""

    send: _CipherState
    recv: _CipherState
    handshake_hash: bytes

    def encrypt(self, pt: bytes, ad: bytes = b"") -> bytes:
        return self.send.encrypt_with_ad(ad, pt)

    def decrypt(self, ct: bytes, ad: bytes = b"") -> bytes:
        return self.recv.decrypt_with_ad(ad, ct)
