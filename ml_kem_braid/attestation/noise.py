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


# --- append to ml_kem_braid/attestation/noise.py ---

from dataclasses import dataclass as _dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kyber_py.ml_kem import ML_KEM_1024

PROTOCOL_NAME = b"Noise_NKhfs_25519+MLKEM1024_ChaChaPoly_SHA256"
_DH_LEN = 32
_KEM_EK_LEN = 1568   # ML-KEM-1024 encapsulation key
_KEM_CT_LEN = 1568   # ML-KEM-1024 ciphertext
_TAG = 16


def x25519_keypair() -> tuple[X25519PrivateKey, bytes]:
    priv = X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv, pub


def _dh(priv: X25519PrivateKey, pub: bytes) -> bytes:
    return priv.exchange(X25519PublicKey.from_public_bytes(pub))


@_dataclass
class _InitiatorPending:
    ss: _SymmetricState
    e_priv: X25519PrivateKey
    kem_dk: bytes

    def finalize(self, msg2: bytes) -> SecureChannel:
        if len(msg2) != _DH_LEN + _KEM_CT_LEN + _TAG:
            raise HandshakeError("bad msg2 length")
        re_pub = msg2[:_DH_LEN]
        kem_ct = msg2[_DH_LEN:_DH_LEN + _KEM_CT_LEN]
        tag = msg2[_DH_LEN + _KEM_CT_LEN:]
        self.ss.mix_hash(re_pub)
        self.ss.mix_key(_dh(self.e_priv, re_pub))
        self.ss.mix_hash(kem_ct)
        kem_ss = ML_KEM_1024.decaps(self.kem_dk, kem_ct)
        self.ss.mix_key(kem_ss)
        self.ss.decrypt_and_hash(tag)  # raises HandshakeError on auth failure
        c_send, c_recv = self.ss.split()
        return SecureChannel(c_send, c_recv, self.ss.handshake_hash)


def nkhfs_initiate(
    responder_static_pub: bytes, *, prologue: bytes = b"", _eph=None, _kem=None
) -> tuple[bytes, _InitiatorPending]:
    """Initiator (client) side. `responder_static_pub` is the ATTESTED static key.
    _eph / _kem allow tests to inject the ephemeral X25519 keypair / ML-KEM keypair."""
    if len(responder_static_pub) != _DH_LEN:
        raise HandshakeError("bad responder static key length")
    ss = _SymmetricState(PROTOCOL_NAME)
    ss.mix_hash(prologue)
    ss.mix_hash(responder_static_pub)  # NK pre-message: responder static
    e_priv, e_pub = _eph if _eph is not None else x25519_keypair()
    kem_ek, kem_dk = _kem if _kem is not None else ML_KEM_1024.keygen()
    ss.mix_hash(e_pub)
    ss.mix_key(_dh(e_priv, responder_static_pub))
    ss.mix_hash(kem_ek)
    tag1 = ss.encrypt_and_hash(b"")  # 16-byte tag over empty payload (cipher exists after mix_key)
    msg1 = e_pub + kem_ek + tag1
    return msg1, _InitiatorPending(ss=ss, e_priv=e_priv, kem_dk=kem_dk)


def nkhfs_respond(
    responder_static_priv: X25519PrivateKey, msg1: bytes, *, prologue: bytes = b"", _eph=None
) -> tuple[bytes, SecureChannel]:
    """Responder (server/enclave) side. Consumes msg1, returns (msg2, channel)."""
    if len(msg1) != _DH_LEN + _KEM_EK_LEN + _TAG:
        raise HandshakeError("bad msg1 length")
    e_pub = msg1[:_DH_LEN]
    kem_ek = msg1[_DH_LEN:_DH_LEN + _KEM_EK_LEN]
    tag1 = msg1[_DH_LEN + _KEM_EK_LEN:]
    s_pub = responder_static_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ss = _SymmetricState(PROTOCOL_NAME)
    ss.mix_hash(prologue)
    ss.mix_hash(s_pub)
    ss.mix_hash(e_pub)
    ss.mix_key(_dh(responder_static_priv, e_pub))
    ss.mix_hash(kem_ek)
    ss.mix_hash(tag1)  # mix tag1 into transcript; auth failure propagates to initiator's finalize
    re_priv, re_pub = _eph if _eph is not None else x25519_keypair()
    ss.mix_hash(re_pub)
    ss.mix_key(_dh(re_priv, e_pub))
    kem_ss, kem_ct = ML_KEM_1024.encaps(kem_ek)
    ss.mix_hash(kem_ct)
    ss.mix_key(kem_ss)
    tag = ss.encrypt_and_hash(b"")  # 16-byte tag over empty payload
    msg2 = re_pub + kem_ct + tag
    c_send, c_recv = ss.split()
    # responder's directions are swapped relative to the initiator
    return msg2, SecureChannel(c_recv, c_send, ss.handshake_hash)
