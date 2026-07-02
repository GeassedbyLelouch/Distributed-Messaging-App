"""XEdDSA over the vendored Signal curve25519 backend (Curve25519 only).

A single 32-byte Montgomery key does both X25519 DH and XEdDSA signing.
All secret-scalar operations run in constant-time C.
"""
from __future__ import annotations

import os

from ml_kem_braid.crypto import backend

KEY_SIZE = 32
SIGNATURE_SIZE = 64
NONCE_SIZE = 64

def generate_identity() -> bytes:
    """Return a fresh 32-byte clamped Curve25519 private key."""
    return backend.load().generatePrivateKey(os.urandom(KEY_SIZE))

def public_key(priv: bytes) -> bytes:
    """Montgomery u-coordinate public key for `priv` (32 bytes)."""
    return backend.load().generatePublicKey(priv)

def dh(priv: bytes, peer_pub: bytes) -> bytes:
    """X25519 shared secret (RFC 7748); interoperable with `cryptography` X25519."""
    return backend.load().calculateAgreement(priv, peer_pub)

def sign(priv: bytes, msg: bytes, *, nonce: bytes | None = None) -> bytes:
    """64-byte XEdDSA signature. `nonce` (Z) defaults to os.urandom(64)."""
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    return backend.load().calculateSignature(nonce, priv, msg)

def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """True iff `sig` is a valid XEdDSA signature by `pub` over `msg`."""
    if len(sig) != SIGNATURE_SIZE or len(pub) != KEY_SIZE:
        return False
    lib = backend.load()
    try:
        return lib.verifySignature(pub, msg, sig) == 0
    except ValueError:
        return False
