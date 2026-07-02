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

# ---------------------------------------------------------------------------
# Domain-separated signing
# ---------------------------------------------------------------------------
#
# A single identity key signs several distinct message spaces (PQXDH prekeys,
# decentralized records, ...). To guarantee a signature minted for one role can
# never be replayed as a valid signature for another, every role-scoped
# signature is taken over a framed message:
#
#     DOMAIN_TAG || uint16(len(context)) || context || msg
#
# The framing is injective in (context, msg): the uint16 length prefix
# unambiguously delimits the context from the message.
#
# Disjointness from raw sign()/verify() is *enforced*, not merely conventional:
# the public raw sign()/verify() below reject any message that starts with
# DOMAIN_TAG. Framed messages therefore live in a byte-space that the raw path
# can never emit or accept, and role-scoped signatures cannot be replayed as
# unscoped ones (or vice versa) even by an attacker who reconstructs the frame.

DOMAIN_TAG = b"MLKEMBraid/xeddsa/v1\x00"
_MAX_CONTEXT = 0xFFFF

def _sign_raw(priv: bytes, msg: bytes, nonce: bytes | None) -> bytes:
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    return backend.load().calculateSignature(nonce, priv, msg)

def _verify_raw(pub: bytes, msg: bytes, sig: bytes) -> bool:
    if len(sig) != SIGNATURE_SIZE or len(pub) != KEY_SIZE:
        return False
    lib = backend.load()
    try:
        return lib.verifySignature(pub, msg, sig) == 0
    except ValueError:
        return False

def sign(priv: bytes, msg: bytes, *, nonce: bytes | None = None) -> bytes:
    """64-byte XEdDSA signature over a raw, unscoped `msg`. `nonce` (Z) defaults
    to os.urandom(64).

    Raw messages must NOT start with DOMAIN_TAG — that byte-space is reserved for
    domain-separated signatures; use `sign_ctx` for anything role-scoped."""
    if msg[: len(DOMAIN_TAG)] == DOMAIN_TAG:
        raise ValueError("raw message must not start with DOMAIN_TAG; use sign_ctx")
    return _sign_raw(priv, msg, nonce)

def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """True iff `sig` is a valid XEdDSA signature by `pub` over the raw `msg`.

    A message starting with DOMAIN_TAG is rejected (reserved for `sign_ctx`), so
    a framed message can never be accepted through the raw path."""
    if msg[: len(DOMAIN_TAG)] == DOMAIN_TAG:
        return False
    return _verify_raw(pub, msg, sig)

def _frame(context: bytes, msg: bytes) -> bytes:
    if len(context) > _MAX_CONTEXT:
        raise ValueError("context label too long")
    return DOMAIN_TAG + len(context).to_bytes(2, "big") + context + msg

def sign_ctx(
    priv: bytes, context: bytes, msg: bytes, *, nonce: bytes | None = None
) -> bytes:
    """XEdDSA signature over `msg` bound to a role `context` (domain-separated)."""
    return _sign_raw(priv, _frame(context, msg), nonce)

def verify_ctx(pub: bytes, context: bytes, msg: bytes, sig: bytes) -> bool:
    """True iff `sig` is a valid signature by `pub` over `msg` under `context`."""
    return _verify_raw(pub, _frame(context, msg), sig)
