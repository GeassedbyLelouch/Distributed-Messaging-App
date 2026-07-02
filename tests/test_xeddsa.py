"""Tests for the XEdDSA signing seam (ml_kem_braid.crypto.xeddsa).

KAT vectors below are SELF-GENERATED regression locks: they guard the vendored
build/encoding pipeline, NOT external Signal-interop compatibility. Do not
compare them against the upstream python-axolotl-curve25519 test vectors
without first confirming identical clamping and nonce-packing conventions.
"""
import os
from ml_kem_braid.crypto import backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from ml_kem_braid.crypto import xeddsa

def test_extension_loads_and_signs():
    c = backend.load()
    priv = c.generatePrivateKey(os.urandom(32))
    pub = c.generatePublicKey(priv)
    assert len(priv) == 32 and len(pub) == 32
    sig = c.calculateSignature(os.urandom(64), priv, b"hello")
    assert len(sig) == 64
    assert c.verifySignature(pub, b"hello", sig) == 0
    assert c.verifySignature(pub, b"tampered", sig) != 0

def test_sign_verify_roundtrip():
    priv = xeddsa.generate_identity()
    pub = xeddsa.public_key(priv)
    sig = xeddsa.sign(priv, b"hello")
    assert len(sig) == 64 and xeddsa.verify(pub, b"hello", sig)
    assert not xeddsa.verify(pub, b"bye", sig)

def test_hedged_nonce_distinct_but_valid():
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    s1, s2 = xeddsa.sign(priv, b"m"), xeddsa.sign(priv, b"m")
    assert s1 != s2 and xeddsa.verify(pub, b"m", s1) and xeddsa.verify(pub, b"m", s2)

def test_signs_large_ml_kem_prekey():
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    blob = os.urandom(1568)  # ML-KEM-1024 encapsulation key size
    assert xeddsa.verify(pub, blob, xeddsa.sign(priv, blob))

def test_dh_matches_cryptography_x25519():
    # identity (C backend) DH with a cryptography-generated prekey must agree.
    ident = xeddsa.generate_identity()
    ident_pub = xeddsa.public_key(ident)
    peer = X25519PrivateKey.generate()
    peer_pub = peer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    a = xeddsa.dh(ident, peer_pub)
    b = peer.exchange(X25519PublicKey.from_public_bytes(ident_pub))
    assert a == b

def test_verify_rejects_bad_lengths():
    pub = xeddsa.public_key(xeddsa.generate_identity())
    assert not xeddsa.verify(pub, b"m", b"\x00" * 10)


# ---------------------------------------------------------------------------
# C5 — KAT / deterministic regression lock
# ---------------------------------------------------------------------------
# Vector derived from: priv = generatePrivateKey(bytes(range(32))),
# nonce = bytes(64), msg = b"MLKEMBraid KAT vector".
# Regenerate with:
#   uv run python -c "
#     from ml_kem_braid.crypto import backend, xeddsa
#     priv = backend.load().generatePrivateKey(bytes(range(32)))
#     sig = xeddsa.sign(priv, b'MLKEMBraid KAT vector', nonce=bytes(64))
#     print(sig.hex())
#   "
_KAT_PRIV = backend.load().generatePrivateKey(bytes(range(32)))
_KAT_PUB  = xeddsa.public_key(_KAT_PRIV)
_KAT_MSG  = b"MLKEMBraid KAT vector"
_KAT_NONCE = bytes(64)
_KAT_SIG_HEX = (
    "bd5fd4567317b2b145f49c13ea7abbab40955b31c658c38a4550cfe338fa76c2"
    "8cf09de82346ae3bda599ad4874153d65fb279589494118c2039e1ce70248008"
)

def test_kat_determinism():
    """Deterministic signature must match the locked vector."""
    sig = xeddsa.sign(_KAT_PRIV, _KAT_MSG, nonce=_KAT_NONCE)
    assert sig.hex() == _KAT_SIG_HEX

def test_kat_verify():
    """Locked KAT vector must verify against the corresponding public key."""
    sig = bytes.fromhex(_KAT_SIG_HEX)
    assert xeddsa.verify(_KAT_PUB, _KAT_MSG, sig) is True

def test_kat_one_byte_flip_fails():
    """Single-byte flip anywhere in the KAT signature must fail verification."""
    sig = bytearray(bytes.fromhex(_KAT_SIG_HEX))
    sig[0] ^= 0x01
    assert xeddsa.verify(_KAT_PUB, _KAT_MSG, bytes(sig)) is False


# ---------------------------------------------------------------------------
# C6 — range / canonicity rejection
# ---------------------------------------------------------------------------

def test_verify_rejects_u_ge_p():
    """Public key u >= p (all-0xFF) must be rejected."""
    sig = bytes.fromhex(_KAT_SIG_HEX)
    assert xeddsa.verify(b"\xff" * 32, _KAT_MSG, sig) is False

def test_verify_rejects_s_out_of_range():
    """Signature with last 32 bytes replaced by 0xFF (s out of range) must fail."""
    sig = bytes.fromhex(_KAT_SIG_HEX)
    bad_sig = sig[:32] + b"\xff" * 32
    assert xeddsa.verify(_KAT_PUB, _KAT_MSG, bad_sig) is False

def test_verify_rejects_neutral_public_key():
    """Neutral / low-order public key (all-zero u-coordinate) must be rejected."""
    sig = bytes.fromhex(_KAT_SIG_HEX)
    assert xeddsa.verify(b"\x00" * 32, _KAT_MSG, sig) is False


# ---------------------------------------------------------------------------
# Domain-separated signing (sign_ctx / verify_ctx)
# ---------------------------------------------------------------------------

def test_sign_ctx_roundtrip():
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    sig = xeddsa.sign_ctx(priv, b"role-a", b"payload")
    assert xeddsa.verify_ctx(pub, b"role-a", b"payload", sig)

def test_sign_ctx_wrong_context_rejected():
    """A signature minted for one context must not verify under another."""
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    sig = xeddsa.sign_ctx(priv, b"role-a", b"payload")
    assert not xeddsa.verify_ctx(pub, b"role-b", b"payload", sig)

def test_ctx_signature_not_valid_as_raw():
    """A context-scoped signature must not verify as a bare sign() over msg, and
    the framed-bytes concatenation trick is blocked by the raw-path guard."""
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    sig = xeddsa.sign_ctx(priv, b"role-a", b"payload")
    assert not xeddsa.verify(pub, b"payload", sig)
    # Reconstructing the exact framed bytes and feeding them to the RAW verify
    # path must still be rejected — verify() refuses any DOMAIN_TAG-prefixed msg.
    framed = xeddsa._frame(b"role-a", b"payload")
    assert not xeddsa.verify(pub, framed, sig)

def test_raw_signature_not_valid_as_ctx():
    """A bare sign() signature must not verify under any context."""
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    sig = xeddsa.sign(priv, b"payload")
    assert not xeddsa.verify_ctx(pub, b"role-a", b"payload", sig)

def test_raw_sign_rejects_domain_tag_prefixed_message():
    """sign() must refuse a raw message that starts with DOMAIN_TAG (reserved
    for domain-separated signing) so the two byte-spaces stay disjoint."""
    import pytest
    priv = xeddsa.generate_identity()
    with pytest.raises(ValueError):
        xeddsa.sign(priv, xeddsa.DOMAIN_TAG + b"anything")

def test_raw_verify_rejects_domain_tag_prefixed_message():
    """verify() must reject any raw message that starts with DOMAIN_TAG, even
    when a genuine ctx signature exists over those exact bytes."""
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    framed = xeddsa.DOMAIN_TAG + b"\x00\x06role-apayload"
    sig = xeddsa._sign_raw(priv, framed, None)  # bypass the guard to mint one
    assert xeddsa._verify_raw(pub, framed, sig)          # genuinely valid bytes
    assert not xeddsa.verify(pub, framed, sig)            # but rejected via guard

def test_ctx_framing_is_unambiguous():
    """Length-prefixing the context prevents (ctx, msg) boundary collisions:
    ('ab', 'c') and ('a', 'bc') must produce independent signatures."""
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    sig = xeddsa.sign_ctx(priv, b"ab", b"c")
    assert not xeddsa.verify_ctx(pub, b"a", b"bc", sig)
    assert xeddsa.verify_ctx(pub, b"ab", b"c", sig)
