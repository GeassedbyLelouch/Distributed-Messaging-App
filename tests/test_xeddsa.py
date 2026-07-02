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
