import os
from ml_kem_braid.crypto import backend

LABEL = b"test-label"

def test_vrf_roundtrip_and_determinism():
    c = backend.load()
    priv = c.generatePrivateKey(os.urandom(32))
    pub = c.generatePublicKey(priv)
    proof = c.calculateVrfSignature(os.urandom(64), priv, b"msg", LABEL)
    assert len(proof) == 96
    out = c.verifyVrfSignature(pub, b"msg", proof, LABEL)
    assert out is not None and len(out) == 32
    # Output is deterministic in (priv, msg, label) regardless of randomness/proof.
    proof2 = c.calculateVrfSignature(os.urandom(64), priv, b"msg", LABEL)
    assert c.verifyVrfSignature(pub, b"msg", proof2, LABEL) == out

def test_vrf_rejects_tamper_and_wrong_label():
    c = backend.load()
    priv = c.generatePrivateKey(os.urandom(32))
    pub = c.generatePublicKey(priv)
    proof = c.calculateVrfSignature(os.urandom(64), priv, b"msg", LABEL)
    assert c.verifyVrfSignature(pub, b"msg", proof, b"other") is None
    bad = bytes(b ^ 0xFF for b in proof[:1]) + proof[1:]
    assert c.verifyVrfSignature(pub, b"msg", bad, LABEL) is None

from ml_kem_braid.crypto import vxeddsa, xeddsa

def test_seam_roundtrip_and_output_binding():
    priv = xeddsa.generate_identity(); pub = xeddsa.public_key(priv)
    proof, out = vxeddsa.vrf_sign(priv, b"m")
    assert len(proof) == 96 and len(out) == 32
    assert vxeddsa.vrf_verify(pub, b"m", proof) == out

def test_seam_output_deterministic_across_nonces():
    priv = xeddsa.generate_identity()
    _, o1 = vxeddsa.vrf_sign(priv, b"m")
    _, o2 = vxeddsa.vrf_sign(priv, b"m")
    assert o1 == o2  # output independent of nonce

def test_seam_different_keys_differ_and_bad_verify_none():
    p1 = xeddsa.generate_identity(); p2 = xeddsa.generate_identity()
    _, o1 = vxeddsa.vrf_sign(p1, b"m"); _, o2 = vxeddsa.vrf_sign(p2, b"m")
    assert o1 != o2
    proof, _ = vxeddsa.vrf_sign(p1, b"m")
    assert vxeddsa.vrf_verify(xeddsa.public_key(p2), b"m", proof) is None
