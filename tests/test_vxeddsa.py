import os
import pytest
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
