import os
from ml_kem_braid.crypto import backend

def test_extension_loads_and_signs():
    c = backend.load()
    priv = c.generatePrivateKey(os.urandom(32))
    pub = c.generatePublicKey(priv)
    assert len(priv) == 32 and len(pub) == 32
    sig = c.calculateSignature(os.urandom(64), priv, b"hello")
    assert len(sig) == 64
    assert c.verifySignature(pub, b"hello", sig) == 0
    assert c.verifySignature(pub, b"tampered", sig) != 0
