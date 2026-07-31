import os
import subprocess
import sys

import pytest

from ml_kem_braid.crypto import backend, vxeddsa, xeddsa

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


# ---------------------------------------------------------------------------
# C7 — VXEdDSA cofactor / neutral-point rejection
# ---------------------------------------------------------------------------

def test_vrf_verify_rejects_neutral_v_point():
    """A proof whose first 32 bytes encode the neutral point (y=1, sign=0)
    must be rejected regardless of the trailing bytes."""
    priv = xeddsa.generate_identity()
    pub = xeddsa.public_key(priv)
    msg = b"neutral-point-test"
    real_proof, _ = vxeddsa.vrf_sign(priv, msg)
    # Neutral point on Ed25519: y=1 with sign bit 0 → little-endian 0x01 followed by 0x00*31
    neutral_v = b"\x01" + b"\x00" * 31
    crafted = neutral_v + real_proof[32:]
    assert vxeddsa.vrf_verify(pub, msg, crafted) is None


# ---------------------------------------------------------------------------
# L3 — VRF output-length invariant must be enforced without `assert`
# ---------------------------------------------------------------------------

class _ShortOutputBackend:
    """Stub backend whose verify returns a truncated VRF output."""

    def verifyVrfSignature(self, pub, msg, proof, label):
        return b"\x00" * (vxeddsa.OUTPUT_SIZE - 1)


def test_vrf_verify_raises_on_wrong_output_length(monkeypatch):
    """L3: a backend returning a wrong-length output must fail closed with a
    RuntimeError. `assert` is stripped under `python -O`, so the invariant would
    otherwise silently return an undersized VRF output."""
    priv = xeddsa.generate_identity()
    pub = xeddsa.public_key(priv)
    proof = b"\x01" * vxeddsa.PROOF_SIZE
    monkeypatch.setattr(backend, "load", lambda: _ShortOutputBackend())
    with pytest.raises(RuntimeError):
        vxeddsa.vrf_verify(pub, b"m", proof)


def test_vrf_length_invariant_survives_optimized_mode():
    """The invariant must still be present when asserts are disabled (-O)."""
    code = (
        "from ml_kem_braid.crypto import backend, vxeddsa, xeddsa\n"
        "class B:\n"
        "    def verifyVrfSignature(self, pub, msg, proof, label):\n"
        "        return b'\\x00' * 31\n"
        "priv = xeddsa.generate_identity()\n"
        "pub = xeddsa.public_key(priv)\n"
        "backend.load = lambda: B()\n"
        "try:\n"
        "    vxeddsa.vrf_verify(pub, b'm', b'\\x01' * 96)\n"
        "except RuntimeError:\n"
        "    print('RAISED')\n"
    )
    out = subprocess.run(
        [sys.executable, "-O", "-c", code], capture_output=True, text=True, check=True
    )
    assert "RAISED" in out.stdout
