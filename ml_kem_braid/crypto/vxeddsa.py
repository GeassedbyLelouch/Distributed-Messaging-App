"""VXEdDSA (VRF) over the vendored Signal curve25519 backend.

General-purpose primitive: (message -> proof, output). A customization `label`
provides domain separation between distinct use-cases. Not yet wired to a consumer.
"""
from __future__ import annotations

import os

from ml_kem_braid.crypto import backend, xeddsa

PROOF_SIZE = 96
OUTPUT_SIZE = 32
NONCE_SIZE = 64
DEFAULT_LABEL = b"MLKEMBraid_VXEdDSA_v1"

def vrf_sign(
    priv: bytes, msg: bytes, *, label: bytes = DEFAULT_LABEL, nonce: bytes | None = None
) -> tuple[bytes, bytes]:
    """Return (96-byte proof, 32-byte VRF output). Output is deterministic in
    (priv, msg, label); the proof is randomized by `nonce` (default os.urandom(64))."""
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE)
    proof = backend.load().calculateVrfSignature(nonce, priv, msg, label)
    output = vrf_verify(xeddsa.public_key(priv), msg, proof, label=label)
    if output is None:  # pragma: no cover - would indicate a backend bug
        raise RuntimeError("VXEdDSA self-verification failed")
    return proof, output

def vrf_verify(
    pub: bytes, msg: bytes, proof: bytes, *, label: bytes = DEFAULT_LABEL
) -> bytes | None:
    """Return the 32-byte VRF output if `proof` is valid, else None."""
    if len(proof) != PROOF_SIZE or len(pub) != xeddsa.KEY_SIZE:
        return None
    try:
        return backend.load().verifyVrfSignature(pub, msg, proof, label)
    except ValueError:
        return None
