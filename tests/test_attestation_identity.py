# tests/test_attestation_identity.py
import json
import struct

import pytest
from ml_kem_braid.crypto import xeddsa
from ml_kem_braid.attestation.identity import IdentityProver, IdentityVerifier, IDENTITY_CTX
from ml_kem_braid.attestation.policy import IdentityPolicy
from ml_kem_braid.attestation.errors import (
    SignatureInvalid, PolicyViolation, ChannelBindingError, ClaimsMismatch,
)

def _setup():
    priv = xeddsa.generate_identity()
    pub = xeddsa.public_key(priv)
    ck = b"\x33" * 32
    ev = IdentityProver(priv).attest(ck, {"device_id": 1, "app_version": "1.0"})
    return priv, pub, ck, ev

def test_valid_identity_attestation_verifies():
    _, pub, ck, ev = _setup()
    claims = IdentityVerifier().verify(ev, channel_key=ck, policy=IdentityPolicy(pub))
    assert claims.subject == pub
    assert claims.channel_key == ck
    assert claims.attributes["device_id"] == 1

def test_wrong_trusted_identity_rejected():
    _, _, ck, ev = _setup()
    other = xeddsa.public_key(xeddsa.generate_identity())
    with pytest.raises(PolicyViolation):
        IdentityVerifier().verify(ev, channel_key=ck, policy=IdentityPolicy(other))

def test_wrong_channel_key_rejected():
    _, pub, _, ev = _setup()
    with pytest.raises(ChannelBindingError):
        IdentityVerifier().verify(ev, channel_key=b"\x44" * 32, policy=IdentityPolicy(pub))

def test_tampered_claims_rejected():
    _, pub, ck, ev = _setup()
    tampered = bytearray(ev)
    tampered[-1] ^= 0x01  # flip a signature byte
    with pytest.raises(SignatureInvalid):
        IdentityVerifier().verify(bytes(tampered), channel_key=ck, policy=IdentityPolicy(pub))

def test_truncated_evidence_rejected():
    _, pub, ck, ev = _setup()
    with pytest.raises((ClaimsMismatch, SignatureInvalid)):
        IdentityVerifier().verify(ev[:20], channel_key=ck, policy=IdentityPolicy(pub))

def test_non_canonical_encoding_rejected():
    priv = xeddsa.generate_identity()
    pub = xeddsa.public_key(priv)
    ck = b"\x33" * 32
    # Semantically-valid claims, but NON-canonical JSON (reordered keys + loose separators).
    non_canon = json.dumps(
        {"subject": pub.hex(), "channel_key": ck.hex(), "attributes": {"device_id": 1}},
        separators=(", ", ": "),
    ).encode()
    sig = xeddsa.sign_ctx(priv, IDENTITY_CTX, non_canon)  # sign the non-canonical bytes
    evidence = struct.pack(">I", len(non_canon)) + non_canon + sig
    with pytest.raises(ClaimsMismatch):
        IdentityVerifier().verify(evidence, channel_key=ck, policy=IdentityPolicy(pub))
