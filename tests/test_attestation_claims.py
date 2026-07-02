import pytest
from ml_kem_braid.attestation.claims import Claims
from ml_kem_braid.attestation import errors

def _claims():
    return Claims(channel_key=b"\x01" * 32, subject=b"\x02" * 32,
                  attributes={"device_id": 7, "app_version": "1.0"})

def test_canonical_is_deterministic_and_order_independent():
    a = Claims(b"\x01" * 32, b"\x02" * 32, {"b": 2, "a": 1})
    b = Claims(b"\x01" * 32, b"\x02" * 32, {"a": 1, "b": 2})
    assert a.canonical() == b.canonical()

def test_report_data_is_sha256_of_canonical():
    import hashlib
    c = _claims()
    assert c.report_data() == hashlib.sha256(c.canonical()).digest()
    assert len(c.report_data()) == 32

def test_claims_is_frozen():
    c = _claims()
    with pytest.raises(Exception):
        c.channel_key = b"\x00" * 32  # type: ignore[misc]

def test_error_hierarchy():
    for name in ("QuoteParseError", "TrustAnchorError", "PolicyViolation",
                 "ChannelBindingError", "ClaimsMismatch", "SignatureInvalid",
                 "HandshakeError"):
        cls = getattr(errors, name)
        assert issubclass(cls, errors.AttestationError)
