import pytest
from ml_kem_braid.attestation.base import check_channel_binding
from ml_kem_braid.attestation.claims import Claims
from ml_kem_braid.attestation.errors import ChannelBindingError

def _claims(ck):
    return Claims(channel_key=ck, subject=b"\x02" * 32, attributes={})

def test_binding_accepts_match():
    ck = b"\x09" * 32
    check_channel_binding(_claims(ck), ck)  # must not raise

def test_binding_rejects_mismatch():
    with pytest.raises(ChannelBindingError):
        check_channel_binding(_claims(b"\x09" * 32), b"\x0a" * 32)

def test_binding_rejects_length_mismatch():
    with pytest.raises(ChannelBindingError):
        check_channel_binding(_claims(b"\x09" * 31), b"\x09" * 32)
