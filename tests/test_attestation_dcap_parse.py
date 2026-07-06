# tests/test_attestation_dcap_parse.py
import struct
import pytest
from ml_kem_braid.attestation.dcap import parse_quote, Quote
from ml_kem_braid.attestation.errors import QuoteParseError

def _report(mr_enclave=b"\xaa" * 32, mr_signer=b"\xbb" * 32, isv_prod_id=1,
            isv_svn=5, report_data=b"\xcc" * 64) -> bytes:
    r = bytearray(384)
    r[64:96] = mr_enclave
    r[128:160] = mr_signer
    r[256:258] = struct.pack("<H", isv_prod_id)
    r[258:260] = struct.pack("<H", isv_svn)
    r[320:384] = report_data
    return bytes(r)

def _quote(version=3, report=None, sig=b"\x11" * 64, attest_pub=b"\x22" * 64,
           qe_report=b"\x33" * 384, qe_report_sig=b"\x44" * 64,
           qe_auth=b"auth", pck=b"-----BEGIN CERT-----\n") -> bytes:
    report = report if report is not None else _report()
    header = bytearray(48); header[0:2] = struct.pack("<H", version)
    body = bytes(header) + report + struct.pack("<I", 64) + sig + attest_pub
    body += qe_report + qe_report_sig + struct.pack("<H", len(qe_auth)) + qe_auth
    body += struct.pack("<I", len(pck)) + pck
    return body

def test_parse_roundtrips_fields():
    q = parse_quote(_quote())
    assert isinstance(q, Quote)
    assert q.report.mr_enclave == b"\xaa" * 32
    assert q.report.mr_signer == b"\xbb" * 32
    assert q.report.isv_svn == 5
    assert q.report.report_data == b"\xcc" * 64
    assert q.qe_auth_data == b"auth"
    assert q.pck_chain_pem.startswith(b"-----BEGIN CERT-----")

def test_parse_rejects_wrong_version():
    with pytest.raises(QuoteParseError):
        parse_quote(_quote(version=2))

def test_parse_rejects_truncated():
    with pytest.raises(QuoteParseError):
        parse_quote(_quote()[:100])
