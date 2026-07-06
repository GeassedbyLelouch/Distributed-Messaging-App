# tests/test_attestation_dcap_verify.py
"""Self-consistent DCAP verify tests: we build a quote signed by a test PCK chain
rooted at a test root, then pin that root. This exercises the verification LOGIC
without real Intel collateral (documented limitation)."""
import hashlib
import struct
import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)
from datetime import datetime, timedelta, UTC

from ml_kem_braid.attestation.dcap import DcapVerifier
from ml_kem_braid.attestation.claims import Claims
from ml_kem_braid.attestation.policy import SgxPolicy
from ml_kem_braid.attestation.errors import (
    ClaimsMismatch, TrustAnchorError, PolicyViolation, SignatureInvalid,
)

P256 = ec.SECP256R1()

def _raw64(sig_der: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(sig_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")

def _sign_raw(key, msg: bytes) -> bytes:
    return _raw64(key.sign(msg, ec.ECDSA(hashes.SHA256())))

def _cert(subject, issuer_name, issuer_key, pub, ca=False):
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
         .issuer_name(issuer_name)
         .public_key(pub)
         .serial_number(x509.random_serial_number())
         .not_valid_before(datetime.now(UTC) - timedelta(days=1))
         .not_valid_after(datetime.now(UTC) + timedelta(days=365)))
    if ca:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key, hashes.SHA256())

def _pub_raw(key) -> bytes:
    n = key.public_key().public_numbers()
    return n.x.to_bytes(32, "big") + n.y.to_bytes(32, "big")

def _build_evidence(claims: Claims, *, mr_enclave, mr_signer, isv_svn,
                    root_key, pck_key, attest_key, break_chain=False,
                    wrong_report_data=False, wrong_attest=False):
    # --- root + PCK certs ---
    root = _cert("Test SGX Root", x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SGX Root")]),
                 root_key, root_key.public_key(), ca=True)
    signer_key = ec.generate_private_key(P256) if break_chain else root_key
    pck = _cert("PCK", root.subject, signer_key, pck_key.public_key(), ca=False)
    pck_pem = pck.public_bytes(serialization.Encoding.PEM) + root.public_bytes(serialization.Encoding.PEM)

    # --- enclave report ---
    report = bytearray(384)
    report[64:96] = mr_enclave
    report[128:160] = mr_signer
    report[256:258] = struct.pack("<H", 1)
    report[258:260] = struct.pack("<H", isv_svn)
    rd = hashlib.sha256(claims.canonical()).digest()
    if wrong_report_data:
        rd = bytes(32)
    report[320:352] = rd
    report[352:384] = bytes(32)
    report = bytes(report)

    attest_pub = _pub_raw(attest_key)
    header = bytearray(48); header[0:2] = struct.pack("<H", 3); header = bytes(header)
    signature = _sign_raw(attest_key, header + report)

    # --- QE report binds attest key ---
    qe_report = bytearray(384)
    qe_auth = b"qe-auth"
    qe_bind = hashlib.sha256((bytes(0) if wrong_attest else attest_pub) + qe_auth).digest()
    qe_report[320:352] = qe_bind
    qe_report = bytes(qe_report)
    qe_report_sig = _sign_raw(pck_key, qe_report)

    blob = header + report + struct.pack("<I", 64) + signature + attest_pub
    blob += qe_report + qe_report_sig + struct.pack("<H", len(qe_auth)) + qe_auth
    blob += struct.pack("<I", len(pck_pem)) + pck_pem

    canonical = claims.canonical()
    return struct.pack(">I", len(canonical)) + canonical + blob, root

def _claims(ck=b"\x33" * 32):
    return Claims(channel_key=ck, subject=b"\xaa" * 32, attributes={"tcb": 5})

def _keys():
    return (ec.generate_private_key(P256), ec.generate_private_key(P256),
            ec.generate_private_key(P256))

def test_valid_quote_verifies():
    root_key, pck_key, attest_key = _keys()
    ck = b"\x33" * 32
    claims = _claims(ck)
    ev, root = _build_evidence(claims, mr_enclave=b"\x01" * 32, mr_signer=b"\x02" * 32,
                               isv_svn=5, root_key=root_key, pck_key=pck_key, attest_key=attest_key)
    policy = SgxPolicy(pinned_root_der=root.public_bytes(serialization.Encoding.DER),
                       mrenclave_allow=frozenset({b"\x01" * 32}), mrsigner_allow=frozenset(),
                       min_isv_svn=3)
    out = DcapVerifier().verify(ev, channel_key=ck, policy=policy)
    assert out.channel_key == ck

def test_tampered_report_data_rejected():
    root_key, pck_key, attest_key = _keys()
    claims = _claims()
    ev, root = _build_evidence(claims, mr_enclave=b"\x01" * 32, mr_signer=b"\x02" * 32,
                               isv_svn=5, root_key=root_key, pck_key=pck_key,
                               attest_key=attest_key, wrong_report_data=True)
    policy = SgxPolicy(pinned_root_der=root.public_bytes(serialization.Encoding.DER),
                       mrenclave_allow=frozenset({b"\x01" * 32}), mrsigner_allow=frozenset(), min_isv_svn=3)
    with pytest.raises(ClaimsMismatch):
        DcapVerifier().verify(ev, channel_key=b"\x33" * 32, policy=policy)

def test_broken_pck_chain_rejected():
    root_key, pck_key, attest_key = _keys()
    claims = _claims()
    ev, root = _build_evidence(claims, mr_enclave=b"\x01" * 32, mr_signer=b"\x02" * 32,
                               isv_svn=5, root_key=root_key, pck_key=pck_key,
                               attest_key=attest_key, break_chain=True)
    policy = SgxPolicy(pinned_root_der=root.public_bytes(serialization.Encoding.DER),
                       mrenclave_allow=frozenset({b"\x01" * 32}), mrsigner_allow=frozenset(), min_isv_svn=3)
    with pytest.raises(TrustAnchorError):
        DcapVerifier().verify(ev, channel_key=b"\x33" * 32, policy=policy)

def test_low_tcb_rejected():
    root_key, pck_key, attest_key = _keys()
    claims = _claims()
    ev, root = _build_evidence(claims, mr_enclave=b"\x01" * 32, mr_signer=b"\x02" * 32,
                               isv_svn=1, root_key=root_key, pck_key=pck_key, attest_key=attest_key)
    policy = SgxPolicy(pinned_root_der=root.public_bytes(serialization.Encoding.DER),
                       mrenclave_allow=frozenset({b"\x01" * 32}), mrsigner_allow=frozenset(), min_isv_svn=3)
    with pytest.raises(PolicyViolation):
        DcapVerifier().verify(ev, channel_key=b"\x33" * 32, policy=policy)

def test_wrong_pinned_root_rejected():
    root_key, pck_key, attest_key = _keys()
    claims = _claims()
    ev, _ = _build_evidence(claims, mr_enclave=b"\x01" * 32, mr_signer=b"\x02" * 32,
                            isv_svn=5, root_key=root_key, pck_key=pck_key, attest_key=attest_key)
    other_root_key = ec.generate_private_key(P256)
    other_root = _cert("Other", x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Other")]),
                       other_root_key, other_root_key.public_key(), ca=True)
    policy = SgxPolicy(pinned_root_der=other_root.public_bytes(serialization.Encoding.DER),
                       mrenclave_allow=frozenset({b"\x01" * 32}), mrsigner_allow=frozenset(), min_isv_svn=3)
    with pytest.raises(TrustAnchorError):
        DcapVerifier().verify(ev, channel_key=b"\x33" * 32, policy=policy)
