# ml_kem_braid/attestation/dcap.py
"""SGX-DCAP ECDSA quote-v3 parsing + verification (verify-only, offline collateral).

The byte layout is a project-defined serialization of the standard ECDSA-v3
fields (real Intel quotes require the DCAP toolchain to produce). The verifier
checks the same trust relationships a real DCAP verifier does: attestation-key
signs the report, the QE report commits to the attestation key, the PCK chain
verifies to a PINNED Intel root, and report_data binds the claims.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from ml_kem_braid.attestation.errors import QuoteParseError

_HEADER_LEN = 48
_REPORT_LEN = 384
_SIG_LEN = 64
_PUB_LEN = 64


@dataclass
class EnclaveReport:
    mr_enclave: bytes
    mr_signer: bytes
    isv_prod_id: int
    isv_svn: int
    report_data: bytes
    raw: bytes


@dataclass
class Quote:
    header: bytes
    report: EnclaveReport
    signature: bytes
    attest_pub: bytes
    qe_report: bytes
    qe_report_sig: bytes
    qe_auth_data: bytes
    pck_chain_pem: bytes


def _report_from_raw(raw: bytes) -> EnclaveReport:
    return EnclaveReport(
        mr_enclave=raw[64:96],
        mr_signer=raw[128:160],
        isv_prod_id=struct.unpack_from("<H", raw, 256)[0],
        isv_svn=struct.unpack_from("<H", raw, 258)[0],
        report_data=raw[320:384],
        raw=raw,
    )


def parse_quote(blob: bytes) -> Quote:
    try:
        off = 0
        header = blob[off:off + _HEADER_LEN]; off += _HEADER_LEN
        if len(header) != _HEADER_LEN:
            raise QuoteParseError("truncated header")
        version = struct.unpack_from("<H", header, 0)[0]
        if version != 3:
            raise QuoteParseError(f"unsupported quote version {version}")
        report_raw = blob[off:off + _REPORT_LEN]; off += _REPORT_LEN
        if len(report_raw) != _REPORT_LEN:
            raise QuoteParseError("truncated enclave report")
        (sig_len,) = struct.unpack_from("<I", blob, off); off += 4
        signature = blob[off:off + _SIG_LEN]; off += _SIG_LEN
        attest_pub = blob[off:off + _PUB_LEN]; off += _PUB_LEN
        qe_report = blob[off:off + _REPORT_LEN]; off += _REPORT_LEN
        qe_report_sig = blob[off:off + _SIG_LEN]; off += _SIG_LEN
        (auth_len,) = struct.unpack_from("<H", blob, off); off += 2
        qe_auth_data = blob[off:off + auth_len]; off += auth_len
        (pck_len,) = struct.unpack_from("<I", blob, off); off += 4
        pck_chain_pem = blob[off:off + pck_len]; off += pck_len
        if (len(signature) != _SIG_LEN or len(attest_pub) != _PUB_LEN
                or len(qe_report) != _REPORT_LEN or len(qe_report_sig) != _SIG_LEN
                or len(qe_auth_data) != auth_len or len(pck_chain_pem) != pck_len):
            raise QuoteParseError("truncated quote body")
        return Quote(
            header=header, report=_report_from_raw(report_raw), signature=signature,
            attest_pub=attest_pub, qe_report=qe_report, qe_report_sig=qe_report_sig,
            qe_auth_data=qe_auth_data, pck_chain_pem=pck_chain_pem,
        )
    except (struct.error, IndexError) as exc:
        raise QuoteParseError("malformed quote") from exc


# --- DcapVerifier (appended) ---

import hashlib
import hmac

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ml_kem_braid.attestation.base import check_channel_binding
from ml_kem_braid.attestation.claims import Claims
from ml_kem_braid.attestation.errors import (
    ClaimsMismatch,
    PolicyViolation,
    SignatureInvalid,
    TrustAnchorError,
)
from ml_kem_braid.attestation.identity import _parse_canonical_claims
from ml_kem_braid.attestation.policy import SgxPolicy

_EV_HDR = struct.Struct(">I")


def _raw64_to_der(sig: bytes) -> bytes:
    if len(sig) != 64:
        raise SignatureInvalid("bad ECDSA signature length")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    return encode_dss_signature(r, s)


def _p256_pub_from_raw(raw: bytes) -> ec.EllipticCurvePublicKey:
    if len(raw) != 64:
        raise SignatureInvalid("bad P-256 public key length")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + raw)


def _ecdsa_verify(pub: ec.EllipticCurvePublicKey, sig64: bytes, msg: bytes, err) -> None:
    try:
        pub.verify(_raw64_to_der(sig64), msg, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise err("ECDSA verification failed") from exc


def _load_pem_chain(pem: bytes) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    marker = b"-----END CERTIFICATE-----"
    idx = 0
    while True:
        end = pem.find(marker, idx)
        if end == -1:
            break
        block = pem[idx:end + len(marker)] + b"\n"
        certs.append(x509.load_pem_x509_certificate(block))
        idx = end + len(marker)
    if not certs:
        raise TrustAnchorError("empty PCK chain")
    return certs


class DcapVerifier:
    """SGX-DCAP ECDSA quote-v3 verifier (verify-only, offline pinned collateral)."""

    kind = "sgx-dcap"

    def verify(self, evidence: bytes, *, channel_key: bytes, policy: SgxPolicy) -> Claims:
        if len(evidence) < _EV_HDR.size:
            raise ClaimsMismatch("evidence too short")
        (clen,) = _EV_HDR.unpack(evidence[: _EV_HDR.size])
        rest = evidence[_EV_HDR.size:]
        if clen <= 0 or len(rest) < clen:
            raise ClaimsMismatch("evidence framing invalid")
        canonical = rest[:clen]
        quote_blob = rest[clen:]
        claims = _parse_canonical_claims(canonical)
        if claims.canonical() != canonical:
            raise ClaimsMismatch("claims not canonical")
        quote = parse_quote(quote_blob)

        # (2) report_data binds the claims digest in the low 32 bytes, high 32 zero.
        digest = hashlib.sha256(canonical).digest()
        if not hmac.compare_digest(quote.report.report_data[:32], digest):
            raise ClaimsMismatch("report_data does not commit to claims")
        if quote.report.report_data[32:] != bytes(32):
            raise ClaimsMismatch("report_data has unexpected high bytes")

        # (3) PCK chain -> pinned root.
        chain = _load_pem_chain(quote.pck_chain_pem)
        leaf, root = chain[0], chain[-1]
        pinned = x509.load_der_x509_certificate(policy.pinned_root_der)
        pinned_spki = pinned.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        root_spki = root.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if not hmac.compare_digest(root_spki, pinned_spki):
            raise TrustAnchorError("PCK chain root is not the pinned root")
        # verify each cert is signed by the next (leaf..root), root self-signed by pinned key.
        for i in range(len(chain) - 1):
            issuer_pub = chain[i + 1].public_key()
            try:
                issuer_pub.verify(
                    chain[i].signature, chain[i].tbs_certificate_bytes,
                    ec.ECDSA(chain[i].signature_hash_algorithm),
                )
            except InvalidSignature as exc:
                raise TrustAnchorError("PCK chain link invalid") from exc

        # (4) PCK leaf signs the QE report.
        _ecdsa_verify(leaf.public_key(), quote.qe_report_sig, quote.qe_report, TrustAnchorError)

        # (5) QE report_data commits to the attestation key.
        qe_bind = hashlib.sha256(quote.attest_pub + quote.qe_auth_data).digest()
        if not hmac.compare_digest(quote.qe_report[320:352], qe_bind):
            raise TrustAnchorError("QE report does not bind the attestation key")

        # (6) attestation key signs the enclave report.
        attest_pub = _p256_pub_from_raw(quote.attest_pub)
        _ecdsa_verify(attest_pub, quote.signature, quote.header + quote.report.raw, SignatureInvalid)

        # (7) policy gate.
        mre_ok = quote.report.mr_enclave in policy.mrenclave_allow
        mrs_ok = quote.report.mr_signer in policy.mrsigner_allow
        if not (mre_ok or mrs_ok):
            raise PolicyViolation("enclave measurement not in allowlist")
        if quote.report.isv_svn < policy.min_isv_svn:
            raise PolicyViolation("ISV SVN below policy minimum")

        # (8) channel binding.
        check_channel_binding(claims, channel_key)
        return claims
