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
