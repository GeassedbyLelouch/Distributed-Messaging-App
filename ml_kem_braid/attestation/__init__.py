"""Post-TLS remote attestation (verify-only) for MLKEM-Braid.

Two attestation kinds share one interface (AttestationVerifier): SGX-DCAP enclave
attestation and device/identity-key attestation (reusing the Curve25519 XEdDSA
identity). Both bind a set of Claims to a PQ-hybrid Noise NKhfs channel key.
"""
from ml_kem_braid.attestation.base import AttestationVerifier, check_channel_binding
from ml_kem_braid.attestation.claims import Claims
from ml_kem_braid.attestation.dcap import DcapVerifier, Quote, parse_quote
from ml_kem_braid.attestation.errors import (
    AttestationError,
    ChannelBindingError,
    ClaimsMismatch,
    HandshakeError,
    PolicyViolation,
    QuoteParseError,
    SignatureInvalid,
    TrustAnchorError,
)
from ml_kem_braid.attestation.identity import (
    IDENTITY_CTX,
    IdentityProver,
    IdentityVerifier,
)
from ml_kem_braid.attestation.noise import SecureChannel, nkhfs_initiate, nkhfs_respond
from ml_kem_braid.attestation.policy import IdentityPolicy, SgxPolicy
from ml_kem_braid.attestation.session import attested_connect

__all__ = [
    "AttestationVerifier", "check_channel_binding", "Claims",
    "IdentityProver", "IdentityVerifier", "IDENTITY_CTX",
    "DcapVerifier", "Quote", "parse_quote",
    "IdentityPolicy", "SgxPolicy",
    "SecureChannel", "nkhfs_initiate", "nkhfs_respond", "attested_connect",
    "AttestationError", "QuoteParseError", "TrustAnchorError", "PolicyViolation",
    "ChannelBindingError", "ClaimsMismatch", "SignatureInvalid", "HandshakeError",
]
