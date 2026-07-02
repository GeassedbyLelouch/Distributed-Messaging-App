"""Typed, fail-closed error hierarchy for the attestation layer."""
from __future__ import annotations


class AttestationError(Exception):
    """Base class for every attestation failure. Callers treat any subclass as
    'do not trust this peer / channel'."""


class QuoteParseError(AttestationError):
    """Malformed or unsupported SGX quote."""


class TrustAnchorError(AttestationError):
    """Certificate-chain / signature verification against the trust root failed."""


class PolicyViolation(AttestationError):
    """Evidence was authentic but violates the trust policy (measurement/TCB/identity)."""


class ChannelBindingError(AttestationError):
    """Claims did not bind the expected Noise channel static key."""


class ClaimsMismatch(AttestationError):
    """Evidence's committed claims digest did not match the presented claims."""


class SignatureInvalid(AttestationError):
    """A required signature failed to verify."""


class HandshakeError(AttestationError):
    """Noise handshake failed (auth failure, malformed message, nonce exhaustion)."""
