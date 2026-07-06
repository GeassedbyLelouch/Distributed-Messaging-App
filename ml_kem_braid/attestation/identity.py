# ml_kem_braid/attestation/identity.py
"""Device/identity-key attestation: the single Curve25519 XEdDSA identity signs a
channel-bound claims set. Reuses sub-project-1 domain-separated signing."""
from __future__ import annotations

import hmac
import json
import struct
from typing import Any, Mapping

from ml_kem_braid.attestation.base import check_channel_binding
from ml_kem_braid.attestation.claims import Claims
from ml_kem_braid.attestation.errors import (
    ClaimsMismatch,
    PolicyViolation,
    SignatureInvalid,
)
from ml_kem_braid.attestation.policy import IdentityPolicy
from ml_kem_braid.crypto import xeddsa

IDENTITY_CTX = b"attestation/identity-claims"
_HDR = struct.Struct(">I")  # 4-byte big-endian length prefix for the canonical claims


def _build_claims(priv: bytes, channel_key: bytes, attributes: Mapping[str, Any]) -> Claims:
    return Claims(channel_key=channel_key, subject=xeddsa.public_key(priv),
                  attributes=dict(attributes))


class IdentityProver:
    """Prover side: sign a channel-bound claims set with the identity key."""

    def __init__(self, priv: bytes) -> None:
        self._priv = priv

    def attest(self, channel_key: bytes, attributes: Mapping[str, Any]) -> bytes:
        claims = _build_claims(self._priv, channel_key, attributes)
        canonical = claims.canonical()
        sig = xeddsa.sign_ctx(self._priv, IDENTITY_CTX, canonical)
        return _HDR.pack(len(canonical)) + canonical + sig


class IdentityVerifier:
    """Verify-only side for identity attestation."""

    kind = "identity"

    def verify(self, evidence: bytes, *, channel_key: bytes, policy: IdentityPolicy) -> Claims:
        if len(evidence) < _HDR.size:
            raise ClaimsMismatch("evidence too short")
        (clen,) = _HDR.unpack(evidence[: _HDR.size])
        body = evidence[_HDR.size:]
        if clen == 0 or len(body) != clen + xeddsa.SIGNATURE_SIZE:
            raise ClaimsMismatch("evidence framing invalid")
        canonical = body[:clen]
        sig = body[clen:]

        claims = _parse_canonical_claims(canonical)
        # Signature must be valid under the identity that the claims name as subject.
        if not xeddsa.verify_ctx(claims.subject, IDENTITY_CTX, canonical, sig):
            raise SignatureInvalid("identity claims signature invalid")
        # The subject must be the policy's trusted identity (constant-time).
        if not hmac.compare_digest(claims.subject, policy.trusted_identity):
            raise PolicyViolation("identity not trusted by policy")
        # Recomputed canonical must match (defends against non-canonical encodings).
        if claims.canonical() != canonical:
            raise ClaimsMismatch("claims are not in canonical form")
        check_channel_binding(claims, channel_key)
        return claims


def _parse_canonical_claims(canonical: bytes) -> Claims:
    try:
        obj = json.loads(canonical.decode("utf-8"))
        return Claims(
            channel_key=bytes.fromhex(obj["channel_key"]),
            subject=bytes.fromhex(obj["subject"]),
            attributes=obj["attributes"],
        )
    except (ValueError, KeyError, TypeError) as exc:
        raise ClaimsMismatch("could not parse claims") from exc
