"""Shared attestation-verifier protocol and the channel-binding invariant."""
from __future__ import annotations

import hmac
from typing import Protocol, runtime_checkable

from ml_kem_braid.attestation.claims import Claims
from ml_kem_braid.attestation.errors import ChannelBindingError


def check_channel_binding(claims: Claims, channel_key: bytes) -> None:
    """Enforce that the claims bind exactly the negotiated Noise static key.

    Uses a constant-time compare so a mismatch does not leak position via timing.
    hmac.compare_digest also returns False on length mismatch (no exception)."""
    if not hmac.compare_digest(claims.channel_key, channel_key):
        raise ChannelBindingError("claims do not bind the expected channel key")


@runtime_checkable
class AttestationVerifier(Protocol):
    """Verify-only attestation. Implementations return verified Claims iff the
    evidence is authentic under `policy` AND binds `channel_key`, else raise an
    AttestationError. `policy` is the implementation-specific TrustPolicy."""

    kind: str

    def verify(self, evidence: bytes, *, channel_key: bytes, policy) -> Claims:
        ...
