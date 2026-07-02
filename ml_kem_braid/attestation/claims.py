"""Attestation claims: the bundle of assertions bound to a Noise channel key."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ml_kem_braid.decentralized.canonical import canonical_json, sha256_bytes


@dataclass(frozen=True)
class Claims:
    """Assertions an attested peer makes about itself, bound to a channel key.

    channel_key -- the Noise responder static public key ("pk") these claims bind to (32B).
    subject     -- SGX MRENCLAVE (32B) or the identity Curve25519 public key (32B).
    attributes  -- arbitrary JSON-serialisable metadata (device_id, versions, tcb, ...).
    """

    channel_key: bytes
    subject: bytes
    attributes: Mapping[str, Any]

    def canonical(self) -> bytes:
        """Deterministic byte encoding (RFC-8785-style canonical JSON) of the claims.
        Binary fields are hex so the encoding is pure-JSON and order-independent."""
        return canonical_json(
            {
                "channel_key": self.channel_key.hex(),
                "subject": self.subject.hex(),
                "attributes": dict(self.attributes),
            }
        )

    def report_data(self) -> bytes:
        """32-byte SGX report_data commitment: SHA-256 over the canonical claims."""
        return sha256_bytes(self.canonical())
