"""Trust policies (trust anchors + acceptance rules) for the two verifiers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class IdentityPolicy:
    """Device/identity attestation: accept exactly this Curve25519 identity key
    (typically the peer's PQXDH bundle ik_pub the client already trusts)."""

    trusted_identity: bytes


@dataclass(frozen=True)
class SgxPolicy:
    """SGX-DCAP attestation trust anchor + acceptance rules. Collateral is offline:
    `pinned_root_der` is the DER of the trusted Intel SGX Root CA (no PCS fetch)."""

    pinned_root_der: bytes
    mrenclave_allow: FrozenSet[bytes] = field(default_factory=frozenset)
    mrsigner_allow: FrozenSet[bytes] = field(default_factory=frozenset)
    min_isv_svn: int = 0

    def __post_init__(self) -> None:
        if not self.pinned_root_der:
            raise ValueError("SgxPolicy requires a pinned root certificate")
        if not self.mrenclave_allow and not self.mrsigner_allow:
            raise ValueError("SgxPolicy requires at least one measurement allowlist")
