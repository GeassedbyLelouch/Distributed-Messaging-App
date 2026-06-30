from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class OPKLease:
    lease_id: str
    username: str
    device_id: int
    opk_id: int
    opk_pub: bytes
    expires_at: float


@dataclass
class _OPKEntry:
    opk_pub: bytes
    state: str = "available"
    lease_id: Optional[str] = None
    expires_at: Optional[float] = None


class OPKLeaseStore:
    def __init__(self) -> None:
        self._opks: Dict[tuple[str, int, int], _OPKEntry] = {}

    def add_opk(
        self,
        username: str,
        device_id: int,
        opk_id: int,
        opk_pub: bytes,
    ) -> bool:
        if not isinstance(opk_pub, bytes):
            raise TypeError("opk_pub must be bytes")
        key = (username, device_id, opk_id)
        if key in self._opks:
            return False
        self._opks[key] = _OPKEntry(opk_pub=opk_pub)
        return True

    def lease_opk(
        self,
        username: str,
        device_id: int,
        now: float,
        ttl: float,
    ) -> Optional[OPKLease]:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        self._expire_old_leases(now)
        for (entry_user, entry_device, opk_id), entry in sorted(self._opks.items()):
            if entry_user != username or entry_device != device_id:
                continue
            if entry.state != "available":
                continue
            lease_id = f"opklease-{secrets.token_urlsafe(18)}"
            entry.state = "leased"
            entry.lease_id = lease_id
            entry.expires_at = now + ttl
            return OPKLease(
                lease_id=lease_id,
                username=username,
                device_id=device_id,
                opk_id=opk_id,
                opk_pub=entry.opk_pub,
                expires_at=entry.expires_at,
            )
        return None

    def consume_opk(
        self,
        username: str,
        device_id: int,
        opk_id: int,
        lease_id: str,
        now: float,
    ) -> None:
        self._expire_old_leases(now)
        entry = self._opks.get((username, device_id, opk_id))
        if entry is None or entry.state != "leased" or entry.lease_id != lease_id:
            raise KeyError("unknown or already consumed OPK lease")
        entry.state = "consumed"
        entry.lease_id = lease_id

    def _expire_old_leases(self, now: float) -> None:
        for entry in self._opks.values():
            if entry.state == "leased" and entry.expires_at is not None:
                if entry.expires_at <= now:
                    entry.state = "expired"
