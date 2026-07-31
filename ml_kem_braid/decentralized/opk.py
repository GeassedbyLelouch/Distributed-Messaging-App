from __future__ import annotations

import hmac
import secrets
import threading
from dataclasses import dataclass
from typing import Dict, Optional

# Lease lifecycle states. ``expired`` is TERMINAL: a one-time prekey whose
# public half was handed to an initiator is burned, whether or not the
# handshake completed (audit H2 / verifier D10).
_AVAILABLE = "available"
_LEASED = "leased"
_CONSUMED = "consumed"
_EXPIRED = "expired"


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
    state: str = _AVAILABLE
    lease_id: Optional[str] = None
    expires_at: Optional[float] = None


class OPKLeaseStore:
    """One-time-prekey lease store with atomic claim and burn-once semantics.

    Audit H2: ``lease_opk`` used to scan for an ``available`` entry and mutate
    it in a second, unsynchronised step. Two concurrent callers could both
    observe the same entry as available and both receive the same
    ``opk_id``/``opk_pub``, so a *one-time* prekey was consumed by two
    handshakes (breaking OPK uniqueness, and with it forward secrecy and KCI
    resistance for those sessions).

    The claim is now a single compare-and-set executed while holding
    ``self._lock``: scan, state check and state mutation happen without any
    interleaving window. The scan/mutate pair is deliberately isolated in
    :meth:`_claim_available_locked` so a database backend can replace it
    verbatim with a single-statement CAS
    (``UPDATE opks SET state='leased', ... WHERE username=? AND device_id=?
    AND state='available' ... RETURNING opk_id, opk_pub``).

    Burn-once on expiry (verifier D10)
    ----------------------------------
    An earlier revision reclaimed an *expired* lease back to ``available`` so a
    stalled initiator could not exhaust the pool. That reinstated exactly the
    impact H2 closed by the slower path: the same ``opk_pub`` was served to a
    second initiator, so the prekey was no longer one-time and the forward
    secrecy/KCI argument that motivates one-time prekeys was lost. Availability
    does not outrank that here, so an expired lease is now parked in the
    terminal ``expired`` state and the prekey is never served again.

    Exhaustion is handled the correct way instead:

    * :meth:`available_count` lets the owner top the pool up (replenishment);
    * a peer that finds no OPK falls back to the signed prekey, which is the
      documented last-resort path in X3DH/PQXDH;
    * :meth:`release_untransmitted_lease` is a narrow, explicitly-attested
      escape hatch for the one case that is provably safe — a lease whose
      ``opk_pub`` was never transmitted to any peer (e.g. the bundle response
      failed before it left the process). It is opt-in per lease, requires the
      secret ``lease_id``, and is never applied automatically.
    """

    def __init__(self) -> None:
        self._opks: Dict[tuple[str, int, int], _OPKEntry] = {}
        self._lock = threading.Lock()

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
        with self._lock:
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
        with self._lock:
            self._expire_old_leases_locked(now)
            return self._claim_available_locked(username, device_id, now, ttl)

    def _claim_available_locked(
        self,
        username: str,
        device_id: int,
        now: float,
        ttl: float,
    ) -> Optional[OPKLease]:
        """Atomic compare-and-set: find ``available`` and flip it to ``leased``.

        Caller MUST hold ``self._lock``. This is the single seam a DB backend
        replaces with ``UPDATE ... WHERE state='available' ... RETURNING``.
        """

        for (entry_user, entry_device, opk_id), entry in sorted(self._opks.items()):
            if entry_user != username or entry_device != device_id:
                continue
            if entry.state != _AVAILABLE:
                continue
            lease_id = f"opklease-{secrets.token_urlsafe(18)}"
            entry.state = _LEASED
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
        with self._lock:
            self._expire_old_leases_locked(now)
            entry = self._opks.get((username, device_id, opk_id))
            if (
                entry is None
                or entry.state != _LEASED
                or entry.lease_id is None
                or not isinstance(lease_id, str)
                or not hmac.compare_digest(entry.lease_id, lease_id)
            ):
                raise KeyError("unknown or already consumed OPK lease")
            entry.state = _CONSUMED
            entry.lease_id = lease_id

    def release_untransmitted_lease(
        self,
        username: str,
        device_id: int,
        opk_id: int,
        lease_id: str,
        now: float,
    ) -> None:
        """Return a lease to ``available`` — ONLY if ``opk_pub`` never left.

        This is the single reclaim path, and it is never automatic. The caller
        asserts, by presenting the secret ``lease_id``, that the leased
        ``opk_pub`` was not transmitted to any peer; under that precondition
        re-serving the prekey cannot break one-time-ness, because no initiator
        ever saw it. Calling this after the bundle was sent re-opens audit H2 —
        do not use it as a timeout handler.

        A lease that has already expired (terminal) or been consumed cannot be
        released; the caller must decide before the TTL elapses.
        """

        with self._lock:
            self._expire_old_leases_locked(now)
            entry = self._opks.get((username, device_id, opk_id))
            if (
                entry is None
                or entry.state != _LEASED
                or entry.lease_id is None
                or not isinstance(lease_id, str)
                or not hmac.compare_digest(entry.lease_id, lease_id)
            ):
                raise KeyError("unknown, expired or already consumed OPK lease")
            entry.state = _AVAILABLE
            entry.lease_id = None
            entry.expires_at = None

    def available_count(self, username: str, device_id: int) -> int:
        """Number of prekeys still leasable — the replenishment signal."""

        with self._lock:
            return sum(
                1
                for (entry_user, entry_device, _), entry in self._opks.items()
                if entry_user == username
                and entry_device == device_id
                and entry.state == _AVAILABLE
            )

    def state_of(self, username: str, device_id: int, opk_id: int) -> Optional[str]:
        """Current lifecycle state of an OPK (``None`` if unknown)."""

        with self._lock:
            entry = self._opks.get((username, device_id, opk_id))
            return None if entry is None else entry.state

    def _expire_old_leases_locked(self, now: float) -> None:
        for entry in self._opks.values():
            if entry.state == _LEASED and entry.expires_at is not None:
                if entry.expires_at <= now:
                    # Terminal: a transmitted one-time prekey is burned.
                    entry.state = _EXPIRED
