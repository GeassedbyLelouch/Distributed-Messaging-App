"""Shared in-process rate-limiting primitive.

One implementation, imported by both :mod:`ml_kem_braid.server.app` and
:mod:`ml_kem_braid.server.decentralized_routes` (round-2 D3): the two modules
previously carried byte-for-byte copies of this class *and* of the client-key
helper, which is exactly how the forwarded-client bug ended up fixed in neither.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

__all__ = ["TokenBucket"]


class TokenBucket:
    """Minimal token bucket keyed by an opaque string.

    Deliberately dependency-free and per-process: a first line of defence
    against trivial single-source flooding, not a distributed quota system.

    Bucket state is bounded by LRU eviction so the limiter cannot itself be
    turned into a memory-exhaustion vector.  Eviction is safe *here* and only
    here: a forgotten bucket is re-created full, i.e. eviction can only grant an
    attacker the allowance they would have regained by waiting
    ``capacity / refill`` seconds anyway.  It is never the sole control on a
    security decision — the endpoints it guards each carry a bound that does not
    depend on remembering individual events (the OPK reserve floor, the mailbox
    quota, the fail-closed circuit cap).
    """

    __slots__ = ("_capacity", "_refill", "_max_keys", "_state", "_lock")

    def __init__(
        self, capacity: int, refill_per_second: float, max_keys: int = 8192
    ) -> None:
        self._capacity = int(capacity)
        self._refill = float(refill_per_second)
        self._max_keys = int(max_keys)
        self._state: "OrderedDict[str, tuple[float, float]]" = OrderedDict()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self._capacity > 0

    def allow(self, key: str) -> bool:
        """Consume one token for ``key``; return ``False`` when exhausted."""
        if self._capacity <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (float(self._capacity), now))
            tokens = min(
                float(self._capacity), tokens + max(0.0, now - last) * self._refill
            )
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._state[key] = (tokens, now)
            self._state.move_to_end(key)
            while len(self._state) > self._max_keys:
                self._state.popitem(last=False)
            return allowed
