from __future__ import annotations

import copy
import hmac
import json
import logging
import threading
import time
from collections import OrderedDict
from typing import Any, Iterable, Optional

from fastapi import APIRouter, Header, HTTPException, Request

from ml_kem_braid.decentralized.records import SignedRecord
from ml_kem_braid.decentralized.services import DecentralizedServices
from ml_kem_braid.server.client_ip import client_key, normalize_trusted_proxies
from ml_kem_braid.server.ratelimit import TokenBucket


_log = logging.getLogger(__name__)

_USERNAME_RECORD_TYPE = "identity.username_record"
_FORBIDDEN_CIRCUIT_FRAME_FIELDS = {
    "username",
    "auth_token",
    "sender_username",
    "recipient_username",
}

# -- circuit relay bounds (audit M14) ---------------------------------------
#: Maximum number of distinct circuits held in the relay map at once.
MAX_CIRCUITS = 1024
#: Maximum circuits a single client may hold open at once (round-2 D4).
#: Partitioning the cap per principal means one flooder can exhaust only its own
#: share, so it can neither evict nor lock out anybody else.
MAX_CIRCUITS_PER_CLIENT = 128
#: Maximum queued frames per circuit.
MAX_FRAMES_PER_CIRCUIT = 64
#: Maximum serialized size of a single frame, in bytes.
MAX_CIRCUIT_FRAME_BYTES = 64 * 1024
#: Maximum nesting depth accepted in a frame (guards the metadata scan).
MAX_CIRCUIT_FRAME_DEPTH = 32
#: Idle lifetime of a circuit queue before it is evicted, in seconds.
CIRCUIT_TTL_SECONDS = 300.0


class _CircuitDepthError(ValueError):
    """Raised when a frame nests deeper than :data:`MAX_CIRCUIT_FRAME_DEPTH`."""


def _contains_identity_metadata(value: Any, max_depth: int = MAX_CIRCUIT_FRAME_DEPTH) -> bool:
    """Iterative, depth-limited scan for forbidden identity fields.

    Audit M14: the previous implementation recursed over arbitrarily nested
    attacker JSON, so a deeply nested body raised ``RecursionError`` and the
    handler returned 500 (and, worse, never completed the privacy check).  This
    version uses an explicit stack and rejects over-deep frames outright — the
    scan must never fail open.
    """
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            raise _CircuitDepthError("frame nesting too deep")
        if isinstance(node, dict):
            for key, nested_value in node.items():
                if isinstance(key, str) and key.lower() in _FORBIDDEN_CIRCUIT_FRAME_FIELDS:
                    return True
                stack.append((nested_value, depth + 1))
        elif isinstance(node, list):
            for item in node:
                stack.append((item, depth + 1))
    return False


#: :meth:`_CircuitFrameStore.append` outcomes.
APPEND_OK = "queued"
APPEND_CIRCUIT_FULL = "circuit_full"
APPEND_AT_CAPACITY = "relay_at_capacity"
APPEND_OWNER_QUOTA = "owner_quota_exceeded"


class _CircuitFrameStore:
    """Bounded, TTL-evicting store of queued circuit frames.

    Audit M14: the relay map used to be an unbounded process-global dict keyed
    by an attacker-chosen ``circuit_id``, so anyone could pin arbitrary memory.
    Every dimension is now capped (circuit count, frames per circuit, frame
    size) and idle circuits expire.

    Round-2 D4: the M14 bound made room for a new circuit by *evicting* the
    least-recently-touched one.  That handed an unauthenticated attacker a
    cheap total-denial primitive the unbounded map never gave them: post
    ``max_circuits`` junk frames and every other circuit's queued frames are
    silently destroyed.  A bounded cache that a stranger can flush is not a
    bound, it is an eviction oracle.  The store now **fails closed** — at
    capacity a *new* circuit is refused (the caller gets 503) and existing
    circuits are never touched.  The only eviction left is the TTL sweep, which
    is driven by the clock, not by attacker traffic.

    Failing closed on a *shared* cap would still let a flooder lock everyone
    else out, so circuit **creation** is additionally partitioned per client
    (``max_circuits_per_client``): the cost of a flood is charged to the
    flooder's own share and legitimate peers keep creating circuits.
    """

    __slots__ = (
        "_max_circuits",
        "_max_frames",
        "_max_per_owner",
        "_ttl",
        "_lock",
        "_circuits",
        "_owner_counts",
    )

    def __init__(
        self,
        max_circuits: int = MAX_CIRCUITS,
        max_frames: int = MAX_FRAMES_PER_CIRCUIT,
        ttl_seconds: float = CIRCUIT_TTL_SECONDS,
        max_circuits_per_client: int = MAX_CIRCUITS_PER_CLIENT,
    ) -> None:
        self._max_circuits = max_circuits
        self._max_frames = max_frames
        self._max_per_owner = max_circuits_per_client
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        # circuit_id -> (last_touched_monotonic, frames, owner)
        self._circuits: (
            "OrderedDict[str, tuple[float, list[dict[str, Any]], str]]"
        ) = OrderedDict()
        # owner -> number of live circuits it created.  Derived from
        # ``_circuits`` (never larger than it), so it adds no new unbounded
        # state and needs no eviction policy of its own.
        self._owner_counts: dict[str, int] = {}

    def _drop_locked(self, circuit_id: str):
        entry = self._circuits.pop(circuit_id, None)
        if entry is not None:
            owner = entry[2]
            remaining = self._owner_counts.get(owner, 0) - 1
            if remaining > 0:
                self._owner_counts[owner] = remaining
            else:
                self._owner_counts.pop(owner, None)
        return entry

    def _evict_expired_locked(self, now: float) -> None:
        expired = [
            cid
            for cid, (touched, _, _) in self._circuits.items()
            if now - touched > self._ttl
        ]
        for cid in expired:
            self._drop_locked(cid)

    def append(self, circuit_id: str, frame: dict[str, Any], owner: str = "") -> str:
        """Queue ``frame`` on behalf of ``owner`` (the client's rate-limit key).

        Returns :data:`APPEND_OK`, :data:`APPEND_CIRCUIT_FULL` (this circuit's
        queue is full), :data:`APPEND_OWNER_QUOTA` (this client already holds
        its share of circuits) or :data:`APPEND_AT_CAPACITY` (the relay is full
        and refuses to create another circuit).  Existing circuits are never
        sacrificed to make room — see the class docstring.
        """
        now = time.monotonic()
        with self._lock:
            self._evict_expired_locked(now)
            entry = self._circuits.get(circuit_id)
            if entry is None:
                if self._max_frames <= 0:
                    # Nothing could be queued anyway; do not create the circuit.
                    return APPEND_CIRCUIT_FULL
                if self._owner_counts.get(owner, 0) >= self._max_per_owner:
                    # Charge the flood to the flooder, not to its victims.
                    return APPEND_OWNER_QUOTA
                if len(self._circuits) >= self._max_circuits:
                    # Fail closed: refuse the newcomer rather than destroy a
                    # stranger's queued frames (round-2 D4).
                    return APPEND_AT_CAPACITY
                entry = (now, [], owner)
                self._circuits[circuit_id] = entry
                self._owner_counts[owner] = self._owner_counts.get(owner, 0) + 1
            frames = entry[1]
            if len(frames) >= self._max_frames:
                return APPEND_CIRCUIT_FULL
            frames.append(frame)
            self._circuits[circuit_id] = (now, frames, entry[2])
            self._circuits.move_to_end(circuit_id)
            return APPEND_OK

    def drain(self, circuit_id: str) -> list[dict[str, Any]]:
        now = time.monotonic()
        with self._lock:
            self._evict_expired_locked(now)
            entry = self._drop_locked(circuit_id)
        return entry[1] if entry is not None else []


#: Round-2 D3: this used to be a byte-for-byte copy of ``app._TokenBucket``.
#: One implementation now, so a fix to one is a fix to both.
_IpRateLimiter = TokenBucket


def build_decentralized_router(
    services: DecentralizedServices,
    relay_token: Optional[str] = None,
    rate_limit: tuple[int, float] = (240, 20.0),
    frame_store: Optional[_CircuitFrameStore] = None,
    trusted_proxies: Iterable[str] = (),
) -> APIRouter:
    """Build the experimental decentralized router.

    Args:
        services:    Signed-record / username registry services.
        relay_token: Optional shared bearer token gating the circuit-relay
                     endpoints (audit M14).  ``None`` leaves the relay open —
                     circuit frames are deliberately anonymous, so there is no
                     per-user identity to authenticate against — but the
                     bounds and rate limit below always apply.
        rate_limit:  ``(capacity, refill_per_second)`` per client for the
                     circuit endpoints; capacity ``0`` disables it.
        frame_store: Injectable store, mainly so tests can shrink the caps.
        trusted_proxies: Peer addresses whose ``X-Forwarded-For`` may be used to
                     derive the rate-limit key (round-2 D3).  Shares one
                     implementation with the main app
                     (:mod:`ml_kem_braid.server.client_ip`) so the two limiters
                     cannot diverge; empty means the header is never trusted.
    """
    router = APIRouter()
    circuit_frames = frame_store or _CircuitFrameStore()
    circuit_limiter = _IpRateLimiter(*rate_limit)
    proxies = normalize_trusted_proxies(trusted_proxies)

    def _authorize_relay(authorization: str) -> None:
        if relay_token is None:
            return
        presented = (
            authorization[len("Bearer "):]
            if authorization.startswith("Bearer ")
            else ""
        )
        if not hmac.compare_digest(presented, relay_token):
            raise HTTPException(status_code=401, detail="invalid relay token")

    def _rate_limit(request: Request) -> None:
        if not circuit_limiter.allow(client_key(request, proxies)):
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    @router.post("/v1/records")
    async def publish_record(request: Request) -> dict[str, str]:
        try:
            payload: Any = await request.json()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="malformed JSON") from exc

        try:
            record = SignedRecord.from_dict(payload)
        except (TypeError, ValueError) as exc:
            # Audit L11: the parser message names internal field/type details.
            _log.info("rejected malformed signed record: %s", exc)
            raise HTTPException(status_code=400, detail="malformed record") from exc

        try:
            services.publish_record(record)
        except TypeError as exc:
            # Round-2 D5: the canonical codec rejects floats (and non-string
            # object keys) with TypeError, raised from
            # ``SignedRecord.signing_payload()`` *inside* verification — a plain
            # float anywhere in the body used to escape as an unauthenticated
            # 500.  It is a malformed record, not a server fault.
            _log.info("rejected non-canonical signed record: %s", exc)
            raise HTTPException(status_code=400, detail="malformed record") from exc
        except PermissionError as exc:
            _log.info("record publish denied: %s", exc)
            raise HTTPException(status_code=403, detail="record rejected") from exc
        except ValueError as exc:
            already = "already registered" in str(exc)
            _log.info("record publish rejected: %s", exc)
            raise HTTPException(
                status_code=409 if already else 422,
                detail="name already registered" if already else "record rejected",
            ) from exc

        return {"status": "published"}

    @router.get("/v1/records/{record_type}/{lookup}")
    def lookup_record(record_type: str, lookup: str) -> dict[str, Any]:
        if record_type != _USERNAME_RECORD_TYPE:
            raise HTTPException(status_code=404, detail="unknown record type")

        record = services.lookup_username(lookup)
        if record is None:
            raise HTTPException(status_code=404, detail="record not found")
        return record.to_dict()

    @router.post("/v1/circuits/{circuit_id}/frames")
    async def queue_circuit_frame(
        circuit_id: str,
        request: Request,
        authorization: str = Header(default=""),
    ) -> dict[str, str]:
        _authorize_relay(authorization)
        _rate_limit(request)

        raw = await request.body()
        if len(raw) > MAX_CIRCUIT_FRAME_BYTES:
            raise HTTPException(status_code=413, detail="frame too large")
        try:
            payload: Any = json.loads(raw)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="malformed JSON") from exc
        except RecursionError as exc:
            # The stdlib decoder itself recurses; a pathologically nested body
            # must be a client error, never an unhandled 500 (audit M14).
            raise HTTPException(status_code=400, detail="malformed JSON") from exc

        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="frame must be a JSON object")

        try:
            has_identity_metadata = _contains_identity_metadata(payload)
        except _CircuitDepthError as exc:
            # Fail closed: an unscannable frame is rejected, never queued.
            raise HTTPException(status_code=422, detail="frame nesting too deep") from exc
        if has_identity_metadata:
            raise HTTPException(status_code=422, detail="identity metadata is not allowed")

        outcome = circuit_frames.append(
            circuit_id, copy.deepcopy(payload), owner=client_key(request, proxies)
        )
        if outcome == APPEND_CIRCUIT_FULL:
            raise HTTPException(status_code=429, detail="circuit frame queue full")
        if outcome == APPEND_OWNER_QUOTA:
            # Per-client partition (round-2 D4): the flooder exhausts only its
            # own share, so it can neither evict nor lock out other peers.
            raise HTTPException(status_code=429, detail="circuit quota exceeded")
        if outcome == APPEND_AT_CAPACITY:
            # Fail closed (round-2 D4): refuse the new circuit; never evict an
            # existing one to make room.
            _log.warning("circuit relay at capacity; refusing new circuit")
            raise HTTPException(
                status_code=503,
                detail="circuit relay at capacity",
                headers={"Retry-After": "1"},
            )
        return {"status": "queued"}

    @router.get("/v1/circuits/{circuit_id}/frames")
    def drain_circuit_frames(
        circuit_id: str,
        request: Request,
        authorization: str = Header(default=""),
    ) -> dict[str, list[dict[str, Any]]]:
        _authorize_relay(authorization)
        _rate_limit(request)
        frames = circuit_frames.drain(circuit_id)
        return {"frames": copy.deepcopy(frames)}

    return router
