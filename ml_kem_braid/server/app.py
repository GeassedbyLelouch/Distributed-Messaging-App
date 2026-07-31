"""
FastAPI server: PQXDH key distribution + Sesame mailbox relay.

Endpoints (all JSON):
  POST /register                      register a device (username + public bundle)
  GET  /keys/{username}               list device ids for a user
  GET  /keys/{username}/{device_id}   fetch a prekey bundle (consumes a one-time prekey)
  POST /messages                      relay an opaque encrypted envelope to a device
  GET  /messages   (Bearer token)     drain the calling device's mailbox
  WS   /ws         (Bearer token)     real-time push channel (send + receive)
                                      (auth via Authorization header; the
                                      ``?token=`` query param is deprecated)
  GET  /health                        liveness probe

The server is a dumb relay: it stores only minimal metadata (username, device id,
registration id, timestamps) and public prekey bundles, and forwards opaque
envelopes. It never sees private keys or plaintext.

WebSocket security: sender identity is always resolved from the connection
token — never from the frame body — so clients cannot spoof each other.

Mailbox / WebSocket delivery split
------------------------------------
When a recipient device has at least one live WebSocket connection, envelopes are
delivered in real time via that connection.  An envelope is stored in the persistent
mailbox **only when no live socket successfully accepted it** (e.g. the socket died
between the connectivity check and the send).  Clients should pick ONE transport per
device: either poll ``GET /messages`` (HTTP) or hold a ``/ws`` connection open (WS).
Using both simultaneously is harmless but each WS-delivered envelope will NOT appear
in a subsequent ``GET /messages`` response because it was not written to the mailbox.
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, Response

from ml_kem_braid.crypto import xeddsa
from ml_kem_braid.pqxdh import create_identity, create_prekey_bundle
from ml_kem_braid.pqxdh.pqxdh import _x25519_pub_bytes
from ml_kem_braid.decentralized.services import DecentralizedServices
from ml_kem_braid.server.client_ip import (
    client_key as _forwarded_client_key,
    normalize_host,
    normalize_trusted_proxies,
)
from ml_kem_braid.server.decentralized_routes import build_decentralized_router
from ml_kem_braid.server.ratelimit import TokenBucket
from ml_kem_braid.sesame.base import StoreBackend
from ml_kem_braid.sesame.sqlite_store import SqliteStore
from ml_kem_braid.sesame.store import (
    Contact,
    ContactRequestRecord,
    Device,
    Envelope,
    SesameStore,
)
from ml_kem_braid.sesame.usernames import UsernameValidationError, normalize_username
from ml_kem_braid.wire import b64d, b64e, bundle_to_dict, registration_challenge

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TLS enforcement middleware
# ---------------------------------------------------------------------------

_HSTS_VALUE = "max-age=63072000; includeSubDomains"

# Paths exempt from the HTTPS requirement so liveness probes can reach the
# server over plain HTTP (e.g. load-balancer health checks).
_TLS_EXEMPT_PATHS: frozenset[str] = frozenset({"/health"})


class _TLSEnforcementMiddleware(BaseHTTPMiddleware):
    """Reject non-HTTPS traffic with 426 and add HSTS to every response.

    Detection strategy (in order):
    1. ASGI ``scope["scheme"]`` — set by uvicorn when the server is started
       with TLS; equals ``"https"`` / ``"wss"`` for TLS connections.  This is
       the only signal that cannot be forged by the client.
    2. ``X-Forwarded-Proto: https`` — set by a reverse proxy (nginx, AWS ALB,
       Cloudflare).  **Audit M11:** this header is attacker-controlled, so it
       is honoured *only* when the immediate peer (``request.client.host``)
       appears in the configured ``trusted_proxies`` allow-list.  The default
       allow-list is empty, meaning the header is never trusted and a
       cleartext client cannot defeat the 426 gate (nor poison HSTS).

    Exempt paths (see ``_TLS_EXEMPT_PATHS``) pass through regardless so
    liveness probes work over plaintext.
    """

    def __init__(self, app, trusted_proxies: Iterable[str] = ()) -> None:
        super().__init__(app)
        self._trusted_proxies: frozenset[str] = normalize_trusted_proxies(
            trusted_proxies
        )

    def _forwarded_proto_is_trusted(self, request: Request) -> bool:
        """Is ``X-Forwarded-Proto`` allowed to influence the TLS decision?"""
        if not self._trusted_proxies:
            return False
        client = request.client
        peer = normalize_host(client.host) if client is not None else ""
        return bool(peer) and peer in self._trusted_proxies

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        path = request.url.path
        if path in _TLS_EXEMPT_PATHS:
            # Exempt endpoint — pass through; still add HSTS so browsers know.
            response: Response = await call_next(request)
            response.headers["Strict-Transport-Security"] = _HSTS_VALUE
            return response

        # Determine whether the transport is secure.
        scheme = request.scope.get("scheme", "http")
        is_secure = scheme in ("https", "wss")
        if not is_secure and self._forwarded_proto_is_trusted(request):
            forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
            # Take the left-most (client-facing) hop of a proxy chain.
            is_secure = forwarded_proto.split(",")[0].strip() == "https"

        if not is_secure:
            return Response(
                content='{"detail":"TLS required — use HTTPS"}',
                status_code=426,
                media_type="application/json",
                headers={"Upgrade": "TLS/1.2, HTTP/1.1"},
            )

        response = await call_next(request)
        response.headers["Strict-Transport-Security"] = _HSTS_VALUE
        return response


# ---------------------------------------------------------------------------
# Abuse limits (audit H1, M12, M13)
# ---------------------------------------------------------------------------

#: Hard ceiling on the number of one-time prekeys accepted at registration.
#: Mirrors the ``le=64`` already enforced on :class:`UIRegisterRequest`.
MAX_ONE_TIME_PREKEYS = 64


@dataclass(frozen=True)
class ServerLimits:
    """Tunable abuse limits.

    Rate limits are ``(capacity, refill_tokens_per_second)`` pairs; a
    ``capacity`` of ``0`` disables that limiter entirely (useful for tests and
    single-tenant deployments behind another rate limiter).
    """

    # Per-source-IP: prekey-bundle fetches (audit H1).
    prekey_bundle_rate: tuple[int, float] = (60, 1.0)
    # Per-source-IP: device registrations (audit M12).
    register_rate: tuple[int, float] = (20, 0.1)
    # Per-auth-token: outbound messages, HTTP and WebSocket (audit M13).
    #
    # Deliberately generous. ``/messages`` carries the Braid SCKA handshake as
    # well as chat: negotiating ONE epoch costs ~46 posts per device, so a
    # bucket sized for human typing rates silently caps how many epochs a
    # session may negotiate — and it fails hard (the client raises on 429), it
    # does not back off. The tight controls on this endpoint are the mailbox
    # quota (``max_mailbox_per_device``) and the body cap
    # (``max_message_body_bytes``), which bound what a flood can actually
    # consume; this bucket is a flood valve on top of them.
    send_rate: tuple[int, float] = (4096, 256.0)
    # Per-source-IP: circuit-relay frame posts (audit M14).
    circuit_rate: tuple[int, float] = (240, 20.0)

    #: Number of one-time prekeys that are reserved from **every** caller,
    #: authenticated or not (audit H1; round-2 D1).
    #:
    #: The round-1 fix reserved the floor from *anonymous* callers only.  But
    #: ``POST /register`` is necessarily unauthenticated, so "authenticated" is
    #: an identity anyone mints for free: register once, then drain the victim's
    #: pool to zero.  The floor must therefore not be a function of "has a
    #: token".  It is derived from the pool size itself — state an attacker can
    #: only shrink, never forge, flood or evict — so no cache stands between the
    #: attack and the decision.
    opk_reserve_floor: int = 1
    #: *Additional* reserve applied to unauthenticated callers.  The effective
    #: floor is ``max(opk_reserve_floor, opk_anonymous_floor)`` for anonymous
    #: callers and ``opk_reserve_floor`` for authenticated ones — so raising
    #: this can only make the endpoint stricter, never weaker.
    opk_anonymous_floor: int = 1
    #: Emit a warning once the remaining pool reaches this size.
    opk_low_water: int = 2

    #: Maximum serialized size of a relayed message body (audit M13).
    max_message_body_bytes: int = 64 * 1024
    #: Maximum number of undelivered envelopes queued per recipient device.
    max_mailbox_per_device: int = 1024

    #: Maximum one-time prekeys accepted in a single registration (audit M12).
    max_one_time_prekeys: int = MAX_ONE_TIME_PREKEYS


#: Shared with the decentralized router — one implementation, no drift (D3).
_TokenBucket = TokenBucket


def _rate_limit(bucket: TokenBucket, key: str, what: str) -> None:
    """Raise 429 when ``key`` has exhausted ``bucket``."""
    if not bucket.allow(key):
        _log.warning("rate limit exceeded for %s (key=%s)", what, key)
        raise HTTPException(status_code=429, detail="rate limit exceeded")


# -- request / response models ---------------------------------------------


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    registration_id: int = Field(ge=0, lt=2**31)
    bundle: dict
    # XEdDSA signature over registration_challenge(username, registration_id),
    # proving possession of the bundle's ik_pub (base64).
    proof_sig: str
    # Audit M12: bounded so a single registration cannot pin unbounded memory.
    one_time_prekeys: dict[str, str] = Field(
        default_factory=dict, max_length=MAX_ONE_TIME_PREKEYS
    )


class RegisterResponse(BaseModel):
    username: str
    device_id: int
    auth_token: str


class UIRegisterRequest(BaseModel):
    username: str
    registration_id: int = Field(default=1, ge=0, lt=2**31)
    one_time_prekey_count: int = Field(default=4, ge=0, le=64)


class UsernameLookupResponse(BaseModel):
    username_display: str
    username_hash: str
    device_id: int
    registration_id: int


class DeviceInfo(BaseModel):
    device_id: int
    registration_id: int


class ContactRequest(BaseModel):
    username: str
    device_id: int = Field(ge=1)
    alias: Optional[str] = Field(default=None, max_length=64)


class ContactResponse(BaseModel):
    contact_id: str
    username_display: str
    username_hash: str
    contact_username: str
    contact_device_id: int
    alias: Optional[str]
    verified: bool
    created_at: float


class ContactRequestResponse(BaseModel):
    request_id: str
    status: str
    direction: str
    requester_username: str
    requester_device_id: int
    requester_username_display: str
    requester_username_hash: str
    recipient_username: str
    recipient_device_id: int
    recipient_username_display: str
    recipient_username_hash: str
    peer_username_display: str
    peer_username_hash: str
    peer_device_id: int
    alias: Optional[str]
    created_at: float
    updated_at: float


class ContactRequestsResponse(BaseModel):
    inbound: List[ContactRequestResponse]
    outbound: List[ContactRequestResponse]


class SendMessageRequest(BaseModel):
    # Sender identity is derived from the caller's bearer token, never the body.
    recipient_username: str
    recipient_device_id: int
    kind: str = Field(pattern="^(pqxdh_init|braid|chat)$")
    body: dict


class EnvelopeModel(BaseModel):
    envelope_id: str
    sender_username: str
    sender_device_id: int
    recipient_username: str
    recipient_device_id: int
    kind: str
    body: dict
    created_at: float


def _envelope_to_model(env: Envelope) -> EnvelopeModel:
    return EnvelopeModel(
        envelope_id=env.envelope_id,
        sender_username=env.sender_username,
        sender_device_id=env.sender_device_id,
        recipient_username=env.recipient_username,
        recipient_device_id=env.recipient_device_id,
        kind=env.kind,
        body=env.body,
        created_at=env.created_at,
    )


# -- WebSocket connection manager ------------------------------------------


class ConnectionManager:
    """Track live WebSocket connections keyed by (username, device_id).

    Multiple connections per device are supported (dict value is a set).
    All push operations are fire-and-forget: a failed send silently removes
    the dead socket.
    """

    def __init__(self) -> None:
        # (username, device_id) -> set of live WebSocket objects
        self._connections: Dict[tuple[str, int], Set[WebSocket]] = {}

    def connect(self, username: str, device_id: int, ws: WebSocket) -> None:
        key = (username, device_id)
        self._connections.setdefault(key, set()).add(ws)

    def disconnect(self, username: str, device_id: int, ws: WebSocket) -> None:
        key = (username, device_id)
        sockets = self._connections.get(key)
        if sockets:
            sockets.discard(ws)
            if not sockets:
                del self._connections[key]

    async def push_envelope(
        self, username: str, device_id: int, envelope_model: EnvelopeModel
    ) -> int:
        """Send an envelope JSON frame to all live sockets for a device.

        Dead sockets are silently removed.  We use a snapshot so iterating
        does not conflict with concurrent disconnects.

        Returns:
            The number of sockets that successfully received the frame.
            A return value of 0 means no live socket accepted the envelope
            (the caller should fall back to storing it in the mailbox).
        """
        key = (username, device_id)
        sockets = set(self._connections.get(key, set()))  # snapshot
        success_count = 0
        for ws in sockets:
            try:
                await ws.send_json(
                    {"type": "envelope", "envelope": envelope_model.model_dump()}
                )
                success_count += 1
            except Exception:
                # Socket is dead; remove it.
                self.disconnect(username, device_id, ws)
        return success_count


def create_app(
    store: Optional[StoreBackend] = None,
    enforce_tls: bool = False,
    enable_demo_ui: bool = False,
    enable_decentralized: bool = False,
    trusted_proxies: Iterable[str] = (),
    limits: Optional[ServerLimits] = None,
    circuit_relay_token: Optional[str] = None,
) -> FastAPI:
    """Build a FastAPI app backed by ``store`` (a fresh in-memory store by default).

    Args:
        store:       Persistent or in-memory store backend.  A fresh
                     :class:`~ml_kem_braid.sesame.store.SesameStore` is used
                     when not provided.
        enforce_tls: When ``True``, attach :class:`_TLSEnforcementMiddleware`
                     which rejects plaintext HTTP with **426 Upgrade Required**
                     and adds ``Strict-Transport-Security`` to every response.
                     ``/health`` is exempt so liveness probes work over HTTP.
                     Defaults to ``False`` so all existing tests pass unchanged.
        enable_demo_ui: Enable the development-only ``/ui/register`` helper,
                     which generates demo key material server-side for the
                     browser UI. Defaults to ``False`` for production safety.
        enable_decentralized: Enable the experimental decentralized signed-record
                     registry API. Defaults to ``False`` to preserve the existing
                     route surface.
        trusted_proxies: Peer addresses whose ``X-Forwarded-Proto`` header the
                     TLS middleware is allowed to trust (audit M11).  Empty by
                     default — the header is then *never* trusted.
        limits:      Abuse limits (rate limits, body/mailbox caps).  See
                     :class:`ServerLimits`; defaults are used when omitted.
        circuit_relay_token: Optional shared bearer token required to post or
                     drain decentralized circuit-relay frames (audit M14).
                     ``None`` keeps the relay open (frames stay anonymous) but
                     still hard-bounded and rate limited.
    """
    store = store or SesameStore()
    limits = limits or ServerLimits()
    app = FastAPI(title="ML-KEM Braid Chat Server", version="0.3.0")
    # Audit M11 / round-2 D3: ONE allow-list drives both the TLS decision and
    # every rate-limit key, so the limiters cannot collapse into a single global
    # bucket behind the reverse proxy M11 was written to support.
    _trusted_proxies = normalize_trusted_proxies(trusted_proxies)
    if enforce_tls:
        app.add_middleware(_TLSEnforcementMiddleware, trusted_proxies=_trusted_proxies)
    app.state.store = store
    app.state.limits = limits
    app.state.trusted_proxies = _trusted_proxies

    def _client_key(request: Request) -> str:
        """Rate-limit key: the forwarded client when the peer is a trusted proxy."""
        return _forwarded_client_key(request, _trusted_proxies)

    _bundle_bucket = _TokenBucket(*limits.prekey_bundle_rate)
    _register_bucket = _TokenBucket(*limits.register_rate)
    _send_bucket = _TokenBucket(*limits.send_rate)

    # Observability for audit H1: how often a device's one-time prekey pool ran
    # down to the anonymous floor.  Keyed by ``(username, device_id)``.
    opk_depletion_events: Dict[tuple[str, int], int] = {}
    app.state.opk_depletion_events = opk_depletion_events

    if enable_decentralized:
        decentralized_services = DecentralizedServices()
        app.state.decentralized_services = decentralized_services
        app.include_router(
            build_decentralized_router(
                decentralized_services,
                relay_token=circuit_relay_token,
                rate_limit=limits.circuit_rate,
                trusted_proxies=_trusted_proxies,
            )
        )

    # Shared connection manager for the WebSocket endpoint.
    manager = ConnectionManager()
    app.state.manager = manager

    _envelope_counter = {"n": 0}
    _envelope_lock = threading.Lock()
    #: Serializes the OPK floor check with the consumption it authorizes.
    _bundle_lock = threading.Lock()

    def _next_envelope_id() -> str:
        """Process-unique *and* globally unique envelope id.

        Audit L10: the counter alone restarts at 0 on every process start, so a
        restart with undrained mailbox rows collided on the ``envelope_id``
        PRIMARY KEY (``sqlite3.IntegrityError`` → 500).  The random suffix makes
        collisions negligible while the counter keeps ids roughly ordered.
        """
        with _envelope_lock:
            _envelope_counter["n"] += 1
            n = _envelope_counter["n"]
        return f"env-{n}-{uuid.uuid4().hex}"

    def auth_device(authorization: str = Header(default="")) -> Device:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization[len("Bearer "):]
        device = store.device_for_token(token)
        if device is None:
            raise HTTPException(status_code=401, detail="invalid token")
        return device

    def _device_for_authorization(authorization: str) -> Optional[Device]:
        """Resolve an optional bearer header to a device (no exception)."""
        if not authorization.startswith("Bearer "):
            return None
        return store.device_for_token(authorization[len("Bearer "):])

    def _validation_422(exc: UsernameValidationError) -> HTTPException:
        return HTTPException(
            status_code=422,
            detail={"code": exc.code, "message": exc.message},
        )

    def _contact_to_model(contact: Contact) -> ContactResponse:
        return ContactResponse(
            contact_id=contact.contact_id,
            username_display=contact.username_display,
            username_hash=contact.username_hash,
            contact_username=contact.contact_username,
            contact_device_id=contact.contact_device_id,
            alias=contact.alias,
            verified=contact.verified,
            created_at=contact.created_at,
        )

    def _contact_request_to_model(
        request: ContactRequestRecord,
        device: Device,
    ) -> ContactRequestResponse:
        outbound = (
            request.requester_username == device.username
            and request.requester_device_id == device.device_id
        )
        direction = "outbound" if outbound else "inbound"
        peer_username_display = (
            request.recipient_username_display
            if outbound
            else request.requester_username_display
        )
        peer_username_hash = (
            request.recipient_username_hash
            if outbound
            else request.requester_username_hash
        )
        peer_device_id = (
            request.recipient_device_id if outbound else request.requester_device_id
        )
        return ContactRequestResponse(
            request_id=request.request_id,
            status=request.status,
            direction=direction,
            requester_username=request.requester_username,
            requester_device_id=request.requester_device_id,
            requester_username_display=request.requester_username_display,
            requester_username_hash=request.requester_username_hash,
            recipient_username=request.recipient_username,
            recipient_device_id=request.recipient_device_id,
            recipient_username_display=request.recipient_username_display,
            recipient_username_hash=request.recipient_username_hash,
            peer_username_display=peer_username_display,
            peer_username_hash=peer_username_hash,
            peer_device_id=peer_device_id,
            alias=request.alias,
            created_at=request.created_at,
            updated_at=request.updated_at,
        )

    async def _deliver_and_push(envelope: Envelope) -> None:
        """Deliver an envelope and push it to any live WS recipient.

        Push is attempted first.  If at least one socket successfully receives
        the frame the envelope is considered delivered and is NOT written to the
        persistent mailbox (avoiding double-delivery for WS-connected clients).

        If no live socket successfully accepts the envelope — either because the
        device has no open connections, or because every socket died between the
        connectivity check and the actual send — the envelope is stored in the
        mailbox so it is never silently lost (at-least-once delivery).

        Both POST /messages and the WS send handler use this helper so
        HTTP-originated envelopes also reach WS subscribers.
        """
        model = _envelope_to_model(envelope)
        sent = await manager.push_envelope(
            envelope.recipient_username, envelope.recipient_device_id, model
        )
        if sent == 0:
            store.deliver(envelope)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    static_dir = Path(__file__).resolve().parent / "static"

    @app.get("/ui")
    def ui_index():
        index_path = static_dir / "index.html"
        if not index_path.exists():
            raise HTTPException(status_code=404, detail="ui static assets not built")
        return FileResponse(index_path)

    def _ui_asset(asset_name: str):
        asset_path = static_dir / asset_name
        if not asset_path.exists():
            raise HTTPException(status_code=404, detail="ui static assets not built")
        return FileResponse(asset_path)

    @app.get("/ui/styles.css")
    def ui_styles():
        return _ui_asset("styles.css")

    @app.get("/ui/app.js")
    def ui_app():
        return _ui_asset("app.js")

    @app.get("/ui/logo.svg")
    def ui_logo():
        return _ui_asset("logo.svg")

    def _guard_registration(request: Request) -> None:
        """Single gate every registration door must pass through.

        Audit M12 / round-2 D2: registration is necessarily unauthenticated, so
        bound how fast one source can mint brand-new identities.  ``/register``
        and the demo ``/ui/register`` share this one limiter (and the bucket
        itself) so a caller cannot dodge the limit by switching doors, and the
        two can never drift apart again.
        """
        _rate_limit(_register_bucket, _client_key(request), "register")

    def _register_device_or_refuse(
        *,
        username: str,
        registration_id: int,
        bundle: dict,
        identity_key: bytes,
        one_time_prekeys: dict,
    ) -> Device:
        """Register a device, mapping a refusal to a generic 403 (audit L11).

        The backend message names the exact reason ("username already registered
        to a different identity key"), an account-existence oracle.  Every
        registration door funnels through here so none of them leaks it.
        """
        try:
            return store.register_device(
                username=username,
                registration_id=registration_id,
                bundle=bundle,
                identity_key=identity_key,
                one_time_prekeys=one_time_prekeys,
            )
        except PermissionError as exc:
            _log.warning("registration refused for %r: %s", username, exc)
            raise HTTPException(status_code=403, detail="registration refused")

    @app.post("/register", response_model=RegisterResponse)
    def register(req: RegisterRequest, request: Request) -> RegisterResponse:
        _guard_registration(request)
        if len(req.one_time_prekeys) > limits.max_one_time_prekeys:
            raise HTTPException(status_code=422, detail="too many one-time prekeys")
        # Authenticate ownership: the bundle's identity key must sign the
        # registration challenge (proves the registrant holds the private key).
        try:
            ik_pub = b64d(req.bundle["ik_pub"])
            proof = b64d(req.proof_sig)
        except (KeyError, ValueError):
            raise HTTPException(status_code=400, detail="malformed bundle/proof")
        if not xeddsa.verify(
            ik_pub, registration_challenge(req.username, req.registration_id), proof
        ):
            raise HTTPException(status_code=401, detail="invalid registration proof")

        # Audit M12: a non-integer opk id used to raise an uncaught ValueError
        # (500).  Reject it as a client error instead.
        try:
            otks = {int(k): v for k, v in req.one_time_prekeys.items()}
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="malformed one-time prekeys")
        device = _register_device_or_refuse(
            username=req.username,
            registration_id=req.registration_id,
            bundle=req.bundle,
            identity_key=ik_pub,
            one_time_prekeys=otks,
        )
        return RegisterResponse(
            username=device.username,
            device_id=device.device_id,
            auth_token=device.auth_token,
        )

    if enable_demo_ui:

        @app.post("/ui/register", response_model=RegisterResponse)
        def ui_register(req: UIRegisterRequest, request: Request) -> RegisterResponse:
            # Round-2 D2: this demo door used to bypass the M12 limiter and the
            # L11 generic-error path entirely.  It now shares both.
            _guard_registration(request)
            try:
                normalize_username(req.username)
            except UsernameValidationError as exc:
                raise _validation_422(exc)

            identity = create_identity()
            bundle, secrets = create_prekey_bundle(
                identity, num_one_time=req.one_time_prekey_count
            )
            one_time_prekeys = {
                opk_id: b64e(_x25519_pub_bytes(priv.public_key()))
                for opk_id, priv in secrets.opk_priv.items()
            }

            device = _register_device_or_refuse(
                username=req.username,
                registration_id=req.registration_id,
                bundle=bundle_to_dict(bundle),
                identity_key=identity.public,
                one_time_prekeys=one_time_prekeys,
            )

            return RegisterResponse(
                username=device.username,
                device_id=device.device_id,
                auth_token=device.auth_token,
            )

    @app.get("/users/by-username/{username}", response_model=UsernameLookupResponse)
    def lookup_username(username: str) -> UsernameLookupResponse:
        try:
            normalize_username(username)
        except UsernameValidationError as exc:
            raise _validation_422(exc)

        device = store.find_device_by_username(username)
        if device is None:
            raise HTTPException(status_code=404, detail="unknown user")
        return UsernameLookupResponse(
            username_display=device.username_display or device.username,
            username_hash=device.username_hash,
            device_id=device.device_id,
            registration_id=device.registration_id,
        )

    @app.get("/contacts", response_model=List[ContactResponse])
    def list_contacts(device: Device = Depends(auth_device)) -> List[ContactResponse]:
        contacts = store.list_contacts(device.username, device.device_id)
        return [_contact_to_model(contact) for contact in contacts]

    @app.post("/contacts", response_model=ContactRequestResponse)
    def request_contact(
        req: ContactRequest, device: Device = Depends(auth_device)
    ) -> ContactRequestResponse:
        try:
            normalize_username(req.username)
        except UsernameValidationError as exc:
            raise _validation_422(exc)

        found = store.find_device_by_username(req.username)
        if found is None:
            raise HTTPException(status_code=404, detail="unknown contact")
        target = store.get_device(found.username, req.device_id)
        if target is None:
            raise HTTPException(status_code=404, detail="unknown contact device")

        try:
            request = store.create_contact_request(
                requester_username=device.username,
                requester_device_id=device.device_id,
                recipient_username=target.username,
                recipient_device_id=target.device_id,
                alias=req.alias,
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return _contact_request_to_model(request, device)

    @app.get("/contact-requests", response_model=ContactRequestsResponse)
    def list_contact_requests(
        device: Device = Depends(auth_device),
    ) -> ContactRequestsResponse:
        try:
            requests = store.list_contact_requests(device.username, device.device_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))

        inbound: List[ContactRequestResponse] = []
        outbound: List[ContactRequestResponse] = []
        for request in requests:
            model = _contact_request_to_model(request, device)
            if model.direction == "inbound":
                inbound.append(model)
            else:
                outbound.append(model)
        return ContactRequestsResponse(inbound=inbound, outbound=outbound)

    @app.post("/contact-requests/{request_id}/accept", response_model=ContactRequestResponse)
    def accept_contact_request(
        request_id: str,
        device: Device = Depends(auth_device),
    ) -> ContactRequestResponse:
        try:
            request = store.accept_contact_request(
                device.username,
                device.device_id,
                request_id,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return _contact_request_to_model(request, device)

    @app.post("/contact-requests/{request_id}/deny", response_model=ContactRequestResponse)
    def deny_contact_request(
        request_id: str,
        device: Device = Depends(auth_device),
    ) -> ContactRequestResponse:
        try:
            request = store.deny_contact_request(
                device.username,
                device.device_id,
                request_id,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return _contact_request_to_model(request, device)

    @app.delete("/contacts/{contact_id}")
    def delete_contact(contact_id: str, device: Device = Depends(auth_device)) -> dict:
        try:
            deleted = store.delete_contact(device.username, device.device_id, contact_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        if not deleted:
            raise HTTPException(status_code=404, detail="unknown contact")
        return {"status": "deleted"}

    @app.get("/keys/{username}", response_model=List[DeviceInfo])
    def list_devices(username: str) -> List[DeviceInfo]:
        devices = store.list_devices(username)
        if not devices:
            raise HTTPException(status_code=404, detail="unknown user")
        return [
            DeviceInfo(device_id=d.device_id, registration_id=d.registration_id)
            for d in devices
        ]

    @app.get("/keys/{username}/{device_id}")
    def get_bundle(
        username: str,
        device_id: int,
        request: Request,
        authorization: str = Header(default=""),
    ) -> dict:
        """Fetch a prekey bundle, normally consuming one one-time prekey.

        Audit H1 (+ round-2 D1) — the endpoint stays publicly reachable (Signal
        model) but a drain-the-pool loop is no longer free:

        * per-client token bucket (proxy-aware key, see ``_client_key``);
        * **no caller** — authenticated or not — is served the last
          ``limits.opk_reserve_floor`` one-time prekeys; it gets a valid bundle
          with ``opk_id=None`` instead.  Anonymous callers additionally respect
          ``limits.opk_anonymous_floor``;
        * depletion is counted on ``app.state.opk_depletion_events`` and logged.

        Why the floor is not gated on authentication (round-2 D1): ``POST
        /register`` is unauthenticated by design, so a bearer token is an
        identity any attacker mints for free — "authenticated" carries no cost
        and therefore no security.  The floor is instead derived from the pool
        size itself: monotone, attacker-shrinkable-only state that cannot be
        forged, flooded or evicted.  A per-(caller, target) consumption quota
        was deliberately *not* added on top: any such table is keyed by
        free-to-mint identities, so it is either unbounded memory or a
        fail-open eviction primitive (flood the table, evict your own counter,
        resume draining) — exactly the anti-pattern this round exists to remove.

        Note the PQ leg is unaffected either way: the ML-KEM public key comes
        from the signed last-resort prekey, not from the one-time prekey.
        """
        _rate_limit(_bundle_bucket, _client_key(request), "prekey bundle")

        authenticated = _device_for_authorization(authorization) is not None
        floor = limits.opk_reserve_floor
        if not authenticated:
            floor = max(floor, limits.opk_anonymous_floor)

        # "count the pool, then consume from it" is check-then-act: two
        # concurrent fetches both observing ``floor + 1`` would each take one
        # and push the pool below the floor.  One process-wide lock (no
        # per-principal state to flood) makes the pair atomic in-process.
        with _bundle_lock:
            device = store.get_device(username, device_id)
            if device is None:
                raise HTTPException(status_code=404, detail="unknown user/device")

            remaining = len(device.one_time_prekeys or {})
            if remaining <= floor:
                key = (username, device_id)
                opk_depletion_events[key] = opk_depletion_events.get(key, 0) + 1
                _log.warning(
                    "one-time prekey pool at floor for %s/%s (%d left, floor=%d); "
                    "serving %s caller a bundle without a one-time prekey",
                    username,
                    device_id,
                    remaining,
                    floor,
                    "authenticated" if authenticated else "anonymous",
                )
                bundle = dict(device.bundle)
                bundle["opk_id"] = None
                bundle["opk_pub"] = None
                return {"username": username, "device_id": device_id, "bundle": bundle}

            bundle = store.take_prekey_bundle(username, device_id)
        if bundle is None:
            raise HTTPException(status_code=404, detail="unknown user/device")
        if remaining - 1 <= limits.opk_low_water:
            _log.warning(
                "one-time prekey pool low for %s/%s: %d remaining — replenish",
                username,
                device_id,
                max(0, remaining - 1),
            )
        return {"username": username, "device_id": device_id, "bundle": bundle}

    def _body_size(body: dict) -> int:
        """Serialized size of a relayed body, in bytes."""
        try:
            return len(json.dumps(body, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError):
            # Non-serialisable body: treat as oversized rather than crashing.
            return limits.max_message_body_bytes + 1

    def _check_relay_quota(req: SendMessageRequest, sender: Device) -> None:
        """Audit M13: bound body size, mailbox depth and per-token send rate.

        Raises :class:`HTTPException` (413 / 429) when a limit is exceeded.
        """
        _rate_limit(_send_bucket, sender.auth_token, "send message")
        if _body_size(req.body) > limits.max_message_body_bytes:
            raise HTTPException(status_code=413, detail="message body too large")
        if limits.max_mailbox_per_device > 0:
            pending = store.pending_count(
                req.recipient_username, req.recipient_device_id
            )
            if pending >= limits.max_mailbox_per_device:
                _log.warning(
                    "mailbox full for %s/%s (%d pending)",
                    req.recipient_username,
                    req.recipient_device_id,
                    pending,
                )
                raise HTTPException(status_code=429, detail="recipient mailbox full")

    @app.post("/messages")
    async def send_message(
        req: SendMessageRequest, sender: Device = Depends(auth_device)
    ) -> dict:
        if store.get_device(req.recipient_username, req.recipient_device_id) is None:
            raise HTTPException(status_code=404, detail="unknown recipient device")
        _check_relay_quota(req, sender)
        # Sender identity comes from the authenticated token, not the request body,
        # so envelopes cannot be spoofed as originating from another device.
        envelope = Envelope(
            envelope_id=_next_envelope_id(),
            sender_username=sender.username,
            sender_device_id=sender.device_id,
            recipient_username=req.recipient_username,
            recipient_device_id=req.recipient_device_id,
            kind=req.kind,
            body=req.body,
        )
        await _deliver_and_push(envelope)
        return {"status": "delivered", "envelope_id": envelope.envelope_id}

    @app.get("/messages", response_model=List[EnvelopeModel])
    def fetch_messages(
        drain: bool = True, device: Device = Depends(auth_device)
    ) -> List[EnvelopeModel]:
        """Drain (or peek at) the calling device's mailbox.

        **Mailbox / WebSocket split:** envelopes pushed to a live WS connection
        are delivered in real time and are stored in the mailbox *only* when no
        live socket successfully accepted them (e.g. the socket died between the
        server's connectivity check and the actual send).  A client that holds an
        open ``/ws`` connection should NOT need to poll this endpoint — doing so
        is harmless but will only return envelopes that the WS path failed to
        deliver.  A client should pick **one** transport per device: either the WS
        channel or HTTP polling.
        """
        envelopes = store.fetch_mailbox(device.username, device.device_id, drain=drain)
        return [_envelope_to_model(e) for e in envelopes]

    # -- WebSocket endpoint ------------------------------------------------

    @app.websocket("/ws")
    async def websocket_endpoint(
        websocket: WebSocket,
        token: Optional[str] = Query(default=None),
        authorization: str = Header(default=""),
    ) -> None:
        """Real-time push channel.

        Authentication (audit L9): prefer ``Authorization: Bearer <token>`` on
        the handshake request.  The ``?token=<bearer>`` query parameter is
        **deprecated** — a URL query string lands in proxy access logs, browser
        history and Referer headers — and is retained only for backwards
        compatibility with existing clients.  Rejected with close code 1008
        (Policy Violation) if neither carries a valid token — matching the HTTP
        401 behaviour on the REST endpoints.

        On connect the device's queued mailbox is flushed to the socket so no
        envelopes are missed during the gap between HTTP polling and WS connect.

        Inbound frames must be JSON objects with ``"action": "send"`` plus the
        ``SendMessageRequest`` fields.  The sender is *always* derived from the
        authenticated token — never from the frame body.
        """
        device = _device_for_authorization(authorization)
        if device is None and token:
            # Deprecated transport for the bearer token; see the docstring.
            device = store.device_for_token(token)
        if device is None:
            await websocket.close(code=1008)
            return

        await websocket.accept()
        manager.connect(device.username, device.device_id, websocket)

        # Flush any queued envelopes so the client misses nothing.
        queued = store.fetch_mailbox(device.username, device.device_id, drain=True)
        for env in queued:
            try:
                await websocket.send_json(
                    {"type": "envelope", "envelope": _envelope_to_model(env).model_dump()}
                )
            except Exception:
                break

        try:
            while True:
                data = await websocket.receive_json()
                if not isinstance(data, dict):
                    continue

                action = data.get("action")
                if action != "send":
                    # Unknown action; ignore rather than close, for forward compat.
                    continue

                # Validate required fields.
                try:
                    req = SendMessageRequest(
                        recipient_username=data["recipient_username"],
                        recipient_device_id=int(data["recipient_device_id"]),
                        kind=data["kind"],
                        body=data["body"],
                    )
                except Exception:
                    # Audit L11: a raw pydantic/`int()` error leaks the server's
                    # internal model shape.  Log it, return a generic message.
                    _log.info(
                        "rejected malformed WS frame from %s/%s",
                        device.username,
                        device.device_id,
                        exc_info=True,
                    )
                    await websocket.send_json(
                        {"type": "error", "detail": "invalid frame"}
                    )
                    continue

                if store.get_device(req.recipient_username, req.recipient_device_id) is None:
                    await websocket.send_json(
                        {"type": "error", "detail": "unknown recipient device"}
                    )
                    continue

                # Audit M13: the WS path relays exactly like POST /messages and
                # must honour the same body/mailbox/rate limits.
                try:
                    _check_relay_quota(req, device)
                except HTTPException as exc:
                    await websocket.send_json(
                        {"type": "error", "detail": exc.detail}
                    )
                    continue

                # Sender identity is taken from the authenticated connection token —
                # it is impossible for the client to forge the sender field.
                envelope = Envelope(
                    envelope_id=_next_envelope_id(),
                    sender_username=device.username,
                    sender_device_id=device.device_id,
                    recipient_username=req.recipient_username,
                    recipient_device_id=req.recipient_device_id,
                    kind=req.kind,
                    body=req.body,
                )
                await _deliver_and_push(envelope)
                await websocket.send_json(
                    {"type": "ack", "envelope_id": envelope.envelope_id}
                )

        except WebSocketDisconnect:
            pass
        except Exception:
            _log.exception(
                "Unexpected error in WebSocket handler for %s/%s",
                device.username,
                device.device_id,
            )
        finally:
            manager.disconnect(device.username, device.device_id, websocket)

    return app


app = create_app()


def main() -> None:
    """Entry point: ``braid-server`` (uvicorn on 127.0.0.1:8000).

    **Store backend** — if ``BRAID_STORE_PATH`` is set the server uses a
    durable :class:`~ml_kem_braid.sesame.sqlite_store.SqliteStore`; otherwise
    the default in-memory store is used.

    **TLS** — set both ``BRAID_TLS_CERT`` (path to PEM certificate) and
    ``BRAID_TLS_KEY`` (path to PEM private key) to enable HTTPS/WSS.  When
    both are set:

    - uvicorn is started with ``ssl_certfile`` / ``ssl_keyfile``.
    - The app is built with ``enforce_tls=True`` (426 for plaintext; HSTS).
    - If ``BRAID_TLS_CLIENT_CA`` is also set, uvicorn requires client
      certificates (mutual TLS); that path is loaded as the trusted CA for
      verifying client certs.

    If neither cert env var is set the server starts in plain HTTP mode,
    identical to the previous behaviour (backwards compatible).
    """
    import os

    import uvicorn

    store_path = os.environ.get("BRAID_STORE_PATH")
    _store: StoreBackend = SqliteStore(store_path) if store_path else SesameStore()

    tls_cert = os.environ.get("BRAID_TLS_CERT")
    tls_key = os.environ.get("BRAID_TLS_KEY")
    tls_client_ca = os.environ.get("BRAID_TLS_CLIENT_CA")
    enable_demo_ui = os.environ.get("BRAID_ENABLE_DEMO_UI") == "1"
    # Audit M11: comma-separated peer addresses whose X-Forwarded-Proto is
    # trusted.  Unset (the default) means the header is never trusted.
    trusted_proxies = tuple(
        p.strip()
        for p in os.environ.get("BRAID_TRUSTED_PROXIES", "").split(",")
        if p.strip()
    )

    use_tls = bool(tls_cert and tls_key)
    _tls_enabled = use_tls  # captured for enforce_tls flag

    # Rebuild the module-level app with the chosen backend so uvicorn serves it.
    global app  # noqa: PLW0603
    app = create_app(
        _store,
        enforce_tls=_tls_enabled,
        enable_demo_ui=enable_demo_ui,
        trusted_proxies=trusted_proxies,
    )

    uvicorn_kwargs: dict = {
        "host": "127.0.0.1",
        "port": 8000,
        "reload": False,
    }
    if use_tls:
        import ssl

        uvicorn_kwargs["ssl_certfile"] = tls_cert
        uvicorn_kwargs["ssl_keyfile"] = tls_key
        if tls_client_ca:
            uvicorn_kwargs["ssl_ca_certs"] = tls_client_ca
            uvicorn_kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED

    uvicorn.run("ml_kem_braid.server.app:app", **uvicorn_kwargs)


if __name__ == "__main__":
    main()
