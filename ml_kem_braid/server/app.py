"""
FastAPI server: PQXDH key distribution + Sesame mailbox relay.

Endpoints (all JSON):
  POST /register                      register a device (username + public bundle)
  GET  /keys/{username}               list device ids for a user
  GET  /keys/{username}/{device_id}   fetch a prekey bundle (consumes a one-time prekey)
  POST /messages                      relay an opaque encrypted envelope to a device
  GET  /messages   (Bearer token)     drain the calling device's mailbox
  WS   /ws?token=  (Bearer token)     real-time push channel (send + receive)
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

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, Response

from ml_kem_braid.pqxdh import create_identity, create_prekey_bundle
from ml_kem_braid.pqxdh.pqxdh import _x25519_pub_bytes
from ml_kem_braid.decentralized.services import DecentralizedServices
from ml_kem_braid.server.decentralized_routes import build_decentralized_router
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
    1. ``X-Forwarded-Proto: https`` header — set by reverse proxies (nginx,
       AWS ALB, Cloudflare).  If present and equals ``"https"`` the request
       is considered secure.
    2. ASGI ``scope["scheme"]`` — set by uvicorn when the server is started
       with TLS; equals ``"https"`` / ``"wss"`` for TLS connections.

    Exempt paths (see ``_TLS_EXEMPT_PATHS``) pass through regardless so
    liveness probes work over plaintext.
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        path = request.url.path
        if path in _TLS_EXEMPT_PATHS:
            # Exempt endpoint — pass through; still add HSTS so browsers know.
            response: Response = await call_next(request)
            response.headers["Strict-Transport-Security"] = _HSTS_VALUE
            return response

        # Determine whether the transport is secure.
        forwarded_proto = request.headers.get("x-forwarded-proto", "").lower()
        scheme = request.scope.get("scheme", "http")
        is_secure = forwarded_proto == "https" or scheme in ("https", "wss")

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


# -- request / response models ---------------------------------------------


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    registration_id: int = Field(ge=0, lt=2**31)
    bundle: dict
    # Ed25519 signature over registration_challenge(username, registration_id),
    # proving possession of the bundle's ik_sign_pub (base64).
    proof_sig: str
    one_time_prekeys: dict[str, str] = Field(default_factory=dict)


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
    """
    store = store or SesameStore()
    app = FastAPI(title="ML-KEM Braid Chat Server", version="0.3.0")
    if enforce_tls:
        app.add_middleware(_TLSEnforcementMiddleware)
    app.state.store = store
    if enable_decentralized:
        decentralized_services = DecentralizedServices()
        app.state.decentralized_services = decentralized_services
        app.include_router(build_decentralized_router(decentralized_services))

    # Shared connection manager for the WebSocket endpoint.
    manager = ConnectionManager()
    app.state.manager = manager

    _envelope_counter = {"n": 0}

    def _next_envelope_id() -> str:
        _envelope_counter["n"] += 1
        return f"env-{_envelope_counter['n']}"

    def auth_device(authorization: str = Header(default="")) -> Device:
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization[len("Bearer "):]
        device = store.device_for_token(token)
        if device is None:
            raise HTTPException(status_code=401, detail="invalid token")
        return device

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

    @app.post("/register", response_model=RegisterResponse)
    def register(req: RegisterRequest) -> RegisterResponse:
        # Authenticate ownership: the bundle's identity key must sign the
        # registration challenge (proves the registrant holds the private key).
        try:
            ik_sign_pub = b64d(req.bundle["ik_sign_pub"])
            proof = b64d(req.proof_sig)
        except (KeyError, ValueError):
            raise HTTPException(status_code=400, detail="malformed bundle/proof")
        try:
            Ed25519PublicKey.from_public_bytes(ik_sign_pub).verify(
                proof, registration_challenge(req.username, req.registration_id)
            )
        except InvalidSignature:
            raise HTTPException(status_code=401, detail="invalid registration proof")

        otks = {int(k): v for k, v in req.one_time_prekeys.items()}
        try:
            device = store.register_device(
                username=req.username,
                registration_id=req.registration_id,
                bundle=req.bundle,
                identity_key=ik_sign_pub,
                one_time_prekeys=otks,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        return RegisterResponse(
            username=device.username,
            device_id=device.device_id,
            auth_token=device.auth_token,
        )

    if enable_demo_ui:

        @app.post("/ui/register", response_model=RegisterResponse)
        def ui_register(req: UIRegisterRequest) -> RegisterResponse:
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

            try:
                device = store.register_device(
                    username=req.username,
                    registration_id=req.registration_id,
                    bundle=bundle_to_dict(bundle),
                    identity_key=identity.sign_pub,
                    one_time_prekeys=one_time_prekeys,
                )
            except PermissionError as exc:
                raise HTTPException(status_code=409, detail=str(exc))

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
    def get_bundle(username: str, device_id: int) -> dict:
        bundle = store.take_prekey_bundle(username, device_id)
        if bundle is None:
            raise HTTPException(status_code=404, detail="unknown user/device")
        return {"username": username, "device_id": device_id, "bundle": bundle}

    @app.post("/messages")
    async def send_message(
        req: SendMessageRequest, sender: Device = Depends(auth_device)
    ) -> dict:
        if store.get_device(req.recipient_username, req.recipient_device_id) is None:
            raise HTTPException(status_code=404, detail="unknown recipient device")
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
        token: str = Query(...),
    ) -> None:
        """Real-time push channel.

        Authentication: ``?token=<bearer>`` query parameter.  Rejected with
        close code 1008 (Policy Violation) if the token is invalid — matching
        the HTTP 401 behaviour on the REST endpoints.

        On connect the device's queued mailbox is flushed to the socket so no
        envelopes are missed during the gap between HTTP polling and WS connect.

        Inbound frames must be JSON objects with ``"action": "send"`` plus the
        ``SendMessageRequest`` fields.  The sender is *always* derived from the
        authenticated token — never from the frame body.
        """
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
                except Exception as exc:
                    await websocket.send_json({"type": "error", "detail": str(exc)})
                    continue

                if store.get_device(req.recipient_username, req.recipient_device_id) is None:
                    await websocket.send_json(
                        {"type": "error", "detail": "unknown recipient device"}
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

    use_tls = bool(tls_cert and tls_key)
    _tls_enabled = use_tls  # captured for enforce_tls flag

    # Rebuild the module-level app with the chosen backend so uvicorn serves it.
    global app  # noqa: PLW0603
    app = create_app(
        _store,
        enforce_tls=_tls_enabled,
        enable_demo_ui=enable_demo_ui,
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
