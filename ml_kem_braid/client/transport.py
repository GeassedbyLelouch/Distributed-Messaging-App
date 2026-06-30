"""
Transport protocol and implementations for the ML-KEM Braid chat client.

Defines a ``Transport`` typing.Protocol so ``BraidChatClient`` is not
coupled to a specific transport.  ``HttpTransport`` (moved here from
client.py and re-exported for backward-compat) satisfies the protocol via
duck-typing, as does the new ``WebSocketTransport``.

The WebSocket transport is intentionally thin: it delegates the three
request/response operations (register, list_devices, get_bundle) to a base
HTTP transport, while ``send`` and ``fetch`` use a live WebSocket connection
so the server can push envelopes in real time instead of the client polling.

Design note: keeping ws-only methods (send/fetch) on the WebSocket but
delegating the REST calls avoids duplicating the HTTP logic and mirrors how
real apps work (REST for key-exchange setup, WS for message delivery).
"""

from __future__ import annotations

import ssl
import threading
from collections import deque
from pathlib import Path
from typing import Any, Deque, List, Optional, Protocol, runtime_checkable

import httpx


# ---------------------------------------------------------------------------
# Transport protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Transport(Protocol):
    """Minimal transport surface used by :class:`BraidChatClient`.

    Any object that provides these five methods can drive the client.
    The protocol is ``runtime_checkable`` so tests can use ``isinstance``.
    """

    def register(self, payload: dict) -> dict:
        """POST /register → RegisterResponse dict."""
        ...

    def list_devices(self, username: str) -> List[dict]:
        """GET /keys/{username} → list of DeviceInfo dicts."""
        ...

    def get_bundle(self, username: str, device_id: int) -> dict:
        """GET /keys/{username}/{device_id} → {username, device_id, bundle}."""
        ...

    def send(self, payload: dict, token: str) -> dict:
        """Deliver an envelope on behalf of the authenticated device.

        *token* is the device's bearer token; sender identity is resolved
        server-side and must never be taken from *payload*.
        """
        ...

    def fetch(self, token: str, drain: bool = True) -> List[dict]:
        """Return pending envelopes for the device identified by *token*.

        When *drain* is True the mailbox is cleared after retrieval.
        """
        ...


# ---------------------------------------------------------------------------
# HTTP transport (thin httpx wrapper; re-exported so existing imports work)
# ---------------------------------------------------------------------------


class HttpTransport:
    """Thin wrapper over an ``httpx.Client`` for the server's JSON API."""

    def __init__(self, client: httpx.Client):
        self._http = client

    def register(self, payload: dict) -> dict:
        r = self._http.post("/register", json=payload)
        r.raise_for_status()
        return r.json()

    def list_devices(self, username: str) -> List[dict]:
        r = self._http.get(f"/keys/{username}")
        r.raise_for_status()
        return r.json()

    def get_bundle(self, username: str, device_id: int) -> dict:
        r = self._http.get(f"/keys/{username}/{device_id}")
        r.raise_for_status()
        return r.json()

    def send(self, payload: dict, token: str) -> dict:
        r = self._http.post(
            "/messages",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        r.raise_for_status()
        return r.json()

    def fetch(self, token: str, drain: bool = True) -> List[dict]:
        r = self._http.get(
            "/messages",
            params={"drain": drain},
            headers={"Authorization": f"Bearer {token}"},
        )
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# WebSocket transport
# ---------------------------------------------------------------------------


class WebSocketTransport:
    """``Transport`` implementation that delivers/receives messages over WS.

    The three key-exchange methods (register, list_devices, get_bundle) are
    delegated to a base HTTP transport because they are strictly
    request/response and do not benefit from a persistent connection.

    ``send`` writes a ``{"action":"send", ...}`` frame to the server, which
    delivers the envelope and may push it to the recipient's live socket.
    It does NOT consume the server's ack frame — the caller is responsible
    for reading the wire when it needs to (see ``receive_one()``).

    ``fetch`` drains the internal inbox populated by ``push()`` calls.
    It is non-blocking: it only returns what the caller has already pumped
    into the inbox via ``push()`` or ``receive_one()``.

    Why passive design: Starlette's ``TestClient.websocket_connect``
    provides a synchronous ``receive_json()`` that blocks indefinitely.
    Calling it in a drain loop would deadlock as soon as the server has
    nothing more to send.  By making the transport passive (only draining
    an internal buffer that the *caller* populates) we avoid that deadlock
    and still give tests full control over the receive sequence.

    WebSocket session lifecycle is managed *externally*: the caller opens a
    connection, passes it to this transport, and is responsible for closing it.

    Args:
        base_http:   HTTP transport for register/list_devices/get_bundle.
        ws_session:  A live WebSocket session object exposing at minimum
                     ``send_json(dict)`` and ``receive_json() -> dict``.
        token:       Bearer token of the device that owns this connection.
    """

    def __init__(
        self,
        base_http: HttpTransport,
        ws_session: Any,
        token: str,
    ) -> None:
        self._http = base_http
        self._ws = ws_session
        self._token = token
        # Thread-safe buffer for inbound "envelope" pushes from the server.
        self._lock = threading.Lock()
        self._inbox: Deque[dict] = deque()

    # -- Transport protocol implementation ------------------------------------

    def register(self, payload: dict) -> dict:
        return self._http.register(payload)

    def list_devices(self, username: str) -> List[dict]:
        return self._http.list_devices(username)

    def get_bundle(self, username: str, device_id: int) -> dict:
        return self._http.get_bundle(username, device_id)

    def send(self, payload: dict, token: str) -> dict:
        """Send an envelope via the WebSocket ``action: send`` frame.

        *token* must match the token this transport was constructed with;
        the server resolves sender identity from the connection's
        authentication token, not from the frame.  Sender identity is never
        taken from *payload*.

        The ack frame the server sends in response is left on the wire —
        call ``receive_one()`` afterwards if you need it.

        Raises:
            ValueError: if *token* does not match the connection token.
        """
        # Explicit check (not assert) so it survives `python -O`.
        if token != self._token:
            raise ValueError("token does not match the WebSocket connection token")
        frame = {"action": "send", **payload}
        self._ws.send_json(frame)
        return {"status": "delivered"}

    def fetch(self, token: str, drain: bool = True) -> List[dict]:
        """Return envelopes that have been pushed into the inbox via ``push()``.

        Non-blocking: only returns what the caller already deposited.
        To actively receive frames from the wire, call ``receive_one()``
        (which blocks until a frame arrives) before calling ``fetch()``.

        Return shape: each item is the inner **envelope** dict (the value of
        the ``"envelope"`` key in the server's ``{"type": "envelope", "envelope": {...}}``
        frame) — identical to the shape returned by ``HttpTransport.fetch()``.
        Keys: ``envelope_id``, ``sender_username``, ``sender_device_id``,
        ``recipient_username``, ``recipient_device_id``, ``kind``, ``body``,
        ``created_at``.
        """
        with self._lock:
            items = list(self._inbox)
            if drain:
                self._inbox.clear()
            return items

    # -- Helpers --------------------------------------------------------------

    def receive_one(self) -> Optional[dict]:
        """Block until one frame arrives from the server and return it.

        If the frame is an ``"envelope"`` push it is also added to the
        internal inbox so a subsequent ``fetch()`` call sees it.

        Return shape: the **raw server frame** dict, e.g.
        ``{"type": "envelope", "envelope": {...}}`` or ``{"type": "ack", ...}``.
        This differs from ``fetch()``, which returns only the inner envelope
        dicts.  Callers that only want envelope payloads should use ``fetch()``
        after calling ``receive_one()``.

        Returns *None* if the socket raised an exception (closed / disconnected).
        """
        receive = getattr(self._ws, "receive_json", None)
        if receive is None:
            return None
        try:
            frame = receive()
            if isinstance(frame, dict) and frame.get("type") == "envelope":
                with self._lock:
                    self._inbox.append(frame.get("envelope", frame))
            return frame
        except Exception:
            return None

    def push(self, frame: dict) -> None:
        """Manually deposit a received frame into the inbox.

        Use this when the test has already consumed a frame from the wire
        (via ``ws_session.receive_json()``) and wants ``fetch()`` to return it.
        Only ``{"type": "envelope", ...}`` frames are stored; acks are ignored.

        The inner ``"envelope"`` dict is extracted and stored so that ``fetch()``
        returns the same shape as ``HttpTransport.fetch()``.
        """
        if isinstance(frame, dict) and frame.get("type") == "envelope":
            with self._lock:
                self._inbox.append(frame.get("envelope", frame))


# ---------------------------------------------------------------------------
# TLS-aware client factory
# ---------------------------------------------------------------------------


def tls_http_client(
    base_url: str,
    *,
    pinned_server_cert: bytes | str | None = None,
    client_cert: str | Path | None = None,
    client_key: str | Path | None = None,
) -> httpx.Client:
    """Return an ``httpx.Client`` that connects to a TLS server with cert pinning.

    Libsignal-style trust model: when *pinned_server_cert* is supplied the
    client trusts ONLY that one self-signed certificate — the system CA store
    is not consulted.  This guarantees the client is talking to the exact
    server whose certificate was distributed out-of-band (e.g. via
    :func:`~ml_kem_braid.tls.generate_dev_certs`).

    Usage with :class:`HttpTransport`::

        from ml_kem_braid.tls import generate_dev_certs
        from ml_kem_braid.client.transport import tls_http_client, HttpTransport

        certs = generate_dev_certs(Path("/tmp/dev-certs"))
        client = tls_http_client(
            "https://127.0.0.1:8443",
            pinned_server_cert=certs["server_cert"].read_bytes(),
            client_cert=certs["client_cert"],   # optional — mTLS only
            client_key=certs["client_key"],     # optional — mTLS only
        )
        transport = HttpTransport(client)

    Args:
        base_url:           Base URL of the server, e.g. ``"https://127.0.0.1:8443"``.
        pinned_server_cert: PEM bytes (or str) of the server certificate to pin.
                            When given, ONLY this cert is trusted; the system CA
                            store is bypassed entirely.
        client_cert:        Path to the client's PEM certificate for mTLS.
        client_key:         Path to the client's PEM private key for mTLS.

    Returns:
        A configured :class:`httpx.Client` with the pinned SSL context applied.
    """
    from ml_kem_braid.tls import make_client_ssl_context

    ssl_ctx: ssl.SSLContext | bool = make_client_ssl_context(
        pinned_server_cert=pinned_server_cert,
        client_cert_path=str(client_cert) if client_cert else None,
        client_key_path=str(client_key) if client_key else None,
    )

    return httpx.Client(base_url=base_url, verify=ssl_ctx)
