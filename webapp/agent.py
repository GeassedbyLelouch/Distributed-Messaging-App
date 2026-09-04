"""
BraidLink web bridge ("agent").

This process is *glue*, not a crypto implementation. It does three things:

  1. Owns exactly one ``ml_kem_braid.client.client.BraidChatClient`` instance
     (imported unmodified) for the person using this browser tab, and drives
     it via its existing public methods: ``register``, ``start_session``,
     ``poll``, ``pump_session``, ``send_chat``.
  2. Proxies the non-cryptographic social-graph endpoints that live on the
     core ml_kem_braid FastAPI server (contacts, contact-requests, username
     lookup) with a plain ``Authorization: Bearer <token>`` pass-through.
  3. Exposes a small local HTTP + WebSocket API that a browser SPA (see
     ``static/``) can call, and pushes decrypted inbox events to the browser
     as they arrive.

Nothing in this file touches key generation, KDF/HKDF derivation, the PQXDH
handshake, the Braid SCKA state machine, the Double Ratchet, or AEAD
encryption. All of that happens exactly as it already does inside
``ml_kem_braid``; this file only calls it and shuttles JSON around it.

Run one agent process per logged-in device:

    BRAID_SERVER_URL=http://localhost:8000 uvicorn agent:app --port 8899

Then open http://localhost:8899/ in a browser.
"""

from __future__ import annotations

import asyncio
import queue
import secrets
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx
from fastapi import Body, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# --- Unmodified project imports -------------------------------------------
# Everything imported here is existing ml_kem_braid code. This module does
# not redefine, wrap-with-different-semantics, or monkeypatch any of it.
from ml_kem_braid.client.client import BraidChatClient, BraidSession
from ml_kem_braid.client.transport import HttpTransport

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="BraidLink web bridge")


# ---------------------------------------------------------------------------
# Agent state: one BraidChatClient per browser session, keyed by a bridge-
# issued session id (a plain random token for this local process — it grants
# access to this *browser tab's* connection to the agent, not to any key
# material's encoding or format).
# ---------------------------------------------------------------------------


@dataclass
class ChatEvent:
    kind: str  # "message" | "session_status" | "dropped" | "error"
    payload: dict


@dataclass
class AgentSession:
    server_url: str
    client: BraidChatClient
    http_client: httpx.Client
    lock: threading.Lock = field(default_factory=threading.Lock)
    events: "queue.Queue[ChatEvent]" = field(default_factory=queue.Queue)
    history: Dict[Tuple[str, int], List[dict]] = field(default_factory=dict)
    stop_flag: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None
    known_epochs: Dict[Tuple[str, int], int] = field(default_factory=dict)

    def note_history(self, peer: Tuple[str, int], entry: dict) -> None:
        self.history.setdefault(peer, []).append(entry)


_SESSIONS: Dict[str, AgentSession] = {}
_SESSIONS_LOCK = threading.Lock()


def _get_session(session_id: str) -> AgentSession:
    sess = _SESSIONS.get(session_id)
    if sess is None:
        raise HTTPException(status_code=401, detail="unknown or expired session_id; connect again")
    return sess


# ---------------------------------------------------------------------------
# Background poller: this is orchestration (deciding *when* to call the
# existing pump_session/poll methods), not protocol logic. The Braid SCKA
# needs several chunk round-trips before an epoch key is agreed; this loop
# just keeps calling the existing driver methods until that happens, exactly
# the way ``run_until_agreed`` does for two in-process test clients.
# ---------------------------------------------------------------------------


def _poller_loop(sid: str, sess: AgentSession) -> None:
    while not sess.stop_flag.is_set():
        try:
            with sess.lock:
                client = sess.client

                # Drain the mailbox; this decrypts any ready chat envelopes
                # internally via client.poll() (unmodified).
                before = len(client.inbox)
                dropped_before = len(client.dropped)
                client.poll()

                # Advance any session whose Braid handshake hasn't produced
                # an epoch key yet by emitting one more chunk.
                for peer, session in list(client.sessions.items()):
                    if session.latest_epoch() is None:
                        try:
                            client.pump_session(session)
                        except Exception as exc:  # noqa: BLE001
                            sess.events.put(ChatEvent("error", {"detail": f"pump failed: {exc!r}"}))
                    else:
                        prev = sess.known_epochs.get(peer)
                        if prev != session.latest_epoch():
                            sess.known_epochs[peer] = session.latest_epoch()
                            sess.events.put(ChatEvent(
                                "session_status",
                                {
                                    "peer_username": peer[0],
                                    "peer_device_id": peer[1],
                                    "epoch": session.latest_epoch(),
                                    "ready": True,
                                },
                            ))

                # Surface newly-decrypted inbound chat messages.
                for peer_user, peer_dev, epoch, text in client.inbox[before:]:
                    entry = {
                        "direction": "in",
                        "peer_username": peer_user,
                        "peer_device_id": peer_dev,
                        "epoch": epoch,
                        "text": text,
                        "ts": time.time(),
                    }
                    sess.note_history((peer_user, peer_dev), entry)
                    sess.events.put(ChatEvent("message", entry))

                for peer, kind, reason in client.dropped[dropped_before:]:
                    sess.events.put(ChatEvent("dropped", {
                        "peer_username": peer[0],
                        "peer_device_id": peer[1],
                        "kind": kind,
                        "reason": reason,
                    }))
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            sess.events.put(ChatEvent("error", {"detail": repr(exc)}))
        sess.stop_flag.wait(0.4)


def _auth_headers(sess: AgentSession) -> dict:
    token = sess.client.auth_token
    if not token:
        raise HTTPException(status_code=409, detail="not registered yet")
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Connection lifecycle
# ---------------------------------------------------------------------------


class ConnectRequest(BaseModel):
    server_url: str
    username: str
    registration_id: int = 1
    num_one_time_prekeys: int = 8


class ConnectResponse(BaseModel):
    session_id: str
    username: str
    device_id: int


@app.post("/api/connect", response_model=ConnectResponse)
def connect(req: ConnectRequest) -> ConnectResponse:
    """Register a new device against the core server.

    This calls ``BraidChatClient.register()`` unmodified. That method
    generates the PQXDH identity/prekeys and keeps all private key material
    inside the client object in this process's memory — the bridge never
    extracts, re-encodes, or persists it anywhere else.
    """
    http_client = httpx.Client(base_url=req.server_url.rstrip("/"), timeout=15.0)
    transport = HttpTransport(http_client)
    client = BraidChatClient(transport, req.username)
    try:
        client.register(registration_id=req.registration_id, num_one_time=req.num_one_time_prekeys)
    except Exception as exc:  # noqa: BLE001
        http_client.close()
        raise HTTPException(status_code=400, detail=f"registration failed: {exc!r}")

    session_id = secrets.token_urlsafe(24)
    sess = AgentSession(server_url=req.server_url, client=client, http_client=http_client)
    sess.thread = threading.Thread(target=_poller_loop, args=(session_id, sess), daemon=True)
    sess.thread.start()

    with _SESSIONS_LOCK:
        _SESSIONS[session_id] = sess

    return ConnectResponse(session_id=session_id, username=client.username, device_id=client.device_id)


@app.post("/api/disconnect")
def disconnect(session_id: str = Body(..., embed=True)) -> dict:
    with _SESSIONS_LOCK:
        sess = _SESSIONS.pop(session_id, None)
    if sess is not None:
        sess.stop_flag.set()
        sess.http_client.close()
    return {"status": "disconnected"}


@app.get("/api/status")
def status(session_id: str) -> dict:
    sess = _get_session(session_id)
    with sess.lock:
        sessions = [
            {
                "peer_username": p[0],
                "peer_device_id": p[1],
                "epoch": s.latest_epoch(),
                "ready": s.latest_epoch() is not None,
            }
            for p, s in sess.client.sessions.items()
        ]
        return {
            "username": sess.client.username,
            "device_id": sess.client.device_id,
            "server_url": sess.server_url,
            "sessions": sessions,
        }


# ---------------------------------------------------------------------------
# Contacts / social graph — thin passthrough to the core server's own REST
# routes. No cryptographic material flows through these; they carry usernames,
# device ids, and metadata timestamps exactly as the core server defines them.
# ---------------------------------------------------------------------------


@app.get("/api/users/{username}")
def lookup_username(username: str, session_id: str) -> dict:
    sess = _get_session(session_id)
    r = sess.http_client.get(f"/users/by-username/{username}")
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


@app.get("/api/contacts")
def list_contacts(session_id: str) -> list:
    sess = _get_session(session_id)
    r = sess.http_client.get("/contacts", headers=_auth_headers(sess))
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


class ContactRequestBody(BaseModel):
    session_id: str
    username: str
    device_id: int
    alias: Optional[str] = None


@app.post("/api/contacts")
def request_contact(body: ContactRequestBody) -> dict:
    sess = _get_session(body.session_id)
    r = sess.http_client.post(
        "/contacts",
        json={"username": body.username, "device_id": body.device_id, "alias": body.alias},
        headers=_auth_headers(sess),
    )
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


@app.get("/api/contact-requests")
def list_contact_requests(session_id: str) -> dict:
    sess = _get_session(session_id)
    r = sess.http_client.get("/contact-requests", headers=_auth_headers(sess))
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


@app.post("/api/contact-requests/{request_id}/accept")
def accept_contact_request(request_id: str, session_id: str = Body(..., embed=True)) -> dict:
    sess = _get_session(session_id)
    r = sess.http_client.post(f"/contact-requests/{request_id}/accept", headers=_auth_headers(sess))
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


@app.post("/api/contact-requests/{request_id}/deny")
def deny_contact_request(request_id: str, session_id: str = Body(..., embed=True)) -> dict:
    sess = _get_session(session_id)
    r = sess.http_client.post(f"/contact-requests/{request_id}/deny", headers=_auth_headers(sess))
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


@app.delete("/api/contacts/{contact_id}")
def delete_contact(contact_id: str, session_id: str) -> dict:
    sess = _get_session(session_id)
    r = sess.http_client.delete(f"/contacts/{contact_id}", headers=_auth_headers(sess))
    if r.status_code >= 400:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()


# ---------------------------------------------------------------------------
# Chat: starts/pumps the existing Braid + PQXDH + Double Ratchet session and
# calls the existing send_chat()/decrypt path. No cryptographic step here is
# reimplemented — this only decides *when* to call the existing methods and
# reshapes their results into JSON for the browser.
# ---------------------------------------------------------------------------


class StartChatRequest(BaseModel):
    session_id: str
    peer_username: str
    peer_device_id: Optional[int] = None


@app.post("/api/chat/start")
def start_chat(req: StartChatRequest) -> dict:
    sess = _get_session(req.session_id)
    with sess.lock:
        existing = None
        if req.peer_device_id is not None:
            existing = sess.client.sessions.get((req.peer_username, req.peer_device_id))
        if existing is not None:
            return {"peer_username": req.peer_username, "peer_device_id": existing.peer_device_id, "already_active": True}
        try:
            session: BraidSession = sess.client.start_session(req.peer_username, req.peer_device_id)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"could not start session: {exc!r}")
        return {
            "peer_username": session.peer_username,
            "peer_device_id": session.peer_device_id,
            "already_active": False,
        }


class SendChatRequest(BaseModel):
    session_id: str
    peer_username: str
    peer_device_id: int
    text: str


@app.post("/api/chat/send")
def send_chat(req: SendChatRequest) -> dict:
    if not req.text.strip():
        raise HTTPException(status_code=422, detail="empty message")
    if len(req.text) > 8000:
        raise HTTPException(status_code=422, detail="message too long")

    sess = _get_session(req.session_id)
    with sess.lock:
        session = sess.client.sessions.get((req.peer_username, req.peer_device_id))
        if session is None:
            raise HTTPException(status_code=404, detail="no active session with that peer/device; call /api/chat/start first")
        if session.latest_epoch() is None:
            raise HTTPException(status_code=409, detail="handshake still in progress; try again shortly")
        try:
            epoch = sess.client.send_chat(session, req.text)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=409, detail=f"send failed: {exc!r}")

    entry = {
        "direction": "out",
        "peer_username": req.peer_username,
        "peer_device_id": req.peer_device_id,
        "epoch": epoch,
        "text": req.text,
        "ts": time.time(),
    }
    sess.note_history((req.peer_username, req.peer_device_id), entry)
    return {"epoch": epoch}


@app.get("/api/chat/history")
def chat_history(session_id: str, peer_username: str, peer_device_id: int) -> list:
    sess = _get_session(session_id)
    return sess.history.get((peer_username, peer_device_id), [])


# ---------------------------------------------------------------------------
# Live event stream to the browser
# ---------------------------------------------------------------------------


@app.websocket("/api/events")
async def events_ws(websocket: WebSocket, session_id: str) -> None:
    await websocket.accept()
    try:
        sess = _get_session(session_id)
    except HTTPException:
        await websocket.close(code=4401)
        return

    try:
        while True:
            try:
                event: ChatEvent = await asyncio.to_thread(sess.events.get, True, 1.0)
            except queue.Empty:
                continue
            await websocket.send_json({"type": event.kind, **event.payload})
    except WebSocketDisconnect:
        return


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------

app.mount("/ui", StaticFiles(directory=str(STATIC_DIR), html=True), name="ui")


@app.get("/")
def root() -> FileResponse:
    return FileResponse(str(STATIC_DIR / "index.html"))
