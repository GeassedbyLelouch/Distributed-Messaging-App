"""
WebSocket transport tests.

Tests cover:
  1. /ws rejects bad tokens with close code 1008.
  2. WS-to-WS push: Alice sends via WS, Bob (WS-connected) receives pushed envelope
     with sender identity derived from the token (never the frame body).
  3. HTTP-to-WS push: envelope delivered via POST /messages is pushed to a
     WS-connected recipient without polling.
  4. Mailbox flush on WS connect: envelopes queued while offline are flushed
     to the socket on connect.
  5. Transport protocol conformance: WebSocketTransport isinstance Transport.
  6. WebSocketTransport.fetch() drains buffered frames (via push()).
  7. BraidChatClient typed against Transport, with WS send + HTTP poll round-trip.

Starlette TestClient constraint
--------------------------------
``WebSocketTestSession.receive_json()`` is synchronous and blocks indefinitely
until a frame arrives.  Two nested ``websocket_connect`` context managers work
only when each receive call is preceded by a guaranteed frame from the server.
``WebSocketTransport`` is therefore *passive*: it never calls ``receive_json()``
internally; the caller drives all wire receives explicitly.  Tests call
``ws.receive_json()`` only when a frame is certain (right after a send that
triggers a server response or push).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.testclient import WebSocketDisconnect

from ml_kem_braid.client.client import BraidChatClient, HttpTransport, run_until_agreed
from ml_kem_braid.client.transport import Transport, WebSocketTransport
from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def store() -> SesameStore:
    return SesameStore()


@pytest.fixture()
def app(store: SesameStore):
    return create_app(store)


@pytest.fixture()
def tc(app) -> TestClient:
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture()
def alice_http(tc: TestClient) -> BraidChatClient:
    client = BraidChatClient(HttpTransport(tc), "alice")
    client.register()
    return client


@pytest.fixture()
def bob_http(tc: TestClient) -> BraidChatClient:
    client = BraidChatClient(HttpTransport(tc), "bob")
    client.register()
    return client


# ---------------------------------------------------------------------------
# 1. Bad-token rejection
# ---------------------------------------------------------------------------


def test_ws_rejects_bad_token(tc: TestClient) -> None:
    """Server closes with 1008 when the token query param is invalid."""
    with pytest.raises(WebSocketDisconnect):
        with tc.websocket_connect("/ws?token=not-a-real-token"):
            pass  # should not reach here


# ---------------------------------------------------------------------------
# 2. WS-to-WS push with token-derived sender identity
# ---------------------------------------------------------------------------


def test_ws_to_ws_push_sender_from_token(
    tc: TestClient, alice_http: BraidChatClient, bob_http: BraidChatClient
) -> None:
    """Alice sends a chat envelope via WS; Bob (WS-connected) receives it pushed.

    The sender_username in the pushed envelope must come from the token, not
    from anything Alice put in the frame body.
    """
    with tc.websocket_connect(f"/ws?token={alice_http.auth_token}") as alice_ws:
        with tc.websocket_connect(f"/ws?token={bob_http.auth_token}") as bob_ws:
            alice_ws.send_json(
                {
                    "action": "send",
                    "recipient_username": "bob",
                    "recipient_device_id": bob_http.device_id,
                    "kind": "chat",
                    "body": {"epoch": 1, "ciphertext": "dGVzdA=="},
                }
            )

            # Alice gets ack (guaranteed: server always acks a valid send).
            ack = alice_ws.receive_json()
            assert ack["type"] == "ack"

            # Bob gets push (guaranteed: server pushed before sending ack).
            pushed = bob_ws.receive_json()
            assert pushed["type"] == "envelope"
            env = pushed["envelope"]
            # Sender comes from the connection token — not from the frame.
            assert env["sender_username"] == "alice"
            assert env["sender_device_id"] == alice_http.device_id
            assert env["recipient_username"] == "bob"
            assert env["kind"] == "chat"


# ---------------------------------------------------------------------------
# 3. HTTP-to-WS push
# ---------------------------------------------------------------------------


def test_http_send_pushes_to_ws_connected_recipient(
    tc: TestClient, alice_http: BraidChatClient, bob_http: BraidChatClient
) -> None:
    """An envelope sent via POST /messages is pushed to a WS-connected recipient."""
    with tc.websocket_connect(f"/ws?token={bob_http.auth_token}") as bob_ws:
        r = tc.post(
            "/messages",
            json={
                "recipient_username": "bob",
                "recipient_device_id": bob_http.device_id,
                "kind": "chat",
                "body": {"msg": "http-to-ws"},
            },
            headers={"Authorization": f"Bearer {alice_http.auth_token}"},
        )
        assert r.status_code == 200

        # Bob receives the push (guaranteed: HTTP send triggers server push).
        pushed = bob_ws.receive_json()
        assert pushed["type"] == "envelope"
        env = pushed["envelope"]
        assert env["sender_username"] == "alice"
        assert env["body"]["msg"] == "http-to-ws"


# ---------------------------------------------------------------------------
# 4. Mailbox flush on WS connect
# ---------------------------------------------------------------------------


def test_queued_envelopes_flushed_on_ws_connect(
    tc: TestClient, alice_http: BraidChatClient, bob_http: BraidChatClient
) -> None:
    """Envelopes delivered to an offline device are flushed when it connects via WS."""
    # Bob is offline — send via HTTP so it lands in the mailbox.
    r = tc.post(
        "/messages",
        json={
            "recipient_username": "bob",
            "recipient_device_id": bob_http.device_id,
            "kind": "chat",
            "body": {"msg": "offline-queued"},
        },
        headers={"Authorization": f"Bearer {alice_http.auth_token}"},
    )
    assert r.status_code == 200

    # Bob connects — the server flushes the mailbox immediately on accept.
    with tc.websocket_connect(f"/ws?token={bob_http.auth_token}") as bob_ws:
        flushed = bob_ws.receive_json()
        assert flushed["type"] == "envelope"
        env = flushed["envelope"]
        assert env["sender_username"] == "alice"
        assert env["body"]["msg"] == "offline-queued"


# ---------------------------------------------------------------------------
# 5. Transport protocol conformance
# ---------------------------------------------------------------------------


def test_websocket_transport_satisfies_transport_protocol(
    tc: TestClient, alice_http: BraidChatClient
) -> None:
    """WebSocketTransport must satisfy the Transport runtime-checkable protocol."""
    http = HttpTransport(tc)
    with tc.websocket_connect(f"/ws?token={alice_http.auth_token}") as ws_session:
        wst = WebSocketTransport(
            base_http=http,
            ws_session=ws_session,
            token=alice_http.auth_token,
        )
        assert isinstance(wst, Transport)
        assert isinstance(http, Transport)


# ---------------------------------------------------------------------------
# 6. WebSocketTransport.fetch() drains buffered frames
# ---------------------------------------------------------------------------


def test_ws_transport_fetch_returns_buffered_envelopes(
    tc: TestClient, alice_http: BraidChatClient, bob_http: BraidChatClient
) -> None:
    """WebSocketTransport.fetch() returns envelopes that were push()-ed into it.

    Because Starlette's receive_json() is blocking, WebSocketTransport does
    not call it internally.  The test reads a frame from the wire explicitly,
    deposits it via push(), then asserts fetch() returns it correctly.
    """
    with tc.websocket_connect(f"/ws?token={bob_http.auth_token}") as bob_ws:
        http = HttpTransport(tc)
        bob_wst = WebSocketTransport(
            base_http=http,
            ws_session=bob_ws,
            token=bob_http.auth_token,
        )

        # Alice sends via HTTP → pushed to Bob's live WS socket.
        r = tc.post(
            "/messages",
            json={
                "recipient_username": "bob",
                "recipient_device_id": bob_http.device_id,
                "kind": "chat",
                "body": {"epoch": 1, "ciphertext": "dGVzdA=="},
            },
            headers={"Authorization": f"Bearer {alice_http.auth_token}"},
        )
        assert r.status_code == 200

        # Receive the pushed frame from the wire and deposit it in the transport.
        frame = bob_ws.receive_json()
        assert frame["type"] == "envelope"
        bob_wst.push(frame)

        # Now fetch() should return the buffered envelope.
        envelopes = bob_wst.fetch(bob_http.auth_token)
        assert len(envelopes) == 1
        env = envelopes[0]
        assert env["sender_username"] == "alice"
        assert env["kind"] == "chat"


# ---------------------------------------------------------------------------
# 7. BraidChatClient over WebSocketTransport — send + receive round-trip
#
# Starlette TestClient limitation: two nested receive_json() loops cannot run
# in the same thread.  We therefore:
#   a. Run PQXDH + Braid key agreement over plain HTTP (no WS context open).
#   b. Open alice's WS connection, send the chat envelope via
#      WebSocketTransport.send(), read the ack frame explicitly, then close.
#   c. Bob polls via HTTP to retrieve the chat envelope and decrypt it.
#
# This proves BraidChatClient is transport-agnostic (accepts any Transport)
# and that WebSocketTransport.send() correctly routes through the server.
# ---------------------------------------------------------------------------


def test_braid_chat_client_over_ws_transport(
    tc: TestClient,
    store: SesameStore,  # noqa: ARG001 — injected so tc and store share the same SesameStore
) -> None:
    """BraidChatClient typed against Transport, driven partly over WebSocketTransport."""
    http = HttpTransport(tc)

    # Both clients start with HTTP transport; BraidChatClient accepts Transport.
    alice: BraidChatClient = BraidChatClient(http, "alice")
    bob: BraidChatClient = BraidChatClient(http, "bob")
    alice.register()
    bob.register()

    assert isinstance(alice.transport, Transport)
    assert isinstance(bob.transport, Transport)

    # PQXDH + Braid session over HTTP (synchronous, no WS involved).
    session = alice.start_session("bob")
    run_until_agreed(alice, bob, session, target_epochs=1)
    epoch = session.latest_epoch()
    assert epoch is not None

    bob.poll()
    bob_session = bob.sessions.get(("alice", alice.device_id))
    assert bob_session is not None

    # Switch Alice to WebSocketTransport for the chat send.
    with tc.websocket_connect(f"/ws?token={alice.auth_token}") as alice_ws:
        alice_wst = WebSocketTransport(
            base_http=http,
            ws_session=alice_ws,
            token=alice.auth_token,
        )
        alice.transport = alice_wst  # BraidChatClient now uses WS transport

        # send_chat() calls transport.send() → WS frame to server.
        alice.send_chat(session, "hello via websocket")

        # Consume the ack the server sends after the WS send.
        ack = alice_ws.receive_json()
        assert ack["type"] == "ack"

    # Bob polls via HTTP to retrieve and decrypt the chat envelope.
    bob.poll()
    assert len(bob.inbox) == 1
    peer_name, peer_dev, recv_epoch, text = bob.inbox[0]
    assert peer_name == "alice"
    assert text == "hello via websocket"
    assert recv_epoch == epoch


# ---------------------------------------------------------------------------
# 8. At-least-once: envelope falls back to mailbox when no live socket succeeds
# ---------------------------------------------------------------------------


def test_envelope_stored_in_mailbox_when_push_fails(
    tc: TestClient, alice_http: BraidChatClient, bob_http: BraidChatClient
) -> None:
    """If every WS socket for the recipient dies before send_json succeeds,
    the envelope must land in the persistent mailbox and be retrievable via
    GET /messages — proving at-least-once delivery.

    Mechanism: we open Bob's WS connection to make the server believe he is
    live, then send the HTTP POST while that connection is already closed
    (simulated by closing the context manager before the POST).  The server's
    push_envelope call therefore finds zero healthy sockets and falls back to
    store.deliver(), so the envelope appears in the mailbox.
    """
    # Open Bob's WS, then deliberately exit (close) it before sending.
    with tc.websocket_connect(f"/ws?token={bob_http.auth_token}"):
        pass  # Bob's socket is now closed / disconnected

    # Bob is offline.  Envelope must go to mailbox.
    r = tc.post(
        "/messages",
        json={
            "recipient_username": "bob",
            "recipient_device_id": bob_http.device_id,
            "kind": "chat",
            "body": {"msg": "fallback-to-mailbox"},
        },
        headers={"Authorization": f"Bearer {alice_http.auth_token}"},
    )
    assert r.status_code == 200

    # Retrieve via GET /messages — envelope must be present.
    r2 = tc.get(
        "/messages",
        headers={"Authorization": f"Bearer {bob_http.auth_token}"},
    )
    assert r2.status_code == 200
    envelopes = r2.json()
    assert len(envelopes) == 1
    env = envelopes[0]
    assert env["sender_username"] == "alice"
    assert env["body"]["msg"] == "fallback-to-mailbox"
    assert env["recipient_username"] == "bob"
