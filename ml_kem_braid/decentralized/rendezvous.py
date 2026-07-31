from __future__ import annotations

import hmac
from hashlib import sha256

_ACTION_DOMAIN = b"ml-kem-braid:rendezvous-action:v1"
_MIN_JOIN_KEY_SIZE = 16
_JOIN_ACTION = "join"
_SEND_ACTION = "send"
_RECEIVE_ACTION = "receive"


def rendezvous_action_authenticator(
    join_key: bytes,
    rendezvous_id: str,
    stream_id: str,
    action: str,
) -> bytes:
    """MAC proving the caller holds the rendezvous token for one operation.

    The MAC binds the rendezvous, the stream identifier *and* the action, so a
    captured authenticator cannot be replayed to claim a different slot, a
    different rendezvous, or a different operation (e.g. a join authenticator
    seen by the relay cannot be reused to drain the peer's inbox).
    """

    if not isinstance(join_key, (bytes, bytearray, memoryview)):
        raise TypeError("join_key must be bytes")
    join_key = bytes(join_key)
    if len(join_key) < _MIN_JOIN_KEY_SIZE:
        raise ValueError(f"join_key must be at least {_MIN_JOIN_KEY_SIZE} bytes")
    if not isinstance(rendezvous_id, str) or not isinstance(stream_id, str):
        raise TypeError("rendezvous_id and stream_id must be strings")
    if not isinstance(action, str) or action == "":
        raise ValueError("action must be a non-empty string")

    rendezvous_bytes = rendezvous_id.encode("utf-8")
    stream_bytes = stream_id.encode("utf-8")
    action_bytes = action.encode("utf-8")
    mac_input = b"".join(
        [
            _ACTION_DOMAIN,
            len(rendezvous_bytes).to_bytes(4, "big"),
            rendezvous_bytes,
            len(stream_bytes).to_bytes(4, "big"),
            stream_bytes,
            len(action_bytes).to_bytes(4, "big"),
            action_bytes,
        ]
    )
    return hmac.new(join_key, mac_input, sha256).digest()


def rendezvous_join_authenticator(
    join_key: bytes,
    rendezvous_id: str,
    stream_id: str,
) -> bytes:
    """MAC a joiner presents to prove it holds the rendezvous token."""

    return rendezvous_action_authenticator(
        join_key, rendezvous_id, stream_id, _JOIN_ACTION
    )


def rendezvous_send_authenticator(
    join_key: bytes,
    rendezvous_id: str,
    stream_id: str,
) -> bytes:
    """MAC a sender presents to queue a payload for its peer."""

    return rendezvous_action_authenticator(
        join_key, rendezvous_id, stream_id, _SEND_ACTION
    )


def rendezvous_receive_authenticator(
    join_key: bytes,
    rendezvous_id: str,
    stream_id: str,
) -> bytes:
    """MAC a receiver presents to drain its own inbox."""

    return rendezvous_action_authenticator(
        join_key, rendezvous_id, stream_id, _RECEIVE_ACTION
    )


class RendezvousRelay:
    """Relay-only rendezvous stream joiner.

    The relay tracks stream membership and opaque payload queues, but never
    stores or exposes peer network addresses.

    Audit M10: joining used to require nothing but knowledge of the
    ``rendezvous_id``, so anyone who learned (or guessed) it could occupy one
    of the two slots, and because ``stream_id`` was a *global* namespace an
    attacker could also pre-register a victim's intended stream id and lock it
    out. A rendezvous must now be created with a join key; every join presents
    an HMAC over ``(rendezvous_id, stream_id, "join")`` under that key, checked
    in constant time, and stream ids are scoped under their rendezvous.

    Verifier D13: authenticating only ``open_stream`` left the fix half done.
    ``send``/``receive`` still trusted bare identifiers, so anyone who learned
    (or observed) ``(rendezvous_id, stream_id)`` could inject payloads into a
    peer's inbox or *drain the victim's inbox*, which both breaks delivery and
    hands the attacker the ciphertexts. Every operation now carries its own
    action-bound MAC under the same join key, checked in constant time before
    any state is read or mutated.
    """

    def __init__(self) -> None:
        self._join_keys: dict[str, bytes] = {}
        self._rendezvous_streams: dict[str, list[str]] = {}
        self._inboxes: dict[tuple[str, str], list[bytes]] = {}

    def create_rendezvous(self, rendezvous_id: str, join_key: bytes) -> None:
        """Register a rendezvous and the key joiners must authenticate with."""

        if not isinstance(rendezvous_id, str) or rendezvous_id == "":
            raise ValueError("rendezvous_id must be a non-empty string")
        if not isinstance(join_key, (bytes, bytearray, memoryview)):
            raise TypeError("join_key must be bytes")
        join_key = bytes(join_key)
        if len(join_key) < _MIN_JOIN_KEY_SIZE:
            raise ValueError(f"join_key must be at least {_MIN_JOIN_KEY_SIZE} bytes")
        if rendezvous_id in self._join_keys:
            raise ValueError("rendezvous already exists")
        self._join_keys[rendezvous_id] = join_key
        self._rendezvous_streams[rendezvous_id] = []

    def open_stream(
        self,
        rendezvous_id: str,
        stream_id: str,
        authenticator: bytes,
    ) -> None:
        if not isinstance(stream_id, str) or stream_id == "":
            raise ValueError("stream_id must be a non-empty string")
        self._require_authenticator(
            rendezvous_id, stream_id, authenticator, _JOIN_ACTION
        )

        streams = self._rendezvous_streams[rendezvous_id]
        if stream_id in streams:
            return
        if len(streams) >= 2:
            raise ValueError("rendezvous supports exactly two streams")

        streams.append(stream_id)
        self._inboxes[(rendezvous_id, stream_id)] = []

    def send(
        self,
        rendezvous_id: str,
        stream_id: str,
        payload: bytes,
        authenticator: bytes,
    ) -> None:
        """Queue ``payload`` for the peer stream (authenticated, audit D13)."""

        self._require_authenticator(
            rendezvous_id, stream_id, authenticator, _SEND_ACTION
        )
        streams = self._known_streams(rendezvous_id, stream_id)
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("payload must be bytes")

        queued_payload = bytes(payload)
        for peer_stream_id in streams:
            if peer_stream_id != stream_id:
                self._inboxes[(rendezvous_id, peer_stream_id)].append(queued_payload)

    def receive(
        self,
        rendezvous_id: str,
        stream_id: str,
        authenticator: bytes,
    ) -> list[bytes]:
        """Drain this stream's inbox (authenticated, audit D13)."""

        self._require_authenticator(
            rendezvous_id, stream_id, authenticator, _RECEIVE_ACTION
        )
        self._known_streams(rendezvous_id, stream_id)
        inbox = self._inboxes[(rendezvous_id, stream_id)]
        payloads = list(inbox)
        inbox.clear()
        return payloads

    def peer_addresses(self, rendezvous_id: str) -> list[str]:
        if rendezvous_id not in self._rendezvous_streams:
            raise KeyError("unknown rendezvous")
        return []

    def _require_authenticator(
        self,
        rendezvous_id: str,
        stream_id: str,
        authenticator: bytes,
        action: str,
    ) -> None:
        """Constant-time MAC check; fails closed before any state is touched."""

        if not isinstance(authenticator, (bytes, bytearray, memoryview)):
            raise TypeError("authenticator must be bytes")
        try:
            join_key = self._join_keys[rendezvous_id]
        except KeyError as exc:
            raise KeyError("unknown rendezvous") from exc

        expected = rendezvous_action_authenticator(
            join_key, rendezvous_id, stream_id, action
        )
        if not hmac.compare_digest(expected, bytes(authenticator)):
            raise PermissionError(
                f"rendezvous {action} authenticator is invalid"
            )

    def _known_streams(self, rendezvous_id: str, stream_id: str) -> list[str]:
        streams = self._rendezvous_streams.get(rendezvous_id)
        if streams is None or stream_id not in streams:
            raise KeyError("unknown stream")
        return streams
