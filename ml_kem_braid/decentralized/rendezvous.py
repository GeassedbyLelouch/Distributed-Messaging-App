from __future__ import annotations


class RendezvousRelay:
    """Relay-only rendezvous stream joiner.

    The relay tracks stream membership and opaque payload queues, but never
    stores or exposes peer network addresses.
    """

    def __init__(self) -> None:
        self._rendezvous_streams: dict[str, list[str]] = {}
        self._stream_rendezvous: dict[str, str] = {}
        self._inboxes: dict[str, list[bytes]] = {}

    def open_stream(self, rendezvous_id: str, stream_id: str) -> None:
        existing_rendezvous = self._stream_rendezvous.get(stream_id)
        if existing_rendezvous == rendezvous_id:
            return
        if existing_rendezvous is not None:
            raise ValueError("stream already open")

        streams = self._rendezvous_streams.setdefault(rendezvous_id, [])
        if len(streams) >= 2:
            raise ValueError("rendezvous supports exactly two streams")

        streams.append(stream_id)
        self._stream_rendezvous[stream_id] = rendezvous_id
        self._inboxes[stream_id] = []

    def send(self, stream_id: str, payload: bytes) -> None:
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("payload must be bytes")

        try:
            rendezvous_id = self._stream_rendezvous[stream_id]
        except KeyError as exc:
            raise KeyError("unknown stream") from exc

        queued_payload = bytes(payload)
        for peer_stream_id in self._rendezvous_streams[rendezvous_id]:
            if peer_stream_id != stream_id:
                self._inboxes[peer_stream_id].append(queued_payload)

    def receive(self, stream_id: str) -> list[bytes]:
        try:
            inbox = self._inboxes[stream_id]
        except KeyError as exc:
            raise KeyError("unknown stream") from exc

        payloads = list(inbox)
        inbox.clear()
        return payloads

    def peer_addresses(self, rendezvous_id: str) -> list[str]:
        if rendezvous_id not in self._rendezvous_streams:
            raise KeyError("unknown rendezvous")
        return []
