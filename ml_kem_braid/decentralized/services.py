from __future__ import annotations

from copy import deepcopy
from typing import Any, Optional

from ml_kem_braid.decentralized.records import SignedRecord, verify_record


_LOWER_HEX = frozenset("0123456789abcdef")
_USERNAME_RECORD_TYPE = "identity.username_record"


class DecentralizedServices:
    """In-memory decentralized registry and opaque mailbox service."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, bytes, int], SignedRecord] = {}
        self._username_records: dict[tuple[str, str], SignedRecord] = {}
        self._mailboxes: dict[tuple[str, int], list[dict[str, Any]]] = {}

    def publish_record(self, record: SignedRecord) -> None:
        if not verify_record(record, record.author_identity):
            raise PermissionError("record signature verification failed")

        if record.record_type == _USERNAME_RECORD_TYPE:
            self._publish_username_record(record)
            return

        self._records[
            (record.record_type, record.author_identity, record.sequence)
        ] = record

    def lookup_username(self, username_hash: str) -> Optional[SignedRecord]:
        return self._username_records.get((_USERNAME_RECORD_TYPE, username_hash))

    def _publish_username_record(self, record: SignedRecord) -> None:
        username_hash = _validated_username_hash(record)
        key = (_USERNAME_RECORD_TYPE, username_hash)
        if key in self._username_records:
            raise ValueError("username hash already registered")

        self._records[
            (record.record_type, record.author_identity, record.sequence)
        ] = record
        self._username_records[key] = record

    def deliver_envelope(
        self,
        recipient_identity: str,
        recipient_device_id: int,
        envelope: dict[str, Any],
    ) -> None:
        if not isinstance(envelope, dict):
            raise TypeError("envelope must be a dict")
        key = (recipient_identity, recipient_device_id)
        self._mailboxes.setdefault(key, []).append(deepcopy(envelope))

    def fetch_mailbox(
        self,
        recipient_identity: str,
        recipient_device_id: int,
        *,
        drain: bool = True,
    ) -> list[dict[str, Any]]:
        key = (recipient_identity, recipient_device_id)
        queued = self._mailboxes.get(key)
        if queued is None:
            return []
        envelopes = deepcopy(queued)
        if drain:
            del self._mailboxes[key]
        return envelopes

    def fetch_envelopes(
        self,
        recipient_identity: str,
        recipient_device_id: int,
        *,
        drain: bool = True,
    ) -> list[dict[str, Any]]:
        return self.fetch_mailbox(
            recipient_identity,
            recipient_device_id,
            drain=drain,
        )


class FederatedRelay:
    """Minimal federated relay wrapper around a decentralized service home."""

    def __init__(self, relay_id: str, services: DecentralizedServices) -> None:
        self.relay_id = relay_id
        self.services = services
        self._peers: dict[str, FederatedRelay] = {}

    def add_peer(self, peer: FederatedRelay) -> None:
        if not isinstance(peer, FederatedRelay):
            raise TypeError("peer must be a FederatedRelay")
        self._peers[peer.relay_id] = peer

    def forward_to_relay(
        self,
        relay_id: str,
        recipient_identity: str,
        recipient_device_id: int,
        envelope: dict[str, Any],
    ) -> None:
        try:
            peer = self._peers[relay_id]
        except KeyError as exc:
            raise KeyError("unknown federated relay") from exc

        peer.services.deliver_envelope(
            recipient_identity=recipient_identity,
            recipient_device_id=recipient_device_id,
            envelope=envelope,
        )


def _validated_username_hash(record: SignedRecord) -> str:
    username_hash = record.body.get("username_hash")
    if not isinstance(username_hash, str):
        raise ValueError("username_hash must be 64 lowercase hex characters")
    if len(username_hash) != 64 or any(char not in _LOWER_HEX for char in username_hash):
        raise ValueError("username_hash must be 64 lowercase hex characters")

    identity_sign_pub = record.body.get("identity_sign_pub")
    if not isinstance(identity_sign_pub, str):
        raise ValueError("identity_sign_pub must match author_identity")
    if identity_sign_pub != record.author_identity.hex():
        raise ValueError("identity_sign_pub must match author_identity")

    return username_hash
