from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional


class InMemoryClientVault:
    """In-memory storage for minimal client-local decentralized state."""

    def __init__(self) -> None:
        self._identities: Dict[str, bytes] = {}
        self._sessions: Dict[str, dict[str, Any]] = {}
        self._contact_records: Dict[str, List[dict[str, Any]]] = {}

    def store_identity(self, username: str, identity_secret: bytes) -> None:
        if not isinstance(identity_secret, bytes):
            raise TypeError("identity_secret must be bytes")
        self._identities[username] = bytes(identity_secret)

    def load_identity(self, username: str) -> Optional[bytes]:
        identity_secret = self._identities.get(username)
        if identity_secret is None:
            return None
        return bytes(identity_secret)

    def store_session(
        self,
        conversation_id: str,
        peer_identity: bytes,
        state: dict[str, Any],
    ) -> None:
        if not isinstance(peer_identity, bytes):
            raise TypeError("peer_identity must be bytes")
        self._sessions[conversation_id] = {
            "peer_identity": peer_identity.hex(),
            "state": deepcopy(state),
        }

    def load_session(self, conversation_id: str) -> Optional[dict[str, Any]]:
        session = self._sessions.get(conversation_id)
        if session is None:
            return None
        return deepcopy(session)

    def append_contact_record(self, conversation_id: str, record: dict[str, Any]) -> None:
        if not isinstance(record, dict):
            raise TypeError("record must be a dict")
        sequence = record.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise ValueError("record sequence must be an int")
        self._contact_records.setdefault(conversation_id, []).append(deepcopy(record))

    def load_contact_records(self, conversation_id: str) -> list[dict[str, Any]]:
        records = self._contact_records.get(conversation_id, [])
        return deepcopy(sorted(records, key=lambda record: record["sequence"]))
