from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Sequence


@dataclass(frozen=True)
class UsernameRecordBody:
    username_hash: str
    username_display_commitment: str
    identity_sign_pub: str
    primary_home_relay: str
    relay_descriptor_hash: str

    def to_record_body(self) -> dict[str, Any]:
        return {
            "username_hash": self.username_hash,
            "username_display_commitment": self.username_display_commitment,
            "identity_sign_pub": self.identity_sign_pub,
            "primary_home_relay": self.primary_home_relay,
            "relay_descriptor_hash": self.relay_descriptor_hash,
        }


@dataclass(frozen=True)
class RelayDescriptorBody:
    relay_id: str
    signing_key: str
    onion_key: str
    endpoints: Sequence[str]
    supports_home: bool
    supports_transit: bool
    supports_rendezvous: bool
    min_circuit_hops: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "endpoints", tuple(self.endpoints))

    def to_record_body(self) -> dict[str, Any]:
        return {
            "relay_id": self.relay_id,
            "signing_key": self.signing_key,
            "onion_key": self.onion_key,
            "endpoints": list(self.endpoints),
            "supports_home": self.supports_home,
            "supports_transit": self.supports_transit,
            "supports_rendezvous": self.supports_rendezvous,
            "min_circuit_hops": self.min_circuit_hops,
        }


@dataclass(frozen=True)
class ContactEventBody:
    event_kind: str
    request_id: str
    peer_identity: str
    peer_device_id: int
    conversation_id: str
    note_ciphertext: Optional[str] = None

    def to_record_body(self) -> dict[str, Any]:
        return {
            "event_kind": self.event_kind,
            "request_id": self.request_id,
            "peer_identity": self.peer_identity,
            "peer_device_id": self.peer_device_id,
            "conversation_id": self.conversation_id,
            "note_ciphertext": self.note_ciphertext,
        }
