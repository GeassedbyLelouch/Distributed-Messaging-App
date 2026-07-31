from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Sequence
from urllib.parse import urlparse

# Audit L13: relay capability flags and ``min_circuit_hops`` are *self-asserted*
# by the relay. A relay that advertises ``min_circuit_hops=1`` is asking clients
# to build a circuit that gives it the full picture. Clients therefore apply
# their own floor (``MIN_CIRCUIT_HOPS``) instead of believing the descriptor,
# and every encoded field is validated so a malformed descriptor cannot be
# silently accepted.
MIN_CIRCUIT_HOPS = 3
MAX_CIRCUIT_HOPS = 8
_ALLOWED_ENDPOINT_SCHEMES = frozenset({"https", "wss"})
_LOWER_HEX = frozenset("0123456789abcdef")


def _require_hex32(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if len(value) != 64 or any(char not in _LOWER_HEX for char in value):
        raise ValueError(f"{field} must be 64 lowercase hex characters")
    return value


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    if value == "" or len(value) > 256:
        raise ValueError(f"{field} must be a non-empty string of at most 256 chars")
    return value


def _require_endpoint(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("endpoints must be strings")
    parsed = urlparse(value)
    if parsed.scheme not in _ALLOWED_ENDPOINT_SCHEMES:
        raise ValueError("relay endpoints must use https or wss")
    if not parsed.hostname:
        raise ValueError("relay endpoints must include a host")
    return value


def enforce_min_circuit_hops(
    advertised_hops: int,
    *,
    floor: int = MIN_CIRCUIT_HOPS,
) -> int:
    """Client-side floor on a relay's self-asserted ``min_circuit_hops``.

    Never trust a descriptor to lower the hop count: the returned value is the
    larger of the advertised value and the client's own floor.
    """

    if not isinstance(advertised_hops, int) or isinstance(advertised_hops, bool):
        raise TypeError("min_circuit_hops must be an integer")
    if advertised_hops < 1 or advertised_hops > MAX_CIRCUIT_HOPS:
        raise ValueError("min_circuit_hops is out of range")
    return max(advertised_hops, floor)


@dataclass(frozen=True)
class UsernameRecordBody:
    username_hash: str
    username_display_commitment: str
    identity_sign_pub: str
    primary_home_relay: str
    relay_descriptor_hash: str

    def __post_init__(self) -> None:
        _require_hex32(self.username_hash, "username_hash")
        _require_hex32(self.username_display_commitment, "username_display_commitment")
        _require_hex32(self.identity_sign_pub, "identity_sign_pub")
        _require_identifier(self.primary_home_relay, "primary_home_relay")
        _require_hex32(self.relay_descriptor_hash, "relay_descriptor_hash")

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
        _require_identifier(self.relay_id, "relay_id")
        _require_hex32(self.signing_key, "signing_key")
        _require_hex32(self.onion_key, "onion_key")
        endpoints = tuple(self.endpoints)
        if not endpoints:
            raise ValueError("relay descriptor must list at least one endpoint")
        for endpoint in endpoints:
            _require_endpoint(endpoint)
        for flag_name in ("supports_home", "supports_transit", "supports_rendezvous"):
            if not isinstance(getattr(self, flag_name), bool):
                raise TypeError(f"{flag_name} must be a bool")
        enforce_min_circuit_hops(self.min_circuit_hops, floor=1)
        object.__setattr__(self, "endpoints", endpoints)

    def effective_min_circuit_hops(self, *, floor: int = MIN_CIRCUIT_HOPS) -> int:
        """Hop count a client should actually build (never below its floor)."""

        return enforce_min_circuit_hops(self.min_circuit_hops, floor=floor)

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

    def __post_init__(self) -> None:
        _require_identifier(self.event_kind, "event_kind")
        _require_identifier(self.request_id, "request_id")
        _require_hex32(self.peer_identity, "peer_identity")
        if not isinstance(self.peer_device_id, int) or isinstance(
            self.peer_device_id, bool
        ):
            raise TypeError("peer_device_id must be an integer")
        _require_identifier(self.conversation_id, "conversation_id")
        if self.note_ciphertext is not None and not isinstance(
            self.note_ciphertext, str
        ):
            raise TypeError("note_ciphertext must be a string or None")

    def to_record_body(self) -> dict[str, Any]:
        return {
            "event_kind": self.event_kind,
            "request_id": self.request_id,
            "peer_identity": self.peer_identity,
            "peer_device_id": self.peer_device_id,
            "conversation_id": self.conversation_id,
            "note_ciphertext": self.note_ciphertext,
        }
