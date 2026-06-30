from __future__ import annotations

from dataclasses import dataclass
import math
from types import MappingProxyType
from typing import Any, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ml_kem_braid.decentralized.canonical import canonical_json


_RECORD_FIELDS = {
    "type",
    "version",
    "author_identity",
    "author_device_id",
    "sequence",
    "created_at",
    "expires_at",
    "body",
    "signature",
}


def _freeze_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_value(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_value(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_value(item) for item in value)
    return value


def _thaw_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_value(item) for item in value]
    return value


def _require_exact_fields(value: Mapping[str, Any]) -> None:
    fields = set(value)
    if fields != _RECORD_FIELDS:
        raise ValueError("signed record has missing or unexpected fields")


def _require_type(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    return value


def _require_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field} must be an int")
    return value


def _require_finite_number(value: Any, field: str) -> int | float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TypeError(f"{field} must be a finite number")
    if not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    return value


def _require_optional_finite_number(value: Any, field: str) -> int | float | None:
    if value is None:
        return None
    return _require_finite_number(value, field)


def _require_hex_bytes(value: Any, field: str, length: int) -> bytes:
    text = _require_type(value, field)
    try:
        parsed = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueError(f"{field} must be hex encoded") from exc
    if text != parsed.hex() or len(parsed) != length:
        raise ValueError(f"{field} must be {length} bytes of lowercase hex")
    return parsed


@dataclass(frozen=True)
class SignedRecord:
    record_type: str
    version: int
    author_identity: bytes
    author_device_id: int
    sequence: int
    created_at: float
    expires_at: Optional[float]
    body: Mapping[str, Any]
    signature: bytes

    def __post_init__(self) -> None:
        object.__setattr__(self, "body", _freeze_value(self.body))

    def signing_payload(self) -> bytes:
        return canonical_json(
            {
                "type": self.record_type,
                "version": self.version,
                "author_identity": self.author_identity.hex(),
                "author_device_id": self.author_device_id,
                "sequence": self.sequence,
                "created_at": self.created_at,
                "expires_at": self.expires_at,
                "body": _thaw_value(self.body),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.record_type,
            "version": self.version,
            "author_identity": self.author_identity.hex(),
            "author_device_id": self.author_device_id,
            "sequence": self.sequence,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "body": _thaw_value(self.body),
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SignedRecord":
        if not isinstance(value, dict):
            raise TypeError("signed record must be a dict")
        _require_exact_fields(value)
        body = value["body"]
        if not isinstance(body, dict):
            raise TypeError("body must be a dict")
        return cls(
            record_type=_require_type(value["type"], "type"),
            version=_require_int(value["version"], "version"),
            author_identity=_require_hex_bytes(
                value["author_identity"], "author_identity", 32
            ),
            author_device_id=_require_int(
                value["author_device_id"], "author_device_id"
            ),
            sequence=_require_int(value["sequence"], "sequence"),
            created_at=_require_finite_number(value["created_at"], "created_at"),
            expires_at=_require_optional_finite_number(
                value["expires_at"], "expires_at"
            ),
            body=body,
            signature=_require_hex_bytes(value["signature"], "signature", 64),
        )


def sign_record(
    *,
    record_type: str,
    author_identity: bytes,
    author_device_id: int,
    sequence: int,
    body: dict[str, Any],
    signing_key: Ed25519PrivateKey,
    created_at: float,
    expires_at: Optional[float] = None,
    version: int = 1,
) -> SignedRecord:
    unsigned = SignedRecord(
        record_type=record_type,
        version=version,
        author_identity=author_identity,
        author_device_id=author_device_id,
        sequence=sequence,
        created_at=created_at,
        expires_at=expires_at,
        body=body,
        signature=b"",
    )
    signature = signing_key.sign(unsigned.signing_payload())
    return SignedRecord(
        record_type=unsigned.record_type,
        version=unsigned.version,
        author_identity=unsigned.author_identity,
        author_device_id=unsigned.author_device_id,
        sequence=unsigned.sequence,
        created_at=unsigned.created_at,
        expires_at=unsigned.expires_at,
        body=unsigned.body,
        signature=signature,
    )


def verify_record(record: SignedRecord, public_key: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            record.signature,
            record.signing_payload(),
        )
        return record.author_identity == public_key
    except (InvalidSignature, TypeError, ValueError):
        return False


def _contact_string_field(record: SignedRecord, field: str) -> str | None:
    if not isinstance(record.body, Mapping):
        return None
    value = record.body.get(field)
    if not isinstance(value, str) or value == "":
        return None
    return value


def _contact_int_field(record: SignedRecord, field: str) -> int | None:
    if not isinstance(record.body, Mapping):
        return None
    value = record.body.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return value


def _contact_identity_field(record: SignedRecord, field: str) -> bytes | None:
    value = _contact_string_field(record, field)
    if value is None:
        return None
    try:
        parsed = bytes.fromhex(value)
    except ValueError:
        return None
    if value != parsed.hex() or len(parsed) != 32:
        return None
    return parsed


def _contact_request_body(record: SignedRecord) -> tuple[str, str, bytes] | None:
    request_id = _contact_string_field(record, "request_id")
    conversation_id = _contact_string_field(record, "conversation_id")
    recipient_identity = _contact_identity_field(record, "recipient_identity")
    recipient_device_id = _contact_int_field(record, "recipient_device_id")
    if (
        request_id is None
        or conversation_id is None
        or recipient_identity is None
        or recipient_device_id is None
    ):
        return None
    return request_id, conversation_id, recipient_identity


def _contact_response_body(record: SignedRecord) -> tuple[str, bytes] | None:
    request_id = _contact_string_field(record, "request_id")
    conversation_id = _contact_string_field(record, "conversation_id")
    requester_identity = _contact_identity_field(record, "requester_identity")
    requester_device_id = _contact_int_field(record, "requester_device_id")
    if (
        request_id is None
        or conversation_id is None
        or requester_identity is None
        or requester_device_id is None
    ):
        return None
    return request_id, requester_identity


def _contact_cancel_body(record: SignedRecord) -> str | None:
    request_id = _contact_string_field(record, "request_id")
    conversation_id = _contact_string_field(record, "conversation_id")
    if request_id is None or conversation_id is None:
        return None
    return request_id


def derive_contact_state(
    records: list[SignedRecord],
    trusted_identities: set[bytes],
) -> dict[str, str]:
    requests: dict[str, tuple[str, bytes, bytes]] = {}
    states: dict[str, str] = {}
    terminal_states = {"accepted", "denied", "cancelled"}
    for record in sorted(records, key=lambda item: (item.created_at, item.sequence)):
        if record.author_identity not in trusted_identities:
            continue
        if not verify_record(record, record.author_identity):
            continue
        if record.record_type == "contact.request":
            request = _contact_request_body(record)
            if request is None:
                continue
            request_id, conversation_id, recipient_identity = request
            if request_id in requests:
                continue
            requests[request_id] = (
                conversation_id,
                recipient_identity,
                record.author_identity,
            )
            if states.get(conversation_id) not in terminal_states:
                states[conversation_id] = "pending"
        elif record.record_type == "contact.accept":
            response = _contact_response_body(record)
            if response is None:
                continue
            request_id, requester_identity = response
            request = requests.get(request_id)
            if request is None:
                continue
            conversation_id, expected_recipient, expected_requester = request
            if record.author_identity != expected_recipient:
                continue
            if requester_identity != expected_requester:
                continue
            states[conversation_id] = "accepted"
        elif record.record_type == "contact.deny":
            response = _contact_response_body(record)
            if response is None:
                continue
            request_id, requester_identity = response
            request = requests.get(request_id)
            if request is None:
                continue
            conversation_id, expected_recipient, expected_requester = request
            if record.author_identity != expected_recipient:
                continue
            if requester_identity != expected_requester:
                continue
            states[conversation_id] = "denied"
        elif record.record_type == "contact.cancel":
            request_id = _contact_cancel_body(record)
            if request_id is None:
                continue
            request = requests.get(request_id)
            if request is None:
                continue
            conversation_id, _, expected_requester = request
            if record.author_identity != expected_requester:
                continue
            states[conversation_id] = "cancelled"
    return states
