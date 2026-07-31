from __future__ import annotations

from dataclasses import dataclass, field
import time
from types import MappingProxyType
from typing import Any, Mapping, Optional

from ml_kem_braid.crypto import xeddsa

from ml_kem_braid.decentralized.canonical import canonical_json

# XEdDSA domain-separation context for signed records (see xeddsa.sign_ctx).
_RECORD_CONTEXT = b"decentralized/record"

# Audit M8: timestamps are integer epoch milliseconds end-to-end. Floats are
# rejected because their canonical encoding depends on the runtime's
# ``repr(float)`` (consensus split between honest verifiers).
MAX_EPOCH_MS = (1 << 63) - 1

# Audit M7: how far into the future a record's ``created_at`` may sit before it
# is treated as forged/misdated (tolerates modest clock skew between peers).
MAX_CLOCK_SKEW_MS = 5 * 60 * 1000


def now_ms() -> int:
    """Current wall-clock time in integer epoch milliseconds."""

    return time.time_ns() // 1_000_000


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

# Verifier D18: fields that ride along on the *publisher's* request but are
# neither signed nor republished. ``username_preimage`` opens the signed
# ``body["username_hash"]`` commitment so the registry can check the claim; the
# registry must never hand that preimage back out to anonymous lookups, which
# is exactly what the hashed-username privacy model exists to prevent. Keeping
# it out of ``signing_payload()`` and ``to_dict()`` makes republication
# structurally impossible rather than a matter of remembering to strip it.
# It is unauthenticated by design and safe to be: every value it can take is
# checked against the *signed* hash and binding before it is believed.
_UNSIGNED_TRANSPORT_FIELDS = {"username_preimage"}


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
    if not _RECORD_FIELDS <= fields:
        raise ValueError("signed record has missing or unexpected fields")
    if not (fields - _RECORD_FIELDS) <= _UNSIGNED_TRANSPORT_FIELDS:
        raise ValueError("signed record has missing or unexpected fields")


def _require_type(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a string")
    return value


def _require_int(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field} must be an int")
    return value


def _require_epoch_ms(value: Any, field: str) -> int:
    """Timestamps are integer epoch milliseconds (audit M8) — no floats."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field} must be an integer epoch-millisecond timestamp")
    if value < 0 or value > MAX_EPOCH_MS:
        raise ValueError(f"{field} must be a non-negative 63-bit epoch-ms value")
    return value


def _require_optional_epoch_ms(value: Any, field: str) -> int | None:
    if value is None:
        return None
    return _require_epoch_ms(value, field)


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
    """A signed record plus (optionally) an unsigned, unpublished opening.

    ``username_preimage`` is deliberately NOT part of the signed payload and
    NOT part of :meth:`to_dict` — see :data:`_UNSIGNED_TRANSPORT_FIELDS`. It is
    excluded from equality/repr so it can never change record identity or leak
    through a log line; use :meth:`to_publish_dict` on the publishing path.
    """

    record_type: str
    version: int
    author_identity: bytes
    author_device_id: int
    sequence: int
    created_at: int
    expires_at: Optional[int]
    body: Mapping[str, Any]
    signature: bytes
    username_preimage: Optional[str] = field(
        default=None, compare=False, repr=False
    )

    def __post_init__(self) -> None:
        _require_epoch_ms(self.created_at, "created_at")
        _require_optional_epoch_ms(self.expires_at, "expires_at")
        _require_int(self.sequence, "sequence")
        if self.sequence < 0:
            raise ValueError("sequence must be non-negative")
        if self.username_preimage is not None and not isinstance(
            self.username_preimage, str
        ):
            raise TypeError("username_preimage must be a string")
        object.__setattr__(self, "body", _freeze_value(self.body))

    def without_unsigned_fields(self) -> "SignedRecord":
        """A copy carrying only signed data — what the registry may store."""

        if self.username_preimage is None:
            return self
        return SignedRecord(
            record_type=self.record_type,
            version=self.version,
            author_identity=self.author_identity,
            author_device_id=self.author_device_id,
            sequence=self.sequence,
            created_at=self.created_at,
            expires_at=self.expires_at,
            body=_thaw_value(self.body),
            signature=self.signature,
        )

    def is_expired(self, at_ms: int) -> bool:
        return self.expires_at is not None and at_ms >= self.expires_at

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
        """The published form: signed fields only, never the opening (D18)."""

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

    def to_publish_dict(self) -> dict[str, Any]:
        """Publisher -> registry form: adds the unsigned opening when present.

        Only ever sent *to* the registry. Anything the registry serves back
        goes through :meth:`to_dict`, which cannot carry the preimage.
        """

        published = self.to_dict()
        if self.username_preimage is not None:
            published["username_preimage"] = self.username_preimage
        return published

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SignedRecord":
        if not isinstance(value, dict):
            raise TypeError("signed record must be a dict")
        _require_exact_fields(value)
        body = value["body"]
        if not isinstance(body, dict):
            raise TypeError("body must be a dict")
        username_preimage = value.get("username_preimage")
        if username_preimage is not None and not isinstance(username_preimage, str):
            raise TypeError("username_preimage must be a string")
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
            created_at=_require_epoch_ms(value["created_at"], "created_at"),
            expires_at=_require_optional_epoch_ms(value["expires_at"], "expires_at"),
            body=body,
            signature=_require_hex_bytes(value["signature"], "signature", 64),
            username_preimage=username_preimage,
        )


def sign_record(
    *,
    record_type: str,
    author_identity: bytes,
    author_device_id: int,
    sequence: int,
    body: dict[str, Any],
    signing_key: bytes,           # 32-byte clamped Curve25519 private key
    created_at: int,
    expires_at: Optional[int] = None,
    version: int = 1,
    username_preimage: Optional[str] = None,
) -> SignedRecord:
    """Sign a record.

    ``username_preimage`` is attached unsigned (verifier D18): it opens the
    signed ``body["username_hash"]`` for the registry and is dropped by
    :meth:`SignedRecord.to_dict`, so it is never republished.
    """

    created_at = _require_epoch_ms(created_at, "created_at")
    expires_at = _require_optional_epoch_ms(expires_at, "expires_at")
    if expires_at is not None and expires_at <= created_at:
        raise ValueError("expires_at must be strictly after created_at")
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
    signature = xeddsa.sign_ctx(signing_key, _RECORD_CONTEXT, unsigned.signing_payload())
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
        username_preimage=username_preimage,
    )


def verify_record(
    record: SignedRecord,
    public_key: bytes,
    *,
    at_ms: Optional[int] = None,
    max_skew_ms: int = MAX_CLOCK_SKEW_MS,
    enforce_freshness: bool = True,
) -> bool:
    """Verify signature, author binding and freshness of a signed record.

    Audit M7: ``expires_at`` is part of the signed payload but was never
    compared against a clock, so an expired (or far-future, misdated) record
    replayed forever. Freshness is now enforced against an injectable clock
    (``at_ms``, integer epoch milliseconds; defaults to the wall clock).
    """

    if not xeddsa.verify_ctx(
        public_key, _RECORD_CONTEXT, record.signing_payload(), record.signature
    ):
        return False
    if record.author_identity != public_key:
        return False
    if enforce_freshness:
        checked_at = now_ms() if at_ms is None else _require_epoch_ms(at_ms, "at_ms")
        if record.is_expired(checked_at):
            return False
        if record.created_at > checked_at + max_skew_ms:
            return False
    return True


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
    *,
    at_ms: Optional[int] = None,
    enforce_freshness: bool = True,
) -> dict[str, str]:
    """Fold signed contact events into per-conversation state.

    Audit M7: records are verified *with freshness* (expired records no longer
    replay) and terminal states (``accepted``/``denied``/``cancelled``) are
    immutable — a later event cannot roll a settled conversation back or move
    it sideways.
    """

    requests: dict[str, tuple[str, bytes, bytes]] = {}
    states: dict[str, str] = {}
    terminal_states = {"accepted", "denied", "cancelled"}
    checked_at = now_ms() if at_ms is None else _require_epoch_ms(at_ms, "at_ms")
    ordered = sorted(
        records,
        key=lambda item: (item.created_at, item.sequence, item.signature),
    )
    for record in ordered:
        if record.author_identity not in trusted_identities:
            continue
        if not verify_record(
            record,
            record.author_identity,
            at_ms=checked_at,
            enforce_freshness=enforce_freshness,
        ):
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
            if states.get(conversation_id) in terminal_states:
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
            if states.get(conversation_id) in terminal_states:
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
            if states.get(conversation_id) in terminal_states:
                continue
            states[conversation_id] = "cancelled"
    return states
