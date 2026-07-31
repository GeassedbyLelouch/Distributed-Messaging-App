import math

import pytest

from ml_kem_braid.crypto import xeddsa
from ml_kem_braid.decentralized.canonical import canonical_json
from ml_kem_braid.decentralized.records import (
    SignedRecord,
    derive_contact_state,
    sign_record,
    verify_record,
)

# Audit M7/M8: timestamps are integer epoch milliseconds and verification is
# clock-checked, so tests pin an explicit "now" inside the records' validity
# window instead of relying on the wall clock.
CLOCK = 1500


def test_signed_record_verifies_with_canonical_body_order():
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)
    record = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=7,
        body={"recipient": "Bob.1042", "requester": "Alice.42"},
        signing_key=key,
        created_at=1000,
        expires_at=2000,
    )

    assert verify_record(record, pub, at_ms=CLOCK) is True
    assert record.body == {"recipient": "Bob.1042", "requester": "Alice.42"}


def test_signed_record_payload_is_independent_of_body_insertion_order():
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)
    body_a = {"recipient": "Bob.1042", "requester": "Alice.42"}
    body_b = {"requester": "Alice.42", "recipient": "Bob.1042"}
    record_a = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=7,
        body=body_a,
        signing_key=key,
        created_at=1000,
        expires_at=2000,
    )
    record_b = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=7,
        body=body_b,
        signing_key=key,
        created_at=1000,
        expires_at=2000,
    )

    assert canonical_json(body_a) == canonical_json(body_b)
    assert record_a.signing_payload() == record_b.signing_payload()


def test_signed_record_body_cannot_be_mutated_after_signing():
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)
    body = {"request_id": "req-1", "metadata": {"priority": "normal"}}
    record = sign_record(
        record_type="contact.accept",
        author_identity=pub,
        author_device_id=2,
        sequence=8,
        body=body,
        signing_key=key,
        created_at=1000,
    )
    payload = record.signing_payload()

    body["request_id"] = "req-2"
    body["metadata"]["priority"] = "urgent"
    with pytest.raises(TypeError):
        record.body["request_id"] = "req-3"
    with pytest.raises(TypeError):
        record.body["metadata"]["priority"] = "low"

    assert record.body == {"request_id": "req-1", "metadata": {"priority": "normal"}}
    assert record.signing_payload() == payload
    assert verify_record(record, pub, at_ms=CLOCK) is True


def test_signed_record_rejects_body_tamper():
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)
    record = sign_record(
        record_type="contact.accept",
        author_identity=pub,
        author_device_id=2,
        sequence=8,
        body={"request_id": "req-1"},
        signing_key=key,
        created_at=1000,
    )
    tampered = SignedRecord(
        record_type=record.record_type,
        version=record.version,
        author_identity=record.author_identity,
        author_device_id=record.author_device_id,
        sequence=record.sequence,
        created_at=record.created_at,
        expires_at=record.expires_at,
        body={"request_id": "req-2"},
        signature=record.signature,
    )

    assert verify_record(tampered, pub, at_ms=CLOCK) is False


def test_canonical_json_rejects_non_finite_floats():
    for value in (math.nan, math.inf, -math.inf):
        with pytest.raises(ValueError):
            canonical_json({"value": value})


def test_signed_record_rejects_non_finite_signed_payload_values():
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)

    with pytest.raises((TypeError, ValueError)):
        sign_record(
            record_type="contact.accept",
            author_identity=pub,
            author_device_id=2,
            sequence=8,
            body={"request_id": "req-1"},
            signing_key=key,
            created_at=math.nan,
        )

    with pytest.raises((TypeError, ValueError)):
        sign_record(
            record_type="contact.accept",
            author_identity=pub,
            author_device_id=2,
            sequence=8,
            body={"expires": "bad"},
            signing_key=key,
            created_at=1000,
            expires_at=math.inf,
        )


def test_signed_record_round_trips_through_dict_and_verifies():
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)
    record = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=7,
        body={"recipient": "Bob.1042", "tags": ["direct", "known"]},
        signing_key=key,
        created_at=1000,
        expires_at=2000,
    )

    restored = SignedRecord.from_dict(record.to_dict())

    assert restored == record
    assert restored.to_dict() == record.to_dict()
    assert verify_record(restored, pub, at_ms=CLOCK) is True


def test_signed_record_from_dict_rejects_malformed_hex_inputs():
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)
    record_dict = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=7,
        body={"recipient": "Bob.1042"},
        signing_key=key,
        created_at=1000,
        expires_at=2000,
    ).to_dict()

    for field in ("author_identity", "signature"):
        malformed = dict(record_dict)
        malformed[field] = "not-hex"
        with pytest.raises(ValueError):
            SignedRecord.from_dict(malformed)


def test_signed_record_from_dict_rejects_malleable_wire_format():
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)
    record_dict = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=7,
        body={"recipient": "Bob.1042"},
        signing_key=key,
        created_at=1000,
        expires_at=2000,
    ).to_dict()

    malformed_values = [
        ("type", 123),
        ("version", "1"),
        ("author_device_id", "1"),
        ("sequence", "7"),
        ("created_at", "1000.0"),
        ("expires_at", "2000.0"),
        ("body", [("recipient", "Bob.1042")]),
    ]
    for field, value in malformed_values:
        malformed = dict(record_dict)
        malformed[field] = value
        with pytest.raises(TypeError):
            SignedRecord.from_dict(malformed)

    missing = dict(record_dict)
    del missing["expires_at"]
    with pytest.raises(ValueError):
        SignedRecord.from_dict(missing)

    extra = dict(record_dict)
    extra["unexpected"] = True
    with pytest.raises(ValueError):
        SignedRecord.from_dict(extra)

    for value in (math.nan, math.inf, -math.inf, 1000.0, 2000.5):
        malformed = dict(record_dict)
        malformed["created_at"] = value
        with pytest.raises((TypeError, ValueError)):
            SignedRecord.from_dict(malformed)

        malformed = dict(record_dict)
        malformed["expires_at"] = value
        with pytest.raises((TypeError, ValueError)):
            SignedRecord.from_dict(malformed)


def test_contact_state_requires_recipient_accept_signature():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    accept = sign_record(
        record_type="contact.accept",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=bob_key,
        created_at=1001,
    )

    state = derive_contact_state([request, accept], {alice_pub, bob_pub}, at_ms=CLOCK)

    assert state["conv-1"] == "accepted"


def test_contact_state_rejects_accept_from_requester():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    forged_accept = sign_record(
        record_type="contact.accept",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=2,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1001,
    )

    state = derive_contact_state([request, forged_accept], {alice_pub, bob_pub}, at_ms=CLOCK)

    assert state["conv-1"] == "pending"


def test_contact_state_uses_request_conversation_id_for_accept():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    accept = sign_record(
        record_type="contact.accept",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-evil",
        },
        signing_key=bob_key,
        created_at=1001,
    )

    state = derive_contact_state([request, accept], {alice_pub, bob_pub}, at_ms=CLOCK)

    assert state["conv-1"] == "accepted"
    assert "conv-evil" not in state


def test_contact_state_ignores_malformed_request_without_crashing():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    malformed_request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "bad-req",
            "recipient_identity": "not-hex",
            "recipient_device_id": 1,
            "conversation_id": "conv-bad",
        },
        signing_key=alice_key,
        created_at=999,
    )
    valid_request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=2,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    accept_bad = sign_record(
        record_type="contact.accept",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "bad-req",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-bad",
        },
        signing_key=bob_key,
        created_at=1001,
    )
    accept_valid = sign_record(
        record_type="contact.accept",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=2,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=bob_key,
        created_at=1002,
    )

    state = derive_contact_state(
        [malformed_request, valid_request, accept_bad, accept_valid],
        {alice_pub, bob_pub},
    )

    assert state == {"conv-1": "accepted"}


def test_contact_state_ignores_malformed_contact_bodies_without_crashing():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    malformed_records = [
        sign_record(
            record_type="contact.request",
            author_identity=alice_pub,
            author_device_id=1,
            sequence=1,
            body={
                "recipient_identity": bob_pub.hex(),
                "recipient_device_id": 1,
                "conversation_id": "conv-missing-request-id",
            },
            signing_key=alice_key,
            created_at=900,
        ),
        sign_record(
            record_type="contact.request",
            author_identity=alice_pub,
            author_device_id=1,
            sequence=2,
            body={
                "request_id": "req-missing-conversation",
                "recipient_identity": bob_pub.hex(),
                "recipient_device_id": 1,
            },
            signing_key=alice_key,
            created_at=901,
        ),
        sign_record(
            record_type="contact.request",
            author_identity=alice_pub,
            author_device_id=1,
            sequence=3,
            body={
                "request_id": "req-bad-recipient-device",
                "recipient_identity": bob_pub.hex(),
                "recipient_device_id": "1",
                "conversation_id": "conv-bad-recipient-device",
            },
            signing_key=alice_key,
            created_at=902,
        ),
        sign_record(
            record_type="contact.accept",
            author_identity=bob_pub,
            author_device_id=1,
            sequence=1,
            body={
                "requester_identity": alice_pub.hex(),
                "requester_device_id": 1,
                "conversation_id": "conv-missing-request-id",
            },
            signing_key=bob_key,
            created_at=903,
        ),
        sign_record(
            record_type="contact.deny",
            author_identity=bob_pub,
            author_device_id=1,
            sequence=2,
            body={
                "request_id": "req-bad-requester",
                "requester_identity": "not-hex",
                "requester_device_id": 1,
                "conversation_id": "conv-bad-requester",
            },
            signing_key=bob_key,
            created_at=904,
        ),
        sign_record(
            record_type="contact.cancel",
            author_identity=alice_pub,
            author_device_id=1,
            sequence=4,
            body={
                "request_id": "req-missing-conversation",
            },
            signing_key=alice_key,
            created_at=905,
        ),
    ]

    state = derive_contact_state(malformed_records, {alice_pub, bob_pub}, at_ms=CLOCK)

    assert state == {}


def test_contact_state_duplicate_request_replay_does_not_reset_accepted_state():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    accept = sign_record(
        record_type="contact.accept",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=bob_key,
        created_at=1001,
    )
    duplicate_request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=2,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1002,
    )

    state = derive_contact_state(
        [request, accept, duplicate_request],
        {alice_pub, bob_pub},
    )

    assert state == {"conv-1": "accepted"}


def test_contact_state_deny_uses_request_conversation_id():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    deny = sign_record(
        record_type="contact.deny",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-evil",
        },
        signing_key=bob_key,
        created_at=1001,
    )

    state = derive_contact_state([request, deny], {alice_pub, bob_pub}, at_ms=CLOCK)

    assert state["conv-1"] == "denied"
    assert "conv-evil" not in state


def test_contact_state_cancel_uses_request_conversation_id():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    cancel = sign_record(
        record_type="contact.cancel",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=2,
        body={
            "request_id": "req-1",
            "conversation_id": "conv-evil",
        },
        signing_key=alice_key,
        created_at=1001,
    )

    state = derive_contact_state([request, cancel], {alice_pub, bob_pub}, at_ms=CLOCK)

    assert state["conv-1"] == "cancelled"
    assert "conv-evil" not in state


def test_contact_state_ignores_untrusted_and_invalid_signature_records():
    alice_key = xeddsa.generate_identity()
    bob_key = xeddsa.generate_identity()
    mallory_key = xeddsa.generate_identity()
    alice_pub = xeddsa.public_key(alice_key)
    bob_pub = xeddsa.public_key(bob_key)
    mallory_pub = xeddsa.public_key(mallory_key)
    valid_request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    untrusted_request = sign_record(
        record_type="contact.request",
        author_identity=mallory_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-evil",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-evil",
        },
        signing_key=mallory_key,
        created_at=1001,
    )
    invalid_accept = SignedRecord(
        record_type="contact.accept",
        version=1,
        author_identity=bob_pub,
        author_device_id=1,
        sequence=1,
        created_at=1002,
        expires_at=None,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-1",
        },
        signature=b"0" * 64,
    )

    state = derive_contact_state(
        [valid_request, untrusted_request, invalid_accept],
        {alice_pub, bob_pub},
    )

    assert state == {"conv-1": "pending"}


# --- Audit M7: freshness, replay and terminal states --------------------------


def _identity():
    key = xeddsa.generate_identity()
    return key, xeddsa.public_key(key)


def test_expired_record_does_not_verify():
    """expires_at is signed but was never checked against a clock (M7)."""

    key, pub = _identity()
    record = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=1,
        body={"request_id": "req-1"},
        signing_key=key,
        created_at=1000,
        expires_at=2000,
    )

    assert verify_record(record, pub, at_ms=1999) is True
    assert verify_record(record, pub, at_ms=2000) is False
    assert verify_record(record, pub, at_ms=10_000) is False


def test_far_future_record_does_not_verify():
    key, pub = _identity()
    record = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=1,
        body={"request_id": "req-1"},
        signing_key=key,
        created_at=10_000_000,
    )

    assert verify_record(record, pub, at_ms=1000) is False


def test_sign_record_rejects_expiry_before_creation():
    key, pub = _identity()

    with pytest.raises(ValueError, match="expires_at"):
        sign_record(
            record_type="contact.request",
            author_identity=pub,
            author_device_id=1,
            sequence=1,
            body={"request_id": "req-1"},
            signing_key=key,
            created_at=2000,
            expires_at=1000,
        )


def _request_and_accept(alice_key, alice_pub, bob_key, bob_pub, created_at=1000):
    request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=created_at,
    )
    accept = sign_record(
        record_type="contact.accept",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=bob_key,
        created_at=created_at + 1,
    )
    return request, accept


def test_terminal_contact_state_cannot_be_rolled_back_by_a_later_cancel():
    alice_key, alice_pub = _identity()
    bob_key, bob_pub = _identity()
    request, accept = _request_and_accept(alice_key, alice_pub, bob_key, bob_pub)
    cancel = sign_record(
        record_type="contact.cancel",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=2,
        body={"request_id": "req-1", "conversation_id": "conv-1"},
        signing_key=alice_key,
        created_at=1002,
    )

    state = derive_contact_state(
        [request, accept, cancel], {alice_pub, bob_pub}, at_ms=CLOCK
    )

    assert state["conv-1"] == "accepted"


def test_terminal_contact_state_cannot_be_flipped_by_a_later_deny():
    alice_key, alice_pub = _identity()
    bob_key, bob_pub = _identity()
    request, accept = _request_and_accept(alice_key, alice_pub, bob_key, bob_pub)
    deny = sign_record(
        record_type="contact.deny",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=2,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=bob_key,
        created_at=1005,
    )

    state = derive_contact_state(
        [request, accept, deny], {alice_pub, bob_pub}, at_ms=CLOCK
    )

    assert state["conv-1"] == "accepted"


def test_expired_accept_is_ignored_by_contact_state():
    alice_key, alice_pub = _identity()
    bob_key, bob_pub = _identity()
    request = sign_record(
        record_type="contact.request",
        author_identity=alice_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "recipient_identity": bob_pub.hex(),
            "recipient_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=alice_key,
        created_at=1000,
    )
    stale_accept = sign_record(
        record_type="contact.accept",
        author_identity=bob_pub,
        author_device_id=1,
        sequence=1,
        body={
            "request_id": "req-1",
            "requester_identity": alice_pub.hex(),
            "requester_device_id": 1,
            "conversation_id": "conv-1",
        },
        signing_key=bob_key,
        created_at=1001,
        expires_at=1100,
    )

    state = derive_contact_state(
        [request, stale_accept], {alice_pub, bob_pub}, at_ms=2000
    )

    assert state["conv-1"] == "pending"


# --- Audit M8: canonical encoding --------------------------------------------


def test_canonical_json_rejects_floats():
    """repr(float) is build-dependent -> two verifiers could split (M8)."""

    with pytest.raises(TypeError):
        canonical_json({"created_at": 1000.0})
    with pytest.raises(TypeError):
        canonical_json({"nested": [1, 2.5]})


def test_canonical_json_rejects_non_string_keys():
    with pytest.raises(TypeError):
        canonical_json({1: "one"})
    with pytest.raises(TypeError):
        canonical_json({"outer": {2: "two"}})


def test_canonical_json_is_injective_for_key_shapes():
    assert canonical_json({"1": "a"}) != canonical_json({"1 ": "a"})


def test_sign_record_rejects_float_timestamps():
    key, pub = _identity()

    with pytest.raises(TypeError):
        sign_record(
            record_type="contact.request",
            author_identity=pub,
            author_device_id=1,
            sequence=1,
            body={"request_id": "req-1"},
            signing_key=key,
            created_at=1000.0,
        )
    with pytest.raises(TypeError):
        sign_record(
            record_type="contact.request",
            author_identity=pub,
            author_device_id=1,
            sequence=1,
            body={"request_id": "req-1"},
            signing_key=key,
            created_at=1000,
            expires_at=2000.0,
        )


def test_sign_record_rejects_float_body_values():
    key, pub = _identity()

    with pytest.raises(TypeError):
        sign_record(
            record_type="contact.request",
            author_identity=pub,
            author_device_id=1,
            sequence=1,
            body={"weight": 1.5},
            signing_key=key,
            created_at=1000,
        )


def test_signing_payload_is_byte_stable_for_integer_timestamps():
    key, pub = _identity()
    record = sign_record(
        record_type="contact.request",
        author_identity=pub,
        author_device_id=1,
        sequence=1,
        body={"request_id": "req-1"},
        signing_key=key,
        created_at=1_700_000_000_123,
        expires_at=1_700_000_060_123,
    )

    assert b'"created_at":1700000000123' in record.signing_payload()
    assert b'"expires_at":1700000060123' in record.signing_payload()
    # no float repr anywhere in the timestamp encoding
    assert b'"created_at":1.7' not in record.signing_payload()
