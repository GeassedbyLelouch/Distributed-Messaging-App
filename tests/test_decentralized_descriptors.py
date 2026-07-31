import pytest

from ml_kem_braid.decentralized.descriptors import (
    MIN_CIRCUIT_HOPS,
    ContactEventBody,
    RelayDescriptorBody,
    UsernameRecordBody,
    enforce_min_circuit_hops,
)


def test_username_record_body_preserves_exact_lookup_only():
    body = UsernameRecordBody(
        username_hash="a" * 64,
        username_display_commitment="b" * 64,
        identity_sign_pub="c" * 64,
        primary_home_relay="relay-main",
        relay_descriptor_hash="d" * 64,
    )

    assert body.to_record_body() == {
        "username_hash": "a" * 64,
        "username_display_commitment": "b" * 64,
        "identity_sign_pub": "c" * 64,
        "primary_home_relay": "relay-main",
        "relay_descriptor_hash": "d" * 64,
    }


def test_relay_descriptor_declares_anonymity_policy():
    body = RelayDescriptorBody(
        relay_id="relay-main",
        signing_key="a" * 64,
        onion_key="b" * 64,
        endpoints=["https://relay.example"],
        supports_home=True,
        supports_transit=True,
        supports_rendezvous=True,
        min_circuit_hops=3,
    )

    assert body.to_record_body() == {
        "relay_id": "relay-main",
        "signing_key": "a" * 64,
        "onion_key": "b" * 64,
        "endpoints": ["https://relay.example"],
        "supports_home": True,
        "supports_transit": True,
        "supports_rendezvous": True,
        "min_circuit_hops": 3,
    }


def test_relay_descriptor_copies_original_endpoints():
    endpoints = ["https://relay.example"]
    body = RelayDescriptorBody(
        relay_id="relay-main",
        signing_key="a" * 64,
        onion_key="b" * 64,
        endpoints=endpoints,
        supports_home=True,
        supports_transit=True,
        supports_rendezvous=True,
        min_circuit_hops=3,
    )

    endpoints.append("https://relay-other.example")

    assert body.to_record_body()["endpoints"] == ["https://relay.example"]


def test_relay_descriptor_returns_fresh_endpoint_list():
    body = RelayDescriptorBody(
        relay_id="relay-main",
        signing_key="a" * 64,
        onion_key="b" * 64,
        endpoints=["https://relay.example"],
        supports_home=True,
        supports_transit=True,
        supports_rendezvous=True,
        min_circuit_hops=3,
    )

    record_body = body.to_record_body()
    record_body["endpoints"].append("https://relay-other.example")

    assert body.to_record_body()["endpoints"] == ["https://relay.example"]


def test_contact_accept_body_references_request_id_and_peer_identity():
    body = ContactEventBody(
        event_kind="contact.accept",
        request_id="req-1",
        peer_identity="f" * 64,
        peer_device_id=1,
        conversation_id="conv-1",
    )

    assert body.to_record_body()["event_kind"] == "contact.accept"
    assert body.to_record_body()["request_id"] == "req-1"
    assert body.to_record_body()["peer_identity"] == "f" * 64
    assert body.to_record_body()["peer_device_id"] == 1
    assert body.to_record_body()["conversation_id"] == "conv-1"
    assert body.to_record_body()["note_ciphertext"] is None


# --- Audit L13: self-asserted relay policy ------------------------------------


def _descriptor(**overrides):
    fields = {
        "relay_id": "relay-main",
        "signing_key": "a" * 64,
        "onion_key": "b" * 64,
        "endpoints": ["https://relay.example"],
        "supports_home": True,
        "supports_transit": True,
        "supports_rendezvous": True,
        "min_circuit_hops": 3,
    }
    fields.update(overrides)
    return RelayDescriptorBody(**fields)


def test_client_floor_overrides_a_relay_advertising_fewer_hops():
    """A relay must not be able to talk a client down to one hop."""

    descriptor = _descriptor(min_circuit_hops=1)

    assert descriptor.min_circuit_hops == 1
    assert descriptor.effective_min_circuit_hops() == MIN_CIRCUIT_HOPS
    assert enforce_min_circuit_hops(1) == MIN_CIRCUIT_HOPS
    assert enforce_min_circuit_hops(2) == MIN_CIRCUIT_HOPS


def test_client_floor_respects_a_relay_asking_for_more_hops():
    assert _descriptor(min_circuit_hops=5).effective_min_circuit_hops() == 5


def test_absurd_hop_counts_are_rejected():
    with pytest.raises(ValueError, match="out of range"):
        _descriptor(min_circuit_hops=0)
    with pytest.raises(ValueError, match="out of range"):
        _descriptor(min_circuit_hops=99)
    with pytest.raises(TypeError):
        _descriptor(min_circuit_hops=True)


@pytest.mark.parametrize(
    "endpoints",
    [
        [],
        ["http://relay.example"],
        ["ftp://relay.example"],
        ["not-a-url"],
        ["https://"],
    ],
)
def test_malformed_endpoints_are_rejected(endpoints):
    with pytest.raises(ValueError):
        _descriptor(endpoints=endpoints)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("signing_key", "a" * 63),
        ("signing_key", "A" * 64),
        ("onion_key", "zz" * 32),
        ("relay_id", ""),
    ],
)
def test_malformed_key_encodings_are_rejected(field, value):
    with pytest.raises(ValueError):
        _descriptor(**{field: value})


def test_username_record_body_rejects_malformed_hex_fields():
    with pytest.raises(ValueError):
        UsernameRecordBody(
            username_hash="a" * 63,
            username_display_commitment="b" * 64,
            identity_sign_pub="c" * 64,
            primary_home_relay="relay-main",
            relay_descriptor_hash="d" * 64,
        )


def test_contact_event_body_rejects_malformed_peer_identity():
    with pytest.raises(ValueError):
        ContactEventBody(
            event_kind="contact.accept",
            request_id="req-1",
            peer_identity="not-hex",
            peer_device_id=1,
            conversation_id="conv-1",
        )
