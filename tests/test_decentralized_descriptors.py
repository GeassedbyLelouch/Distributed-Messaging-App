from ml_kem_braid.decentralized.descriptors import (
    ContactEventBody,
    RelayDescriptorBody,
    UsernameRecordBody,
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
