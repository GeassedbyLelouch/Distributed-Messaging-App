from __future__ import annotations

import pytest

from ml_kem_braid.decentralized.services import DecentralizedServices, FederatedRelay


def test_federated_relay_forwards_opaque_envelope_to_remote_home() -> None:
    relay_a = FederatedRelay("relay-a", DecentralizedServices())
    relay_b = FederatedRelay("relay-b", DecentralizedServices())
    relay_a.add_peer(relay_b)

    relay_a.forward_to_relay(
        "relay-b",
        recipient_identity="b" * 64,
        recipient_device_id=1,
        envelope={"kind": "chat", "body": {"ciphertext": "opaque"}},
    )

    assert relay_b.services.fetch_mailbox("b" * 64, 1) == [
        {"kind": "chat", "body": {"ciphertext": "opaque"}}
    ]


def test_federated_relay_rejects_unknown_peer() -> None:
    relay = FederatedRelay("relay-a", DecentralizedServices())

    with pytest.raises(KeyError, match="unknown federated relay"):
        relay.forward_to_relay(
            "relay-b",
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope={"kind": "chat", "body": {"ciphertext": "opaque"}},
        )


@pytest.mark.parametrize("peer", [None, object()])
def test_federated_relay_rejects_invalid_peer_registration(peer: object) -> None:
    relay = FederatedRelay("relay-a", DecentralizedServices())

    with pytest.raises(TypeError, match="peer must be a FederatedRelay"):
        relay.add_peer(peer)


def test_federated_relay_rejects_relay_id_only_peer_registration() -> None:
    class RelayIdOnly:
        relay_id = "relay-b"

    relay = FederatedRelay("relay-a", DecentralizedServices())

    with pytest.raises(TypeError, match="peer must be a FederatedRelay"):
        relay.add_peer(RelayIdOnly())


def test_federated_relay_allows_self_peering() -> None:
    relay = FederatedRelay("relay-a", DecentralizedServices())
    relay.add_peer(relay)

    relay.forward_to_relay(
        "relay-a",
        recipient_identity="a" * 64,
        recipient_device_id=1,
        envelope={"kind": "chat", "body": {"ciphertext": "opaque"}},
    )

    assert relay.services.fetch_mailbox("a" * 64, 1) == [
        {"kind": "chat", "body": {"ciphertext": "opaque"}}
    ]


def test_federated_relay_propagates_invalid_envelope_type() -> None:
    relay_a = FederatedRelay("relay-a", DecentralizedServices())
    relay_b = FederatedRelay("relay-b", DecentralizedServices())
    relay_a.add_peer(relay_b)

    with pytest.raises(TypeError, match="envelope must be a dict"):
        relay_a.forward_to_relay("relay-b", "b" * 64, 1, "not an envelope")


def test_forwarded_envelope_is_isolated_from_caller_mutation() -> None:
    relay_a = FederatedRelay("relay-a", DecentralizedServices())
    relay_b = FederatedRelay("relay-b", DecentralizedServices())
    relay_a.add_peer(relay_b)
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}

    relay_a.forward_to_relay("relay-b", "b" * 64, 1, envelope)
    envelope["body"]["ciphertext"] = "tampered"

    assert relay_b.services.fetch_mailbox("b" * 64, 1) == [
        {"kind": "chat", "body": {"ciphertext": "opaque"}}
    ]


def test_duplicate_peer_registration_replaces_existing_peer() -> None:
    relay_a = FederatedRelay("relay-a", DecentralizedServices())
    old_peer = FederatedRelay("relay-b", DecentralizedServices())
    replacement_peer = FederatedRelay("relay-b", DecentralizedServices())

    relay_a.add_peer(old_peer)
    relay_a.add_peer(replacement_peer)
    relay_a.forward_to_relay(
        "relay-b",
        recipient_identity="b" * 64,
        recipient_device_id=1,
        envelope={"kind": "chat", "body": {"ciphertext": "opaque"}},
    )

    assert old_peer.services.fetch_mailbox("b" * 64, 1) == []
    assert replacement_peer.services.fetch_mailbox("b" * 64, 1) == [
        {"kind": "chat", "body": {"ciphertext": "opaque"}}
    ]
