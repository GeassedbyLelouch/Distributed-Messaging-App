from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from ml_kem_braid.crypto import xeddsa
from ml_kem_braid.decentralized.records import SignedRecord, sign_record
from ml_kem_braid.decentralized.services import (
    DecentralizedServices,
    sign_envelope,
    username_binding,
    username_hash,
)
from ml_kem_braid.server.app import create_app


# Audit M9: a username claim must open its hash to a preimage and bind that
# preimage to the claiming identity, so tests build real claims.
# Verifier D18: the opening rides along UNSIGNED and unpublished — it must
# never appear in the signed body, which is served verbatim to anonymous
# lookups.
def _username_body(username: str, public_key: bytes) -> dict[str, object]:
    return {
        "username_hash": username_hash(username),
        "identity_sign_pub": public_key.hex(),
        "username_binding": username_binding(username, public_key),
    }


def _authenticated_delivery(
    services: DecentralizedServices,
    recipient_identity: str,
    recipient_device_id: int,
    envelope: dict,
) -> None:
    key, public_key = _signing_keys()
    services.deliver_envelope(
        recipient_identity=recipient_identity,
        recipient_device_id=recipient_device_id,
        envelope=envelope,
        sender_identity=public_key,
        sender_signature=sign_envelope(
            key, recipient_identity, recipient_device_id, envelope
        ),
    )


def _signing_keys() -> tuple[bytes, bytes]:
    """Return (private_key_bytes, public_key_bytes) using XEdDSA (Curve25519)."""
    priv = xeddsa.generate_identity()
    pub = xeddsa.public_key(priv)
    return priv, pub


def _signed_record(
    *,
    record_type: str = "identity.username_record",
    body: dict[str, object] | None = None,
    sequence: int = 1,
) -> SignedRecord:
    key, public_key = _signing_keys()
    return sign_record(
        record_type=record_type,
        author_identity=public_key,
        author_device_id=1,
        sequence=sequence,
        body=body
        or {
            "username_hash": "a" * 64,
            "identity_sign_pub": public_key.hex(),
        },
        signing_key=key,
        created_at=1,
    )


def _username_record(username: str = "alice") -> SignedRecord:
    key, public_key = _signing_keys()
    return sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body=_username_body(username, public_key),
        signing_key=key,
        created_at=1,
        username_preimage=username,
    )


def _username_record_with_body(body: dict[str, object]) -> SignedRecord:
    key, public_key = _signing_keys()
    return sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body=body,
        signing_key=key,
        created_at=1,
    )


def _enabled_client() -> TestClient:
    return TestClient(create_app(enable_decentralized=True))


def _publish_record(client: TestClient, record: SignedRecord):
    # The publish direction carries the unsigned opening; the lookup direction
    # (``to_dict``) never can (verifier D18).
    return client.post("/v1/records", json=record.to_publish_dict())


def _lookup_username_record(client: TestClient, username_hash: str):
    return client.get(f"/v1/records/identity.username_record/{username_hash}")


def test_registry_stores_only_verified_username_record() -> None:
    record = _username_record("alice")
    services = DecentralizedServices()

    services.publish_record(record)

    assert services.lookup_username(username_hash("alice")) == record


def test_registry_rejects_duplicate_username_hash_without_replacing_first() -> None:
    services = DecentralizedServices()
    first = _username_record("alice")
    second = _username_record("alice")

    services.publish_record(first)

    with pytest.raises(ValueError, match="username hash already registered"):
        services.publish_record(second)

    assert services.lookup_username(username_hash("alice")) == first


def test_registry_rejects_invalid_signature() -> None:
    record = _username_record()
    invalid_record = SignedRecord(
        record_type=record.record_type,
        version=record.version,
        author_identity=record.author_identity,
        author_device_id=record.author_device_id,
        sequence=record.sequence,
        created_at=record.created_at,
        expires_at=record.expires_at,
        body={**record.body, "username_hash": "c" * 64},
        signature=record.signature,
    )
    services = DecentralizedServices()

    with pytest.raises(PermissionError):
        services.publish_record(invalid_record)

    assert services.lookup_username("c" * 64) is None


@pytest.mark.parametrize(
    "body",
    [
        {"identity_sign_pub": "00" * 32},
        {"username_hash": 1, "identity_sign_pub": "00" * 32},
        {"username_hash": "a" * 63, "identity_sign_pub": "00" * 32},
        {"username_hash": "g" * 64, "identity_sign_pub": "00" * 32},
        {"username_hash": "A" * 64, "identity_sign_pub": "00" * 32},
    ],
)
def test_registry_rejects_malformed_signed_username_hash(body: dict[str, object]) -> None:
    record = _username_record_with_body(body)
    services = DecentralizedServices()

    with pytest.raises(ValueError):
        services.publish_record(record)


def test_registry_rejects_username_record_with_mismatched_identity_sign_pub() -> None:
    key, public_key = _signing_keys()
    record = sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body={
            "username_hash": "a" * 64,
            "identity_sign_pub": "00" * 32,
        },
        signing_key=key,
        created_at=1,
    )
    services = DecentralizedServices()

    with pytest.raises(ValueError):
        services.publish_record(record)


def test_mailbox_stores_opaque_envelope_without_plaintext_inspection() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}

    _authenticated_delivery(services, "b" * 64, 1, envelope)

    assert (
        services.fetch_mailbox(
            recipient_identity="b" * 64,
            recipient_device_id=1,
        )
        == [envelope]
    )


def test_fetch_envelopes_drains_by_default() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}
    _authenticated_delivery(services, "b" * 64, 1, envelope)

    assert services.fetch_mailbox("b" * 64, 1) == [envelope]
    assert services.fetch_mailbox("b" * 64, 1) == []


def test_fetch_envelopes_without_drain_returns_defensive_copies() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}
    _authenticated_delivery(services, "b" * 64, 1, envelope)

    fetched = services.fetch_mailbox("b" * 64, 1, drain=False)
    fetched[0]["body"]["ciphertext"] = "tampered"

    assert services.fetch_mailbox("b" * 64, 1, drain=False) == [envelope]


def test_fetch_missing_mailbox_returns_empty_without_creating_mailbox() -> None:
    services = DecentralizedServices()

    assert services.fetch_mailbox("b" * 64, 1) == []
    assert services._mailboxes == {}


def test_fetch_missing_mailbox_without_drain_returns_empty_without_creating_mailbox() -> None:
    services = DecentralizedServices()

    assert services.fetch_mailbox("b" * 64, 1, drain=False) == []
    assert services._mailboxes == {}


def test_mutating_original_envelope_after_delivery_does_not_change_queue() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}

    _authenticated_delivery(services, "b" * 64, 1, envelope)
    envelope["body"]["ciphertext"] = "tampered"

    assert services.fetch_mailbox("b" * 64, 1, drain=False) == [
        {"kind": "chat", "body": {"ciphertext": "opaque"}}
    ]


def test_mutating_drained_returned_envelope_does_not_repopulate_mailbox() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}
    _authenticated_delivery(services, "b" * 64, 1, envelope)

    fetched = services.fetch_mailbox("b" * 64, 1)
    fetched[0]["body"]["ciphertext"] = "tampered"

    assert services.fetch_mailbox("b" * 64, 1) == []


def test_decentralized_router_can_publish_and_lookup_record():
    client = _enabled_client()
    key = xeddsa.generate_identity()
    pub = xeddsa.public_key(key)
    record = sign_record(
        record_type="identity.username_record",
        author_identity=pub,
        author_device_id=1,
        sequence=1,
        body=_username_body("carol", pub),
        signing_key=key,
        created_at=1000,
        username_preimage="carol",
    )
    publish = client.post("/v1/records", json=record.to_publish_dict())
    lookup = client.get("/v1/records/identity.username_record/" + username_hash("carol"))
    assert publish.status_code == 200
    assert lookup.status_code == 200
    assert lookup.json()["body"]["username_hash"] == username_hash("carol")


def test_decentralized_routes_are_disabled_by_default() -> None:
    app = create_app()
    client = TestClient(app)

    response = _lookup_username_record(client, "a" * 64)

    assert response.status_code == 404
    assert not hasattr(app.state, "decentralized_services")


def test_decentralized_publish_rejects_non_object_json() -> None:
    client = _enabled_client()

    response = client.post("/v1/records", json=[])

    assert response.status_code == 400


def test_decentralized_publish_rejects_malformed_signed_record_dict() -> None:
    client = _enabled_client()

    response = client.post("/v1/records", json={})

    assert response.status_code == 400


def test_decentralized_publish_rejects_invalid_signature() -> None:
    client = _enabled_client()
    record = _username_record("alice")
    invalid_record = SignedRecord(
        record_type=record.record_type,
        version=record.version,
        author_identity=record.author_identity,
        author_device_id=record.author_device_id,
        sequence=record.sequence,
        created_at=record.created_at,
        expires_at=record.expires_at,
        body={**record.body, "username_hash": "b" * 64},
        signature=record.signature,
    )

    response = _publish_record(client, invalid_record)

    assert response.status_code == 403


def test_decentralized_publish_rejects_malformed_signed_username_body() -> None:
    client = _enabled_client()
    record = _username_record_with_body(
        {"username_hash": "g" * 64, "identity_sign_pub": "00" * 32}
    )

    response = _publish_record(client, record)

    assert response.status_code == 422


def test_decentralized_publish_rejects_duplicate_username_hash() -> None:
    client = _enabled_client()
    first = _username_record("alice")
    second = _username_record("alice")

    first_response = _publish_record(client, first)
    second_response = _publish_record(client, second)

    assert first_response.status_code == 200
    assert second_response.status_code == 409


def test_decentralized_enabled_apps_have_isolated_registries() -> None:
    first_client = _enabled_client()
    second_client = _enabled_client()
    record = _username_record("dave")

    publish = _publish_record(first_client, record)
    second_lookup = _lookup_username_record(second_client, username_hash("dave"))

    assert publish.status_code == 200
    assert second_lookup.status_code == 404


def test_decentralized_username_hash_lookup_does_not_normalize_case() -> None:
    client = _enabled_client()
    record = _username_record("erin")

    publish = _publish_record(client, record)
    uppercase_lookup = _lookup_username_record(
        client, username_hash("erin").upper()
    )

    assert publish.status_code == 200
    assert uppercase_lookup.status_code == 404


# --- Audit M7: record freshness and sequence monotonicity ---------------------


def _record(record_type: str, sequence: int, key, public_key, **kwargs) -> SignedRecord:
    return sign_record(
        record_type=record_type,
        author_identity=public_key,
        author_device_id=1,
        sequence=sequence,
        body=kwargs.pop("body", {"note": "n"}),
        signing_key=key,
        created_at=kwargs.pop("created_at", 1000),
        **kwargs,
    )


def test_publish_rejects_expired_record() -> None:
    services = DecentralizedServices(clock=lambda: 5000)
    key, public_key = _signing_keys()
    record = _record("contact.note", 1, key, public_key, expires_at=2000)

    with pytest.raises(PermissionError):
        services.publish_record(record)


def test_publish_rejects_sequence_replay_and_rollback() -> None:
    services = DecentralizedServices(clock=lambda: 1500)
    key, public_key = _signing_keys()
    services.publish_record(_record("contact.note", 5, key, public_key))

    with pytest.raises(ValueError, match="strictly increasing"):
        services.publish_record(_record("contact.note", 5, key, public_key))
    with pytest.raises(ValueError, match="strictly increasing"):
        services.publish_record(_record("contact.note", 4, key, public_key))

    services.publish_record(_record("contact.note", 6, key, public_key))


def test_sequence_monotonicity_is_scoped_per_type_and_author() -> None:
    services = DecentralizedServices(clock=lambda: 1500)
    key_a, pub_a = _signing_keys()
    key_b, pub_b = _signing_keys()
    services.publish_record(_record("contact.note", 5, key_a, pub_a))

    services.publish_record(_record("contact.note", 1, key_b, pub_b))
    services.publish_record(_record("contact.other", 1, key_a, pub_a))


# --- Audit M9: username claims must open a preimage ---------------------------


def test_username_claim_without_a_preimage_proof_is_rejected() -> None:
    """Squatting an arbitrary 64-hex string is no longer a claim."""

    services = DecentralizedServices(clock=lambda: 1500)
    key, public_key = _signing_keys()
    squat = sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body={"username_hash": "a" * 64, "identity_sign_pub": public_key.hex()},
        signing_key=key,
        created_at=1000,
    )

    with pytest.raises(ValueError, match="preimage"):
        services.publish_record(squat)

    assert services.lookup_username("a" * 64) is None


def test_username_claim_with_a_preimage_for_a_different_hash_is_rejected() -> None:
    services = DecentralizedServices(clock=lambda: 1500)
    key, public_key = _signing_keys()
    record = sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body={
            "username_hash": username_hash("alice"),
            "identity_sign_pub": public_key.hex(),
            "username_binding": username_binding("bob", public_key),
        },
        signing_key=key,
        created_at=1000,
        username_preimage="bob",
    )

    with pytest.raises(ValueError, match="does not open"):
        services.publish_record(record)


def test_username_binding_must_bind_the_preimage_to_the_author() -> None:
    services = DecentralizedServices(clock=lambda: 1500)
    key, public_key = _signing_keys()
    _, other_public_key = _signing_keys()
    record = sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body={
            "username_hash": username_hash("alice"),
            "identity_sign_pub": public_key.hex(),
            "username_binding": username_binding("alice", other_public_key),
        },
        signing_key=key,
        created_at=1000,
        username_preimage="alice",
    )

    with pytest.raises(ValueError, match="username_binding"):
        services.publish_record(record)


def test_username_preimage_may_be_supplied_out_of_band() -> None:
    services = DecentralizedServices(clock=lambda: 1500)
    key, public_key = _signing_keys()
    record = sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body={
            "username_hash": username_hash("alice"),
            "identity_sign_pub": public_key.hex(),
            "username_binding": username_binding("alice", public_key),
        },
        signing_key=key,
        created_at=1000,
    )

    services.publish_record(record, username_preimage="alice")

    assert services.lookup_username(username_hash("alice")) == record


def test_username_record_is_owner_updatable_with_monotonic_sequence() -> None:
    services = DecentralizedServices(clock=lambda: 1500)
    key, public_key = _signing_keys()
    first = sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body=_username_body("alice", public_key),
        signing_key=key,
        created_at=1000,
        username_preimage="alice",
    )
    second = sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=2,
        body={**_username_body("alice", public_key), "primary_home_relay": "relay-2"},
        signing_key=key,
        created_at=1100,
        username_preimage="alice",
    )
    services.publish_record(first)
    services.publish_record(second)

    assert services.lookup_username(username_hash("alice")) == second


def test_expired_username_claim_is_reclaimable_so_squatting_is_reversible() -> None:
    clock = {"now": 1500}
    services = DecentralizedServices(clock=lambda: clock["now"])
    squatter_key, squatter_pub = _signing_keys()
    owner_key, owner_pub = _signing_keys()
    squat = sign_record(
        record_type="identity.username_record",
        author_identity=squatter_pub,
        author_device_id=1,
        sequence=1,
        body=_username_body("alice", squatter_pub),
        signing_key=squatter_key,
        created_at=1000,
        expires_at=2000,
        username_preimage="alice",
    )
    services.publish_record(squat)

    # While the squat is live nobody else can take the name...
    contender = sign_record(
        record_type="identity.username_record",
        author_identity=owner_pub,
        author_device_id=1,
        sequence=1,
        body=_username_body("alice", owner_pub),
        signing_key=owner_key,
        created_at=1400,
        username_preimage="alice",
    )
    with pytest.raises(ValueError, match="already registered"):
        services.publish_record(contender)

    # ...but the claim expires and the name becomes claimable again.
    clock["now"] = 3000
    assert services.lookup_username(username_hash("alice")) is None
    reclaim = sign_record(
        record_type="identity.username_record",
        author_identity=owner_pub,
        author_device_id=1,
        sequence=1,
        body=_username_body("alice", owner_pub),
        signing_key=owner_key,
        created_at=2900,
        username_preimage="alice",
    )
    services.publish_record(reclaim)

    assert services.lookup_username(username_hash("alice")) == reclaim


# --- Audit L12: mailbox delivery is authenticated and bounded -----------------


def test_unauthenticated_delivery_is_rejected() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat"}
    _, public_key = _signing_keys()

    with pytest.raises(PermissionError):
        services.deliver_envelope(
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope=envelope,
            sender_identity=public_key,
            sender_signature=b"\x00" * 64,
        )

    assert services.fetch_mailbox("b" * 64, 1) == []


def test_rejected_delivery_allocates_no_mailbox_state() -> None:
    """A refused envelope must not pin memory keyed on the recipient string."""

    services = DecentralizedServices()
    _, public_key = _signing_keys()

    for index in range(64):
        with pytest.raises(PermissionError):
            services.deliver_envelope(
                recipient_identity=f"{index:064x}",
                recipient_device_id=1,
                envelope={"kind": "chat"},
                sender_identity=public_key,
                sender_signature=b"\x00" * 64,
            )

    assert services._mailboxes == {}


def test_delivery_signature_is_bound_to_recipient_and_envelope() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat"}
    key, public_key = _signing_keys()
    signature = sign_envelope(key, "b" * 64, 1, envelope)

    with pytest.raises(PermissionError):
        services.deliver_envelope(
            recipient_identity="c" * 64,
            recipient_device_id=1,
            envelope=envelope,
            sender_identity=public_key,
            sender_signature=signature,
        )
    with pytest.raises(PermissionError):
        services.deliver_envelope(
            recipient_identity="b" * 64,
            recipient_device_id=2,
            envelope=envelope,
            sender_identity=public_key,
            sender_signature=signature,
        )
    with pytest.raises(PermissionError):
        services.deliver_envelope(
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope={"kind": "spam"},
            sender_identity=public_key,
            sender_signature=signature,
        )


def test_mailbox_allowlist_blocks_unauthorised_senders() -> None:
    services = DecentralizedServices()
    allowed_key, allowed_pub = _signing_keys()
    blocked_key, blocked_pub = _signing_keys()
    services.set_mailbox_allowlist("b" * 64, 1, {allowed_pub})
    envelope = {"kind": "chat"}

    with pytest.raises(PermissionError, match="not authorised"):
        services.deliver_envelope(
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope=envelope,
            sender_identity=blocked_pub,
            sender_signature=sign_envelope(blocked_key, "b" * 64, 1, envelope),
        )

    services.deliver_envelope(
        recipient_identity="b" * 64,
        recipient_device_id=1,
        envelope=envelope,
        sender_identity=allowed_pub,
        sender_signature=sign_envelope(allowed_key, "b" * 64, 1, envelope),
    )
    assert services.fetch_mailbox("b" * 64, 1) == [envelope]


def test_mailbox_depth_is_capped() -> None:
    services = DecentralizedServices(max_mailbox_depth=3)
    key, public_key = _signing_keys()

    for index in range(3):
        envelope = {"n": index}
        services.deliver_envelope(
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope=envelope,
            sender_identity=public_key,
            sender_signature=sign_envelope(key, "b" * 64, 1, envelope),
        )

    overflow = {"n": 3}
    with pytest.raises(ValueError, match="mailbox is full"):
        services.deliver_envelope(
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope=overflow,
            sender_identity=public_key,
            sender_signature=sign_envelope(key, "b" * 64, 1, overflow),
        )

    assert len(services.fetch_mailbox("b" * 64, 1)) == 3


# --- Verifier D15: the depth cap must not fail closed against the victim ------


def _deliver(services: DecentralizedServices, key, public_key, envelope) -> None:
    services.deliver_envelope(
        recipient_identity="b" * 64,
        recipient_device_id=1,
        envelope=envelope,
        sender_identity=public_key,
        sender_signature=sign_envelope(key, "b" * 64, 1, envelope),
    )


def test_a_flooder_cannot_jam_delivery_for_an_honest_sender() -> None:
    """A shared depth cap turned spam into a reliable DoS on the recipient.

    The flooder mints its own identity, fills the mailbox, and every honest
    sender is then permanently rejected with "mailbox is full". Capacity must
    be per sender.
    """

    services = DecentralizedServices(
        max_mailbox_depth=16, max_envelopes_per_sender=4
    )
    flood_key, flood_pub = _signing_keys()
    honest_key, honest_pub = _signing_keys()

    # Flood far past the mailbox depth from one identity.
    accepted = 0
    for index in range(200):
        try:
            _deliver(services, flood_key, flood_pub, {"spam": index})
        except ValueError:
            continue
        accepted += 1
    assert accepted == 4, "one sender must never exceed its own quota"

    # The honest sender still gets through, repeatedly.
    for index in range(4):
        _deliver(services, honest_key, honest_pub, {"real": index})

    delivered = services.fetch_mailbox("b" * 64, 1)
    assert [envelope for envelope in delivered if "real" in envelope] == [
        {"real": 0},
        {"real": 1},
        {"real": 2},
        {"real": 3},
    ]


def test_many_flooding_identities_cannot_squeeze_out_an_honest_sender() -> None:
    """Even with a fresh identity per message, the victim stays reachable."""

    services = DecentralizedServices(
        max_mailbox_depth=8, max_envelopes_per_sender=4
    )
    for index in range(64):
        spam_key, spam_pub = _signing_keys()
        _deliver(services, spam_key, spam_pub, {"spam": index})

    honest_key, honest_pub = _signing_keys()
    _deliver(services, honest_key, honest_pub, {"real": True})

    assert {"real": True} in services.fetch_mailbox("b" * 64, 1)


def test_eviction_never_takes_a_slot_from_a_quieter_sender() -> None:
    services = DecentralizedServices(
        max_mailbox_depth=4, max_envelopes_per_sender=4
    )
    loud_key, loud_pub = _signing_keys()
    quiet_key, quiet_pub = _signing_keys()

    _deliver(services, quiet_key, quiet_pub, {"quiet": 0})
    for index in range(3):
        _deliver(services, loud_key, loud_pub, {"loud": index})

    # Mailbox is full; a third sender displaces the loud sender, not the quiet.
    third_key, third_pub = _signing_keys()
    _deliver(services, third_key, third_pub, {"third": 0})

    delivered = services.fetch_mailbox("b" * 64, 1)
    assert {"quiet": 0} in delivered
    assert {"third": 0} in delivered
    assert len([e for e in delivered if "loud" in e]) == 2


def test_relay_forwarding_is_rate_limited() -> None:
    from ml_kem_braid.decentralized.services import FederatedRelay

    relay_a = FederatedRelay(
        "relay-a",
        DecentralizedServices(),
        clock=lambda: 0,
        max_forwards_per_window=2,
    )
    relay_b = FederatedRelay("relay-b", DecentralizedServices())
    relay_a.add_peer(relay_b)
    key, public_key = _signing_keys()

    def forward(index: int) -> None:
        envelope = {"n": index}
        relay_a.forward_to_relay(
            "relay-b",
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope=envelope,
            sender_identity=public_key,
            sender_signature=sign_envelope(key, "b" * 64, 1, envelope),
        )

    forward(0)
    forward(1)
    with pytest.raises(PermissionError, match="rate limit"):
        forward(2)


# --- Verifier D14: quota is charged to a VERIFIED identity, and bounded -------


def test_forward_quota_table_is_not_grown_by_unverified_senders() -> None:
    """An unsigned forward must cost the relay nothing but a signature check."""

    from ml_kem_braid.decentralized.services import FederatedRelay

    relay_a = FederatedRelay(
        "relay-a",
        DecentralizedServices(),
        clock=lambda: 0,
        max_forwards_per_window=2,
        max_tracked_senders=4,
    )
    relay_a.add_peer(FederatedRelay("relay-b", DecentralizedServices()))

    envelope = {"n": 0}
    for index in range(500):
        # A fresh attacker-chosen "identity" per message, no valid signature.
        with pytest.raises(PermissionError, match="authentication failed"):
            relay_a.forward_to_relay(
                "relay-b",
                recipient_identity="b" * 64,
                recipient_device_id=1,
                envelope=envelope,
                sender_identity=index.to_bytes(32, "big"),
                sender_signature=b"\x00" * 64,
            )

    assert relay_a._forward_counters == {}

    # And a genuine sender is still served afterwards.
    key, public_key = _signing_keys()
    relay_a.forward_to_relay(
        "relay-b",
        recipient_identity="b" * 64,
        recipient_device_id=1,
        envelope=envelope,
        sender_identity=public_key,
        sender_signature=sign_envelope(key, "b" * 64, 1, envelope),
    )


def test_forward_quota_table_is_bounded_and_fails_closed() -> None:
    from ml_kem_braid.decentralized.services import FederatedRelay

    relay_a = FederatedRelay(
        "relay-a",
        DecentralizedServices(),
        clock=lambda: 0,
        max_forwards_per_window=2,
        max_tracked_senders=3,
    )
    relay_a.add_peer(FederatedRelay("relay-b", DecentralizedServices()))

    def forward(key: bytes, public_key: bytes, index: int) -> None:
        envelope = {"n": index}
        relay_a.forward_to_relay(
            "relay-b",
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope=envelope,
            sender_identity=public_key,
            sender_signature=sign_envelope(key, "b" * 64, 1, envelope),
        )

    tracked = [_signing_keys() for _ in range(3)]
    for index, (key, public_key) in enumerate(tracked):
        forward(key, public_key, index)
    assert len(relay_a._forward_counters) == 3

    # A fourth verified identity cannot displace an existing counter: the
    # relay refuses the forward instead of forgetting somebody's quota.
    overflow_key, overflow_pub = _signing_keys()
    with pytest.raises(PermissionError, match="quota table is full"):
        forward(overflow_key, overflow_pub, 3)

    # Every previously tracked sender still has its counter enforced.
    for index, (key, public_key) in enumerate(tracked):
        forward(key, public_key, 100 + index)
        with pytest.raises(PermissionError, match="rate limit"):
            forward(key, public_key, 200 + index)


def test_relay_rejects_unsigned_forward_before_touching_the_peer() -> None:
    from ml_kem_braid.decentralized.services import FederatedRelay

    peer_services = DecentralizedServices()
    relay_a = FederatedRelay("relay-a", DecentralizedServices(), clock=lambda: 0)
    relay_a.add_peer(FederatedRelay("relay-b", peer_services))
    _, public_key = _signing_keys()

    with pytest.raises(PermissionError):
        relay_a.forward_to_relay(
            "relay-b",
            recipient_identity="b" * 64,
            recipient_device_id=1,
            envelope={"n": 0},
            sender_identity=public_key,
            sender_signature=b"\x00" * 64,
        )

    assert peer_services.fetch_mailbox("b" * 64, 1) == []


# --- Verifier D18: the preimage must never be republished ---------------------


def test_published_username_record_never_carries_the_plaintext_username() -> None:
    """The hashed-username model dies the moment a lookup returns the name."""

    services = DecentralizedServices(clock=lambda: 1500)
    record = _username_record("alice")

    services.publish_record(record)

    published = services.lookup_username(username_hash("alice"))
    assert published is not None
    assert "username_preimage" not in published.body
    assert published.username_preimage is None
    assert "alice" not in str(published.to_dict())
    # Round-tripping the published form must not smuggle the opening back.
    assert "username_preimage" not in published.to_dict()
    assert "username_preimage" not in published.to_publish_dict()


def test_username_record_with_the_preimage_in_the_signed_body_is_rejected() -> None:
    services = DecentralizedServices(clock=lambda: 1500)
    key, public_key = _signing_keys()
    leaky = sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body={
            "username_hash": username_hash("alice"),
            "identity_sign_pub": public_key.hex(),
            "username_preimage": "alice",
            "username_binding": username_binding("alice", public_key),
        },
        signing_key=key,
        created_at=1000,
    )

    with pytest.raises(ValueError, match="must not appear"):
        services.publish_record(leaky)
    # Even supplying a matching out-of-band opening cannot launder it.
    with pytest.raises(ValueError, match="must not appear"):
        services.publish_record(leaky, username_preimage="alice")

    assert services.lookup_username(username_hash("alice")) is None


def test_http_lookup_does_not_serve_the_username_preimage() -> None:
    client = _enabled_client()
    record = _username_record("frank")

    assert _publish_record(client, record).status_code == 200
    lookup = _lookup_username_record(client, username_hash("frank"))

    assert lookup.status_code == 200
    assert "username_preimage" not in lookup.json()["body"]
    assert "frank" not in lookup.text
