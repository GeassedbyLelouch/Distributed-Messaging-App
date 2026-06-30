from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ml_kem_braid.decentralized.records import SignedRecord, sign_record
from ml_kem_braid.decentralized.services import DecentralizedServices
from ml_kem_braid.server.app import create_app


def _signing_keys() -> tuple[Ed25519PrivateKey, bytes]:
    key = Ed25519PrivateKey.generate()
    public_key = key.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return key, public_key


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
        created_at=1.0,
    )


def _username_record(username_hash: str = "a" * 64) -> SignedRecord:
    key, public_key = _signing_keys()
    return sign_record(
        record_type="identity.username_record",
        author_identity=public_key,
        author_device_id=1,
        sequence=1,
        body={
            "username_hash": username_hash,
            "identity_sign_pub": public_key.hex(),
        },
        signing_key=key,
        created_at=1.0,
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
        created_at=1.0,
    )


def _enabled_client() -> TestClient:
    return TestClient(create_app(enable_decentralized=True))


def _publish_record(client: TestClient, record: SignedRecord):
    return client.post("/v1/records", json=record.to_dict())


def _lookup_username_record(client: TestClient, username_hash: str):
    return client.get(f"/v1/records/identity.username_record/{username_hash}")


def test_registry_stores_only_verified_username_record() -> None:
    record = _username_record()
    services = DecentralizedServices()

    services.publish_record(record)

    assert services.lookup_username("a" * 64) == record


def test_registry_rejects_duplicate_username_hash_without_replacing_first() -> None:
    services = DecentralizedServices()
    first = _username_record("a" * 64)
    second = _username_record("a" * 64)

    services.publish_record(first)

    with pytest.raises(ValueError, match="username hash already registered"):
        services.publish_record(second)

    assert services.lookup_username("a" * 64) == first


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
        created_at=1.0,
    )
    services = DecentralizedServices()

    with pytest.raises(ValueError):
        services.publish_record(record)


def test_mailbox_stores_opaque_envelope_without_plaintext_inspection() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}

    services.deliver_envelope(
        recipient_identity="b" * 64,
        recipient_device_id=1,
        envelope=envelope,
    )

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
    services.deliver_envelope("b" * 64, 1, envelope)

    assert services.fetch_mailbox("b" * 64, 1) == [envelope]
    assert services.fetch_mailbox("b" * 64, 1) == []


def test_fetch_envelopes_without_drain_returns_defensive_copies() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}
    services.deliver_envelope("b" * 64, 1, envelope)

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

    services.deliver_envelope("b" * 64, 1, envelope)
    envelope["body"]["ciphertext"] = "tampered"

    assert services.fetch_mailbox("b" * 64, 1, drain=False) == [
        {"kind": "chat", "body": {"ciphertext": "opaque"}}
    ]


def test_mutating_drained_returned_envelope_does_not_repopulate_mailbox() -> None:
    services = DecentralizedServices()
    envelope = {"kind": "chat", "body": {"ciphertext": "opaque"}}
    services.deliver_envelope("b" * 64, 1, envelope)

    fetched = services.fetch_mailbox("b" * 64, 1)
    fetched[0]["body"]["ciphertext"] = "tampered"

    assert services.fetch_mailbox("b" * 64, 1) == []


def test_decentralized_router_can_publish_and_lookup_record():
    client = _enabled_client()
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw()
    record = sign_record(
        record_type="identity.username_record",
        author_identity=pub,
        author_device_id=1,
        sequence=1,
        body={"username_hash": "c" * 64, "identity_sign_pub": pub.hex()},
        signing_key=key,
        created_at=1000.0,
    )
    publish = client.post("/v1/records", json=record.to_dict())
    lookup = client.get("/v1/records/identity.username_record/" + "c" * 64)
    assert publish.status_code == 200
    assert lookup.status_code == 200
    assert lookup.json()["body"]["username_hash"] == "c" * 64


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
    record = _username_record("a" * 64)
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
    record = _username_record("g" * 64)

    response = _publish_record(client, record)

    assert response.status_code == 422


def test_decentralized_publish_rejects_duplicate_username_hash() -> None:
    client = _enabled_client()
    first = _username_record("a" * 64)
    second = _username_record("a" * 64)

    first_response = _publish_record(client, first)
    second_response = _publish_record(client, second)

    assert first_response.status_code == 200
    assert second_response.status_code == 409


def test_decentralized_enabled_apps_have_isolated_registries() -> None:
    first_client = _enabled_client()
    second_client = _enabled_client()
    record = _username_record("d" * 64)

    publish = _publish_record(first_client, record)
    second_lookup = _lookup_username_record(second_client, "d" * 64)

    assert publish.status_code == 200
    assert second_lookup.status_code == 404


def test_decentralized_username_hash_lookup_does_not_normalize_case() -> None:
    client = _enabled_client()
    record = _username_record("e" * 64)

    publish = _publish_record(client, record)
    uppercase_lookup = _lookup_username_record(client, "E" * 64)

    assert publish.status_code == 200
    assert uppercase_lookup.status_code == 404
