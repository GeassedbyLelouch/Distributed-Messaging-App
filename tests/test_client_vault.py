from copy import deepcopy

from ml_kem_braid.decentralized import InMemoryClientVault
from ml_kem_braid.client.vault_client import VaultBackedClient
from ml_kem_braid.crypto import xeddsa
from ml_kem_braid.decentralized.records import sign_record
import pytest


# Audit L14: contact records are verified before the vault trusts them, so
# tests store genuinely signed records and pin the verification clock.
CLOCK = 1500


def _contact_record(sequence: int, body: dict | None = None) -> dict:
    key = xeddsa.generate_identity()
    public_key = xeddsa.public_key(key)
    return sign_record(
        record_type="contact.request",
        author_identity=public_key,
        author_device_id=1,
        sequence=sequence,
        body=body if body is not None else {"request_id": f"req-{sequence}"},
        signing_key=key,
        created_at=1000,
        expires_at=2000,
    ).to_dict()


def test_vault_round_trips_identity_and_session_state():
    vault = InMemoryClientVault()

    vault.store_identity("Alice.42", b"identity-secret")
    vault.store_session("conv-1", b"peer", {"epoch": 3, "ratchet": "encoded"})

    assert vault.load_identity("Alice.42") == b"identity-secret"
    assert vault.load_session("conv-1") == {
        "peer_identity": "70656572",
        "state": {"epoch": 3, "ratchet": "encoded"},
    }


def test_vault_stores_signed_contact_log_ordered():
    vault = InMemoryClientVault()
    first = _contact_record(1)
    second = _contact_record(2)

    vault.append_contact_record("conv-1", first, at_ms=CLOCK)
    vault.append_contact_record("conv-1", second, at_ms=CLOCK)

    assert vault.load_contact_records("conv-1") == [first, second]


def test_vault_rejects_unsigned_or_forged_contact_records():
    """Audit L14: the vault must not trust a record it cannot verify."""

    vault = InMemoryClientVault()
    record = _contact_record(1)
    forged = dict(record)
    forged["body"] = {"request_id": "req-evil"}

    with pytest.raises(PermissionError):
        vault.append_contact_record("conv-1", forged, at_ms=CLOCK)

    assert vault.load_contact_records("conv-1") == []


def test_vault_rejects_contact_record_sequence_rollback():
    vault = InMemoryClientVault()
    vault.append_contact_record("conv-1", _contact_record(5), at_ms=CLOCK)

    with pytest.raises(ValueError, match="strictly increasing"):
        vault.append_contact_record("conv-1", _contact_record(4), at_ms=CLOCK)

    with pytest.raises(ValueError, match="strictly increasing"):
        vault.append_contact_record("conv-1", _contact_record(5), at_ms=CLOCK)


def test_vault_rejects_expired_contact_record():
    vault = InMemoryClientVault()

    with pytest.raises(PermissionError):
        vault.append_contact_record("conv-1", _contact_record(1), at_ms=9999)


def test_vault_session_version_is_monotonic():
    vault = InMemoryClientVault()
    vault.store_session("conv-1", b"peer", {"epoch": 1})
    first_version = vault.session_version("conv-1")
    vault.store_session("conv-1", b"peer", {"epoch": 2})

    assert vault.session_version("conv-1") == first_version + 1
    assert vault.load_session("conv-1")["state"] == {"epoch": 2}


def test_vault_copies_session_and_contact_state():
    vault = InMemoryClientVault()
    session_state = {"epoch": 3, "ratchet": {"step": 1}}
    contact_record = _contact_record(1, {"proof": {"signature": "sig-1"}})

    vault.store_session("conv-1", b"peer", session_state)
    vault.append_contact_record("conv-1", contact_record, at_ms=CLOCK)
    stored_copy = deepcopy(contact_record)

    session_state["ratchet"]["step"] = 99
    contact_record["body"]["proof"]["signature"] = "changed"
    loaded_session = vault.load_session("conv-1")
    loaded_contact_records = vault.load_contact_records("conv-1")
    loaded_session["state"]["ratchet"]["step"] = 100
    loaded_contact_records[0]["body"]["proof"]["signature"] = "mutated"

    assert vault.load_session("conv-1") == {
        "peer_identity": "70656572",
        "state": {"epoch": 3, "ratchet": {"step": 1}},
    }
    assert vault.load_contact_records("conv-1") == [stored_copy]


def test_vault_returns_empty_missing_state():
    vault = InMemoryClientVault()

    assert vault.load_identity("missing") is None
    assert vault.load_session("missing") is None
    assert vault.load_contact_records("missing") == []


def test_vault_rejects_malformed_contact_records_without_poisoning_log():
    vault = InMemoryClientVault()
    first = _contact_record(1)
    vault.append_contact_record("conv-1", first, at_ms=CLOCK)

    malformed_records = [
        None,
        [],
        {},
        {"sequence": "1"},
        {"sequence": True},
        {"sequence": 3},
    ]

    for record in malformed_records:
        with pytest.raises((TypeError, ValueError, PermissionError)):
            vault.append_contact_record("conv-1", record, at_ms=CLOCK)

    second = _contact_record(2)
    vault.append_contact_record("conv-1", second, at_ms=CLOCK)

    assert vault.load_contact_records("conv-1") == [first, second]


def test_vault_rejects_mutable_byte_like_identity_inputs():
    vault = InMemoryClientVault()

    with pytest.raises(TypeError):
        vault.store_identity("Alice.42", bytearray(b"identity-secret"))
    with pytest.raises(TypeError):
        vault.store_identity("Alice.42", memoryview(b"identity-secret"))
    with pytest.raises(TypeError):
        vault.store_session("conv-1", bytearray(b"peer"), {"epoch": 1})
    with pytest.raises(TypeError):
        vault.store_session("conv-1", memoryview(b"peer"), {"epoch": 1})

    assert vault.load_identity("Alice.42") is None
    assert vault.load_session("conv-1") is None


def test_vault_backed_client_persists_identity_secret():
    vault = InMemoryClientVault()
    client = VaultBackedClient(vault, "Alice.42")
    client.initialize_identity(b"identity-secret")
    assert vault.load_identity("Alice.42") == b"identity-secret"


def test_vault_backed_clients_isolate_identity_secrets_by_username():
    vault = InMemoryClientVault()
    alice = VaultBackedClient(vault, "Alice.42")
    bob = VaultBackedClient(vault, "Bob.17")

    alice.initialize_identity(b"alice-secret")
    bob.initialize_identity(b"bob-secret")

    assert vault.load_identity("Alice.42") == b"alice-secret"
    assert vault.load_identity("Bob.17") == b"bob-secret"


def test_vault_backed_client_delegates_identity_secret_type_validation():
    vault = InMemoryClientVault()
    client = VaultBackedClient(vault, "Alice.42")

    with pytest.raises(TypeError):
        client.initialize_identity(bytearray(b"identity-secret"))

    assert vault.load_identity("Alice.42") is None


# --- Verifier D17: no random-nonce multi-use AEAD path -----------------------


def test_vault_uses_counter_nonces_not_random_ones():
    """The vault key seals many blobs, so every nonce must be structural.

    ``_seal`` used to draw ``os.urandom(12)`` per call, re-opening the exact
    multi-use random-nonce path core/aead.py forbids (audit M4). Counter
    nonces are strictly increasing 12-byte big-endian integers, so this asserts
    both uniqueness and the encoding.
    """

    from ml_kem_braid.core.aead import NONCE_SIZE

    vault = InMemoryClientVault()
    nonces = []
    for index in range(16):
        vault.store_session(f"conv-{index}", b"peer", {"epoch": index})
        _version, counter, sealed = vault._sessions[f"conv-{index}"]
        nonce = sealed[:NONCE_SIZE]
        assert nonce == counter.to_bytes(NONCE_SIZE, "big")
        nonces.append(nonce)

    assert len(set(nonces)) == len(nonces)
    assert nonces == sorted(nonces)


def test_vault_requires_an_aes_256_at_rest_key():
    with pytest.raises(ValueError, match="32 bytes"):
        InMemoryClientVault(b"\x01" * 16)
    with pytest.raises(TypeError):
        InMemoryClientVault(bytearray(b"\x01" * 32))


# --- Verifier D16: the rollback claim must match the implementation ----------


class _ExternalMonotonicCounter:
    """Stands in for a TPM/TEE counter the rollback adversary cannot rewind."""

    def __init__(self) -> None:
        self._versions: dict[str, int] = {}

    def next_version(self, slot: str) -> int:
        version = self._versions.get(slot, 0) + 1
        self._versions[slot] = version
        return version

    def current_version(self, slot: str) -> int:
        return self._versions.get(slot, 0)


def test_stale_sealed_blob_cannot_be_swapped_back_in():
    """The version is AEAD-bound, so an old ciphertext is not openable."""

    vault = InMemoryClientVault()
    vault.store_identity("Alice.42", b"v1-secret")
    stale = vault._identities["Alice.42"]
    vault.store_identity("Alice.42", b"v2-secret")

    # Attacker restores the old ciphertext but cannot rewind the version.
    version, counter, sealed = stale
    current_version = vault._identities["Alice.42"][0]
    vault._identities["Alice.42"] = (current_version, counter, sealed)

    with pytest.raises(Exception):  # InvalidTag: AAD version mismatch
        vault.load_identity("Alice.42")


def test_whole_store_rollback_is_detected_with_an_external_version_source():
    """The advertised guarantee holds exactly when the counter is trusted."""

    counter_source = _ExternalMonotonicCounter()
    vault = InMemoryClientVault(b"k" * 32, version_source=counter_source)
    vault.store_identity("Alice.42", b"v1-secret")
    vault.store_session("conv-1", b"peer", {"epoch": 1})
    snapshot_identity = vault._identities["Alice.42"]
    snapshot_session = vault._sessions["conv-1"]

    vault.store_identity("Alice.42", b"v2-secret")
    vault.store_session("conv-1", b"peer", {"epoch": 2})

    # Attacker rolls the entire vault store back to the earlier snapshot.
    vault._identities["Alice.42"] = snapshot_identity
    vault._sessions["conv-1"] = snapshot_session

    with pytest.raises(ValueError, match="rollback detected"):
        vault.load_identity("Alice.42")
    with pytest.raises(ValueError, match="rollback detected"):
        vault.load_session("conv-1")


def test_external_version_source_still_round_trips_normally():
    vault = InMemoryClientVault(b"k" * 32, version_source=_ExternalMonotonicCounter())
    vault.store_identity("Alice.42", b"identity-secret")
    vault.store_session("conv-1", b"peer", {"epoch": 3})

    assert vault.load_identity("Alice.42") == b"identity-secret"
    assert vault.load_session("conv-1")["state"] == {"epoch": 3}
