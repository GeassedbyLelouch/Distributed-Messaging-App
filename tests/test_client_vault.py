from ml_kem_braid.decentralized import InMemoryClientVault
from ml_kem_braid.client.vault_client import VaultBackedClient
import pytest


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

    vault.append_contact_record("conv-1", {"sequence": 2})
    vault.append_contact_record("conv-1", {"sequence": 1})

    assert vault.load_contact_records("conv-1") == [{"sequence": 1}, {"sequence": 2}]


def test_vault_copies_session_and_contact_state():
    vault = InMemoryClientVault()
    session_state = {"epoch": 3, "ratchet": {"step": 1}}
    contact_record = {"sequence": 1, "proof": {"signature": "sig-1"}}

    vault.store_session("conv-1", b"peer", session_state)
    vault.append_contact_record("conv-1", contact_record)

    session_state["ratchet"]["step"] = 99
    contact_record["proof"]["signature"] = "changed"
    loaded_session = vault.load_session("conv-1")
    loaded_contact_records = vault.load_contact_records("conv-1")
    loaded_session["state"]["ratchet"]["step"] = 100
    loaded_contact_records[0]["proof"]["signature"] = "mutated"

    assert vault.load_session("conv-1") == {
        "peer_identity": "70656572",
        "state": {"epoch": 3, "ratchet": {"step": 1}},
    }
    assert vault.load_contact_records("conv-1") == [
        {"sequence": 1, "proof": {"signature": "sig-1"}}
    ]


def test_vault_returns_empty_missing_state():
    vault = InMemoryClientVault()

    assert vault.load_identity("missing") is None
    assert vault.load_session("missing") is None
    assert vault.load_contact_records("missing") == []


def test_vault_rejects_malformed_contact_records_without_poisoning_log():
    vault = InMemoryClientVault()
    vault.append_contact_record("conv-1", {"sequence": 2})

    malformed_records = [
        None,
        [],
        {},
        {"sequence": "1"},
        {"sequence": True},
    ]

    for record in malformed_records:
        with pytest.raises((TypeError, ValueError)):
            vault.append_contact_record("conv-1", record)

    vault.append_contact_record("conv-1", {"sequence": 1})

    assert vault.load_contact_records("conv-1") == [{"sequence": 1}, {"sequence": 2}]


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
