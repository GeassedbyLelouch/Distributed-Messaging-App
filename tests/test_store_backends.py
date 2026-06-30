"""
Parametrized behavioral tests for SesameStore (in-memory) and SqliteStore.

Both backends must exhibit identical observable behaviour for every test in the
shared suite.  A SQLite-specific persistence test additionally verifies that
data survives reopening the database file.
"""

from __future__ import annotations

import json
import sqlite3
import time

import pytest

from ml_kem_braid.sesame.base import StoreBackend
from ml_kem_braid.sesame.sqlite_store import SqliteStore
from ml_kem_braid.sesame.store import Account, Envelope, SesameStore
from ml_kem_braid.sesame.usernames import UsernameValidationError, normalize_username


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path) -> StoreBackend:
    """Yield a fresh backend instance for each parametrized variant."""
    if request.param == "memory":
        return SesameStore()
    return SqliteStore(":memory:")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BUNDLE_A = {"ik_sign_pub": "aaa", "ik_kem_pub": "bbb", "spk_pub": "ccc"}
_BUNDLE_B = {"ik_sign_pub": "xxx", "ik_kem_pub": "yyy", "spk_pub": "zzz"}
_IK_A = b"\x01" * 32
_IK_B = b"\x02" * 32
_OPK_SET = {1: "opk-one", 2: "opk-two"}


def _reg(store: StoreBackend, username="alice", reg_id=1, bundle=None, ik=None, opks=None):
    return store.register_device(
        username=username,
        registration_id=reg_id,
        bundle=bundle or _BUNDLE_A,
        identity_key=ik or _IK_A,
        one_time_prekeys=opks,
    )


def _envelope(
    sender_u: str,
    sender_d: int,
    recipient_u: str,
    recipient_d: int,
    eid: str = "env-1",
) -> Envelope:
    return Envelope(
        envelope_id=eid,
        sender_username=sender_u,
        sender_device_id=sender_d,
        recipient_username=recipient_u,
        recipient_device_id=recipient_d,
        kind="chat",
        body={"text": "hello"},
    )


# ---------------------------------------------------------------------------
# Shared behavioral suite (runs on both backends)
# ---------------------------------------------------------------------------


class TestSharedBehavior:
    def test_register_device_returns_device(self, store):
        dev = _reg(store)
        assert dev.username == "alice"
        assert dev.device_id == 1
        assert dev.registration_id == 1
        assert dev.bundle == _BUNDLE_A
        assert len(dev.auth_token) > 8

    def test_register_records_username_display_and_hash(self, store):
        dev = _reg(store, username="Alice.42")
        assert dev.username == "Alice.42"
        assert dev.username_display == "Alice.42"
        assert len(dev.username_hash) == 64

    def test_case_only_duplicate_username_rejected(self, store):
        _reg(store, username="Alice.42", ik=_IK_A)
        with pytest.raises(PermissionError, match="username hash"):
            _reg(store, username="alice.42", ik=_IK_A)

    def test_exact_same_signal_username_allows_second_device(self, store):
        first = _reg(store, username="Alice.42", reg_id=1, ik=_IK_A)
        second = _reg(store, username="Alice.42", reg_id=2, ik=_IK_A)

        assert second.device_id == 2
        assert second.username_display == first.username_display == "Alice.42"
        assert second.username_hash == first.username_hash
        assert len(second.username_hash) == 64

    def test_second_device_gets_incremented_id(self, store):
        d1 = _reg(store, reg_id=1)
        d2 = _reg(store, reg_id=2)
        assert d1.device_id == 1
        assert d2.device_id == 2

    def test_identity_key_pinned_on_first_registration(self, store):
        _reg(store, ik=_IK_A)
        with pytest.raises(PermissionError):
            _reg(store, ik=_IK_B)

    def test_same_identity_key_allows_second_device(self, store):
        _reg(store, reg_id=1, ik=_IK_A)
        dev2 = _reg(store, reg_id=2, ik=_IK_A)
        assert dev2.device_id == 2

    def test_get_account_returns_account(self, store):
        _reg(store)
        account = store.get_account("alice")
        assert account is not None
        assert account.username == "alice"
        assert account.identity_key == _IK_A

    def test_get_account_unknown_returns_none(self, store):
        assert store.get_account("nobody") is None

    def test_list_devices(self, store):
        _reg(store, reg_id=1)
        _reg(store, reg_id=2)
        devices = store.list_devices("alice")
        assert len(devices) == 2
        ids = {d.device_id for d in devices}
        assert ids == {1, 2}

    def test_list_devices_unknown_returns_empty(self, store):
        assert store.list_devices("nobody") == []

    def test_get_device(self, store):
        _reg(store)
        dev = store.get_device("alice", 1)
        assert dev is not None
        assert dev.device_id == 1

    def test_get_device_unknown_returns_none(self, store):
        _reg(store)
        assert store.get_device("alice", 99) is None

    def test_device_for_token_returns_device(self, store):
        dev = _reg(store)
        found = store.device_for_token(dev.auth_token)
        assert found is not None
        assert found.device_id == dev.device_id
        assert found.username == dev.username

    def test_device_for_token_bumps_last_seen(self, store):
        import time

        dev = _reg(store)
        before = dev.last_seen
        time.sleep(0.01)
        found = store.device_for_token(dev.auth_token)
        assert found is not None
        assert found.last_seen >= before

    def test_device_for_token_unknown_returns_none(self, store):
        assert store.device_for_token("no-such-token") is None

    def test_lookup_device_by_exact_username(self, store):
        dev = _reg(store, username="Alice.42")
        found = store.find_device_by_username("alice.42")
        assert found is not None
        assert found.username == "Alice.42"
        assert found.device_id == dev.device_id

    def test_lookup_rejects_prefix(self, store):
        _reg(store, username="Alice.42")
        with pytest.raises(UsernameValidationError):
            store.find_device_by_username("Ali")

    def test_add_list_delete_contact(self, store):
        owner = _reg(store, username="Alice.42", ik=_IK_A)
        target = _reg(store, username="Bob.1042", ik=_IK_B)

        contact = store.add_contact(
            owner_username="Alice.42",
            owner_device_id=owner.device_id,
            contact_username="Bob.1042",
            contact_device_id=target.device_id,
            alias="Bob",
        )

        assert contact.alias == "Bob"
        assert contact.username_display == "Bob.1042"
        assert store.list_contacts("Alice.42", owner.device_id) == [contact]
        assert store.delete_contact("Alice.42", owner.device_id, contact.contact_id) is True
        assert store.list_contacts("Alice.42", owner.device_id) == []

    def test_contact_request_accept_creates_reciprocal_contacts(self, store):
        alice = _reg(store, username="Alice.42", ik=_IK_A)
        bob = _reg(store, username="Bob.1042", ik=_IK_B)

        request = store.create_contact_request(
            requester_username="Alice.42",
            requester_device_id=alice.device_id,
            recipient_username="Bob.1042",
            recipient_device_id=bob.device_id,
            alias="Bob",
        )

        assert request.status == "pending"
        assert request.requester_username_display == "Alice.42"
        assert request.recipient_username_display == "Bob.1042"
        assert store.list_contact_requests("Alice.42", alice.device_id) == [request]
        assert store.list_contact_requests("Bob.1042", bob.device_id) == [request]
        assert store.list_contacts("Alice.42", alice.device_id) == []

        accepted = store.accept_contact_request(
            "Bob.1042",
            bob.device_id,
            request.request_id,
        )

        assert accepted.status == "accepted"
        assert store.list_contact_requests("Alice.42", alice.device_id) == []
        assert store.list_contact_requests("Bob.1042", bob.device_id) == []

        alice_contacts = store.list_contacts("Alice.42", alice.device_id)
        bob_contacts = store.list_contacts("Bob.1042", bob.device_id)
        assert [contact.contact_id for contact in alice_contacts] == ["Bob.1042:1"]
        assert alice_contacts[0].alias == "Bob"
        assert [contact.contact_id for contact in bob_contacts] == ["Alice.42:1"]
        assert bob_contacts[0].alias is None

    def test_contact_request_deny_does_not_create_contacts(self, store):
        alice = _reg(store, username="Alice.42", ik=_IK_A)
        bob = _reg(store, username="Bob.1042", ik=_IK_B)
        request = store.create_contact_request(
            "Alice.42",
            alice.device_id,
            "Bob.1042",
            bob.device_id,
        )

        denied = store.deny_contact_request("Bob.1042", bob.device_id, request.request_id)

        assert denied.status == "denied"
        assert store.list_contact_requests("Alice.42", alice.device_id) == []
        assert store.list_contact_requests("Bob.1042", bob.device_id) == []
        assert store.list_contacts("Alice.42", alice.device_id) == []
        assert store.list_contacts("Bob.1042", bob.device_id) == []

    def test_contact_request_recipient_only_accept_or_deny(self, store):
        alice = _reg(store, username="Alice.42", ik=_IK_A)
        bob = _reg(store, username="Bob.1042", ik=_IK_B)
        request = store.create_contact_request(
            "Alice.42",
            alice.device_id,
            "Bob.1042",
            bob.device_id,
        )

        with pytest.raises(PermissionError):
            store.accept_contact_request("Alice.42", alice.device_id, request.request_id)

        with pytest.raises(PermissionError):
            store.deny_contact_request("Alice.42", alice.device_id, request.request_id)

    def test_contact_request_duplicate_pending_rejected(self, store):
        alice = _reg(store, username="Alice.42", ik=_IK_A)
        bob = _reg(store, username="Bob.1042", ik=_IK_B)
        store.create_contact_request("Alice.42", alice.device_id, "Bob.1042", bob.device_id)

        with pytest.raises(ValueError, match="request already pending"):
            store.create_contact_request("Alice.42", alice.device_id, "Bob.1042", bob.device_id)

        with pytest.raises(ValueError, match="request already pending"):
            store.create_contact_request("Bob.1042", bob.device_id, "Alice.42", alice.device_id)

    def test_contact_duplicate_rejected(self, store):
        owner = _reg(store, username="Alice.42", ik=_IK_A)
        target = _reg(store, username="Bob.1042", ik=_IK_B)
        store.add_contact(
            "Alice.42",
            owner.device_id,
            "Bob.1042",
            target.device_id,
            alias="Bob",
        )

        with pytest.raises(ValueError, match="already exists"):
            store.add_contact(
                "Alice.42",
                owner.device_id,
                "Bob.1042",
                target.device_id,
                alias="Bob",
            )

    def test_list_contacts_requires_existing_owner_device(self, store):
        with pytest.raises(KeyError):
            store.list_contacts("Alice.42", 99)

    def test_delete_contact_requires_existing_owner_device(self, store):
        with pytest.raises(KeyError):
            store.delete_contact("Alice.42", 99, "Bob.1042:1")

    def test_contacts_are_isolated_by_owner_device(self, store):
        owner_one = _reg(store, username="Alice.42", reg_id=1, ik=_IK_A)
        owner_two = _reg(store, username="Alice.42", reg_id=2, ik=_IK_A)
        target = _reg(store, username="Bob.1042", ik=_IK_B)

        contact = store.add_contact(
            "Alice.42",
            owner_one.device_id,
            "Bob.1042",
            target.device_id,
            alias="Bob",
        )

        assert store.list_contacts("Alice.42", owner_one.device_id) == [contact]
        assert store.list_contacts("Alice.42", owner_two.device_id) == []

    def test_contacts_are_sorted_by_created_at(self, store):
        import time

        owner = _reg(store, username="Alice.42", ik=_IK_A)
        bob = _reg(store, username="Bob.1042", ik=_IK_B)
        carol = _reg(
            store,
            username="Carol.2042",
            ik=b"\x03" * 32,
            bundle={"ik_sign_pub": "111", "ik_kem_pub": "222", "spk_pub": "333"},
        )

        older = store.add_contact(
            "Alice.42",
            owner.device_id,
            "Bob.1042",
            bob.device_id,
            alias="Bob",
        )
        time.sleep(0.01)
        newer = store.add_contact(
            "Alice.42",
            owner.device_id,
            "Carol.2042",
            carol.device_id,
            alias="Carol",
        )

        contacts = store.list_contacts("Alice.42", owner.device_id)
        assert contacts == [older, newer]
        assert [contact.created_at for contact in contacts] == sorted(
            contact.created_at for contact in contacts
        )

    def test_created_at_stable_after_last_seen_bump(self, store):
        # created_at must not drift when last_seen is updated (backend parity:
        # the SQLite backend must read created_at, not alias it to last_seen).
        import time

        dev = _reg(store)
        created = dev.created_at
        time.sleep(0.01)
        store.device_for_token(dev.auth_token)  # bumps last_seen
        reloaded = store.get_device(dev.username, dev.device_id)
        assert reloaded is not None
        assert reloaded.created_at == created
        assert reloaded.last_seen >= created

    def test_take_prekey_bundle_no_opks(self, store):
        _reg(store, opks=None)
        bundle = store.take_prekey_bundle("alice", 1)
        assert bundle is not None
        assert bundle["opk_id"] is None
        assert bundle["opk_pub"] is None

    def test_take_prekey_bundle_consumes_opk(self, store):
        _reg(store, opks={10: "opk-ten"})
        bundle = store.take_prekey_bundle("alice", 1)
        assert bundle["opk_id"] == 10
        assert bundle["opk_pub"] == "opk-ten"
        # Second call: no opks left
        bundle2 = store.take_prekey_bundle("alice", 1)
        assert bundle2["opk_id"] is None
        assert bundle2["opk_pub"] is None

    def test_take_prekey_bundle_consumes_sequentially(self, store):
        _reg(store, opks=_OPK_SET)
        first = store.take_prekey_bundle("alice", 1)
        second = store.take_prekey_bundle("alice", 1)
        # Both returned a real OPK, and they are different
        assert first["opk_pub"] in _OPK_SET.values()
        assert second["opk_pub"] in _OPK_SET.values()
        assert first["opk_pub"] != second["opk_pub"]
        # Third call: exhausted
        third = store.take_prekey_bundle("alice", 1)
        assert third["opk_id"] is None

    def test_take_prekey_bundle_unknown_device_returns_none(self, store):
        assert store.take_prekey_bundle("alice", 99) is None

    def test_take_prekey_bundle_does_not_mutate_base_bundle(self, store):
        _reg(store, bundle=_BUNDLE_A, opks={5: "opk-five"})
        bundle1 = store.take_prekey_bundle("alice", 1)
        # After consuming the OPK the base bundle keys must still be present
        for k in _BUNDLE_A:
            assert k in bundle1

    def test_deliver_and_fetch_mailbox(self, store):
        dev = _reg(store)
        env = _envelope("bob", 1, "alice", dev.device_id)
        store.deliver(env)
        fetched = store.fetch_mailbox("alice", dev.device_id)
        assert len(fetched) == 1
        assert fetched[0].envelope_id == env.envelope_id
        assert fetched[0].body == env.body

    def test_fetch_mailbox_drains_by_default(self, store):
        dev = _reg(store)
        store.deliver(_envelope("bob", 1, "alice", dev.device_id))
        store.fetch_mailbox("alice", dev.device_id, drain=True)
        # After drain, mailbox is empty
        assert store.fetch_mailbox("alice", dev.device_id) == []

    def test_fetch_mailbox_no_drain_preserves_envelopes(self, store):
        dev = _reg(store)
        store.deliver(_envelope("bob", 1, "alice", dev.device_id))
        first = store.fetch_mailbox("alice", dev.device_id, drain=False)
        second = store.fetch_mailbox("alice", dev.device_id, drain=False)
        assert len(first) == 1
        assert len(second) == 1

    def test_deliver_raises_for_unknown_recipient(self, store):
        with pytest.raises(KeyError):
            store.deliver(_envelope("bob", 1, "alice", 99))

    def test_pending_count(self, store):
        dev = _reg(store)
        assert store.pending_count("alice", dev.device_id) == 0
        store.deliver(_envelope("bob", 1, "alice", dev.device_id, eid="e1"))
        store.deliver(_envelope("bob", 1, "alice", dev.device_id, eid="e2"))
        assert store.pending_count("alice", dev.device_id) == 2

    def test_pending_count_after_drain(self, store):
        dev = _reg(store)
        store.deliver(_envelope("bob", 1, "alice", dev.device_id))
        store.fetch_mailbox("alice", dev.device_id, drain=True)
        assert store.pending_count("alice", dev.device_id) == 0

    def test_mailbox_isolation_between_devices(self, store):
        d1 = _reg(store, reg_id=1)
        d2 = _reg(store, reg_id=2)
        store.deliver(_envelope("bob", 1, "alice", d1.device_id, eid="for-d1"))
        # d2 mailbox is untouched
        assert store.pending_count("alice", d2.device_id) == 0
        fetched_d1 = store.fetch_mailbox("alice", d1.device_id)
        assert len(fetched_d1) == 1
        assert fetched_d1[0].envelope_id == "for-d1"

    def test_mailbox_isolation_between_users(self, store):
        alice_dev = _reg(store, username="alice", reg_id=1, ik=_IK_A)
        bob_dev = _reg(store, username="bob", reg_id=1, ik=_IK_B)
        store.deliver(_envelope("carol", 1, "alice", alice_dev.device_id, eid="for-alice"))
        assert store.pending_count("bob", bob_dev.device_id) == 0


def test_account_positional_devices_compatibility():
    devices = {1: object()}
    account = Account("alice", _IK_A, 123.0, devices)

    assert account.devices is devices
    assert account.username_display == ""
    assert account.username_hash == ""


def test_store_backend_requires_username_lookup_and_contacts():
    assert {
        "find_device_by_username",
        "list_contacts",
        "add_contact",
        "delete_contact",
        "create_contact_request",
        "list_contact_requests",
        "accept_contact_request",
        "deny_contact_request",
    }.issubset(StoreBackend.__abstractmethods__)


# ---------------------------------------------------------------------------
# SQLite-specific: persistence across reopen
# ---------------------------------------------------------------------------


def _insert_sqlite_device_row(
    conn: sqlite3.Connection,
    username: str,
    created_at: float,
    registration_id: int = 42,
) -> None:
    conn.execute(
        """INSERT INTO devices
           (username, device_id, registration_id, bundle_json, auth_token, created_at, last_seen)
           VALUES (?,?,?,?,?,?,?)""",
        (
            username,
            1,
            registration_id,
            json.dumps(_BUNDLE_A),
            f"token-{username}",
            created_at,
            created_at,
        ),
    )


def _insert_old_sqlite_account(
    conn: sqlite3.Connection,
    username: str,
    identity_key: bytes,
    created_at: float,
) -> None:
    conn.execute(
        "INSERT INTO accounts (username, identity_key, created_at) VALUES (?,?,?)",
        (username, identity_key, created_at),
    )
    _insert_sqlite_device_row(conn, username, created_at)


def _insert_sqlite_account_with_metadata(
    conn: sqlite3.Connection,
    username: str,
    identity_key: bytes,
    created_at: float,
    username_display: str,
    username_hash: str,
) -> None:
    conn.execute(
        """INSERT INTO accounts
           (username, identity_key, created_at, username_display, username_hash)
           VALUES (?,?,?,?,?)""",
        (username, identity_key, created_at, username_display, username_hash),
    )
    _insert_sqlite_device_row(conn, username, created_at)


def _create_sqlite_store_with_username_metadata(db_path, rows) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE accounts (
                username         TEXT PRIMARY KEY,
                identity_key     BLOB NOT NULL,
                created_at       REAL NOT NULL,
                username_display TEXT NOT NULL DEFAULT '',
                username_hash    TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE devices (
                username        TEXT NOT NULL,
                device_id       INTEGER NOT NULL,
                registration_id INTEGER NOT NULL,
                bundle_json     TEXT NOT NULL,
                auth_token      TEXT NOT NULL UNIQUE,
                created_at      REAL NOT NULL,
                last_seen       REAL NOT NULL,
                PRIMARY KEY (username, device_id)
            );

            CREATE TABLE one_time_prekeys (
                username  TEXT NOT NULL,
                device_id INTEGER NOT NULL,
                opk_id    INTEGER NOT NULL,
                opk_pub   TEXT NOT NULL,
                PRIMARY KEY (username, device_id, opk_id)
            );

            CREATE TABLE mailbox (
                envelope_id        TEXT PRIMARY KEY,
                sender_username    TEXT NOT NULL,
                sender_device_id   INTEGER NOT NULL,
                recipient_username TEXT NOT NULL,
                recipient_device_id INTEGER NOT NULL,
                kind               TEXT NOT NULL,
                body_json          TEXT NOT NULL,
                created_at         REAL NOT NULL
            );
            """
        )
        for row in rows:
            _insert_sqlite_account_with_metadata(conn, *row)
        conn.commit()
    finally:
        conn.close()


def _create_old_sqlite_store(db_path, username: str, identity_key: bytes = _IK_A) -> None:
    now = time.time()
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE accounts (
                username     TEXT PRIMARY KEY,
                identity_key BLOB NOT NULL,
                created_at   REAL NOT NULL
            );

            CREATE TABLE devices (
                username        TEXT NOT NULL,
                device_id       INTEGER NOT NULL,
                registration_id INTEGER NOT NULL,
                bundle_json     TEXT NOT NULL,
                auth_token      TEXT NOT NULL UNIQUE,
                created_at      REAL NOT NULL,
                last_seen       REAL NOT NULL,
                PRIMARY KEY (username, device_id)
            );

            CREATE TABLE one_time_prekeys (
                username  TEXT NOT NULL,
                device_id INTEGER NOT NULL,
                opk_id    INTEGER NOT NULL,
                opk_pub   TEXT NOT NULL,
                PRIMARY KEY (username, device_id, opk_id)
            );

            CREATE TABLE mailbox (
                envelope_id        TEXT PRIMARY KEY,
                sender_username    TEXT NOT NULL,
                sender_device_id   INTEGER NOT NULL,
                recipient_username TEXT NOT NULL,
                recipient_device_id INTEGER NOT NULL,
                kind               TEXT NOT NULL,
                body_json          TEXT NOT NULL,
                created_at         REAL NOT NULL
            );
            """
        )
        _insert_old_sqlite_account(conn, username, identity_key, now)
        conn.commit()
    finally:
        conn.close()


def test_sqlite_migrates_old_schema_signal_username_lookup(tmp_path):
    db_path = tmp_path / "old_signal.db"
    _create_old_sqlite_store(db_path, "Alice.42")

    store = SqliteStore(db_path)

    found = store.find_device_by_username("alice.42")
    assert found is not None
    assert found.username == "Alice.42"
    assert found.device_id == 1
    assert found.username_display == "Alice.42"
    assert len(found.username_hash) == 64

    with pytest.raises(PermissionError, match="username hash"):
        store.register_device(
            username="alice.42",
            registration_id=43,
            bundle=_BUNDLE_A,
            identity_key=_IK_A,
        )


def test_sqlite_migrates_old_schema_simple_username_as_legacy(tmp_path):
    db_path = tmp_path / "old_simple.db"
    _create_old_sqlite_store(db_path, "alice")

    store = SqliteStore(db_path)

    account = store.get_account("alice")
    assert account is not None
    assert account.username_display == "alice"
    assert account.username_hash == ""
    device = store.get_device("alice", 1)
    assert device is not None
    assert device.username_display == "alice"
    assert device.username_hash == ""
    assert store.find_device_by_username("alice.42") is None


def test_sqlite_migration_leaves_later_colliding_username_legacy(tmp_path):
    db_path = tmp_path / "old_collision.db"
    _create_old_sqlite_store(db_path, "Alice.42", _IK_A)
    conn = sqlite3.connect(db_path)
    try:
        _insert_old_sqlite_account(conn, "alice.42", _IK_B, time.time() + 1)
        conn.commit()
    finally:
        conn.close()

    store = SqliteStore(db_path)

    found = store.find_device_by_username("alice.42")
    assert found is not None
    assert found.username == "Alice.42"
    first = store.get_account("Alice.42")
    colliding = store.get_account("alice.42")
    assert first is not None
    assert colliding is not None
    assert len(first.username_hash) == 64
    assert colliding.username_display == "alice.42"
    assert colliding.username_hash == ""


def test_sqlite_migration_repairs_duplicate_non_empty_hashes_before_index(tmp_path):
    db_path = tmp_path / "partial_duplicate_hash.db"
    username_hash = normalize_username("Alice.42").lookup_hash
    _create_sqlite_store_with_username_metadata(
        db_path,
        [
            ("Alice.42", _IK_A, 100.0, "Alice.42", username_hash),
            ("alice.42", _IK_B, 101.0, "alice.42", username_hash),
        ],
    )

    store = SqliteStore(db_path)

    first = store.get_account("Alice.42")
    duplicate = store.get_account("alice.42")
    assert first is not None
    assert duplicate is not None
    assert first.username_hash == username_hash
    assert duplicate.username_hash == ""
    found = store.find_device_by_username("alice.42")
    assert found is not None
    assert found.username == "Alice.42"


def test_sqlite_register_repairs_existing_blank_signal_metadata(tmp_path):
    db_path = tmp_path / "blank_signal_metadata.db"
    _create_sqlite_store_with_username_metadata(
        db_path,
        [("Alice.42", _IK_A, 100.0, "", "")],
    )
    store = SqliteStore(db_path)
    store._conn.execute(
        "UPDATE accounts SET username_display = '', username_hash = '' WHERE username = ?",
        ("Alice.42",),
    )

    device = store.register_device(
        username="Alice.42",
        registration_id=43,
        bundle=_BUNDLE_A,
        identity_key=_IK_A,
    )

    account = store.get_account("Alice.42")
    assert account is not None
    assert device.device_id == 2
    assert account.username_display == "Alice.42"
    assert len(account.username_hash) == 64
    assert device.username_hash == account.username_hash


def test_sqlite_migrated_old_schema_can_store_contacts(tmp_path):
    db_path = tmp_path / "old_contacts.db"
    _create_old_sqlite_store(db_path, "Alice.42", _IK_A)
    conn = sqlite3.connect(db_path)
    try:
        _insert_old_sqlite_account(conn, "Bob.1042", _IK_B, time.time() + 1)
        conn.commit()
    finally:
        conn.close()
    store = SqliteStore(db_path)

    contact = store.add_contact("Alice.42", 1, "Bob.1042", 1, alias="Bob")

    assert contact.username_display == "Bob.1042"
    assert store.list_contacts("Alice.42", 1) == [contact]
    assert store.delete_contact("Alice.42", 1, contact.contact_id) is True
    assert store.list_contacts("Alice.42", 1) == []


def test_sqlite_migrated_old_schema_can_store_contact_requests(tmp_path):
    db_path = tmp_path / "old_contact_requests.db"
    _create_old_sqlite_store(db_path, "Alice.42", _IK_A)
    conn = sqlite3.connect(db_path)
    try:
        _insert_old_sqlite_account(conn, "Bob.1042", _IK_B, time.time() + 1)
        conn.commit()
    finally:
        conn.close()
    store = SqliteStore(db_path)

    request = store.create_contact_request("Alice.42", 1, "Bob.1042", 1, alias="Bob")
    accepted = store.accept_contact_request("Bob.1042", 1, request.request_id)

    assert accepted.status == "accepted"
    assert [contact.contact_id for contact in store.list_contacts("Alice.42", 1)] == [
        "Bob.1042:1"
    ]
    assert [contact.contact_id for contact in store.list_contacts("Bob.1042", 1)] == [
        "Alice.42:1"
    ]


def test_sqlite_persists_across_reopen(tmp_path):
    db_path = tmp_path / "braid_test.db"

    # --- Phase 1: populate the database ---
    store1 = SqliteStore(db_path)
    dev = store1.register_device(
        username="alice",
        registration_id=42,
        bundle=_BUNDLE_A,
        identity_key=_IK_A,
        one_time_prekeys={7: "opk-seven", 8: "opk-eight"},
    )
    env = _envelope("bob", 1, "alice", dev.device_id, eid="persist-env")
    store1.deliver(env)
    token = dev.auth_token
    del store1  # close the first instance

    # --- Phase 2: open a fresh instance on the same file ---
    store2 = SqliteStore(db_path)

    # Device is recoverable by lookup
    recovered_dev = store2.get_device("alice", dev.device_id)
    assert recovered_dev is not None, "device not found after reopen"
    assert recovered_dev.registration_id == 42
    assert recovered_dev.bundle == _BUNDLE_A

    # Auth token still works
    found = store2.device_for_token(token)
    assert found is not None, "token lookup failed after reopen"

    # One-time prekeys survived
    bundle = store2.take_prekey_bundle("alice", dev.device_id)
    assert bundle is not None
    assert bundle["opk_pub"] in ("opk-seven", "opk-eight"), "OPK not persisted"

    # Undelivered envelope is still in the mailbox
    fetched = store2.fetch_mailbox("alice", dev.device_id)
    assert len(fetched) == 1, "mailbox envelope not persisted"
    assert fetched[0].envelope_id == "persist-env"
    assert fetched[0].body == {"text": "hello"}

    # Account identity key is pinned
    account = store2.get_account("alice")
    assert account is not None
    assert account.identity_key == _IK_A
