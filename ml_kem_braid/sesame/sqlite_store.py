"""
Durable SQLite-backed Sesame store.

Persists accounts, devices, one-time prekeys, and mailbox envelopes across
process restarts.  Uses a single connection with ``check_same_thread=False``
plus a :class:`threading.Lock` so FastAPI's thread-pool is safe.  Critical
multi-step operations (``take_prekey_bundle``, ``fetch_mailbox`` with drain)
are wrapped in explicit transactions so they are atomic.

Schema
------
accounts        (username PK, identity_key BLOB, created_at REAL,
                 username_display TEXT, username_hash TEXT)
devices         (username, device_id, registration_id, bundle_json TEXT,
                 auth_token, created_at REAL, last_seen REAL)
one_time_prekeys(username, device_id, opk_id INTEGER, opk_pub TEXT)
mailbox         (envelope_id TEXT PK, sender_username, sender_device_id,
                 recipient_username, recipient_device_id,
                 kind, body_json TEXT, created_at REAL)
contacts        (owner_username, owner_device_id, contact_id, ...)
contact_requests(request_id PK, requester_username/device_id,
                 recipient_username/device_id, status, ...)
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Union

from ml_kem_braid.sesame.base import StoreBackend
from ml_kem_braid.sesame.store import (
    Account,
    Contact,
    ContactRequestRecord,
    Device,
    Envelope,
)
from ml_kem_braid.sesame.usernames import UsernameValidationError, normalize_username


def _now() -> float:
    return time.time()


_DDL = """
CREATE TABLE IF NOT EXISTS accounts (
    username         TEXT PRIMARY KEY,
    identity_key     BLOB NOT NULL,
    created_at       REAL NOT NULL,
    username_display TEXT NOT NULL DEFAULT '',
    username_hash    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS devices (
    username        TEXT NOT NULL,
    device_id       INTEGER NOT NULL,
    registration_id INTEGER NOT NULL,
    bundle_json     TEXT NOT NULL,
    auth_token      TEXT NOT NULL UNIQUE,
    created_at      REAL NOT NULL,
    last_seen       REAL NOT NULL,
    PRIMARY KEY (username, device_id)
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    username  TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    opk_id    INTEGER NOT NULL,
    opk_pub   TEXT NOT NULL,
    PRIMARY KEY (username, device_id, opk_id)
);

CREATE TABLE IF NOT EXISTS mailbox (
    envelope_id        TEXT PRIMARY KEY,
    sender_username    TEXT NOT NULL,
    sender_device_id   INTEGER NOT NULL,
    recipient_username TEXT NOT NULL,
    recipient_device_id INTEGER NOT NULL,
    kind               TEXT NOT NULL,
    body_json          TEXT NOT NULL,
    created_at         REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    owner_username   TEXT NOT NULL,
    owner_device_id  INTEGER NOT NULL,
    contact_id       TEXT NOT NULL,
    contact_username TEXT NOT NULL,
    contact_device_id INTEGER NOT NULL,
    username_display TEXT NOT NULL,
    username_hash    TEXT NOT NULL,
    alias            TEXT,
    verified         INTEGER NOT NULL DEFAULT 0,
    created_at       REAL NOT NULL,
    PRIMARY KEY (owner_username, owner_device_id, contact_id)
);

CREATE TABLE IF NOT EXISTS contact_requests (
    request_id                 TEXT PRIMARY KEY,
    requester_username         TEXT NOT NULL,
    requester_device_id        INTEGER NOT NULL,
    recipient_username         TEXT NOT NULL,
    recipient_device_id        INTEGER NOT NULL,
    requester_username_display TEXT NOT NULL,
    requester_username_hash    TEXT NOT NULL,
    recipient_username_display TEXT NOT NULL,
    recipient_username_hash    TEXT NOT NULL,
    alias                      TEXT,
    status                     TEXT NOT NULL,
    created_at                 REAL NOT NULL,
    updated_at                 REAL NOT NULL
);
"""

_USERNAME_HASH_INDEX_DDL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_accounts_username_hash
ON accounts(username_hash)
WHERE username_hash != ''
"""

_CONTACT_REQUEST_PENDING_PAIR_INDEX_DDL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_contact_requests_pending_pair
ON contact_requests(
    requester_username,
    requester_device_id,
    recipient_username,
    recipient_device_id
)
WHERE status = 'pending'
"""


class SqliteStore(StoreBackend):
    """Durable Sesame store backed by a SQLite database file.

    Parameters
    ----------
    path:
        Filesystem path for the database file, or ``":memory:"`` for an
        ephemeral in-process database (useful for tests).
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self._path,
            check_same_thread=False,
            isolation_level=None,  # autocommit; we manage transactions explicitly
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._apply_schema()

    # -- internal helpers --------------------------------------------------

    def _apply_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_DDL)
            self._ensure_column(
                "accounts",
                "username_display",
                "username_display TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "accounts",
                "username_hash",
                "username_hash TEXT NOT NULL DEFAULT ''",
            )
            self._backfill_account_usernames()
            self._conn.execute(_USERNAME_HASH_INDEX_DDL)
            self._conn.execute(_CONTACT_REQUEST_PENDING_PAIR_INDEX_DDL)

    def _ensure_column(self, table: str, column: str, ddl: str) -> None:
        columns = {
            row["name"]
            for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")

    def _backfill_account_usernames(self) -> None:
        rows = self._conn.execute(
            """SELECT username, username_display, username_hash
               FROM accounts
               ORDER BY created_at, username"""
        ).fetchall()
        hash_owner: Dict[str, str] = {}

        for row in rows:
            username = row["username"]
            username_display = row["username_display"] or username
            existing_hash = row["username_hash"] or ""
            username_hash = existing_hash
            cleared_duplicate_hash = False

            if username_hash != "":
                owner = hash_owner.get(username_hash)
                if owner is None or owner == username:
                    hash_owner[username_hash] = username
                else:
                    username_hash = ""
                    cleared_duplicate_hash = True

            if username_hash == "" and not cleared_duplicate_hash:
                try:
                    normalized = normalize_username(username)
                except UsernameValidationError:
                    pass
                else:
                    owner = hash_owner.get(normalized.lookup_hash)
                    username_display = username
                    if owner is None or owner == username:
                        username_hash = normalized.lookup_hash
                        hash_owner[username_hash] = username

            if (
                username_display != row["username_display"]
                or username_hash != row["username_hash"]
            ):
                self._conn.execute(
                    """UPDATE accounts
                       SET username_display = ?, username_hash = ?
                       WHERE username = ?""",
                    (username_display, username_hash, username),
                )

    @staticmethod
    def _is_username_hash_integrity_error(exc: sqlite3.IntegrityError) -> bool:
        return "accounts.username_hash" in str(exc)

    @staticmethod
    def _is_contact_duplicate_integrity_error(exc: sqlite3.IntegrityError) -> bool:
        message = str(exc)
        return (
            "contacts.owner_username" in message
            and "contacts.owner_device_id" in message
            and "contacts.contact_id" in message
        )

    @staticmethod
    def _is_contact_request_duplicate_integrity_error(exc: sqlite3.IntegrityError) -> bool:
        message = str(exc)
        return (
            "contact_requests.requester_username" in message
            and "contact_requests.requester_device_id" in message
            and "contact_requests.recipient_username" in message
            and "contact_requests.recipient_device_id" in message
        )

    # -- registration ------------------------------------------------------

    def register_device(
        self,
        username: str,
        registration_id: int,
        bundle: dict,
        identity_key: bytes,
        one_time_prekeys: Optional[Dict[int, str]] = None,
    ) -> Device:
        """Register a new device; pin identity_key on first registration.

        Raises :class:`PermissionError` if a different identity key is supplied
        for a username that is already registered.
        """
        with self._lock:
            try:
                normalized = normalize_username(username)
            except UsernameValidationError:
                normalized = None

            if normalized is not None:
                hash_row = self._conn.execute(
                    "SELECT username FROM accounts WHERE username_hash = ?",
                    (normalized.lookup_hash,),
                ).fetchone()
                if hash_row is not None and hash_row["username"] != username:
                    raise PermissionError("username hash is already registered")

            # Check the identity-key pin before opening the write transaction
            # so we can raise PermissionError cleanly without transaction state.
            existing_row = self._conn.execute(
                """SELECT identity_key, username_display, username_hash
                   FROM accounts WHERE username = ?""",
                (username,),
            ).fetchone()
            if existing_row is not None and bytes(existing_row["identity_key"]) != identity_key:
                raise PermissionError(
                    f"username '{username}' is bound to a different identity key"
                )

            repair_account_metadata = False
            if existing_row is None:
                username_display = normalized.display if normalized is not None else username
                username_hash = normalized.lookup_hash if normalized is not None else ""
            else:
                existing_display = existing_row["username_display"]
                existing_hash = existing_row["username_hash"]
                if existing_hash == "" and normalized is not None:
                    username_display = username
                    username_hash = normalized.lookup_hash
                    repair_account_metadata = True
                else:
                    username_display = existing_display or username
                    username_hash = existing_hash
                    repair_account_metadata = username_display != existing_display

            self._conn.execute("BEGIN")
            try:
                if existing_row is None:
                    now = _now()
                    self._conn.execute(
                        """INSERT INTO accounts
                           (username, identity_key, created_at, username_display, username_hash)
                           VALUES (?,?,?,?,?)""",
                        (username, identity_key, now, username_display, username_hash),
                    )
                elif repair_account_metadata:
                    self._conn.execute(
                        """UPDATE accounts
                           SET username_display = ?, username_hash = ?
                           WHERE username = ?""",
                        (username_display, username_hash, username),
                    )

                # Assign next device_id (max + 1, or 1 if none yet).
                max_row = self._conn.execute(
                    "SELECT MAX(device_id) AS m FROM devices WHERE username = ?", (username,)
                ).fetchone()
                device_id = (max_row["m"] + 1) if max_row["m"] is not None else 1

                import secrets as _secrets

                auth_token = _secrets.token_urlsafe(24)
                now = _now()
                self._conn.execute(
                    """INSERT INTO devices
                       (username, device_id, registration_id, bundle_json, auth_token, created_at, last_seen)
                       VALUES (?,?,?,?,?,?,?)""",
                    (username, device_id, registration_id, json.dumps(bundle), auth_token, now, now),
                )

                if one_time_prekeys:
                    self._conn.executemany(
                        "INSERT INTO one_time_prekeys (username, device_id, opk_id, opk_pub) VALUES (?,?,?,?)",
                        [
                            (username, device_id, opk_id, opk_pub)
                            for opk_id, opk_pub in one_time_prekeys.items()
                        ],
                    )

                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                if self._is_username_hash_integrity_error(exc):
                    raise PermissionError("username hash is already registered") from exc
                raise
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

            opks = dict(one_time_prekeys) if one_time_prekeys else {}
            return Device(
                username=username,
                device_id=device_id,
                registration_id=registration_id,
                bundle=dict(bundle),
                auth_token=auth_token,
                created_at=now,
                last_seen=now,
                one_time_prekeys=opks,
                username_display=username_display,
                username_hash=username_hash,
            )

    # -- lookup ------------------------------------------------------------

    def get_account(self, username: str) -> Optional[Account]:
        with self._lock:
            row = self._conn.execute(
                """SELECT username, identity_key, created_at, username_display, username_hash
                   FROM accounts WHERE username = ?""",
                (username,),
            ).fetchone()
            if row is None:
                return None
            devices = {d.device_id: d for d in self._list_devices_locked(username)}
            return Account(
                username=row["username"],
                identity_key=bytes(row["identity_key"]),
                created_at=row["created_at"],
                devices=devices,
                username_display=row["username_display"],
                username_hash=row["username_hash"],
            )

    def list_devices(self, username: str) -> List[Device]:
        with self._lock:
            return self._list_devices_locked(username)

    def _list_devices_locked(self, username: str) -> List[Device]:
        rows = self._conn.execute(
            "SELECT * FROM devices WHERE username = ? ORDER BY device_id", (username,)
        ).fetchall()
        return [self._row_to_device(r) for r in rows]

    def _row_to_device(self, row: sqlite3.Row) -> Device:
        username = row["username"]
        device_id = row["device_id"]
        opk_rows = self._conn.execute(
            "SELECT opk_id, opk_pub FROM one_time_prekeys WHERE username = ? AND device_id = ?",
            (username, device_id),
        ).fetchall()
        account_row = self._conn.execute(
            "SELECT username_display, username_hash FROM accounts WHERE username = ?",
            (username,),
        ).fetchone()
        username_display = account_row["username_display"] if account_row is not None else ""
        username_hash = account_row["username_hash"] if account_row is not None else ""
        return Device(
            username=username,
            device_id=device_id,
            registration_id=row["registration_id"],
            bundle=json.loads(row["bundle_json"]),
            auth_token=row["auth_token"],
            created_at=row["created_at"],
            last_seen=row["last_seen"],
            one_time_prekeys={r["opk_id"]: r["opk_pub"] for r in opk_rows},
            username_display=username_display,
            username_hash=username_hash,
        )

    def get_device(self, username: str, device_id: int) -> Optional[Device]:
        with self._lock:
            return self._get_device_locked(username, device_id)

    def _get_device_locked(self, username: str, device_id: int) -> Optional[Device]:
        row = self._conn.execute(
            "SELECT * FROM devices WHERE username = ? AND device_id = ?",
            (username, device_id),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_device(row)

    def device_for_token(self, token: str) -> Optional[Device]:
        with self._lock:
            row = self._conn.execute(
                "SELECT username, device_id FROM devices WHERE auth_token = ?", (token,)
            ).fetchone()
            if row is None:
                return None
            username, device_id = row["username"], row["device_id"]
            now = _now()
            self._conn.execute(
                "UPDATE devices SET last_seen = ? WHERE username = ? AND device_id = ?",
                (now, username, device_id),
            )
            device = self._get_device_locked(username, device_id)
            return device

    def find_device_by_username(self, username: str) -> Optional[Device]:
        normalized = normalize_username(username)
        with self._lock:
            row = self._conn.execute(
                """SELECT d.*
                   FROM accounts AS a
                   JOIN devices AS d ON d.username = a.username
                   WHERE a.username_hash = ?
                   ORDER BY d.device_id
                   LIMIT 1""",
                (normalized.lookup_hash,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_device(row)

    def list_contacts(self, username: str, device_id: int) -> List[Contact]:
        with self._lock:
            if self._get_device_locked(username, device_id) is None:
                raise KeyError(f"no such owner device: {(username, device_id)}")
            rows = self._conn.execute(
                """SELECT *
                   FROM contacts
                   WHERE owner_username = ? AND owner_device_id = ?
                   ORDER BY created_at""",
                (username, device_id),
            ).fetchall()
            return [self._row_to_contact(row) for row in rows]

    def add_contact(
        self,
        owner_username: str,
        owner_device_id: int,
        contact_username: str,
        contact_device_id: int,
        alias: Optional[str] = None,
    ) -> Contact:
        with self._lock:
            return self._add_contact_locked(
                owner_username,
                owner_device_id,
                contact_username,
                contact_device_id,
                alias=alias,
            )

    def _add_contact_locked(
        self,
        owner_username: str,
        owner_device_id: int,
        contact_username: str,
        contact_device_id: int,
        alias: Optional[str] = None,
        allow_existing: bool = False,
    ) -> Contact:
        owner = self._get_device_locked(owner_username, owner_device_id)
        target = self._get_device_locked(contact_username, contact_device_id)
        if owner is None:
            raise KeyError(f"no such owner device: {(owner_username, owner_device_id)}")
        if target is None:
            raise KeyError(f"no such contact device: {(contact_username, contact_device_id)}")

        contact_id = f"{contact_username}:{contact_device_id}"
        existing_contact = self._conn.execute(
            """SELECT *
               FROM contacts
               WHERE owner_username = ? AND owner_device_id = ? AND contact_id = ?""",
            (owner_username, owner_device_id, contact_id),
        ).fetchone()
        if existing_contact is not None:
            if allow_existing:
                return self._row_to_contact(existing_contact)
            raise ValueError("contact already exists")

        contact = Contact(
            contact_id=contact_id,
            owner_username=owner_username,
            owner_device_id=owner_device_id,
            contact_username=contact_username,
            contact_device_id=contact_device_id,
            username_display=target.username_display or target.username,
            username_hash=target.username_hash,
            alias=alias,
            created_at=_now(),
        )
        try:
            self._conn.execute(
                """INSERT INTO contacts
                   (owner_username, owner_device_id, contact_id,
                    contact_username, contact_device_id, username_display,
                    username_hash, alias, verified, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    contact.owner_username,
                    contact.owner_device_id,
                    contact.contact_id,
                    contact.contact_username,
                    contact.contact_device_id,
                    contact.username_display,
                    contact.username_hash,
                    contact.alias,
                    int(contact.verified),
                    contact.created_at,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if self._is_contact_duplicate_integrity_error(exc):
                if allow_existing:
                    existing = self._conn.execute(
                        """SELECT *
                           FROM contacts
                           WHERE owner_username = ?
                             AND owner_device_id = ?
                             AND contact_id = ?""",
                        (owner_username, owner_device_id, contact_id),
                    ).fetchone()
                    if existing is not None:
                        return self._row_to_contact(existing)
                raise ValueError("contact already exists") from exc
            raise
        return contact

    def create_contact_request(
        self,
        requester_username: str,
        requester_device_id: int,
        recipient_username: str,
        recipient_device_id: int,
        alias: Optional[str] = None,
    ) -> ContactRequestRecord:
        with self._lock:
            requester = self._get_device_locked(requester_username, requester_device_id)
            recipient = self._get_device_locked(recipient_username, recipient_device_id)
            if requester is None:
                raise KeyError(
                    f"no such requester device: {(requester_username, requester_device_id)}"
                )
            if recipient is None:
                raise KeyError(
                    f"no such recipient device: {(recipient_username, recipient_device_id)}"
                )
            if (
                requester_username == recipient_username
                and requester_device_id == recipient_device_id
            ):
                raise ValueError("cannot request your own device")

            existing_contact = self._conn.execute(
                """SELECT 1
                   FROM contacts
                   WHERE (
                       owner_username = ?
                       AND owner_device_id = ?
                       AND contact_id = ?
                   ) OR (
                       owner_username = ?
                       AND owner_device_id = ?
                       AND contact_id = ?
                   )""",
                (
                    requester_username,
                    requester_device_id,
                    f"{recipient_username}:{recipient_device_id}",
                    recipient_username,
                    recipient_device_id,
                    f"{requester_username}:{requester_device_id}",
                ),
            ).fetchone()
            if existing_contact is not None:
                raise ValueError("contact already exists")

            reverse_pending = self._conn.execute(
                """SELECT 1
                   FROM contact_requests
                   WHERE status = 'pending'
                     AND requester_username = ?
                     AND requester_device_id = ?
                     AND recipient_username = ?
                     AND recipient_device_id = ?""",
                (
                    recipient_username,
                    recipient_device_id,
                    requester_username,
                    requester_device_id,
                ),
            ).fetchone()
            if reverse_pending is not None:
                raise ValueError("request already pending")

            import secrets as _secrets

            request_id = f"req-{_secrets.token_urlsafe(18)}"
            while (
                self._conn.execute(
                    "SELECT 1 FROM contact_requests WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                is not None
            ):
                request_id = f"req-{_secrets.token_urlsafe(18)}"
            now = _now()
            request = ContactRequestRecord(
                request_id=request_id,
                requester_username=requester_username,
                requester_device_id=requester_device_id,
                recipient_username=recipient_username,
                recipient_device_id=recipient_device_id,
                requester_username_display=requester.username_display or requester.username,
                requester_username_hash=requester.username_hash,
                recipient_username_display=recipient.username_display or recipient.username,
                recipient_username_hash=recipient.username_hash,
                alias=alias,
                created_at=now,
                updated_at=now,
            )
            try:
                self._conn.execute(
                    """INSERT INTO contact_requests
                       (request_id, requester_username, requester_device_id,
                        recipient_username, recipient_device_id,
                        requester_username_display, requester_username_hash,
                        recipient_username_display, recipient_username_hash,
                        alias, status, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        request.request_id,
                        request.requester_username,
                        request.requester_device_id,
                        request.recipient_username,
                        request.recipient_device_id,
                        request.requester_username_display,
                        request.requester_username_hash,
                        request.recipient_username_display,
                        request.recipient_username_hash,
                        request.alias,
                        request.status,
                        request.created_at,
                        request.updated_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if self._is_contact_request_duplicate_integrity_error(exc):
                    raise ValueError("request already pending") from exc
                raise
            return request

    def list_contact_requests(
        self,
        username: str,
        device_id: int,
    ) -> List[ContactRequestRecord]:
        with self._lock:
            if self._get_device_locked(username, device_id) is None:
                raise KeyError(f"no such owner device: {(username, device_id)}")
            rows = self._conn.execute(
                """SELECT *
                   FROM contact_requests
                   WHERE status = 'pending'
                     AND (
                         (requester_username = ? AND requester_device_id = ?)
                         OR (recipient_username = ? AND recipient_device_id = ?)
                     )
                   ORDER BY created_at""",
                (username, device_id, username, device_id),
            ).fetchall()
            return [self._row_to_contact_request(row) for row in rows]

    def accept_contact_request(
        self,
        username: str,
        device_id: int,
        request_id: str,
    ) -> ContactRequestRecord:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                row = self._conn.execute(
                    """SELECT *
                       FROM contact_requests
                       WHERE request_id = ? AND status = 'pending'""",
                    (request_id,),
                ).fetchone()
                if row is None:
                    self._conn.execute("ROLLBACK")
                    raise KeyError("unknown contact request")
                request = self._row_to_contact_request(row)
                if request.recipient_username != username or request.recipient_device_id != device_id:
                    self._conn.execute("ROLLBACK")
                    raise PermissionError("only the recipient can accept this request")

                self._add_contact_locked(
                    request.requester_username,
                    request.requester_device_id,
                    request.recipient_username,
                    request.recipient_device_id,
                    alias=request.alias,
                    allow_existing=True,
                )
                self._add_contact_locked(
                    request.recipient_username,
                    request.recipient_device_id,
                    request.requester_username,
                    request.requester_device_id,
                    allow_existing=True,
                )
                request.status = "accepted"
                request.updated_at = _now()
                self._conn.execute(
                    """UPDATE contact_requests
                       SET status = ?, updated_at = ?
                       WHERE request_id = ?""",
                    (request.status, request.updated_at, request.request_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                if self._conn.in_transaction:
                    self._conn.execute("ROLLBACK")
                raise
            return request

    def deny_contact_request(
        self,
        username: str,
        device_id: int,
        request_id: str,
    ) -> ContactRequestRecord:
        with self._lock:
            row = self._conn.execute(
                """SELECT *
                   FROM contact_requests
                   WHERE request_id = ? AND status = 'pending'""",
                (request_id,),
            ).fetchone()
            if row is None:
                raise KeyError("unknown contact request")
            request = self._row_to_contact_request(row)
            if request.recipient_username != username or request.recipient_device_id != device_id:
                raise PermissionError("only the recipient can deny this request")

            request.status = "denied"
            request.updated_at = _now()
            self._conn.execute(
                """UPDATE contact_requests
                   SET status = ?, updated_at = ?
                   WHERE request_id = ?""",
                (request.status, request.updated_at, request.request_id),
            )
            return request

    def delete_contact(self, username: str, device_id: int, contact_id: str) -> bool:
        with self._lock:
            if self._get_device_locked(username, device_id) is None:
                raise KeyError(f"no such owner device: {(username, device_id)}")
            cursor = self._conn.execute(
                """DELETE FROM contacts
                   WHERE owner_username = ? AND owner_device_id = ? AND contact_id = ?""",
                (username, device_id, contact_id),
            )
            return cursor.rowcount > 0

    # -- prekey distribution -----------------------------------------------

    def take_prekey_bundle(self, username: str, device_id: int) -> Optional[dict]:
        """Return bundle copy, atomically consuming one one-time prekey."""
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                dev_row = self._conn.execute(
                    "SELECT bundle_json FROM devices WHERE username = ? AND device_id = ?",
                    (username, device_id),
                ).fetchone()
                if dev_row is None:
                    self._conn.execute("ROLLBACK")
                    return None

                bundle = json.loads(dev_row["bundle_json"])

                opk_row = self._conn.execute(
                    """SELECT opk_id, opk_pub FROM one_time_prekeys
                       WHERE username = ? AND device_id = ?
                       ORDER BY opk_id LIMIT 1""",
                    (username, device_id),
                ).fetchone()

                if opk_row is not None:
                    bundle["opk_id"] = opk_row["opk_id"]
                    bundle["opk_pub"] = opk_row["opk_pub"]
                    self._conn.execute(
                        "DELETE FROM one_time_prekeys WHERE username = ? AND device_id = ? AND opk_id = ?",
                        (username, device_id, opk_row["opk_id"]),
                    )
                else:
                    bundle["opk_id"] = None
                    bundle["opk_pub"] = None

                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

            return bundle

    # -- mailbox -----------------------------------------------------------

    def deliver(self, envelope: Envelope) -> None:
        """Store envelope in recipient mailbox.

        Raises :class:`KeyError` if the recipient device does not exist.
        """
        with self._lock:
            exists = self._conn.execute(
                "SELECT 1 FROM devices WHERE username = ? AND device_id = ?",
                (envelope.recipient_username, envelope.recipient_device_id),
            ).fetchone()
            if exists is None:
                raise KeyError(
                    f"no such recipient device: ({envelope.recipient_username!r}, {envelope.recipient_device_id})"
                )
            self._conn.execute(
                """INSERT INTO mailbox
                   (envelope_id, sender_username, sender_device_id,
                    recipient_username, recipient_device_id, kind, body_json, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    envelope.envelope_id,
                    envelope.sender_username,
                    envelope.sender_device_id,
                    envelope.recipient_username,
                    envelope.recipient_device_id,
                    envelope.kind,
                    json.dumps(envelope.body),
                    envelope.created_at,
                ),
            )

    def fetch_mailbox(self, username: str, device_id: int, drain: bool = True) -> List[Envelope]:
        """Return queued envelopes, optionally draining the mailbox atomically."""
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                rows = self._conn.execute(
                    """SELECT * FROM mailbox
                       WHERE recipient_username = ? AND recipient_device_id = ?
                       ORDER BY created_at""",
                    (username, device_id),
                ).fetchall()
                envelopes = [self._row_to_envelope(r) for r in rows]
                if drain and envelopes:
                    self._conn.execute(
                        "DELETE FROM mailbox WHERE recipient_username = ? AND recipient_device_id = ?",
                        (username, device_id),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

            return envelopes

    def pending_count(self, username: str, device_id: int) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM mailbox WHERE recipient_username = ? AND recipient_device_id = ?",
                (username, device_id),
            ).fetchone()
            return row["n"]

    # -- serialisation helpers ---------------------------------------------

    @staticmethod
    def _row_to_envelope(row: sqlite3.Row) -> Envelope:
        return Envelope(
            envelope_id=row["envelope_id"],
            sender_username=row["sender_username"],
            sender_device_id=row["sender_device_id"],
            recipient_username=row["recipient_username"],
            recipient_device_id=row["recipient_device_id"],
            kind=row["kind"],
            body=json.loads(row["body_json"]),
            created_at=row["created_at"],
        )

    @staticmethod
    def _row_to_contact(row: sqlite3.Row) -> Contact:
        return Contact(
            contact_id=row["contact_id"],
            owner_username=row["owner_username"],
            owner_device_id=row["owner_device_id"],
            contact_username=row["contact_username"],
            contact_device_id=row["contact_device_id"],
            username_display=row["username_display"],
            username_hash=row["username_hash"],
            alias=row["alias"],
            verified=bool(row["verified"]),
            created_at=row["created_at"],
        )

    @staticmethod
    def _row_to_contact_request(row: sqlite3.Row) -> ContactRequestRecord:
        return ContactRequestRecord(
            request_id=row["request_id"],
            requester_username=row["requester_username"],
            requester_device_id=row["requester_device_id"],
            recipient_username=row["recipient_username"],
            recipient_device_id=row["recipient_device_id"],
            requester_username_display=row["requester_username_display"],
            requester_username_hash=row["requester_username_hash"],
            recipient_username_display=row["recipient_username_display"],
            recipient_username_hash=row["recipient_username_hash"],
            alias=row["alias"],
            status=row["status"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
