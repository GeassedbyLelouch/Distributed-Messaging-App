"""
Server-side Sesame store: accounts, devices, prekey bundles, and mailboxes.

Deliberately captures **minimal metadata**: a username, an opaque per-device id,
a registration id, and timestamps. No phone numbers, emails, real names, or
contact graphs are stored. Devices publish public PQXDH prekey bundles; the
server hands them out (consuming one-time prekeys) and relays opaque encrypted
envelopes between devices. The store never sees private keys or plaintext.

This reference store is in-memory and thread-safe. Swapping in a database only
requires providing an alternative :class:`~ml_kem_braid.sesame.base.StoreBackend`
implementation — see :class:`~ml_kem_braid.sesame.sqlite_store.SqliteStore`.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from ml_kem_braid.sesame.base import StoreBackend
from ml_kem_braid.sesame.usernames import UsernameValidationError, normalize_username


def _now() -> float:
    return time.time()


@dataclass
class Account:
    """A user account, keyed by username (the only required identifier)."""

    username: str
    # Ed25519 identity public key the username is pinned to (trust-on-first-use).
    # Subsequent registrations must prove possession of this key.
    identity_key: bytes = b""
    created_at: float = field(default_factory=_now)
    devices: Dict[int, "Device"] = field(default_factory=dict)
    username_display: str = ""
    username_hash: str = ""


@dataclass
class Device:
    """A single device belonging to an account."""

    username: str
    device_id: int
    registration_id: int
    # Public PQXDH prekey bundle, serialised as a JSON-compatible dict by the
    # transport layer. The store treats it as an opaque mapping.
    bundle: dict
    # Auth token the device uses to fetch its own mailbox.
    auth_token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    created_at: float = field(default_factory=_now)
    last_seen: float = field(default_factory=_now)
    # Remaining one-time prekeys, keyed by opk_id -> serialised public key.
    one_time_prekeys: Dict[int, str] = field(default_factory=dict)
    username_display: str = ""
    username_hash: str = ""


@dataclass
class Envelope:
    """An opaque ciphertext relayed from one device to another."""

    envelope_id: str
    sender_username: str
    sender_device_id: int
    recipient_username: str
    recipient_device_id: int
    kind: str  # "pqxdh_init" | "braid" | "chat"
    body: dict  # JSON-compatible payload (base64 fields), opaque to the server
    created_at: float = field(default_factory=_now)


@dataclass
class Contact:
    """A contact saved by one device."""

    contact_id: str
    owner_username: str
    owner_device_id: int
    contact_username: str
    contact_device_id: int
    username_display: str
    username_hash: str
    alias: Optional[str] = None
    verified: bool = False
    created_at: float = field(default_factory=_now)


@dataclass
class ContactRequestRecord:
    """A pending social contact request between two devices."""

    request_id: str
    requester_username: str
    requester_device_id: int
    recipient_username: str
    recipient_device_id: int
    requester_username_display: str
    requester_username_hash: str
    recipient_username_display: str
    recipient_username_hash: str
    alias: Optional[str] = None
    status: str = "pending"
    created_at: float = field(default_factory=_now)
    updated_at: float = field(default_factory=_now)


class SesameStore(StoreBackend):
    """Thread-safe in-memory account/device/mailbox store.

    Implements :class:`~ml_kem_braid.sesame.base.StoreBackend`.
    Importing from ``ml_kem_braid.sesame`` remains fully backwards-compatible.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._accounts: Dict[str, Account] = {}
        self._mailboxes: Dict[tuple[str, int], Deque[Envelope]] = {}
        self._by_token: Dict[str, tuple[str, int]] = {}
        self._by_username_hash: Dict[str, str] = {}
        self._contacts: Dict[tuple[str, int], Dict[str, Contact]] = {}
        self._contact_requests: Dict[str, ContactRequestRecord] = {}

    # -- registration ------------------------------------------------------

    def register_device(
        self,
        username: str,
        registration_id: int,
        bundle: dict,
        identity_key: bytes,
        one_time_prekeys: Optional[Dict[int, str]] = None,
    ) -> Device:
        """
        Register a new device for ``username`` (server assigns a fresh device id;
        existing devices are never overwritten, so a mailbox cannot be hijacked).

        The username is pinned to ``identity_key`` on first registration; later
        registrations must present the same identity key (the caller is expected
        to have already verified a possession proof for it).

        Raises:
            PermissionError: if ``identity_key`` differs from the account's pin.
        """
        with self._lock:
            try:
                normalized = normalize_username(username)
            except UsernameValidationError:
                normalized = None

            if normalized is not None:
                existing_username = self._by_username_hash.get(normalized.lookup_hash)
                if existing_username is not None and existing_username != username:
                    raise PermissionError("username hash is already registered")

            account = self._accounts.get(username)
            if account is None:
                account = Account(
                    username=username,
                    identity_key=identity_key,
                    username_display=normalized.display if normalized else username,
                    username_hash=normalized.lookup_hash if normalized else "",
                )
                self._accounts[username] = account
                if normalized is not None:
                    self._by_username_hash[normalized.lookup_hash] = username
            elif account.identity_key != identity_key:
                raise PermissionError(
                    f"username '{username}' is bound to a different identity key"
                )

            device_id = (max(account.devices) + 1) if account.devices else 1
            device = Device(
                username=username,
                device_id=device_id,
                registration_id=registration_id,
                bundle=bundle,
                one_time_prekeys=dict(one_time_prekeys or {}),
                username_display=normalized.display if normalized else username,
                username_hash=normalized.lookup_hash if normalized else "",
            )
            account.devices[device_id] = device
            self._mailboxes.setdefault((username, device_id), deque())
            self._contacts.setdefault((username, device_id), {})
            self._by_token[device.auth_token] = (username, device_id)
            return device

    # -- lookup ------------------------------------------------------------

    def get_account(self, username: str) -> Optional[Account]:
        with self._lock:
            return self._accounts.get(username)

    def list_devices(self, username: str) -> List[Device]:
        with self._lock:
            account = self._accounts.get(username)
            return list(account.devices.values()) if account else []

    def get_device(self, username: str, device_id: int) -> Optional[Device]:
        with self._lock:
            account = self._accounts.get(username)
            return account.devices.get(device_id) if account else None

    def device_for_token(self, token: str) -> Optional[Device]:
        with self._lock:
            ref = self._by_token.get(token)
            if ref is None:
                return None
            device = self.get_device(*ref)
            if device is not None:
                device.last_seen = _now()
            return device

    def find_device_by_username(self, username: str) -> Optional[Device]:
        normalized = normalize_username(username)
        with self._lock:
            account_username = self._by_username_hash.get(normalized.lookup_hash)
            if account_username is None:
                return None
            account = self._accounts.get(account_username)
            if account is None or not account.devices:
                return None
            return account.devices[min(account.devices)]

    def list_contacts(self, username: str, device_id: int) -> List[Contact]:
        with self._lock:
            if self.get_device(username, device_id) is None:
                raise KeyError(f"no such owner device: {(username, device_id)}")
            contacts = self._contacts.get((username, device_id), {})
            return sorted(contacts.values(), key=lambda contact: contact.created_at)

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
        owner = self.get_device(owner_username, owner_device_id)
        target = self.get_device(contact_username, contact_device_id)
        if owner is None:
            raise KeyError(f"no such owner device: {(owner_username, owner_device_id)}")
        if target is None:
            raise KeyError(f"no such contact device: {(contact_username, contact_device_id)}")

        contact_id = f"{contact_username}:{contact_device_id}"
        contacts = self._contacts.setdefault((owner_username, owner_device_id), {})
        existing = contacts.get(contact_id)
        if existing is not None:
            if allow_existing:
                return existing
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
        )
        contacts[contact_id] = contact
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
            requester = self.get_device(requester_username, requester_device_id)
            recipient = self.get_device(recipient_username, recipient_device_id)
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

            requester_contacts = self._contacts.get((requester_username, requester_device_id), {})
            recipient_contacts = self._contacts.get((recipient_username, recipient_device_id), {})
            if (
                f"{recipient_username}:{recipient_device_id}" in requester_contacts
                or f"{requester_username}:{requester_device_id}" in recipient_contacts
            ):
                raise ValueError("contact already exists")

            for existing in self._contact_requests.values():
                if existing.status != "pending":
                    continue
                same_pair = (
                    existing.requester_username == requester_username
                    and existing.requester_device_id == requester_device_id
                    and existing.recipient_username == recipient_username
                    and existing.recipient_device_id == recipient_device_id
                )
                reverse_pair = (
                    existing.requester_username == recipient_username
                    and existing.requester_device_id == recipient_device_id
                    and existing.recipient_username == requester_username
                    and existing.recipient_device_id == requester_device_id
                )
                if same_pair or reverse_pair:
                    raise ValueError("request already pending")

            request_id = f"req-{secrets.token_urlsafe(18)}"
            while request_id in self._contact_requests:
                request_id = f"req-{secrets.token_urlsafe(18)}"
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
            self._contact_requests[request_id] = request
            return request

    def list_contact_requests(
        self,
        username: str,
        device_id: int,
    ) -> List[ContactRequestRecord]:
        with self._lock:
            if self.get_device(username, device_id) is None:
                raise KeyError(f"no such owner device: {(username, device_id)}")
            requests = [
                request
                for request in self._contact_requests.values()
                if request.status == "pending"
                and (
                    (
                        request.requester_username == username
                        and request.requester_device_id == device_id
                    )
                    or (
                        request.recipient_username == username
                        and request.recipient_device_id == device_id
                    )
                )
            ]
            return sorted(requests, key=lambda request: request.created_at)

    def accept_contact_request(
        self,
        username: str,
        device_id: int,
        request_id: str,
    ) -> ContactRequestRecord:
        with self._lock:
            request = self._contact_requests.get(request_id)
            if request is None or request.status != "pending":
                raise KeyError("unknown contact request")
            if request.recipient_username != username or request.recipient_device_id != device_id:
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
            return request

    def deny_contact_request(
        self,
        username: str,
        device_id: int,
        request_id: str,
    ) -> ContactRequestRecord:
        with self._lock:
            request = self._contact_requests.get(request_id)
            if request is None or request.status != "pending":
                raise KeyError("unknown contact request")
            if request.recipient_username != username or request.recipient_device_id != device_id:
                raise PermissionError("only the recipient can deny this request")

            request.status = "denied"
            request.updated_at = _now()
            return request

    def delete_contact(self, username: str, device_id: int, contact_id: str) -> bool:
        with self._lock:
            if self.get_device(username, device_id) is None:
                raise KeyError(f"no such owner device: {(username, device_id)}")
            contacts = self._contacts.get((username, device_id))
            if not contacts or contact_id not in contacts:
                return False
            del contacts[contact_id]
            return True

    # -- prekey distribution ----------------------------------------------

    def take_prekey_bundle(self, username: str, device_id: int) -> Optional[dict]:
        """
        Return a copy of the device's bundle for a new session, consuming one
        one-time prekey if any remain (Sesame/PQXDH one-time-prekey semantics).
        """
        with self._lock:
            device = self.get_device(username, device_id)
            if device is None:
                return None
            bundle = dict(device.bundle)
            if device.one_time_prekeys:
                opk_id = next(iter(device.one_time_prekeys))
                opk_pub = device.one_time_prekeys.pop(opk_id)
                bundle["opk_id"] = opk_id
                bundle["opk_pub"] = opk_pub
            else:
                bundle["opk_id"] = None
                bundle["opk_pub"] = None
            return bundle

    # -- mailbox -----------------------------------------------------------

    def deliver(self, envelope: Envelope) -> None:
        with self._lock:
            key = (envelope.recipient_username, envelope.recipient_device_id)
            if key not in self._mailboxes:
                raise KeyError(f"no such recipient device: {key}")
            self._mailboxes[key].append(envelope)

    def fetch_mailbox(self, username: str, device_id: int, drain: bool = True) -> List[Envelope]:
        with self._lock:
            mailbox = self._mailboxes.get((username, device_id))
            if not mailbox:
                return []
            items = list(mailbox)
            if drain:
                mailbox.clear()
            return items

    def pending_count(self, username: str, device_id: int) -> int:
        with self._lock:
            return len(self._mailboxes.get((username, device_id), ()))
