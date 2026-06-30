"""
Abstract base for Sesame store backends.

Any implementation that satisfies this interface can be wired into the server
via ``create_app(store=...)``.  The in-memory :class:`~ml_kem_braid.sesame.store.SesameStore`
and the durable :class:`~ml_kem_braid.sesame.sqlite_store.SqliteStore` both subclass this.

Note: type hints reference the dataclasses by string to avoid a circular import
with :mod:`ml_kem_braid.sesame.store` (which defines the dataclasses *and* the
first concrete backend).  At runtime the real classes are always resolved.
"""

from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from ml_kem_braid.sesame.store import (
        Account,
        Contact,
        ContactRequestRecord,
        Device,
        Envelope,
    )


class StoreBackend(abc.ABC):
    """Interface every Sesame store backend must implement.

    All methods must be thread-safe.  Callers never see backend internals;
    they only interact with :class:`~ml_kem_braid.sesame.store.Account`,
    :class:`~ml_kem_braid.sesame.store.Device`, and
    :class:`~ml_kem_braid.sesame.store.Envelope` dataclasses.
    """

    # -- registration -------------------------------------------------------

    @abc.abstractmethod
    def register_device(
        self,
        username: str,
        registration_id: int,
        bundle: dict,
        identity_key: bytes,
        one_time_prekeys: Optional[Dict[int, str]] = None,
    ) -> "Device":
        """Register a new device and return it (server assigns device_id).

        On first registration the username is pinned to ``identity_key``
        (trust-on-first-use).  Subsequent registrations must present the same
        key; a different key raises :class:`PermissionError`.
        """

    # -- lookup -------------------------------------------------------------

    @abc.abstractmethod
    def get_account(self, username: str) -> "Optional[Account]":
        """Return the :class:`~ml_kem_braid.sesame.store.Account` for ``username``, or ``None``."""

    @abc.abstractmethod
    def list_devices(self, username: str) -> "List[Device]":
        """Return all :class:`~ml_kem_braid.sesame.store.Device` objects registered to ``username``."""

    @abc.abstractmethod
    def get_device(self, username: str, device_id: int) -> "Optional[Device]":
        """Return the device identified by ``(username, device_id)``, or ``None``."""

    @abc.abstractmethod
    def device_for_token(self, token: str) -> "Optional[Device]":
        """Return the device that owns ``token`` and bump its ``last_seen``."""

    @abc.abstractmethod
    def find_device_by_username(self, username: str) -> "Optional[Device]":
        """Return the first device for an exact Signal-style username lookup."""

    @abc.abstractmethod
    def list_contacts(self, username: str, device_id: int) -> "List[Contact]":
        """Return contacts owned by the device."""

    @abc.abstractmethod
    def add_contact(
        self,
        owner_username: str,
        owner_device_id: int,
        contact_username: str,
        contact_device_id: int,
        alias: Optional[str] = None,
    ) -> "Contact":
        """Add a contact to the owner's contact book."""

    @abc.abstractmethod
    def delete_contact(self, username: str, device_id: int, contact_id: str) -> bool:
        """Delete a contact owned by the device. Return True when deleted."""

    @abc.abstractmethod
    def create_contact_request(
        self,
        requester_username: str,
        requester_device_id: int,
        recipient_username: str,
        recipient_device_id: int,
        alias: Optional[str] = None,
    ) -> "ContactRequestRecord":
        """Create a pending contact request from requester to recipient."""

    @abc.abstractmethod
    def list_contact_requests(
        self,
        username: str,
        device_id: int,
    ) -> "List[ContactRequestRecord]":
        """Return pending contact requests involving the device."""

    @abc.abstractmethod
    def accept_contact_request(
        self,
        username: str,
        device_id: int,
        request_id: str,
    ) -> "ContactRequestRecord":
        """Accept a pending inbound request and create reciprocal contacts."""

    @abc.abstractmethod
    def deny_contact_request(
        self,
        username: str,
        device_id: int,
        request_id: str,
    ) -> "ContactRequestRecord":
        """Deny a pending inbound request without creating contacts."""

    # -- prekey distribution ------------------------------------------------

    @abc.abstractmethod
    def take_prekey_bundle(self, username: str, device_id: int) -> Optional[dict]:
        """Return a copy of the device bundle, consuming one one-time prekey.

        If no one-time prekeys remain, ``opk_id`` and ``opk_pub`` are both
        ``None`` in the returned dict.  Returns ``None`` if the device does not
        exist.
        """

    # -- mailbox ------------------------------------------------------------

    @abc.abstractmethod
    def deliver(self, envelope: "Envelope") -> None:
        """Append ``envelope`` to the recipient's mailbox.

        Raises :class:`KeyError` if the recipient device does not exist.
        """

    @abc.abstractmethod
    def fetch_mailbox(self, username: str, device_id: int, drain: bool = True) -> "List[Envelope]":
        """Return queued envelopes; clear the mailbox if ``drain`` is ``True``."""

    @abc.abstractmethod
    def pending_count(self, username: str, device_id: int) -> int:
        """Return the number of envelopes currently queued for the device."""
