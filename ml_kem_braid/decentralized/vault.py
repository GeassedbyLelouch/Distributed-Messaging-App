from __future__ import annotations

import json
import os
from copy import deepcopy
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from ml_kem_braid.core.aead import CounterAeadKey
from ml_kem_braid.decentralized.canonical import canonical_json
from ml_kem_braid.decentralized.records import SignedRecord, verify_record


_VAULT_INFO = b"ml-kem-braid:client-vault:v1"


@runtime_checkable
class MonotonicVersionSource(Protocol):
    """Source of per-slot version numbers that only ever increase.

    This is the trust seam for rollback resistance (verifier D16). The vault
    can prove a *ciphertext* is stale — the version is bound into the AEAD
    associated data, so a sealed blob from version N cannot be opened at
    version N+1 without the at-rest key. What it cannot do by itself is know
    which version is current: that fact has to come from storage the rollback
    adversary does not control (a TPM/TEE monotonic counter, a secure element,
    a server-side counter). Implement this protocol against such a counter and
    the guarantee becomes real; the in-process default below does not have it.
    """

    def next_version(self, slot: str) -> int:
        """Allocate and return the next version for ``slot`` (strictly up)."""

    def current_version(self, slot: str) -> int:
        """The most recently allocated version for ``slot`` (0 if none)."""


class _InProcessVersionSource:
    """Default version source: a plain in-memory counter.

    Deliberately NOT trusted state. An adversary who can roll the vault's
    storage back can roll this dict back with it, so with this source the vault
    offers *no* rollback resistance — see :class:`InMemoryClientVault`.
    """

    __slots__ = ("_versions",)

    def __init__(self) -> None:
        self._versions: Dict[str, int] = {}

    def next_version(self, slot: str) -> int:
        version = self._versions.get(slot, 0) + 1
        self._versions[slot] = version
        return version

    def current_version(self, slot: str) -> int:
        return self._versions.get(slot, 0)


class InMemoryClientVault:
    """In-memory storage for minimal client-local decentralized state.

    Audit L14 — at-rest contract. The reference implementation keeps state in
    process memory only, but everything it holds is nevertheless:

    * **sealed** with AES-256-GCM under a key derived from ``at_rest_key`` (a
      random per-process key when the caller supplies none), so a persistent
      backend can reuse this class verbatim by handing it a key derived from
      the user's passphrase/OS keystore. Nonces come from a monotonic counter
      (:class:`~ml_kem_braid.core.aead.CounterAeadKey`), never from
      ``os.urandom`` — the vault key seals many messages, which is exactly the
      case the M4 single-use random-nonce discipline forbids (verifier D17);
    * **authenticated** — contact records are verified against the author's
      signature before they are trusted and stored, and each sealed blob binds
      its slot and version into the AEAD associated data.

    Rollback resistance — precise claim (verifier D16)
    --------------------------------------------------
    An earlier docstring advertised this class as "rollback-guarded" on the
    strength of a version counter that lived in the very same in-memory
    structure the postulated attacker controls. Rolling back the store rolled
    back the counter too, so the guard detected nothing and the claim was
    simply false. What is actually true:

    * a **stale ciphertext** cannot be substituted. The version is in the AEAD
      associated data, so a blob sealed at version N fails authentication when
      opened at version N+1, and forging one requires the at-rest key;
    * a **whole-store rollback** is detected only if ``version_source`` is
      backed by a counter the attacker cannot rewind (TPM/TEE/secure element/
      server). With the default in-process counter it is NOT detected, and this
      class makes no such claim.

    Pass a ``version_source`` implementing :class:`MonotonicVersionSource` to
    obtain the real guarantee.

    Python ``bytes`` cannot be wiped, so plaintext secrets still leak into the
    heap while in use (audit L5); the Rust port owns that fix.
    """

    def __init__(
        self,
        at_rest_key: Optional[bytes] = None,
        *,
        version_source: Optional[MonotonicVersionSource] = None,
    ) -> None:
        if at_rest_key is None:
            at_rest_key = os.urandom(32)
        if not isinstance(at_rest_key, bytes):
            raise TypeError("at_rest_key must be bytes")
        if len(at_rest_key) != 32:
            raise ValueError("at_rest_key must be 32 bytes (AES-256)")
        # Counter nonces: the vault key is multi-use by construction, so the
        # random-nonce path in core.aead is not an option (verifier D17).
        self._aead = CounterAeadKey(at_rest_key)
        self._versions: MonotonicVersionSource = (
            _InProcessVersionSource() if version_source is None else version_source
        )
        self._identities: Dict[str, tuple[int, int, bytes]] = {}
        self._sessions: Dict[str, tuple[int, int, bytes]] = {}
        self._contact_records: Dict[str, List[dict[str, Any]]] = {}
        self._contact_sequences: Dict[str, int] = {}

    # -- sealing -------------------------------------------------------------

    def _next_version(self, slot: str) -> int:
        return self._versions.next_version(slot)

    def _associated_data(self, slot: str, version: int) -> bytes:
        return b"".join(
            [
                _VAULT_INFO,
                len(slot.encode("utf-8")).to_bytes(4, "big"),
                slot.encode("utf-8"),
                version.to_bytes(8, "big"),
            ]
        )

    def _seal(self, slot: str, version: int, plaintext: bytes) -> tuple[int, bytes]:
        return self._aead.seal(plaintext, self._associated_data(slot, version))

    def _open(self, slot: str, version: int, counter: int, sealed: bytes) -> bytes:
        return self._aead.open(counter, sealed, self._associated_data(slot, version))

    def _authoritative_version(self, slot: str, stored_version: int) -> int:
        """Reject a slot whose sealed version is not the current one."""

        current = self._versions.current_version(slot)
        if stored_version != current:
            raise ValueError(f"vault rollback detected for {slot}")
        return current

    # -- identities ----------------------------------------------------------

    def store_identity(self, username: str, identity_secret: bytes) -> None:
        if not isinstance(identity_secret, bytes):
            raise TypeError("identity_secret must be bytes")
        slot = f"identity:{username}"
        version = self._next_version(slot)
        counter, sealed = self._seal(slot, version, bytes(identity_secret))
        self._identities[username] = (version, counter, sealed)

    def load_identity(self, username: str) -> Optional[bytes]:
        entry = self._identities.get(username)
        if entry is None:
            return None
        version, counter, sealed = entry
        slot = f"identity:{username}"
        current = self._authoritative_version(slot, version)
        return self._open(slot, current, counter, sealed)

    # -- sessions ------------------------------------------------------------

    def store_session(
        self,
        conversation_id: str,
        peer_identity: bytes,
        state: dict[str, Any],
    ) -> None:
        if not isinstance(peer_identity, bytes):
            raise TypeError("peer_identity must be bytes")
        slot = f"session:{conversation_id}"
        version = self._next_version(slot)
        plaintext = canonical_json(
            {
                "peer_identity": peer_identity.hex(),
                "state": state,
            }
        )
        counter, sealed = self._seal(slot, version, plaintext)
        self._sessions[conversation_id] = (version, counter, sealed)

    def load_session(self, conversation_id: str) -> Optional[dict[str, Any]]:
        entry = self._sessions.get(conversation_id)
        if entry is None:
            return None
        version, counter, sealed = entry
        slot = f"session:{conversation_id}"
        current = self._authoritative_version(slot, version)
        return json.loads(self._open(slot, current, counter, sealed).decode("utf-8"))

    def session_version(self, conversation_id: str) -> Optional[int]:
        entry = self._sessions.get(conversation_id)
        return None if entry is None else entry[0]

    # -- contact records -----------------------------------------------------

    def append_contact_record(
        self,
        conversation_id: str,
        record: dict[str, Any],
        *,
        public_key: Optional[bytes] = None,
        at_ms: Optional[int] = None,
    ) -> None:
        """Append a contact record after verifying its author signature.

        Audit L14: records used to be trusted purely because they arrived, and
        nothing stopped an older ``sequence`` being appended after a newer one
        (rollback). Both are now checked before anything is stored.
        """

        if not isinstance(record, dict):
            raise TypeError("record must be a dict")
        sequence = record.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise ValueError("record sequence must be an int")

        signed = SignedRecord.from_dict(record)
        verifier = signed.author_identity if public_key is None else public_key
        if not verify_record(signed, verifier, at_ms=at_ms):
            raise PermissionError("contact record signature verification failed")

        last_sequence = self._contact_sequences.get(conversation_id)
        if last_sequence is not None and sequence <= last_sequence:
            raise ValueError("contact record sequence must be strictly increasing")

        self._contact_records.setdefault(conversation_id, []).append(deepcopy(record))
        self._contact_sequences[conversation_id] = sequence

    def load_contact_records(self, conversation_id: str) -> list[dict[str, Any]]:
        records = self._contact_records.get(conversation_id, [])
        return deepcopy(sorted(records, key=lambda record: record["sequence"]))
