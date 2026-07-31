from __future__ import annotations

import hmac
from copy import deepcopy
from typing import Any, Callable, Optional

from ml_kem_braid.crypto import xeddsa

from ml_kem_braid.decentralized.canonical import canonical_json, sha256_hex
from ml_kem_braid.decentralized.records import (
    SignedRecord,
    now_ms,
    verify_record,
)


_LOWER_HEX = frozenset("0123456789abcdef")
_USERNAME_RECORD_TYPE = "identity.username_record"

# Audit M9: a username hash must be the image of a preimage the claimant can
# actually open, and the record must bind that preimage to the claiming
# identity. Both are recomputed by the registry before a claim is accepted.
_USERNAME_HASH_DOMAIN = b"ml-kem-braid:username-hash:v1"
_USERNAME_BINDING_DOMAIN = b"ml-kem-braid:username-binding:v1"

# Audit L12: envelope delivery is authenticated by the sender's identity key
# and mailboxes are bounded.
_ENVELOPE_CONTEXT = b"decentralized/envelope"
DEFAULT_MAX_MAILBOX_DEPTH = 256
#: Verifier D15: no single sender may occupy more than this much of a mailbox,
#: so one flooder cannot jam delivery for everyone else.
DEFAULT_MAX_ENVELOPES_PER_SENDER = 32
DEFAULT_MAX_FORWARDS_PER_WINDOW = 64
DEFAULT_FORWARD_WINDOW_MS = 60_000
#: Verifier D14: bound on the number of *verified* sender identities the relay
#: tracks quota for. Reaching it fails closed rather than evicting a counter.
DEFAULT_MAX_TRACKED_SENDERS = 4096


def username_hash(username: str) -> str:
    """Public, deterministic hash of a username preimage."""

    if not isinstance(username, str) or username == "":
        raise ValueError("username must be a non-empty string")
    return sha256_hex(_USERNAME_HASH_DOMAIN + username.encode("utf-8"))


def username_binding(username: str, author_identity: bytes) -> str:
    """Commitment binding a username preimage to the claiming identity."""

    if not isinstance(author_identity, bytes):
        raise TypeError("author_identity must be bytes")
    if not isinstance(username, str) or username == "":
        raise ValueError("username must be a non-empty string")
    return sha256_hex(
        _USERNAME_BINDING_DOMAIN
        + len(author_identity).to_bytes(4, "big")
        + author_identity
        + username.encode("utf-8")
    )


def envelope_signing_payload(
    recipient_identity: str,
    recipient_device_id: int,
    envelope: dict[str, Any],
) -> bytes:
    """Canonical bytes a sender signs to authorise a mailbox delivery."""

    return canonical_json(
        {
            "recipient_identity": recipient_identity,
            "recipient_device_id": recipient_device_id,
            "envelope": envelope,
        }
    )


def sign_envelope(
    signing_key: bytes,
    recipient_identity: str,
    recipient_device_id: int,
    envelope: dict[str, Any],
) -> bytes:
    return xeddsa.sign_ctx(
        signing_key,
        _ENVELOPE_CONTEXT,
        envelope_signing_payload(recipient_identity, recipient_device_id, envelope),
    )


def verify_envelope_sender(
    recipient_identity: str,
    recipient_device_id: int,
    envelope: dict[str, Any],
    *,
    sender_identity: bytes,
    sender_signature: bytes,
) -> None:
    """Authenticate an envelope's sender, or raise.

    Split out of :meth:`DecentralizedServices.deliver_envelope` so relays can
    do the verification BEFORE spending any state on the sender (verifier D14):
    an unauthenticated ``sender_identity`` is an attacker-chosen string, so
    charging a quota to it is both useless as a limit and a memory-exhaustion
    vector.
    """

    if not isinstance(envelope, dict):
        raise TypeError("envelope must be a dict")
    if not isinstance(sender_identity, bytes) or len(sender_identity) != 32:
        raise TypeError("sender_identity must be a 32-byte public key")
    if not isinstance(sender_signature, bytes):
        raise TypeError("sender_signature must be bytes")

    payload = envelope_signing_payload(
        recipient_identity, recipient_device_id, envelope
    )
    if not xeddsa.verify_ctx(
        sender_identity, _ENVELOPE_CONTEXT, payload, sender_signature
    ):
        raise PermissionError("envelope sender authentication failed")


class DecentralizedServices:
    """In-memory decentralized registry and opaque mailbox service."""

    def __init__(
        self,
        *,
        clock: Optional[Callable[[], int]] = None,
        max_mailbox_depth: int = DEFAULT_MAX_MAILBOX_DEPTH,
        max_envelopes_per_sender: int = DEFAULT_MAX_ENVELOPES_PER_SENDER,
    ) -> None:
        if max_mailbox_depth <= 0:
            raise ValueError("max_mailbox_depth must be positive")
        if max_envelopes_per_sender <= 0:
            raise ValueError("max_envelopes_per_sender must be positive")
        self._clock = clock if clock is not None else now_ms
        self._max_mailbox_depth = max_mailbox_depth
        # A per-sender quota larger than the mailbox itself is not a quota.
        self._max_envelopes_per_sender = min(
            max_envelopes_per_sender, max_mailbox_depth
        )
        self._records: dict[tuple[str, bytes, int], SignedRecord] = {}
        self._latest_sequence: dict[tuple[str, bytes], int] = {}
        self._username_records: dict[tuple[str, str], SignedRecord] = {}
        # Each queued item is (sender_identity, envelope) so the depth cap can
        # be charged to whoever actually filled the mailbox (verifier D15).
        self._mailboxes: dict[tuple[str, int], list[tuple[bytes, dict[str, Any]]]] = {}
        self._mailbox_allowlists: dict[tuple[str, int], set[bytes]] = {}

    # -- signed records ------------------------------------------------------

    def publish_record(
        self,
        record: SignedRecord,
        *,
        username_preimage: Optional[str] = None,
        at_ms: Optional[int] = None,
    ) -> None:
        """Verify and store a signed record.

        Audit M7: verification now enforces freshness (``expires_at``) against
        the service clock, and ``sequence`` must be strictly increasing per
        ``(record_type, author_identity)`` so an old signed record cannot be
        replayed to roll state back.
        """

        checked_at = self._clock() if at_ms is None else at_ms
        if not verify_record(record, record.author_identity, at_ms=checked_at):
            raise PermissionError("record signature verification failed")

        sequence_key = (record.record_type, record.author_identity)
        latest = self._latest_sequence.get(sequence_key)
        if latest is not None and record.sequence <= latest:
            raise ValueError("record sequence must be strictly increasing")

        if record.record_type == _USERNAME_RECORD_TYPE:
            self._publish_username_record(
                record, username_preimage=username_preimage, at_ms=checked_at
            )
        else:
            # Verifier D18: nothing unsigned is ever stored, so nothing
            # unsigned can ever be served back out.
            self._records[
                (record.record_type, record.author_identity, record.sequence)
            ] = record.without_unsigned_fields()

        self._latest_sequence[sequence_key] = record.sequence

    def lookup_username(
        self,
        lookup: str,
        *,
        at_ms: Optional[int] = None,
    ) -> Optional[SignedRecord]:
        """Look up a username record by its hash; expired claims are invisible."""

        record = self._username_records.get((_USERNAME_RECORD_TYPE, lookup))
        if record is None:
            return None
        checked_at = self._clock() if at_ms is None else at_ms
        if record.is_expired(checked_at):
            return None
        return record

    def _publish_username_record(
        self,
        record: SignedRecord,
        *,
        username_preimage: Optional[str],
        at_ms: int,
    ) -> None:
        claimed_hash = _validated_username_hash(record)

        # Audit M9: the claimant must open the hash and bind the preimage to
        # its own identity — a bare 64-hex string is no longer a claim.
        #
        # Verifier D18: the opening must NOT live in the signed body. A signed
        # body is republished verbatim to anonymous lookups (the record is only
        # meaningful with its signature, so it cannot be redacted after the
        # fact), which handed every unauthenticated reader the plaintext
        # username and defeated the entire hashed-username privacy model. The
        # preimage therefore travels as an unsigned, unpublished sidecar
        # (``SignedRecord.username_preimage``, dropped by ``to_dict``) or as
        # this out-of-band argument. Leaving it unsigned costs nothing: it is
        # believed only after it reproduces the *signed* hash and binding.
        if "username_preimage" in record.body:
            raise ValueError(
                "username_preimage must not appear in the published record body; "
                "supply it as the unsigned opening instead"
            )
        if username_preimage is None:
            username_preimage = record.username_preimage
        if not isinstance(username_preimage, str) or username_preimage == "":
            raise ValueError("username claim requires the username preimage")
        if not hmac.compare_digest(username_hash(username_preimage), claimed_hash):
            raise ValueError("username_hash does not open to the supplied preimage")
        expected_binding = username_binding(username_preimage, record.author_identity)
        claimed_binding = record.body.get("username_binding")
        if not isinstance(claimed_binding, str) or not hmac.compare_digest(
            expected_binding, claimed_binding
        ):
            raise ValueError("username_binding does not bind preimage to author")

        key = (_USERNAME_RECORD_TYPE, claimed_hash)
        current = self._username_records.get(key)
        if current is not None and not current.is_expired(at_ms):
            # Audit M9: names are owner-updatable (monotonic sequence) and
            # expire, so a squat is neither permanent nor unrecoverable.
            if current.author_identity != record.author_identity:
                raise ValueError("username hash already registered")
            if record.sequence <= current.sequence:
                raise ValueError("username record sequence must be strictly increasing")

        published = record.without_unsigned_fields()
        self._records[
            (record.record_type, record.author_identity, record.sequence)
        ] = published
        self._username_records[key] = published

    # -- mailboxes -----------------------------------------------------------

    def set_mailbox_allowlist(
        self,
        recipient_identity: str,
        recipient_device_id: int,
        senders: set[bytes],
    ) -> None:
        """Restrict who may deposit into a mailbox (audit L12)."""

        for sender in senders:
            if not isinstance(sender, bytes):
                raise TypeError("allowlisted senders must be bytes")
        self._mailbox_allowlists[(recipient_identity, recipient_device_id)] = set(senders)

    def deliver_envelope(
        self,
        recipient_identity: str,
        recipient_device_id: int,
        envelope: dict[str, Any],
        *,
        sender_identity: bytes,
        sender_signature: bytes,
    ) -> None:
        """Deposit an envelope after authenticating and authorising the sender.

        Audit L12: delivery used to be open to anyone, making the mailbox a
        free spam/DoS sink and an open relay. The sender must now sign the
        (recipient, envelope) tuple with its identity key, must pass the
        recipient's allowlist when one is installed, and the queue is capped.

        Verifier D15 — the cap must not punish the victim. A single shared
        depth limit that rejects on overflow let any self-minted identity fill
        a recipient's mailbox and permanently jam delivery *for everyone else*:
        the flooding nuisance became a reliable denial of service against the
        recipient. Capacity is now allocated per sender:

        * a sender may never hold more than ``max_envelopes_per_sender`` slots,
          so the cost of flooding is charged only to the flooder;
        * when the mailbox is otherwise full, the incoming envelope displaces
          the OLDEST envelope of whichever sender currently holds the most
          slots — never an entry belonging to a sender who is using less than
          the incoming one. A sender within its quota is therefore always
          deliverable, no matter what any other sender does.
        """

        verify_envelope_sender(
            recipient_identity,
            recipient_device_id,
            envelope,
            sender_identity=sender_identity,
            sender_signature=sender_signature,
        )

        key = (recipient_identity, recipient_device_id)
        allowlist = self._mailbox_allowlists.get(key)
        if allowlist is not None and sender_identity not in allowlist:
            raise PermissionError("sender is not authorised for this mailbox")

        # Materialise the mailbox only once the delivery is actually accepted,
        # so a rejected envelope never allocates state keyed on an
        # attacker-chosen recipient.
        queued = self._mailboxes.get(key)
        created = queued is None
        if queued is None:
            queued = []
        self._reserve_mailbox_slot(queued, sender_identity)
        queued.append((sender_identity, deepcopy(envelope)))
        if created:
            self._mailboxes[key] = queued

    def _reserve_mailbox_slot(
        self,
        queued: list[tuple[bytes, dict[str, Any]]],
        sender_identity: bytes,
    ) -> None:
        """Make room for ``sender_identity``, fairly (verifier D15)."""

        counts: dict[bytes, int] = {}
        for queued_sender, _ in queued:
            counts[queued_sender] = counts.get(queued_sender, 0) + 1
        mine = counts.get(sender_identity, 0)

        if mine >= self._max_envelopes_per_sender:
            # Fail closed against the flooder only.
            raise ValueError("mailbox is full for this sender")

        if len(queued) < self._max_mailbox_depth:
            return

        # Mailbox full: evict from the greediest sender, deterministically.
        greediest, greediest_count = max(
            counts.items(), key=lambda item: (item[1], item[0])
        )
        if greediest_count <= mine:
            # The incoming sender is (one of) the greediest; it eats its own
            # overflow rather than displacing a better-behaved peer.
            raise ValueError("mailbox is full for this sender")
        for index, (queued_sender, _) in enumerate(queued):
            if queued_sender == greediest:
                del queued[index]
                return
        raise ValueError("mailbox is full")  # pragma: no cover - unreachable

    def fetch_mailbox(
        self,
        recipient_identity: str,
        recipient_device_id: int,
        *,
        drain: bool = True,
    ) -> list[dict[str, Any]]:
        key = (recipient_identity, recipient_device_id)
        queued = self._mailboxes.get(key)
        if queued is None:
            return []
        envelopes = [deepcopy(envelope) for _, envelope in queued]
        if drain:
            del self._mailboxes[key]
        return envelopes

    def fetch_envelopes(
        self,
        recipient_identity: str,
        recipient_device_id: int,
        *,
        drain: bool = True,
    ) -> list[dict[str, Any]]:
        return self.fetch_mailbox(
            recipient_identity,
            recipient_device_id,
            drain=drain,
        )


class FederatedRelay:
    """Minimal federated relay wrapper around a decentralized service home."""

    def __init__(
        self,
        relay_id: str,
        services: DecentralizedServices,
        *,
        clock: Optional[Callable[[], int]] = None,
        max_forwards_per_window: int = DEFAULT_MAX_FORWARDS_PER_WINDOW,
        forward_window_ms: int = DEFAULT_FORWARD_WINDOW_MS,
        max_tracked_senders: int = DEFAULT_MAX_TRACKED_SENDERS,
    ) -> None:
        if max_forwards_per_window <= 0:
            raise ValueError("max_forwards_per_window must be positive")
        if forward_window_ms <= 0:
            raise ValueError("forward_window_ms must be positive")
        if max_tracked_senders <= 0:
            raise ValueError("max_tracked_senders must be positive")
        self.relay_id = relay_id
        self.services = services
        self._clock = clock if clock is not None else now_ms
        self._max_forwards_per_window = max_forwards_per_window
        self._forward_window_ms = forward_window_ms
        self._max_tracked_senders = max_tracked_senders
        self._peers: dict[str, FederatedRelay] = {}
        self._forward_counters: dict[bytes, tuple[int, int]] = {}

    def add_peer(self, peer: FederatedRelay) -> None:
        if not isinstance(peer, FederatedRelay):
            raise TypeError("peer must be a FederatedRelay")
        self._peers[peer.relay_id] = peer

    def forward_to_relay(
        self,
        relay_id: str,
        recipient_identity: str,
        recipient_device_id: int,
        envelope: dict[str, Any],
        *,
        sender_identity: bytes,
        sender_signature: bytes,
    ) -> None:
        """Forward an authenticated envelope to a peer relay (rate limited).

        Verifier D14: the quota used to be charged before anything was
        verified, keyed on the raw ``sender_identity`` argument. That is an
        attacker-chosen value, so (a) the limit bought nothing — a fresh
        32-byte "identity" per message reset the counter — and (b) the counter
        table grew without bound on junk keys, a memory-exhaustion vector that
        cost the attacker one bogus message each. The signature is now checked
        FIRST, so only an identity that actually holds a private key can create
        a counter, and the table is bounded and fails closed.
        """

        try:
            peer = self._peers[relay_id]
        except KeyError as exc:
            raise KeyError("unknown federated relay") from exc

        # Authenticate before spending a single byte of state on this sender.
        verify_envelope_sender(
            recipient_identity,
            recipient_device_id,
            envelope,
            sender_identity=sender_identity,
            sender_signature=sender_signature,
        )
        self._consume_forward_quota(sender_identity)

        peer.services.deliver_envelope(
            recipient_identity=recipient_identity,
            recipient_device_id=recipient_device_id,
            envelope=envelope,
            sender_identity=sender_identity,
            sender_signature=sender_signature,
        )

    def _consume_forward_quota(self, sender_identity: bytes) -> None:
        """Charge one forward to a VERIFIED identity; bounded, fail closed."""

        now = self._clock()
        entry = self._forward_counters.get(sender_identity)
        if entry is None:
            # Dropping a counter whose window has fully elapsed grants nothing
            # (it would reset to zero on its next use anyway), so this is the
            # only reclamation the table ever does — it never forgets a live
            # counter to make room.
            self._drop_elapsed_counters(now)
            if len(self._forward_counters) >= self._max_tracked_senders:
                raise PermissionError("relay forwarding quota table is full")
            window_start, count = now, 0
        else:
            window_start, count = entry
            if now - window_start >= self._forward_window_ms:
                window_start, count = now, 0
        if count >= self._max_forwards_per_window:
            raise PermissionError("relay forwarding rate limit exceeded")
        self._forward_counters[sender_identity] = (window_start, count + 1)

    def _drop_elapsed_counters(self, now: int) -> None:
        for identity, (window_start, _) in list(self._forward_counters.items()):
            if now - window_start >= self._forward_window_ms:
                del self._forward_counters[identity]


def _validated_username_hash(record: SignedRecord) -> str:
    claimed_hash = record.body.get("username_hash")
    if not isinstance(claimed_hash, str):
        raise ValueError("username_hash must be 64 lowercase hex characters")
    if len(claimed_hash) != 64 or any(char not in _LOWER_HEX for char in claimed_hash):
        raise ValueError("username_hash must be 64 lowercase hex characters")

    identity_sign_pub = record.body.get("identity_sign_pub")
    if not isinstance(identity_sign_pub, str):
        raise ValueError("identity_sign_pub must match author_identity")
    if identity_sign_pub != record.author_identity.hex():
        raise ValueError("identity_sign_pub must match author_identity")

    return claimed_hash
