"""
ML-KEM Braid chat client.

Drives the full end-to-end flow against the FastAPI server:

  1. ``register()`` — create a PQXDH identity + prekey bundle, publish the public
     bundle (and one-time prekeys), keep all private key material locally.
  2. ``start_session(peer)`` — fetch the peer's bundle, run the PQXDH initiator
     handshake to get the initial secret ``SK``, send a ``pqxdh_init`` envelope,
     and seed an ML-KEM Braid SCKA as Role.ALICE.  The PQXDH ``SK`` also seeds
     a :class:`DoubleRatchet` so per-message forward secrecy is available from
     the first agreed epoch.
  3. ``pump_session()`` / ``poll()`` — exchange Braid chunk messages through the
     mailbox until epoch keys are agreed; when ``record_key`` fires it calls
     ``ratchet.ratchet_epoch(epoch, key)`` so both ratchets stay in sync.
  4. ``send_chat()`` — Double-Ratchet-encrypt a message; the envelope body is
     ``{header: {epoch, index}, ciphertext: b64}`` (replaces the old raw-epoch
     ``{epoch, ciphertext}`` shape).

The transport is any object satisfying the :class:`Transport` protocol defined in
:mod:`ml_kem_braid.client.transport`; tests inject an in-process ASGI transport.
``HttpTransport`` and ``WebSocketTransport`` are both valid transports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from ml_kem_braid.core.double_ratchet import DoubleRatchet
from ml_kem_braid.core.double_ratchet import Role as DRRole
from ml_kem_braid.core.double_ratchet import RatchetHeader
from ml_kem_braid.protocol.braid import MLKEMBraid, Role
from ml_kem_braid.protocol.messages import Message
from ml_kem_braid.pqxdh import (
    IdentityKeyPair,
    PreKeySecrets,
    create_identity,
    create_prekey_bundle,
    initiator_handshake,
    responder_handshake,
)
from ml_kem_braid.pqxdh.pqxdh import _x25519_pub_bytes
from ml_kem_braid.wire import (
    b64d,
    b64e,
    braid_message_from_dict,
    braid_message_to_dict,
    bundle_from_dict,
    bundle_to_dict,
    initial_message_from_dict,
    initial_message_to_dict,
    registration_challenge,
)

# Re-export so callers that did ``from ml_kem_braid.client.client import HttpTransport``
# continue to work unchanged.
from ml_kem_braid.client.transport import HttpTransport, Transport, WebSocketTransport

__all__ = [
    "HttpTransport",
    "WebSocketTransport",
    "Transport",
    "BraidChatClient",
    "BraidSession",
    "run_until_agreed",
]

# Map Braid roles to Double-Ratchet directional roles.
_BRAID_TO_DR_ROLE: Dict[Role, DRRole] = {
    Role.ALICE: DRRole.ALICE,
    Role.BOB: DRRole.BOB,
}


@dataclass
class BraidSession:
    """Live session with one peer device: PQXDH ``SK`` + the Braid SCKA state
    + a :class:`DoubleRatchet` for per-message forward secrecy."""

    peer_username: str
    peer_device_id: int
    role: Role
    braid: MLKEMBraid
    ratchet: DoubleRatchet
    epoch_keys: Dict[int, bytes] = field(default_factory=dict)
    initialized_peer: bool = False

    def record_key(self, output_key: Optional[Tuple[int, bytes]]) -> None:
        """Store the epoch key and advance the Double Ratchet to the new epoch."""
        if output_key is not None:
            epoch, key = output_key
            self.epoch_keys[epoch] = key
            self.ratchet.ratchet_epoch(epoch, key)

    def latest_epoch(self) -> Optional[int]:
        return max(self.epoch_keys) if self.epoch_keys else None


class BraidChatClient:
    """A single device participating in the ML-KEM Braid chat network.

    Accepts any object satisfying the :class:`Transport` protocol so the same
    client code works with HTTP polling or the WebSocket push transport.
    """

    def __init__(self, transport: Transport, username: str):
        self.transport = transport
        self.username = username
        self.identity: IdentityKeyPair = create_identity()
        self.registration_id: int = 0
        self.device_id: Optional[int] = None
        self.auth_token: Optional[str] = None
        self._secrets: Optional[PreKeySecrets] = None
        self.sessions: Dict[Tuple[str, int], BraidSession] = {}
        # Chat messages received & decrypted, surfaced to the application.
        self.inbox: List[Tuple[str, int, int, str]] = []  # (peer, dev, epoch, text)
        # Envelopes dropped during poll() (malformed/forged), for observability.
        self.dropped: List[Tuple[Tuple[str, int], object, str]] = []

    # -- registration ------------------------------------------------------

    def register(self, registration_id: int = 1, num_one_time: int = 4) -> dict:
        bundle, secrets = create_prekey_bundle(
            self.identity, num_one_time=num_one_time
        )
        self._secrets = secrets
        self.registration_id = registration_id

        one_time = {
            str(opk_id): b64e(_x25519_pub_bytes(priv.public_key()))
            for opk_id, priv in secrets.opk_priv.items()
        }
        # Prove ownership of the username by signing the registration challenge
        # with the identity key (the server verifies this against ik_sign_pub).
        proof = self.identity.sign(registration_challenge(self.username, registration_id))
        resp = self.transport.register(
            {
                "username": self.username,
                "registration_id": registration_id,
                "bundle": bundle_to_dict(bundle),
                "proof_sig": b64e(proof),
                "one_time_prekeys": one_time,
            }
        )
        self.device_id = resp["device_id"]
        self.auth_token = resp["auth_token"]
        return resp

    # -- session establishment (initiator) ---------------------------------

    def start_session(
        self, peer_username: str, peer_device_id: Optional[int] = None
    ) -> BraidSession:
        if peer_device_id is None:
            devices = self.transport.list_devices(peer_username)
            peer_device_id = devices[0]["device_id"]

        bundle_resp = self.transport.get_bundle(peer_username, peer_device_id)
        bundle = bundle_from_dict(bundle_resp["bundle"])

        sk, init_msg = initiator_handshake(self.identity, bundle)
        braid = MLKEMBraid(Role.ALICE, sk)
        # Seed the Double Ratchet from the PQXDH SK; directional role = ALICE.
        ratchet = DoubleRatchet(sk, DRRole.ALICE)
        session = BraidSession(
            peer_username=peer_username,
            peer_device_id=peer_device_id,
            role=Role.ALICE,
            braid=braid,
            ratchet=ratchet,
            initialized_peer=True,
        )
        self.sessions[(peer_username, peer_device_id)] = session

        self._send_envelope(
            peer_username,
            peer_device_id,
            "pqxdh_init",
            initial_message_to_dict(init_msg),
        )
        return session

    # -- mailbox polling / dispatch ---------------------------------------

    def poll(self) -> None:
        """Drain the mailbox and dispatch every envelope by kind. A malformed or
        forged envelope is dropped without discarding the rest of the batch."""
        assert self.auth_token, "register() first"
        for env in self.transport.fetch(self.auth_token):
            peer = (env["sender_username"], env["sender_device_id"])
            try:
                kind = env["kind"]
                if kind == "pqxdh_init":
                    self._handle_pqxdh_init(peer, env["body"])
                elif kind == "braid":
                    self._handle_braid(peer, env["body"])
                elif kind == "chat":
                    self._handle_chat(peer, env["body"])
            except Exception as exc:  # noqa: BLE001 - drop bad/forged envelopes
                self.dropped.append((peer, env.get("kind"), repr(exc)))

    def _handle_pqxdh_init(self, peer: Tuple[str, int], body: dict) -> None:
        assert self._secrets is not None
        # Do not let an unsolicited init replace an already-established session
        # with this peer device (defends against forced session reset).
        if peer in self.sessions:
            return
        init_msg = initial_message_from_dict(body)
        sk = responder_handshake(self.identity, self._secrets, init_msg)
        braid = MLKEMBraid(Role.BOB, sk)
        # Seed the Double Ratchet from the same PQXDH SK; directional role = BOB.
        ratchet = DoubleRatchet(sk, DRRole.BOB)
        self.sessions[peer] = BraidSession(
            peer_username=peer[0],
            peer_device_id=peer[1],
            role=Role.BOB,
            braid=braid,
            ratchet=ratchet,
            initialized_peer=True,
        )

    def _handle_braid(self, peer: Tuple[str, int], body: dict) -> None:
        session = self.sessions.get(peer)
        if session is None:
            return  # braid chunk before handshake completed; ignore
        msg = braid_message_from_dict(body)
        _, output_key = session.braid.receive(msg)
        session.record_key(output_key)

    def _handle_chat(self, peer: Tuple[str, int], body: dict) -> None:
        """Decrypt an inbound chat envelope via the Double Ratchet.

        New envelope shape: ``{header: {epoch, index}, ciphertext: b64}``.
        Old shape ``{epoch, ciphertext}`` (no header sub-dict) is rejected
        and falls through to the dropped list via the caller's except block.
        """
        session = self.sessions.get(peer)
        if session is None:
            return
        # Require the new ratchet envelope shape.
        header = RatchetHeader.from_dict(body["header"])
        epoch = header.epoch
        # Verify we have an epoch key (ratchet must be seeded for this epoch).
        if epoch not in session.epoch_keys:
            self.dropped.append((peer, "chat", f"no key for epoch {epoch}"))
            return
        ad = self._chat_ad(peer[0], peer[1], self.username, self.device_id)
        plaintext = session.ratchet.decrypt(
            header, b64d(body["ciphertext"]), ad
        ).decode("utf-8")
        self.inbox.append((peer[0], peer[1], epoch, plaintext))

    # -- braid pumping -----------------------------------------------------

    def pump_session(self, session: BraidSession) -> Optional[Tuple[int, bytes]]:
        """Emit one Braid chunk to the peer; return any newly derived epoch key."""
        msg, _, output_key = session.braid.send()
        session.record_key(output_key)
        self._send_envelope(
            session.peer_username,
            session.peer_device_id,
            "braid",
            braid_message_to_dict(msg),
        )
        return output_key

    # -- chat --------------------------------------------------------------

    def send_chat(self, session: BraidSession, text: str, epoch: Optional[int] = None) -> int:
        """Double-Ratchet-encrypt ``text`` and send it to the peer.

        ``epoch`` selects which SCKA epoch key the ratchet is currently on;
        if omitted, the latest agreed epoch is used.  The ratchet must already
        have called ``ratchet_epoch`` for that epoch (happens automatically via
        ``record_key``).

        The envelope body is ``{header: {epoch, index}, ciphertext: b64}``.
        """
        epoch = epoch if epoch is not None else session.latest_epoch()
        if epoch is None or epoch not in session.epoch_keys:
            raise RuntimeError("no agreed epoch key yet; pump the session first")
        # The ratchet must be on the requested epoch; if the caller specifies
        # an older epoch we cannot retroactively re-derive (forward secrecy).
        if session.ratchet._current_epoch != epoch:
            raise RuntimeError(
                f"ratchet is on epoch {session.ratchet._current_epoch}, "
                f"cannot send on epoch {epoch}"
            )
        ad = self._chat_ad(
            self.username, self.device_id, session.peer_username, session.peer_device_id
        )
        header, blob = session.ratchet.encrypt(text.encode("utf-8"), ad)
        self._send_envelope(
            session.peer_username,
            session.peer_device_id,
            "chat",
            {"header": header.to_dict(), "ciphertext": b64e(blob)},
        )
        return epoch

    # -- helpers -----------------------------------------------------------

    def _send_envelope(self, peer_username: str, peer_device_id: int, kind: str, body: dict) -> None:
        assert self.auth_token, "register() first"
        # Sender identity is derived server-side from the bearer token.
        self.transport.send(
            {
                "recipient_username": peer_username,
                "recipient_device_id": peer_device_id,
                "kind": kind,
                "body": body,
            },
            self.auth_token,
        )

    @staticmethod
    def _chat_ad(
        s_user: str, s_dev: Optional[int], r_user: str, r_dev: Optional[int]
    ) -> bytes:
        """Associated data binding sender + recipient identity (no epoch — the
        ratchet header's epoch+index are bound inside DoubleRatchet.encrypt)."""
        return f"{s_user}:{s_dev}->{r_user}:{r_dev}".encode("utf-8")


def run_until_agreed(
    initiator: BraidChatClient,
    responder: BraidChatClient,
    session: BraidSession,
    target_epochs: int = 1,
    max_rounds: int = 4000,
    on_round: Optional[Callable[[int], None]] = None,
) -> int:
    """
    Pump a session between two in-process clients (sharing one server) until the
    initiator has agreed ``target_epochs`` epoch keys. Returns the highest agreed
    epoch. The responder's Braid is auto-created on its first ``poll()``.
    """
    for rnd in range(max_rounds):
        responder.poll()  # consume pqxdh_init / inbound braid chunks
        resp_session = responder.sessions.get((initiator.username, initiator.device_id))
        if resp_session is not None:
            responder.pump_session(resp_session)
        initiator.pump_session(session)
        initiator.poll()
        if on_round:
            on_round(rnd)
        if len(session.epoch_keys) >= target_epochs:
            return session.latest_epoch()
    raise RuntimeError("session did not reach agreement within max_rounds")
