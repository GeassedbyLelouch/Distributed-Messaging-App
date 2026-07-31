"""
Ratcheted Authenticator for ML-KEM Braid

Provides internal authentication guarantees for the protocol through
a ratcheting MAC scheme. The authenticator state is updated with new
entropy from each epoch's shared secret.

Authentication adds 32 bytes (MAC) to header and ciphertext messages,
but can be omitted if the higher-level protocol (e.g., Double Ratchet)
provides its own authentication.

Security Properties:
- Message authenticity: Header and ciphertext messages are authenticated
- Forward secrecy: Compromise doesn't reveal past MAC keys
- Post-compromise security: MAC key heals after compromise

Reference:
    ML-KEM Braid Section 2.4: https://signal.org/docs/specifications/mlkembraid/
"""

from __future__ import annotations

import hmac
import hashlib
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ml_kem_braid.core.kdf import KDF, epoch_to_bytes, hkdf


# MAC output size (HMAC-SHA256)
MAC_SIZE = 32

# Domain separator for the canonical MAC input encoding. Bumped when the
# encoding changes (audit finding L6: raw concatenation -> length-prefixed).
_MAC_DOMAIN = b"MLKEMBraid-mac-v2"

# HKDF info suffixes for the two DIRECTIONAL wire-frame authentication keys
# (post-audit hardening D9). A single shared frame key made every frame verify in
# both directions, so an attacker could reflect a peer's own frame back at it.
_FRAME_KEY_INFO_I2R = b":frame-auth:i2r"  # initiator -> responder
_FRAME_KEY_INFO_R2I = b":frame-auth:r2i"  # responder -> initiator
_HKDF_ZERO_SALT = b"\x00" * 32


class FrameRole(Enum):
    """Which end of the session this authenticator sits on.

    Determines which directional frame key is used to seal outgoing frames and
    which is used to verify incoming ones. ``INITIATOR`` corresponds to the Braid
    ``Role.ALICE``, ``RESPONDER`` to ``Role.BOB``.
    """

    INITIATOR = "i"
    RESPONDER = "r"


def _canonical_mac_input(
    protocol_info: bytes, label: bytes, epoch: int, payload: bytes
) -> bytes:
    """
    Canonical, injective MAC input encoding (audit finding L6).

    ``_MAC_DOMAIN || u16(len(info)) || info || u16(len(label)) || label
      || u64(epoch) || u32(len(payload)) || payload``

    Every variable-length component is length-prefixed, so no two distinct
    (info, label, epoch, payload) tuples can produce the same byte string.
    """
    return (
        _MAC_DOMAIN
        + struct.pack(">H", len(protocol_info)) + protocol_info
        + struct.pack(">H", len(label)) + label
        + epoch_to_bytes(epoch)
        + struct.pack(">I", len(payload)) + payload
    )


@dataclass
class AuthenticatorState:
    """
    Internal state of the ratcheted authenticator.

    Attributes:
        root_key: Current root key for KDF chain
        mac_key: Current MAC key for message authentication
        frame_key_send: Frame key for frames THIS party sends (does NOT ratchet)
        frame_key_recv: Frame key for frames this party RECEIVES (does NOT ratchet)

    ``frame_key_send`` and ``frame_key_recv`` are the two ends of the same pair
    swapped between initiator and responder, so a frame this party produced can
    never verify against the key this party verifies with (no reflection).
    """
    root_key: bytes = field(default_factory=lambda: b"\x00" * 32)
    mac_key: Optional[bytes] = None
    frame_key_send: Optional[bytes] = None
    frame_key_recv: Optional[bytes] = None


class AuthenticatorError(Exception):
    """Raised when MAC verification fails."""
    pass


class Authenticator:
    """
    Ratcheted Authenticator for ML-KEM Braid Protocol.

    The authenticator provides internal message authentication using
    a ratcheting MAC scheme. Each time a new shared secret is derived,
    the authenticator state is updated to derive new keys.

    Frame authentication: scope and limits (audit M1, hardening D9)
    ---------------------------------------------------------------
    :meth:`mac_frame` / :meth:`verify_frame` protect the *wire framing* (message
    type byte, epoch, length prefix, payload) so a network attacker cannot inject
    or re-type a frame and drive the state machine. Two properties are worth
    stating exactly, because the frame key is NOT the ratcheting ``mac_key``:

    * **Directional.** Two frame keys are derived from the handshake secret with
      distinct HKDF labels: initiator->responder and responder->initiator. A
      party seals with its send key and verifies with its receive key, so a frame
      REFLECTED back at its own author fails verification. (Before D9 a single
      shared frame key made every frame verify in both directions.)
    * **No post-compromise security.** The frame keys are session-scoped and do
      NOT ratchet. This is deliberate: the two peers update authenticator state
      at different moments in the Braid exchange (the encapsulator ratchets on
      Send, the decapsulator only once ``ct2`` is fully reassembled), so a
      ratcheting frame key would make honest frames unverifiable. The consequence
      is explicit: an adversary who learns the handshake secret can forge and
      verify framing for the remainder of the session, and the session never
      heals at the framing layer. Frame authentication is therefore an
      **outsider-only control with no PCS**. Message-content authenticity and
      post-compromise security remain with the ratcheting ``mac_key``
      (:meth:`mac_header` / :meth:`mac_ciphertext`), which is the layer that
      actually protects derived key material. Epoch-scoped frame-key rotation is
      left to the Rust port, where the two ratchet points can be made to agree.

    Protocol Messages Authenticated:
    - Header: ek_seed || hek (64 bytes) with header MAC
    - Ciphertext: ct1 || ct2 with ciphertext MAC
    
    Usage:
        >>> auth = Authenticator()
        >>> auth.init(epoch=1, key=preshared_secret)
        >>> 
        >>> # Update when shared secret derived
        >>> auth.update(epoch=1, key=shared_secret)
        >>> 
        >>> # Compute MACs for messages
        >>> header_mac = auth.mac_header(epoch, header_bytes)
        >>> ct_mac = auth.mac_ciphertext(epoch, ct1 + ct2)
        >>> 
        >>> # Verify MACs on received messages
        >>> auth.verify_header(epoch, header_bytes, received_mac)
        >>> auth.verify_ciphertext(epoch, ct1 + ct2, received_mac)
    
    Attributes:
        state: Current authenticator state
        protocol_info: Protocol identifier for domain separation
        kdf: KDF instance for key derivation
    """
    
    def __init__(
        self,
        protocol_info: str = "MLKEMBraid_MLKEM768_HMAC-SHA256",
        *,
        role: FrameRole = FrameRole.INITIATOR,
    ):
        """
        Initialize authenticator with protocol information.

        Args:
            protocol_info: Protocol identifier string
            role: which end of the session this is. It selects which of the two
                directional frame keys seals outgoing frames and which verifies
                incoming ones (D9). The two peers MUST pass opposite roles;
                passing the same role on both ends makes honest frames fail to
                verify (fail closed), never silently accept.
        """
        self.protocol_info = protocol_info.encode("utf-8")
        self.role = role
        self.kdf = KDF(protocol_info)
        self.state = AuthenticatorState()

    def init(self, epoch: int, key: bytes) -> None:
        """
        Initialize authenticator state with pre-shared secret.

        Called during protocol initialization with the pre-shared
        secret from the handshake (e.g., PQXDH).

        Args:
            epoch: Initial epoch number (usually 1)
            key: Pre-shared secret from handshake
        """
        # Derive BOTH session-scoped wire-frame authentication keys from the
        # handshake secret, under distinct HKDF labels, and assign send/recv by
        # role. Directionality is what stops frame REFLECTION: a frame sealed by
        # this party can only be verified by the peer, never by this party
        # (finding M1 / hardening D9).
        #
        # Neither key ratchets — see the class docstring for exactly what that
        # costs (outsider-only control, no post-compromise security).
        key_i2r = hkdf(
            ikm=key,
            salt=_HKDF_ZERO_SALT,
            info=self.protocol_info + _FRAME_KEY_INFO_I2R,
            length=32,
        )
        key_r2i = hkdf(
            ikm=key,
            salt=_HKDF_ZERO_SALT,
            info=self.protocol_info + _FRAME_KEY_INFO_R2I,
            length=32,
        )
        if self.role == FrameRole.INITIATOR:
            frame_send, frame_recv = key_i2r, key_r2i
        else:
            frame_send, frame_recv = key_r2i, key_i2r

        # Start with zero root key
        self.state = AuthenticatorState(
            root_key=b"\x00" * 32,
            mac_key=None,
            frame_key_send=frame_send,
            frame_key_recv=frame_recv,
        )
        # Update to derive first MAC key
        self.update(epoch, key)
    
    def update(self, epoch: int, key: bytes) -> None:
        """
        Update authenticator state with new entropy.

        Called when a new shared secret is derived for an epoch.
        Updates the root key and MAC key using HKDF.

        Args:
            epoch: Current epoch number
            key: New shared secret for this epoch
        """
        new_root_key, new_mac_key = self.kdf.kdf_auth(
            self.state.root_key,
            key,
            epoch
        )
        self.state.root_key = new_root_key
        self.state.mac_key = new_mac_key
        # Best-effort key hygiene (audit finding L5): drop the local references to
        # the new key material so only the state object holds them. Python `bytes`
        # are immutable, so the old root/MAC key buffers cannot be wiped — true
        # zeroization is deferred to the Rust port (`zeroize::Zeroizing`).
        del new_root_key, new_mac_key

    def update_and_verify_ciphertext(
        self,
        epoch: int,
        key: bytes,
        ciphertext: bytes,
        expected_mac: bytes,
    ) -> None:
        """
        Transactionally ratchet on a *decapsulated* shared secret only if the
        ciphertext MAC verifies under the resulting MAC key.

        The decapsulator derives ``key`` from a received (possibly tampered)
        ciphertext, so committing the ratchet before checking the MAC would
        corrupt long-term authenticator state on a forged ciphertext. Here the
        candidate ``(root_key, mac_key)`` is computed, the MAC is verified with
        the candidate key, and the state is committed **only on success**; on
        failure the authenticator is left untouched and the session must halt.
        """
        cand_root, cand_mac = self.kdf.kdf_auth(self.state.root_key, key, epoch)
        data = _canonical_mac_input(
            self.protocol_info, b":ciphertext", epoch, ciphertext
        )
        computed = hmac.new(cand_mac, data, hashlib.sha256).digest()
        if not hmac.compare_digest(computed, expected_mac):
            raise AuthenticatorError(
                f"Ciphertext MAC verification failed for epoch {epoch}"
            )
        self.state.root_key = cand_root
        self.state.mac_key = cand_mac
    
    def _ensure_mac_key(self) -> bytes:
        """Ensure MAC key is initialized."""
        if self.state.mac_key is None:
            raise RuntimeError("Authenticator not initialized - call init() first")
        return self.state.mac_key

    def _ensure_frame_send_key(self) -> bytes:
        """Ensure the outbound wire-frame authentication key is initialized."""
        if self.state.frame_key_send is None:
            raise RuntimeError("Authenticator not initialized - call init() first")
        return self.state.frame_key_send

    def _ensure_frame_recv_key(self) -> bytes:
        """Ensure the inbound wire-frame authentication key is initialized."""
        if self.state.frame_key_recv is None:
            raise RuntimeError("Authenticator not initialized - call init() first")
        return self.state.frame_key_recv

    def mac_frame(self, mac_input: bytes) -> bytes:
        """
        Compute the wire-frame MAC for a frame THIS party is sending.

        ``mac_input`` is the canonical encoding of the ENTIRE serialized frame
        (message type byte, epoch, length prefix and payload) produced by
        :meth:`ml_kem_braid.protocol.messages.Message.mac_input`. Binding the
        whole frame closes finding M1: the state machine transitions on the
        ``epoch``/``type`` fields, which were previously unauthenticated.

        Uses the DIRECTIONAL send key, so the resulting tag verifies only at the
        peer — never at this party (D9: no reflection).

        Args:
            mac_input: canonical frame encoding

        Returns:
            32-byte MAC value
        """
        return hmac.new(
            self._ensure_frame_send_key(), mac_input, hashlib.sha256
        ).digest()

    def verify_frame(self, mac_input: bytes, expected_mac: Optional[bytes]) -> None:
        """
        Verify a wire-frame MAC on an INCOMING frame, failing closed.

        Uses the DIRECTIONAL receive key. A frame this party itself produced is
        sealed under the *send* key, so replaying/reflecting it back here fails
        (hardening D9); before that, one shared frame key made a party's own
        frames verify against itself.

        A missing MAC is rejected outright — accepting unsealed frames would
        leave a trivial downgrade path around frame authentication.

        Raises:
            AuthenticatorError: if the MAC is absent or does not verify
        """
        if expected_mac is None:
            raise AuthenticatorError("frame carries no authentication tag")
        computed = hmac.new(
            self._ensure_frame_recv_key(), mac_input, hashlib.sha256
        ).digest()
        if not hmac.compare_digest(computed, expected_mac):
            raise AuthenticatorError("frame MAC verification failed")


    def mac_header(self, epoch: int, header: bytes) -> bytes:
        """
        Compute MAC for a header message.
        
        MAC(mac_key, PROTOCOL_INFO || ":ekheader" || epoch || header)
        
        Args:
            epoch: Current epoch number
            header: Header bytes (ek_seed || hek, 64 bytes)
        
        Returns:
            32-byte MAC value
        """
        mac_key = self._ensure_mac_key()

        data = _canonical_mac_input(self.protocol_info, b":ekheader", epoch, header)

        return hmac.new(mac_key, data, hashlib.sha256).digest()
    
    def mac_ciphertext(self, epoch: int, ciphertext: bytes) -> bytes:
        """
        Compute MAC for a ciphertext message.
        
        MAC(mac_key, PROTOCOL_INFO || ":ciphertext" || epoch || ciphertext)
        
        Args:
            epoch: Current epoch number
            ciphertext: Full ciphertext (ct1 || ct2)
        
        Returns:
            32-byte MAC value
        """
        mac_key = self._ensure_mac_key()

        data = _canonical_mac_input(
            self.protocol_info, b":ciphertext", epoch, ciphertext
        )

        return hmac.new(mac_key, data, hashlib.sha256).digest()
    
    def verify_header(
        self,
        epoch: int,
        header: bytes,
        expected_mac: bytes
    ) -> None:
        """
        Verify MAC on a received header.
        
        Args:
            epoch: Epoch of the header
            header: Received header bytes
            expected_mac: MAC received with the header
        
        Raises:
            AuthenticatorError: If MAC verification fails
        """
        computed_mac = self.mac_header(epoch, header)
        
        if not hmac.compare_digest(computed_mac, expected_mac):
            raise AuthenticatorError(
                f"Header MAC verification failed for epoch {epoch}"
            )
    
    def verify_ciphertext(
        self,
        epoch: int,
        ciphertext: bytes,
        expected_mac: bytes
    ) -> None:
        """
        Verify MAC on a received ciphertext.
        
        Args:
            epoch: Epoch of the ciphertext
            ciphertext: Received ciphertext bytes (ct1 || ct2)
            expected_mac: MAC received with the ciphertext
        
        Raises:
            AuthenticatorError: If MAC verification fails
        """
        computed_mac = self.mac_ciphertext(epoch, ciphertext)
        
        if not hmac.compare_digest(computed_mac, expected_mac):
            raise AuthenticatorError(
                f"Ciphertext MAC verification failed for epoch {epoch}"
            )
    
    def clone(self) -> Authenticator:
        """
        Create a deep copy of this authenticator.
        
        Useful for protocol state management.
        
        Returns:
            New Authenticator with copied state
        """
        auth = Authenticator(self.protocol_info.decode("utf-8"), role=self.role)
        auth.state = AuthenticatorState(
            root_key=self.state.root_key,
            mac_key=self.state.mac_key,
            frame_key_send=self.state.frame_key_send,
            frame_key_recv=self.state.frame_key_recv,
        )
        return auth


# Self-test
if __name__ == "__main__":
    import os
    
    print("Testing Ratcheted Authenticator...")
    
    # Initialize two authenticators (Alice and Bob) with OPPOSITE frame roles.
    alice_auth = Authenticator(role=FrameRole.INITIATOR)
    bob_auth = Authenticator(role=FrameRole.RESPONDER)
    
    preshared_secret = os.urandom(32)
    epoch = 1
    
    alice_auth.init(epoch, preshared_secret)
    bob_auth.init(epoch, preshared_secret)
    
    print(f"Initialized with preshared secret: {preshared_secret.hex()[:32]}...")
    
    # Test header MAC
    header = os.urandom(64)  # ek_seed || hek
    alice_mac = alice_auth.mac_header(epoch, header)
    print(f"Header MAC: {alice_mac.hex()[:32]}...")
    
    # Bob verifies
    bob_auth.verify_header(epoch, header, alice_mac)
    print("Header MAC verified ✓")
    
    # Test ciphertext MAC
    ciphertext = os.urandom(960 + 128)  # ct1 || ct2 for ML-KEM-768
    bob_mac = bob_auth.mac_ciphertext(epoch, ciphertext)
    print(f"Ciphertext MAC: {bob_mac.hex()[:32]}...")
    
    # Alice verifies
    alice_auth.verify_ciphertext(epoch, ciphertext, bob_mac)
    print("Ciphertext MAC verified ✓")
    
    # Test update
    new_secret = os.urandom(32)
    alice_auth.update(epoch + 1, new_secret)
    bob_auth.update(epoch + 1, new_secret)
    print("Authenticator state updated for new epoch ✓")
    
    # Test MAC failure
    try:
        alice_auth.verify_header(epoch + 1, header, b"\x00" * 32)
        print("ERROR: Should have raised AuthenticatorError")
    except AuthenticatorError:
        print("Invalid MAC correctly rejected ✓")
    
    print("Authenticator tests passed!")
