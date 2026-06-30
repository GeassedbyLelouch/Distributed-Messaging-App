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
from dataclasses import dataclass, field
from typing import Optional

from ml_kem_braid.core.kdf import KDF, epoch_to_bytes


# MAC output size (HMAC-SHA256)
MAC_SIZE = 32


@dataclass
class AuthenticatorState:
    """
    Internal state of the ratcheted authenticator.
    
    Attributes:
        root_key: Current root key for KDF chain
        mac_key: Current MAC key for message authentication
    """
    root_key: bytes = field(default_factory=lambda: b"\x00" * 32)
    mac_key: Optional[bytes] = None


class AuthenticatorError(Exception):
    """Raised when MAC verification fails."""
    pass


class Authenticator:
    """
    Ratcheted Authenticator for ML-KEM Braid Protocol.
    
    The authenticator provides internal message authentication using
    a ratcheting MAC scheme. Each time a new shared secret is derived,
    the authenticator state is updated to derive new keys.
    
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
    
    def __init__(self, protocol_info: str = "MLKEMBraid_MLKEM768_HMAC-SHA256"):
        """
        Initialize authenticator with protocol information.
        
        Args:
            protocol_info: Protocol identifier string
        """
        self.protocol_info = protocol_info.encode("utf-8")
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
        # Start with zero root key
        self.state = AuthenticatorState(
            root_key=b"\x00" * 32,
            mac_key=None
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
        data = (
            self.protocol_info + b":ciphertext" + epoch_to_bytes(epoch) + ciphertext
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
        
        data = (
            self.protocol_info +
            b":ekheader" +
            epoch_to_bytes(epoch) +
            header
        )
        
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
        
        data = (
            self.protocol_info +
            b":ciphertext" +
            epoch_to_bytes(epoch) +
            ciphertext
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
        auth = Authenticator(self.protocol_info.decode("utf-8"))
        auth.state = AuthenticatorState(
            root_key=self.state.root_key,
            mac_key=self.state.mac_key
        )
        return auth


# Self-test
if __name__ == "__main__":
    import os
    
    print("Testing Ratcheted Authenticator...")
    
    # Initialize two authenticators (Alice and Bob)
    alice_auth = Authenticator()
    bob_auth = Authenticator()
    
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
