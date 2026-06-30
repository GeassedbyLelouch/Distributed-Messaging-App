"""
ML-KEM Braid Protocol Orchestration

Main protocol class that combines all components:
- ML-KEM for key encapsulation
- Authenticator for message authentication
- State machine for protocol logic
- Erasure coding for message chunking

This module provides the high-level interface for using the ML-KEM Braid
protocol as a Sparse Continuous Key Agreement (SCKA) mechanism.

Usage:
    >>> from ml_kem_braid.protocol.braid import MLKEMBraid, Role
    >>> 
    >>> # Initialize with pre-shared secret (from PQXDH handshake)
    >>> preshared_secret = os.urandom(32)
    >>> 
    >>> alice = MLKEMBraid(Role.ALICE, preshared_secret)
    >>> bob = MLKEMBraid(Role.BOB, preshared_secret)
    >>> 
    >>> # Exchange messages
    >>> msg, sending_epoch, output_key = alice.send()
    >>> receiving_epoch, output_key = bob.receive(msg)

Reference:
    ML-KEM Braid Specification: https://signal.org/docs/specifications/mlkembraid/
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Tuple

from ml_kem_braid.core.ml_kem import MLKEM, MLKEMVariant
from ml_kem_braid.core.kdf import KDF
from ml_kem_braid.core.authenticator import Authenticator, MAC_SIZE
from ml_kem_braid.encoding.erasure import Encoder
from ml_kem_braid.protocol.messages import Message
from ml_kem_braid.protocol.states import (
    State, StateName, SendResult, ReceiveResult,
    KeysUnsampled, NoHeaderReceived,
    Ct1Acknowledged, Ct2Sampled,
    init_alice_state, init_bob_state
)


class Role(Enum):
    """
    Protocol role determining initial state.
    
    ALICE: Begins in KeysUnsampled, will send first encapsulation key
    BOB: Begins in NoHeaderReceived, will receive first encapsulation key
    """
    ALICE = auto()
    BOB = auto()


# Type alias for output key: (epoch, 32-byte key) or None
OutputKey = Optional[Tuple[int, bytes]]


@dataclass
class MLKEMBraid:
    """
    ML-KEM Braid Protocol Instance.
    
    Implements the Sparse Continuous Key Agreement (SCKA) interface
    with Send() and Receive() functions that advance the state machine
    and emit shared secrets.
    
    The protocol alternates between two modes:
    1. Transmitting encapsulation key (and receiving ciphertext)
    2. Transmitting ciphertext (and receiving encapsulation key)
    
    After each complete exchange, roles switch and a new shared secret
    is derived for that epoch.
    
    Security Properties:
    - Forward Secrecy: Past keys cannot be derived from current state
    - Post-Compromise Security: Protocol heals after temporary compromise
    - Authentication: Messages are MAC'd with ratcheting keys
    
    Usage:
        >>> braid = MLKEMBraid(Role.ALICE, preshared_secret)
        >>> 
        >>> # Generate message to send
        >>> msg, sending_epoch, output_key = braid.send()
        >>> 
        >>> # Process received message
        >>> receiving_epoch, output_key = braid.receive(incoming_msg)
        >>> 
        >>> # Check for emitted keys
        >>> if output_key:
        ...     epoch, key = output_key
        ...     print(f"Derived key for epoch {epoch}: {key.hex()[:32]}...")
    
    Attributes:
        role: Initial protocol role (ALICE or BOB)
        epoch: Current epoch being negotiated
        state: Current state machine state
        auth: Ratcheted authenticator
        kem: ML-KEM instance
        kdf: Key derivation function
        derived_keys: List of (epoch, key) pairs that have been derived
    """
    
    role: Role
    _preshared_secret: bytes = field(repr=False)
    variant: MLKEMVariant = MLKEMVariant.ML_KEM_768
    protocol_info: str = "MLKEMBraid_MLKEM768_HMAC-SHA256"
    
    # Runtime state (initialized in __post_init__)
    epoch: int = field(init=False, default=1)
    state: State = field(init=False)
    auth: Authenticator = field(init=False)
    kem: MLKEM = field(init=False)
    kdf: KDF = field(init=False)
    derived_keys: List[Tuple[int, bytes]] = field(init=False, default_factory=list)
    
    def __post_init__(self):
        """Initialize protocol components."""
        # Initialize cryptographic components
        self.kem = MLKEM(self.variant)
        self.kdf = KDF(self.protocol_info)
        
        # Initialize authenticator with preshared secret
        self.auth = Authenticator(self.protocol_info)
        self.auth.init(self.epoch, self._preshared_secret)
        
        # Initialize state based on role
        if self.role == Role.ALICE:
            self.state = init_alice_state()
        else:
            self.state = init_bob_state(self.kem)
        
        self.derived_keys = []
    
    def send(self) -> Tuple[Message, int, OutputKey]:
        """
        Generate a message to send to the other party.
        
        This advances the state machine and may emit a shared secret
        depending on the current state.
        
        Returns:
            Tuple of (message, sending_epoch, output_key)
            - message: The Message to send
            - sending_epoch: Latest epoch known by receiver on receipt
            - output_key: Optional (epoch, key) if a key was derived
        
        Example:
            >>> msg, epoch, key = braid.send()
            >>> if key:
            ...     print(f"Derived key for epoch {key[0]}")
            >>> transport.send(msg.to_bytes())
        """
        result = self.state.send(
            epoch=self.epoch,
            auth=self.auth,
            kem=self.kem,
            kdf=self.kdf
        )
        
        # Update state
        self.state = result.new_state
        
        # Handle epoch advancement if we transitioned to certain states
        self._handle_epoch_advancement(result)
        
        # Track derived keys
        if result.output_key:
            self.derived_keys.append(result.output_key)
        
        return result.message, result.sending_epoch, result.output_key
    
    def receive(self, msg: Message) -> Tuple[int, OutputKey]:
        """
        Process a received message from the other party.
        
        This advances the state machine based on the message type
        and may emit a shared secret.
        
        Args:
            msg: The received Message
        
        Returns:
            Tuple of (receiving_epoch, output_key)
            - receiving_epoch: Epoch returned by sender as sending_epoch
            - output_key: Optional (epoch, key) if a key was derived
        
        Example:
            >>> msg = Message.from_bytes(received_bytes)
            >>> epoch, key = braid.receive(msg)
            >>> if key:
            ...     print(f"Derived key for epoch {key[0]}")
        """
        # Store old state before transition for epoch advancement check
        old_state = self.state
        
        result = self.state.receive(
            msg=msg,
            epoch=self.epoch,
            auth=self.auth,
            kem=self.kem,
            kdf=self.kdf
        )
        
        # Update state
        self.state = result.new_state
        
        # Handle epoch advancement if we transitioned to certain states
        self._handle_epoch_advancement_receive(result, msg, old_state)
        
        # Track derived keys
        if result.output_key:
            self.derived_keys.append(result.output_key)
        
        return result.receiving_epoch, result.output_key
    
    def _handle_epoch_advancement(self, result: SendResult) -> None:
        """Handle epoch advancement after send transitions."""
        # Epoch advances when certain states are reached
        # This is handled implicitly by state transitions
        pass
    
    def _handle_epoch_advancement_receive(
        self,
        result: ReceiveResult,
        msg: Message,
        old_state: State
    ) -> None:
        """Handle epoch advancement after receive transitions."""
        # When transitioning to NoHeaderReceived after EkSentCt1Received,
        # we've completed an epoch and should increment
        if (result.new_state.name == StateName.NO_HEADER_RECEIVED and
            result.output_key is not None):
            self.epoch += 1
        
        # When transitioning to KeysUnsampled from Ct2Sampled,
        # we've completed an epoch from the other side
        elif (result.new_state.name == StateName.KEYS_UNSAMPLED and
              old_state.name == StateName.CT2_SAMPLED):
            self.epoch += 1
    
    @property
    def state_name(self) -> StateName:
        """Current state machine state name."""
        return self.state.name
    
    @property
    def latest_key(self) -> OutputKey:
        """Most recently derived key, or None."""
        return self.derived_keys[-1] if self.derived_keys else None
    
    def get_key(self, epoch: int) -> Optional[bytes]:
        """
        Get derived key for a specific epoch.
        
        Args:
            epoch: Epoch number to look up
        
        Returns:
            32-byte key for that epoch, or None if not yet derived
        """
        for e, k in self.derived_keys:
            if e == epoch:
                return k
        return None
    
    def __repr__(self) -> str:
        return (
            f"MLKEMBraid(role={self.role.name}, "
            f"epoch={self.epoch}, "
            f"state={self.state_name.name}, "
            f"keys_derived={len(self.derived_keys)})"
        )


def run_exchange(
    alice: MLKEMBraid,
    bob: MLKEMBraid,
    target_epochs: int = 2,
    max_rounds: int = 5000,
    verbose: bool = False,
) -> List[Tuple[int, bytes, bytes]]:
    """
    Drive a full-duplex ML-KEM Braid exchange between two parties over a reliable,
    in-order channel until both have agreed on ``target_epochs`` output keys.

    The Braid protocol is full-duplex: in each round every party emits exactly one
    chunk message and consumes the peer's chunk. This models a synchronous
    bidirectional link (which is what the FastAPI mailbox provides per poll).

    Args:
        alice: party initialised with :data:`Role.ALICE`
        bob: party initialised with :data:`Role.BOB`
        target_epochs: stop once both sides have a key for epochs ``1..target_epochs``
        max_rounds: safety bound on rounds
        verbose: print per-key progress

    Returns:
        Sorted list of ``(epoch, alice_key, bob_key)`` for every mutually-agreed
        epoch. The caller can assert ``alice_key == bob_key`` for each entry.

    Raises:
        RuntimeError: if convergence is not reached within ``max_rounds``.
    """
    alice_keys: dict = {}
    bob_keys: dict = {}

    def _record(store: dict, out: OutputKey) -> None:
        if out is not None:
            epoch, key = out
            store[epoch] = key
            if verbose:
                who = "Alice" if store is alice_keys else "Bob"
                print(f"  {who} derived key for epoch {epoch}: {key.hex()[:16]}...")

    wanted = set(range(1, target_epochs + 1))
    for _ in range(max_rounds):
        msg_a, _, ok_a = alice.send()
        _record(alice_keys, ok_a)
        msg_b, _, ok_b = bob.send()
        _record(bob_keys, ok_b)

        _, ok_b_recv = bob.receive(msg_a)
        _record(bob_keys, ok_b_recv)
        _, ok_a_recv = alice.receive(msg_b)
        _record(alice_keys, ok_a_recv)

        if wanted <= alice_keys.keys() and wanted <= bob_keys.keys():
            break
    else:
        raise RuntimeError(
            f"exchange did not converge to {target_epochs} epochs in {max_rounds} rounds "
            f"(alice={sorted(alice_keys)}, bob={sorted(bob_keys)})"
        )

    shared = sorted(set(alice_keys) & set(bob_keys))
    return [(ep, alice_keys[ep], bob_keys[ep]) for ep in shared]


# Backwards-compatible alias for the previous (broken) helper name.
def simulate_exchange(alice, bob, max_messages: int = 5000, verbose: bool = False, **_):
    """Deprecated alias for :func:`run_exchange`. Returns agreed ``(epoch, a, b)`` keys."""
    return run_exchange(alice, bob, target_epochs=2, max_rounds=max_messages, verbose=verbose)


# Self-test
if __name__ == "__main__":
    import os
    
    print("Testing ML-KEM Braid Protocol...")
    print("=" * 60)
    
    # Initialize with pre-shared secret
    preshared_secret = os.urandom(32)
    print(f"Pre-shared secret: {preshared_secret.hex()[:32]}...")
    
    alice = MLKEMBraid(Role.ALICE, preshared_secret)
    bob = MLKEMBraid(Role.BOB, preshared_secret)
    
    print(f"\nAlice: {alice}")
    print(f"Bob: {bob}")
    
    print("\n" + "-" * 60)
    print("Simulating message exchange...")
    print("-" * 60)
    
    agreed_keys = simulate_exchange(alice, bob, verbose=True)
    
    print("\n" + "=" * 60)
    print("Results:")
    print("=" * 60)
    
    for epoch, alice_key, bob_key in agreed_keys:
        match = "✓ MATCH" if alice_key == bob_key else "✗ MISMATCH"
        print(f"Epoch {epoch}: {match}")
        print(f"  Alice: {alice_key.hex()[:32]}...")
        print(f"  Bob:   {bob_key.hex()[:32]}...")
    
    print(f"\nFinal states:")
    print(f"  Alice: {alice}")
    print(f"  Bob: {bob}")
    
    print("\nML-KEM Braid test complete!")
