"""
Message Types for ML-KEM Braid Protocol

Defines the protocol message format and serialization.

Message Structure:
    - epoch: Current epoch being negotiated (8 bytes)
    - type: Message type enum (1 byte)
    - data: Optional chunk payload (variable length)

Message Types:
    - None: No payload (empty message)
    - Hdr: Header chunk
    - Ek: Encapsulation key vector chunk
    - EkCt1Ack: EK chunk + acknowledgment that ct1 was received
    - Ct1Ack: Acknowledgment only (no payload)
    - Ct1: Ciphertext part 1 chunk
    - Ct2: Ciphertext part 2 chunk

Reference:
    ML-KEM Braid Section 2.3
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


class MessageType(IntEnum):
    """
    Protocol message types.
    
    Each type indicates what payload is present and what protocol
    state transition should occur.
    """
    NONE = 0       # No payload
    HDR = 1        # Header chunk (ek_seed || hek, with MAC)
    EK = 2         # Encapsulation key vector chunk
    EK_CT1_ACK = 3 # EK chunk + ct1 received acknowledgment
    CT1_ACK = 4    # ct1 acknowledgment only (no payload)
    CT1 = 5        # Ciphertext part 1 chunk
    CT2 = 6        # Ciphertext part 2 chunk
    
    @classmethod
    def from_byte(cls, b: int) -> "MessageType":
        """Convert byte to MessageType."""
        return cls(b)
    
    def to_byte(self) -> bytes:
        """Convert to single byte."""
        return bytes([self.value])
    
    def has_payload(self) -> bool:
        """Check if this message type carries a data payload."""
        return self not in (MessageType.NONE, MessageType.CT1_ACK)


@dataclass
class Message:
    """
    ML-KEM Braid protocol message.
    
    A message carries:
    - The current epoch being negotiated
    - A type indicating the message purpose
    - Optional chunk data as payload
    
    Wire Format:
        [epoch: 8 bytes, big-endian]
        [type: 1 byte]
        [data_len: 2 bytes, big-endian] (only if type has payload)
        [data: data_len bytes] (only if type has payload)
    
    Usage:
        >>> msg = Message(epoch=1, type=MessageType.HDR, data=chunk_bytes)
        >>> wire_bytes = msg.to_bytes()
        >>> 
        >>> msg2 = Message.from_bytes(wire_bytes)
        >>> assert msg2.epoch == msg.epoch
    
    Attributes:
        epoch: Epoch identifier (unsigned 64-bit)
        type: Message type enum
        data: Optional payload bytes (chunk data)
    """
    epoch: int
    type: MessageType
    data: Optional[bytes] = None
    
    def __post_init__(self):
        """Validate message consistency."""
        if self.type.has_payload() and self.data is None:
            raise ValueError(f"Message type {self.type.name} requires data payload")
        if not self.type.has_payload() and self.data is not None:
            # Silently ignore data for types that don't use it
            self.data = None
    
    def to_bytes(self) -> bytes:
        """
        Serialize message to wire format.
        
        Returns:
            Bytes representation for transmission
        """
        # Header: epoch (8 bytes) + type (1 byte)
        header = struct.pack(">Q", self.epoch) + self.type.to_byte()
        
        if self.type.has_payload() and self.data is not None:
            # Include length-prefixed data
            data_len = struct.pack(">H", len(self.data))
            return header + data_len + self.data
        else:
            return header
    
    @classmethod
    def from_bytes(cls, raw: bytes) -> "Message":
        """
        Deserialize message from wire format.
        
        Args:
            raw: Wire bytes received
        
        Returns:
            Parsed Message object
        
        Raises:
            ValueError: If message is malformed
        """
        if len(raw) < 9:
            raise ValueError(f"Message too short: {len(raw)} bytes")
        
        # Parse header
        epoch = struct.unpack(">Q", raw[:8])[0]
        msg_type = MessageType.from_byte(raw[8])
        
        # Parse optional payload
        data = None
        if msg_type.has_payload():
            if len(raw) < 11:
                raise ValueError("Message with payload missing length field")
            data_len = struct.unpack(">H", raw[9:11])[0]
            if len(raw) < 11 + data_len:
                raise ValueError(f"Message payload truncated: expected {data_len} bytes")
            data = raw[11:11 + data_len]
        
        return cls(epoch=epoch, type=msg_type, data=data)
    
    def __repr__(self) -> str:
        data_info = f", {len(self.data)}B" if self.data else ""
        return f"Message(epoch={self.epoch}, type={self.type.name}{data_info})"


# Factory functions for creating specific message types

def msg_none(epoch: int) -> Message:
    """Create a no-payload message."""
    return Message(epoch=epoch, type=MessageType.NONE)


def msg_header(epoch: int, chunk_data: bytes) -> Message:
    """Create a header chunk message."""
    return Message(epoch=epoch, type=MessageType.HDR, data=chunk_data)


def msg_ek(epoch: int, chunk_data: bytes) -> Message:
    """Create an encapsulation key vector chunk message."""
    return Message(epoch=epoch, type=MessageType.EK, data=chunk_data)


def msg_ek_ct1_ack(epoch: int, chunk_data: bytes) -> Message:
    """Create an EK chunk with ct1 acknowledgment."""
    return Message(epoch=epoch, type=MessageType.EK_CT1_ACK, data=chunk_data)


def msg_ct1_ack(epoch: int) -> Message:
    """Create a ct1 acknowledgment (no payload)."""
    return Message(epoch=epoch, type=MessageType.CT1_ACK)


def msg_ct1(epoch: int, chunk_data: bytes) -> Message:
    """Create a ciphertext part 1 chunk message."""
    return Message(epoch=epoch, type=MessageType.CT1, data=chunk_data)


def msg_ct2(epoch: int, chunk_data: bytes) -> Message:
    """Create a ciphertext part 2 chunk message."""
    return Message(epoch=epoch, type=MessageType.CT2, data=chunk_data)


# Self-test
if __name__ == "__main__":
    import os
    
    print("Testing Message Types...")
    
    # Test each message type
    chunk = os.urandom(34)  # 32-byte chunk + 2-byte index
    
    messages = [
        msg_none(epoch=1),
        msg_header(epoch=1, chunk_data=chunk),
        msg_ek(epoch=1, chunk_data=chunk),
        msg_ek_ct1_ack(epoch=1, chunk_data=chunk),
        msg_ct1_ack(epoch=2),
        msg_ct1(epoch=2, chunk_data=chunk),
        msg_ct2(epoch=2, chunk_data=chunk),
    ]
    
    for msg in messages:
        # Test serialization roundtrip
        wire = msg.to_bytes()
        recovered = Message.from_bytes(wire)
        
        assert recovered.epoch == msg.epoch
        assert recovered.type == msg.type
        assert recovered.data == msg.data
        
        print(f"  {msg} -> {len(wire)} bytes ✓")
    
    # Test has_payload
    assert not MessageType.NONE.has_payload()
    assert not MessageType.CT1_ACK.has_payload()
    assert MessageType.HDR.has_payload()
    assert MessageType.CT1.has_payload()
    print("  has_payload() ✓")
    
    # Test large epoch
    large_epoch = 2**63 - 1
    msg = msg_none(epoch=large_epoch)
    wire = msg.to_bytes()
    recovered = Message.from_bytes(wire)
    assert recovered.epoch == large_epoch
    print(f"  Large epoch {large_epoch} ✓")
    
    print("Message tests passed!")
