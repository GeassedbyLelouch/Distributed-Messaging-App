"""
Message Types for ML-KEM Braid Protocol

Defines the protocol message format and serialization.

Message Structure:
    - epoch: Current epoch being negotiated (8 bytes)
    - type: Message type enum (1 byte)
    - data_len: payload length (2 bytes, ALWAYS present, 0 for payload-free types)
    - data: Optional chunk payload (variable length)
    - frame_mac: 32-byte MAC over the whole frame body (see below)

Frame authentication (audit finding M1)
---------------------------------------
The Braid content MACs cover only the reassembled header (``ek_seed || hek``) and
the ciphertext bytes. They do **not** cover the wire framing, yet the state machine
transitions on ``msg.epoch`` and ``msg.type`` (e.g. ``Ct2Sampled.receive`` advances
the epoch on *any* message with ``epoch + 1``). A single spoofed frame therefore
desynchronised a session permanently, because ``epoch`` is bound into every
subsequent MAC.

Every frame now carries a ``frame_mac`` computed by
:meth:`ml_kem_braid.core.authenticator.Authenticator.mac_frame` over
:meth:`Message.mac_input`, which is the canonical, length-prefixed encoding of the
ENTIRE frame body (type byte + epoch + length prefix + payload). The Braid
orchestrator seals on send and verifies before dispatching to the state machine, so
no epoch/type-driven transition happens without a verified MAC.

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


# Size of the per-frame MAC (HMAC-SHA256, truncated to nothing).
FRAME_MAC_SIZE = 32

# Fixed part of the wire frame: epoch (8) + type (1) + data_len (2).
_FRAME_PREAMBLE_SIZE = 11

# Domain separator for the frame MAC input. Bumped whenever the framing changes.
FRAME_MAC_DOMAIN = b"MLKEMBraid:frame:v2"


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
    
    Wire Format (v2 — frame-authenticated):
        [epoch: 8 bytes, big-endian]
        [type: 1 byte]
        [data_len: 2 bytes, big-endian]   (ALWAYS present; 0 for payload-free types)
        [data: data_len bytes]
        [frame_mac: 32 bytes]             (present iff the frame has been sealed)

    The total frame length is therefore exactly ``11 + data_len`` (unsealed) or
    ``11 + data_len + 32`` (sealed). Any other length is a framing error and is
    rejected — trailing bytes are never ignored (audit finding L7).

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
        frame_mac: 32-byte MAC over :meth:`mac_input`, or None if not yet sealed
    """
    epoch: int
    type: MessageType
    data: Optional[bytes] = None
    frame_mac: Optional[bytes] = None

    def __post_init__(self):
        """Validate message consistency."""
        if self.type.has_payload() and self.data is None:
            raise ValueError(f"Message type {self.type.name} requires data payload")
        if not self.type.has_payload() and self.data is not None:
            # Silently ignore data for types that don't use it
            self.data = None
        if not 0 <= self.epoch < 2 ** 64:
            raise ValueError(f"epoch out of range: {self.epoch}")
        if self.data is not None and len(self.data) > 0xFFFF:
            raise ValueError(f"payload too large: {len(self.data)} bytes")
        if self.frame_mac is not None and len(self.frame_mac) != FRAME_MAC_SIZE:
            raise ValueError(
                f"frame_mac must be {FRAME_MAC_SIZE} bytes, got {len(self.frame_mac)}"
            )

    def frame_body(self) -> bytes:
        """
        Serialize everything except the frame MAC.

        This is the exact byte string the frame MAC authenticates.
        """
        payload = self.data or b""
        return (
            struct.pack(">Q", self.epoch)
            + self.type.to_byte()
            + struct.pack(">H", len(payload))
            + payload
        )

    def mac_input(self) -> bytes:
        """
        Canonical MAC input for this frame.

        ``FRAME_MAC_DOMAIN || u32(len(body)) || body`` where ``body`` is
        :meth:`frame_body` — i.e. the ENTIRE serialized frame (type byte, epoch,
        length prefix and payload). Every variable-length component is
        length-prefixed so the encoding is injective (audit finding L6).
        """
        body = self.frame_body()
        return FRAME_MAC_DOMAIN + struct.pack(">I", len(body)) + body

    def to_bytes(self) -> bytes:
        """
        Serialize message to wire format.

        Returns:
            Bytes representation for transmission
        """
        if self.frame_mac is None:
            return self.frame_body()
        return self.frame_body() + self.frame_mac

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Message":
        """
        Deserialize message from wire format.

        Args:
            raw: Wire bytes received

        Returns:
            Parsed Message object

        Raises:
            ValueError: If message is malformed, truncated, or has trailing bytes
        """
        if len(raw) < _FRAME_PREAMBLE_SIZE:
            raise ValueError(f"Message too short: {len(raw)} bytes")

        # Parse header
        epoch = struct.unpack(">Q", raw[:8])[0]
        msg_type = MessageType.from_byte(raw[8])
        data_len = struct.unpack(">H", raw[9:11])[0]

        if not msg_type.has_payload() and data_len != 0:
            raise ValueError(
                f"Message type {msg_type.name} carries no payload but declares "
                f"{data_len} bytes"
            )

        body_end = _FRAME_PREAMBLE_SIZE + data_len
        if len(raw) < body_end:
            raise ValueError(f"Message payload truncated: expected {data_len} bytes")

        data = raw[_FRAME_PREAMBLE_SIZE:body_end] if msg_type.has_payload() else None

        # The frame is either exactly the body, or the body plus a frame MAC.
        # Anything else is trailing garbage and MUST be rejected (L7): silently
        # ignoring it would make the wire encoding malleable.
        remainder = len(raw) - body_end
        if remainder == 0:
            frame_mac = None
        elif remainder == FRAME_MAC_SIZE:
            frame_mac = raw[body_end:]
        else:
            raise ValueError(
                f"Message has {remainder} trailing bytes after the frame body"
            )

        return cls(epoch=epoch, type=msg_type, data=data, frame_mac=frame_mac)

    def __repr__(self) -> str:
        data_info = f", {len(self.data)}B" if self.data else ""
        sealed = "" if self.frame_mac is None else ", sealed"
        return f"Message(epoch={self.epoch}, type={self.type.name}{data_info}{sealed})"


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
