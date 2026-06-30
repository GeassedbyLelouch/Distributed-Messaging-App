"""Anonymous circuit frame primitives."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_AES_KEY_SIZES = {16, 24, 32}
_HOP_LAYER_INDEX = {
    "entry": 0,
    "middle": 1,
    "exit": 2,
}
_HOP_ORDER = ("entry", "middle", "exit")
_MAX_U16 = (1 << 16) - 1
_MAX_U64 = (1 << 64) - 1


def pad_payload(payload: bytes, size_class: int) -> bytes:
    """Pad a payload to a fixed-size anonymous circuit size class."""

    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    _validate_size_class(size_class, minimum=2)
    if len(payload) > _MAX_U16:
        raise ValueError("payload is too large for 2-byte length prefix")
    if len(payload) > size_class - 2:
        raise ValueError("payload is too large for size class")

    payload_length = len(payload).to_bytes(2, "big")
    return payload_length + payload + (b"\x00" * (size_class - 2 - len(payload)))


def unpad_payload(padded: bytes) -> bytes:
    """Remove fixed-size anonymous circuit padding."""

    if not isinstance(padded, bytes):
        raise TypeError("padded payload must be bytes")
    if len(padded) < 2:
        raise ValueError("padded payload must include a 2-byte declared length")

    payload_length = int.from_bytes(padded[:2], "big")
    if payload_length > len(padded) - 2:
        raise ValueError("declared length exceeds available bytes")
    if padded[2 + payload_length :] != b"\x00" * (len(padded) - 2 - payload_length):
        raise ValueError("padding bytes must be zero")
    return padded[2 : 2 + payload_length]


@dataclass(frozen=True)
class LayerKeys:
    hop_id: str
    key: bytes

    def __post_init__(self) -> None:
        if self.hop_id not in _HOP_LAYER_INDEX:
            raise ValueError("hop_id must be entry, middle, or exit")
        if not isinstance(self.key, bytes):
            raise TypeError("key must be bytes")
        if len(self.key) not in _AES_KEY_SIZES:
            raise ValueError("AES-GCM key must be 16, 24, or 32 bytes")


@dataclass(frozen=True)
class CircuitFrame:
    circuit_id: bytes
    frame_type: str
    size_class: int
    sequence: int
    payload: bytes

    def __post_init__(self) -> None:
        _validate_circuit_id(self.circuit_id)
        _validate_sequence(self.sequence)
        if not isinstance(self.frame_type, str) or not self.frame_type:
            raise ValueError("frame_type must be a non-empty string")
        _validate_size_class(self.size_class, minimum=0)
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be bytes")


def build_three_hop_frame(
    circuit_id: bytes,
    payload: bytes,
    keys: tuple[LayerKeys, ...] | list[LayerKeys],
    sequence: int,
    frame_type: str = "data",
    size_class: int = 1024,
) -> CircuitFrame:
    """Build a 3-hop circuit frame with exit, middle, then entry encryption."""

    _validate_circuit_id(circuit_id)
    _validate_sequence(sequence)
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    hop_keys = _require_three_hops(keys)
    frame = CircuitFrame(
        circuit_id=circuit_id,
        frame_type=frame_type,
        size_class=size_class,
        sequence=sequence,
        payload=payload,
    )

    encrypted_payload = payload
    for hop_id in reversed(_HOP_ORDER):
        layer_key = hop_keys[hop_id]
        encrypted_payload = AESGCM(layer_key.key).encrypt(
            _nonce_for(frame.circuit_id, sequence, hop_id),
            encrypted_payload,
            _associated_data(frame, hop_id),
        )

    return CircuitFrame(
        circuit_id=frame.circuit_id,
        frame_type=frame.frame_type,
        size_class=frame.size_class,
        sequence=frame.sequence,
        payload=encrypted_payload,
    )


def peel_hop_layer(frame: CircuitFrame, key: LayerKeys) -> CircuitFrame:
    plaintext = AESGCM(key.key).decrypt(
        _nonce_for(frame.circuit_id, frame.sequence, key.hop_id),
        frame.payload,
        _associated_data(frame, key.hop_id),
    )
    return CircuitFrame(
        circuit_id=frame.circuit_id,
        frame_type=frame.frame_type,
        size_class=frame.size_class,
        sequence=frame.sequence,
        payload=plaintext,
    )


def _require_three_hops(keys: tuple[LayerKeys, ...] | list[LayerKeys]) -> dict[str, LayerKeys]:
    if len(keys) != 3:
        raise ValueError("circuit frames require exactly three hops")

    hop_keys = {layer_key.hop_id: layer_key for layer_key in keys}
    if set(hop_keys) != set(_HOP_ORDER):
        raise ValueError("circuit frames require entry, middle, and exit three hops")
    return hop_keys


def _nonce_for(circuit_id: bytes, sequence: int, hop_id: str) -> bytes:
    layer_index = _HOP_LAYER_INDEX[hop_id]
    digest = sha256(
        b"ml-kem-braid:circuit-frame-nonce:v1"
        + circuit_id
        + sequence.to_bytes(8, "big")
        + layer_index.to_bytes(4, "big")
    ).digest()
    return digest[:12]


def _associated_data(frame: CircuitFrame, hop_id: str) -> bytes:
    return b"".join(
        [
            frame.circuit_id,
            frame.frame_type.encode("utf-8"),
            frame.size_class.to_bytes(8, "big"),
            frame.sequence.to_bytes(8, "big"),
            hop_id.encode("utf-8"),
        ]
    )


def _validate_circuit_id(circuit_id: bytes) -> None:
    if not isinstance(circuit_id, bytes):
        raise TypeError("circuit_id must be bytes")
    if len(circuit_id) != 16:
        raise ValueError("circuit_id must be exactly 16 bytes")


def _validate_sequence(sequence: int) -> None:
    if not isinstance(sequence, int):
        raise TypeError("sequence must be an integer")
    if sequence < 0:
        raise ValueError("sequence must be non-negative")
    if sequence > _MAX_U64:
        raise ValueError("sequence must fit in 64 bits")


def _validate_size_class(size_class: int, minimum: int) -> None:
    if not isinstance(size_class, int) or isinstance(size_class, bool):
        raise TypeError("size_class must be an integer")
    if size_class < minimum:
        if minimum == 0:
            raise ValueError("size_class must be a non-negative integer")
        raise ValueError(f"size class must be at least {minimum} bytes")
