"""Anonymous circuit frame primitives.

Layer-key contract (audit M5)
-----------------------------
Every layer key is **single-use per circuit**: the AES-GCM nonce is derived
deterministically from ``(circuit_id, sequence, hop_id)``, so re-using a
``sequence`` value under the same key and circuit reproduces the nonce. An
AES-GCM nonce collision is a total break — it XORs the two plaintexts together
and leaks the GHASH authentication key, which lets an attacker forge circuit
layers. The module therefore owns a monotonic sequence guard and refuses to
build a second frame for a ``(key, circuit_id, hop_id)`` triple at a sequence
that is not strictly greater than the last one used. Rotate layer keys (a new
circuit) rather than restarting sequence numbers.

Frame sizing (audit M6)
-----------------------
``build_three_hop_frame`` pads the innermost payload to ``size_class`` before
the first encryption, so every on-wire frame for a size class has exactly the
same length (``size_class + 48``: 16 bytes of GCM tag per hop). Peeling
validates the length expected at each hop and rejects off-size frames.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_AES_KEY_SIZES = {16, 24, 32}
_GCM_TAG_SIZE = 16
# Bound on the number of distinct ``(layer key, circuit_id, hop)`` triples the
# guard will track. Reaching it FAILS CLOSED (see CircuitSequenceGuard): the
# guard never forgets a high-water mark, because forgetting one re-authorises
# an AES-GCM nonce that has already been used.
_SEQUENCE_GUARD_CAPACITY = 1 << 16
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


class CircuitGuardCapacityError(ValueError):
    """Raised when the guard cannot track a new circuit without forgetting one.

    Subclasses ``ValueError`` so existing ``except ValueError`` callers keep
    failing closed.
    """


class CircuitSequenceGuard:
    """Monotonic high-water mark per ``(key, circuit_id, hop_id)``.

    Enforcing this in-module is what makes the deterministic nonce derivation
    safe: a nonce is only ever produced once per key (audit M5).

    Verifier D11 — why this is not a cache
    --------------------------------------
    The state per circuit-hop is ONE integer: the highest sequence ever used.
    It is not a set of seen sequences, so it cannot be grown by an attacker who
    sends many frames on a circuit — a million frames still cost one ``int``.

    An earlier revision wrapped the same table in a 4096-entry LRU that evicted
    the oldest entry once full. That turned the control into an eviction
    primitive: touch 4096 fresh ``(key, circuit_id, hop)`` triples and the
    victim circuit's high-water mark is silently forgotten, after which the
    original sequence is accepted again and the AES-GCM nonce
    ``H(circuit_id || sequence || hop)`` REPEATS. GCM nonce reuse XORs the two
    plaintexts and leaks the GHASH key, i.e. universal layer forgery — the
    single worst thing this module can do.

    The table therefore never forgets. The only bound left is on the number of
    distinct circuit-hops tracked, and hitting it FAILS CLOSED: new circuits
    are refused (:class:`CircuitGuardCapacityError`) while every existing mark
    stays enforced. Recover by rotating layer keys in a fresh process (or
    :meth:`reset`, which is exactly "these keys no longer exist").
    """

    def __init__(self, capacity: int = _SEQUENCE_GUARD_CAPACITY) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._capacity = capacity
        self._lock = threading.Lock()
        self._last: dict[tuple[bytes, bytes, str], int] = {}

    @staticmethod
    def _entry_key(key: bytes, circuit_id: bytes, hop_id: str) -> tuple[bytes, bytes, str]:
        # Store a digest, never the raw layer key.
        return (sha256(b"circuit-seq-guard:" + key).digest(), circuit_id, hop_id)

    def reserve(self, key: bytes, circuit_id: bytes, hop_id: str, sequence: int) -> None:
        entry_key = self._entry_key(key, circuit_id, hop_id)
        with self._lock:
            last = self._last.get(entry_key)
            if last is None and len(self._last) >= self._capacity:
                # Fail closed: refusing a new circuit is survivable, forgetting
                # a used nonce is not.
                raise CircuitGuardCapacityError(
                    "circuit sequence guard is at capacity; refusing to forget "
                    "a used AES-GCM nonce. Rotate layer keys in a fresh process."
                )
            if last is not None and sequence <= last:
                raise ValueError(
                    "circuit sequence must be strictly increasing per "
                    "(layer key, circuit_id, hop); reusing it would repeat an "
                    "AES-GCM nonce"
                )
            self._last[entry_key] = sequence

    def tracked_circuit_hops(self) -> int:
        """Number of ``(key, circuit_id, hop)`` triples currently tracked."""

        with self._lock:
            return len(self._last)

    def reset(self) -> None:
        with self._lock:
            self._last.clear()


_DEFAULT_SEQUENCE_GUARD = CircuitSequenceGuard()


def reset_default_sequence_guard() -> None:
    """Drop all remembered sequences (equivalent to fresh keys/process)."""

    _DEFAULT_SEQUENCE_GUARD.reset()


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
    guard: "CircuitSequenceGuard | None" = None,
) -> CircuitFrame:
    """Build a 3-hop circuit frame with exit, middle, then entry encryption.

    The payload is padded to ``size_class`` before the innermost encryption so
    the on-wire length carries no information about the plaintext length
    (audit M6). Padding is ALWAYS applied and always carries its own explicit
    2-byte length prefix, so ``open_three_hop_frame`` returns the caller's
    bytes exactly — for every payload length, including payloads that happen to
    look like padding (verifier D12).
    """

    _validate_circuit_id(circuit_id)
    _validate_sequence(sequence)
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")

    hop_keys = _require_three_hops(keys)
    _validate_size_class(size_class, minimum=2)
    padded_payload = _pad_to_size_class(payload, size_class)

    sequence_guard = _DEFAULT_SEQUENCE_GUARD if guard is None else guard
    for hop_id in _HOP_ORDER:
        sequence_guard.reserve(hop_keys[hop_id].key, circuit_id, hop_id, sequence)

    frame = CircuitFrame(
        circuit_id=circuit_id,
        frame_type=frame_type,
        size_class=size_class,
        sequence=sequence,
        payload=padded_payload,
    )

    encrypted_payload = padded_payload
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


def _pad_to_size_class(payload: bytes, size_class: int) -> bytes:
    """Always pad, unconditionally (verifier D12).

    An earlier revision treated a payload that was exactly ``size_class`` bytes
    long and happened to parse as well-formed padding as "already padded" and
    passed it through untouched. Opening then stripped a length prefix the
    caller never wrote, silently truncating the payload. Padding is now
    unambiguous: the length prefix inside the padded block is always ours, so
    the round trip is exact for every payload the size class can hold.
    """

    return pad_payload(payload, size_class)


def _expected_layer_length(size_class: int, hop_id: str) -> int:
    """On-wire payload length a frame must have when ``hop_id`` peels it."""

    remaining_layers = len(_HOP_ORDER) - _HOP_LAYER_INDEX[hop_id]
    return size_class + _GCM_TAG_SIZE * remaining_layers


def peel_hop_layer(frame: CircuitFrame, key: LayerKeys) -> CircuitFrame:
    expected_length = _expected_layer_length(frame.size_class, key.hop_id)
    if len(frame.payload) != expected_length:
        raise ValueError(
            "circuit frame length does not match its declared size class"
        )
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


def open_three_hop_frame(
    frame: CircuitFrame,
    keys: tuple[LayerKeys, ...] | list[LayerKeys],
) -> bytes:
    """Peel all three layers and strip the size-class padding.

    Rejects frames whose length does not match the declared size class at
    every hop, then returns the original (unpadded) payload.
    """

    hop_keys = _require_three_hops(keys)
    peeled = frame
    for hop_id in _HOP_ORDER:
        peeled = peel_hop_layer(peeled, hop_keys[hop_id])
    if len(peeled.payload) != frame.size_class:
        raise ValueError("peeled payload does not match its declared size class")
    return unpad_payload(peeled.payload)


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
