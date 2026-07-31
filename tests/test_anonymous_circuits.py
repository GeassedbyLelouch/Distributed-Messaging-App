import pytest
from cryptography.exceptions import InvalidTag
from dataclasses import replace

from ml_kem_braid.decentralized.circuits import (
    CircuitFrame,
    CircuitGuardCapacityError,
    CircuitSequenceGuard,
    LayerKeys,
    build_three_hop_frame,
    open_three_hop_frame,
    pad_payload,
    peel_hop_layer,
    reset_default_sequence_guard,
    unpad_payload,
)


@pytest.fixture(autouse=True)
def _fresh_sequence_guard():
    """Each test acts as a fresh process with fresh layer keys (audit M5).

    The module-level guard refuses to reuse a (key, circuit_id, hop, sequence)
    tuple, which is exactly the AES-GCM nonce reuse the fix forbids; tests that
    legitimately rebuild the same frame therefore start from a clean guard.
    """

    reset_default_sequence_guard()
    yield
    reset_default_sequence_guard()


def _keys():
    return (
        LayerKeys(hop_id="entry", key=b"e" * 32),
        LayerKeys(hop_id="middle", key=b"m" * 32),
        LayerKeys(hop_id="exit", key=b"x" * 32),
    )


def test_three_hop_frame_hides_payload_until_all_layers_are_peeled():
    plaintext = b"GET /v1/mailbox"
    keys = _keys()

    frame = build_three_hop_frame(
        circuit_id=b"1" * 16,
        payload=plaintext,
        keys=keys,
        sequence=1,
    )

    assert plaintext not in frame.payload

    frame = peel_hop_layer(frame, keys[0])
    assert plaintext not in frame.payload

    frame = peel_hop_layer(frame, keys[1])
    assert plaintext not in frame.payload

    frame = peel_hop_layer(frame, keys[2])
    assert frame.payload != plaintext  # still padded to the size class
    assert len(frame.payload) == 1024
    assert unpad_payload(frame.payload) == plaintext


def test_three_hop_frame_accepts_positional_plan_api_shape():
    keys = _keys()

    frame = build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", keys, 1)

    assert frame.circuit_id == b"1" * 16


def test_three_hop_frame_defaults_to_stable_size_class():
    frame = build_three_hop_frame(
        circuit_id=b"1" * 16,
        payload=b"GET /v1/mailbox",
        keys=_keys(),
        sequence=1,
    )

    assert frame.size_class == 1024


def test_same_sequence_on_different_circuits_produces_different_outer_payloads():
    keys = _keys()

    first = build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", keys, 1)
    second = build_three_hop_frame(b"2" * 16, b"GET /v1/mailbox", keys, 1)

    assert first.payload != second.payload


def test_circuit_frame_requires_three_hops():
    keys = (
        LayerKeys(hop_id="entry", key=b"e" * 32),
        LayerKeys(hop_id="middle", key=b"m" * 32),
    )

    with pytest.raises(ValueError, match="three hops"):
        build_three_hop_frame(
            circuit_id=b"1" * 16,
            payload=b"GET /v1/mailbox",
            keys=keys,
            sequence=1,
        )


def test_circuit_frame_rejects_duplicate_hop_ids():
    keys = (
        LayerKeys(hop_id="entry", key=b"e" * 32),
        LayerKeys(hop_id="entry", key=b"m" * 32),
        LayerKeys(hop_id="exit", key=b"x" * 32),
    )

    with pytest.raises(ValueError, match="three hops"):
        build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", keys, 1)


def test_wrong_peel_order_fails():
    keys = _keys()
    frame = build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", keys, 1)

    # Fixed size classes (audit M6) make an out-of-order peel detectable from
    # the frame length alone; deeper hops still fail on the AEAD tag.
    with pytest.raises((InvalidTag, ValueError)):
        peel_hop_layer(frame, keys[1])


def test_wrong_key_fails_to_peel_layer():
    keys = _keys()
    frame = build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", keys, 1)
    wrong_entry_key = LayerKeys(hop_id="entry", key=b"z" * 32)

    with pytest.raises(InvalidTag):
        peel_hop_layer(frame, wrong_entry_key)


def test_invalid_circuit_id_is_rejected():
    with pytest.raises(ValueError, match="16 bytes"):
        build_three_hop_frame(b"short", b"GET /v1/mailbox", _keys(), 1)


@pytest.mark.parametrize("sequence", [-1, 1 << 64])
def test_invalid_sequence_bounds_are_rejected(sequence):
    with pytest.raises(ValueError, match="sequence"):
        build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", _keys(), sequence)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("circuit_id", b"2" * 16),
        ("frame_type", "control"),
        ("sequence", 2),
    ],
)
def test_tampered_associated_data_fields_fail_to_peel(field, value):
    keys = _keys()
    frame = build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", keys, 1)
    tampered = replace(frame, **{field: value})

    with pytest.raises(InvalidTag):
        peel_hop_layer(tampered, keys[0])


def test_tampered_size_class_is_rejected_before_decryption():
    """size_class is bound into the AD *and* fixes the expected frame length."""

    keys = _keys()
    frame = build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", keys, 1)
    tampered = replace(frame, size_class=2048)

    with pytest.raises(ValueError, match="size class"):
        peel_hop_layer(tampered, keys[0])


def test_padding_uses_declared_size_class():
    padded = pad_payload(b"hello", size_class=64)

    assert len(padded) == 64
    assert unpad_payload(padded) == b"hello"


def test_padding_rejects_payload_too_large_for_class():
    with pytest.raises(ValueError, match="size class"):
        pad_payload(b"x" * 65, size_class=64)


def test_padding_accepts_largest_two_byte_payload_length():
    payload = b"x" * 65535
    padded = pad_payload(payload, size_class=65537)

    assert len(padded) == 65537
    assert unpad_payload(padded) == payload


def test_padding_rejects_payload_too_large_for_two_byte_length_prefix():
    with pytest.raises(ValueError, match="length prefix"):
        pad_payload(b"x" * 65536, size_class=65538)


def test_padding_rejects_too_small_size_class():
    with pytest.raises(ValueError, match="size class"):
        pad_payload(b"", size_class=1)


def test_unpadding_rejects_invalid_declared_length():
    with pytest.raises(ValueError, match="declared length"):
        unpad_payload(b"\x00\x04ab")


def test_unpadding_rejects_nonzero_padding_bytes():
    with pytest.raises(ValueError, match="padding"):
        unpad_payload(b"\x00\x02hi\x01")


@pytest.mark.parametrize(
    ("func", "args"),
    [
        (pad_payload, ("hello", 64)),
        (unpad_payload, ("hello",)),
    ],
)
def test_padding_helpers_reject_non_bytes_inputs(func, args):
    with pytest.raises(TypeError, match="bytes"):
        func(*args)


def test_padding_rejects_bool_size_class():
    with pytest.raises(TypeError, match="size_class"):
        pad_payload(b"", True)


def test_circuit_frame_rejects_bool_size_class():
    with pytest.raises(TypeError, match="size_class"):
        CircuitFrame(
            circuit_id=b"1" * 16,
            frame_type="data",
            size_class=True,
            sequence=1,
            payload=b"GET /v1/mailbox",
        )


def test_build_three_hop_frame_rejects_bool_size_class():
    with pytest.raises(TypeError, match="size_class"):
        build_three_hop_frame(
            circuit_id=b"1" * 16,
            payload=b"GET /v1/mailbox",
            keys=_keys(),
            sequence=1,
            size_class=True,
        )


# --- Audit M6: size-class padding -------------------------------------------


@pytest.mark.parametrize("payload", [b"", b"hi", b"GET /v1/mailbox", b"x" * 400])
def test_frame_length_does_not_leak_plaintext_length(payload):
    """Every frame in a size class is byte-identical in length (audit M6)."""

    keys = _keys()
    frame = build_three_hop_frame(b"1" * 16, payload, keys, 1, size_class=1024)

    assert len(frame.payload) == 1024 + 48
    assert open_three_hop_frame(frame, keys) == payload


def test_frames_of_different_payload_lengths_are_indistinguishable_by_length():
    keys = _keys()
    short = build_three_hop_frame(b"1" * 16, b"a", keys, 1)
    long = build_three_hop_frame(b"1" * 16, b"a" * 512, keys, 2)

    assert len(short.payload) == len(long.payload)


def test_off_size_frame_is_rejected():
    keys = _keys()
    frame = build_three_hop_frame(b"1" * 16, b"payload", keys, 1)
    truncated = replace(frame, payload=frame.payload[:-1])

    with pytest.raises(ValueError, match="size class"):
        peel_hop_layer(truncated, keys[0])


def test_payload_that_looks_like_padding_round_trips_byte_for_byte():
    """Verifier D12: padding must never be inferred from payload contents.

    ``pad_payload(b"abc", 1024)`` is a 1024-byte blob that parses as
    well-formed padding. The old ``_pad_to_size_class`` treated any payload of
    exactly ``size_class`` bytes that parsed as padding as "pre-padded" and
    passed it through, so opening the frame silently returned ``b"abc"`` — 1021
    bytes of the caller's data were destroyed with no error anywhere.
    """

    keys = _keys()
    lookalike = pad_payload(b"abc", 1024)

    frame = build_three_hop_frame(b"1" * 16, lookalike, keys, 1, size_class=2048)

    assert len(frame.payload) == 2048 + 48
    assert open_three_hop_frame(frame, keys) == lookalike


def test_payload_exactly_filling_the_size_class_round_trips_exactly():
    keys = _keys()
    # size_class - 2 is the largest payload a size class can carry (2-byte
    # length prefix), and it is the boundary the truncation bug lived on.
    payload = bytes(range(256)) * 2 + b"\xff" * 510
    assert len(payload) == 1022

    frame = build_three_hop_frame(b"1" * 16, payload, keys, 1, size_class=1024)

    assert open_three_hop_frame(frame, keys) == payload


@pytest.mark.parametrize("length", [0, 1, 2, 3, 1021, 1022])
def test_round_trip_is_exact_at_every_boundary_length(length):
    keys = _keys()
    payload = bytes((index * 7 + 3) % 256 for index in range(length))

    frame = build_three_hop_frame(b"1" * 16, payload, keys, length + 1, size_class=1024)

    assert open_three_hop_frame(frame, keys) == payload


def test_payload_of_exactly_size_class_bytes_is_rejected_not_truncated():
    keys = _keys()
    zero_padding_lookalike = pad_payload(b"", 1024)

    with pytest.raises(ValueError, match="size class"):
        build_three_hop_frame(
            b"1" * 16, zero_padding_lookalike, keys, 1, size_class=1024
        )


def test_payload_larger_than_size_class_is_rejected():
    with pytest.raises(ValueError, match="size class"):
        build_three_hop_frame(b"1" * 16, b"x" * 2048, _keys(), 1, size_class=1024)


# --- Audit M5: AES-GCM nonce uniqueness --------------------------------------


def test_sequence_reuse_under_same_key_and_circuit_is_rejected():
    """Reusing a sequence reproduces the GCM nonce -> must fail closed."""

    keys = _keys()
    build_three_hop_frame(b"1" * 16, b"first", keys, 7)

    with pytest.raises(ValueError, match="strictly increasing"):
        build_three_hop_frame(b"1" * 16, b"second", keys, 7)


def test_sequence_rollback_under_same_key_and_circuit_is_rejected():
    keys = _keys()
    build_three_hop_frame(b"1" * 16, b"first", keys, 9)

    with pytest.raises(ValueError, match="strictly increasing"):
        build_three_hop_frame(b"1" * 16, b"second", keys, 8)


def test_increasing_sequences_are_accepted_and_use_distinct_nonces():
    keys = _keys()
    first = build_three_hop_frame(b"1" * 16, b"same-plaintext", keys, 1)
    second = build_three_hop_frame(b"1" * 16, b"same-plaintext", keys, 2)

    assert first.payload != second.payload


def test_sequence_guard_is_scoped_per_circuit_and_hop_key():
    keys = _keys()
    other_keys = (
        LayerKeys(hop_id="entry", key=b"E" * 32),
        LayerKeys(hop_id="middle", key=b"M" * 32),
        LayerKeys(hop_id="exit", key=b"X" * 32),
    )
    build_three_hop_frame(b"1" * 16, b"payload", keys, 1)

    # Different circuit with the same keys, and different keys on the same
    # circuit, both produce distinct nonces and are therefore allowed.
    build_three_hop_frame(b"2" * 16, b"payload", keys, 1)
    build_three_hop_frame(b"1" * 16, b"payload", other_keys, 1)


def test_explicit_guard_isolates_sequence_state():
    keys = _keys()
    guard = CircuitSequenceGuard()
    build_three_hop_frame(b"1" * 16, b"payload", keys, 1, guard=guard)

    with pytest.raises(ValueError, match="strictly increasing"):
        build_three_hop_frame(b"1" * 16, b"payload", keys, 1, guard=guard)


# --- Verifier D11: the guard must not be an eviction primitive ---------------


def test_flooding_the_guard_cannot_evict_a_victim_high_water_mark():
    """Flood the guard, then replay the victim's sequence: still rejected.

    The guard used to be a 4096-entry LRU. Touching 4096 fresh
    ``(key, circuit_id, hop)`` triples evicted the victim circuit's entry, and
    the victim's sequence — and therefore its AES-GCM nonce — became reusable.
    """

    keys = _keys()
    victim_circuit = b"V" * 16
    build_three_hop_frame(victim_circuit, b"victim frame", keys, 7)
    victim_nonce_frame = build_three_hop_frame(victim_circuit, b"victim two", keys, 8)

    # Flood well past the old 4096-entry capacity with attacker circuits.
    for index in range(5000):
        build_three_hop_frame(index.to_bytes(16, "big"), b"flood", keys, 1)

    # The victim's mark survived the flood: the nonce cannot be replayed.
    for replayed in (7, 8):
        with pytest.raises(ValueError, match="strictly increasing"):
            build_three_hop_frame(victim_circuit, b"forged", keys, replayed)

    # And the legitimate next sequence still works and is a distinct nonce.
    following = build_three_hop_frame(victim_circuit, b"victim two", keys, 9)
    assert following.payload != victim_nonce_frame.payload


def test_guard_fails_closed_instead_of_forgetting_when_full():
    keys = _keys()
    guard = CircuitSequenceGuard(capacity=6)  # two circuits' worth (3 hops each)
    build_three_hop_frame(b"1" * 16, b"first", keys, 5, guard=guard)
    build_three_hop_frame(b"2" * 16, b"second", keys, 5, guard=guard)
    assert guard.tracked_circuit_hops() == 6

    with pytest.raises(CircuitGuardCapacityError, match="capacity"):
        build_three_hop_frame(b"3" * 16, b"overflow", keys, 5, guard=guard)

    # Nothing was forgotten to make room, so both victims stay protected.
    for circuit_id in (b"1" * 16, b"2" * 16):
        with pytest.raises(ValueError, match="strictly increasing"):
            build_three_hop_frame(circuit_id, b"replay", keys, 5, guard=guard)
    assert guard.tracked_circuit_hops() == 6


def test_guard_state_per_circuit_hop_is_one_integer_not_a_seen_set():
    """A million frames on one circuit must not grow the guard."""

    keys = _keys()
    guard = CircuitSequenceGuard(capacity=3)
    for sequence in range(1, 500):
        build_three_hop_frame(b"1" * 16, b"payload", keys, sequence, guard=guard)

    assert guard.tracked_circuit_hops() == 3
    with pytest.raises(ValueError, match="strictly increasing"):
        build_three_hop_frame(b"1" * 16, b"replay", keys, 250, guard=guard)
