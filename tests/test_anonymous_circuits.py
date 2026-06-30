import pytest
from cryptography.exceptions import InvalidTag
from dataclasses import replace

from ml_kem_braid.decentralized.circuits import (
    CircuitFrame,
    LayerKeys,
    build_three_hop_frame,
    pad_payload,
    peel_hop_layer,
    unpad_payload,
)


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
    assert frame.payload == plaintext


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

    with pytest.raises(InvalidTag):
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
        ("size_class", 2048),
        ("sequence", 2),
    ],
)
def test_tampered_associated_data_fields_fail_to_peel(field, value):
    keys = _keys()
    frame = build_three_hop_frame(b"1" * 16, b"GET /v1/mailbox", keys, 1)
    tampered = replace(frame, **{field: value})

    with pytest.raises(InvalidTag):
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
