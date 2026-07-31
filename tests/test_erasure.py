"""Reed-Solomon erasure coding tests: lossless and genuine loss recovery."""

import os
import random

import pytest

from ml_kem_braid.encoding.erasure import (
    CHUNK_TAG_SIZE,
    Chunk,
    ChunkIntegrityError,
    Decoder,
    Encoder,
    MessageIntegrityError,
    chunk_tag,
    decode_message,
    encode_message,
)


@pytest.mark.parametrize("size", [64, 96, 160, 640, 960, 1152, 1408])
def test_lossless_roundtrip(size):
    msg = os.urandom(size)
    enc = Encoder(msg, allow_unauthenticated_shares=True)
    dec = Decoder.new(size, allow_unauthenticated_shares=True)
    for i in range(enc.message_chunks):
        dec.add_chunk(enc.chunk_at(i))
    assert dec.has_message()
    assert dec.message() == msg


@pytest.mark.parametrize("size", [96, 960, 1152, 1408])
def test_recovery_under_loss(size):
    """Any k of (k+p) chunks must reconstruct the message."""
    rng = random.Random(size)
    msg = os.urandom(size)
    enc = Encoder(msg, allow_unauthenticated_shares=True)
    chunks = [enc.chunk_at(i) for i in range(enc.total_chunks)]
    # Drop exactly `parity_chunks` chunks (the maximum the code tolerates).
    rng.shuffle(chunks)
    survivors = chunks[: enc.message_chunks]  # keep only k chunks
    assert len(survivors) == enc.message_chunks

    dec = Decoder.new(size, allow_unauthenticated_shares=True)
    for c in survivors:
        dec.add_chunk(c)
    assert dec.has_message()
    assert dec.message() == msg


def test_insufficient_chunks_no_message():
    msg = os.urandom(960)
    enc = Encoder(msg, allow_unauthenticated_shares=True)
    dec = Decoder.new(960, allow_unauthenticated_shares=True)
    for i in range(enc.message_chunks - 1):  # one short
        dec.add_chunk(enc.chunk_at(i))
    assert not dec.has_message()
    assert dec.message() is None


def test_chunk_serialization():
    c = Chunk(index=1234, data=os.urandom(32))
    assert (
        Chunk.from_bytes(c.to_bytes(), allow_unauthenticated_shares=True) == c
    )


# --- Audit H3: per-share integrity -------------------------------------------

KEY = b"k" * 32
OTHER_KEY = b"z" * 32


def _keyed_pair(msg, key=KEY):
    enc = Encoder(msg, key=key)
    dec = Decoder.new(len(msg), key=key, expected_message_tag=enc.message_tag())
    return enc, dec


def test_keyed_roundtrip_with_loss_still_recovers():
    msg = os.urandom(960)
    enc, dec = _keyed_pair(msg)
    chunks = [enc.chunk_at(i) for i in range(enc.total_chunks)]
    rng = random.Random(7)
    rng.shuffle(chunks)
    for chunk in chunks[: enc.message_chunks]:
        dec.add_chunk(chunk)

    assert dec.message() == msg


def test_flipped_byte_in_delivered_share_is_rejected():
    """RS erasure decoding cannot see corruption; the keyed tag must."""

    msg = os.urandom(320)
    enc, dec = _keyed_pair(msg)
    chunk = enc.chunk_at(3)
    corrupted = Chunk(
        index=chunk.index,
        data=bytes([chunk.data[0] ^ 0x01]) + chunk.data[1:],
        tag=chunk.tag,
    )

    with pytest.raises(ChunkIntegrityError):
        dec.add_chunk(corrupted)

    # And the corrupted share never entered the decoder state.
    for i in range(enc.message_chunks):
        dec.add_chunk(enc.chunk_at(i))
    assert dec.message() == msg


def test_corrupted_share_without_integrity_would_silently_corrupt_output():
    """Documents why RS alone is not enough (the H3 exploit, unkeyed mode)."""

    msg = os.urandom(320)
    enc = Encoder(msg, allow_unauthenticated_shares=True)
    dec = Decoder.new(len(msg), allow_unauthenticated_shares=True)
    for i in range(enc.message_chunks):
        chunk = enc.chunk_at(i)
        if i == 2:
            chunk = Chunk(index=i, data=bytes([chunk.data[0] ^ 0xFF]) + chunk.data[1:])
        dec.add_chunk(chunk)

    # Unkeyed mode gives no corruption detection: this is exactly why a keyed
    # decoder (or a caller-level MAC over the object) is mandatory.
    assert dec.message() != msg


def test_share_tag_is_bound_to_its_index():
    msg = os.urandom(320)
    enc, dec = _keyed_pair(msg)
    chunk = enc.chunk_at(4)
    moved = Chunk(index=5, data=chunk.data, tag=chunk.tag)

    with pytest.raises(ChunkIntegrityError):
        dec.add_chunk(moved)


def test_share_tag_under_a_different_key_is_rejected():
    msg = os.urandom(320)
    enc, dec = _keyed_pair(msg)
    forged = Encoder(msg, key=OTHER_KEY).chunk_at(1)

    with pytest.raises(ChunkIntegrityError):
        dec.add_chunk(forged)


def test_share_from_another_stream_cannot_be_spliced_in():
    msg = os.urandom(320)
    enc, dec = _keyed_pair(msg)
    other = Encoder(os.urandom(640), key=KEY)

    with pytest.raises(ChunkIntegrityError):
        dec.add_chunk(other.chunk_at(1))


def test_duplicate_index_with_different_data_is_rejected():
    """Even an attacker holding the chunk key cannot overwrite a stored share."""

    msg = os.urandom(320)
    enc = Encoder(msg, key=KEY)
    dec = Decoder.new(len(msg), key=KEY)
    dec.add_chunk(enc.chunk_at(0))

    other_data = b"\x00" * enc.chunk_size
    forged = Chunk(
        index=0,
        data=other_data,
        tag=chunk_tag(
            KEY,
            0,
            other_data,
            chunk_size=enc.chunk_size,
            message_size=len(msg),
        ),
    )
    with pytest.raises(ChunkIntegrityError):
        dec.add_chunk(forged)

    # The originally received share is untouched.
    for i in range(1, enc.message_chunks):
        dec.add_chunk(enc.chunk_at(i))
    assert dec.message() == msg


def test_duplicate_index_with_identical_data_is_idempotent():
    msg = os.urandom(320)
    enc = Encoder(msg, key=KEY)
    dec = Decoder.new(len(msg), key=KEY)

    assert dec.add_chunk(enc.chunk_at(0)) is True
    assert dec.add_chunk(enc.chunk_at(0)) is False


def test_keyed_decoder_rejects_untagged_shares_and_vice_versa():
    msg = os.urandom(320)
    enc = Encoder(msg, allow_unauthenticated_shares=True)
    keyed = Decoder.new(len(msg), key=KEY)

    with pytest.raises(ChunkIntegrityError):
        keyed.add_chunk(enc.chunk_at(0))

    unkeyed = Decoder.new(len(msg), allow_unauthenticated_shares=True)
    with pytest.raises(ChunkIntegrityError):
        unkeyed.add_chunk(Encoder(msg, key=KEY).chunk_at(0))


def test_whole_message_tag_catches_error_injection_during_rs_decode():
    """Belt and braces: the reassembled object is authenticated too."""

    msg = os.urandom(320)
    enc = Encoder(msg, key=KEY)
    dec = Decoder.new(len(msg), key=KEY, expected_message_tag=enc.message_tag())
    for i in range(enc.message_chunks):
        dec.add_chunk(enc.chunk_at(i))
    # Simulate an attacker who reached past add_chunk into decoder state.
    dec._chunks[1] = bytes([dec._chunks[1][0] ^ 0x01]) + dec._chunks[1][1:]

    with pytest.raises(MessageIntegrityError):
        dec.message()


def test_tagged_chunk_wire_format_round_trip():
    enc = Encoder(os.urandom(64), key=KEY)
    chunk = enc.chunk_at(1)
    raw = chunk.to_bytes()

    assert len(raw) == 2 + 16 + enc.chunk_size
    # Authenticated parsing is the DEFAULT.
    assert Chunk.from_bytes(raw) == chunk
    # Unauthenticated parsing of a tagged frame yields different bytes, so a
    # reader must know which stream it configured.
    assert (
        Chunk.from_bytes(raw, allow_unauthenticated_shares=True).data
        != chunk.data
    )


# --- D19/D20: per-share integrity must be ON by default ----------------------


def test_encoder_without_key_fails_closed():
    """An unkeyed stream must be asked for by name, never obtained by default."""

    with pytest.raises(ValueError, match="allow_unauthenticated_shares"):
        Encoder(os.urandom(320))

    with pytest.raises(ValueError, match="allow_unauthenticated_shares"):
        encode_message(os.urandom(320))


def test_decoder_without_key_fails_closed():
    with pytest.raises(ValueError, match="allow_unauthenticated_shares"):
        Decoder.new(320)

    with pytest.raises(ValueError, match="allow_unauthenticated_shares"):
        Decoder(320)

    with pytest.raises(ValueError, match="allow_unauthenticated_shares"):
        decode_message(320)


def test_default_encoder_emits_tagged_shares():
    msg = os.urandom(320)
    enc = Encoder(msg, key=KEY)
    for i in range(enc.total_chunks):
        chunk = enc.chunk_at(i)
        assert chunk.is_tagged
        assert len(chunk.tag) == CHUNK_TAG_SIZE
        assert len(chunk.to_bytes()) == 2 + CHUNK_TAG_SIZE + enc.chunk_size


def test_untagged_share_cannot_be_parsed_by_default():
    """A stripped tag must not be silently reinterpreted as data."""

    untagged = Chunk(index=0, data=b"\x11" * 32).to_bytes()  # 2 + 32 bytes
    parsed = Chunk.from_bytes(untagged)
    # Default parsing consumes 16 bytes as the tag, so the residual data length
    # no longer matches the stream geometry and the decoder drops the share.
    dec = Decoder.new(320, key=KEY)
    assert len(parsed.data) != dec.chunk_size
    assert dec.add_chunk(parsed) is False
    assert dec.missing_indices() == list(range(dec.message_chunks))
