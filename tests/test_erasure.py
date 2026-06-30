"""Reed-Solomon erasure coding tests: lossless and genuine loss recovery."""

import os
import random

import pytest

from ml_kem_braid.encoding.erasure import Chunk, Decoder, Encoder


@pytest.mark.parametrize("size", [64, 96, 160, 640, 960, 1152, 1408])
def test_lossless_roundtrip(size):
    msg = os.urandom(size)
    enc = Encoder(msg)
    dec = Decoder.new(size)
    for i in range(enc.message_chunks):
        dec.add_chunk(enc.chunk_at(i))
    assert dec.has_message()
    assert dec.message() == msg


@pytest.mark.parametrize("size", [96, 960, 1152, 1408])
def test_recovery_under_loss(size):
    """Any k of (k+p) chunks must reconstruct the message."""
    rng = random.Random(size)
    msg = os.urandom(size)
    enc = Encoder(msg)
    chunks = [enc.chunk_at(i) for i in range(enc.total_chunks)]
    # Drop exactly `parity_chunks` chunks (the maximum the code tolerates).
    rng.shuffle(chunks)
    survivors = chunks[: enc.message_chunks]  # keep only k chunks
    assert len(survivors) == enc.message_chunks

    dec = Decoder.new(size)
    for c in survivors:
        dec.add_chunk(c)
    assert dec.has_message()
    assert dec.message() == msg


def test_insufficient_chunks_no_message():
    msg = os.urandom(960)
    enc = Encoder(msg)
    dec = Decoder.new(960)
    for i in range(enc.message_chunks - 1):  # one short
        dec.add_chunk(enc.chunk_at(i))
    assert not dec.has_message()
    assert dec.message() is None


def test_chunk_serialization():
    c = Chunk(index=1234, data=os.urandom(32))
    assert Chunk.from_bytes(c.to_bytes()) == c
