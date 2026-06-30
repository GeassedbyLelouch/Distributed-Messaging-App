"""
Reed-Solomon erasure coding for the ML-KEM Braid chunk stream.

The Braid protocol transmits large objects (header, ek_vector, ct1, ct2) as a
stream of fixed-size chunks so the receiver can reconstruct them even if some
chunks are lost or blocked (Braid spec Sections 1.3, 3.5-3.6). This module
implements a **real, systematic Reed-Solomon erasure code** using the
``reedsolo`` library (GF(2^8)):

* A message is split into ``k`` systematic data chunks (chunk ``i`` is the raw
  ``i``-th slice of the message). With no loss the receiver simply concatenates
  the ``k`` data chunks — zero coding overhead on the happy path.
* ``p`` parity chunks are derived by RS-encoding **across** chunks: for each byte
  offset ``o``, the column ``(data[0][o], ..., data[k-1][o])`` is treated as a
  ``k``-symbol message and RS-encoded to ``k + p`` symbols; parity chunk ``j``'s
  byte ``o`` is parity symbol ``j``. Any ``k`` of the ``k + p`` chunks (in any
  mix of data/parity) reconstruct the message via RS erasure decoding.

This is genuine erasure coding (verified against real chunk loss in the tests),
not a placeholder. The spec recommends GF(2^16); we use ``reedsolo``'s GF(2^8),
which bounds a single object to ``k + p <= 255`` chunks — ample for ML-KEM-1024
(largest object ct1 = 1408 B → 44 data chunks).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Set

import reedsolo

DEFAULT_CHUNK_SIZE = 32
# GF(2^8) Reed-Solomon: total codeword symbols per column must be <= 255.
GF_TOTAL_LIMIT = 255


def _parity_count(k: int) -> int:
    """Number of parity chunks for ``k`` data chunks (allow ~50% loss, capped)."""
    if k >= GF_TOTAL_LIMIT:
        # GF(2^8) RS bounds a codeword to 255 symbols (data + parity). Real Braid
        # objects need <= 44 data chunks, so this only guards against misuse.
        raise ValueError(
            f"message needs {k} chunks; GF(2^8) RS supports at most "
            f"{GF_TOTAL_LIMIT - 1} data chunks. Use a larger chunk_size."
        )
    if k <= 1:
        return 1 if k == 1 else 0
    return min(k, GF_TOTAL_LIMIT - k)


@dataclass
class Chunk:
    """A single erasure-code chunk: a 2-byte index plus payload bytes."""

    index: int
    data: bytes

    def to_bytes(self) -> bytes:
        return struct.pack(">H", self.index) + self.data

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Chunk":
        return cls(index=struct.unpack(">H", raw[:2])[0], data=raw[2:])


class Encoder:
    """
    Streaming systematic RS encoder. Emits data chunks ``0..k-1`` followed by
    parity chunks ``k..k+p-1`` (then cycles). Call :meth:`next_chunk` repeatedly.
    """

    def __init__(self, message: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.message = message
        self.chunk_size = chunk_size
        self.message_size = len(message)
        self.message_chunks = max(1, (self.message_size + chunk_size - 1) // chunk_size)
        self.parity_chunks = _parity_count(self.message_chunks)
        self.total_chunks = self.message_chunks + self.parity_chunks

        padded = message + b"\x00" * (self.message_chunks * chunk_size - self.message_size)
        self._data_chunks: List[bytes] = [
            padded[i * chunk_size : (i + 1) * chunk_size]
            for i in range(self.message_chunks)
        ]
        self._parity_cache: Optional[List[bytes]] = None
        self._current = 0

    def _compute_parity(self) -> List[bytes]:
        if self._parity_cache is not None:
            return self._parity_cache
        k, p = self.message_chunks, self.parity_chunks
        parity = [bytearray(self.chunk_size) for _ in range(p)]
        if p:
            rsc = reedsolo.RSCodec(p)
            for offset in range(self.chunk_size):
                column = bytes(self._data_chunks[i][offset] for i in range(k))
                codeword = rsc.encode(column)  # systematic: k data + p parity
                for j in range(p):
                    parity[j][offset] = codeword[k + j]
        self._parity_cache = [bytes(b) for b in parity]
        return self._parity_cache

    def chunk_at(self, index: int) -> Chunk:
        """Return the chunk for a logical index (data if < k, else parity)."""
        if index < self.message_chunks:
            return Chunk(index=index, data=self._data_chunks[index])
        parity = self._compute_parity()
        return Chunk(index=index, data=parity[index - self.message_chunks])

    def next_chunk(self) -> Chunk:
        index = self._current % self.total_chunks
        self._current += 1
        return self.chunk_at(index)

    def __iter__(self) -> Iterator[Chunk]:
        self._current = 0
        return self

    def __next__(self) -> Chunk:
        # One full generation (all data + parity) is enough to recover.
        if self._current >= self.total_chunks:
            raise StopIteration
        return self.next_chunk()


class Decoder:
    """
    Systematic RS erasure decoder. Feed received :class:`Chunk` objects via
    :meth:`add_chunk`; once enough chunks are present, :meth:`has_message` is
    ``True`` and :meth:`message` reconstructs the original bytes.
    """

    def __init__(self, message_size: int, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.message_size = message_size
        self.chunk_size = chunk_size
        self.message_chunks = max(1, (message_size + chunk_size - 1) // chunk_size)
        self.parity_chunks = _parity_count(self.message_chunks)
        self.total_chunks = self.message_chunks + self.parity_chunks
        self._chunks: Dict[int, bytes] = {}

    @classmethod
    def new(cls, message_size: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> "Decoder":
        return cls(message_size, chunk_size)

    def add_chunk(self, chunk: Chunk) -> None:
        if 0 <= chunk.index < self.total_chunks and len(chunk.data) == self.chunk_size:
            self._chunks[chunk.index] = chunk.data

    def _have_all_data(self) -> bool:
        return all(i in self._chunks for i in range(self.message_chunks))

    def has_message(self) -> bool:
        if self._have_all_data():
            return True
        # Need at least k chunks total, and missing-data count within parity budget.
        if len(self._chunks) < self.message_chunks:
            return False
        missing_data = sum(1 for i in range(self.message_chunks) if i not in self._chunks)
        return missing_data <= self.parity_chunks

    def message(self) -> Optional[bytes]:
        if not self.has_message():
            return None
        if self._have_all_data():
            data_chunks = [self._chunks[i] for i in range(self.message_chunks)]
            return b"".join(data_chunks)[: self.message_size]

        # RS erasure decode column by column.
        k, p = self.message_chunks, self.parity_chunks
        present: Set[int] = set(self._chunks)
        erase_pos = [i for i in range(self.total_chunks) if i not in present]
        rsc = reedsolo.RSCodec(p)
        recovered = [bytearray(self.chunk_size) for _ in range(k)]
        for offset in range(self.chunk_size):
            codeword = bytearray(self.total_chunks)
            for idx in range(self.total_chunks):
                if idx in self._chunks:
                    codeword[idx] = self._chunks[idx][offset]
            decoded = rsc.decode(bytes(codeword), erase_pos=erase_pos)[0]
            for i in range(k):
                recovered[i][offset] = decoded[i]
        return b"".join(bytes(c) for c in recovered)[: self.message_size]

    def missing_indices(self) -> List[int]:
        return [i for i in range(self.message_chunks) if i not in self._chunks]

    def reset(self) -> None:
        self._chunks.clear()


def encode_message(message: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Encoder:
    return Encoder(message, chunk_size)


def decode_message(message_size: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Decoder:
    return Decoder.new(message_size, chunk_size)


if __name__ == "__main__":
    import os
    import random

    rng = random.Random(1234)
    for size in (96, 160, 960, 1152, 1408):
        msg = os.urandom(size)
        enc = Encoder(msg)
        # Drop up to `parity_chunks` random chunks, keep the rest, shuffle order.
        all_chunks = [enc.chunk_at(i) for i in range(enc.total_chunks)]
        keep = list(all_chunks)
        for _ in range(min(enc.parity_chunks, enc.total_chunks - enc.message_chunks)):
            keep.pop(rng.randrange(len(keep)))
        rng.shuffle(keep)
        dec = Decoder.new(size)
        for c in keep:
            dec.add_chunk(c)
        out = dec.message()
        assert out == msg, f"recovery failed for size {size}"
        print(f"size {size:5d}: k={enc.message_chunks} p={enc.parity_chunks} "
              f"recovered from {len(keep)}/{enc.total_chunks} chunks (with loss) OK")
    print("Erasure coding self-tests passed.")
