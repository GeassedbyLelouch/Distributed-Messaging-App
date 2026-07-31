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

import hmac
import struct
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Dict, Iterator, List, Optional, Set

import reedsolo

DEFAULT_CHUNK_SIZE = 32
# GF(2^8) Reed-Solomon: total codeword symbols per column must be <= 255.
GF_TOTAL_LIMIT = 255

# --- Per-share integrity (audit H3) -----------------------------------------
# Reed-Solomon *erasure* decoding trusts every delivered share: error positions
# are the missing indices only, so a single flipped byte in a delivered chunk
# reconstructs a corrupted object with no error signalled. RS is therefore used
# here for loss only, never for corruption detection.
#
# What this module actually guarantees (and what it does not):
#
# * **Per-share integrity is mandatory by default.** :class:`Encoder` and
#   :class:`Decoder` both REQUIRE an integrity ``key``; every share carries an
#   HMAC tag over ``index || data`` bound to the stream geometry
#   (``chunk_size``, ``message_size``), verified with a constant-time compare
#   *before* the share is inserted. A duplicate index carrying different data is
#   rejected rather than overwriting the share already held.
# * The only way to get untagged shares is the explicit, loudly-named opt-out
#   ``allow_unauthenticated_shares=True``. No in-tree production caller passes
#   it: :mod:`ml_kem_braid.protocol.states` derives a per-epoch, per-stream
#   chunk key from the session key schedule, so every encoder and decoder on the
#   Braid path is keyed. The opt-out exists for tests and for demonstrating the
#   H3 exploit.
# * **The whole-message tag is optional**, because it has to reach the receiver
#   out of band (it is not part of the chunk wire format). Callers that have such
#   a channel pass ``expected_message_tag``; callers whose reassembled object
#   already carries its own authenticator do not need it. ML-KEM Braid is in the
#   latter group — the header carries a MAC, ``ek_vector`` is bound by ``hek``,
#   and ``ct1 || ct2`` carries the ciphertext MAC — so ``states.py`` keys its
#   decoders but leaves ``expected_message_tag`` unset.
# * NOT guaranteed here: freshness. A share tag binds only
#   ``(index, data, chunk_size, message_size)``; two distinct objects of equal
#   size under the same key have interchangeable shares. Callers must scope the
#   key per stream — ``states.py`` binds epoch and stream identity into the key
#   derivation for exactly this reason.
CHUNK_TAG_SIZE = 16
MESSAGE_TAG_SIZE = 32
_CHUNK_TAG_DOMAIN = b"ml-kem-braid:erasure-chunk:v1"
_MESSAGE_TAG_DOMAIN = b"ml-kem-braid:erasure-message:v1"

_UNAUTHENTICATED_OPT_OUT = (
    "erasure shares are authenticated by default: pass key=... , or pass "
    "allow_unauthenticated_shares=True to explicitly opt out (no production "
    "caller does — an unauthenticated stream gives NO corruption detection)"
)


class ChunkIntegrityError(ValueError):
    """A share failed per-share integrity verification (or conflicts)."""


class MessageIntegrityError(ValueError):
    """The reconstructed message failed whole-message integrity verification."""


def _require_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("integrity key must be bytes")
    key = bytes(key)
    if len(key) < 16:
        raise ValueError("integrity key must be at least 16 bytes")
    return key


def chunk_tag(
    key: bytes,
    index: int,
    data: bytes,
    *,
    chunk_size: int,
    message_size: int,
) -> bytes:
    """Keyed tag over ``index || data`` bound to the stream's geometry.

    Binding ``chunk_size``/``message_size`` prevents splicing a valid share
    from one object into the decode of another.
    """

    mac_input = b"".join(
        [
            _CHUNK_TAG_DOMAIN,
            struct.pack(">HII", index, chunk_size, message_size),
            struct.pack(">I", len(data)),
            data,
        ]
    )
    return hmac.new(_require_key(key), mac_input, sha256).digest()[:CHUNK_TAG_SIZE]


def message_tag(key: bytes, message: bytes, *, chunk_size: int) -> bytes:
    """Keyed tag over the whole reconstructed message."""

    mac_input = b"".join(
        [
            _MESSAGE_TAG_DOMAIN,
            struct.pack(">II", chunk_size, len(message)),
            message,
        ]
    )
    return hmac.new(_require_key(key), mac_input, sha256).digest()[:MESSAGE_TAG_SIZE]


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
    """A single erasure-code chunk.

    Wire layout (audit H3 changed this format):

    * authenticated share (the default): ``u16 index || tag[16] || data``
    * unauthenticated share: ``u16 index || data`` (``tag == b""``)

    The two forms are distinguished by the reader, not by the bytes, so
    :meth:`from_bytes` parses the authenticated layout unless the caller passes
    the explicit ``allow_unauthenticated_shares=True`` opt-out — a receiver
    always knows whether the stream it configured is keyed. Unauthenticated
    shares provide **no** corruption detection.
    """

    index: int
    data: bytes
    tag: bytes = field(default=b"")

    def __post_init__(self) -> None:
        if not isinstance(self.tag, bytes):
            raise TypeError("chunk tag must be bytes")
        if self.tag and len(self.tag) != CHUNK_TAG_SIZE:
            raise ValueError(f"chunk tag must be {CHUNK_TAG_SIZE} bytes")

    @property
    def is_tagged(self) -> bool:
        return bool(self.tag)

    def to_bytes(self) -> bytes:
        return struct.pack(">H", self.index) + self.tag + self.data

    @classmethod
    def from_bytes(
        cls, raw: bytes, *, allow_unauthenticated_shares: bool = False
    ) -> "Chunk":
        if len(raw) < 2:
            raise ValueError("chunk is too short to carry an index")
        index = struct.unpack(">H", raw[:2])[0]
        if allow_unauthenticated_shares:
            return cls(index=index, data=raw[2:])
        if len(raw) < 2 + CHUNK_TAG_SIZE:
            raise ValueError("chunk is too short to carry an integrity tag")
        return cls(
            index=index,
            data=raw[2 + CHUNK_TAG_SIZE :],
            tag=raw[2 : 2 + CHUNK_TAG_SIZE],
        )


class Encoder:
    """
    Streaming systematic RS encoder. Emits data chunks ``0..k-1`` followed by
    parity chunks ``k..k+p-1`` (then cycles). Call :meth:`next_chunk` repeatedly.
    """

    def __init__(
        self,
        message: bytes,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        *,
        key: Optional[bytes] = None,
        allow_unauthenticated_shares: bool = False,
    ):
        self.message = message
        self.chunk_size = chunk_size
        self.message_size = len(message)
        self.message_chunks = max(1, (self.message_size + chunk_size - 1) // chunk_size)
        self.parity_chunks = _parity_count(self.message_chunks)
        self.total_chunks = self.message_chunks + self.parity_chunks
        # Fail closed: an unkeyed stream has to be asked for by name.
        if key is None and not allow_unauthenticated_shares:
            raise ValueError(_UNAUTHENTICATED_OPT_OUT)
        self.key = None if key is None else _require_key(key)

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
            data = self._data_chunks[index]
        else:
            parity = self._compute_parity()
            data = parity[index - self.message_chunks]
        return Chunk(index=index, data=data, tag=self._tag_for(index, data))

    def _tag_for(self, index: int, data: bytes) -> bytes:
        if self.key is None:
            return b""
        return chunk_tag(
            self.key,
            index,
            data,
            chunk_size=self.chunk_size,
            message_size=self.message_size,
        )

    def message_tag(self) -> bytes:
        """Keyed tag over the whole message (keyed encoders only)."""

        if self.key is None:
            raise ValueError("message_tag requires a keyed encoder")
        return message_tag(self.key, self.message, chunk_size=self.chunk_size)

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

    def __init__(
        self,
        message_size: int,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        *,
        key: Optional[bytes] = None,
        expected_message_tag: Optional[bytes] = None,
        allow_unauthenticated_shares: bool = False,
    ):
        self.message_size = message_size
        self.chunk_size = chunk_size
        self.message_chunks = max(1, (message_size + chunk_size - 1) // chunk_size)
        self.parity_chunks = _parity_count(self.message_chunks)
        self.total_chunks = self.message_chunks + self.parity_chunks
        # Fail closed: an unkeyed decoder accepts corrupted shares silently, so
        # it has to be asked for by name.
        if key is None and not allow_unauthenticated_shares:
            raise ValueError(_UNAUTHENTICATED_OPT_OUT)
        self.key = None if key is None else _require_key(key)
        if expected_message_tag is not None:
            if self.key is None:
                raise ValueError("expected_message_tag requires a keyed decoder")
            if not isinstance(expected_message_tag, bytes):
                raise TypeError("expected_message_tag must be bytes")
        self.expected_message_tag = expected_message_tag
        self._chunks: Dict[int, bytes] = {}

    @classmethod
    def new(
        cls,
        message_size: int,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        *,
        key: Optional[bytes] = None,
        expected_message_tag: Optional[bytes] = None,
        allow_unauthenticated_shares: bool = False,
    ) -> "Decoder":
        return cls(
            message_size,
            chunk_size,
            key=key,
            expected_message_tag=expected_message_tag,
            allow_unauthenticated_shares=allow_unauthenticated_shares,
        )

    def add_chunk(self, chunk: Chunk) -> bool:
        """Verify and insert a share. Returns ``True`` if it was stored.

        Audit H3: integrity is checked *before* insertion, and a duplicate
        index carrying different data is rejected rather than silently
        overwriting the share already held.
        """

        if not (0 <= chunk.index < self.total_chunks):
            return False
        if len(chunk.data) != self.chunk_size:
            return False

        if self.key is None:
            if chunk.is_tagged:
                raise ChunkIntegrityError(
                    "tagged chunk supplied to an unkeyed decoder"
                )
        else:
            if not chunk.is_tagged:
                raise ChunkIntegrityError("untagged chunk supplied to a keyed decoder")
            expected = chunk_tag(
                self.key,
                chunk.index,
                chunk.data,
                chunk_size=self.chunk_size,
                message_size=self.message_size,
            )
            if not hmac.compare_digest(expected, chunk.tag):
                raise ChunkIntegrityError("chunk integrity tag verification failed")

        existing = self._chunks.get(chunk.index)
        if existing is not None:
            if not hmac.compare_digest(existing, chunk.data):
                raise ChunkIntegrityError(
                    "conflicting data for an already-received chunk index"
                )
            return False

        self._chunks[chunk.index] = chunk.data
        return True

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
        reconstructed = self._reconstruct()
        if reconstructed is None:
            return None
        if self.expected_message_tag is not None:
            assert self.key is not None  # guaranteed by __init__
            computed = message_tag(
                self.key, reconstructed, chunk_size=self.chunk_size
            )
            if not hmac.compare_digest(computed, self.expected_message_tag):
                raise MessageIntegrityError(
                    "reconstructed message failed integrity verification"
                )
        return reconstructed

    def _reconstruct(self) -> Optional[bytes]:
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


def encode_message(
    message: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    *,
    key: Optional[bytes] = None,
    allow_unauthenticated_shares: bool = False,
) -> Encoder:
    return Encoder(
        message,
        chunk_size,
        key=key,
        allow_unauthenticated_shares=allow_unauthenticated_shares,
    )


def decode_message(
    message_size: int,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    *,
    key: Optional[bytes] = None,
    expected_message_tag: Optional[bytes] = None,
    allow_unauthenticated_shares: bool = False,
) -> Decoder:
    return Decoder.new(
        message_size,
        chunk_size,
        key=key,
        expected_message_tag=expected_message_tag,
        allow_unauthenticated_shares=allow_unauthenticated_shares,
    )


if __name__ == "__main__":
    import os
    import random

    rng = random.Random(1234)
    self_test_key = os.urandom(32)
    for size in (96, 160, 960, 1152, 1408):
        msg = os.urandom(size)
        enc = Encoder(msg, key=self_test_key)
        # Drop up to `parity_chunks` random chunks, keep the rest, shuffle order.
        all_chunks = [enc.chunk_at(i) for i in range(enc.total_chunks)]
        keep = list(all_chunks)
        for _ in range(min(enc.parity_chunks, enc.total_chunks - enc.message_chunks)):
            keep.pop(rng.randrange(len(keep)))
        rng.shuffle(keep)
        dec = Decoder.new(size, key=self_test_key)
        for c in keep:
            dec.add_chunk(c)
        out = dec.message()
        assert out == msg, f"recovery failed for size {size}"
        print(f"size {size:5d}: k={enc.message_chunks} p={enc.parity_chunks} "
              f"recovered from {len(keep)}/{enc.total_chunks} chunks (with loss) OK")
    print("Erasure coding self-tests passed.")
