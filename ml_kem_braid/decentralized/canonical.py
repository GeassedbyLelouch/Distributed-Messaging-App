from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Mapping


def _validate_canonical(value: Any) -> None:
    """Reject every value whose JSON encoding is not injective/deterministic.

    Audit M8: ``json.dumps`` serialises floats through the runtime's
    ``repr(float)`` and silently coerces non-string mapping keys to strings.
    Both make the canonical form of a *signed* record depend on the encoder
    rather than only on the record, so two honest verifiers can compute
    different signing bytes for the same object. The canonical codec therefore
    accepts only ``None``/``bool``/``int``/``str``/list/dict and requires
    string keys.
    """

    if value is None or isinstance(value, (bool, str)):
        return
    if isinstance(value, float):
        # Non-finite first so the historical ValueError contract is preserved.
        if not math.isfinite(value):
            raise ValueError("canonical encoding rejects non-finite floats")
        raise TypeError(
            "canonical encoding rejects floats; use integer epoch milliseconds"
        )
    if isinstance(value, int):
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("canonical encoding requires string object keys")
            _validate_canonical(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_canonical(item)
        return
    raise TypeError(f"canonical encoding rejects value of type {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Deterministic, injective JSON encoding of ``value``.

    Floats and non-string object keys are rejected outright (see
    :func:`_validate_canonical`); everything else is emitted with sorted keys,
    no insignificant whitespace and ASCII escaping.
    """

    _validate_canonical(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
