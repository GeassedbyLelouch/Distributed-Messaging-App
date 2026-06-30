from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
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
