"""Loads the vendored curve25519 C extension."""
from __future__ import annotations

_mod = None

def load():
    """Return the compiled `_curve25519` module, or raise an actionable error."""
    global _mod
    if _mod is None:
        try:
            from ml_kem_braid.crypto import _curve25519 as m
        except ImportError as exc:  # pragma: no cover - build-time condition
            raise ImportError(
                "curve25519 C extension not built. Run:\n"
                "  uv run python build_curve25519.py build_ext --inplace"
            ) from exc
        _mod = m
    return _mod
