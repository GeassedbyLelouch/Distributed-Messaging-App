"""Builds the vendored curve25519 C extension in place.

Run: uv run python build_curve25519.py build_ext --inplace
Requires a C compiler. Output: ml_kem_braid/crypto/_curve25519*.so
"""
from glob import glob
from setuptools import setup, Extension

ROOT = "ml_kem_braid/crypto/_curve25519"
sources = [f"{ROOT}/_curve25519module.c", f"{ROOT}/curve/curve25519-donna.c"]
sources += glob(f"{ROOT}/curve/ed25519/*.c")
sources += glob(f"{ROOT}/curve/ed25519/additions/*.c")
sources += glob(f"{ROOT}/curve/ed25519/additions/generalized/*.c")   # VRF sources
sources += glob(f"{ROOT}/curve/ed25519/nacl_sha512/*.c")

ext = Extension(
    "ml_kem_braid.crypto._curve25519",
    sources=sorted(sources),
    include_dirs=[
        f"{ROOT}/curve/ed25519/nacl_includes",
        f"{ROOT}/curve/ed25519/additions",
        f"{ROOT}/curve/ed25519/additions/generalized",
        f"{ROOT}/curve/ed25519",
    ],
)
setup(name="ml-kem-braid-curve25519", ext_modules=[ext], py_modules=[])
