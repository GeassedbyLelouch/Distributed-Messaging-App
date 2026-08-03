#!/usr/bin/env python3
"""
THE INDEPENDENT ORACLE for `tests/key_schedule_kat.rs`.

Why this file exists
--------------------
Every other test of the ML-KEM-Braid key schedule is *differential*: it asserts
that different inputs give different outputs. A differential test proves the
derivation is injective. It cannot detect that the whole schedule is shifted --
a wrong label, a swapped leg order, a missing `F` prefix, an HKDF-Expand where
the spec says extract-then-expand. Two independent implementations that must
agree on the wire need ABSOLUTE bytes, and absolute bytes pinned from our own
Rust output would be circular and worth nothing.

So this script re-derives every expected value **from the specification text**,
using only the Python standard library:

    hashlib, hmac                       -- SHA-256, SHAKE-256, HMAC
    a from-scratch RFC 7748 X25519      -- validated below against RFC 7748 5.2
    a from-scratch RFC 8439 ChaCha20    -- validated below against RFC 8439 2.8.2
      + Poly1305 + HChaCha20 (XChaCha)     and draft-irtf-cfrg-xchacha 2.2.1

Nothing here imports the Rust crate, reads its output, or links any third-party
cryptography. The HKDF, the HMAC chain step, the ML-KEM implicit-rejection
branch and the AEAD are each transcribed from the RFC / FIPS text and then
pinned against that document's own published test vectors, so a bug in this
file shows up as a failing self-test rather than as a "matching" KAT.

Where a v2 derivation has an equivalent in `ml_kem_braid/` -- the v1 Python
reference this project is a rewrite of -- `_selftest_python_reference` also
checks the two against each other. That corroborates the *shape* of the
schedule (leg order, the `F` prefix, the salt, the `info` layout, the 32||32
split and its order) by a route that does not pass through the spec text, and
so is independent of a misreading of the spec on this file's part. Only the
labels changed between v1 and v2, so the cross-check supplies the v1 label to
both sides; the v2 label bytes are pinned against the spec documents instead.

Specification sources (paths relative to the repository root)
------------------------------------------------------------
  docs/specs/2026-07-31-rust-rewrite-spec.md          -- "parent"
  docs/specs/2026-08-01-m1-normative-resolutions.md   -- "M1" (amends parent)

  parent 4.1  SK = HKDF-SHA256(ikm  = F || DH1 || DH2 || DH3 [|| DH4] || KEM_SS,
                               salt = 0x00 * 32,
                               info = "MLKEMBraid/pqxdh/v2" || IdA || IdB,
                               len  = 32)          F = 0xFF * 32
  parent 4.2  k_cf    = HKDF-Expand(SK, "MLKEMBraid/pqxdh/confirm/v2", 32)
              confirm = HMAC-SHA256(k_cf, preimage)
  parent 4.4  K_frame_i2r = HKDF-Expand(SK, "MLKEMBraid/frame/i2r/v2", 32)
              K_frame_r2i = HKDF-Expand(SK, "MLKEMBraid/frame/r2i/v2", 32)
              session_id  = HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)
  parent 3.6  signed_msg = "MLKEMBraid/xeddsa/v2\\x00" || u16(len(ctx)) || ctx
                        || IdentityId || payload
  M1 D.2      (RK', CK) = HKDF-SHA256(ikm  = dh_out || kem_ss,
                                      salt = RK,
                                      info = "MLKEMBraid/ratchet/root/v2",
                                      len  = 64)   split 32 || 32
              MK  = HMAC-SHA256(CK, 0x01)
              CK' = HMAC-SHA256(CK, 0x02)
  M1 E.2      ctx registry, literal ASCII, no terminator and no length prefix
  M1 G.5      K_store = HKDF-Expand(prk, "MLKEMBraid/store/v2", 32)

"HKDF-Expand(SK, info, 32)" in parent 4.4 is expand-from-PRK (RFC 5869 3.3):
`SK` is already uniform, so it is used directly as the PRK with no second
extract. That reading is forced by parent 4.1 already having done the one
extract, and it is what makes `k_cf` a sibling of `session_id` rather than a
re-extraction.

Reading a secret out of the Rust
--------------------------------
Two of the derived keys have no public byte accessor, so the KAT pins them
through the one public function that consumes them:

  * `FrameKey`   -> pinned by HMAC-SHA256(K_frame_dir, fixed preimage).
  * `MessageKey` -> pinned by XChaCha20-Poly1305 opening a ciphertext this
                    script produced. A wrong message key cannot authenticate
                    it, so a successful open pins all 32 bytes.

The `MessageKey` route is why this script carries an AEAD. `tests/` sees only
the public API; that constraint is a feature, since it means the KAT exercises
exactly the surface another implementation would.

Usage
-----
    uv run python rust/crates/mlkb-crypto/tests/vectors/generate.py

Writes `key_schedule_vectors.rs` next to this file (included by the KAT) and
runs every self-test first. Regenerating must be a no-op; if the file changes,
either a spec value changed or this oracle did.
"""

from __future__ import annotations

import hashlib
import hmac
import pathlib
import struct
import sys

# ---------------------------------------------------------------------------
# RFC 5869 HKDF-SHA256, transcribed from the RFC
# ---------------------------------------------------------------------------


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 2.2: PRK = HMAC-Hash(salt, IKM)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 2.3: T(i) = HMAC(PRK, T(i-1) || info || i)."""
    if length > 255 * 32:
        raise ValueError("RFC 5869 2.3 bounds OKM at 255*HashLen")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def _selftest_hkdf() -> None:
    # RFC 5869 A.1 (test case 1, SHA-256).
    ikm = bytes([0x0B] * 22)
    salt = bytes(range(0x00, 0x0D))
    info = bytes(range(0xF0, 0xFA))
    prk = hkdf_extract(salt, ikm)
    assert prk.hex() == (
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    ), prk.hex()
    okm = hkdf_expand(prk, info, 42)
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ), okm.hex()
    # RFC 5869 A.3 (zero-length salt and info). RFC 5869 2.2 says an absent
    # salt is HashLen zero bytes, which is why the empty and the 32-zero forms
    # agree; spec parent 4.1 spells the 32-zero form.
    prk3 = hkdf_extract(b"", ikm)
    assert prk3.hex() == (
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    ), prk3.hex()
    assert hkdf_extract(bytes(32), ikm) == prk3
    okm3 = hkdf_expand(prk3, b"", 42)
    assert okm3.hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    ), okm3.hex()
    # RFC 4231 test case 1, since the chain step is a bare HMAC.
    tag = hmac.new(bytes([0x0B] * 20), b"Hi There", hashlib.sha256).digest()
    assert tag.hex() == (
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    ), tag.hex()


# ---------------------------------------------------------------------------
# RFC 7748 X25519, transcribed from the RFC
# ---------------------------------------------------------------------------

_P = 2**255 - 19
_A24 = 121665


def _decode_scalar(k: bytes) -> int:
    """RFC 7748 5: decodeScalar25519 (the clamp)."""
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return int.from_bytes(b, "little")


def _decode_u(u: bytes) -> int:
    """RFC 7748 5: decodeUCoordinate masks the MSB for curve25519."""
    b = bytearray(u)
    b[31] &= 127
    return int.from_bytes(b, "little") % _P


def x25519(k: bytes, u: bytes) -> bytes:
    """RFC 7748 5: the Montgomery ladder, constant-time-shaped (not that it
    matters here -- this is an offline oracle, not production code)."""
    kk = _decode_scalar(k)
    x1 = _decode_u(u)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        k_t = (kk >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t

        a = (x2 + z2) % _P
        aa = (a * a) % _P
        b = (x2 - z2) % _P
        bb = (b * b) % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = (d * a) % _P
        cb = (c * b) % _P
        x3 = pow((da + cb) % _P, 2, _P)
        z3 = (x1 * pow((da - cb) % _P, 2, _P)) % _P
        x2 = (aa * bb) % _P
        z2 = (e * ((aa + _A24 * e) % _P)) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


_BASE_U = (9).to_bytes(32, "little")


def x25519_base(k: bytes) -> bytes:
    return x25519(k, _BASE_U)


def _selftest_x25519() -> None:
    # RFC 7748 5.2, first vector.
    k = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
    )
    u = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
    )
    assert (
        x25519(k, u).hex()
        == "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
    )
    # RFC 7748 6.1, Alice's and Bob's public keys and the shared secret.
    a = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    b = bytes.fromhex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    ka = x25519_base(a)
    kb = x25519_base(b)
    assert (
        ka.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    assert (
        kb.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    )
    ss = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert x25519(a, kb).hex() == ss
    assert x25519(b, ka).hex() == ss


# ---------------------------------------------------------------------------
# RFC 8439 ChaCha20-Poly1305 + HChaCha20 (XChaCha20-Poly1305), from the RFCs
# ---------------------------------------------------------------------------


def _rotl32(v: int, n: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _qr(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


_SIGMA = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]


def _chacha_rounds(state: list[int]) -> list[int]:
    s = list(state)
    for _ in range(10):
        _qr(s, 0, 4, 8, 12)
        _qr(s, 1, 5, 9, 13)
        _qr(s, 2, 6, 10, 14)
        _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15)
        _qr(s, 1, 6, 11, 12)
        _qr(s, 2, 7, 8, 13)
        _qr(s, 3, 4, 9, 14)
    return s


def chacha20_block(key: bytes, counter: int, nonce12: bytes) -> bytes:
    """RFC 8439 2.3."""
    state = (
        _SIGMA
        + list(struct.unpack("<8I", key))
        + [counter]
        + list(struct.unpack("<3I", nonce12))
    )
    worked = _chacha_rounds(state)
    out = [(worked[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20(key: bytes, counter: int, nonce12: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce12)
        chunk = data[i : i + 64]
        out += bytes(x ^ y for x, y in zip(chunk, block))
    return bytes(out)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """draft-irtf-cfrg-xchacha 2.2: the subkey derivation."""
    state = (
        _SIGMA + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    )
    worked = _chacha_rounds(state)
    return struct.pack("<8I", *(worked[0:4] + worked[12:16]))


def poly1305(key: bytes, msg: bytes) -> bytes:
    """RFC 8439 2.5."""
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        chunk = msg[i : i + 16]
        n = int.from_bytes(chunk + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * ((16 - len(b) % 16) % 16)


def chacha20poly1305_seal(
    key: bytes, nonce12: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """RFC 8439 2.8: ciphertext || 16-byte tag."""
    otk = chacha20_block(key, 0, nonce12)[:32]
    ct = chacha20(key, 1, nonce12, plaintext)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct)
    mac_data += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    return ct + poly1305(otk, mac_data)


def xchacha20poly1305_seal(
    key: bytes, nonce24: bytes, plaintext: bytes, aad: bytes
) -> bytes:
    """draft-irtf-cfrg-xchacha 3.1."""
    subkey = hchacha20(key, nonce24[:16])
    nonce12 = b"\x00\x00\x00\x00" + nonce24[16:]
    return chacha20poly1305_seal(subkey, nonce12, plaintext, aad)


def _selftest_aead() -> None:
    # RFC 8439 2.3.2, the ChaCha20 block function.
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    assert chacha20_block(key, 1, nonce).hex().startswith("10f1e7e4d13b5915500fdd1f")

    # RFC 8439 2.8.2, the AEAD construction.
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    k = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    n = bytes.fromhex("070000004041424344454647")
    out = chacha20poly1305_seal(k, n, pt, aad)
    assert out[:114].hex().startswith("d31a8d34648e60db7b86afbc53ef7ec2"), out[:16].hex()
    assert out[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", out[-16:].hex()

    # draft-irtf-cfrg-xchacha 2.2.1, HChaCha20.
    hk = bytes.fromhex(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    hn = bytes.fromhex("000000090000004a0000000031415927")
    assert (
        hchacha20(hk, hn).hex()
        == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    )

    # draft-irtf-cfrg-xchacha A.3.1, the full XChaCha20-Poly1305 AEAD vector.
    # This is the one that pins the 24-byte-nonce composition itself:
    # subkey = HChaCha20(key, nonce[0..16]), nonce12 = 0x00000000 || nonce[16..24].
    xpt = pt
    xaad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    xk = bytes.fromhex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
    )
    xn = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    xout = xchacha20poly1305_seal(xk, xn, xpt, xaad)
    assert xout.hex().startswith("bd6d179d3e83d43b9576579493c0e939"), xout[:16].hex()
    assert xout[-16:].hex() == "c0875924c1c7987947deafd8780acf49", xout[-16:].hex()


# ---------------------------------------------------------------------------
# FIPS 203 ML-KEM-1024: the implicit-rejection branch of Decaps
# ---------------------------------------------------------------------------
#
# The KAT needs a `KemSharedSecret` whose 32 bytes are known independently of
# the Rust. FIPS 203 Algorithm 18 (ML-KEM.Decaps_internal) ends:
#
#     K_bar <- J(z || c)                              (J = SHAKE256(., 32))
#     c' <- K-PKE.Encrypt(ek_pke, m', r')
#     if c != c' then K <- K_bar                      (implicit rejection)
#
# For a ciphertext drawn pseudo-randomly, c != c' with overwhelming probability,
# so decapsulating it yields exactly SHAKE256(z || c, 32) -- computable here
# with hashlib alone and with no ML-KEM implementation at all. `z` is the second
# half of the 64-byte (d, z) seed FIPS 203 serialises a decapsulation key as,
# which is the form `KemDecapsulationKey::from_seed` takes (spec M1 I).
#
# This is a stronger oracle than re-implementing ML-KEM would be: it depends on
# one line of the standard rather than on a second full implementation.


def ml_kem_implicit_reject(seed64: bytes, ciphertext: bytes) -> bytes:
    """FIPS 203 Alg. 18 line 8 / Alg. 17 line 3: K_bar = J(z || c)."""
    z = seed64[32:64]
    return hashlib.shake_256(z + ciphertext).digest(32)


def _selftest_ml_kem(seed64: bytes, ciphertexts: list[bytes]) -> None:
    """Optional second opinion from `kyber-py`, an unrelated pure-Python
    FIPS 203 implementation (a dependency of the project's Python reference,
    and in no way derived from the Rust `ml-kem` crate).

    It confirms two things the one-line oracle above cannot confirm alone:
    that the pseudo-random ciphertexts really do take the implicit-rejection
    branch, and that `z` really is the second half of the (d, z) seed. Skipped
    rather than failed if the package is absent, since the KAT's correctness
    does not depend on it."""
    try:
        from kyber_py.ml_kem import ML_KEM_1024  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover - environment-dependent
        print("note: kyber-py absent, skipping the ML-KEM cross-check", file=sys.stderr)
        return
    _ek, dk = ML_KEM_1024._keygen_internal(seed64[:32], seed64[32:])
    for ct in ciphertexts:
        theirs = ML_KEM_1024._decaps_internal(dk, ct)
        mine = ml_kem_implicit_reject(seed64, ct)
        assert theirs == mine, (
            "kyber-py disagrees with the FIPS 203 implicit-rejection oracle; "
            "the chosen ciphertext may not be taking that branch"
        )


# ---------------------------------------------------------------------------
# Cross-check against the v1 Python reference implementation
# ---------------------------------------------------------------------------
#
# A second, independent corroboration of the *construction* (as opposed to the
# labels). `ml_kem_braid/` is the v1 reference this project is a rewrite of. It
# was written before these specs and shares no code with either the Rust or the
# rest of this file, so where a v2 derivation has a v1 equivalent, the two
# agreeing pins the shape of the derivation -- the leg order, the `F` prefix,
# the salt, the `info` layout, the 32||32 split and its ORDER -- by a route that
# does not pass through the spec text at all.
#
# The labels legitimately differ: v2 renamed every domain separator (v1's
# `MLKEMBraid_PQXDH_CURVE25519_SHA-256_ML-KEM-1024` became parent 4.1's
# `MLKEMBraid/pqxdh/v2`, v1's `MLKEMBraid-DR-root` became M1 D.2's
# `MLKEMBraid/ratchet/root/v2`). So each check below feeds the v1 code the v1
# label and this file's code the same v1 label: what is being compared is the
# arithmetic, not the naming. The v2 label bytes are pinned separately, against
# the spec documents, by `key_schedule_kat.rs`.
#
# v2 also changes the root step's `ikm` from v1's opaque `epoch_key` to
# `dh_out || kem_ss` (M1 D.2's hybrid step). That is a deliberate v2 change and
# is why the check below passes v1 the concatenation as its `epoch_key`.


def _selftest_python_reference() -> None:
    """Optional second opinion from `ml_kem_braid/`, the v1 Python reference.

    Skipped rather than failed if the package is not importable, since the
    KAT's correctness rests on the spec text and this is corroboration."""
    try:
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[5]))
        from ml_kem_braid.core.double_ratchet import _kdf_ck, _kdf_rk  # type: ignore
        from ml_kem_braid.core.kdf import hkdf as ref_hkdf  # type: ignore
        from ml_kem_braid.pqxdh.pqxdh import (  # type: ignore
            _F_PREFIX as REF_F,
            _HKDF_SALT as REF_SALT,
            PQXDH_INFO as REF_INFO,
            _derive_sk as ref_derive_sk,
        )
    except ImportError:  # pragma: no cover - environment-dependent
        print("note: ml_kem_braid absent, skipping the v1 cross-check", file=sys.stderr)
        return

    # The two constants parent 4.1 inherits from v1 unchanged.
    assert REF_F == F_PREFIX, "v1 disagrees on the F prefix"
    assert REF_SALT == ZERO_SALT, "v1 disagrees on the 32-zero-byte salt"

    # HKDF itself: same extract-then-expand on a project-shaped input.
    assert ref_hkdf(ikm=b"ikm", salt=b"salt", info=b"info", length=64) == hkdf(
        salt=b"salt", ikm=b"ikm", info=b"info", length=64
    ), "v1 disagrees on RFC 5869 HKDF-SHA256"

    # parent 4.1: `ikm = F || DH.. || SS`, `info = <label> || IdA || IdB`,
    # `salt = 0x00*32`, for BOTH arities. Fed the v1 label on both sides, since
    # only the label changed in v2.
    #
    # Note this drives `derive_sk` itself, not a copy of it: a cross-check that
    # reimplements the thing it is checking checks nothing.
    legs4 = [bytes([i]) * 32 for i in (0xA1, 0xA2, 0xA3, 0xA4)]
    ss = bytes([0xB0]) * 32
    for n in (3, 4):
        assert derive_sk(
            legs4[:n], ss, ID_A, ID_B, info_prefix=REF_INFO
        ) == ref_derive_sk(legs4[:n], ss, ID_A, ID_B), (
            f"v1 disagrees on the {n}-leg SK construction"
        )

    # M1 D.2 chain step: byte-identical to v1's `_kdf_ck`, no label involved,
    # so this is an unqualified agreement.
    ck = bytes([0xC0]) * 32
    assert chain_step(ck) == _kdf_ck(ck), "v1 disagrees on MK/CK' = HMAC(CK, 01/02)"

    # M1 D.2 root step: salt = RK, 64 bytes, split (new_root, chain) in THAT
    # order -- the 32-byte offset a differential test cannot see. Compared
    # under v1's label and with v1's single `epoch_key` set to `dh || kem_ss`.
    # v1 returns `(new_root_key, chain_seed)`, which is M1 D.2's `(RK', CK)`;
    # `ratchet_root` is driven directly so a reversed split is caught here.
    rk, dh, kem = bytes([0xD0]) * 32, bytes([0xD1]) * 32, bytes([0xD2]) * 32
    assert ratchet_root(rk, dh, kem, info=b"MLKEMBraid-DR-root") == _kdf_rk(
        rk, dh + kem
    ), "v1 disagrees on the root-step construction or on the 32||32 split order"


# ---------------------------------------------------------------------------
# The specification's labels, retyped by hand from the spec documents
# ---------------------------------------------------------------------------
# Retyped, not imported: if the Rust and this file agreed because both read the
# same source there would be no independent check left.

SK_INFO_PREFIX = b"MLKEMBraid/pqxdh/v2"  # parent 4.1, 4.4
FRAME_I2R = b"MLKEMBraid/frame/i2r/v2"  # parent 4.4
FRAME_R2I = b"MLKEMBraid/frame/r2i/v2"  # parent 4.4
PQXDH_CONFIRM = b"MLKEMBraid/pqxdh/confirm/v2"  # parent 4.2, 4.4
SESSION_ID = b"MLKEMBraid/sid/v2"  # parent 4.4, 6.3
ERASURE_CHUNK = b"MLKEMBraid/erasure-chunk/v2"  # parent 4.4
RATCHET_ROOT = b"MLKEMBraid/ratchet/root/v2"  # M1 D.2
K_STORE = b"MLKEMBraid/store/v2"  # M1 G.5 (spelling fixed by the crate)
XEDDSA_DOMAIN = b"MLKEMBraid/xeddsa/v2\x00"  # parent 3.6, M1 E.2
CTX_SPK = b"MLKEMBraid/ctx/spk/v2"  # M1 E.2
CTX_PQSPK = b"MLKEMBraid/ctx/pqspk/v2"  # M1 E.2
CTX_ENROLMENT = b"MLKEMBraid/ctx/enrolment/v2"  # M1 E.2

F_PREFIX = b"\xff" * 32  # parent 4.1
ZERO_SALT = b"\x00" * 32  # parent 4.1
CHAIN_MK = b"\x01"  # M1 D.2
CHAIN_CK = b"\x02"  # M1 D.2

# ---------------------------------------------------------------------------
# Fixed inputs. Every one of these is also spelled in the Rust KAT.
# ---------------------------------------------------------------------------

# IdentityIds (parent 3.5); this crate treats them as opaque 32-byte strings.
ID_A = bytes(range(0, 32))
ID_B = bytes(range(32, 64))

# X25519 private keys. `X25519SecretKey::from_bytes` stores them unclamped and
# clamps at use, exactly as RFC 7748 decodeScalar25519 does here.
SK_LEGS = [bytes([i]) * 32 for i in (1, 2, 3, 4)]  # our side of DH1..DH4
PEER_LEGS = [bytes([0x10 + i]) * 32 for i in (1, 2, 3, 4)]  # peer side
SK_RATCHET = bytes([5]) * 32
PEER_RATCHET = bytes([0x15]) * 32

# ML-KEM-1024 decapsulation key seed (d || z), FIPS 203 / spec M1 I.
KEM_SEED = bytes(range(64))

# Pseudo-random ML-KEM ciphertexts, so decapsulation takes the implicit
# rejection branch. Generated by SHAKE-256 so the Rust constant is reproducible
# from this line alone.
KEM_CT_PQXDH = hashlib.shake_256(b"MLKEMBraid/kat/kem-ct/pqxdh").digest(1568)
KEM_CT_RATCHET = hashlib.shake_256(b"MLKEMBraid/kat/kem-ct/ratchet").digest(1568)

FRAME_PREIMAGE = b"MLKEMBraid/frame/v2|KAT|frame preimage"
CONFIRM_PREIMAGE = b"canonical(InitialMessageV2 without confirm)|KAT"

# The AEAD inputs used to read a `MessageKey` and a `StoreKey` back out.
# `aad` is the canonical CBOR encoding of the unsigned integer 0, which
# RFC 8949 encodes as the single byte 0x00; the Rust KAT asserts that the
# encoding it feeds the AEAD is exactly this byte.
AEAD_AAD = b"\x00"
AEAD_NONCE = bytes(range(24))
MK1_PLAINTEXT = b"KAT: the first message key of the first chain"
MK2_PLAINTEXT = b"KAT: the second message key of the first chain"
STORE_PLAINTEXT = b"KAT: a sealed value at rest"
STORE_MASTER_PRK = bytes([0x5A]) * 32

# `signed_message` payloads (parent 3.6).
SIGNED_PAYLOAD = b"KAT payload"


# ---------------------------------------------------------------------------
# The derivations
# ---------------------------------------------------------------------------


def derive_sk(
    dh_legs: list[bytes],
    kem_ss: bytes,
    id_a: bytes,
    id_b: bytes,
    info_prefix: bytes = SK_INFO_PREFIX,
) -> bytes:
    """parent 4.1. DH4 is omitted from `ikm` entirely when absent -- never
    zero-filled -- which is what makes the two shapes unambiguous with no
    length prefix.

    `info_prefix` is a parameter for one reason only: so the v1 cross-check can
    drive THIS function under v1's label rather than reimplementing it. Every
    vector is produced with the default, parent 4.1's label."""
    ikm = F_PREFIX + b"".join(dh_legs) + kem_ss
    info = info_prefix + id_a + id_b
    return hkdf(salt=ZERO_SALT, ikm=ikm, info=info, length=32)


def ratchet_root(
    rk: bytes, dh_out: bytes, kem_ss: bytes, info: bytes = RATCHET_ROOT
) -> tuple[bytes, bytes]:
    """M1 D.2: salt = RK, ikm = dh_out || kem_ss, 64 bytes split 32 || 32.

    `info` is a parameter for the same reason as `derive_sk`'s `info_prefix`."""
    okm = hkdf(salt=rk, ikm=dh_out + kem_ss, info=info, length=64)
    return okm[:32], okm[32:]


def chain_step(ck: bytes) -> tuple[bytes, bytes]:
    """M1 D.2: MK = HMAC(CK, 0x01), CK' = HMAC(CK, 0x02)."""
    mk = hmac.new(ck, CHAIN_MK, hashlib.sha256).digest()
    ck2 = hmac.new(ck, CHAIN_CK, hashlib.sha256).digest()
    return ck2, mk


def signed_message(ctx: bytes, identity: bytes, payload: bytes) -> bytes:
    """parent 3.6 / M1 E.2."""
    return (
        XEDDSA_DOMAIN + struct.pack(">H", len(ctx)) + ctx + identity + payload
    )


def compute() -> dict[str, str]:
    v: dict[str, str] = {}

    # --- X25519 legs -----------------------------------------------------
    peer_pubs = [x25519_base(p) for p in PEER_LEGS]
    dh_legs = [x25519(SK_LEGS[i], peer_pubs[i]) for i in range(4)]
    for i, pub in enumerate(peer_pubs, start=1):
        v[f"PEER_PUB_{i}"] = pub.hex()
    peer_pub_ratchet = x25519_base(PEER_RATCHET)
    dh_ratchet = x25519(SK_RATCHET, peer_pub_ratchet)
    v["PEER_PUB_RATCHET"] = peer_pub_ratchet.hex()

    # --- ML-KEM legs (implicit rejection) --------------------------------
    kem_ss_pqxdh = ml_kem_implicit_reject(KEM_SEED, KEM_CT_PQXDH)
    kem_ss_ratchet = ml_kem_implicit_reject(KEM_SEED, KEM_CT_RATCHET)
    v["KEM_CT_PQXDH"] = KEM_CT_PQXDH.hex()
    v["KEM_CT_RATCHET"] = KEM_CT_RATCHET.hex()

    # --- parent 4.1: SK, three legs and four ------------------------------
    #
    # `RootKey` deliberately has no byte accessor -- `SK` never leaves the type
    # (keys.rs). So the root keys themselves are emitted for the record and for
    # a second implementation to check against, while the KAT pins them
    # transitively through the parent 4.4 derivations, which ARE observable.
    sk3 = derive_sk(dh_legs[:3], kem_ss_pqxdh, ID_A, ID_B)
    sk4 = derive_sk(dh_legs[:4], kem_ss_pqxdh, ID_A, ID_B)
    assert sk3 != sk4
    v["SK_THREE_LEG"] = sk3.hex()
    v["SK_FOUR_LEG"] = sk4.hex()

    def observable(prefix: str, sk: bytes) -> None:
        """The parent 4.4 / 4.2 derivations, which have public accessors."""
        v[f"{prefix}_SESSION_ID"] = hkdf_expand(sk, SESSION_ID, 32).hex()
        k_cf = hkdf_expand(sk, PQXDH_CONFIRM, 32)
        v[f"{prefix}_CONFIRM_TAG"] = (
            hmac.new(k_cf, CONFIRM_PREIMAGE, hashlib.sha256).digest().hex()
        )
        k_i2r = hkdf_expand(sk, FRAME_I2R, 32)
        k_r2i = hkdf_expand(sk, FRAME_R2I, 32)
        v[f"{prefix}_FRAME_MAC_I2R"] = (
            hmac.new(k_i2r, FRAME_PREIMAGE, hashlib.sha256).digest().hex()
        )
        v[f"{prefix}_FRAME_MAC_R2I"] = (
            hmac.new(k_r2i, FRAME_PREIMAGE, hashlib.sha256).digest().hex()
        )

    observable("THREE_LEG", sk3)
    observable("FOUR_LEG", sk4)

    # --- M1 D.2: the hybrid root step, from the 4-leg SK ------------------
    rk1, ck0 = ratchet_root(sk4, dh_ratchet, kem_ss_ratchet)
    v["RATCHET_RK1"] = rk1.hex()
    v["RATCHET_CK0"] = ck0.hex()
    # `RK'` is a `RootKey` too, so it is pinned the same way.
    observable("RATCHET_RK1", rk1)

    # --- M1 D.2: the chain step, pinned through the AEAD ------------------
    ck1, mk1 = chain_step(ck0)
    ck2, mk2 = chain_step(ck1)
    v["CHAIN_CK1"] = ck1.hex()
    v["CHAIN_MK1"] = mk1.hex()
    v["CHAIN_CK2"] = ck2.hex()
    v["CHAIN_MK2"] = mk2.hex()
    v["MK1_CIPHERTEXT"] = xchacha20poly1305_seal(
        mk1, AEAD_NONCE, MK1_PLAINTEXT, AEAD_AAD
    ).hex()
    v["MK2_CIPHERTEXT"] = xchacha20poly1305_seal(
        mk2, AEAD_NONCE, MK2_PLAINTEXT, AEAD_AAD
    ).hex()

    # --- M1 G.5: K_store, which anchors the AEAD independently ------------
    k_store = hkdf_expand(STORE_MASTER_PRK, K_STORE, 32)
    v["K_STORE"] = k_store.hex()
    v["STORE_CIPHERTEXT"] = xchacha20poly1305_seal(
        k_store, AEAD_NONCE, STORE_PLAINTEXT, AEAD_AAD
    ).hex()

    # --- parent 3.6 / M1 E.2: the framed signing input --------------------
    v["SIGNED_MSG_SPK"] = signed_message(CTX_SPK, ID_A, SIGNED_PAYLOAD).hex()
    v["SIGNED_MSG_PQSPK"] = signed_message(CTX_PQSPK, ID_A, SIGNED_PAYLOAD).hex()
    v["SIGNED_MSG_ENROLMENT"] = signed_message(
        CTX_ENROLMENT, ID_A, SIGNED_PAYLOAD
    ).hex()

    return v


# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------

_ORDER = [
    "PEER_PUB_1",
    "PEER_PUB_2",
    "PEER_PUB_3",
    "PEER_PUB_4",
    "PEER_PUB_RATCHET",
    "KEM_CT_PQXDH",
    "KEM_CT_RATCHET",
    "SK_THREE_LEG",
    "SK_FOUR_LEG",
    "THREE_LEG_SESSION_ID",
    "THREE_LEG_CONFIRM_TAG",
    "THREE_LEG_FRAME_MAC_I2R",
    "THREE_LEG_FRAME_MAC_R2I",
    "FOUR_LEG_SESSION_ID",
    "FOUR_LEG_CONFIRM_TAG",
    "FOUR_LEG_FRAME_MAC_I2R",
    "FOUR_LEG_FRAME_MAC_R2I",
    "RATCHET_RK1",
    "RATCHET_RK1_SESSION_ID",
    "RATCHET_RK1_CONFIRM_TAG",
    "RATCHET_RK1_FRAME_MAC_I2R",
    "RATCHET_RK1_FRAME_MAC_R2I",
    "RATCHET_CK0",
    "CHAIN_CK1",
    "CHAIN_MK1",
    "CHAIN_CK2",
    "CHAIN_MK2",
    "MK1_CIPHERTEXT",
    "MK2_CIPHERTEXT",
    "K_STORE",
    "STORE_CIPHERTEXT",
    "SIGNED_MSG_SPK",
    "SIGNED_MSG_PQSPK",
    "SIGNED_MSG_ENROLMENT",
]

_HEADER = """\
// GENERATED FILE -- DO NOT EDIT BY HAND.
//
// Produced by `tests/vectors/generate.py`, which re-derives every value below
// from the specification text using only the Python standard library. It does
// not read the Rust implementation, so these bytes are an INDEPENDENT oracle
// rather than a recording of what this crate currently emits.
//
// Regenerate with:
//     uv run python rust/crates/mlkb-crypto/tests/vectors/generate.py
//
// If regenerating changes a value, either the spec changed or the oracle did.
// If a KAT in `key_schedule_kat.rs` fails, the Rust is wrong -- do not edit
// this file to make it pass.
"""


def main() -> int:
    _selftest_hkdf()
    _selftest_x25519()
    _selftest_aead()
    _selftest_ml_kem(KEM_SEED, [KEM_CT_PQXDH, KEM_CT_RATCHET])
    _selftest_python_reference()

    vectors = compute()
    missing = set(vectors) ^ set(_ORDER)
    if missing:
        raise SystemExit(f"vector list out of sync: {sorted(missing)}")

    lines = [_HEADER]
    for name in _ORDER:
        value = vectors[name]
        lines.append(f'const {name}: &str = "{value}";')
    body = "\n".join(lines) + "\n"

    out = pathlib.Path(__file__).with_name("key_schedule_vectors.rs")
    previous = out.read_text() if out.exists() else None
    out.write_text(body)
    if previous is not None and previous != body:
        print(f"CHANGED: {out}", file=sys.stderr)
    else:
        print(f"wrote {out} ({len(_ORDER)} vectors, self-tests passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
