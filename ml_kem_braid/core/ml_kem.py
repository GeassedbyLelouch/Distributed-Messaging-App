"""
ML-KEM Incremental Interface (FIPS 203) for the ML-KEM Braid protocol.

This module implements the *real* incremental encapsulation interface required by
Signal's ML-KEM Braid specification, by orchestrating the FIPS-203 K-PKE
primitives exposed by the ``kyber-py`` library. **No cryptography is implemented
from scratch here** — every lattice operation (matrix expansion, CBD sampling,
NTT, compression, encoding, the FO transform and implicit rejection) is performed
by ``kyber-py``'s own audited primitives. This file only *re-orders* the standard
``encaps`` computation into the two phases the Braid protocol needs.

Why kyber-py and not liboqs/pycryptodome
-----------------------------------------
The Braid protocol's defining optimisation is splitting ML-KEM encapsulation so
that the first ciphertext component ``ct1`` can be produced from the 64-byte
header alone, and the reconciliation component ``ct2`` is produced later once the
full encapsulation-key vector arrives. This requires access to ML-KEM's internal
K-PKE encryption (``c1`` vs ``c2``). ``liboqs`` and ``pycryptodome`` expose only a
monolithic ``encaps()`` and therefore *cannot* implement the Braid split. The
pure-Python ``kyber-py`` reference implementation exposes exactly the internals
needed, so it is the only viable backend for a faithful Braid KEM in Python.

Mapping to FIPS-203 byte layout
-------------------------------
A FIPS-203 encapsulation key is ``ek = Encode_12(t_hat) || rho`` (``384k + 32``
bytes). The Braid "header" is built from:

* ``ek_seed`` = ``rho`` (the 32-byte matrix seed)            = ``ek[-32:]``
* ``ek_vector`` = ``Encode_12(t_hat)`` (``384k`` bytes)       = ``ek[:-32]``
* ``hek`` = ``SHA3-256(ek)``  (over the *canonical* ek bytes; needed by the FO
  transform, since ``(K, r) = G(m || H(ek))``)

``ct1`` is the ``u``-vector ciphertext component ``Compress_du`` encoded
(``32*du*k`` bytes); ``ct2`` is the ``v``-polynomial component ``Compress_dv``
encoded (``32*dv`` bytes). Concatenated, ``ct1 || ct2`` is *exactly* the standard
ML-KEM ciphertext, so standard FIPS-203 ``Decaps`` recovers the shared secret.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import Enum
from typing import NamedTuple, Optional, Tuple

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024


class MLKEMVariant(Enum):
    """ML-KEM security levels (FIPS 203)."""

    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"


_IMPL = {
    MLKEMVariant.ML_KEM_512: ML_KEM_512,
    MLKEMVariant.ML_KEM_768: ML_KEM_768,
    MLKEMVariant.ML_KEM_1024: ML_KEM_1024,
}


@dataclass(frozen=True)
class MLKEMParams:
    """Byte sizes for a variant, derived from the backing FIPS-203 parameters."""

    variant: MLKEMVariant
    k: int
    du: int
    dv: int
    ek_seed_size: int = 32
    shared_secret_size: int = 32

    @property
    def ek_vector_size(self) -> int:
        # Encode_12(t_hat): k polynomials * 256 coeffs * 12 bits / 8 = 384*k
        return 384 * self.k

    @property
    def ek_size(self) -> int:
        return self.ek_vector_size + self.ek_seed_size

    @property
    def header_size(self) -> int:
        return self.ek_seed_size + 32  # ek_seed || hek = 64

    @property
    def ct1_size(self) -> int:
        return 32 * self.du * self.k

    @property
    def ct2_size(self) -> int:
        return 32 * self.dv

    @property
    def ct_size(self) -> int:
        return self.ct1_size + self.ct2_size


class KeyPair(NamedTuple):
    """An ML-KEM keypair exposed in the Braid header layout."""

    dk: bytes  # FIPS-203 decapsulation key (768k + 96 bytes), private
    ek_seed: bytes  # rho, 32 bytes (public, goes in header)
    ek_vector: bytes  # Encode_12(t_hat), 384k bytes (public, sent separately)
    hek: bytes  # SHA3-256(ek) over canonical ek bytes (public, goes in header)


@dataclass
class EncapsulationSecret:
    """
    In-memory intermediate state produced by :meth:`MLKEM.encaps1` and consumed by
    :meth:`MLKEM.encaps2`. Holds the lattice objects already sampled from the
    encapsulation randomness so ``ct2`` can be completed once ``ek_vector`` is
    known, without resampling. This object is **never serialised or transmitted**.
    """

    m: bytes  # 32-byte FO message; mu = Decompress_1(Decode_1(m))
    y_hat: object  # NTT-domain randomness vector (kyber_py Vector)
    e2: object  # error polynomial for the v component (kyber_py Polynomial)
    shared_secret: bytes  # K = G(m || hek)[:32]


class MLKEM:
    """
    Real FIPS-203 ML-KEM with the Braid incremental interface.

    >>> kem = MLKEM(MLKEMVariant.ML_KEM_768)
    >>> kp = kem.keygen()
    >>> es, ct1, ss_b = kem.encaps1(kp.ek_seed, kp.hek)   # from header only
    >>> ct2 = kem.encaps2(es, kp.ek_seed, kp.ek_vector)   # once ek_vector known
    >>> ss_a = kem.decaps(kp.dk, ct1, ct2)
    >>> ss_a == ss_b
    True
    """

    def __init__(self, variant: MLKEMVariant = MLKEMVariant.ML_KEM_768):
        self.variant = variant
        self._impl = _IMPL[variant]
        self.params = MLKEMParams(
            variant=variant,
            k=self._impl.k,
            du=self._impl.du,
            dv=self._impl.dv,
        )

    # -- key generation -----------------------------------------------------

    def keygen(self, seed: Optional[bytes] = None) -> KeyPair:
        """
        Generate a keypair. If ``seed`` (64 bytes = d||z) is given, generation is
        deterministic via FIPS-203 Section 7.1 key expansion; otherwise system
        randomness is used.
        """
        if seed is not None:
            if len(seed) != 64:
                raise ValueError("deterministic seed must be 64 bytes (d || z)")
            ek, dk = self._impl.key_derive(seed)
        else:
            ek, dk = self._impl.keygen()

        ek_vector, ek_seed = ek[:-32], ek[-32:]
        hek = self._impl._H(ek)
        return KeyPair(dk=dk, ek_seed=ek_seed, ek_vector=ek_vector, hek=hek)

    def hek_for(self, ek_seed: bytes, ek_vector: bytes) -> bytes:
        """Recompute ``hek = SHA3-256(ek)`` from the header seed and the vector.

        The canonical encapsulation key is ``ek_vector || ek_seed``
        (``Encode_12(t_hat) || rho``); hashing in any other order would not match
        the value fed into the FO transform and decapsulation would fail.
        """
        return self._impl._H(ek_vector + ek_seed)

    # -- incremental encapsulation -----------------------------------------

    def encaps1(
        self,
        ek_seed: bytes,
        hek: bytes,
        m: Optional[bytes] = None,
    ) -> Tuple[EncapsulationSecret, bytes, bytes]:
        """
        Phase 1: compute the shared secret ``K`` and ``ct1`` from the header only.

        Mirrors the first half of ``kyber_py``'s ``_k_pke_encrypt`` (the ``u``
        component), which depends solely on ``rho`` (= ``ek_seed``) and the
        encapsulation randomness ``r`` derived from ``m`` and ``hek``.
        """
        impl = self._impl
        if m is None:
            m = secrets.token_bytes(32)

        # FO transform: (K, r) = G(m || H(ek)). hek IS H(ek).
        shared_secret, r = impl._G(m + hek)

        a_hat_t = impl._generate_matrix_from_seed(ek_seed, transpose=True)
        n = 0
        y, n = impl._generate_error_vector(r, impl.eta_1, n)
        e1, n = impl._generate_error_vector(r, impl.eta_2, n)
        e2, n = impl._generate_polynomial(r, impl.eta_2, n)

        y_hat = y.to_ntt()
        u = (a_hat_t @ y_hat).from_ntt() + e1
        ct1 = u.compress(impl.du).encode(impl.du)

        secret = EncapsulationSecret(
            m=m, y_hat=y_hat, e2=e2, shared_secret=shared_secret
        )
        return secret, ct1, shared_secret

    def encaps2(
        self,
        secret: EncapsulationSecret,
        ek_seed: bytes,
        ek_vector: bytes,
    ) -> bytes:
        """
        Phase 2: compute ``ct2`` (the ``v``-component reconciliation message) once
        the full ``ek_vector`` (= ``Encode_12(t_hat)``) is available.

        Mirrors the second half of ``_k_pke_encrypt`` using the lattice values
        already sampled in :meth:`encaps1`.
        """
        impl = self._impl
        if len(ek_vector) != self.params.ek_vector_size:
            raise ValueError(
                f"ek_vector wrong length: expected {self.params.ek_vector_size}, "
                f"got {len(ek_vector)}"
            )

        t_hat = impl.M.decode_vector(ek_vector, impl.k, 12, is_ntt=True)
        mu = impl.R.decode(secret.m, 1).decompress(1)
        v = t_hat.dot(secret.y_hat).from_ntt() + secret.e2 + mu
        ct2 = v.compress(impl.dv).encode(impl.dv)
        return ct2

    # -- decapsulation ------------------------------------------------------

    def decaps(self, dk: bytes, ct1: bytes, ct2: bytes) -> bytes:
        """
        Standard FIPS-203 decapsulation over the reassembled ciphertext
        ``ct1 || ct2``, including the modulus/type checks and constant-time
        implicit rejection performed by ``kyber_py._decaps_internal``.
        """
        return self._impl._decaps_internal(dk, ct1 + ct2)

    def __repr__(self) -> str:
        return f"MLKEM({self.variant.value})"


def create_ml_kem(variant: str = "768") -> MLKEM:
    """Create an :class:`MLKEM` by security level string (``"512"``/``"768"``/``"1024"``)."""
    return MLKEM(
        {
            "512": MLKEMVariant.ML_KEM_512,
            "768": MLKEMVariant.ML_KEM_768,
            "1024": MLKEMVariant.ML_KEM_1024,
        }[variant]
    )


if __name__ == "__main__":
    for v in MLKEMVariant:
        kem = MLKEM(v)
        kp = kem.keygen()
        assert len(kp.ek_seed) == 32
        assert len(kp.ek_vector) == kem.params.ek_vector_size
        es, ct1, ss_b = kem.encaps1(kp.ek_seed, kp.hek)
        ct2 = kem.encaps2(es, kp.ek_seed, kp.ek_vector)
        assert len(ct1) == kem.params.ct1_size, (len(ct1), kem.params.ct1_size)
        assert len(ct2) == kem.params.ct2_size, (len(ct2), kem.params.ct2_size)
        ss_a = kem.decaps(kp.dk, ct1, ct2)
        # Cross-check against the library's own monolithic ciphertext too.
        assert ss_a == ss_b, f"{v}: shared secret mismatch"
        print(f"{v.value}: OK  ct1={len(ct1)} ct2={len(ct2)} ss={ss_a.hex()[:16]}...")
    print("All ML-KEM incremental self-tests passed.")
