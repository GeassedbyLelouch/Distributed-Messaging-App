"""
Minimal crypto provider abstraction for research and development use.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import ClassVar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ml_kem_braid.core.aead import (  # noqa: F401  (NonceReuseError re-exported)
    NonceReuseError,
    claim_single_use,
    nonce_from_counter,
)


@dataclass(frozen=True)
class ResearchCryptoProvider:
    """Small crypto provider backed by local OS randomness and cryptography."""

    name: ClassVar[str] = "research"

    def random_bytes(self, size: int) -> bytes:
        """Return ``size`` bytes from the operating system CSPRNG."""
        if size < 0:
            raise ValueError("size must be non-negative")
        return os.urandom(size)

    def hkdf_sha256(self, ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
        """Derive key material with HKDF-SHA256."""
        if length < 0:
            raise ValueError("length must be non-negative")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(ikm)

    def aead_encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        associated_data: bytes,
    ) -> tuple[bytes, bytes]:
        """Encrypt with AES-GCM under a **single-use** key; returns ``(nonce, ciphertext)``.

        The random 96-bit nonce is only safe for a key that encrypts exactly one
        message (audit finding M4). Single-use is the CALLER's obligation.

        The shared process-local guard behind :func:`claim_single_use` only
        *detects* violations it happens to remember: it is bounded, per-process,
        and blind across restarts. It never evicts, so at capacity it raises
        :class:`~ml_kem_braid.core.aead.SingleUseGuardExhausted` and this method
        refuses to encrypt (fail closed) instead of silently forgetting an
        earlier key. See :mod:`ml_kem_braid.core.aead` for the exact contract.

        For any key that encrypts more than one message use
        :meth:`aead_encrypt_counter`, whose nonce uniqueness is structural.
        """
        claim_single_use(key)
        nonce = self.random_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def aead_encrypt_counter(
        self,
        key: bytes,
        counter: int,
        plaintext: bytes,
        associated_data: bytes,
    ) -> tuple[bytes, bytes]:
        """Encrypt with AES-GCM under a monotonic ``u64`` counter nonce.

        Structurally collision-free for a caller that never repeats ``counter``
        under one ``key``; exhaustion of the counter space is rejected
        explicitly rather than wrapping to zero.
        """
        nonce = nonce_from_counter(counter)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def aead_decrypt_counter(
        self,
        key: bytes,
        counter: int,
        ciphertext: bytes,
        associated_data: bytes,
    ) -> bytes:
        """Decrypt a counter-nonce AES-GCM ciphertext at sequence position ``counter``."""
        return AESGCM(key).decrypt(
            nonce_from_counter(counter), ciphertext, associated_data
        )

    def aead_decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes,
    ) -> bytes:
        """Decrypt an AES-GCM ciphertext."""
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data)
