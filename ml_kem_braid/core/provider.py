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
        """Encrypt with AES-GCM and return ``(nonce, ciphertext)``."""
        nonce = self.random_bytes(12)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

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
