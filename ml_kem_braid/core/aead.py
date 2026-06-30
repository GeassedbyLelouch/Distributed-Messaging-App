"""
Authenticated encryption for chat payloads.

Uses AES-256-GCM from ``cryptography`` (no hand-rolled crypto). Each message key
derived by the Braid SCKA (or PQXDH initial key) is used as an AES-256 key with a
fresh 96-bit random nonce per message; the nonce is prepended to the ciphertext.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96-bit GCM nonce
KEY_SIZE = 32  # AES-256


def aead_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> bytes:
    """Encrypt ``plaintext`` under a 32-byte ``key``; returns ``nonce || ciphertext||tag``."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"AEAD key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return nonce + ct


def aead_decrypt(key: bytes, blob: bytes, associated_data: bytes = b"") -> bytes:
    """Inverse of :func:`aead_encrypt`. Raises ``InvalidTag`` on tamper/wrong key."""
    if len(key) != KEY_SIZE:
        raise ValueError(f"AEAD key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(blob) < NONCE_SIZE:
        raise ValueError("ciphertext too short to contain a nonce")
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ct, associated_data)
