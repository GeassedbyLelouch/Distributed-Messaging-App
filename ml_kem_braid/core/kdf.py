"""
Key Derivation Functions for ML-KEM Braid

Implements the KDF functions specified in the ML-KEM Braid protocol:
- KDF_AUTH: Derives authenticator update keys
- KDF_OK: Derives output keys from shared secrets

Both use HKDF (RFC 5869) with SHA-256 as the underlying hash function.

Reference:
    HKDF: https://www.rfc-editor.org/rfc/rfc5869
    ML-KEM Braid: https://signal.org/docs/specifications/mlkembraid/
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Tuple


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """
    HKDF-Extract: Extract a pseudorandom key from input keying material.
    
    PRK = HMAC-Hash(salt, IKM)
    
    Args:
        salt: Optional salt value (a non-secret random value)
        ikm: Input keying material
    
    Returns:
        A pseudorandom key (PRK)
    """
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """
    HKDF-Expand: Expand a pseudorandom key to the desired length.
    
    T(0) = empty string
    T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
    OKM = T(1) || T(2) || ... truncated to length
    
    Args:
        prk: Pseudorandom key from HKDF-Extract
        info: Context and application-specific information
        length: Desired output length in bytes
    
    Returns:
        Output keying material (OKM) of specified length
    """
    hash_len = 32  # SHA-256 output length
    n = (length + hash_len - 1) // hash_len
    
    if n > 255:
        raise ValueError("HKDF cannot produce more than 255*HashLen bytes")
    
    okm = b""
    t = b""
    
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    
    return okm[:length]


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """
    Full HKDF: Extract-then-Expand.
    
    Args:
        ikm: Input keying material
        salt: Salt for extraction
        info: Context info for expansion
        length: Desired output length
    
    Returns:
        Output keying material of specified length
    """
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


class KDF:
    """
    Key Derivation Functions for ML-KEM Braid Protocol.
    
    Provides the two KDF functions specified:
    1. KDF_AUTH: For authenticator state updates
    2. KDF_OK: For deriving output keys from shared secrets
    
    Usage:
        >>> kdf = KDF("MyProtocol_MLKEM768_SHA-256")
        >>> 
        >>> # Update authenticator state
        >>> new_root, new_mac_key = kdf.kdf_auth(root_key, update_key, epoch)
        >>> 
        >>> # Derive output key from shared secret
        >>> output_key = kdf.kdf_ok(shared_secret, epoch)
    
    Attributes:
        protocol_info: Protocol identifier string for domain separation
    """
    
    def __init__(self, protocol_info: str = "MLKEMBraid_MLKEM768_HMAC-SHA256"):
        """
        Initialize KDF with protocol information.
        
        Args:
            protocol_info: Protocol identifier string including:
                          - Protocol name
                          - KEM variant
                          - MAC algorithm
        """
        self.protocol_info = protocol_info.encode("utf-8")
    
    def kdf_auth(
        self,
        root_key: bytes,
        update_key: bytes,
        epoch: int
    ) -> Tuple[bytes, bytes]:
        """
        Derive authenticator update keys.
        
        Used to update the ratcheted authenticator state when new
        entropy (shared secret) becomes available.
        
        KDF_AUTH(root_key, update_key, epoch):
            HKDF-SHA256(
                salt=root_key,
                ikm=update_key,
                info=PROTOCOL_INFO || ":Authenticator Update" || ToBytes(epoch),
                length=64
            )
        
        Args:
            root_key: Current authenticator root key (32 bytes)
            update_key: New entropy from shared secret (32 bytes)
            epoch: Current epoch number
        
        Returns:
            Tuple of (new_root_key, new_mac_key), each 32 bytes
        """
        info = self.protocol_info + b":Authenticator Update" + epoch_to_bytes(epoch)
        
        output = hkdf(
            ikm=update_key,
            salt=root_key,
            info=info,
            length=64
        )
        
        new_root_key = output[:32]
        new_mac_key = output[32:64]
        
        return new_root_key, new_mac_key
    
    def kdf_ok(self, shared_secret: bytes, epoch: int) -> bytes:
        """
        Derive output key from shared secret.
        
        Used to derive the final output key that will be passed to
        the higher-level protocol (e.g., Double Ratchet).
        
        KDF_OK(shared_secret, epoch):
            HKDF-SHA256(
                salt=0x00*32,  # Zero-filled 32 bytes
                ikm=shared_secret,
                info=PROTOCOL_INFO || ":SCKA Key" || ToBytes(epoch),
                length=32
            )
        
        Args:
            shared_secret: KEM shared secret (32 bytes)
            epoch: Current epoch number
        
        Returns:
            32-byte output key for the epoch
        """
        info = self.protocol_info + b":SCKA Key" + epoch_to_bytes(epoch)
        
        # Salt is zero-filled byte sequence of hash output length (32 for SHA-256)
        salt = b"\x00" * 32
        
        output_key = hkdf(
            ikm=shared_secret,
            salt=salt,
            info=info,
            length=32
        )
        
        return output_key


def epoch_to_bytes(epoch: int) -> bytes:
    """
    Convert epoch to bytes using big-endian encoding.
    
    The specification recommends 64-bit unsigned integers with
    big-endian encoding.
    
    Args:
        epoch: Epoch number (unsigned 64-bit integer)
    
    Returns:
        8-byte big-endian representation
    """
    return epoch.to_bytes(8, byteorder="big")


def bytes_to_epoch(data: bytes) -> int:
    """
    Convert bytes back to epoch number.
    
    Args:
        data: 8-byte big-endian representation
    
    Returns:
        Epoch number as integer
    """
    return int.from_bytes(data, byteorder="big")


# Self-test
if __name__ == "__main__":
    print("Testing Key Derivation Functions...")
    
    kdf = KDF()
    
    # Test KDF_AUTH
    root_key = b"\x01" * 32
    update_key = b"\x02" * 32
    epoch = 1
    
    new_root, new_mac = kdf.kdf_auth(root_key, update_key, epoch)
    print(f"KDF_AUTH output:")
    print(f"  new_root_key: {new_root.hex()[:32]}...")
    print(f"  new_mac_key:  {new_mac.hex()[:32]}...")
    
    # Test KDF_OK
    shared_secret = b"\x03" * 32
    output_key = kdf.kdf_ok(shared_secret, epoch)
    print(f"KDF_OK output:")
    print(f"  output_key: {output_key.hex()}")
    
    # Test epoch encoding
    test_epoch = 0x0102030405060708
    encoded = epoch_to_bytes(test_epoch)
    decoded = bytes_to_epoch(encoded)
    assert decoded == test_epoch, "Epoch encoding/decoding failed"
    print(f"Epoch encoding: {test_epoch} -> {encoded.hex()} -> {decoded}")
    
    print("KDF tests passed!")
