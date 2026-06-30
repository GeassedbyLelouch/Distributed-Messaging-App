"""
Core cryptographic primitives for ML-KEM Braid.

Contains:
    - ML-KEM incremental interface wrapper
    - Key derivation functions (HKDF)
    - Ratcheted authenticator (HMAC-based MAC)
"""

from ml_kem_braid.core.ml_kem import MLKEM, MLKEMParams
from ml_kem_braid.core.kdf import KDF
from ml_kem_braid.core.authenticator import Authenticator

__all__ = ["MLKEM", "MLKEMParams", "KDF", "Authenticator"]
