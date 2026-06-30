"""
Encoding module for ML-KEM Braid.

Provides erasure coding for robust message chunking over
potentially lossy/adversarial networks.
"""

from ml_kem_braid.encoding.erasure import Chunk, Encoder, Decoder

__all__ = ["Chunk", "Encoder", "Decoder"]
