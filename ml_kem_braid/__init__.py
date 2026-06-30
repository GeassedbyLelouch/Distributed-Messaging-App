"""
ML-KEM Braid: a real (FIPS-203) implementation of Signal's post-quantum Sparse
Continuous Key Agreement, plus PQXDH initial key agreement and a Sesame-style
chat scaffold (FastAPI server + client + testnet).

Modules:
    core        ML-KEM incremental KEM, HKDF KDFs, ratcheted authenticator, AEAD
    encoding    Reed-Solomon erasure coding for the chunk stream
    protocol    Braid SCKA state machine, messages, orchestration + exchange driver
    pqxdh       PQXDH handshake (X25519 + ML-KEM-1024) producing the initial secret
    sesame      account / device / mailbox store (minimal metadata)
    server      FastAPI key-distribution + mailbox relay
    client      registration, handshake, Braid session, AEAD chat
    testnet     in-process end-to-end demo
    transport   wire/HTTP helpers
"""

__version__ = "0.2.0"

from ml_kem_braid.protocol.braid import MLKEMBraid, Role, run_exchange

__all__ = ["MLKEMBraid", "Role", "run_exchange", "__version__"]
