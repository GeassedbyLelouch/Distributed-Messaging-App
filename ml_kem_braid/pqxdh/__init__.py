"""
PQXDH: Post-Quantum Extended Diffie-Hellman initial key agreement.

Implements Signal's PQXDH (https://signal.org/docs/specifications/pqxdh/) to
establish the initial shared secret ``SK`` that seeds the ML-KEM Braid SCKA
authenticator. Combines classical X25519 Diffie-Hellman with an ML-KEM-1024
encapsulation so the handshake is secure unless *both* the elliptic-curve and the
lattice problem are broken ("harvest-now-decrypt-later" resistant).
"""

from ml_kem_braid.pqxdh.pqxdh import (
    MAX_REPLAY_CACHE,
    IdentityKeyPair,
    PreKeyBundle,
    PreKeySecrets,
    InitialMessage,
    PQXDH_KEM,
    ReplayCache,
    ReplayError,
    create_identity,
    create_prekey_bundle,
    initiator_handshake,
    responder_handshake,
)

__all__ = [
    "IdentityKeyPair",
    "PreKeyBundle",
    "PreKeySecrets",
    "InitialMessage",
    "PQXDH_KEM",
    # Replay protection (audit M2). Exported so a multi-tenant responder can
    # pass a per-account/device cache instead of sharing the process-wide
    # default, where one loud peer could evict another's entries.
    "MAX_REPLAY_CACHE",
    "ReplayCache",
    "ReplayError",
    "create_identity",
    "create_prekey_bundle",
    "initiator_handshake",
    "responder_handshake",
]
