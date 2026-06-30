"""
Sesame-style account / device / session management.

A minimal-metadata implementation of the concepts in Signal's Sesame spec
(https://signal.org/docs/specifications/sesame/): users are identified by a
*username* only, each user owns one or more *devices*, every device publishes a
PQXDH prekey bundle and owns a server-side *mailbox*. The client side keeps
per-(peer, device) *session records* holding the live ML-KEM Braid state.
"""

from ml_kem_braid.sesame.base import StoreBackend
from ml_kem_braid.sesame.sqlite_store import SqliteStore
from ml_kem_braid.sesame.store import (
    Account,
    Device,
    Envelope,
    SesameStore,
)

__all__ = ["Account", "Device", "Envelope", "SesameStore", "SqliteStore", "StoreBackend"]
