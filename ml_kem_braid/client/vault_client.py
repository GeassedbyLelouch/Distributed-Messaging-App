from __future__ import annotations

from ml_kem_braid.decentralized import InMemoryClientVault


class VaultBackedClient:
    """Minimal client wrapper for vault-owned identity state."""

    def __init__(self, vault: InMemoryClientVault, username: str) -> None:
        self.vault = vault
        self.username = username

    def initialize_identity(self, identity_secret: bytes) -> None:
        self.vault.store_identity(self.username, identity_secret)
