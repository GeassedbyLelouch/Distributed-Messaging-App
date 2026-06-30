"""FastAPI key-distribution + mailbox server for the ML-KEM Braid chat scaffold."""

from ml_kem_braid.server.app import create_app

__all__ = ["create_app"]
