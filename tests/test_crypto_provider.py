import pytest
from cryptography.exceptions import InvalidTag

from ml_kem_braid.core.provider import ResearchCryptoProvider


def test_research_provider_hkdf_and_aead_round_trip():
    provider = ResearchCryptoProvider()

    key = provider.hkdf_sha256(b"ikm", b"salt", b"info", 32)
    nonce, ciphertext = provider.aead_encrypt(key, b"plaintext", b"ad")

    assert len(key) == 32
    assert len(nonce) == 12
    assert provider.aead_decrypt(key, nonce, ciphertext, b"ad") == b"plaintext"


def test_research_provider_random_bytes_length():
    provider = ResearchCryptoProvider()

    assert len(provider.random_bytes(48)) == 48


def test_research_provider_rejects_negative_random_bytes_size():
    provider = ResearchCryptoProvider()

    with pytest.raises(ValueError):
        provider.random_bytes(-1)


def test_research_provider_rejects_negative_hkdf_length():
    provider = ResearchCryptoProvider()

    with pytest.raises(ValueError):
        provider.hkdf_sha256(b"ikm", b"salt", b"info", -1)


def test_research_provider_aead_decrypt_rejects_non_12_byte_nonce():
    provider = ResearchCryptoProvider()
    key = provider.hkdf_sha256(b"ikm", b"salt", b"info", 32)
    nonce, ciphertext = provider.aead_encrypt(key, b"plaintext", b"ad")

    with pytest.raises(ValueError):
        provider.aead_decrypt(key, nonce + b"x", ciphertext, b"ad")


def test_research_provider_aead_rejects_wrong_associated_data():
    provider = ResearchCryptoProvider()
    key = provider.hkdf_sha256(b"ikm", b"salt", b"info", 32)
    nonce, ciphertext = provider.aead_encrypt(key, b"plaintext", b"ad")

    with pytest.raises(InvalidTag):
        provider.aead_decrypt(key, nonce, ciphertext, b"wrong-ad")
