import pytest
from cryptography.exceptions import InvalidTag

from ml_kem_braid.core import aead
from ml_kem_braid.core.aead import (
    MAX_COUNTER,
    NonceReuseError,
    SingleUseGuardExhausted,
)
from ml_kem_braid.core.provider import ResearchCryptoProvider


@pytest.fixture(autouse=True)
def _clean_single_use_guard():
    aead.reset_single_use_guard()
    yield
    aead.reset_single_use_guard()


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
    # Distinct `info` per test: the random-nonce path is single-use per key (M4),
    # so two tests must not derive the same key.
    key = provider.hkdf_sha256(b"ikm", b"salt", b"info-nonce-len", 32)
    nonce, ciphertext = provider.aead_encrypt(key, b"plaintext", b"ad")

    with pytest.raises(ValueError):
        provider.aead_decrypt(key, nonce + b"x", ciphertext, b"ad")


def test_research_provider_aead_rejects_wrong_associated_data():
    provider = ResearchCryptoProvider()
    key = provider.hkdf_sha256(b"ikm", b"salt", b"info-wrong-ad", 32)
    nonce, ciphertext = provider.aead_encrypt(key, b"plaintext", b"ad")

    with pytest.raises(InvalidTag):
        provider.aead_decrypt(key, nonce, ciphertext, b"wrong-ad")


# -- M4: nonce discipline ----------------------------------------------------


def test_research_provider_random_nonce_key_is_single_use():
    """M4: a second random-nonce encryption under one AES-GCM key risks a nonce
    collision (full break) and must be rejected."""
    provider = ResearchCryptoProvider()
    key = provider.hkdf_sha256(b"ikm", b"salt", b"info-single-use", 32)
    provider.aead_encrypt(key, b"first", b"ad")

    with pytest.raises(NonceReuseError):
        provider.aead_encrypt(key, b"second", b"ad")


def test_research_provider_counter_nonces_are_unique_and_round_trip():
    provider = ResearchCryptoProvider()
    key = provider.hkdf_sha256(b"ikm", b"salt", b"info-counter", 32)

    n0, c0 = provider.aead_encrypt_counter(key, 0, b"m0", b"ad")
    n1, c1 = provider.aead_encrypt_counter(key, 1, b"m1", b"ad")

    assert n0 != n1
    assert n0 == b"\x00" * 12
    assert provider.aead_decrypt_counter(key, 0, c0, b"ad") == b"m0"
    assert provider.aead_decrypt_counter(key, 1, c1, b"ad") == b"m1"
    with pytest.raises(InvalidTag):
        provider.aead_decrypt_counter(key, 1, c0, b"ad")


def test_research_provider_counter_overflow_is_rejected():
    provider = ResearchCryptoProvider()
    key = provider.hkdf_sha256(b"ikm", b"salt", b"info-overflow", 32)

    with pytest.raises(NonceReuseError):
        provider.aead_encrypt_counter(key, MAX_COUNTER + 1, b"m", b"ad")
    with pytest.raises(ValueError):
        provider.aead_encrypt_counter(key, -1, b"m", b"ad")


# ---------------------------------------------------------------------------
# D8 — the provider shares the guard, so it must fail closed the same way
# ---------------------------------------------------------------------------


def test_provider_guard_fails_closed_and_never_forgets():
    provider = ResearchCryptoProvider()
    original = aead.single_use_guard_capacity()
    aead.reset_single_use_guard()
    aead.set_single_use_guard_capacity(3)
    try:
        victim = provider.random_bytes(32)
        provider.aead_encrypt(victim, b"first", b"ad")
        for _ in range(2):
            provider.aead_encrypt(provider.random_bytes(32), b"x", b"ad")

        # Flood: the provider refuses rather than evicting the victim's record.
        for _ in range(100):
            with pytest.raises(SingleUseGuardExhausted):
                provider.aead_encrypt(provider.random_bytes(32), b"x", b"ad")

        with pytest.raises(NonceReuseError) as excinfo:
            provider.aead_encrypt(victim, b"second", b"ad")
        assert not isinstance(excinfo.value, SingleUseGuardExhausted)

        # The structural path is unaffected by guard state.
        key = provider.random_bytes(32)
        for counter in range(5):
            nonce, ct = provider.aead_encrypt_counter(key, counter, b"m", b"ad")
            assert provider.aead_decrypt_counter(key, counter, ct, b"ad") == b"m"
    finally:
        aead.set_single_use_guard_capacity(original)
        aead.reset_single_use_guard()
