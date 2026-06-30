from __future__ import annotations

import binascii
import hashlib

import pytest

from ml_kem_braid.sesame.usernames import (
    UsernameValidationError,
    normalize_username,
    username_lookup_hash,
)


def test_normalize_username_preserves_display_case_and_hashes_lowercase_nickname():
    mixed = normalize_username("Alice_42.1042")
    lower = normalize_username("alice_42.1042")

    assert mixed.display == "Alice_42.1042"
    assert mixed.normalized == "alice_42.1042"
    assert mixed.lookup_hash == lower.lookup_hash


@pytest.mark.parametrize(
    ("username", "code"),
    [
        ("alice", "missing_separator"),
        (".42", "nickname_empty"),
        ("ab.42", "nickname_too_short"),
        ("0alice.42", "nickname_starts_with_digit"),
        ("ali-ce.42", "nickname_bad_character"),
        ("alice.1", "discriminator_single_digit"),
        ("alice.0", "discriminator_zero"),
        ("alice.00", "discriminator_zero"),
        ("alice.001", "discriminator_leading_zero"),
        ("alice.+42", "discriminator_bad_character"),
    ],
)
def test_invalid_usernames_raise_stable_codes(username: str, code: str):
    with pytest.raises(UsernameValidationError) as exc_info:
        normalize_username(username)

    assert exc_info.value.code == code
    assert isinstance(exc_info.value.message, str)
    assert exc_info.value.message


def test_discriminator_rejects_non_ascii_digits():
    with pytest.raises(UsernameValidationError) as exc_info:
        normalize_username("alice.\u0664\u0662")

    assert exc_info.value.code == "discriminator_bad_character"


def test_very_long_all_zero_discriminator_raises_username_validation_error():
    with pytest.raises(UsernameValidationError) as exc_info:
        normalize_username(f"alice.{'0' * 5000}")

    assert exc_info.value.code == "discriminator_zero"


@pytest.mark.parametrize("username", ["_SiGNA1.42", "LOUD.700", "usr.999999999"])
def test_valid_usernames_normalize(username: str):
    normalized = normalize_username(username)

    nickname, discriminator = username.rsplit(".", 1)
    assert normalized.display == username
    assert normalized.normalized == f"{nickname.lower()}.{discriminator}"
    assert normalized.lookup_hash == username_lookup_hash(username)


def test_nickname_length_boundaries():
    valid_nickname = "a" * 32
    assert normalize_username(f"{valid_nickname}.42").normalized == f"{valid_nickname}.42"

    invalid_nickname = "a" * 33
    with pytest.raises(UsernameValidationError) as exc_info:
        normalize_username(f"{invalid_nickname}.42")

    assert exc_info.value.code == "nickname_too_long"


def test_username_lookup_hash_is_case_insensitive_sha256_hex():
    digest = username_lookup_hash("Alice.42")

    assert digest == username_lookup_hash("alice.42")
    assert digest == hashlib.sha256("alice.42".encode("utf-8")).hexdigest()
    assert len(digest) == 64
    assert binascii.unhexlify(digest)
