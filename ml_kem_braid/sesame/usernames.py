"""Username normalization for Signal-style nickname discriminators."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


_NICKNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DISCRIMINATOR_RE = re.compile(r"^[0-9]+$")


class UsernameValidationError(ValueError):
    """Raised when a username fails validation."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(message)


@dataclass(frozen=True)
class NormalizedUsername:
    display: str
    normalized: str
    lookup_hash: str


def normalize_username(username: str) -> NormalizedUsername:
    """Validate and normalize ``nickname.discriminator`` usernames."""
    if "." not in username:
        _raise("missing_separator", "username must include a nickname and discriminator")

    nickname, discriminator = username.rsplit(".", 1)
    _validate_nickname(nickname)
    _validate_discriminator(discriminator)

    normalized = f"{nickname.lower()}.{discriminator}"
    return NormalizedUsername(
        display=username,
        normalized=normalized,
        lookup_hash=_lookup_hash(normalized),
    )


def username_lookup_hash(username: str) -> str:
    """Return the SHA-256 lookup hash for a normalized username."""
    return normalize_username(username).lookup_hash


def _validate_nickname(nickname: str) -> None:
    if not nickname:
        _raise("nickname_empty", "nickname must not be empty")
    if len(nickname) < 3:
        _raise("nickname_too_short", "nickname must be at least 3 characters")
    if len(nickname) > 32:
        _raise("nickname_too_long", "nickname must be at most 32 characters")
    if nickname[0].isdigit():
        _raise("nickname_starts_with_digit", "nickname must not start with a digit")
    if not _is_ascii(nickname) or not _NICKNAME_RE.fullmatch(nickname):
        _raise("nickname_bad_character", "nickname contains an invalid character")


def _validate_discriminator(discriminator: str) -> None:
    if not _DISCRIMINATOR_RE.fullmatch(discriminator):
        _raise(
            "discriminator_bad_character",
            "discriminator must contain only ASCII digits",
        )
    if all(char == "0" for char in discriminator):
        _raise("discriminator_zero", "discriminator must be greater than zero")
    if len(discriminator) < 2:
        _raise(
            "discriminator_single_digit",
            "discriminator must contain at least two digits",
        )
    if len(discriminator) > 2 and discriminator.startswith("0"):
        _raise(
            "discriminator_leading_zero",
            "discriminator must not contain leading zeros",
        )


def _lookup_hash(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _is_ascii(value: str) -> bool:
    return value.isascii()


def _raise(code: str, message: str) -> None:
    raise UsernameValidationError(code, message)


__all__ = [
    "NormalizedUsername",
    "UsernameValidationError",
    "normalize_username",
    "username_lookup_hash",
]
