"""AEAD nonce-discipline and associated-data binding tests (audit M4, L4)."""

import inspect
import os

import pytest
from cryptography.exceptions import InvalidTag

from ml_kem_braid.core import aead
from ml_kem_braid.core.aead import (
    MAX_COUNTER,
    NONCE_SIZE,
    CounterAeadKey,
    NonceReuseError,
    SingleUseGuardExhausted,
    aead_decrypt,
    aead_decrypt_counter,
    aead_encrypt,
    aead_encrypt_counter,
    nonce_from_counter,
)


@pytest.fixture(autouse=True)
def _clean_guard():
    aead.reset_single_use_guard()
    yield
    aead.reset_single_use_guard()


# -- L4: associated_data must be required -----------------------------------


def test_associated_data_is_a_required_parameter():
    """L4: `associated_data` must not default to b"" — epoch/header context must
    always be bound explicitly by the caller."""
    for fn in (aead_encrypt, aead_decrypt):
        param = inspect.signature(fn).parameters["associated_data"]
        assert param.default is inspect.Parameter.empty, f"{fn.__name__} AD is optional"
    with pytest.raises(TypeError):
        aead_encrypt(os.urandom(32), b"pt")  # type: ignore[call-arg]


def test_round_trip_binds_associated_data():
    key = os.urandom(32)
    blob = aead_encrypt(key, b"pt", b"ad")
    assert aead_decrypt(key, blob, b"ad") == b"pt"
    with pytest.raises(InvalidTag):
        aead_decrypt(key, blob, b"other-ad")


# -- M4: random-nonce path is single-use per key ----------------------------


def test_random_nonce_encrypt_refuses_second_use_of_same_key():
    """M4: a second random-nonce encryption under the SAME AES-GCM key is a
    nonce-collision risk (birthday bound over 96 bits) and must be rejected."""
    key = os.urandom(32)
    aead_encrypt(key, b"first", b"ad")
    with pytest.raises(NonceReuseError):
        aead_encrypt(key, b"second", b"ad")


def test_distinct_keys_are_unaffected_by_the_guard():
    for _ in range(64):
        key = os.urandom(32)
        blob = aead_encrypt(key, b"pt", b"ad")
        assert aead_decrypt(key, blob, b"ad") == b"pt"


def test_decrypt_is_not_rate_limited_by_the_guard():
    key = os.urandom(32)
    blob = aead_encrypt(key, b"pt", b"ad")
    for _ in range(5):
        assert aead_decrypt(key, blob, b"ad") == b"pt"


# -- M4: counter-nonce API ---------------------------------------------------


def test_nonce_from_counter_is_12_byte_big_endian():
    assert nonce_from_counter(0) == b"\x00" * NONCE_SIZE
    assert nonce_from_counter(1) == b"\x00" * 11 + b"\x01"
    assert nonce_from_counter(MAX_COUNTER) == b"\x00" * 4 + b"\xff" * 8


def test_nonce_from_counter_rejects_overflow_and_negative():
    with pytest.raises(NonceReuseError):
        nonce_from_counter(MAX_COUNTER + 1)
    with pytest.raises(ValueError):
        nonce_from_counter(-1)
    with pytest.raises(TypeError):
        nonce_from_counter(True)  # bool is not an acceptable counter


def test_counter_round_trip_and_nonce_binding():
    key = os.urandom(32)
    blob0 = aead_encrypt_counter(key, 0, b"m0", b"ad")
    blob1 = aead_encrypt_counter(key, 1, b"m1", b"ad")
    assert blob0[:NONCE_SIZE] != blob1[:NONCE_SIZE]
    assert aead_decrypt_counter(key, 0, blob0, b"ad") == b"m0"
    assert aead_decrypt_counter(key, 1, blob1, b"ad") == b"m1"
    # A blob presented under the wrong counter must be rejected, not silently
    # decrypted using the nonce carried in the blob.
    with pytest.raises(ValueError):
        aead_decrypt_counter(key, 1, blob0, b"ad")


def test_counter_key_is_monotonic_and_rejects_exhaustion():
    key = os.urandom(32)
    ck = CounterAeadKey(key)
    c0, b0 = ck.seal(b"m0", b"ad")
    c1, b1 = ck.seal(b"m1", b"ad")
    assert (c0, c1) == (0, 1)
    assert ck.open(c0, b0, b"ad") == b"m0"
    assert ck.open(c1, b1, b"ad") == b"m1"

    exhausted = CounterAeadKey(key, next_counter=MAX_COUNTER)
    exhausted.seal(b"last", b"ad")
    with pytest.raises(NonceReuseError):
        exhausted.seal(b"one too many", b"ad")


def test_counter_key_rejects_bad_key_size():
    with pytest.raises(ValueError):
        CounterAeadKey(os.urandom(16))


# ---------------------------------------------------------------------------
# D8 — the single-use-key guard must fail CLOSED, never forget
# ---------------------------------------------------------------------------


@pytest.fixture
def _small_guard():
    """Shrink the guard so capacity behaviour is testable, then restore it."""
    original = aead.single_use_guard_capacity()
    aead.reset_single_use_guard()
    yield aead.set_single_use_guard_capacity
    aead.set_single_use_guard_capacity(original)
    aead.reset_single_use_guard()


def test_guard_never_forgets_a_key_when_flooded(_small_guard):
    """THE D8 ATTACK.

    The guard used to evict oldest-first at capacity, so after enough unrelated
    encryptions a key's record silently disappeared and its reuse — the thing
    that leaks the GHASH key — stopped being detected.
    """
    _small_guard(4)
    victim = os.urandom(32)
    aead_encrypt(victim, b"first", b"ad")

    # Fill the remaining capacity, then flood far past it.
    for _ in range(3):
        aead_encrypt(os.urandom(32), b"x", b"ad")
    assert aead.single_use_guard_size() == 4

    for _ in range(200):
        with pytest.raises(SingleUseGuardExhausted):
            aead_encrypt(os.urandom(32), b"x", b"ad")

    # Never grew, never forgot.
    assert aead.single_use_guard_size() == 4
    with pytest.raises(NonceReuseError) as excinfo:
        aead_encrypt(victim, b"second", b"ad")
    assert not isinstance(excinfo.value, SingleUseGuardExhausted), (
        "reuse of a recorded key must be reported as reuse, not as exhaustion"
    )


def test_exhaustion_is_a_nonce_reuse_error_and_value_error():
    assert issubclass(SingleUseGuardExhausted, NonceReuseError)
    assert issubclass(SingleUseGuardExhausted, ValueError)


def test_counter_key_is_immune_to_guard_exhaustion(_small_guard):
    """The structural control needs no memory, so it keeps working when the
    best-effort guard has given up."""
    _small_guard(1)
    aead_encrypt(os.urandom(32), b"x", b"ad")  # guard now full
    with pytest.raises(SingleUseGuardExhausted):
        aead_encrypt(os.urandom(32), b"y", b"ad")

    k = CounterAeadKey(os.urandom(32))
    for i in range(50):
        ctr, blob = k.seal(f"m{i}".encode(), b"ad")
        assert k.open(ctr, blob, b"ad") == f"m{i}".encode()
    assert k.next_counter == 50


def test_guard_capacity_accessors_and_validation(_small_guard):
    _small_guard(7)
    assert aead.single_use_guard_capacity() == 7
    assert aead.single_use_guard_size() == 0
    with pytest.raises(ValueError):
        aead.set_single_use_guard_capacity(0)
    with pytest.raises(TypeError):
        aead.set_single_use_guard_capacity("8")  # type: ignore[arg-type]


def test_shrinking_capacity_does_not_discard_records(_small_guard):
    """Resizing bounds memory, never knowledge."""
    _small_guard(8)
    keys = [os.urandom(32) for _ in range(5)]
    for k in keys:
        aead_encrypt(k, b"x", b"ad")

    aead.set_single_use_guard_capacity(2)  # below the current population
    assert aead.single_use_guard_size() == 5
    for k in keys:
        with pytest.raises(NonceReuseError):
            aead_encrypt(k, b"again", b"ad")
    # No room for anything new — fail closed.
    with pytest.raises(SingleUseGuardExhausted):
        aead_encrypt(os.urandom(32), b"x", b"ad")


def test_default_guard_capacity_is_documented_and_sane():
    assert aead.DEFAULT_KEY_GUARD_CAPACITY >= 1 << 16
