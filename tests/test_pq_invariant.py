"""The post-quantum invariant, pinned so no future hardening pass can erode it.

    SK = HKDF(F || DH1..DHn || SS, info = PQXDH_INFO || IK_A || IK_B)

Every one of those inputs must be *load-bearing*: change any DH leg or the
ML-KEM shared secret and ``SK`` must change. In particular there must be no
path — no negotiation, no fallback, no exception handler — that derives an ``SK``
without the KEM contribution, or harvest-now-decrypt-later resistance is gone.
"""

import os

import pytest
from cryptography.exceptions import InvalidSignature

from ml_kem_braid.pqxdh.pqxdh import (
    PQXDH_KEM,
    ReplayCache,
    _derive_sk,
    create_identity,
    create_prekey_bundle,
    initiator_handshake,
    responder_handshake,
)


def _fresh_cache() -> ReplayCache:
    """Scope replay detection to one test (the module default is process-wide)."""
    return ReplayCache()


# ---------------------------------------------------------------------------
# Every KDF input is bound
# ---------------------------------------------------------------------------


def test_kem_shared_secret_is_bound_into_sk():
    """Changing ONLY the ML-KEM shared secret must change SK."""
    dhs = [os.urandom(32) for _ in range(4)]
    ik_a, ik_b = os.urandom(32), os.urandom(32)
    ss = os.urandom(32)

    baseline = _derive_sk(dhs, ss, ik_a, ik_b)
    other = _derive_sk(dhs, os.urandom(32), ik_a, ik_b)
    assert baseline != other

    # A zeroed / omitted KEM secret must not collide with a real one either.
    assert baseline != _derive_sk(dhs, bytes(32), ik_a, ik_b)
    assert baseline != _derive_sk(dhs, b"", ik_a, ik_b)


@pytest.mark.parametrize("leg", range(4))
def test_every_dh_leg_is_bound_into_sk(leg):
    """Changing ONLY DH{leg+1} must change SK — no leg is decorative."""
    dhs = [os.urandom(32) for _ in range(4)]
    ik_a, ik_b = os.urandom(32), os.urandom(32)
    ss = os.urandom(32)

    baseline = _derive_sk(dhs, ss, ik_a, ik_b)
    mutated = list(dhs)
    mutated[leg] = os.urandom(32)
    assert baseline != _derive_sk(mutated, ss, ik_a, ik_b)


def test_dropping_a_dh_leg_changes_sk():
    """The OPK leg cannot be silently dropped and still reach the same SK."""
    dhs = [os.urandom(32) for _ in range(4)]
    ik_a, ik_b = os.urandom(32), os.urandom(32)
    ss = os.urandom(32)
    assert _derive_sk(dhs, ss, ik_a, ik_b) != _derive_sk(dhs[:3], ss, ik_a, ik_b)


def test_identities_are_bound_into_sk():
    """UKS resistance: SK is tied to who-talks-to-whom."""
    dhs = [os.urandom(32) for _ in range(3)]
    ss = os.urandom(32)
    ik_a, ik_b = os.urandom(32), os.urandom(32)
    baseline = _derive_sk(dhs, ss, ik_a, ik_b)
    assert baseline != _derive_sk(dhs, ss, os.urandom(32), ik_b)
    assert baseline != _derive_sk(dhs, ss, ik_a, os.urandom(32))
    # Not symmetric: swapping the roles must not produce the same SK.
    assert baseline != _derive_sk(dhs, ss, ik_b, ik_a)


# ---------------------------------------------------------------------------
# No downgrade path in the real handshake
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("num_one_time", [0, 1])
def test_handshake_always_carries_a_kem_ciphertext(num_one_time):
    """Both the OPK and last-resort paths encapsulate — no PQ-free branch."""
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=num_one_time)

    sk_a, msg = initiator_handshake(alice, bundle)
    assert len(msg.kem_ct) == 1568  # ML-KEM-1024 ciphertext, always present
    assert (msg.opk_id is not None) == bool(num_one_time)

    sk_b = responder_handshake(bob, secrets, msg, replay_cache=_fresh_cache())
    assert sk_a == sk_b


def test_responder_sk_depends_on_the_kem_ciphertext():
    """Swapping the KEM ciphertext must change the responder's SK.

    ML-KEM implicit rejection means decaps still *returns* a value, so the only
    thing proving the KEM output reaches the KDF is that a different ct yields a
    different SK.
    """
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=0)

    _sk_a, msg = initiator_handshake(alice, bundle)
    honest = responder_handshake(bob, secrets, msg, replay_cache=_fresh_cache())

    # A different (well-formed) ciphertext for the same PQ prekey.
    _other_ss, other_ct = PQXDH_KEM.encaps(bundle.pqspk_pub)
    assert other_ct != msg.kem_ct
    msg.kem_ct = other_ct
    forged = responder_handshake(bob, secrets, msg, replay_cache=_fresh_cache())
    assert forged != honest


def test_tampered_pq_prekey_is_rejected_not_downgraded():
    """A stripped/forged PQ prekey must abort, never fall back to DH-only."""
    alice, bob = create_identity(), create_identity()
    bundle, _secrets = create_prekey_bundle(bob, num_one_time=1)

    evil, _ = create_prekey_bundle(create_identity(), num_one_time=0)
    bundle.pqspk_pub = evil.pqspk_pub  # signature no longer matches

    with pytest.raises(InvalidSignature):
        initiator_handshake(alice, bundle)


def test_pq_prekey_is_not_optional_on_the_bundle():
    """There is no ``pqspk=None`` bundle shape to negotiate down to."""
    _bundle, _secrets = create_prekey_bundle(create_identity(), num_one_time=0)
    with pytest.raises(TypeError):
        # Constructing a bundle without the PQ prekey must be impossible.
        from ml_kem_braid.pqxdh.pqxdh import PreKeyBundle

        PreKeyBundle(
            ik_pub=bytes(32),
            spk_id=1,
            spk_pub=bytes(32),
            spk_sig=bytes(64),
        )
