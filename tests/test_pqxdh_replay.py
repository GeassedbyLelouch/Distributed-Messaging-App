"""PQXDH replay tests (audit finding M2 + post-audit hardening D6).

``responder_handshake`` only consumed state when the bundle advertised a one-time
prekey. On the no-OPK / last-resort path nothing was consumed and ``_derive_sk`` is
deterministic, so a captured :class:`InitialMessage` re-derived the identical SK
forever.

The first fix introduced a *fail-open eviction primitive*: a single process-wide
FIFO of 4096 fingerprints that was written to **before** any validation. ~4096
malformed handshakes evicted the victim's record and the replay worked again.
The tests below pin the corrected behaviour: validate-then-record, per-principal
partitioning, and fail-closed (never evicting) capacity handling.
"""

import os
import threading

import pytest

from ml_kem_braid.pqxdh.pqxdh import (
    MAX_REPLAY_CACHE,
    MAX_REPLAY_PER_INITIATOR,
    InitialMessage,
    ReplayCache,
    ReplayError,
    ReplayGuardFull,
    create_identity,
    create_prekey_bundle,
    initiator_handshake,
    responder_handshake,
)


def test_no_opk_replay_is_rejected():
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=0)
    cache = ReplayCache()

    sk_a, msg = initiator_handshake(alice, bundle)
    assert msg.opk_id is None, "this test must exercise the no-OPK path"
    sk_b = responder_handshake(bob, secrets, msg, replay_cache=cache)
    assert sk_a == sk_b

    with pytest.raises(ReplayError):
        responder_handshake(bob, secrets, msg, replay_cache=cache)


def test_replay_error_is_a_key_error():
    """Callers that already catch KeyError for OPK replay keep working."""
    assert issubclass(ReplayError, KeyError)


def test_opk_path_replay_still_rejected():
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=1)
    cache = ReplayCache()
    _, msg = initiator_handshake(alice, bundle)
    responder_handshake(bob, secrets, msg, replay_cache=cache)
    with pytest.raises(KeyError):
        responder_handshake(bob, secrets, msg, replay_cache=cache)


def test_distinct_handshakes_are_not_false_positives():
    alice, bob = create_identity(), create_identity()
    cache = ReplayCache()
    for _ in range(5):
        bundle, secrets = create_prekey_bundle(bob, num_one_time=0)
        sk_a, msg = initiator_handshake(alice, bundle)
        assert responder_handshake(bob, secrets, msg, replay_cache=cache) == sk_a


def test_replay_cache_is_bounded_and_fails_closed_never_evicting():
    """D6: at capacity the guard refuses NEW entries; it never forgets old ones."""
    p = b"P" * 64
    cache = ReplayCache(max_per_initiator=4)
    for i in range(4):
        cache.check_and_add(p, f"k{i}".encode())
    assert len(cache) == 4

    # Capacity reached: a *new* fingerprint is refused rather than evicting one.
    for i in range(4, 100):
        with pytest.raises(ReplayGuardFull):
            cache.check_and_add(p, f"k{i}".encode())
    assert len(cache) == 4, "guard must not grow past its bound"

    # Every recorded fingerprint — including the OLDEST — is still detected.
    for i in range(4):
        with pytest.raises(ReplayError):
            cache.check_and_add(p, f"k{i}".encode())


def test_guard_full_is_a_replay_error_and_key_error():
    """Existing `except KeyError` / `except ReplayError` callers keep failing closed."""
    assert issubclass(ReplayGuardFull, ReplayError)
    assert issubclass(ReplayGuardFull, KeyError)


def test_guard_is_partitioned_per_principal():
    """One initiator flooding its own partition cannot displace another's record."""
    victim = b"V" * 64
    flooder = b"F" * 64
    cache = ReplayCache(max_per_initiator=4)
    cache.check_and_add(victim, b"victim-handshake")

    for i in range(4):
        cache.check_and_add(flooder, f"f{i}".encode())
    for i in range(4, 200):
        with pytest.raises(ReplayGuardFull):
            cache.check_and_add(flooder, f"f{i}".encode())

    # The victim's record survived the flood, and its partition still has room.
    with pytest.raises(ReplayError):
        cache.check_and_add(victim, b"victim-handshake")
    cache.check_and_add(victim, b"victim-handshake-2")


def test_partition_table_fails_closed_too():
    cache = ReplayCache(max_initiators=3, max_per_initiator=2)
    for i in range(3):
        cache.check_and_add(f"p{i}".encode(), b"fp")
    with pytest.raises(ReplayGuardFull):
        cache.check_and_add(b"p3", b"fp")
    # Known principals keep working and keep detecting their replays.
    with pytest.raises(ReplayError):
        cache.check_and_add(b"p0", b"fp")
    cache.check_and_add(b"p0", b"fp-other")


def test_guard_is_thread_safe():
    """Concurrent check_and_add of one fingerprint admits it exactly once."""
    cache = ReplayCache()
    admitted = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        try:
            cache.check_and_add(b"p" * 64, b"f" * 32)
            admitted.append(1)
        except ReplayError:
            pass

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(admitted) == 1
    assert len(cache) == 1


def test_default_cache_bound_is_sane():
    assert MAX_REPLAY_CACHE >= 1024
    assert MAX_REPLAY_PER_INITIATOR >= 256


# ---------------------------------------------------------------------------
# D6 — the flood attack itself
# ---------------------------------------------------------------------------


def _garbage_message(template: InitialMessage) -> InitialMessage:
    """A structurally invalid handshake: ek_pub is not a valid X25519 point size."""
    return InitialMessage(
        ik_pub=os.urandom(32),
        ek_pub=os.urandom(31),  # rejected by X25519PublicKey.from_public_bytes
        spk_id=template.spk_id,
        pqspk_id=template.pqspk_id,
        kem_ct=template.kem_ct,
        opk_id=None,
    )


def test_invalid_handshake_flood_cannot_evict_a_recorded_replay():
    """THE D6 ATTACK.

    Old behaviour: ``check_and_add`` ran before any validation and evicted
    oldest-first at 4096 entries, so 4096 malformed messages erased the victim's
    fingerprint and the captured handshake replayed successfully.
    """
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=0)
    cache = ReplayCache(max_initiators=8, max_per_initiator=8)

    sk_a, msg = initiator_handshake(alice, bundle)
    assert msg.opk_id is None
    assert responder_handshake(bob, secrets, msg, replay_cache=cache) == sk_a
    entries_after_honest = len(cache)

    # Flood: far more malformed handshakes than either capacity bound.
    flood = 5000
    for _ in range(flood):
        with pytest.raises(Exception):
            responder_handshake(
                bob, secrets, _garbage_message(msg), replay_cache=cache
            )

    # Invalid handshakes cost the attacker work and the guard NOTHING.
    assert len(cache) == entries_after_honest
    assert cache.partitions == 1

    # The original replay is STILL rejected.
    with pytest.raises(ReplayError):
        responder_handshake(bob, secrets, msg, replay_cache=cache)


def test_flood_of_unusable_prekey_ids_does_not_consume_guard_state():
    """Handshakes naming unknown prekey ids never reach the guard either."""
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=0)
    cache = ReplayCache(max_initiators=4, max_per_initiator=4)
    sk_a, msg = initiator_handshake(alice, bundle)
    responder_handshake(bob, secrets, msg, replay_cache=cache)

    for i in range(2000):
        bad = InitialMessage(
            ik_pub=msg.ik_pub,
            ek_pub=msg.ek_pub,
            spk_id=999_000 + i,  # unknown signed prekey
            pqspk_id=msg.pqspk_id,
            kem_ct=msg.kem_ct,
            opk_id=None,
        )
        with pytest.raises(KeyError):
            responder_handshake(bob, secrets, bad, replay_cache=cache)

    assert len(cache) == 1
    with pytest.raises(ReplayError):
        responder_handshake(bob, secrets, msg, replay_cache=cache)


def test_fingerprint_is_bound_to_the_responder():
    """The shared process-wide guard must not false-positive across responders."""
    alice = create_identity()
    bob, carol = create_identity(), create_identity()
    cache = ReplayCache()

    b_bundle, b_secrets = create_prekey_bundle(bob, num_one_time=0)
    sk_a, msg = initiator_handshake(alice, b_bundle)
    responder_handshake(bob, b_secrets, msg, replay_cache=cache)

    # Carol has her own prekeys; a *different* handshake to Carol must be fine
    # even though the same guard object is used.
    c_bundle, c_secrets = create_prekey_bundle(carol, num_one_time=0)
    sk_c, msg_c = initiator_handshake(alice, c_bundle)
    assert responder_handshake(carol, c_secrets, msg_c, replay_cache=cache) == sk_c
    assert cache.partitions == 2


def test_module_default_cache_rejects_replay():
    """Without an explicit cache the module-level default still blocks replays."""
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=0)
    sk_a, msg = initiator_handshake(alice, bundle)
    assert responder_handshake(bob, secrets, msg) == sk_a
    with pytest.raises(ReplayError):
        responder_handshake(bob, secrets, msg)


def test_replay_rejected_before_any_state_is_consumed():
    """The replay check runs before the OPK is touched, so a replay cannot burn
    a fresh one-time prekey."""
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=2, first_opk_id=1)
    cache = ReplayCache()
    _, msg = initiator_handshake(alice, bundle)
    responder_handshake(bob, secrets, msg, replay_cache=cache)
    remaining = set(secrets.opk_priv)
    with pytest.raises(KeyError):
        responder_handshake(bob, secrets, msg, replay_cache=cache)
    assert set(secrets.opk_priv) == remaining
