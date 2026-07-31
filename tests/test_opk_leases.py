import pytest

from ml_kem_braid.decentralized.opk import OPKLeaseStore


def test_opk_lease_prevents_double_lease():
    store = OPKLeaseStore()
    assert store.add_opk("Alice.42", 1, 10, b"opk-pub") is True

    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)

    assert lease.opk_id == 10
    assert lease.opk_pub == b"opk-pub"
    assert store.lease_opk("Alice.42", 1, now=1001.0, ttl=30.0) is None


def test_opk_consume_prevents_replay():
    store = OPKLeaseStore()
    assert store.add_opk("Alice.42", 1, 10, b"opk-pub") is True
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None

    store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1001.0)

    with pytest.raises(KeyError):
        store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1002.0)


@pytest.mark.parametrize("ttl", [0.0, -1.0])
def test_opk_lease_rejects_invalid_ttl(ttl):
    store = OPKLeaseStore()
    assert store.add_opk("Alice.42", 1, 10, b"opk-pub") is True

    with pytest.raises(ValueError, match="ttl must be positive"):
        store.lease_opk("Alice.42", 1, now=1000.0, ttl=ttl)


def test_opk_consume_rejects_expired_lease():
    store = OPKLeaseStore()
    assert store.add_opk("Alice.42", 1, 10, b"opk-pub") is True
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None

    with pytest.raises(KeyError):
        store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1030.0)


def test_opk_duplicate_add_does_not_reset_consumed_state():
    store = OPKLeaseStore()
    assert store.add_opk("Alice.42", 1, 10, b"opk-pub") is True
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None
    store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1001.0)

    assert store.add_opk("Alice.42", 1, 10, b"replacement-opk-pub") is False
    assert store.lease_opk("Alice.42", 1, now=1002.0, ttl=30.0) is None


def test_opk_duplicate_add_does_not_reset_leased_state():
    store = OPKLeaseStore()
    assert store.add_opk("Alice.42", 1, 10, b"opk-pub") is True
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None

    assert store.add_opk("Alice.42", 1, 10, b"replacement-opk-pub") is False
    assert store.lease_opk("Alice.42", 1, now=1001.0, ttl=30.0) is None
    store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1002.0)


def test_opk_duplicate_add_does_not_reset_expired_state():
    """Burn-once policy: an expired lease is parked, never re-leased."""

    store = OPKLeaseStore()
    assert store.add_opk("Alice.42", 1, 10, b"opk-pub") is True
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None

    assert store.lease_opk("Alice.42", 1, now=1030.0, ttl=30.0) is None
    assert store.add_opk("Alice.42", 1, 10, b"replacement-opk-pub") is False
    assert store.lease_opk("Alice.42", 1, now=1031.0, ttl=30.0) is None


def test_opk_pub_must_be_immutable_bytes():
    store = OPKLeaseStore()

    with pytest.raises(TypeError, match="opk_pub must be bytes"):
        store.add_opk("Alice.42", 1, 10, bytearray(b"opk-pub"))


# --- Audit H2: atomic claim --------------------------------------------------


def test_concurrent_leases_never_hand_out_the_same_opk():
    """TOCTOU regression: scan+mutate must be one atomic compare-and-set.

    Verified against the pre-fix implementation: with a short switch interval
    the unsynchronised check-then-act handed out 101 leases for 64 OPKs.
    """

    import sys
    import threading

    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    store = OPKLeaseStore()
    opk_count = 64
    for opk_id in range(opk_count):
        assert store.add_opk("Alice.42", 1, opk_id, bytes([opk_id])) is True

    leases = []
    lock = threading.Lock()
    start = threading.Barrier(16)

    def worker() -> None:
        start.wait()
        for _ in range(8):
            lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
            if lease is not None:
                with lock:
                    leases.append(lease)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    sys.setswitchinterval(previous_interval)

    leased_ids = [lease.opk_id for lease in leases]
    assert len(leased_ids) == opk_count, "every OPK must be leased exactly once"
    assert len(set(leased_ids)) == len(leased_ids), "an OPK was double-leased"
    assert len({lease.lease_id for lease in leases}) == len(leases)


def test_concurrent_consume_allows_exactly_one_winner():
    import threading

    store = OPKLeaseStore()
    store.add_opk("Alice.42", 1, 10, b"opk-pub")
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None

    successes = []
    lock = threading.Lock()
    start = threading.Barrier(8)

    def worker() -> None:
        start.wait()
        try:
            store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1001.0)
        except KeyError:
            return
        with lock:
            successes.append(True)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(successes) == 1


def test_expired_lease_never_reissues_the_same_opk():
    """Verifier D10: the timeout path must not re-serve a transmitted prekey.

    Reclaiming an expired lease to ``available`` reinstated the exact
    OPK-uniqueness break H2 fixed — the same ``opk_id``/``opk_pub`` was handed
    to a second initiator, so a "one-time" prekey was not one-time and the
    forward-secrecy/KCI argument for it collapsed. Expiry is terminal.
    """

    store = OPKLeaseStore()
    store.add_opk("Alice.42", 1, 10, b"opk-pub")
    first = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert first is not None

    # Let the lease time out, then hammer the store: no later call, at any
    # time, may ever hand out opk_id 10 again.
    for offset in range(0, 10_000, 500):
        assert store.lease_opk("Alice.42", 1, now=1031.0 + offset, ttl=30.0) is None
    assert store.state_of("Alice.42", 1, 10) == "expired"

    # The expired lease is dead for consumption too — no stale-lease replay.
    with pytest.raises(KeyError):
        store.consume_opk("Alice.42", 1, 10, first.lease_id, now=1032.0)
    assert store.available_count("Alice.42", 1) == 0


def test_expired_lease_cannot_be_released_back_into_the_pool():
    """The explicit escape hatch must not resurrect a burned prekey."""

    store = OPKLeaseStore()
    store.add_opk("Alice.42", 1, 10, b"opk-pub")
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None

    with pytest.raises(KeyError):
        store.release_untransmitted_lease(
            "Alice.42", 1, 10, lease.lease_id, now=1031.0
        )
    assert store.lease_opk("Alice.42", 1, now=1032.0, ttl=30.0) is None
    assert store.state_of("Alice.42", 1, 10) == "expired"


def test_untransmitted_lease_can_be_released_before_it_expires():
    """Availability path: a bundle that never left may return to the pool."""

    store = OPKLeaseStore()
    store.add_opk("Alice.42", 1, 10, b"opk-pub")
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None

    store.release_untransmitted_lease("Alice.42", 1, 10, lease.lease_id, now=1005.0)

    assert store.state_of("Alice.42", 1, 10) == "available"
    reissued = store.lease_opk("Alice.42", 1, now=1006.0, ttl=30.0)
    assert reissued is not None and reissued.lease_id != lease.lease_id
    # The stale lease id is worthless after the release.
    with pytest.raises(KeyError):
        store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1007.0)


def test_release_requires_the_secret_lease_id():
    store = OPKLeaseStore()
    store.add_opk("Alice.42", 1, 10, b"opk-pub")
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert lease is not None

    with pytest.raises(KeyError):
        store.release_untransmitted_lease("Alice.42", 1, 10, "guessed", now=1001.0)
    assert store.state_of("Alice.42", 1, 10) == "leased"
    store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1002.0)


def test_available_count_is_the_replenishment_signal():
    store = OPKLeaseStore()
    for opk_id in range(3):
        store.add_opk("Alice.42", 1, opk_id, bytes([opk_id]))

    assert store.available_count("Alice.42", 1) == 3
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    assert store.available_count("Alice.42", 1) == 2
    store.consume_opk("Alice.42", 1, lease.opk_id, lease.lease_id, now=1001.0)
    assert store.available_count("Alice.42", 1) == 2

    # Burned-by-timeout prekeys are not counted as available capacity.
    store.lease_opk("Alice.42", 1, now=1002.0, ttl=30.0)
    assert store.available_count("Alice.42", 1) == 1
    store.lease_opk("Alice.42", 1, now=2000.0, ttl=30.0)
    assert store.available_count("Alice.42", 1) == 0


def test_consumed_opk_is_never_reclaimed():
    store = OPKLeaseStore()
    store.add_opk("Alice.42", 1, 10, b"opk-pub")
    lease = store.lease_opk("Alice.42", 1, now=1000.0, ttl=30.0)
    store.consume_opk("Alice.42", 1, 10, lease.lease_id, now=1001.0)

    assert store.lease_opk("Alice.42", 1, now=9999.0, ttl=30.0) is None
    assert store.state_of("Alice.42", 1, 10) == "consumed"
