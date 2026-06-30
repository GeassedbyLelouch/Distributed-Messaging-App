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
