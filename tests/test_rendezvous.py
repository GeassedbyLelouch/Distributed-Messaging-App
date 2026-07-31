import pytest

from ml_kem_braid.decentralized.rendezvous import (
    RendezvousRelay,
    rendezvous_join_authenticator,
    rendezvous_receive_authenticator,
    rendezvous_send_authenticator,
)

JOIN_KEY = b"j" * 32
OTHER_JOIN_KEY = b"k" * 32


def _relay(*rendezvous_ids: str) -> RendezvousRelay:
    relay = RendezvousRelay()
    for rendezvous_id in rendezvous_ids or ("rv-1",):
        relay.create_rendezvous(rendezvous_id, JOIN_KEY)
    return relay


def _join(relay: RendezvousRelay, rendezvous_id: str, stream_id: str) -> None:
    relay.open_stream(
        rendezvous_id,
        stream_id,
        rendezvous_join_authenticator(JOIN_KEY, rendezvous_id, stream_id),
    )


def _send(
    relay: RendezvousRelay,
    rendezvous_id: str,
    stream_id: str,
    payload,
    key: bytes = JOIN_KEY,
) -> None:
    relay.send(
        rendezvous_id,
        stream_id,
        payload,
        rendezvous_send_authenticator(key, rendezvous_id, stream_id),
    )


def _receive(
    relay: RendezvousRelay,
    rendezvous_id: str,
    stream_id: str,
    key: bytes = JOIN_KEY,
) -> list[bytes]:
    return relay.receive(
        rendezvous_id,
        stream_id,
        rendezvous_receive_authenticator(key, rendezvous_id, stream_id),
    )


def test_rendezvous_joins_two_anonymous_streams_without_peer_addresses():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    _send(relay, "rv-1", "stream-a", b"ciphertext")
    assert _receive(relay, "rv-1", "stream-b") == [b"ciphertext"]
    assert relay.peer_addresses("rv-1") == []


def test_open_stream_is_idempotent_for_same_rendezvous():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")

    _send(relay, "rv-1", "stream-a", b"payload")

    assert _receive(relay, "rv-1", "stream-b") == [b"payload"]


def test_stream_ids_are_scoped_per_rendezvous():
    """Audit M10: a stream id in one rendezvous cannot lock out another."""

    relay = _relay("rv-1", "rv-2")
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")

    # Same stream id under a different rendezvous is a different channel.
    _join(relay, "rv-2", "stream-a")
    _join(relay, "rv-2", "stream-c")

    _send(relay, "rv-1", "stream-b", b"still-rv-1")
    _send(relay, "rv-2", "stream-a", b"rv-2-traffic")

    assert _receive(relay, "rv-1", "stream-a") == [b"still-rv-1"]
    assert _receive(relay, "rv-2", "stream-c") == [b"rv-2-traffic"]


def test_third_stream_is_rejected_without_corrupting_existing_streams():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")

    with pytest.raises(ValueError, match="rendezvous supports exactly two streams"):
        _join(relay, "rv-1", "stream-c")

    _send(relay, "rv-1", "stream-a", b"payload")
    assert _receive(relay, "rv-1", "stream-b") == [b"payload"]
    with pytest.raises(KeyError, match="unknown stream"):
        _send(relay, "rv-1", "stream-c", b"payload")
    with pytest.raises(KeyError, match="unknown stream"):
        _receive(relay, "rv-1", "stream-c")


def test_send_before_second_stream_queues_nothing_and_sender_gets_no_echo():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")

    _send(relay, "rv-1", "stream-a", b"early")
    assert _receive(relay, "rv-1", "stream-a") == []

    _join(relay, "rv-1", "stream-b")
    assert _receive(relay, "rv-1", "stream-b") == []


def test_sender_gets_no_echo_after_both_peers_joined():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")

    _send(relay, "rv-1", "stream-a", b"for-peer")

    assert _receive(relay, "rv-1", "stream-a") == []
    assert _receive(relay, "rv-1", "stream-b") == [b"for-peer"]


def test_receive_drains_inbox():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    _send(relay, "rv-1", "stream-a", b"one")
    _send(relay, "rv-1", "stream-a", b"two")

    assert _receive(relay, "rv-1", "stream-b") == [b"one", b"two"]
    assert _receive(relay, "rv-1", "stream-b") == []


def test_unknown_stream_and_rendezvous_errors_are_deterministic():
    relay = _relay()

    with pytest.raises(KeyError, match="unknown stream"):
        _send(relay, "rv-1", "missing", b"payload")

    with pytest.raises(KeyError, match="unknown stream"):
        _receive(relay, "rv-1", "missing")

    with pytest.raises(KeyError, match="unknown rendezvous"):
        relay.peer_addresses("missing")

    with pytest.raises(KeyError, match="unknown rendezvous"):
        _send(relay, "rv-missing", "stream-a", b"payload")

    with pytest.raises(KeyError, match="unknown rendezvous"):
        _receive(relay, "rv-missing", "stream-a")


def test_send_copies_bytearray_payloads():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    payload = bytearray(b"original")

    _send(relay, "rv-1", "stream-a", payload)
    payload[:] = b"mutated!"

    assert _receive(relay, "rv-1", "stream-b") == [b"original"]


def test_send_copies_memoryview_payloads():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    payload = bytearray(b"original")
    view = memoryview(payload)

    _send(relay, "rv-1", "stream-a", view)
    payload[:] = b"mutated!"

    assert _receive(relay, "rv-1", "stream-b") == [b"original"]


def test_send_rejects_invalid_payloads():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")

    with pytest.raises(TypeError, match="payload must be bytes"):
        _send(relay, "rv-1", "stream-a", "payload")

    assert _receive(relay, "rv-1", "stream-b") == []


# --- Audit M10: authenticated join -------------------------------------------


def test_join_without_authenticator_is_rejected():
    """Knowing the rendezvous_id alone must not buy a slot."""

    relay = _relay()

    with pytest.raises(PermissionError, match="authenticator"):
        relay.open_stream("rv-1", "squatted", b"")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.open_stream("rv-1", "squatted", b"\x00" * 32)


def test_join_with_wrong_key_is_rejected_and_slot_stays_free():
    relay = _relay()
    forged = rendezvous_join_authenticator(OTHER_JOIN_KEY, "rv-1", "stream-a")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.open_stream("rv-1", "stream-a", forged)

    # Both slots are still available to the legitimate peers.
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    _send(relay, "rv-1", "stream-a", b"ok")
    assert _receive(relay, "rv-1", "stream-b") == [b"ok"]


def test_authenticator_is_bound_to_the_stream_id():
    relay = _relay()
    authenticator = rendezvous_join_authenticator(JOIN_KEY, "rv-1", "stream-a")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.open_stream("rv-1", "stream-b", authenticator)


def test_authenticator_is_bound_to_the_rendezvous_id():
    relay = _relay("rv-1", "rv-2")
    authenticator = rendezvous_join_authenticator(JOIN_KEY, "rv-1", "stream-a")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.open_stream("rv-2", "stream-a", authenticator)


def test_join_to_unknown_rendezvous_is_rejected():
    relay = _relay()

    with pytest.raises(KeyError, match="unknown rendezvous"):
        relay.open_stream(
            "rv-unknown",
            "stream-a",
            rendezvous_join_authenticator(JOIN_KEY, "rv-unknown", "stream-a"),
        )


def test_create_rendezvous_rejects_weak_or_duplicate_registration():
    relay = RendezvousRelay()

    with pytest.raises(ValueError, match="join_key"):
        relay.create_rendezvous("rv-1", b"short")

    relay.create_rendezvous("rv-1", JOIN_KEY)
    with pytest.raises(ValueError, match="already exists"):
        relay.create_rendezvous("rv-1", JOIN_KEY)


# --- Verifier D13: send/receive must be authenticated too ---------------------


def test_receive_without_the_token_cannot_drain_the_victims_inbox():
    """Knowing the ids must not let an attacker steal queued ciphertexts."""

    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    _send(relay, "rv-1", "stream-a", b"secret-ciphertext")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.receive("rv-1", "stream-b", b"")
    with pytest.raises(PermissionError, match="authenticator"):
        relay.receive(
            "rv-1",
            "stream-b",
            rendezvous_receive_authenticator(OTHER_JOIN_KEY, "rv-1", "stream-b"),
        )

    # The rejected drain must not have consumed anything.
    assert _receive(relay, "rv-1", "stream-b") == [b"secret-ciphertext"]


def test_send_without_the_token_cannot_inject_into_a_stream():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.send("rv-1", "stream-a", b"injected", b"")
    with pytest.raises(PermissionError, match="authenticator"):
        relay.send(
            "rv-1",
            "stream-a",
            b"injected",
            rendezvous_send_authenticator(OTHER_JOIN_KEY, "rv-1", "stream-a"),
        )

    assert _receive(relay, "rv-1", "stream-b") == []


def test_join_authenticator_cannot_be_replayed_as_send_or_receive():
    """Actions are domain-separated: one captured MAC is not a master key."""

    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    join_mac = rendezvous_join_authenticator(JOIN_KEY, "rv-1", "stream-b")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.receive("rv-1", "stream-b", join_mac)
    with pytest.raises(PermissionError, match="authenticator"):
        relay.send("rv-1", "stream-b", b"payload", join_mac)


def test_send_authenticator_cannot_be_replayed_as_receive():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    _send(relay, "rv-1", "stream-a", b"secret")
    send_mac = rendezvous_send_authenticator(JOIN_KEY, "rv-1", "stream-b")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.receive("rv-1", "stream-b", send_mac)

    assert _receive(relay, "rv-1", "stream-b") == [b"secret"]


def test_send_and_receive_authenticators_are_bound_to_the_stream():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    _send(relay, "rv-1", "stream-a", b"for-b")

    # stream-a's own receive MAC does not open stream-b's inbox.
    with pytest.raises(PermissionError, match="authenticator"):
        relay.receive(
            "rv-1",
            "stream-b",
            rendezvous_receive_authenticator(JOIN_KEY, "rv-1", "stream-a"),
        )
    assert _receive(relay, "rv-1", "stream-b") == [b"for-b"]


def test_send_and_receive_authenticators_are_bound_to_the_rendezvous():
    relay = _relay("rv-1", "rv-2")
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")
    _join(relay, "rv-2", "stream-a")
    _join(relay, "rv-2", "stream-b")
    _send(relay, "rv-1", "stream-a", b"rv-1-only")

    with pytest.raises(PermissionError, match="authenticator"):
        relay.receive(
            "rv-1",
            "stream-b",
            rendezvous_receive_authenticator(JOIN_KEY, "rv-2", "stream-b"),
        )
    assert _receive(relay, "rv-1", "stream-b") == [b"rv-1-only"]


def test_send_and_receive_reject_non_bytes_authenticators():
    relay = _relay()
    _join(relay, "rv-1", "stream-a")
    _join(relay, "rv-1", "stream-b")

    with pytest.raises(TypeError, match="authenticator must be bytes"):
        relay.send("rv-1", "stream-a", b"payload", "not-bytes")
    with pytest.raises(TypeError, match="authenticator must be bytes"):
        relay.receive("rv-1", "stream-b", None)
