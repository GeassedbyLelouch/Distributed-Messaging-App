import pytest

from ml_kem_braid.decentralized.rendezvous import RendezvousRelay


def test_rendezvous_joins_two_anonymous_streams_without_peer_addresses():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")
    relay.send("stream-a", b"ciphertext")
    assert relay.receive("stream-b") == [b"ciphertext"]
    assert relay.peer_addresses("rv-1") == []


def test_open_stream_is_idempotent_for_same_rendezvous():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")

    relay.send("stream-a", b"payload")

    assert relay.receive("stream-b") == [b"payload"]


def test_reopening_stream_under_different_rendezvous_is_rejected_without_moving_it():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")

    with pytest.raises(ValueError, match="stream already open"):
        relay.open_stream("rv-2", "stream-a")

    relay.open_stream("rv-2", "stream-c")
    relay.send("stream-b", b"still-rv-1")

    assert relay.receive("stream-a") == [b"still-rv-1"]
    assert relay.receive("stream-c") == []


def test_third_stream_is_rejected_without_corrupting_existing_streams():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")

    with pytest.raises(ValueError, match="rendezvous supports exactly two streams"):
        relay.open_stream("rv-1", "stream-c")

    relay.send("stream-a", b"payload")
    assert relay.receive("stream-b") == [b"payload"]
    with pytest.raises(KeyError, match="unknown stream"):
        relay.send("stream-c", b"payload")
    with pytest.raises(KeyError, match="unknown stream"):
        relay.receive("stream-c")


def test_send_before_second_stream_queues_nothing_and_sender_gets_no_echo():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")

    relay.send("stream-a", b"early")
    assert relay.receive("stream-a") == []

    relay.open_stream("rv-1", "stream-b")
    assert relay.receive("stream-b") == []


def test_sender_gets_no_echo_after_both_peers_joined():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")

    relay.send("stream-a", b"for-peer")

    assert relay.receive("stream-a") == []
    assert relay.receive("stream-b") == [b"for-peer"]


def test_receive_drains_inbox():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")
    relay.send("stream-a", b"one")
    relay.send("stream-a", b"two")

    assert relay.receive("stream-b") == [b"one", b"two"]
    assert relay.receive("stream-b") == []


def test_unknown_stream_and_rendezvous_errors_are_deterministic():
    relay = RendezvousRelay()

    with pytest.raises(KeyError, match="unknown stream"):
        relay.send("missing", b"payload")

    with pytest.raises(KeyError, match="unknown stream"):
        relay.receive("missing")

    with pytest.raises(KeyError, match="unknown rendezvous"):
        relay.peer_addresses("missing")


def test_send_copies_bytearray_payloads():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")
    payload = bytearray(b"original")

    relay.send("stream-a", payload)
    payload[:] = b"mutated!"

    assert relay.receive("stream-b") == [b"original"]


def test_send_copies_memoryview_payloads():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")
    payload = bytearray(b"original")
    view = memoryview(payload)

    relay.send("stream-a", view)
    payload[:] = b"mutated!"

    assert relay.receive("stream-b") == [b"original"]


def test_send_rejects_invalid_payloads():
    relay = RendezvousRelay()
    relay.open_stream("rv-1", "stream-a")
    relay.open_stream("rv-1", "stream-b")

    with pytest.raises(TypeError, match="payload must be bytes"):
        relay.send("stream-a", "payload")

    assert relay.receive("stream-b") == []
