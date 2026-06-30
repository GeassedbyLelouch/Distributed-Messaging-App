import pytest
from fastapi.testclient import TestClient

from ml_kem_braid.client.anonymous_transport import AnonymousTransport, _DEV_LAYER_KEYS
from ml_kem_braid.decentralized.circuits import peel_hop_layer, unpad_payload
from ml_kem_braid.server.app import create_app


class RecordingGateway:
    def __init__(self):
        self.frames = []

    def send_frame(self, frame):
        self.frames.append(frame)
        return {"status": "queued"}


class FailingGateway:
    def __init__(self, exc):
        self.exc = exc
        self.frames = []

    def send_frame(self, frame):
        self.frames.append(frame)
        raise self.exc


class FailOnceGateway:
    def __init__(self):
        self.frames = []
        self._failed = False

    def send_frame(self, frame):
        if not self._failed:
            self._failed = True
            raise RuntimeError("gateway unavailable")

        self.frames.append(frame)
        return {"status": "queued"}


def test_anonymous_transport_requires_three_hops():
    gateway = RecordingGateway()

    with pytest.raises(ValueError, match="three hops"):
        AnonymousTransport(gateway, route=["entry", "middle"])


@pytest.mark.parametrize(
    "route",
    [
        ["middle", "entry", "exit"],
        ["entry", "entry", "exit"],
        ["alpha", "middle", "exit"],
    ],
)
def test_anonymous_transport_requires_entry_middle_exit_route(route):
    gateway = RecordingGateway()

    with pytest.raises(ValueError, match="entry, middle, exit|three hops"):
        AnonymousTransport(gateway, route=route)


def test_anonymous_transport_rejects_direct_peer_endpoint():
    gateway = RecordingGateway()
    try:
        AnonymousTransport(
            gateway,
            route=["entry", "middle", "exit"],
            direct_peer_endpoint="192.0.2.10:4444",
        )
    except ValueError as exc:
        assert "direct peer-to-peer is disabled" in str(exc)
    else:
        raise AssertionError("direct peer endpoint accepted")


def test_anonymous_transport_accepts_none_direct_peer_endpoint():
    gateway = RecordingGateway()

    transport = AnonymousTransport(
        gateway,
        route=["entry", "middle", "exit"],
        direct_peer_endpoint=None,
    )

    assert transport.route == ("entry", "middle", "exit")


def test_anonymous_transport_does_not_send_plaintext_payload():
    gateway = RecordingGateway()
    transport = AnonymousTransport(gateway, route=["entry", "middle", "exit"])

    response = transport.send_request(b"GET /v1/mailbox")

    assert response == {"status": "queued"}
    assert gateway.frames
    assert b"GET /v1/mailbox" not in gateway.frames[0].payload


def test_anonymous_transport_preserves_payload_after_all_layers_are_peeled():
    gateway = RecordingGateway()
    transport = AnonymousTransport(gateway, route=["entry", "middle", "exit"])

    transport.send_request(b"abc")

    frame = gateway.frames[0]
    frame = peel_hop_layer(frame, _DEV_LAYER_KEYS[0])
    frame = peel_hop_layer(frame, _DEV_LAYER_KEYS[1])
    frame = peel_hop_layer(frame, _DEV_LAYER_KEYS[2])
    assert len(frame.payload) == 1024
    assert unpad_payload(frame.payload) == b"abc"


def test_anonymous_transport_increments_frame_sequences():
    gateway = RecordingGateway()
    transport = AnonymousTransport(gateway, route=["entry", "middle", "exit"])

    transport.send_request(b"first")
    transport.send_request(b"second")

    assert [frame.sequence for frame in gateway.frames] == [1, 2]


def test_anonymous_transport_does_not_reuse_sequence_after_gateway_failure():
    gateway = FailOnceGateway()
    transport = AnonymousTransport(gateway, route=["entry", "middle", "exit"])

    with pytest.raises(RuntimeError, match="gateway unavailable"):
        transport.send_request(b"first")
    transport.send_request(b"second")

    assert [frame.sequence for frame in gateway.frames] == [2]


def test_anonymous_transport_uses_16_byte_circuit_id():
    gateway = RecordingGateway()
    transport = AnonymousTransport(gateway, route=["entry", "middle", "exit"])

    transport.send_request(b"abc")

    assert len(gateway.frames[0].circuit_id) == 16


def test_anonymous_transport_instances_do_not_share_circuit_id():
    first_gateway = RecordingGateway()
    second_gateway = RecordingGateway()
    first = AnonymousTransport(first_gateway, route=["entry", "middle", "exit"])
    second = AnonymousTransport(second_gateway, route=["entry", "middle", "exit"])

    first.send_request(b"abc")
    second.send_request(b"abc")

    assert first_gateway.frames[0].circuit_id != second_gateway.frames[0].circuit_id


def test_anonymous_transport_propagates_gateway_exception_unchanged():
    exc = RuntimeError("gateway unavailable")
    gateway = FailingGateway(exc)
    transport = AnonymousTransport(gateway, route=["entry", "middle", "exit"])

    with pytest.raises(RuntimeError) as raised:
        transport.send_request(b"abc")

    assert raised.value is exc


def test_anonymous_transport_requires_bytes_payload():
    gateway = RecordingGateway()
    transport = AnonymousTransport(gateway, route=["entry", "middle", "exit"])

    with pytest.raises(TypeError, match="bytes"):
        transport.send_request("GET /v1/mailbox")


def test_circuit_api_accepts_frame_without_username_metadata():
    client = TestClient(create_app(enable_decentralized=True))
    payload = {
        "circuit_id": "31" * 16,
        "frame_type": "data",
        "size_class": 1024,
        "sequence": 1,
        "payload": "aa",
    }
    response = client.post("/v1/circuits/test-circuit/frames", json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": "queued"}


@pytest.mark.parametrize(
    "field",
    ["username", "auth_token", "sender_username", "recipient_username"],
)
def test_circuit_api_rejects_identity_metadata(field):
    client = TestClient(create_app(enable_decentralized=True))
    payload = {
        "circuit_id": "31" * 16,
        "frame_type": "data",
        "size_class": 1024,
        "sequence": 1,
        "payload": "aa",
        field: "alice",
    }

    response = client.post("/v1/circuits/test-circuit/frames", json=payload)

    assert response.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {"payload": {"auth_token": "secret"}},
        {"Auth_Token": "secret"},
    ],
)
def test_circuit_api_rejects_nested_or_cased_identity_metadata(payload):
    client = TestClient(create_app(enable_decentralized=True))

    response = client.post("/v1/circuits/test-circuit/frames", json=payload)

    assert response.status_code == 422


def test_circuit_api_accepts_opaque_frames_with_missing_or_unexpected_fields():
    client = TestClient(create_app(enable_decentralized=True))
    payload = {
        "unexpected": "field",
        "nested": {"values": [1, {"opaque": True}]},
    }

    response = client.post("/v1/circuits/test-circuit/frames", json=payload)
    queued = client.get("/v1/circuits/test-circuit/frames")

    assert response.status_code == 200
    assert response.json() == {"status": "queued"}
    assert queued.json() == {"frames": [payload]}


def test_circuit_api_get_drains_queued_frames():
    client = TestClient(create_app(enable_decentralized=True))
    first = {
        "circuit_id": "31" * 16,
        "frame_type": "data",
        "size_class": 1024,
        "sequence": 1,
        "payload": "aa",
    }
    second = {
        "circuit_id": "31" * 16,
        "frame_type": "data",
        "size_class": 1024,
        "sequence": 2,
        "payload": "bb",
    }

    client.post("/v1/circuits/test-circuit/frames", json=first)
    client.post("/v1/circuits/test-circuit/frames", json=second)

    response = client.get("/v1/circuits/test-circuit/frames")
    drained = client.get("/v1/circuits/test-circuit/frames")

    assert response.status_code == 200
    assert response.json() == {"frames": [first, second]}
    assert drained.status_code == 200
    assert drained.json() == {"frames": []}


def test_circuit_api_missing_circuit_returns_empty_frames():
    client = TestClient(create_app(enable_decentralized=True))

    response = client.get("/v1/circuits/missing-circuit/frames")

    assert response.status_code == 200
    assert response.json() == {"frames": []}


def test_circuit_api_isolates_queued_frames_by_circuit_id():
    client = TestClient(create_app(enable_decentralized=True))
    first = {"payload": {"value": "first"}}
    second = {"payload": {"value": "second"}}

    client.post("/v1/circuits/first-circuit/frames", json=first)
    client.post("/v1/circuits/second-circuit/frames", json=second)

    assert client.get("/v1/circuits/first-circuit/frames").json() == {"frames": [first]}
    assert client.get("/v1/circuits/second-circuit/frames").json() == {"frames": [second]}


def test_circuit_api_preserves_nested_opaque_frame_content():
    client = TestClient(create_app(enable_decentralized=True))
    first = {
        "payload": {
            "layers": [{"ciphertext": "aa"}, {"ciphertext": "bb"}],
            "padding": [0, 1, 2],
        },
    }
    second = {"payload": {"layers": [{"ciphertext": "cc"}]}}

    client.post("/v1/circuits/test-circuit/frames", json=first)
    client.post("/v1/circuits/test-circuit/frames", json=second)

    response = client.get("/v1/circuits/test-circuit/frames")
    frames = response.json()["frames"]
    frames[0]["payload"]["layers"][0]["ciphertext"] = "mutated"

    assert response.status_code == 200
    assert response.json()["frames"] == [first, second]
