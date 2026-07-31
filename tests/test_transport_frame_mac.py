"""Cross-subsystem: the JSON transport hop must preserve the wire-frame MAC.

Audit M1 made ``Message.frame_mac`` mandatory on the Braid receive path. Any
transport that re-encodes a :class:`Message` into JSON therefore has to carry the
tag, or every honest frame is rejected as a forgery (availability break) — and,
worse, a transport that silently dropped it would be indistinguishable from a
stripping attacker.

``ml_kem_braid.wire`` already carries it; ``ml_kem_braid.transport.http_client``
has its own duplicate serializer that did not, so these tests pin both.
"""

import os

import pytest

from ml_kem_braid.core.authenticator import AuthenticatorError
from ml_kem_braid.protocol.braid import MLKEMBraid, Role
from ml_kem_braid.protocol.messages import FRAME_MAC_SIZE, Message, MessageType
from ml_kem_braid.transport.http_client import BraidHttpClient, BraidServer
from ml_kem_braid.wire import braid_message_from_dict, braid_message_to_dict


def _client() -> BraidHttpClient:
    return BraidHttpClient("https://peer.example.com/braid")


def _sealed_message() -> tuple[Message, MLKEMBraid, MLKEMBraid]:
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)
    msg, _, _ = alice.send()
    assert msg.frame_mac is not None
    return msg, alice, bob


class TestHttpClientSerialization:
    def test_json_roundtrip_preserves_frame_mac(self):
        msg, _, _ = _sealed_message()
        client = _client()
        recovered = client._deserialize_message(client._serialize_message(msg))
        assert recovered.frame_mac == msg.frame_mac
        assert recovered.to_bytes() == msg.to_bytes()

    def test_message_survives_http_json_hop_and_verifies(self):
        """End-to-end: a frame that made the JSON round trip is still accepted."""
        msg, _alice, bob = _sealed_message()
        client = _client()
        wire = client._serialize_message(msg)
        # The tag must actually be on the wire, not merely reconstructible.
        assert wire.get("frame_mac")
        bob.receive(client._deserialize_message(wire))

    def test_stripped_frame_mac_is_rejected(self):
        """Negative: dropping the tag in transit must not be accepted."""
        msg, _alice, bob = _sealed_message()
        client = _client()
        wire = client._serialize_message(msg)
        wire.pop("frame_mac", None)
        with pytest.raises(AuthenticatorError):
            bob.receive(client._deserialize_message(wire))

    def test_forged_frame_mac_is_rejected(self):
        msg, _alice, bob = _sealed_message()
        client = _client()
        wire = client._serialize_message(msg)
        import base64

        wire["frame_mac"] = base64.b64encode(bytes(FRAME_MAC_SIZE)).decode("ascii")
        with pytest.raises(AuthenticatorError):
            bob.receive(client._deserialize_message(wire))

    def test_unsealed_message_serializes_without_tag(self):
        """An unsealed frame stays unsealed (no fabricated tag)."""
        client = _client()
        msg = Message(epoch=3, type=MessageType.NONE)
        wire = client._serialize_message(msg)
        assert wire.get("frame_mac") is None
        assert client._deserialize_message(wire).frame_mac is None


class TestBraidServerSerialization:
    @pytest.mark.asyncio
    async def test_handle_request_preserves_frame_mac_both_ways(self):
        msg, _alice, bob = _sealed_message()
        bob_msg, _, _ = bob.send()

        server = BraidServer()
        server.on_message = lambda _received: bob_msg

        response = await server.handle_request(braid_message_to_dict(msg))

        # Inbound: the server must reconstruct the sealed frame verbatim.
        received = server.get_messages()
        assert len(received) == 1
        assert received[0].to_bytes() == msg.to_bytes()

        # Outbound: the response must carry its own tag.
        assert response.get("frame_mac")
        assert braid_message_from_dict(response).frame_mac == bob_msg.frame_mac


class TestWireHelpersAgree:
    def test_wire_and_http_serializers_are_interchangeable(self):
        """The two duplicate codecs must not diverge again."""
        msg, _, _ = _sealed_message()
        client = _client()
        assert client._deserialize_message(braid_message_to_dict(msg)).to_bytes() == (
            msg.to_bytes()
        )
        assert braid_message_from_dict(client._serialize_message(msg)).to_bytes() == (
            msg.to_bytes()
        )
