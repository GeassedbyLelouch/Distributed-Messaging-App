"""
Component tests: KDF, ratcheted authenticator, message serialisation, transport.

(KEM, full protocol, PQXDH, erasure and server/testnet are covered in the other
test_*.py modules. The previous fake "key agreement" test that only checked key
lengths has been removed — real agreement is asserted in test_braid_protocol.py.)
"""

import os

import pytest

from ml_kem_braid.core.authenticator import Authenticator, AuthenticatorError
from ml_kem_braid.core.kdf import KDF, bytes_to_epoch, epoch_to_bytes
from ml_kem_braid.protocol.messages import (
    Message,
    MessageType,
    msg_ct1,
    msg_header,
    msg_none,
)
from ml_kem_braid.transport.http_client import (
    InMemoryTransport,
    deserialize_from_wire,
    serialize_for_wire,
)


class TestKDF:
    def test_kdf_auth_lengths_and_change(self):
        kdf = KDF()
        root, mac = kdf.kdf_auth(b"\x01" * 32, b"\x02" * 32, 1)
        assert len(root) == 32 and len(mac) == 32 and root != mac

    def test_kdf_ok_deterministic(self):
        kdf = KDF()
        a = kdf.kdf_ok(b"\x03" * 32, 7)
        b = kdf.kdf_ok(b"\x03" * 32, 7)
        assert a == b and len(a) == 32
        assert kdf.kdf_ok(b"\x03" * 32, 8) != a  # epoch-bound

    @pytest.mark.parametrize("epoch", [0, 1, 255, 65535, 2**32 - 1, 2**63 - 1])
    def test_epoch_roundtrip(self, epoch):
        assert bytes_to_epoch(epoch_to_bytes(epoch)) == epoch


class TestAuthenticator:
    def test_matched_init_verifies(self):
        key = os.urandom(32)
        a, b = Authenticator(), Authenticator()
        a.init(1, key)
        b.init(1, key)
        header = os.urandom(64)
        b.verify_header(1, header, a.mac_header(1, header))

    def test_bad_mac_rejected(self):
        a = Authenticator()
        a.init(1, os.urandom(32))
        with pytest.raises(AuthenticatorError):
            a.verify_header(1, os.urandom(64), os.urandom(32))

    def test_ratchet_changes_mac_key(self):
        a = Authenticator()
        a.init(1, os.urandom(32))
        mac1 = a.mac_header(1, b"x" * 64)
        a.update(2, os.urandom(32))
        assert a.mac_header(2, b"x" * 64) != mac1


class TestMessages:
    def test_roundtrip_all_types(self):
        chunk = os.urandom(34)
        for msg in [
            msg_none(1),
            msg_header(1, chunk),
            msg_ct1(2, chunk),
        ]:
            assert Message.from_bytes(msg.to_bytes()) == msg

    def test_payload_required(self):
        with pytest.raises(ValueError):
            Message(epoch=1, type=MessageType.HDR, data=None)


class TestTransport:
    def test_in_memory(self):
        t = InMemoryTransport()
        m = msg_header(1, os.urandom(34))
        t.alice_send(m)
        assert t.bob_receive().epoch == m.epoch

    def test_wire(self):
        m = msg_ct1(42, os.urandom(34))
        assert deserialize_from_wire(serialize_for_wire(m)) == m
