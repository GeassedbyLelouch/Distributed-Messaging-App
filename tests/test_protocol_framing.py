"""Wire-framing integrity tests for the ML-KEM Braid SCKA (audit findings M1, L6, L7).

M1: the Braid MAC used to cover only header *contents* and ciphertext bytes, never
    the ``MessageType`` byte, the length prefix, or the ``epoch`` field. Because
    ``Ct2Sampled.receive`` transitions on ``msg.epoch == epoch + 1`` for *any* type,
    a single injected ``Message(epoch=epoch+1, type=NONE)`` desynced the session
    permanently (epoch is bound into every subsequent MAC).
L6: MAC/AD inputs were raw concatenations; every variable-length component is now
    length-prefixed.
L7: ``Message.from_bytes`` silently ignored trailing bytes.
"""

import os

import pytest

from ml_kem_braid.core.authenticator import (
    Authenticator,
    AuthenticatorError,
    FrameRole,
)
from ml_kem_braid.protocol.braid import MLKEMBraid, Role, run_exchange
from ml_kem_braid.protocol.messages import (
    FRAME_MAC_SIZE,
    Message,
    MessageType,
    msg_ct1,
    msg_header,
    msg_none,
)
from ml_kem_braid.protocol.states import StateName


# ---------------------------------------------------------------------------
# L7 — trailing bytes / framing canonicality
# ---------------------------------------------------------------------------


class TestFramingParse:
    def test_trailing_bytes_rejected(self):
        wire = msg_none(1).to_bytes()
        with pytest.raises(ValueError, match="trailing"):
            Message.from_bytes(wire + b"\x00")

    def test_trailing_bytes_rejected_with_payload(self):
        wire = msg_ct1(2, os.urandom(34)).to_bytes()
        with pytest.raises(ValueError, match="trailing"):
            Message.from_bytes(wire + b"AAAA")

    def test_truncated_payload_rejected(self):
        wire = msg_ct1(2, os.urandom(34)).to_bytes()
        with pytest.raises(ValueError):
            Message.from_bytes(wire[:-3])

    def test_length_prefix_always_present(self):
        # Even payload-free types carry an explicit (zero) length prefix so the
        # frame length is unambiguous and MAC-bound.
        assert len(msg_none(1).to_bytes()) == 11

    def test_roundtrip_preserves_frame_mac(self):
        msg = msg_header(7, os.urandom(34))
        msg.frame_mac = os.urandom(FRAME_MAC_SIZE)
        assert Message.from_bytes(msg.to_bytes()) == msg

    def test_bad_frame_mac_length_rejected(self):
        with pytest.raises(ValueError):
            Message(epoch=1, type=MessageType.NONE, frame_mac=b"\x00" * 31)

    def test_mac_input_binds_type_epoch_and_length(self):
        payload = b"\x00\x01" + b"z" * 32
        base = msg_header(1, payload).mac_input()
        assert msg_header(2, payload).mac_input() != base       # epoch bound
        assert msg_ct1(1, payload).mac_input() != base          # type byte bound
        assert msg_header(1, payload + b"\x00").mac_input() != base  # length bound

    def test_mac_input_is_unambiguous_across_split(self):
        """Length prefixes make concatenation injective (L6)."""
        a = msg_header(1, b"AB" + b"x" * 4).mac_input()
        b = msg_header(1, b"AB" + b"x" * 5).mac_input()
        assert a != b and not b.startswith(a)


# ---------------------------------------------------------------------------
# M1 — spoofed frame must not drive a state transition
# ---------------------------------------------------------------------------


def _advance_to_ct2_sampled(secret: bytes):
    """Drive a real pair until Bob is in Ct2Sampled (the vulnerable state)."""
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)
    for _ in range(500):
        msg_a, _, _ = alice.send()
        msg_b, _, _ = bob.send()
        bob.receive(msg_a)
        alice.receive(msg_b)
        if bob.state_name == StateName.CT2_SAMPLED:
            return alice, bob
    raise AssertionError("bob never reached CT2_SAMPLED")


class TestSpoofedFrameDesync:
    def test_spoofed_epoch_bump_is_rejected(self):
        """A forged ``Message(epoch+1, NONE)`` must not advance Bob's epoch/state."""
        secret = os.urandom(32)
        alice, bob = _advance_to_ct2_sampled(secret)

        epoch_before = bob.epoch
        state_before = bob.state_name

        forged = msg_none(bob.epoch + 1)  # no frame MAC — attacker cannot forge one
        with pytest.raises(AuthenticatorError):
            bob.receive(forged)

        assert bob.epoch == epoch_before, "forged frame advanced the epoch"
        assert bob.state_name == state_before, "forged frame drove a state transition"

    def test_spoofed_frame_with_wrong_key_rejected(self):
        """An attacker holding a *different* session secret cannot forge framing."""
        secret = os.urandom(32)
        alice, bob = _advance_to_ct2_sampled(secret)
        attacker = MLKEMBraid(Role.ALICE, os.urandom(32))

        forged = msg_none(bob.epoch + 1)
        attacker._seal_frame(forged)  # sealed under the WRONG session frame key

        epoch_before = bob.epoch
        with pytest.raises(AuthenticatorError):
            bob.receive(forged)
        assert bob.epoch == epoch_before

    def test_flipped_type_byte_rejected(self):
        """Re-typing an authentic frame invalidates the frame MAC."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        msg, _, _ = alice.send()
        assert msg.type == MessageType.HDR
        tampered = Message(
            epoch=msg.epoch,
            type=MessageType.EK,
            data=msg.data,
            frame_mac=msg.frame_mac,
        )
        with pytest.raises(AuthenticatorError):
            bob.receive(tampered)
        assert bob.state_name == StateName.NO_HEADER_RECEIVED

    def test_flipped_epoch_rejected(self):
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        msg, _, _ = alice.send()
        tampered = Message(
            epoch=msg.epoch + 7,
            type=msg.type,
            data=msg.data,
            frame_mac=msg.frame_mac,
        )
        with pytest.raises(AuthenticatorError):
            bob.receive(tampered)

    def test_unsealed_frame_rejected(self):
        """A frame carrying no MAC at all is refused (no downgrade path)."""
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)

        msg, _, _ = alice.send()
        stripped = Message(epoch=msg.epoch, type=msg.type, data=msg.data)
        with pytest.raises(AuthenticatorError):
            bob.receive(stripped)

    def test_honest_exchange_still_converges(self):
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)
        agreed = run_exchange(alice, bob, target_epochs=3)
        assert len(agreed) >= 3
        for _, a, b in agreed:
            assert a == b

    def test_every_sent_frame_is_sealed(self):
        secret = os.urandom(32)
        alice = MLKEMBraid(Role.ALICE, secret)
        bob = MLKEMBraid(Role.BOB, secret)
        for _ in range(40):
            msg_a, _, _ = alice.send()
            msg_b, _, _ = bob.send()
            assert msg_a.frame_mac is not None and len(msg_a.frame_mac) == FRAME_MAC_SIZE
            assert msg_b.frame_mac is not None
            bob.receive(msg_a)
            alice.receive(msg_b)


# ---------------------------------------------------------------------------
# Authenticator frame key / canonical MAC inputs
# ---------------------------------------------------------------------------


def _frame_pair(key: bytes):
    """An initiator/responder pair sharing one handshake secret."""
    a = Authenticator(role=FrameRole.INITIATOR)
    b = Authenticator(role=FrameRole.RESPONDER)
    a.init(1, key)
    b.init(1, key)
    return a, b


class TestAuthenticatorFraming:
    def test_frame_key_is_shared_and_stable_across_ratchets(self):
        key = os.urandom(32)
        a, b = _frame_pair(key)
        frame = msg_none(3).mac_input()
        mac = a.mac_frame(frame)
        b.verify_frame(frame, mac)

        # The frame key must survive an epoch ratchet: the two peers ratchet at
        # different moments, so a ratcheting frame key would desync them.
        a.update(2, os.urandom(32))
        assert a.mac_frame(frame) == mac
        b.verify_frame(frame, mac)

    def test_frame_mac_rejects_other_session(self):
        a = Authenticator(role=FrameRole.INITIATOR)
        b = Authenticator(role=FrameRole.RESPONDER)
        a.init(1, os.urandom(32))
        b.init(1, os.urandom(32))
        frame = msg_none(3).mac_input()
        with pytest.raises(AuthenticatorError):
            b.verify_frame(frame, a.mac_frame(frame))

    def test_clone_preserves_frame_key(self):
        a = Authenticator(role=FrameRole.INITIATOR)
        a.init(1, os.urandom(32))
        frame = msg_none(3).mac_input()
        assert a.clone().mac_frame(frame) == a.mac_frame(frame)

    # -- D9: directional frame keys / reflection -----------------------------

    def test_own_frame_does_not_verify_against_itself(self):
        """D9: a frame sealed by a party must NOT verify at that same party.

        With one shared frame key this passed, which is exactly the reflection
        primitive: bounce a peer's frame back and it authenticates.
        """
        key = os.urandom(32)
        a, _ = _frame_pair(key)
        frame = msg_none(3).mac_input()
        with pytest.raises(AuthenticatorError):
            a.verify_frame(frame, a.mac_frame(frame))

    def test_directional_keys_are_distinct(self):
        key = os.urandom(32)
        a, b = _frame_pair(key)
        assert a.state.frame_key_send != a.state.frame_key_recv
        # ...and they cross over correctly between the two roles.
        assert a.state.frame_key_send == b.state.frame_key_recv
        assert a.state.frame_key_recv == b.state.frame_key_send

    def test_both_directions_verify_at_the_peer(self):
        key = os.urandom(32)
        a, b = _frame_pair(key)
        frame = msg_none(3).mac_input()
        b.verify_frame(frame, a.mac_frame(frame))
        a.verify_frame(frame, b.mac_frame(frame))

    def test_same_role_on_both_ends_fails_closed(self):
        """Misconfiguration must break honest verification, never open a hole."""
        key = os.urandom(32)
        a = Authenticator(role=FrameRole.INITIATOR)
        b = Authenticator(role=FrameRole.INITIATOR)
        a.init(1, key)
        b.init(1, key)
        frame = msg_none(3).mac_input()
        with pytest.raises(AuthenticatorError):
            b.verify_frame(frame, a.mac_frame(frame))

    def test_mac_inputs_are_length_prefixed(self):
        """L6: header/ciphertext MAC inputs are canonical (no splice ambiguity)."""
        a = Authenticator()
        a.init(1, os.urandom(32))
        # Distinct (label, payload) splits must not collide.
        assert a.mac_header(1, b"x" * 64) != a.mac_ciphertext(1, b"x" * 64)
        assert a.mac_header(1, b"x" * 64) != a.mac_header(2, b"x" * 64)
