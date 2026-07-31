"""L2 at the protocol layer: ``ek_vector`` is authenticated only by ``hek``.

The reassembled ``ek_vector`` carries no MAC of its own — its sole integrity
check is ``H(ek_vector || ek_seed) == hek``, where ``hek`` arrived inside the
MAC-authenticated 64-byte header. That check is therefore an *authenticated
equality* and must be constant-time (``hmac.compare_digest``), like every other
tag comparison in the codebase.

The frame MAC (audit M1) already stops an outsider from rewriting EK chunks, so
these tests model the in-session attacker: the tampered frame is re-sealed with
a valid frame MAC, forcing the EK integrity check to be the line of defence.
"""

import inspect
import os

import pytest

from ml_kem_braid.encoding.erasure import Chunk, chunk_tag
from ml_kem_braid.protocol import states as states_mod
from ml_kem_braid.protocol.braid import MLKEMBraid, Role
from ml_kem_braid.protocol.messages import Message, MessageType
from ml_kem_braid.protocol.states import STREAM_EK, chunk_integrity_key


def _drive_until_ek(alice: MLKEMBraid, bob: MLKEMBraid, max_rounds: int = 200):
    """Pump the exchange until Alice emits an EK-bearing frame Bob will consume.

    Returns the (unsent) tampered-candidate message; everything before it has
    already been delivered honestly.
    """
    for _ in range(max_rounds):
        msg_a, _, _ = alice.send()
        if msg_a.type in (MessageType.EK, MessageType.EK_CT1_ACK):
            return msg_a
        bob.receive(msg_a)
        msg_b, _, _ = bob.send()
        alice.receive(msg_b)
    pytest.fail("no EK frame produced")


def test_tampered_ek_vector_is_rejected():
    """A forged ek_vector must not be folded into encaps2."""
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)

    ek_msg = _drive_until_ek(alice, bob)

    # Flip a byte of the share's DATA so only the reconstructed ek_vector
    # changes, then restore BOTH lower-layer authenticators the in-session
    # attacker can compute — the per-share erasure tag (audit H3, now wired into
    # states.py) and the frame MAC (audit M1) — so the EK integrity check is
    # what has to catch it.
    original = Chunk.from_bytes(ek_msg.data)
    data = original.data[:-1] + bytes([original.data[-1] ^ 0x01])
    retagged = Chunk(
        index=original.index,
        data=data,
        tag=chunk_tag(
            chunk_integrity_key(alice.auth, ek_msg.epoch, STREAM_EK),
            original.index,
            data,
            chunk_size=len(original.data),
            message_size=alice.kem.params.ek_vector_size,
        ),
    )
    forged = alice._seal_frame(
        Message(epoch=ek_msg.epoch, type=ek_msg.type, data=retagged.to_bytes())
    )

    # Feed EK chunks until the decoder completes; the tampered one must be
    # caught, never silently accepted.
    with pytest.raises(ValueError, match="EK integrity check failed"):
        bob.receive(forged)
        for _ in range(64):
            nxt, _, _ = alice.send()
            if nxt.type in (MessageType.EK, MessageType.EK_CT1_ACK):
                bob.receive(nxt)


def test_honest_ek_vector_is_accepted():
    """Control: the same pump with no tampering converges."""
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)
    from ml_kem_braid.protocol.braid import run_exchange

    agreed = run_exchange(alice, bob, target_epochs=2)
    assert len(agreed) >= 2
    for _, a, b in agreed:
        assert a == b


def test_ek_integrity_check_is_constant_time():
    """Every hek comparison in the state machine uses hmac.compare_digest."""
    source = inspect.getsource(states_mod)
    assert "hmac.compare_digest" in source
    # No variable-time comparison of the header hash may remain.
    assert "!= self.hek" not in source
    assert "== self.hek" not in source
