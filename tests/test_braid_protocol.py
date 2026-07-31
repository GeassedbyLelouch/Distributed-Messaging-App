"""Full ML-KEM Braid SCKA tests: real, matching keys across epochs and variants."""

import os

import pytest

from ml_kem_braid.core.authenticator import MAC_SIZE, AuthenticatorError
from ml_kem_braid.core.ml_kem import MLKEMVariant
from ml_kem_braid.encoding.erasure import (
    CHUNK_TAG_SIZE,
    Chunk,
    ChunkIntegrityError,
    Decoder,
    Encoder,
    chunk_tag,
)
from ml_kem_braid.protocol import states as states_mod
from ml_kem_braid.protocol.braid import MLKEMBraid, Role, run_exchange
from ml_kem_braid.protocol.messages import Message, MessageType
from ml_kem_braid.protocol.states import (
    STREAM_CT1,
    STREAM_CT2,
    STREAM_EK,
    STREAM_HEADER,
    chunk_integrity_key,
)


def _flip(data: bytes, index: int) -> bytes:
    """Flip one bit of ``data`` at ``index``."""
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def _forge_share(
    braid: MLKEMBraid,
    msg: Message,
    stream: bytes,
    *,
    message_size: int,
    data: bytes,
    index: int = None,
) -> Message:
    """Model an IN-SESSION attacker rewriting one erasure share.

    Such an attacker holds the session key schedule, so it can re-tag the share
    (audit H3) and re-seal the frame (audit M1); the content MACs are then the
    only remaining defence. A mere network attacker cannot do this — which is
    the point of the per-share tag.
    """
    original = Chunk.from_bytes(msg.data)
    key = chunk_integrity_key(braid.auth, msg.epoch, stream)
    idx = original.index if index is None else index
    forged = Chunk(
        index=idx,
        data=data,
        tag=chunk_tag(
            key,
            idx,
            data,
            chunk_size=len(original.data),
            message_size=message_size,
        ),
    )
    return braid._seal_frame(
        Message(epoch=msg.epoch, type=msg.type, data=forged.to_bytes())
    )


def _next_of_type(braid: MLKEMBraid, msg_type: MessageType, limit: int = 64) -> Message:
    for _ in range(limit):
        msg, _, _ = braid.send()
        if msg.type == msg_type:
            return msg
    raise AssertionError(f"no {msg_type.name} frame produced")


def test_initial_states():
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)
    from ml_kem_braid.protocol.states import StateName

    assert alice.state_name == StateName.KEYS_UNSAMPLED
    assert bob.state_name == StateName.NO_HEADER_RECEIVED


@pytest.mark.parametrize("variant", list(MLKEMVariant))
def test_key_agreement_matches(variant):
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret, variant=variant)
    bob = MLKEMBraid(Role.BOB, secret, variant=variant)

    agreed = run_exchange(alice, bob, target_epochs=2)
    assert len(agreed) >= 2
    for epoch, a_key, b_key in agreed:
        assert a_key == b_key, f"epoch {epoch} keys differ"
        assert len(a_key) == 32


def test_distinct_secrets_diverge():
    """Different pre-shared secrets must not agree on keys."""
    alice = MLKEMBraid(Role.ALICE, os.urandom(32))
    bob = MLKEMBraid(Role.BOB, os.urandom(32))
    # Authentication is keyed by the pre-shared secret, so authentication fails
    # (now at the wire-frame MAC, which is the first check on the receive path).
    with pytest.raises(AuthenticatorError):
        run_exchange(alice, bob, target_epochs=1, max_rounds=500)


def test_tampered_header_mac_rejected():
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)

    # Collect Alice's header (HDR) chunks until the decoder has a full header.
    hdr_chunks = []
    while len(hdr_chunks) < 3:
        msg, _, _ = alice.send()
        if msg.type == MessageType.HDR:
            hdr_chunks.append(msg)

    # Corrupt one byte of the share's DATA, then re-tag the share and re-seal the
    # frame with valid authenticators, so this test still exercises the header
    # content MAC. Two lower layers now guard the wire independently — the frame
    # MAC (audit M1) and the per-share erasure tag (audit H3) — so only an
    # attacker holding the session keys can reach the header MAC at all.
    hdr_chunks[1] = _forge_share(
        alice,
        hdr_chunks[1],
        STREAM_HEADER,
        message_size=alice.kem.params.header_size + MAC_SIZE,
        data=_flip(Chunk.from_bytes(hdr_chunks[1].data).data, 3),
    )

    with pytest.raises(AuthenticatorError):
        for m in hdr_chunks:
            bob.receive(m)


def test_keys_change_per_epoch():
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)
    agreed = run_exchange(alice, bob, target_epochs=3)
    keys = [k for _, k, _ in agreed]
    assert len(set(keys)) == len(keys), "epoch keys must be distinct"


# =============================================================================
# D19/D20 — per-share erasure integrity must be live on the REAL states.py path
# =============================================================================
#
# Round 1 added keyed shares to encoding/erasure.py but every production call
# site in protocol/states.py used the untagged path, so the H3 fix was inert.
# These tests pin the wiring: shares on the wire are tagged, corruption of a
# delivered shard is REJECTED rather than silently reconstructed, and a
# duplicate index carrying different data cannot overwrite a stored share.


def test_production_shares_on_the_wire_are_tagged():
    """Every chunk-bearing frame carries index || tag[16] || data."""

    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)

    seen = set()
    for _ in range(200):
        for sender, receiver in ((alice, bob), (bob, alice)):
            msg, _, _ = sender.send()
            if msg.type.has_payload():
                seen.add(msg.type)
                # 2-byte index + 16-byte tag + one full 32-byte chunk.
                assert len(msg.data) == 2 + CHUNK_TAG_SIZE + 32, msg.type
                assert Chunk.from_bytes(msg.data).is_tagged
            receiver.receive(msg)
        if {MessageType.HDR, MessageType.EK, MessageType.CT1, MessageType.CT2} <= seen:
            break
    else:  # pragma: no cover - defensive
        raise AssertionError(f"did not observe all chunk streams, saw {seen}")


def test_states_path_never_builds_an_unauthenticated_coder(monkeypatch):
    """No shipped caller may opt out of per-share integrity.

    This is the regression guard for D19/D20: the round-1 fix was inert because
    every production call site used the unkeyed path.
    """

    built = []

    class SpyEncoder(Encoder):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            built.append(("encoder", self.key))

    class SpyDecoder(Decoder):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            built.append(("decoder", self.key))

    monkeypatch.setattr(states_mod, "Encoder", SpyEncoder)
    monkeypatch.setattr(states_mod, "Decoder", SpyDecoder)

    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)
    agreed = run_exchange(alice, bob, target_epochs=2)
    assert len(agreed) >= 2

    kinds = {kind for kind, _ in built}
    assert kinds == {"encoder", "decoder"}, built
    assert len(built) >= 8, built
    unkeyed = [entry for entry in built if entry[1] is None]
    assert unkeyed == [], f"unauthenticated erasure coders on the production path: {unkeyed}"


@pytest.mark.parametrize("byte_index", [0, 5, 31])
def test_flipped_byte_in_delivered_header_shard_is_rejected(byte_index):
    """H3 in production: a corrupted shard must not reconstruct silently."""

    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)

    hdr = _next_of_type(alice, MessageType.HDR)
    chunk = Chunk.from_bytes(hdr.data)
    corrupted = Chunk(
        index=chunk.index,
        data=_flip(chunk.data, byte_index),
        tag=chunk.tag,
    )
    # Re-seal only the FRAME: this models a relay that can rewrite framing but
    # does not hold the chunk key. Without the per-share tag the corrupted shard
    # would enter the decoder and reconstruct a corrupted header.
    forged = alice._seal_frame(
        Message(epoch=hdr.epoch, type=MessageType.HDR, data=corrupted.to_bytes())
    )

    with pytest.raises(ChunkIntegrityError):
        bob.receive(forged)

    # Fail closed: nothing was stored, so the honest header still reassembles.
    bob.receive(hdr)
    for _ in range(8):
        nxt, _, _ = alice.send()
        if nxt.type == MessageType.HDR:
            bob.receive(nxt)
    from ml_kem_braid.protocol.states import StateName

    assert bob.state_name == StateName.HEADER_RECEIVED


def test_flipped_byte_in_delivered_ct1_shard_is_rejected():
    """The same guarantee on the ciphertext stream, not just the header."""

    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)

    ct1 = None
    for _ in range(64):
        msg_a, _, _ = alice.send()
        bob.receive(msg_a)
        msg_b, _, _ = bob.send()
        if msg_b.type == MessageType.CT1:
            ct1 = msg_b
            break
        alice.receive(msg_b)
    assert ct1 is not None, "no CT1 frame produced"

    chunk = Chunk.from_bytes(ct1.data)
    corrupted = Chunk(index=chunk.index, data=_flip(chunk.data, 7), tag=chunk.tag)
    forged = bob._seal_frame(
        Message(epoch=ct1.epoch, type=MessageType.CT1, data=corrupted.to_bytes())
    )

    with pytest.raises(ChunkIntegrityError):
        alice.receive(forged)


def test_duplicate_index_with_different_data_is_rejected_on_the_states_path():
    """Even a key-holding attacker cannot overwrite an already-stored share."""

    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)

    hdr = _next_of_type(alice, MessageType.HDR)
    bob.receive(hdr)  # honest share for this index is now stored

    original = Chunk.from_bytes(hdr.data)
    forged = _forge_share(
        alice,
        hdr,
        STREAM_HEADER,
        message_size=alice.kem.params.header_size + MAC_SIZE,
        data=_flip(original.data, 0),
    )
    # The forged share carries a VALID tag for its (index, data) pair, so the
    # duplicate-index check is the only thing standing between it and a
    # corrupted header.
    assert Chunk.from_bytes(forged.data).is_tagged
    with pytest.raises(ChunkIntegrityError):
        bob.receive(forged)


def test_share_from_one_stream_cannot_be_spliced_into_another():
    """Chunk keys are scoped per stream, so equal-size objects do not collide."""

    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)

    keys = {
        stream: chunk_integrity_key(alice.auth, 1, stream)
        for stream in (STREAM_HEADER, STREAM_EK, STREAM_CT1, STREAM_CT2)
    }
    assert len(set(keys.values())) == len(keys)
    # ... and scoped per epoch.
    assert chunk_integrity_key(alice.auth, 1, STREAM_HEADER) != chunk_integrity_key(
        alice.auth, 2, STREAM_HEADER
    )
    # Both peers derive the same key from the shared handshake secret.
    bob = MLKEMBraid(Role.BOB, secret)
    assert chunk_integrity_key(bob.auth, 1, STREAM_HEADER) == keys[STREAM_HEADER]
    # A different session does not.
    mallory = MLKEMBraid(Role.BOB, os.urandom(32))
    assert chunk_integrity_key(mallory.auth, 1, STREAM_HEADER) != keys[STREAM_HEADER]


def test_chunk_integrity_key_fails_closed_without_session_keys():
    """No silent unkeyed fallback if the authenticator was never initialised."""

    from ml_kem_braid.core.authenticator import Authenticator

    with pytest.raises(RuntimeError):
        chunk_integrity_key(Authenticator(), 1, STREAM_HEADER)


# ---------------------------------------------------------------------------
# D9 — frame keys are directional: a peer's own frame cannot be reflected at it
# ---------------------------------------------------------------------------


def test_reflected_frame_is_rejected_by_its_own_author():
    """THE D9 ATTACK.

    The frame key used to be a single session-scoped value shared by both peers,
    so a frame Alice sealed verified at Alice too. An on-path attacker could
    simply bounce Alice's own frames back at her and they authenticated, letting
    the framing layer drive her state machine with her own traffic. Directional
    frame keys (initiator->responder / responder->initiator) make that fail.
    """
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)

    msg, _, _ = alice.send()
    assert msg.frame_mac is not None

    epoch_before, state_before = alice.epoch, alice.state_name
    with pytest.raises(AuthenticatorError):
        alice.receive(msg)  # reflection
    assert alice.epoch == epoch_before
    assert alice.state_name == state_before

    # Control: the same frame still verifies at its intended recipient.
    bob.receive(msg)


def test_reflected_frame_rejected_in_both_directions():
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)

    msg_a, _, _ = alice.send()
    msg_b, _, _ = bob.send()

    with pytest.raises(AuthenticatorError):
        alice.receive(msg_a)
    with pytest.raises(AuthenticatorError):
        bob.receive(msg_b)

    # Honest cross-delivery still works.
    bob.receive(msg_a)
    alice.receive(msg_b)


def test_directional_frame_keys_do_not_break_convergence():
    secret = os.urandom(32)
    alice = MLKEMBraid(Role.ALICE, secret)
    bob = MLKEMBraid(Role.BOB, secret)
    agreed = run_exchange(alice, bob, target_epochs=3)
    assert len(agreed) >= 3
    for _, a, b in agreed:
        assert a == b
