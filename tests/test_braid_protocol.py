"""Full ML-KEM Braid SCKA tests: real, matching keys across epochs and variants."""

import os

import pytest

from ml_kem_braid.core.authenticator import AuthenticatorError
from ml_kem_braid.core.ml_kem import MLKEMVariant
from ml_kem_braid.protocol.braid import MLKEMBraid, Role, run_exchange
from ml_kem_braid.protocol.messages import Message, MessageType


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
    # Authentication is keyed by the pre-shared secret, so the header MAC fails.
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

    # Corrupt one byte of the payload (offset >= 2 so the 2-byte chunk index stays
    # valid and the chunk is still accepted; only the reconstructed header changes).
    bad = bytearray(hdr_chunks[1].data)
    bad[5] ^= 0x01
    hdr_chunks[1] = Message(epoch=hdr_chunks[1].epoch, type=MessageType.HDR, data=bytes(bad))

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
