"""PQXDH handshake tests: matching SK, signature verification, AEAD, wire round-trip."""

import pytest
from cryptography.exceptions import InvalidSignature

from ml_kem_braid.core.aead import aead_decrypt, aead_encrypt
from ml_kem_braid.pqxdh import (
    create_identity,
    create_prekey_bundle,
    initiator_handshake,
    responder_handshake,
)
from ml_kem_braid.wire import (
    bundle_from_dict,
    bundle_to_dict,
    initial_message_from_dict,
    initial_message_to_dict,
)


def test_handshake_agrees_with_opk():
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=1)
    sk_a, msg = initiator_handshake(alice, bundle)
    sk_b = responder_handshake(bob, secrets, msg)
    assert sk_a == sk_b
    assert len(sk_a) == 32
    assert msg.opk_id is not None


def test_handshake_agrees_without_opk():
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=0)
    sk_a, msg = initiator_handshake(alice, bundle)
    sk_b = responder_handshake(bob, secrets, msg)
    assert sk_a == sk_b and msg.opk_id is None


def test_distinct_initiators_get_distinct_sk():
    bob = create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=2)
    sk1, _ = initiator_handshake(create_identity(), bundle)
    bundle2, _ = create_prekey_bundle(bob, num_one_time=2)
    sk2, _ = initiator_handshake(create_identity(), bundle2)
    assert sk1 != sk2


def test_tampered_bundle_signature_rejected():
    bob = create_identity()
    bundle, _ = create_prekey_bundle(bob)
    bundle.spk_pub = bytes(b ^ 0xFF for b in bundle.spk_pub)  # forge prekey
    with pytest.raises(InvalidSignature):
        initiator_handshake(create_identity(), bundle)


def test_wire_roundtrip_bundle_and_message():
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=1)

    bundle2 = bundle_from_dict(bundle_to_dict(bundle))
    sk_a, msg = initiator_handshake(alice, bundle2)
    msg2 = initial_message_from_dict(initial_message_to_dict(msg))
    sk_b = responder_handshake(bob, secrets, msg2)
    assert sk_a == sk_b


def test_sk_seeds_working_aead_channel():
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=1)
    sk_a, msg = initiator_handshake(alice, bundle)
    sk_b = responder_handshake(bob, secrets, msg)
    blob = aead_encrypt(sk_a, b"secret", b"ad")
    assert aead_decrypt(sk_b, blob, b"ad") == b"secret"
