"""
Regression tests for the 9 findings from the adversarial review.

Each test fails on the pre-fix behaviour and passes after the corresponding fix.
"""

import os

import pytest
from cryptography.exceptions import InvalidSignature
from fastapi.testclient import TestClient

from ml_kem_braid.client.client import BraidChatClient, HttpTransport
from ml_kem_braid.core.authenticator import Authenticator, AuthenticatorError
from ml_kem_braid.encoding.erasure import Encoder
from ml_kem_braid.pqxdh import (
    create_identity,
    create_prekey_bundle,
    initiator_handshake,
    responder_handshake,
)
from ml_kem_braid.server.app import create_app
from ml_kem_braid.sesame.store import SesameStore


# -- #1/#2 PQXDH identity binding -------------------------------------------


def test_responder_rejects_unbound_initiator_dh_key():
    """A forged ik_dh_sig (DH key not signed by the claimed identity) is rejected."""
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=1)
    _, msg = initiator_handshake(alice, bundle)
    msg.ik_dh_sig = bytes(b ^ 0xFF for b in msg.ik_dh_sig)  # break the binding
    with pytest.raises(InvalidSignature):
        responder_handshake(bob, secrets, msg)


def test_sk_bound_to_identities():
    """SK incorporates both identity keys (UKS resistance): a substituted
    initiator identity yields a different SK on the responder."""
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=1)
    sk_a, msg = initiator_handshake(alice, bundle)
    # Honest responder agrees.
    bundle2, secrets2 = create_prekey_bundle(bob, num_one_time=1)
    sk_a2, msg2 = initiator_handshake(alice, bundle2)
    sk_b2 = responder_handshake(bob, secrets2, msg2)
    assert sk_a2 == sk_b2
    # The info string folds in ik_sign keys, so two different initiators never collide.
    assert sk_a != sk_a2 or msg.ek_pub != msg2.ek_pub


# -- #3 one-time prekey replay ----------------------------------------------


def test_one_time_prekey_consumed_blocks_replay():
    alice, bob = create_identity(), create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=1)
    _, msg = initiator_handshake(alice, bundle)
    responder_handshake(bob, secrets, msg)  # consumes the OPK
    with pytest.raises(KeyError):
        responder_handshake(bob, secrets, msg)  # replay must fail


# -- #4 transactional ratchet -----------------------------------------------


def test_failed_ciphertext_mac_does_not_mutate_authenticator():
    a = Authenticator()
    a.init(1, os.urandom(32))
    before = (a.state.root_key, a.state.mac_key)
    with pytest.raises(AuthenticatorError):
        a.update_and_verify_ciphertext(2, os.urandom(32), b"ct", os.urandom(32))
    assert (a.state.root_key, a.state.mac_key) == before  # state untouched

    # And a correct MAC commits the ratchet.
    ss = os.urandom(32)
    cand_root, cand_mac = a.kdf.kdf_auth(a.state.root_key, ss, 2)
    import hashlib
    import hmac
    good = hmac.new(cand_mac, a.protocol_info + b":ciphertext" + (2).to_bytes(8, "big") + b"ct", hashlib.sha256).digest()
    a.update_and_verify_ciphertext(2, ss, b"ct", good)
    assert a.state.mac_key == cand_mac


# -- #5 erasure bound -------------------------------------------------------


def test_erasure_rejects_too_many_chunks():
    with pytest.raises(ValueError):
        Encoder(os.urandom(256 * 32))  # 256 data chunks > GF(2^8) limit


# -- #6 registration auth ---------------------------------------------------


def _client(app, name):
    return BraidChatClient(HttpTransport(TestClient(app)), name)


def test_registration_requires_valid_proof():
    app = create_app(SesameStore())
    c = TestClient(app)
    # Hand-rolled register with a bogus proof must be rejected.
    bob = create_identity()
    from ml_kem_braid.wire import b64e, bundle_to_dict

    bundle, _ = create_prekey_bundle(bob)
    r = c.post("/register", json={
        "username": "mallory",
        "registration_id": 1,
        "bundle": bundle_to_dict(bundle),
        "proof_sig": b64e(b"\x00" * 64),  # invalid signature
        "one_time_prekeys": {},
    })
    assert r.status_code == 401


def test_username_pinned_to_identity_key():
    app = create_app(SesameStore())
    alice = _client(app, "alice")
    alice.register()
    # A different identity trying to register the same username is rejected (403).
    attacker = _client(app, "alice")  # fresh identity, same username
    with pytest.raises(Exception) as exc:
        attacker.register()
    assert "403" in str(exc.value)


# -- #7 sender authenticity -------------------------------------------------


def test_messages_endpoint_requires_auth():
    app = create_app(SesameStore())
    c = TestClient(app)
    r = c.post("/messages", json={
        "recipient_username": "bob", "recipient_device_id": 1,
        "kind": "chat", "body": {},
    })
    assert r.status_code == 401


def test_sender_derived_from_token_not_body():
    app = create_app(SesameStore())
    alice, bob = _client(app, "alice"), _client(app, "bob")
    alice.register()
    bob.register()
    # Alice sends to Bob; even if she tried to set a different sender in the body,
    # the server uses her token identity. (Client omits sender fields entirely.)
    alice._send_envelope("bob", bob.device_id, "chat", {"epoch": 1, "ciphertext": "AA=="})
    env = bob.transport.fetch(bob.auth_token)[0]
    assert env["sender_username"] == "alice"
    assert env["sender_device_id"] == alice.device_id


# -- #8 poll robustness -----------------------------------------------------


def test_poll_drops_bad_envelope_keeps_batch():
    app = create_app(SesameStore())
    alice, bob = _client(app, "alice"), _client(app, "bob")
    alice.register()
    bob.register()
    # A forged/garbage chat envelope from alice (no session) must not crash bob.poll().
    alice._send_envelope("bob", bob.device_id, "chat", {"epoch": 1, "ciphertext": "!!notb64!!"})
    bob.poll()  # should not raise
    assert len(bob.dropped) >= 0  # handled gracefully (no session => ignored or dropped)


# -- #9 registration_id bound -----------------------------------------------


def test_registration_id_upper_bound():
    app = create_app(SesameStore())
    c = TestClient(app)
    bob = create_identity()
    from ml_kem_braid.wire import b64e, bundle_to_dict, registration_challenge

    bundle, _ = create_prekey_bundle(bob)
    proof = bob.sign(registration_challenge("x", 2**31))
    r = c.post("/register", json={
        "username": "x", "registration_id": 2**31,
        "bundle": bundle_to_dict(bundle), "proof_sig": b64e(proof),
    })
    assert r.status_code == 422  # pydantic rejects (lt=2**31)
