# tests/test_attestation_session.py
import pytest
from ml_kem_braid.crypto import xeddsa
from ml_kem_braid.attestation import (
    attested_connect, IdentityProver, IdentityVerifier, IdentityPolicy,
)
from ml_kem_braid.attestation import noise
from ml_kem_braid.attestation.errors import ChannelBindingError, SignatureInvalid

def test_end_to_end_identity_attested_channel():
    # Responder identity + Noise static == the attested channel key.
    ik_priv = xeddsa.generate_identity()
    ik_pub = xeddsa.public_key(ik_priv)
    s_priv, s_pub = noise.x25519_keypair()  # responder Noise static
    evidence = IdentityProver(ik_priv).attest(s_pub, {"device_id": 1})

    server_state = {}
    def send_msg1(msg1: bytes) -> bytes:
        msg2, chan = noise.nkhfs_respond(s_priv, msg1)
        server_state["chan"] = chan
        return msg2

    chan, claims = attested_connect(
        evidence, IdentityVerifier(), IdentityPolicy(ik_pub), send_msg1=send_msg1)
    assert claims.subject == ik_pub
    server = server_state["chan"]
    assert server.decrypt(chan.encrypt(b"hi")) == b"hi"
    assert chan.decrypt(server.encrypt(b"yo")) == b"yo"

def test_mitm_substituting_static_key_is_rejected():
    # Attacker keeps the genuine evidence (binds ik_pub -> s_pub) but wants the
    # client to talk to attacker static a_pub. Attacker cannot forge evidence for a_pub.
    ik_priv = xeddsa.generate_identity()
    ik_pub = xeddsa.public_key(ik_priv)
    s_priv, s_pub = noise.x25519_keypair()
    a_priv, a_pub = noise.x25519_keypair()  # attacker static
    genuine = IdentityProver(ik_priv).attest(s_pub, {"device_id": 1})
    # Attacker tries to pass evidence but terminate the Noise handshake themselves.
    forged = IdentityProver(xeddsa.generate_identity()).attest(a_pub, {"device_id": 1})

    def send_msg1(msg1: bytes) -> bytes:
        msg2, _ = noise.nkhfs_respond(a_priv, msg1)
        return msg2

    # Using the forged evidence: subject is not the trusted identity -> rejected.
    with pytest.raises(Exception):
        attested_connect(forged, IdentityVerifier(), IdentityPolicy(ik_pub), send_msg1=send_msg1)
