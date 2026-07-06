# tests/test_attestation_noise_handshake.py
import pytest
from ml_kem_braid.attestation import noise
from ml_kem_braid.attestation.errors import HandshakeError

def test_handshake_roundtrip_and_bidirectional_traffic():
    s_priv, s_pub = noise.x25519_keypair()
    msg1, pending = noise.nkhfs_initiate(s_pub)
    msg2, server_chan = noise.nkhfs_respond(s_priv, msg1)
    client_chan = pending.finalize(msg2)
    assert client_chan.handshake_hash == server_chan.handshake_hash
    # client -> server
    assert server_chan.decrypt(client_chan.encrypt(b"ping")) == b"ping"
    # server -> client
    assert client_chan.decrypt(server_chan.encrypt(b"pong")) == b"pong"

def test_wrong_static_key_breaks_handshake():
    _, s_pub = noise.x25519_keypair()
    other_priv, _ = noise.x25519_keypair()
    msg1, pending = noise.nkhfs_initiate(s_pub)
    # Standard Noise NK: the responder AEAD-authenticates msg1 under the es DH.
    # A responder holding a DIFFERENT static key than the initiator encrypted to
    # cannot verify msg1's tag, so it rejects immediately (before producing msg2).
    with pytest.raises(HandshakeError):
        noise.nkhfs_respond(other_priv, msg1)

def test_tampered_kem_ciphertext_breaks_handshake():
    s_priv, s_pub = noise.x25519_keypair()
    msg1, pending = noise.nkhfs_initiate(s_pub)
    msg2, _ = noise.nkhfs_respond(s_priv, msg1)
    tampered = bytearray(msg2)
    tampered[40] ^= 0x01  # inside the kem_ct region -> different kem_ss on decaps
    with pytest.raises(HandshakeError):
        pending.finalize(bytes(tampered))

def test_deterministic_with_injected_ephemerals():
    s_priv, s_pub = noise.x25519_keypair()
    ie = noise.x25519_keypair()
    re = noise.x25519_keypair()
    from kyber_py.ml_kem import ML_KEM_1024
    kem = ML_KEM_1024.keygen()
    m1a, pa = noise.nkhfs_initiate(s_pub, _eph=ie, _kem=kem)
    m1b, pb = noise.nkhfs_initiate(s_pub, _eph=ie, _kem=kem)
    assert m1a == m1b  # same injected ephemerals -> identical msg1
