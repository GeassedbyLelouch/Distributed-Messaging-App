# tests/test_attestation_noise_state.py
import pytest
from ml_kem_braid.attestation import noise
from ml_kem_braid.attestation.errors import HandshakeError

def test_noise_hkdf_output_count_and_size():
    o = noise.noise_hkdf(b"\x00" * 32, b"ikm", 3)
    assert len(o) == 3 and all(len(x) == 32 for x in o)

def test_cipherstate_roundtrip_and_nonce_advance():
    key = b"\x07" * 32
    cs_a = noise._CipherState(key)
    cs_b = noise._CipherState(key)
    ct1 = cs_a.encrypt_with_ad(b"ad", b"hello")
    ct2 = cs_a.encrypt_with_ad(b"ad", b"hello")
    assert ct1 != ct2  # nonce advanced
    assert cs_b.decrypt_with_ad(b"ad", ct1) == b"hello"
    assert cs_b.decrypt_with_ad(b"ad", ct2) == b"hello"

def test_cipherstate_tamper_fails():
    cs = noise._CipherState(b"\x07" * 32)
    ct = bytearray(cs.encrypt_with_ad(b"", b"data"))
    ct[0] ^= 0x01
    with pytest.raises(HandshakeError):
        noise._CipherState(b"\x07" * 32).decrypt_with_ad(b"", bytes(ct))

def test_symmetricstate_encrypt_and_hash_pairs():
    a = noise._SymmetricState(b"Noise_TEST")
    b = noise._SymmetricState(b"Noise_TEST")
    a.mix_key(b"\x11" * 32)
    b.mix_key(b"\x11" * 32)
    ct = a.encrypt_and_hash(b"payload")
    assert b.decrypt_and_hash(ct) == b"payload"
    assert a.handshake_hash == b.handshake_hash

def test_split_gives_directional_channels():
    a = noise._SymmetricState(b"Noise_TEST"); a.mix_key(b"\x11" * 32)
    b = noise._SymmetricState(b"Noise_TEST"); b.mix_key(b"\x11" * 32)
    a_send, a_recv = a.split()            # initiator role
    b_first, b_second = b.split()          # responder role swaps send/recv
    chan_a = noise.SecureChannel(a_send, a_recv, a.handshake_hash)
    chan_b = noise.SecureChannel(b_second, b_first, b.handshake_hash)
    # initiator's send channel pairs with responder's recv channel
    assert chan_b.recv.decrypt_with_ad(b"", chan_a.send.encrypt_with_ad(b"", b"m")) == b"m"
