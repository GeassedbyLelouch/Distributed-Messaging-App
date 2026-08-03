"""Differential fuzz: Rust mlkb_crypto::xeddsa vs the vendored Signal C.

Sign: same (clamped key, msg, Z) must give identical 64 bytes.
Verify: the ACCEPTED SET must be identical, including the cases the C does NOT
reject (non-canonical s, unreduced u, small-order / torsion A).
"""
import os
import random
import subprocess
import sys

from ml_kem_braid.crypto import backend

import pathlib
XED = str(pathlib.Path(__file__).resolve().parents[2] / "target" / "release" / "xeddsa-crosscheck")

c = backend.load()
rnd = random.Random(20260801)

Q = 2**252 + 27742317777372353535851937790883648493
P = 2**255 - 19


def hx(b):
    return b.hex() if b else "-"


class Rust:
    def __init__(self):
        self.p = subprocess.Popen([XED], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1)

    def sign(self, seed, z, msg):
        self.p.stdin.write(f"S {seed.hex()} {z.hex()} {hx(msg)}\n")
        self.p.stdin.flush()
        tag, sig, pub = self.p.stdout.readline().split()
        assert tag == "S"
        return bytes.fromhex(sig), bytes.fromhex(pub)

    def verify(self, pub, msg, sig):
        self.p.stdin.write(f"V {pub.hex()} {hx(msg)} {sig.hex()}\n")
        self.p.stdin.flush()
        tag, r = self.p.stdout.readline().split()
        assert tag == "V"
        return r == "ACCEPT"


rust = Rust()
sign_fail = ver_fail = 0
n_sign = n_ver = 0
accept_c = 0
signbits = {0: 0, 1: 0}
tally = {}

MSG_LENS = [0, 1, 31, 32, 33, 63, 64, 111, 128, 1568]


def check_verify(pub, msg, sig, label):
    global ver_fail, n_ver, accept_c
    n_ver += 1
    cv = (c.verifySignature(pub, msg, sig) == 0)
    rv = rust.verify(pub, msg, sig)
    tally[label] = tally.get(label, [0, 0])
    tally[label][0] += 1
    if cv:
        accept_c += 1
        tally[label][1] += 1
    if cv != rv:
        ver_fail += 1
        print(f"VERIFY MISMATCH [{label}] C={'ACCEPT' if cv else 'REJECT'} "
              f"rust={'ACCEPT' if rv else 'REJECT'}")
        print("  pub", pub.hex(), "\n  msg", msg.hex(), "\n  sig", sig.hex())


N = int(sys.argv[1]) if len(sys.argv) > 1 else 400
for i in range(N):
    seed = bytes(rnd.getrandbits(8) for _ in range(32))
    z = bytes(rnd.getrandbits(8) for _ in range(64))
    msg = bytes(rnd.getrandbits(8) for _ in range(rnd.choice(MSG_LENS)))

    priv = c.generatePrivateKey(seed)
    cpub = c.generatePublicKey(priv)
    csig = c.calculateSignature(z, priv, msg)

    rsig, rpub = rust.sign(seed, z, msg)
    n_sign += 1
    signbits[csig[63] >> 7] += 1
    if rpub != cpub:
        sign_fail += 1
        print(f"PUBKEY MISMATCH seed={seed.hex()} c={cpub.hex()} rust={rpub.hex()}")
    if rsig != csig:
        sign_fail += 1
        print(f"SIGN MISMATCH seed={seed.hex()} z={z.hex()} msg={msg.hex()}")
        print("  c   ", csig.hex())
        print("  rust", rsig.hex())

    # --- verify: the honest signature ---
    check_verify(cpub, msg, csig, "honest")

    # --- verify: flip the pubkey sign bit carried in sig[63] ---
    m = bytearray(csig)
    m[63] ^= 0x80
    check_verify(cpub, msg, bytes(m), "signbit-flip")

    # --- verify: set the s high bits the C strictly parses ---
    for bit in (5, 6):
        m = bytearray(csig)
        m[63] |= 1 << bit
        check_verify(cpub, msg, bytes(m), f"s-high-bit-{bit}")

    # --- verify: NON-CANONICAL s (s + q), which the C does NOT reject ---
    s = int.from_bytes(csig[32:], "little") & ((1 << 255) - 1)
    s_lo = s & ~(0x80 << 248)          # strip the carried sign bit
    for k in (1, 2):
        s2 = s_lo + k * Q
        if s2 >> 253 == 0 and (s2 >> 248) & 0xE0 == 0:
            b = s2.to_bytes(32, "little")
            b = b[:31] + bytes([b[31] | (csig[63] & 0x80)])
            check_verify(cpub, msg, csig[:32] + b, f"s-plus-{k}q")

    # --- verify: random single-bit flips anywhere ---
    for _ in range(3):
        m = bytearray(csig)
        j = rnd.randrange(64)
        m[j] ^= 1 << rnd.randrange(8)
        check_verify(cpub, msg, bytes(m), "random-flip")

    # --- verify: random / structured public keys against a real signature ---
    for pub2, lab in (
        (bytes(32), "u=0"),
        (b"\xff" * 32, "u=0xff*32"),
        ((P).to_bytes(32, "little"), "u=p"),
        ((P + 1).to_bytes(32, "little"), "u=p+1"),
        ((P - 1).to_bytes(32, "little"), "u=p-1"),
        (bytes([1] + [0] * 31), "u=1"),
        (bytes([rnd.getrandbits(8) for _ in range(32)]), "u=random"),
        (bytes(cpub[:31]) + bytes([cpub[31] ^ 0x80]), "u-high-bit-flip"),
    ):
        check_verify(pub2, msg, csig, f"pub:{lab}")

    # --- verify: forged sigs under structured keys (R = rB, s = r) ---
    if i % 7 == 0:
        r_sc = bytes(rnd.getrandbits(8) for _ in range(32))
        # borrow the C to build R = rB is not exposed; instead reuse csig's R
        forged = csig[:32] + bytes(32)
        check_verify(bytes(32), msg, forged, "forge-u0-s0")
        check_verify(cpub, msg, forged, "forge-real-s0")
        _ = r_sc

print(f"\nsign cases {n_sign}, mismatches {sign_fail}; sign-bit dist {signbits}")
for k in sorted(tally):
    print(f"  {k:24s} n={tally[k][0]:6d} C-accepted={tally[k][1]}")
print(f"verify cases {n_ver}, mismatches {ver_fail}; C accepted {accept_c}")
sys.exit(1 if (sign_fail or ver_fail) else 0)
