"""
PQXDH initial key agreement (Signal PQXDH spec).

Construction
-----------
The identity key is a single Curve25519 key used for both DH and XEdDSA signing
(Signal's construction). Per the PQXDH spec, reuse of IK for DH and signing is
intentionally not separately modeled.

A published :class:`PreKeyBundle` contains, all signed by the identity:
  * ``ik_pub``                          — identity public key (Montgomery u-coord)
  * ``spk_pub`` (+ ``spk_sig``)         — signed X25519 prekey
  * ``pqspk_pub`` (+ ``pqspk_sig``)     — signed ML-KEM-1024 (last-resort) prekey
  * optional ``opk_pub`` (one-time X25519 prekey)

The initiator derives::

    DH1 = DH(IK_A, SPK_B)        SS  = ML-KEM.Encaps(PQSPK_B) -> ct
    DH2 = DH(EK_A, IK_B)
    DH3 = DH(EK_A, SPK_B)
    DH4 = DH(EK_A, OPK_B)        # omitted if no one-time prekey
    SK  = HKDF(F || DH1 || DH2 || DH3 || DH4 || SS)

where ``F = 0xFF * 32`` (X25519 domain-separation prefix). The responder
recomputes the same ``SK`` from its private prekeys and the initiator's
:class:`InitialMessage`. ``SK`` is the 32-byte value used to initialise the Braid
authenticator on both sides.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from kyber_py.ml_kem import ML_KEM_1024

from ml_kem_braid.core.kdf import hkdf
from ml_kem_braid.crypto import xeddsa

# The post-quantum KEM used by PQXDH prekeys (monolithic encaps/decaps; the Braid
# *incremental* split is a separate concern handled in core.ml_kem).
PQXDH_KEM = ML_KEM_1024

PQXDH_INFO = b"MLKEMBraid_PQXDH_CURVE25519_SHA-256_ML-KEM-1024"
_F_PREFIX = b"\xff" * 32  # X25519 KDF domain separator (X3DH/PQXDH convention)
_HKDF_SALT = b"\x00" * 32

# XEdDSA domain-separation contexts for the identity key's prekey signatures
# (see ml_kem_braid.crypto.xeddsa.sign_ctx).
_SPK_CONTEXT = b"pqxdh/signed-prekey"
_PQSPK_CONTEXT = b"pqxdh/pq-signed-prekey"


def _x25519_pub_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


@dataclass
class IdentityKeyPair:
    """Long-term identity: a single Curve25519 key used for BOTH X25519 DH and
    XEdDSA signing (Signal's actual construction)."""

    priv: bytes  # 32-byte clamped Curve25519 private key

    @property
    def public(self) -> bytes:
        return xeddsa.public_key(self.priv)

    def sign_registration_challenge(self, challenge: bytes) -> bytes:
        """Raw (unscoped) XEdDSA signature — for the registration ownership proof
        ONLY. The registration challenge carries its own in-band domain tag
        (``MLKEMBraid-register:``). For every other identity-key signature use
        ``xeddsa.sign_ctx`` so the signature is domain-separated by role."""
        return xeddsa.sign(self.priv, challenge)

    def dh(self, peer_pub: bytes) -> bytes:
        return xeddsa.dh(self.priv, peer_pub)


@dataclass
class PreKeyBundle:
    """Public prekey bundle published to the server and fetched by initiators."""

    ik_pub: bytes            # single Curve25519 identity key (u-coordinate)
    spk_id: int
    spk_pub: bytes
    spk_sig: bytes           # XEdDSA(ik) over spk_pub
    pqspk_id: int
    pqspk_pub: bytes
    pqspk_sig: bytes         # XEdDSA(ik) over the ML-KEM encapsulation key
    opk_id: Optional[int] = None
    opk_pub: Optional[bytes] = None

    def verify(self) -> None:
        """Verify every signature in the bundle; raise on any failure."""
        if not (xeddsa.verify_ctx(self.ik_pub, _SPK_CONTEXT, self.spk_pub, self.spk_sig)
                and xeddsa.verify_ctx(
                    self.ik_pub, _PQSPK_CONTEXT, self.pqspk_pub, self.pqspk_sig)):
            raise InvalidSignature("PQXDH prekey bundle signature invalid")


@dataclass
class PreKeySecrets:
    """Private counterparts the responder keeps to complete the handshake."""

    spk_priv: Dict[int, X25519PrivateKey]
    pqspk_priv: Dict[int, bytes]  # id -> ML-KEM-1024 decapsulation key
    opk_priv: Dict[int, X25519PrivateKey]


@dataclass
class InitialMessage:
    """Initiator-to-responder PQXDH handshake message (public)."""

    ik_pub: bytes            # initiator's single Curve25519 identity key
    ek_pub: bytes            # ephemeral X25519 public key
    spk_id: int
    pqspk_id: int
    kem_ct: bytes            # ML-KEM-1024 ciphertext
    opk_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def create_identity() -> IdentityKeyPair:
    return IdentityKeyPair(priv=xeddsa.generate_identity())


def create_prekey_bundle(
    identity: IdentityKeyPair,
    spk_id: int = 1,
    pqspk_id: int = 1,
    num_one_time: int = 1,
    first_opk_id: int = 1,
) -> Tuple[PreKeyBundle, PreKeySecrets]:
    """
    Generate a signed prekey, a signed ML-KEM-1024 prekey, and ``num_one_time``
    one-time X25519 prekeys. Returns the public bundle (advertising the first
    one-time prekey, if any) and the private secrets for the responder.
    """
    # Signed X25519 prekey.
    spk_priv = X25519PrivateKey.generate()
    spk_pub = _x25519_pub_bytes(spk_priv.public_key())
    spk_sig = xeddsa.sign_ctx(identity.priv, _SPK_CONTEXT, spk_pub)

    # Signed ML-KEM-1024 prekey (post-quantum).
    pq_ek, pq_dk = PQXDH_KEM.keygen()
    pqspk_sig = xeddsa.sign_ctx(identity.priv, _PQSPK_CONTEXT, pq_ek)

    # One-time X25519 prekeys.
    opk_priv: Dict[int, X25519PrivateKey] = {}
    for i in range(num_one_time):
        opk_priv[first_opk_id + i] = X25519PrivateKey.generate()

    first_opk_id_val: Optional[int] = first_opk_id if num_one_time else None
    first_opk_pub = (
        _x25519_pub_bytes(opk_priv[first_opk_id].public_key()) if num_one_time else None
    )

    bundle = PreKeyBundle(
        ik_pub=identity.public,
        spk_id=spk_id,
        spk_pub=spk_pub,
        spk_sig=spk_sig,
        pqspk_id=pqspk_id,
        pqspk_pub=pq_ek,
        pqspk_sig=pqspk_sig,
        opk_id=first_opk_id_val,
        opk_pub=first_opk_pub,
    )
    secrets = PreKeySecrets(
        spk_priv={spk_id: spk_priv},
        pqspk_priv={pqspk_id: pq_dk},
        opk_priv=opk_priv,
    )
    return bundle, secrets


# ---------------------------------------------------------------------------
# Handshake
# ---------------------------------------------------------------------------


def _derive_sk(
    dhs: list[bytes], ss: bytes, ik_a: bytes, ik_b: bytes
) -> bytes:
    """
    SK = HKDF(IKM = F || DH1..DHn || SS, info = PQXDH_INFO || IK_A || IK_B).

    Binding both identity keys (Montgomery u-coordinates) into ``info`` ties the
    derived secret to who-talks-to-whom, defeating unknown-key-share /
    identity-misbinding attacks (Signal PQXDH binds identities into the session,
    here via the KDF info).
    """
    ikm = _F_PREFIX + b"".join(dhs) + ss
    info = PQXDH_INFO + ik_a + ik_b
    return hkdf(ikm=ikm, salt=_HKDF_SALT, info=info, length=32)


def initiator_handshake(
    initiator: IdentityKeyPair,
    bundle: PreKeyBundle,
) -> Tuple[bytes, InitialMessage]:
    """
    Run the initiator side. Verifies the bundle's signatures, performs the four
    X25519 DHs and the ML-KEM encapsulation, and returns ``(SK, InitialMessage)``.
    """
    bundle.verify()

    ek_priv = X25519PrivateKey.generate()
    spk_pub = X25519PublicKey.from_public_bytes(bundle.spk_pub)

    dh1 = initiator.dh(bundle.spk_pub)              # DH(IK_A, SPK_B)
    dh2 = ek_priv.exchange(X25519PublicKey.from_public_bytes(bundle.ik_pub))  # DH(EK_A, IK_B)
    dh3 = ek_priv.exchange(spk_pub)                 # DH(EK_A, SPK_B)
    dhs = [dh1, dh2, dh3]
    if bundle.opk_pub is not None:
        dhs.append(ek_priv.exchange(X25519PublicKey.from_public_bytes(bundle.opk_pub)))

    ss, kem_ct = PQXDH_KEM.encaps(bundle.pqspk_pub)
    sk = _derive_sk(dhs, ss, initiator.public, bundle.ik_pub)

    message = InitialMessage(
        ik_pub=initiator.public,
        ek_pub=_x25519_pub_bytes(ek_priv.public_key()),
        spk_id=bundle.spk_id,
        pqspk_id=bundle.pqspk_id,
        kem_ct=kem_ct,
        opk_id=bundle.opk_id,
    )
    return sk, message


def responder_handshake(
    responder: IdentityKeyPair,
    secrets: PreKeySecrets,
    message: InitialMessage,
) -> bytes:
    """
    Run the responder side. Recomputes the same ``SK`` and **consumes** the
    one-time prekey so a replayed :class:`InitialMessage` cannot re-derive the
    secret. The initiator is authenticated by the DH legs (DH1/DH2) per PQXDH.
    """
    spk_priv = secrets.spk_priv.get(message.spk_id)
    if spk_priv is None:
        raise KeyError(f"unknown signed prekey id {message.spk_id}")
    pq_dk = secrets.pqspk_priv.get(message.pqspk_id)
    if pq_dk is None:
        raise KeyError(f"unknown PQ prekey id {message.pqspk_id}")

    ik_a_dh = X25519PublicKey.from_public_bytes(message.ik_pub)
    ek_a = X25519PublicKey.from_public_bytes(message.ek_pub)

    dh1 = spk_priv.exchange(ik_a_dh)
    dh2 = responder.dh(message.ek_pub)             # DH(EK_A, IK_B)
    dh3 = spk_priv.exchange(ek_a)
    dhs = [dh1, dh2, dh3]
    if message.opk_id is not None:
        opk_priv = secrets.opk_priv.get(message.opk_id)
        if opk_priv is None:
            raise KeyError(f"one-time prekey {message.opk_id} unavailable (replay?)")
        dhs.append(opk_priv.exchange(ek_a))
        del secrets.opk_priv[message.opk_id]

    ss = PQXDH_KEM.decaps(pq_dk, message.kem_ct)
    return _derive_sk(dhs, ss, message.ik_pub, responder.public)


if __name__ == "__main__":
    alice = create_identity()
    bob = create_identity()
    bundle, secrets = create_prekey_bundle(bob, num_one_time=1)

    sk_a, init_msg = initiator_handshake(alice, bundle)
    sk_b = responder_handshake(bob, secrets, init_msg)
    assert sk_a == sk_b, "PQXDH shared secret mismatch!"
    print(f"PQXDH OK: SK={sk_a.hex()[:32]}...  (ct={len(init_msg.kem_ct)}B)")

    # No-OPK path must also agree.
    bundle2, secrets2 = create_prekey_bundle(bob, num_one_time=0)
    sk_a2, m2 = initiator_handshake(alice, bundle2)
    sk_b2 = responder_handshake(bob, secrets2, m2)
    assert sk_a2 == sk_b2 and m2.opk_id is None
    print("PQXDH no-OPK path OK")
