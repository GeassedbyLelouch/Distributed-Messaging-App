"""
PQXDH initial key agreement (Signal PQXDH spec).

Construction
-----------
Each identity owns an Ed25519 *signing* key and an X25519 *DH* key. (Signal uses
one Montgomery key for both via XEdDSA; to avoid hand-rolling XEdDSA we use a
dedicated Ed25519 key for signatures and bind the X25519 identity key to it with
a signature. This is a standard, clearly-documented deviation.)

A published :class:`PreKeyBundle` contains, all signed by the identity:
  * ``ik_sign_pub`` / ``ik_dh_pub`` — identity signing + DH public keys
  * ``spk_pub`` (+ ``spk_sig``)     — signed X25519 prekey
  * ``pqspk_pub`` (+ ``pqspk_sig``) — signed ML-KEM-1024 (last-resort) prekey
  * optional ``opk_pub`` (one-time X25519 prekey)

The initiator derives::

    DH1 = DH(IK_A_dh, SPK_B)        SS  = ML-KEM.Encaps(PQSPK_B) -> ct
    DH2 = DH(EK_A,    IK_B_dh)
    DH3 = DH(EK_A,    SPK_B)
    DH4 = DH(EK_A,    OPK_B)        # omitted if no one-time prekey
    SK  = HKDF(F || DH1 || DH2 || DH3 || DH4 || SS)

where ``F = 0xFF * 32`` (X25519 domain-separation prefix). The responder
recomputes the same ``SK`` from its private prekeys and the initiator's
:class:`InitialMessage`. ``SK`` is the 32-byte value used to initialise the Braid
authenticator on both sides.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from kyber_py.ml_kem import ML_KEM_1024

from ml_kem_braid.core.kdf import hkdf

# The post-quantum KEM used by PQXDH prekeys (monolithic encaps/decaps; the Braid
# *incremental* split is a separate concern handled in core.ml_kem).
PQXDH_KEM = ML_KEM_1024

PQXDH_INFO = b"MLKEMBraid_PQXDH_CURVE25519_SHA-256_ML-KEM-1024"
_F_PREFIX = b"\xff" * 32  # X25519 KDF domain separator (X3DH/PQXDH convention)
_HKDF_SALT = b"\x00" * 32


def _x25519_pub_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def _ed25519_pub_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


# ---------------------------------------------------------------------------
# Key material
# ---------------------------------------------------------------------------


@dataclass
class IdentityKeyPair:
    """Long-term identity: an Ed25519 signing key and an X25519 DH key."""

    sign_priv: Ed25519PrivateKey
    dh_priv: X25519PrivateKey

    @property
    def sign_pub(self) -> bytes:
        return _ed25519_pub_bytes(self.sign_priv.public_key())

    @property
    def dh_pub(self) -> bytes:
        return _x25519_pub_bytes(self.dh_priv.public_key())

    def sign(self, data: bytes) -> bytes:
        return self.sign_priv.sign(data)


@dataclass
class PreKeyBundle:
    """Public prekey bundle published to the server and fetched by initiators."""

    ik_sign_pub: bytes
    ik_dh_pub: bytes
    ik_dh_sig: bytes  # Ed25519 sig over ik_dh_pub (binds DH key to identity)
    spk_id: int
    spk_pub: bytes
    spk_sig: bytes
    pqspk_id: int
    pqspk_pub: bytes
    pqspk_sig: bytes
    opk_id: Optional[int] = None
    opk_pub: Optional[bytes] = None

    def verify(self) -> None:
        """Verify every signature in the bundle; raise on any failure."""
        ik = Ed25519PublicKey.from_public_bytes(self.ik_sign_pub)
        try:
            ik.verify(self.ik_dh_sig, self.ik_dh_pub)
            ik.verify(self.spk_sig, self.spk_pub)
            ik.verify(self.pqspk_sig, self.pqspk_pub)
        except InvalidSignature as exc:  # pragma: no cover - exercised in tests
            raise InvalidSignature("PQXDH prekey bundle signature invalid") from exc


@dataclass
class PreKeySecrets:
    """Private counterparts the responder keeps to complete the handshake."""

    spk_priv: Dict[int, X25519PrivateKey]
    pqspk_priv: Dict[int, bytes]  # id -> ML-KEM-1024 decapsulation key
    opk_priv: Dict[int, X25519PrivateKey]


@dataclass
class InitialMessage:
    """Initiator-to-responder PQXDH handshake message (public)."""

    ik_sign_pub: bytes
    ik_dh_pub: bytes
    ik_dh_sig: bytes  # Ed25519(ik_sign) over ik_dh_pub — binds the initiator's
    #                   X25519 DH key to its signing identity (responder verifies)
    ek_pub: bytes  # ephemeral X25519 public key
    spk_id: int
    pqspk_id: int
    kem_ct: bytes  # ML-KEM-1024 ciphertext
    opk_id: Optional[int] = None


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------


def create_identity() -> IdentityKeyPair:
    return IdentityKeyPair(
        sign_priv=Ed25519PrivateKey.generate(),
        dh_priv=X25519PrivateKey.generate(),
    )


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
    spk_sig = identity.sign(spk_pub)

    # Signed ML-KEM-1024 prekey (post-quantum).
    pq_ek, pq_dk = PQXDH_KEM.keygen()
    pqspk_sig = identity.sign(pq_ek)

    # One-time X25519 prekeys.
    opk_priv: Dict[int, X25519PrivateKey] = {}
    for i in range(num_one_time):
        opk_priv[first_opk_id + i] = X25519PrivateKey.generate()

    first_opk_id_val: Optional[int] = first_opk_id if num_one_time else None
    first_opk_pub = (
        _x25519_pub_bytes(opk_priv[first_opk_id].public_key()) if num_one_time else None
    )

    bundle = PreKeyBundle(
        ik_sign_pub=identity.sign_pub,
        ik_dh_pub=identity.dh_pub,
        ik_dh_sig=identity.sign(identity.dh_pub),
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
    dhs: list[bytes], ss: bytes, ik_a_sign: bytes, ik_b_sign: bytes
) -> bytes:
    """
    SK = HKDF(IKM = F || DH1..DHn || SS, info = PQXDH_INFO || IK_A || IK_B).

    Binding both identity *signing* keys into ``info`` ties the derived secret to
    who-talks-to-whom, defeating unknown-key-share / identity-misbinding attacks
    (Signal PQXDH binds identities into the session, here via the KDF info).
    """
    ikm = _F_PREFIX + b"".join(dhs) + ss
    info = PQXDH_INFO + ik_a_sign + ik_b_sign
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
    ik_b_dh = X25519PublicKey.from_public_bytes(bundle.ik_dh_pub)

    dh1 = initiator.dh_priv.exchange(spk_pub)
    dh2 = ek_priv.exchange(ik_b_dh)
    dh3 = ek_priv.exchange(spk_pub)
    dhs = [dh1, dh2, dh3]

    if bundle.opk_pub is not None:
        opk_pub = X25519PublicKey.from_public_bytes(bundle.opk_pub)
        dhs.append(ek_priv.exchange(opk_pub))

    ss, kem_ct = PQXDH_KEM.encaps(bundle.pqspk_pub)
    # A = initiator, B = responder (bundle owner).
    sk = _derive_sk(dhs, ss, initiator.sign_pub, bundle.ik_sign_pub)

    message = InitialMessage(
        ik_sign_pub=initiator.sign_pub,
        ik_dh_pub=initiator.dh_pub,
        ik_dh_sig=initiator.sign(initiator.dh_pub),
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
    Run the responder side. Authenticates the initiator's identity binding,
    recomputes the same ``SK``, and **consumes** the one-time prekey so a replayed
    :class:`InitialMessage` cannot re-derive the secret.
    """
    # Authenticate the initiator: its X25519 DH key must be signed by its Ed25519
    # identity key (the binding the bundle enforces for the responder direction).
    Ed25519PublicKey.from_public_bytes(message.ik_sign_pub).verify(
        message.ik_dh_sig, message.ik_dh_pub
    )

    spk_priv = secrets.spk_priv.get(message.spk_id)
    if spk_priv is None:
        raise KeyError(f"unknown signed prekey id {message.spk_id}")
    pq_dk = secrets.pqspk_priv.get(message.pqspk_id)
    if pq_dk is None:
        raise KeyError(f"unknown PQ prekey id {message.pqspk_id}")

    ik_a_dh = X25519PublicKey.from_public_bytes(message.ik_dh_pub)
    ek_a = X25519PublicKey.from_public_bytes(message.ek_pub)

    dh1 = spk_priv.exchange(ik_a_dh)
    dh2 = responder.dh_priv.exchange(ek_a)
    dh3 = spk_priv.exchange(ek_a)
    dhs = [dh1, dh2, dh3]

    if message.opk_id is not None:
        opk_priv = secrets.opk_priv.get(message.opk_id)
        if opk_priv is None:
            # Already consumed (replay) or never existed.
            raise KeyError(f"one-time prekey {message.opk_id} unavailable (replay?)")
        dhs.append(opk_priv.exchange(ek_a))
        del secrets.opk_priv[message.opk_id]  # one-time: consume on use

    ss = PQXDH_KEM.decaps(pq_dk, message.kem_ct)
    # A = initiator (message sender), B = responder (self).
    return _derive_sk(dhs, ss, message.ik_sign_pub, responder.sign_pub)


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
