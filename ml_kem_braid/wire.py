"""
JSON wire serialisation shared by the server and client.

All binary fields are base64 (standard, padded). These helpers convert between
the in-memory dataclasses (PQXDH bundles/messages, Braid messages) and
JSON-compatible dicts that travel over HTTP. The server treats message bodies as
opaque dicts; only clients interpret them.
"""

from __future__ import annotations

import base64
from typing import Optional

from ml_kem_braid.pqxdh.pqxdh import InitialMessage, PreKeyBundle
from ml_kem_braid.protocol.messages import Message, MessageType


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def registration_challenge(username: str, registration_id: int) -> bytes:
    """Canonical message a client signs with its identity key to prove ownership
    of the username it registers (verified server-side against the bundle's
    ``ik_sign_pub``)."""
    return f"MLKEMBraid-register:{username}:{registration_id}".encode("utf-8")


# -- PQXDH prekey bundle ----------------------------------------------------


def bundle_to_dict(bundle: PreKeyBundle) -> dict:
    return {
        "ik_sign_pub": b64e(bundle.ik_sign_pub),
        "ik_dh_pub": b64e(bundle.ik_dh_pub),
        "ik_dh_sig": b64e(bundle.ik_dh_sig),
        "spk_id": bundle.spk_id,
        "spk_pub": b64e(bundle.spk_pub),
        "spk_sig": b64e(bundle.spk_sig),
        "pqspk_id": bundle.pqspk_id,
        "pqspk_pub": b64e(bundle.pqspk_pub),
        "pqspk_sig": b64e(bundle.pqspk_sig),
        "opk_id": bundle.opk_id,
        "opk_pub": b64e(bundle.opk_pub) if bundle.opk_pub is not None else None,
    }


def bundle_from_dict(data: dict) -> PreKeyBundle:
    opk_pub = data.get("opk_pub")
    return PreKeyBundle(
        ik_sign_pub=b64d(data["ik_sign_pub"]),
        ik_dh_pub=b64d(data["ik_dh_pub"]),
        ik_dh_sig=b64d(data["ik_dh_sig"]),
        spk_id=int(data["spk_id"]),
        spk_pub=b64d(data["spk_pub"]),
        spk_sig=b64d(data["spk_sig"]),
        pqspk_id=int(data["pqspk_id"]),
        pqspk_pub=b64d(data["pqspk_pub"]),
        pqspk_sig=b64d(data["pqspk_sig"]),
        opk_id=data.get("opk_id"),
        opk_pub=b64d(opk_pub) if opk_pub else None,
    )


# -- PQXDH initial message --------------------------------------------------


def initial_message_to_dict(msg: InitialMessage) -> dict:
    return {
        "ik_sign_pub": b64e(msg.ik_sign_pub),
        "ik_dh_pub": b64e(msg.ik_dh_pub),
        "ik_dh_sig": b64e(msg.ik_dh_sig),
        "ek_pub": b64e(msg.ek_pub),
        "spk_id": msg.spk_id,
        "pqspk_id": msg.pqspk_id,
        "kem_ct": b64e(msg.kem_ct),
        "opk_id": msg.opk_id,
    }


def initial_message_from_dict(data: dict) -> InitialMessage:
    return InitialMessage(
        ik_sign_pub=b64d(data["ik_sign_pub"]),
        ik_dh_pub=b64d(data["ik_dh_pub"]),
        ik_dh_sig=b64d(data["ik_dh_sig"]),
        ek_pub=b64d(data["ek_pub"]),
        spk_id=int(data["spk_id"]),
        pqspk_id=int(data["pqspk_id"]),
        kem_ct=b64d(data["kem_ct"]),
        opk_id=data.get("opk_id"),
    )


# -- Braid protocol message -------------------------------------------------


def braid_message_to_dict(msg: Message) -> dict:
    return {
        "epoch": msg.epoch,
        "type": msg.type.name,
        "data": b64e(msg.data) if msg.data is not None else None,
    }


def braid_message_from_dict(data: dict) -> Message:
    raw: Optional[str] = data.get("data")
    return Message(
        epoch=int(data["epoch"]),
        type=MessageType[data["type"]],
        data=b64d(raw) if raw else None,
    )
