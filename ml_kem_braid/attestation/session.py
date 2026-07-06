# ml_kem_braid/attestation/session.py
"""Client entry point: verify attestation, then run NKhfs to the attested static key."""
from __future__ import annotations

import json
import struct
from typing import Callable

from ml_kem_braid.attestation.base import AttestationVerifier
from ml_kem_braid.attestation.claims import Claims
from ml_kem_braid.attestation.errors import ClaimsMismatch
from ml_kem_braid.attestation.noise import SecureChannel, nkhfs_initiate, nkhfs_respond

_HDR = struct.Struct(">I")


def _peek_channel_key(evidence: bytes) -> bytes:
    """Extract claims.channel_key from evidence WITHOUT trusting it; the value is
    authenticated by the subsequent verifier.verify() (which re-checks the same
    canonical claims and the channel binding)."""
    if len(evidence) < _HDR.size:
        raise ClaimsMismatch("evidence too short")
    (clen,) = _HDR.unpack(evidence[: _HDR.size])
    if clen == 0 or _HDR.size + clen > len(evidence):
        raise ClaimsMismatch("evidence framing invalid")
    canonical = evidence[_HDR.size: _HDR.size + clen]
    try:
        return bytes.fromhex(json.loads(canonical.decode("utf-8"))["channel_key"])
    except (ValueError, KeyError, TypeError) as exc:
        raise ClaimsMismatch("cannot read channel key from evidence") from exc


def attested_connect(
    evidence: bytes,
    verifier: AttestationVerifier,
    policy,
    *,
    send_msg1: Callable[[bytes], bytes],
) -> tuple[SecureChannel, Claims]:
    """Verify `evidence` under `policy`, then open a Noise NKhfs channel to the
    attested static key. `send_msg1` delivers Noise msg1 to the responder over the
    (already pinned-TLS) transport and returns msg2. Returns (channel, claims)."""
    channel_key = _peek_channel_key(evidence)
    claims = verifier.verify(evidence, channel_key=channel_key, policy=policy)
    msg1, pending = nkhfs_initiate(claims.channel_key)
    msg2 = send_msg1(msg1)
    channel = pending.finalize(msg2)
    return channel, claims


def responder_handshake(static_priv: bytes, msg1: bytes) -> tuple[bytes, SecureChannel]:
    """Server-side convenience: thin re-export of nkhfs_respond for test symmetry."""
    return nkhfs_respond(static_priv, msg1)
