"""Decentralized relay, signed-record, and anonymous-transport support."""

from ml_kem_braid.decentralized.descriptors import (
    ContactEventBody,
    RelayDescriptorBody,
    UsernameRecordBody,
)
from ml_kem_braid.decentralized.circuits import (
    CircuitFrame,
    LayerKeys,
    build_three_hop_frame,
    pad_payload,
    peel_hop_layer,
    unpad_payload,
)
from ml_kem_braid.decentralized.opk import OPKLease, OPKLeaseStore
from ml_kem_braid.decentralized.records import SignedRecord, sign_record, verify_record
from ml_kem_braid.decentralized.rendezvous import RendezvousRelay
from ml_kem_braid.decentralized.services import DecentralizedServices, FederatedRelay
from ml_kem_braid.decentralized.vault import InMemoryClientVault

__all__ = [
    "CircuitFrame",
    "ContactEventBody",
    "DecentralizedServices",
    "FederatedRelay",
    "InMemoryClientVault",
    "LayerKeys",
    "OPKLease",
    "OPKLeaseStore",
    "RelayDescriptorBody",
    "RendezvousRelay",
    "SignedRecord",
    "UsernameRecordBody",
    "build_three_hop_frame",
    "pad_payload",
    "peel_hop_layer",
    "sign_record",
    "unpad_payload",
    "verify_record",
]
