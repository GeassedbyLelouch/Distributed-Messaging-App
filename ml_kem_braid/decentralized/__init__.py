"""Decentralized relay, signed-record, and anonymous-transport support."""

from ml_kem_braid.decentralized.descriptors import (
    ContactEventBody,
    RelayDescriptorBody,
    UsernameRecordBody,
)
from ml_kem_braid.decentralized.circuits import (
    CircuitFrame,
    CircuitGuardCapacityError,
    CircuitSequenceGuard,
    LayerKeys,
    build_three_hop_frame,
    open_three_hop_frame,
    pad_payload,
    peel_hop_layer,
    reset_default_sequence_guard,
    unpad_payload,
)
from ml_kem_braid.decentralized.opk import OPKLease, OPKLeaseStore
from ml_kem_braid.decentralized.records import SignedRecord, sign_record, verify_record
from ml_kem_braid.decentralized.rendezvous import (
    RendezvousRelay,
    rendezvous_action_authenticator,
    rendezvous_join_authenticator,
    rendezvous_receive_authenticator,
    rendezvous_send_authenticator,
)
from ml_kem_braid.decentralized.services import (
    DecentralizedServices,
    FederatedRelay,
    sign_envelope,
    username_binding,
    username_hash,
)
from ml_kem_braid.decentralized.vault import InMemoryClientVault

__all__ = [
    "CircuitFrame",
    "CircuitGuardCapacityError",
    "CircuitSequenceGuard",
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
    "open_three_hop_frame",
    "pad_payload",
    "peel_hop_layer",
    "rendezvous_action_authenticator",
    "rendezvous_join_authenticator",
    "rendezvous_receive_authenticator",
    "rendezvous_send_authenticator",
    "reset_default_sequence_guard",
    "sign_envelope",
    "sign_record",
    "username_binding",
    "username_hash",
    "unpad_payload",
    "verify_record",
]
