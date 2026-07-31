"""
State Machine for ML-KEM Braid Protocol

Implements the 11-state state machine described in Section 2.5 of the
ML-KEM Braid specification.

State Categories:
1. Transmitting Encapsulation Key (receiving ciphertext):
   - KeysUnsampled: Ready to sample new keypair
   - KeysSampled: Has keypair, sending header chunks
   - HeaderSent: Header complete, sending ek_vector, receiving ct1
   - Ct1Received: Got ct1, still sending ek_vector
   - EkSentCt1Received: Got ct1, sent ek, receiving ct2

2. Transmitting Ciphertext (receiving encapsulation key):
   - NoHeaderReceived: Receiving header chunks
   - HeaderReceived: Got header, ready to sample ct1
   - Ct1Sampled: Sampled ct1, sending it, receiving ek_vector
   - EkReceivedCt1Sampled: Got ek_vector, still sending ct1
   - Ct1Acknowledged: ct1 acknowledged, receiving ek_vector
   - Ct2Sampled: Sending ct2 chunks

Each state implements Send() and Receive() as per SCKA interface.

Reference:
    ML-KEM Braid Section 2.5: State Machine and Transitions
    State diagram: https://signal.org/docs/specifications/mlkembraid/braid-state-machine.png
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Tuple, TYPE_CHECKING

from ml_kem_braid.core.ml_kem import MLKEM, KeyPair, EncapsulationSecret
from ml_kem_braid.core.kdf import KDF, epoch_to_bytes, hkdf
from ml_kem_braid.core.authenticator import Authenticator, MAC_SIZE
from ml_kem_braid.encoding.erasure import Chunk, Encoder, Decoder
from ml_kem_braid.protocol.messages import (
    Message, MessageType,
    msg_none, msg_header, msg_ek, msg_ek_ct1_ack, msg_ct1, msg_ct2
)

if TYPE_CHECKING:
    pass


# Type alias for output key: (epoch, key) or None
OutputKey = Optional[Tuple[int, bytes]]


# =============================================================================
# Per-share erasure integrity (audit H3, wired into production here)
# =============================================================================
#
# Reed-Solomon *erasure* decoding cannot detect a byte-flip in a delivered
# share, so every Braid object (header, ek_vector, ct1, ct2) is chunked with a
# keyed per-share tag (see :mod:`ml_kem_braid.encoding.erasure`). The tag key is
# derived HERE, from the session key schedule, so that every encoder and decoder
# the state machine builds is keyed — there is no unauthenticated production
# path and no caller has to opt in.
#
# Key source. The chunk key is expanded from the authenticator's session frame
# key material (see :func:`_session_integrity_secret`) under its own HKDF label,
# which is:
#
#   * **A fresh key, not a reuse.** The frame key is never used as a chunk tag
#     key; HKDF-Expand under a distinct ``info`` yields an independent key.
#   * **Symmetric.** The frame key material is derived from the handshake secret
#     by both peers in :meth:`Authenticator.init` and deliberately does not
#     ratchet, so encoder and decoder agree. The ratcheting ``root_key``/
#     ``mac_key`` cannot be used: the two peers ratchet at different moments of
#     an epoch (the encapsulator on Send, the decapsulator only once ct2 is
#     reassembled), so a ratcheting chunk key would make honest shares
#     unverifiable.
#   * **Scoped.** ``epoch`` and a stream label are bound into the derivation, so
#     a share of epoch N's 96-byte header cannot be spliced into epoch N+1's
#     header decode, nor a ct1 share into an equally sized ct2 decode. The share
#     tag itself only binds ``(index, data, chunk_size, message_size)``.
#
# Trust level: this is an *integrity* key at the same level as the frame key. It
# stops corruption and share splicing; message-content authenticity and
# post-compromise security still come from the ratcheting content MACs
# (header MAC, ``hek`` binding, ciphertext MAC), which are unchanged.
_CHUNK_KEY_INFO = b":erasure-chunk-integrity:v1"
_HKDF_ZERO_SALT = b"\x00" * 32

# Stream labels: one Braid object per label, so keys never collide across the
# four concurrent chunk streams of an epoch.
STREAM_HEADER = b"header"
STREAM_EK = b"ek"
STREAM_CT1 = b"ct1"
STREAM_CT2 = b"ct2"


def _session_integrity_secret(auth: Authenticator) -> bytes:
    """Return the symmetric, non-ratcheting session secret to expand from.

    ``Authenticator`` exposes its frame-authentication material either as one
    session-scoped ``frame_key`` or as a *directional pair*
    (``frame_key_send``/``frame_key_recv``, whose roles are swapped between the
    two peers). Both peers hold the same *set* of keys, so the pair is folded in
    a canonical (sorted) order: the fold is therefore role-independent and both
    ends derive the same chunk key, which is what encoder/decoder agreement
    requires.

    Raises:
        RuntimeError: if no session key material is available (authenticator not
            initialised, or an unrecognised key layout). Failing closed matters
            here: any silent fallback would produce an unauthenticated chunk
            stream, which is exactly the defect this wiring fixes.
    """
    state = auth.state
    frame_key = getattr(state, "frame_key", None)
    if frame_key is not None:
        return frame_key
    for first, second in (
        ("frame_key_send", "frame_key_recv"),
        ("frame_key_i2r", "frame_key_r2i"),
    ):
        pair = [getattr(state, first, None), getattr(state, second, None)]
        if all(part is not None for part in pair):
            return b"".join(sorted(pair))
    raise RuntimeError(
        "authenticator not initialised - no session key material for "
        "erasure-share integrity"
    )


def chunk_integrity_key(auth: Authenticator, epoch: int, stream: bytes) -> bytes:
    """Derive the per-epoch, per-stream erasure-share integrity key.

    Args:
        auth: initialised authenticator (holds the session frame key material)
        epoch: epoch the chunk stream belongs to
        stream: one of :data:`STREAM_HEADER`, :data:`STREAM_EK`,
            :data:`STREAM_CT1`, :data:`STREAM_CT2`

    Raises:
        RuntimeError: if the authenticator has not been initialised.
    """
    info = (
        auth.protocol_info
        + _CHUNK_KEY_INFO
        + epoch_to_bytes(epoch)
        + struct.pack(">H", len(stream))
        + stream
    )
    return hkdf(
        ikm=_session_integrity_secret(auth),
        salt=_HKDF_ZERO_SALT,
        info=info,
        length=32,
    )


class StateName(Enum):
    """Enumeration of all state machine states."""
    KEYS_UNSAMPLED = auto()
    KEYS_SAMPLED = auto()
    HEADER_SENT = auto()
    CT1_RECEIVED = auto()
    EK_SENT_CT1_RECEIVED = auto()
    NO_HEADER_RECEIVED = auto()
    HEADER_RECEIVED = auto()
    CT1_SAMPLED = auto()
    EK_RECEIVED_CT1_SAMPLED = auto()
    CT1_ACKNOWLEDGED = auto()
    CT2_SAMPLED = auto()


@dataclass
class SendResult:
    """Result of a Send() operation."""
    message: Message
    sending_epoch: int
    output_key: OutputKey
    new_state: "State"


@dataclass
class ReceiveResult:
    """Result of a Receive() operation."""
    receiving_epoch: int
    output_key: OutputKey
    new_state: "State"


class State(ABC):
    """
    Abstract base class for state machine states.
    
    Each concrete state implements the SCKA Send() and Receive()
    interface functions, returning results that include the next
    state to transition to.
    
    Shared State Variables:
        epoch: Current epoch being negotiated
        auth: Ratcheted authenticator
        kem: ML-KEM instance
        kdf: Key derivation function
    """
    
    @property
    @abstractmethod
    def name(self) -> StateName:
        """State identifier."""
        pass
    
    @abstractmethod
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        """
        Generate a message to send.
        
        Args:
            epoch: Current epoch
            auth: Authenticator state
            kem: ML-KEM instance
            kdf: KDF instance
        
        Returns:
            SendResult with message, epochs, and next state
        """
        pass
    
    @abstractmethod
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        """
        Process a received message.
        
        Args:
            msg: Received message
            epoch: Current epoch
            auth: Authenticator state
            kem: ML-KEM instance
            kdf: KDF instance
        
        Returns:
            ReceiveResult with epoch info and next state
        """
        pass


# =============================================================================
# States for Transmitting Encapsulation Key (receiving ciphertext)
# =============================================================================

@dataclass
class KeysUnsampled(State):
    """
    Ready to sample a new KEM keypair on next Send().
    
    Transition (1): -> KeysSampled on Send()
    """
    
    @property
    def name(self) -> StateName:
        return StateName.KEYS_UNSAMPLED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        # Generate keypair and header
        keypair = kem.keygen()
        header = keypair.ek_seed + keypair.hek  # 64 bytes
        mac = auth.mac_header(epoch, header)
        header_with_mac = header + mac
        
        # Start encoding header (keyed: every share carries an integrity tag)
        header_encoder = Encoder(
            header_with_mac,
            key=chunk_integrity_key(auth, epoch, STREAM_HEADER),
        )
        chunk = header_encoder.next_chunk()
        
        # Create message
        msg = msg_header(epoch, chunk.to_bytes())
        
        # Transition (1) -> KeysSampled
        new_state = KeysSampled(
            dk=keypair.dk,
            ek_seed=keypair.ek_seed,
            ek_vector=keypair.ek_vector,
            hek=keypair.hek,
            header_encoder=header_encoder
        )
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=new_state
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        # No action taken
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class KeysSampled(State):
    """
    Has sampled keypair, sending header chunks.
    
    Additional state: dk, ek_seed, ek_vector, hek, header_encoder
    
    Transition (2): -> HeaderSent when receiving Ct1
    """
    dk: bytes
    ek_seed: bytes
    ek_vector: bytes
    hek: bytes
    header_encoder: Encoder
    
    @property
    def name(self) -> StateName:
        return StateName.KEYS_SAMPLED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        # Generate next header chunk
        chunk = self.header_encoder.next_chunk()
        msg = msg_header(epoch, chunk.to_bytes())
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        if msg.epoch == epoch and msg.type == MessageType.CT1:
            # Initialize ct1 decoder and ek encoder (both keyed)
            ct1_decoder = Decoder.new(
                kem.params.ct1_size,
                key=chunk_integrity_key(auth, epoch, STREAM_CT1),
            )
            chunk = Chunk.from_bytes(msg.data)
            ct1_decoder.add_chunk(chunk)

            ek_encoder = Encoder(
                self.ek_vector,
                key=chunk_integrity_key(auth, epoch, STREAM_EK),
            )
            
            # Transition (2) -> HeaderSent
            new_state = HeaderSent(
                dk=self.dk,
                ct1_decoder=ct1_decoder,
                ek_encoder=ek_encoder
            )
            
            return ReceiveResult(
                receiving_epoch=epoch - 1,
                output_key=None,
                new_state=new_state
            )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class HeaderSent(State):
    """
    Header complete, sending ek_vector, receiving ct1 chunks.
    
    Transition (3): -> Ct1Received when ct1 is complete
    """
    dk: bytes
    ct1_decoder: Decoder
    ek_encoder: Encoder
    
    @property
    def name(self) -> StateName:
        return StateName.HEADER_SENT
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        chunk = self.ek_encoder.next_chunk()
        msg = msg_ek(epoch, chunk.to_bytes())
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        if msg.epoch == epoch and msg.type == MessageType.CT1:
            chunk = Chunk.from_bytes(msg.data)
            self.ct1_decoder.add_chunk(chunk)

            if self.ct1_decoder.has_message():
                ct1 = self.ct1_decoder.message()
                
                # Transition (3) -> Ct1Received
                new_state = Ct1Received(
                    dk=self.dk,
                    ct1=ct1,
                    ek_encoder=self.ek_encoder
                )
                
                return ReceiveResult(
                    receiving_epoch=epoch - 1,
                    output_key=None,
                    new_state=new_state
                )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class Ct1Received(State):
    """
    Received ct1, still sending ek_vector chunks.
    
    Transition (4): -> EkSentCt1Received when receiving Ct2
    """
    dk: bytes
    ct1: bytes
    ek_encoder: Encoder
    
    @property
    def name(self) -> StateName:
        return StateName.CT1_RECEIVED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        # Send EK chunk with ct1 acknowledgment
        chunk = self.ek_encoder.next_chunk()
        msg = msg_ek_ct1_ack(epoch, chunk.to_bytes())
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        if msg.epoch == epoch and msg.type == MessageType.CT2:
            # Initialize ct2 decoder (keyed)
            ct2_with_mac_size = kem.params.ct2_size + MAC_SIZE
            ct2_decoder = Decoder.new(
                ct2_with_mac_size,
                key=chunk_integrity_key(auth, epoch, STREAM_CT2),
            )

            chunk = Chunk.from_bytes(msg.data)
            ct2_decoder.add_chunk(chunk)
            
            # Transition (4) -> EkSentCt1Received
            new_state = EkSentCt1Received(
                dk=self.dk,
                ct1=self.ct1,
                ct2_decoder=ct2_decoder
            )
            
            return ReceiveResult(
                receiving_epoch=epoch - 1,
                output_key=None,
                new_state=new_state
            )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class EkSentCt1Received(State):
    """
    Received ct1, sent ek, receiving ct2 chunks.
    
    Transition (5): -> NoHeaderReceived when ct2 complete (emits key)
    """
    dk: bytes
    ct1: bytes
    ct2_decoder: Decoder
    
    @property
    def name(self) -> StateName:
        return StateName.EK_SENT_CT1_RECEIVED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        # No data to send
        msg = msg_none(epoch)
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        if msg.epoch == epoch and msg.type == MessageType.CT2:
            chunk = Chunk.from_bytes(msg.data)
            self.ct2_decoder.add_chunk(chunk)
            
            if self.ct2_decoder.has_message():
                ct2_with_mac = self.ct2_decoder.message()
                ct2 = ct2_with_mac[:kem.params.ct2_size]
                mac = ct2_with_mac[kem.params.ct2_size:]
                
                # Decapsulate shared secret
                ss = kem.decaps(self.dk, self.ct1, ct2)
                ss = kdf.kdf_ok(ss, epoch)
                
                # Ratchet on the decapsulated secret only if the ciphertext MAC
                # verifies under the resulting key (transactional: a forged ct
                # cannot corrupt long-term authenticator state).
                auth.update_and_verify_ciphertext(epoch, ss, self.ct1 + ct2, mac)
                
                # Prepare for next epoch. The decoder is built lazily by
                # NoHeaderReceived.receive: the next header belongs to the NEXT
                # epoch, and its chunk key must be derived for that epoch, which
                # the orchestrator has not advanced to yet at this point.
                # Transition (5) -> NoHeaderReceived
                new_state = NoHeaderReceived(header_decoder=None)
                
                return ReceiveResult(
                    receiving_epoch=epoch - 1,
                    output_key=(epoch, ss),
                    new_state=new_state
                )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


# =============================================================================
# States for Transmitting Ciphertext (receiving encapsulation key)
# =============================================================================

@dataclass
class NoHeaderReceived(State):
    """
    Receiving header chunks.

    Transition (6): -> HeaderReceived when header complete

    ``header_decoder`` starts as ``None`` and is built on the first header chunk
    of the epoch. It cannot be built earlier: the erasure-share integrity key is
    bound to the epoch the header belongs to, and this state is entered *before*
    the orchestrator advances the epoch (and, for Bob's very first state, before
    any authenticator is in scope at all). Building it inside
    :meth:`receive` — which is gated on ``msg.epoch == epoch`` — guarantees the
    decoder is always keyed for the epoch whose header it decodes, so no
    unauthenticated share is ever accepted.
    """
    header_decoder: Optional[Decoder] = None

    @property
    def name(self) -> StateName:
        return StateName.NO_HEADER_RECEIVED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        msg = msg_none(epoch)
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        if msg.epoch == epoch and msg.type == MessageType.HDR:
            if self.header_decoder is None:
                self.header_decoder = Decoder.new(
                    kem.params.header_size + MAC_SIZE,
                    key=chunk_integrity_key(auth, epoch, STREAM_HEADER),
                )

            chunk = Chunk.from_bytes(msg.data)
            self.header_decoder.add_chunk(chunk)

            if self.header_decoder.has_message():
                header_with_mac = self.header_decoder.message()
                header = header_with_mac[:64]
                mac = header_with_mac[64:]
                
                ek_seed = header[:32]
                hek = header[32:]
                
                # Verify header MAC
                auth.verify_header(epoch, header, mac)
                
                # Prepare ek_vector decoder (keyed)
                ek_decoder = Decoder.new(
                    kem.params.ek_vector_size,
                    key=chunk_integrity_key(auth, epoch, STREAM_EK),
                )
                
                # Transition (6) -> HeaderReceived
                new_state = HeaderReceived(
                    ek_seed=ek_seed,
                    hek=hek,
                    ek_decoder=ek_decoder
                )
                
                return ReceiveResult(
                    receiving_epoch=epoch - 1,
                    output_key=None,
                    new_state=new_state
                )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class HeaderReceived(State):
    """
    Header received, ready to sample ct1 on Send().
    
    Transition (7): -> Ct1Sampled on Send() (emits key)
    """
    ek_seed: bytes
    hek: bytes
    ek_decoder: Decoder
    
    @property
    def name(self) -> StateName:
        return StateName.HEADER_RECEIVED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        # Generate shared secret and ct1
        encaps_secret, ct1, ss = kem.encaps1(self.ek_seed, self.hek)
        ss = kdf.kdf_ok(ss, epoch)
        
        # Update authenticator
        auth.update(epoch, ss)
        
        # Encode ct1 for transmission (keyed)
        ct1_encoder = Encoder(
            ct1, key=chunk_integrity_key(auth, epoch, STREAM_CT1)
        )
        chunk = ct1_encoder.next_chunk()
        msg = msg_ct1(epoch, chunk.to_bytes())
        
        # Transition (7) -> Ct1Sampled
        new_state = Ct1Sampled(
            ek_seed=self.ek_seed,
            hek=self.hek,
            encaps_secret=encaps_secret,
            ct1=ct1,
            ct1_encoder=ct1_encoder,
            ek_decoder=self.ek_decoder
        )
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=(epoch, ss),
            new_state=new_state
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        # No action taken
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class Ct1Sampled(State):
    """
    Sampled ct1, sending it, receiving ek_vector.
    
    Transitions:
    - (8): -> Ct1Acknowledged on EkCt1Ack (ek_vector incomplete)
    - (9): -> Ct2Sampled on EkCt1Ack (ek_vector complete)
    - (10): -> EkReceivedCt1Sampled on Ek (ek_vector complete)
    """
    ek_seed: bytes
    hek: bytes
    encaps_secret: EncapsulationSecret
    ct1: bytes
    ct1_encoder: Encoder
    ek_decoder: Decoder
    
    @property
    def name(self) -> StateName:
        return StateName.CT1_SAMPLED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        chunk = self.ct1_encoder.next_chunk()
        msg = msg_ct1(epoch, chunk.to_bytes())
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        if msg.epoch == epoch and msg.type == MessageType.EK:
            chunk = Chunk.from_bytes(msg.data)
            self.ek_decoder.add_chunk(chunk)
            
            if self.ek_decoder.has_message():
                ek_vector = self.ek_decoder.message()
                
                # Verify ek_vector integrity. `hek` came from the MAC-verified
                # header, so this equality is what authenticates ek_vector (it
                # carries no MAC of its own) -- compare in constant time.
                computed_hek = kem.hek_for(self.ek_seed, ek_vector)
                if not hmac.compare_digest(computed_hek, self.hek):
                    raise ValueError("EK integrity check failed")
                
                # Transition (10) -> EkReceivedCt1Sampled
                new_state = EkReceivedCt1Sampled(
                    encaps_secret=self.encaps_secret,
                    ct1=self.ct1,
                    ek_seed=self.ek_seed,
                    ek_vector=ek_vector,
                    ct1_encoder=self.ct1_encoder
                )
                
                return ReceiveResult(
                    receiving_epoch=epoch - 1,
                    output_key=None,
                    new_state=new_state
                )
        
        elif msg.epoch == epoch and msg.type == MessageType.EK_CT1_ACK:
            chunk = Chunk.from_bytes(msg.data)
            self.ek_decoder.add_chunk(chunk)
            
            if self.ek_decoder.has_message():
                ek_vector = self.ek_decoder.message()
                
                # Verify ek_vector integrity. `hek` came from the MAC-verified
                # header, so this equality is what authenticates ek_vector (it
                # carries no MAC of its own) -- compare in constant time.
                computed_hek = kem.hek_for(self.ek_seed, ek_vector)
                if not hmac.compare_digest(computed_hek, self.hek):
                    raise ValueError("EK integrity check failed")
                
                # Complete encapsulation
                ct2 = kem.encaps2(self.encaps_secret, self.ek_seed, ek_vector)
                mac = auth.mac_ciphertext(epoch, self.ct1 + ct2)
                ct2_encoder = Encoder(
                    ct2 + mac, key=chunk_integrity_key(auth, epoch, STREAM_CT2)
                )
                
                # Transition (9) -> Ct2Sampled
                new_state = Ct2Sampled(ct2_encoder=ct2_encoder)
                
                return ReceiveResult(
                    receiving_epoch=epoch - 1,
                    output_key=None,
                    new_state=new_state
                )
            else:
                # Transition (8) -> Ct1Acknowledged
                new_state = Ct1Acknowledged(
                    ek_seed=self.ek_seed,
                    hek=self.hek,
                    encaps_secret=self.encaps_secret,
                    ct1=self.ct1,
                    ek_decoder=self.ek_decoder
                )
                
                return ReceiveResult(
                    receiving_epoch=epoch - 1,
                    output_key=None,
                    new_state=new_state
                )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class EkReceivedCt1Sampled(State):
    """
    Got ek_vector, still sending ct1 chunks.
    
    Transition (12): -> Ct2Sampled on EkCt1Ack
    """
    encaps_secret: EncapsulationSecret
    ct1: bytes
    ek_seed: bytes
    ek_vector: bytes
    ct1_encoder: Encoder
    
    @property
    def name(self) -> StateName:
        return StateName.EK_RECEIVED_CT1_SAMPLED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        chunk = self.ct1_encoder.next_chunk()
        msg = msg_ct1(epoch, chunk.to_bytes())
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        if msg.epoch == epoch and msg.type == MessageType.EK_CT1_ACK:
            # Complete encapsulation
            ct2 = kem.encaps2(self.encaps_secret, self.ek_seed, self.ek_vector)
            mac = auth.mac_ciphertext(epoch, self.ct1 + ct2)
            ct2_encoder = Encoder(
                ct2 + mac, key=chunk_integrity_key(auth, epoch, STREAM_CT2)
            )
            
            # Transition (12) -> Ct2Sampled
            new_state = Ct2Sampled(ct2_encoder=ct2_encoder)
            
            return ReceiveResult(
                receiving_epoch=epoch - 1,
                output_key=None,
                new_state=new_state
            )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class Ct1Acknowledged(State):
    """
    ct1 acknowledged, still receiving ek_vector.
    
    Transition (11): -> Ct2Sampled when ek_vector complete
    """
    ek_seed: bytes
    hek: bytes
    encaps_secret: EncapsulationSecret
    ct1: bytes
    ek_decoder: Decoder
    
    @property
    def name(self) -> StateName:
        return StateName.CT1_ACKNOWLEDGED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        msg = msg_none(epoch)
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        if msg.epoch == epoch and msg.type == MessageType.EK_CT1_ACK:
            chunk = Chunk.from_bytes(msg.data)
            self.ek_decoder.add_chunk(chunk)
            
            if self.ek_decoder.has_message():
                ek_vector = self.ek_decoder.message()
                
                # Verify ek_vector integrity. `hek` came from the MAC-verified
                # header, so this equality is what authenticates ek_vector (it
                # carries no MAC of its own) -- compare in constant time.
                computed_hek = kem.hek_for(self.ek_seed, ek_vector)
                if not hmac.compare_digest(computed_hek, self.hek):
                    raise ValueError("EK integrity check failed")
                
                # Complete encapsulation and generate ct2
                ct2 = kem.encaps2(self.encaps_secret, self.ek_seed, ek_vector)
                mac = auth.mac_ciphertext(epoch, self.ct1 + ct2)
                ct2_encoder = Encoder(
                    ct2 + mac, key=chunk_integrity_key(auth, epoch, STREAM_CT2)
                )
                
                # Transition (11) -> Ct2Sampled
                new_state = Ct2Sampled(ct2_encoder=ct2_encoder)
                
                return ReceiveResult(
                    receiving_epoch=epoch - 1,
                    output_key=None,
                    new_state=new_state
                )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


@dataclass
class Ct2Sampled(State):
    """
    Sending ct2 chunks, waiting for next epoch message.
    
    Transition (13): -> KeysUnsampled on receiving next epoch message
    """
    ct2_encoder: Encoder
    
    @property
    def name(self) -> StateName:
        return StateName.CT2_SAMPLED
    
    def send(
        self,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> SendResult:
        chunk = self.ct2_encoder.next_chunk()
        msg = msg_ct2(epoch, chunk.to_bytes())
        
        return SendResult(
            message=msg,
            sending_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )
    
    def receive(
        self,
        msg: Message,
        epoch: int,
        auth: Authenticator,
        kem: MLKEM,
        kdf: KDF
    ) -> ReceiveResult:
        # Transition (13) is the ONLY epoch-driven transition in the machine, and
        # `epoch` is bound into every subsequent MAC — so taking it spuriously
        # desyncs the session permanently (audit finding M1). Two guards:
        #   1. The caller (MLKEMBraid.receive) verifies the frame MAC over the
        #      whole serialized frame before dispatching here, so `msg.epoch`
        #      and `msg.type` are authenticated.
        #   2. Only the message the peer actually emits when it opens the next
        #      epoch is accepted. A peer that has just completed epoch N sits in
        #      NoHeaderReceived and emits MessageType.NONE at epoch N+1; no other
        #      type is reachable from that state, so anything else is bogus.
        if msg.epoch == epoch + 1 and msg.type == MessageType.NONE:
            # Next epoch has begun
            # Transition (13) -> KeysUnsampled
            new_state = KeysUnsampled()

            return ReceiveResult(
                receiving_epoch=epoch - 1,
                output_key=None,
                new_state=new_state
            )
        
        return ReceiveResult(
            receiving_epoch=epoch - 1,
            output_key=None,
            new_state=self
        )


# Factory functions for state initialization

def init_alice_state() -> State:
    """Initialize Alice's starting state (KeysUnsampled)."""
    return KeysUnsampled()


def init_bob_state(kem: MLKEM) -> State:
    """Initialize Bob's starting state (NoHeaderReceived).

    No header decoder is built here. Building one would mean building it
    *unkeyed* — this factory has no authenticator in scope — and an unkeyed
    decoder accepts corrupted shares silently, which is exactly audit finding
    H3. :meth:`NoHeaderReceived.receive` builds the decoder keyed for the epoch
    whose header it is about to decode instead.

    ``kem`` is retained for API compatibility (the geometry it used to supply is
    now read from ``kem`` inside ``receive``).
    """
    return NoHeaderReceived(header_decoder=None)
