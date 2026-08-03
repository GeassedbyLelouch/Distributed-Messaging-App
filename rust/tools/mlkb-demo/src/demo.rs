//! The world the UI drives: two real parties, two real sessions, real frames.
//!
//! # Nothing here is simulated
//!
//! Every identity key, prekey, signature, encapsulation, nonce and ciphertext
//! the browser displays was produced by `mlkb-crypto` from the platform CSPRNG
//! (see [`crate::entropy`]). Every frame is a real [`Frame`], every rejection is
//! the [`ProtocolError`] the library actually returned, and every state counter
//! is read back out of the live [`Session`]. There is no canned output and no
//! fixture path in this binary.
//!
//! # What the tamper controls can and cannot show
//!
//! The frame MAC's preimage is `label || wire[0 .. 15 + payload_len]`
//! (M1 §A.1) — i.e. the entire frame except the tag itself. So **every**
//! byte-level mutation of a frame, wherever it lands, is refused by the frame
//! MAC before the state machine sees it. That is not a limitation of the demo,
//! it is the property audit M1 was about (the Python MAC did not cover the
//! framing), and the tamper panel is arranged to make it visible: flipping a
//! ciphertext bit, a MAC bit, the `msg_type` byte and an `epoch` bit all give
//! the same answer, at the same stage, for the same reason.
//!
//! The cases that get *past* the MAC are the ones that do not modify bytes:
//! replay, and reordering. Those reach [`Session::classify`], and that is where
//! `ReplayDetected` and the M1 §D.3 ordering rule become observable.

use std::time::{SystemTime, UNIX_EPOCH};

use mlkb_crypto::{
    HYBRID_SIGNATURE_LEN, HybridSignature, KEM_CIPHERTEXT_LEN, KEM_ENCAPSULATION_KEY_LEN,
    KemDecapsulationKey, MLDSA_SIGNATURE_LEN, MLDSA_VERIFYING_KEY_LEN, MlDsaSigningKey,
    X25519SecretKey, sha256,
};
use mlkb_protocol::{
    Accepted, Event, HandshakeGuard, Initiated, LocalIdentity, ResponderPrekeys, Session, initiate,
    respond, verify_bundle,
};
use mlkb_secrets::{Progress, ProtocolError};
use mlkb_wire::{
    EnrolmentProof, FRAME_HEADER_LEN, FRAME_MAC_LEN, HybridIdentityPublic, IdentityId, MsgType,
    OneTimePrekey, PrekeyBundleV2, RatchetMessage, SignedPqPrekey, SignedPrekey,
};

use crate::entropy::{OsEntropy, OsRng};

/// Prekey ids this demo publishes under. Arbitrary; the protocol only requires
/// that the responder hold the private half of whatever the initiator names
/// (M1 §C.3).
const SPK_ID: u32 = 1;
/// See [`SPK_ID`].
const PQSPK_ID: u32 = 2;
/// See [`SPK_ID`].
const OPK_ID: u32 = 3;

/// Which end of the conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// The initiator.
    Alice,
    /// The responder.
    Bob,
}

impl Side {
    /// The lowercase name the HTTP API uses.
    #[must_use]
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Alice => "alice",
            Self::Bob => "bob",
        }
    }

    /// The other end.
    #[must_use]
    pub(crate) fn peer(self) -> Self {
        match self {
            Self::Alice => Self::Bob,
            Self::Bob => Self::Alice,
        }
    }

    /// Parses the API name.
    #[must_use]
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "alice" => Some(Self::Alice),
            "bob" => Some(Self::Bob),
            _ => None,
        }
    }
}

/// What to do to a frame's bytes before handing it to the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tamper {
    /// Deliver the frame exactly as sent.
    None,
    /// Flip one bit inside the AEAD ciphertext, in the CBOR payload.
    Ciphertext,
    /// Flip one bit in the trailing 32-byte frame MAC.
    Mac,
    /// Overwrite `msg_type` with a reserved value (M1 §A.2).
    MsgType,
    /// Flip one bit in the big-endian `epoch` field (M1 §A.1, §A.3).
    Epoch,
}

impl Tamper {
    /// Parses the API name.
    #[must_use]
    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "none" | "" => Some(Self::None),
            "ct" => Some(Self::Ciphertext),
            "mac" => Some(Self::Mac),
            "type" => Some(Self::MsgType),
            "epoch" => Some(Self::Epoch),
            _ => None,
        }
    }

    /// A one-line description of what the button does.
    #[must_use]
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::None => "delivered unmodified",
            Self::Ciphertext => "flipped one bit inside the AEAD ciphertext",
            Self::Mac => "flipped one bit in the 32-byte frame MAC",
            Self::MsgType => "overwrote msg_type with the reserved value 0x07",
            Self::Epoch => "flipped one bit in the epoch field",
        }
    }
}

/// One long-term device, with every private key a handshake can need.
///
/// The X25519 identity secret is duplicated into [`LocalIdentity`] through the
/// same serialized form `mlkb-store` uses (parent §9); neither key type is
/// `Clone`, by design.
struct Party {
    ik: X25519SecretKey,
    mldsa: MlDsaSigningKey,
    spk: X25519SecretKey,
    pqspk: KemDecapsulationKey,
    opk: X25519SecretKey,
    device_id: u32,
}

impl Party {
    fn generate(device_id: u32) -> Self {
        Self {
            ik: X25519SecretKey::random(&mut OsRng),
            mldsa: MlDsaSigningKey::generate(&mut OsRng),
            spk: X25519SecretKey::random(&mut OsRng),
            pqspk: KemDecapsulationKey::generate(&mut OsRng),
            opk: X25519SecretKey::random(&mut OsRng),
            device_id,
        }
    }

    fn ik_mldsa_hash(&self) -> [u8; 32] {
        sha256(&[&self.mldsa.verifying_key().to_wire()])
    }

    fn identity(&self) -> LocalIdentity {
        LocalIdentity::new(
            X25519SecretKey::from_bytes(*self.ik.to_secret().expose_secret()),
            self.ik_mldsa_hash(),
        )
    }

    fn id(&self) -> IdentityId {
        IdentityId::from_public_keys(
            self.ik.public_key().as_bytes(),
            &self.mldsa.verifying_key().to_wire(),
        )
    }

    fn prekeys(&self) -> ResponderPrekeys<'_> {
        ResponderPrekeys {
            device_id: self.device_id,
            spk: (SPK_ID, &self.spk),
            pqspk: (PQSPK_ID, &self.pqspk),
            opk: Some((OPK_ID, &self.opk)),
        }
    }

    /// A `PrekeyBundleV2` whose two prekeys carry **genuine** hybrid signatures
    /// (parent §4.3, M1 §E.2) over the real `canonical(<part> without "s")`
    /// payload, each under its own signature context.
    ///
    /// The `EnrolmentProof`'s signature is the one synthetic value in this
    /// binary, and it is synthetic because no code path here checks it: its
    /// issuer keys are a pinned set and verification is `mlkb-policy`'s
    /// (M1 §F). The UI says so rather than implying the bundle is fully
    /// verified.
    fn bundle(&self) -> Result<PrekeyBundleV2, ProtocolError> {
        let id = self.id();

        let mut signed_prekey = SignedPrekey {
            id: SPK_ID,
            public: *self.spk.public_key().as_bytes(),
            signature: placeholder_signature()?,
        };
        signed_prekey.signature = Box::new(HybridSignature::sign(
            &self.ik,
            &self.mldsa,
            SignedPrekey::CONTEXT,
            id.as_bytes(),
            signed_prekey.signed_payload()?.as_bytes(),
            &mut OsRng,
        )?);

        let mut pq_prekey = SignedPqPrekey {
            id: PQSPK_ID,
            ek: Box::new(self.pqspk.encapsulation_key().to_wire()),
            signature: placeholder_signature()?,
        };
        pq_prekey.signature = Box::new(HybridSignature::sign(
            &self.ik,
            &self.mldsa,
            SignedPqPrekey::CONTEXT,
            id.as_bytes(),
            pq_prekey.signed_payload()?.as_bytes(),
            &mut OsRng,
        )?);

        Ok(PrekeyBundleV2 {
            identity: HybridIdentityPublic {
                ik_x25519: *self.ik.public_key().as_bytes(),
                ik_mldsa: Box::new(self.mldsa.verifying_key().to_wire()),
            },
            signed_prekey,
            pq_prekey,
            one_time: Some(OneTimePrekey {
                id: OPK_ID,
                public: *self.opk.public_key().as_bytes(),
            }),
            enrolment: EnrolmentProof {
                issuer_epoch: 1,
                issuer_key_id: 1,
                not_after_ms: now_ms().saturating_add(DAY_MS),
                subject: id,
                tier: 1,
                signature: placeholder_signature()?,
            },
            expires_at_ms: now_ms().saturating_add(DAY_MS),
        })
    }
}

/// Milliseconds in a day, for the two expiry fields the demo has to fill.
const DAY_MS: u64 = 86_400_000;

/// The largest chat line this demo will seal, in bytes.
///
/// Not a protocol constant — `MAX_FRAME_PAYLOAD` is, and it is 65 536. This is
/// the caller-side bound that keeps the demo well clear of it; see
/// [`World::send`] for why sitting near that cliff is not safe.
const MAX_PLAINTEXT: usize = 4096;

/// A structurally valid but cryptographically meaningless `HybridSignature`.
///
/// Used in exactly two places: as the value a `SignedPrekey` holds for the
/// instant between construction and being signed over (its own signature is not
/// in its signed payload), and as the `EnrolmentProof`'s signature, which
/// nothing in this binary verifies. It is never presented as valid.
fn placeholder_signature() -> Result<Box<HybridSignature>, ProtocolError> {
    let mut bytes = Vec::with_capacity(HYBRID_SIGNATURE_LEN);
    bytes.extend_from_slice(&mlkb_crypto::HYBRID_SIGNATURE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&mlkb_crypto::HYBRID_SIGNATURE_SUITE.to_be_bytes());
    let ed_len =
        u16::try_from(mlkb_crypto::XEDDSA_SIGNATURE_LEN).map_err(|_| ProtocolError::Internal)?;
    bytes.extend_from_slice(&ed_len.to_be_bytes());
    bytes.extend_from_slice(&[0u8; mlkb_crypto::XEDDSA_SIGNATURE_LEN]);
    let ml_len = u16::try_from(MLDSA_SIGNATURE_LEN).map_err(|_| ProtocolError::Internal)?;
    bytes.extend_from_slice(&ml_len.to_be_bytes());
    bytes.extend_from_slice(&[0u8; MLDSA_SIGNATURE_LEN]);
    Ok(Box::new(HybridSignature::from_bytes(&bytes)?))
}

/// Wall-clock milliseconds. `mlkb-protocol` is sans-io and never reads a clock
/// (parent §11 gate 6); supplying `now_ms` to [`HandshakeGuard`] is the
/// caller's job, and here the caller is this file.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// A frame that has been sent but not yet delivered.
#[derive(Debug)]
pub(crate) struct InFlight {
    /// Demo-local id, so the UI can name it.
    pub(crate) id: u64,
    /// Who sent it.
    pub(crate) from: Side,
    /// The literal wire bytes.
    pub(crate) wire: Vec<u8>,
    /// Frame epoch (M1 §A.3).
    pub(crate) epoch: u64,
    /// `n`, the index within the sending chain, when the payload is a
    /// `RatchetMessage`.
    pub(crate) n: Option<u64>,
    /// Whether this message opens a new chain, i.e. carries `"ek"`/`"kc"`
    /// (M1 §D.3).
    pub(crate) opens_chain: bool,
    /// What the sender typed. Shown so a successful decrypt can be compared
    /// against it — this is the *sender's* copy, never the receiver's.
    pub(crate) plaintext: String,
}

/// A frame that has already been delivered once, kept so it can be replayed.
#[derive(Debug)]
pub(crate) struct Delivered {
    /// The id it had in flight.
    pub(crate) id: u64,
    /// Who sent it.
    pub(crate) from: Side,
    /// The literal wire bytes, unmodified.
    pub(crate) wire: Vec<u8>,
    /// What the sender typed.
    pub(crate) plaintext: String,
}

/// One line of the transcript the UI renders.
#[derive(Debug)]
pub(crate) struct LogLine {
    /// A short tag: `setup`, `send`, `deliver`, `attack`, `error`.
    pub(crate) kind: String,
    /// The message.
    pub(crate) text: String,
    /// `true` if this line records a rejection.
    pub(crate) rejected: bool,
}

/// The observable state of one side, and a fingerprint over it.
#[derive(Debug)]
pub(crate) struct StateFingerprint {
    /// `send_epoch` (M1 §A.3).
    pub(crate) send_epoch: u64,
    /// `recv_generation` (M1 §A.3).
    pub(crate) recv_generation: u64,
    /// How many skipped message keys are held (M1 §D.4).
    pub(crate) skipped_keys: u64,
    /// Whether the next send performs a DH ratchet step (M1 §D.2).
    pub(crate) ratchet_due: bool,
    /// SHA-256 over the four values above plus the `session_id`, hex.
    pub(crate) digest: String,
}

/// What one receive attempt did.
#[derive(Debug)]
pub(crate) struct Outcome {
    /// Which of `decode_frame` / `classify` / `apply` produced the answer.
    pub(crate) stage: &'static str,
    /// `true` if the frame was accepted all the way through `apply`.
    pub(crate) accepted: bool,
    /// The literal `ProtocolError` the library returned, if it refused.
    pub(crate) error: Option<ProtocolError>,
    /// The `Event`s `apply` emitted, rendered.
    pub(crate) events: Vec<String>,
    /// The plaintext the receiver recovered, if any. This is the receiver's
    /// own copy — the point of showing it is that it matches what was typed.
    pub(crate) plaintext: Option<String>,
}

impl Outcome {
    fn refused(stage: &'static str, error: ProtocolError) -> Self {
        Self {
            stage,
            accepted: false,
            error: Some(error),
            events: Vec::new(),
            plaintext: None,
        }
    }
}

/// The handshake record the UI shows once, at the top.
#[derive(Debug)]
pub(crate) struct Handshake {
    /// Alice's `IdentityId`, hex (parent §3.5).
    pub(crate) alice_id: String,
    /// Bob's `IdentityId`, hex.
    pub(crate) bob_id: String,
    /// Whether `verify_bundle` accepted Bob's bundle (parent §4.3).
    pub(crate) bundle_verified: bool,
    /// Total encoded size of the bundle, bytes.
    pub(crate) bundle_bytes: usize,
    /// Size of the ML-DSA-65 verifying key in it, bytes.
    pub(crate) mldsa_vk_bytes: usize,
    /// Size of the ML-KEM-1024 encapsulation key in it, bytes.
    pub(crate) kem_ek_bytes: usize,
    /// Size of one hybrid signature, bytes.
    pub(crate) hybrid_sig_bytes: usize,
    /// Size of the sealed `InitialMessageV2` frame, bytes.
    pub(crate) initial_frame_bytes: usize,
    /// The ML-KEM-1024 ciphertext carried in it, bytes.
    pub(crate) kem_ct_bytes: usize,
    /// Alice's `session_id` = `HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)`, hex.
    pub(crate) alice_sid: String,
    /// Bob's, computed independently from his own `SK`.
    pub(crate) bob_sid: String,
    /// Whether the two agree, i.e. whether both derived the same `SK`.
    pub(crate) sid_match: bool,
    /// The whole `0x01` frame, hex.
    pub(crate) initial_wire: String,
}

/// Everything the demo owns.
pub(crate) struct World {
    alice: Party,
    bob: Party,
    /// `Option` because [`Session::apply`] consumes the session by value
    /// (parent §8.1); it is `Some` outside an `apply` call.
    alice_session: Option<Session>,
    bob_session: Option<Session>,
    guard: HandshakeGuard,
    initial_wire: Vec<u8>,
    handshake_seq: u64,
    /// Bob's bundle, kept so the handshake-replay attack can re-run `respond`.
    bob_bundle_ok: bool,
    /// The record the UI renders at the top.
    pub(crate) handshake: Handshake,
    /// Frames sent but not delivered, in send order. The UI delivers them in
    /// any order it likes; that is the reordering control.
    pub(crate) inflight: Vec<InFlight>,
    /// Frames already delivered, kept so they can be replayed.
    pub(crate) delivered: Vec<Delivered>,
    /// The transcript.
    pub(crate) log: Vec<LogLine>,
    next_id: u64,
}

impl std::fmt::Debug for World {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("World")
            .field("inflight", &self.inflight.len())
            .field("delivered", &self.delivered.len())
            .finish_non_exhaustive()
    }
}

impl World {
    /// Generates two identities, publishes Bob's bundle, verifies it, runs
    /// PQXDH and admits the handshake to the replay guard.
    ///
    /// # Errors
    /// Any [`ProtocolError`] the real handshake returns. In a working build
    /// there is no input that can cause one here — every value is freshly
    /// generated — so an error means something is genuinely wrong, and the UI
    /// shows it rather than retrying.
    pub(crate) fn bootstrap() -> Result<Self, ProtocolError> {
        let alice = Party::generate(1);
        let bob = Party::generate(2);

        let bundle = bob.bundle()?;
        let bundle_bytes = bundle.encode()?.as_bytes().len();

        // Parent §4.3, and the UI shows the result rather than assuming it.
        let bundle_verified = verify_bundle(&bundle).is_ok();

        let alice_identity = alice.identity();
        let bob_identity = bob.identity();
        let handshake_seq = 1;

        let Initiated {
            session: alice_session,
            initial,
        } = initiate(
            &alice_identity,
            &bundle,
            bob.device_id,
            handshake_seq,
            &mut OsEntropy,
        )?;

        let initial_wire = initial.to_wire();
        let Progress::Complete(Accepted {
            session: bob_session,
            handshake_seq: seen_seq,
        }) = respond(&bob_identity, &bob.prekeys(), &initial_wire)?
        else {
            return Err(ProtocolError::Malformed);
        };

        // Parent §6.3: `respond` has no replay defence of its own, by design —
        // the guard is a separate object and calling it is the caller's
        // obligation. This is that call.
        let mut guard = HandshakeGuard::new(64, 256);
        guard.admit(
            &alice.id(),
            seen_seq,
            bob_session.session_id(),
            now_ms().saturating_add(DAY_MS),
            now_ms(),
        )?;

        let alice_sid = crate::json::hex(&alice_session.session_id());
        let bob_sid = crate::json::hex(&bob_session.session_id());
        let sid_match = alice_session.session_id() == bob_session.session_id();

        let handshake = Handshake {
            alice_id: crate::json::hex(alice.id().as_bytes()),
            bob_id: crate::json::hex(bob.id().as_bytes()),
            bundle_verified,
            bundle_bytes,
            mldsa_vk_bytes: MLDSA_VERIFYING_KEY_LEN,
            kem_ek_bytes: KEM_ENCAPSULATION_KEY_LEN,
            hybrid_sig_bytes: HYBRID_SIGNATURE_LEN,
            initial_frame_bytes: initial_wire.len(),
            kem_ct_bytes: KEM_CIPHERTEXT_LEN,
            alice_sid,
            bob_sid,
            sid_match,
            initial_wire: crate::json::hex(&initial_wire),
        };

        let mut world = Self {
            alice,
            bob,
            alice_session: Some(alice_session),
            bob_session: Some(bob_session),
            guard,
            initial_wire,
            handshake_seq,
            bob_bundle_ok: bundle_verified,
            handshake,
            inflight: Vec::new(),
            delivered: Vec::new(),
            log: Vec::new(),
            next_id: 1,
        };

        world.note(
            "setup",
            "two hybrid identities generated (X25519 + ML-DSA-65)",
        );
        world.note(
            "setup",
            if bundle_verified {
                "Bob's prekey bundle verified: both hybrid signatures, each under its own context (parent §4.3, M1 §E.2)"
            } else {
                "Bob's prekey bundle FAILED verification"
            },
        );
        world.note(
            "setup",
            "PQXDH complete (M1 §C.1): 4 X25519 legs + 1 ML-KEM-1024 encapsulation",
        );
        world.note(
            "setup",
            if sid_match {
                "both sides derived the same SK: their independently computed session_id values are equal"
            } else {
                "SESSION IDS DIFFER - the two sides did not derive the same SK"
            },
        );
        world.note(
            "setup",
            "handshake admitted to HandshakeGuard (M1 §C.4, parent §6.3)",
        );
        world.note(
            "setup",
            "Alice must speak first: InitialMessageV2 (M1 §C.3) carries no ML-KEM encapsulation key for the initiator, so Bob has nothing to encapsulate to until he receives one application message",
        );
        Ok(world)
    }

    fn note(&mut self, kind: &str, text: &str) {
        self.log.push(LogLine {
            kind: kind.to_owned(),
            text: text.to_owned(),
            rejected: false,
        });
    }

    fn note_rejected(&mut self, kind: &str, text: String) {
        self.log.push(LogLine {
            kind: kind.to_owned(),
            text,
            rejected: true,
        });
    }

    fn session(&self, side: Side) -> Option<&Session> {
        match side {
            Side::Alice => self.alice_session.as_ref(),
            Side::Bob => self.bob_session.as_ref(),
        }
    }

    /// The observable state of one side, plus a digest over it.
    ///
    /// # What this fingerprint covers, exactly
    ///
    /// The `Session` type exposes no reader for the root key, either chain key,
    /// the frame keys or the ratchet keypairs — deliberately, and this demo is
    /// not going to add one. So this digest is over the four public counters
    /// and the `session_id`, and that is what the UI claims and no more.
    ///
    /// The counters are nevertheless the right thing to watch: `send_epoch`,
    /// `recv_generation`, `ratchet_due` and the skipped-key count are exactly
    /// the fields a frame that got past authentication would move. To check the
    /// *keys* as well, use the liveness probe — a genuine message that still
    /// decrypts after a rejection proves the receiving chain key did not move.
    #[must_use]
    pub(crate) fn fingerprint(&self, side: Side) -> StateFingerprint {
        let Some(s) = self.session(side) else {
            return StateFingerprint {
                send_epoch: 0,
                recv_generation: 0,
                skipped_keys: 0,
                ratchet_due: false,
                digest: String::from("unavailable"),
            };
        };
        let skipped = u64::try_from(s.skipped_keys()).unwrap_or(u64::MAX);
        let due = u8::from(s.ratchet_due());
        let digest = sha256(&[
            &s.session_id(),
            &s.send_epoch().to_be_bytes(),
            &s.recv_generation().to_be_bytes(),
            &skipped.to_be_bytes(),
            &[due],
        ]);
        StateFingerprint {
            send_epoch: s.send_epoch(),
            recv_generation: s.recv_generation(),
            skipped_keys: skipped,
            ratchet_due: s.ratchet_due(),
            digest: crate::json::hex(&digest),
        }
    }

    /// Seals one application message and puts it in flight.
    ///
    /// Nothing is delivered here: the frame sits in the queue until the UI
    /// delivers it, which is what makes the reordering control possible.
    ///
    /// # The plaintext bound, and why it is checked *here*
    ///
    /// `Session::send` performs its DH ratchet step before `Frame::seal` can
    /// refuse an oversized payload, so a refused send leaves the ratchet
    /// advanced and the peer permanently unable to enter the new chain — the
    /// MEDIUM finding from the `mlkb-protocol` review, which is a real defect
    /// and not this tool's to fix. It is reachable from here: a chain-opening
    /// message already carries `"ek"` (1568) and `"kc"` (1568), so a plaintext
    /// somewhere above ~62 KB trips `MAX_FRAME_PAYLOAD`.
    ///
    /// The check below is the caller-side bound the review says
    /// `mlkb-session` must impose in any case. It is deliberately far below
    /// the cliff rather than at it: a demo whose session silently died because
    /// someone pasted a long message would be worse than useless.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] if `text` exceeds [`MAX_PLAINTEXT`], and
    /// otherwise whatever [`Session::send`] returns — the interesting one being
    /// [`ProtocolError::Malformed`] from Bob before he has received anything.
    pub(crate) fn send(&mut self, from: Side, text: &str) -> Result<u64, ProtocolError> {
        if text.len() > MAX_PLAINTEXT {
            return Err(ProtocolError::Malformed);
        }
        let slot = match from {
            Side::Alice => &mut self.alice_session,
            Side::Bob => &mut self.bob_session,
        };
        let session = slot.as_mut().ok_or(ProtocolError::Internal)?;
        let frame = session.send(text.as_bytes(), &mut OsEntropy)?;

        let wire = frame.to_wire();
        let msg = RatchetMessage::decode(frame.payload()).ok();
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let entry = InFlight {
            id,
            from,
            epoch: frame.epoch(),
            n: msg.as_ref().map(RatchetMessage::n),
            opens_chain: msg.as_ref().is_some_and(RatchetMessage::opens_chain),
            wire,
            plaintext: text.to_owned(),
        };
        let detail = format!(
            "{} sealed frame #{id}: epoch {}, n {}, {} bytes on the wire{}",
            from.name(),
            entry.epoch,
            entry.n.map_or_else(|| String::from("-"), |n| n.to_string()),
            entry.wire.len(),
            if entry.opens_chain {
                " (opens a new chain: carries \"ek\" and \"kc\")"
            } else {
                ""
            }
        );
        self.inflight.push(entry);
        self.note("send", &detail);
        Ok(id)
    }

    /// Delivers an in-flight frame, optionally mutating its bytes first.
    ///
    /// A frame delivered unmodified moves to the delivered archive so it can be
    /// replayed later; a tampered delivery leaves the original in flight,
    /// because a rejected frame is exactly the case where the UI wants to try
    /// again cleanly.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] if `id` names no in-flight frame.
    pub(crate) fn deliver(&mut self, id: u64, tamper: Tamper) -> Result<Outcome, ProtocolError> {
        let Some(pos) = self.inflight.iter().position(|f| f.id == id) else {
            return Err(ProtocolError::Malformed);
        };
        let (from, plaintext, wire) = {
            let f = self.inflight.get(pos).ok_or(ProtocolError::Internal)?;
            (f.from, f.plaintext.clone(), f.wire.clone())
        };
        let to = from.peer();

        let (bytes, what) = apply_tamper(&wire, tamper);
        let outcome = self.receive(to, &bytes);

        self.push_delivery_line(id, from, &what, tamper_label(tamper), &outcome);

        if tamper == Tamper::None && outcome.accepted {
            let f = self.inflight.remove(pos);
            self.delivered.push(Delivered {
                id: f.id,
                from: f.from,
                wire: f.wire,
                plaintext,
            });
        }
        Ok(outcome)
    }

    /// Re-delivers a frame that has already been accepted once (parent §8.4,
    /// M1 §D.4).
    ///
    /// The bytes are untouched, so the frame MAC verifies exactly as it did the
    /// first time — which is the point: this is the one wire-level attack the
    /// MAC cannot catch, and it has to be caught by the state machine.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] if `id` names nothing in the archive.
    pub(crate) fn replay(&mut self, id: u64) -> Result<Outcome, ProtocolError> {
        let Some(rec) = self.delivered.iter().find(|d| d.id == id) else {
            return Err(ProtocolError::Malformed);
        };
        let (from, wire) = (rec.from, rec.wire.clone());
        let to = from.peer();
        let outcome = self.receive(to, &wire);
        self.push_delivery_line(
            id,
            from,
            "replayed a frame already accepted once",
            "replay",
            &outcome,
        );
        Ok(outcome)
    }

    /// Replays the captured `0x01` handshake frame at the responder
    /// (M1 §C.4, parent §6.3).
    ///
    /// Two things happen, and the UI shows both:
    ///
    /// 1. [`respond`] accepts it and builds a second, fully functional session
    ///    with the same `session_id`. That is not a bug — `respond` has no
    ///    replay defence and is not supposed to; the guard is a separate
    ///    object. It is a caller obligation that no type enforces, which is
    ///    worth seeing.
    /// 2. [`HandshakeGuard::admit`] then refuses it with
    ///    [`ProtocolError::ReplayDetected`], which is the control that actually
    ///    closes the hole.
    ///
    /// # Errors
    /// Any error `respond` returns on the captured frame.
    pub(crate) fn replay_handshake(
        &mut self,
    ) -> Result<(bool, Option<ProtocolError>), ProtocolError> {
        let bob_identity = self.bob.identity();
        let wire = self.initial_wire.clone();
        let Progress::Complete(accepted) = respond(&bob_identity, &self.bob.prekeys(), &wire)?
        else {
            return Err(ProtocolError::Malformed);
        };
        let same_sid = accepted.session.session_id()
            == self
                .bob_session
                .as_ref()
                .map(Session::session_id)
                .unwrap_or_default();

        let guard_result = self.guard.admit(
            &self.alice.id(),
            accepted.handshake_seq,
            accepted.session.session_id(),
            now_ms().saturating_add(DAY_MS),
            now_ms(),
        );
        let err = guard_result.err();

        self.note_rejected(
            "attack",
            format!(
                "handshake replayed: respond() accepted it again (same session_id: {same_sid}) - it has no replay defence of its own, by design; HandshakeGuard::admit then refused it with {}",
                err.map_or_else(|| String::from("NOTHING - the guard let it through"), |e| format!("{e:?} (\"{e}\")"))
            ),
        );
        Ok((same_sid, err))
    }

    /// Sends a fresh message from `from` and delivers it immediately.
    ///
    /// This is the liveness probe: it proves that after a rejection the
    /// *secret* state — the receiving chain key, which no accessor can read —
    /// is still where it was, because a genuine message still opens under it.
    /// The counter fingerprint cannot show that; this can.
    ///
    /// # Errors
    /// Whatever `send` returns.
    pub(crate) fn probe(&mut self, from: Side) -> Result<Outcome, ProtocolError> {
        let id = self.send(from, "liveness probe")?;
        self.deliver(id, Tamper::None)
    }

    /// Runs the three-step receive pipeline: `decode_frame`, `classify`,
    /// `apply` (parent §8.1).
    ///
    /// Every rejection below is the value the library returned, unmodified.
    fn receive(&mut self, to: Side, wire: &[u8]) -> Outcome {
        let slot = match to {
            Side::Alice => &mut self.alice_session,
            Side::Bob => &mut self.bob_session,
        };
        let Some(session) = slot.take() else {
            return Outcome::refused("apply", ProtocolError::Internal);
        };

        let outcome = match session.decode_frame(wire) {
            Err(e) => Outcome::refused("decode_frame", e),
            Ok(Progress::NeedMore) => Outcome::refused("decode_frame", ProtocolError::Malformed),
            Ok(Progress::Complete(frame)) => match session.classify(&frame) {
                Err(e) => Outcome::refused("classify", e),
                Ok(plan) => {
                    // `apply` consumes the session, so it is put back below.
                    let (next, events) = session.apply(plan);
                    let out = render_events(&events);
                    *slot = Some(next);
                    return out;
                }
            },
        };
        // Refused before `apply`: the session was never moved out of, so
        // nothing has changed. Put the same value back.
        *slot = Some(session);
        outcome
    }

    fn push_delivery_line(
        &mut self,
        id: u64,
        from: Side,
        what: &str,
        label: &str,
        outcome: &Outcome,
    ) {
        let line = format!(
            "frame #{id} {} -> {}: {what} ({label}) => {}",
            from.name(),
            from.peer().name(),
            describe(outcome)
        );
        if outcome.error.is_none() {
            self.note("deliver", &line);
        } else {
            self.note_rejected("deliver", line);
        }
    }

    /// Whether Bob's bundle verified at bootstrap (parent §4.3).
    #[must_use]
    pub(crate) fn bundle_ok(&self) -> bool {
        self.bob_bundle_ok
    }

    /// The `handshake_seq` the initiator used (M1 §C.4).
    #[must_use]
    pub(crate) fn handshake_seq(&self) -> u64 {
        self.handshake_seq
    }

    /// How many peers hold a replay floor, and how many live `session_id`s the
    /// guard is holding (parent §6.4).
    #[must_use]
    pub(crate) fn guard_counts(&self) -> (usize, usize) {
        (self.guard.peers(), self.guard.sessions())
    }
}

fn tamper_label(t: Tamper) -> &'static str {
    match t {
        Tamper::None => "unmodified",
        Tamper::Ciphertext => "ciphertext bit flip",
        Tamper::Mac => "MAC bit flip",
        Tamper::MsgType => "reserved msg_type",
        Tamper::Epoch => "epoch bit flip",
    }
}

fn describe(o: &Outcome) -> String {
    match o.error {
        Some(e) => format!("REFUSED at {} with {e:?} (\"{e}\")", o.stage),
        None => format!("accepted; events: {}", o.events.join(", ")),
    }
}

/// Turns the `Event` vector `apply` returned into display strings.
fn render_events(events: &[Event]) -> Outcome {
    let mut rendered = Vec::new();
    let mut plaintext = None;
    let mut failed = false;
    for e in events {
        match e {
            Event::MessageReceived(pt) => {
                rendered.push(format!("MessageReceived({} bytes)", pt.as_bytes().len()));
                plaintext = Some(String::from_utf8_lossy(pt.as_bytes()).into_owned());
            }
            Event::RatchetAdvanced { generation } => {
                rendered.push(format!("RatchetAdvanced(generation={generation})"));
            }
            Event::KeysSkipped { count } => {
                rendered.push(format!("KeysSkipped(count={count})"));
            }
            Event::AckReceived => rendered.push(String::from("AckReceived")),
            Event::OpenFailed => {
                rendered.push(String::from("OpenFailed"));
                failed = true;
            }
        }
    }
    Outcome {
        stage: "apply",
        accepted: !failed && plaintext.is_some(),
        error: if failed {
            Some(ProtocolError::Unauthenticated)
        } else {
            None
        },
        events: rendered,
        plaintext,
    }
}

/// Mutates a copy of the wire bytes and says, in words, exactly what it did.
///
/// Offsets come from the M1 §A.1 layout: `version` at 0, `epoch` at 2,
/// `msg_type` at 10, `payload_len` at 11, payload at 15, MAC in the last 32
/// bytes. Nothing here is indexed blindly — a buffer too short for the field
/// being targeted is left alone and says so, because a tamper control that
/// silently did nothing would be the worst possible thing in this panel.
fn apply_tamper(wire: &[u8], tamper: Tamper) -> (Vec<u8>, String) {
    let mut out = wire.to_vec();
    match tamper {
        Tamper::None => (out, String::from("delivered unmodified")),

        Tamper::Ciphertext => {
            let Some(offset) = ciphertext_offset(wire) else {
                return (out, String::from("could not locate the ciphertext"));
            };
            let Some(b) = out.get_mut(offset) else {
                return (out, String::from("could not locate the ciphertext"));
            };
            *b ^= 0x01;
            (
                out,
                format!("flipped bit 0 of wire byte {offset}, inside the AEAD ciphertext"),
            )
        }

        Tamper::Mac => {
            let Some(offset) = wire.len().checked_sub(FRAME_MAC_LEN) else {
                return (out, String::from("frame too short to hold a MAC"));
            };
            let Some(b) = out.get_mut(offset) else {
                return (out, String::from("frame too short to hold a MAC"));
            };
            *b ^= 0x80;
            (
                out,
                format!("flipped bit 7 of wire byte {offset}, the first byte of the frame MAC"),
            )
        }

        Tamper::MsgType => {
            // 0x07 is outside `MsgType`'s closed registry (M1 §A.2); the
            // registry has 0x01..=0x03 and everything else is reserved.
            let Some(b) = out.get_mut(10) else {
                return (out, String::from("frame too short to hold a msg_type"));
            };
            *b = 0x07;
            (
                out,
                String::from("set wire byte 10 (msg_type) to the reserved value 0x07"),
            )
        }

        Tamper::Epoch => {
            // The epoch is the big-endian u64 at offset 2; byte 9 is its least
            // significant byte, so this is `epoch ^ 1`.
            let Some(b) = out.get_mut(9) else {
                return (out, String::from("frame too short to hold an epoch"));
            };
            *b ^= 0x01;
            (
                out,
                String::from("flipped bit 0 of wire byte 9, the low byte of the epoch"),
            )
        }
    }
}

/// Finds a byte inside the AEAD ciphertext, as an offset into the whole frame.
///
/// The payload is deterministic CBOR (M1 §D.3) and this binary contains no
/// second decoder for it, so the ciphertext is located by decoding the payload
/// with `mlkb-wire` and then finding those exact bytes back inside it. If the
/// payload does not parse — a frame that is not a `RatchetMessage` — this
/// returns `None` rather than guessing.
fn ciphertext_offset(wire: &[u8]) -> Option<usize> {
    let payload_end = wire.len().checked_sub(FRAME_MAC_LEN)?;
    let payload = wire.get(FRAME_HEADER_LEN..payload_end)?;
    let msg = RatchetMessage::decode(payload).ok()?;
    let ct = msg.ct();
    if ct.is_empty() {
        return None;
    }
    let start = payload.windows(ct.len()).position(|w| w == ct)?;
    // The middle of the ciphertext, so the flip is visibly inside the body and
    // not in a length prefix that happens to abut it.
    let within = start.saturating_add(ct.len() / 2);
    FRAME_HEADER_LEN.checked_add(within)
}

/// The `msg_type` registry, evaluated directly (M1 §A.2).
///
/// The wire-level `MsgType` tamper above is refused by the frame MAC, because
/// the MAC covers byte 10 along with everything else. That means the registry
/// check itself — M1 §A.1 rule 6, "validate `msg_type` only after the MAC
/// verifies" — is unreachable from outside without the frame key, which is the
/// property, not a gap. This function calls the registry directly so the UI can
/// show what it does with a reserved byte.
pub(crate) fn registry_probe(byte: u8) -> Result<MsgType, ProtocolError> {
    MsgType::from_u8(byte)
}
