//! The established session — classify / apply, and the send path
//! (spec parent §8.1, §8.3, M1 §D.2, §D.3, §D.4).
//!
//! # Classify / apply is a shape, not a discipline
//!
//! Parent §8.1: the Python state machine mutated on unauthenticated fields.
//! Here [`Session::classify`] borrows and cannot mutate, [`Session::apply`]
//! consumes `self` and is the only mutator, and [`Plan`] has no public
//! constructor and no public fields — so the only way to reach `apply` is
//! through `classify`, and that is enforced by the type system rather than by
//! review.
//!
//! M1 §G.3 resolves the borrow conflict this creates with parent §8.2's
//! consuming `ChainKey::step`: `classify` plans against a **clone** of the
//! chain key and `apply` consumes the original.
//!
//! # How far `classify` gets
//!
//! `classify` does the whole of the work a non-mutating borrow allows, and for
//! every path that carries a ciphertext that now includes the AEAD:
//!
//! | frame | verified in | state touched on failure |
//! |---|---|---|
//! | in the current receiving chain | `classify` | none |
//! | opening a new receiving chain | `classify` | none |
//! | matching a cached skipped key | `apply` (see below) | none |
//!
//! **The cached path.** A cached [`mlkb_crypto::MessageKey`] is neither
//! `Clone` nor readable, and `open` consumes it, so `classify` cannot use one
//! from behind `&self`. `apply` therefore removes it, opens, and — on failure
//! — **puts it back**. That is exactly why `MessageKey::open` returns the key
//! in its error arm, and it is M1 §D.4's rule that a failed open must not
//! spend a cached key: the Python audit's D7 defect, at the protocol layer.
//! Net state change on failure is nil, so this is the one remaining source of
//! [`Event::OpenFailed`].
//!
//! # The new-chain path, and the residue that used to live here
//!
//! `RootKey::ratchet` consumes the root key and [`mlkb_crypto::RootKey`] is
//! deliberately not `Clone` (parent §4.1), so `classify` could not once
//! compute the new receiving chain key from `&self`. The AEAD check therefore
//! landed *after* the root step, and a MAC-valid frame opening a new chain
//! permanently desynchronised the receiver: `RatchetAdvanced` and `OpenFailed`
//! together, `recv_generation` advanced, every later genuine message refused.
//!
//! That was argued to be acceptable because reaching `apply` requires a frame
//! whose MAC verifies under `K_frame_dir`, and parent §3.3 declares frame
//! authentication an outsider-only control. The argument does not hold:
//! `K_frame_dir` never ratchets, so an attacker who held `SK` **once** and then
//! lost access kept a one-frame permanent-denial primitive *past* the
//! post-compromise-security boundary the whole ratchet exists to establish.
//! Parent §3.3 disclaims PCS for frame *authentication*; it does not license a
//! MAC-only-authenticated frame to advance the *root* ratchet.
//!
//! It is closed structurally by [`mlkb_crypto::RootKey::ratchet_preview`],
//! which derives the prospective `(RK', CK)` from `&self` without consuming
//! the root key. `classify` previews, takes the single M1 §D.3 chain step, and
//! runs the AEAD; a ciphertext the AEAD refuses returns
//! [`ProtocolError::Unauthenticated`] with the previewed keys dropped
//! unwritten, and `apply` receives only transitions already known to be
//! genuine. Audit M1's defect — *one spoofed `Message(epoch+1)` permanently
//! desyncs a session* — is now closed twice over: by the frame MAC covering
//! the framing (`mlkb-wire`'s job, unconditional), and by the root step no
//! longer preceding the AEAD.
//!
//! # The send path is atomic across its root step too
//!
//! The same shape governs [`Session::send`]: a sending root step is computed
//! into locals ([`Session::plan_root_step`]) and **nothing** is written to
//! `self` until [`Frame::seal`] has returned a frame. That matters because
//! `Frame::seal` refuses a payload over `MAX_FRAME_PAYLOAD`, and a
//! chain-opening message carries `ek` and `kc` — 3136 bytes of ML-KEM — so a
//! large plaintext can fail *after* the step. Committing the step and dropping
//! the [`RatchetStep`] would emit the rest of that chain with `n >= 1` and no
//! `ek`/`kc`, which M1 §D.3 puts only on the `n == 0` message: the receiver
//! would refuse every one of them, forever.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU64;

use mlkb_codec::CanonicalBytes;
use mlkb_crypto::{
    Aad, ChainKey, Ciphertext, FrameDirection, FrameKey, KemCiphertext, KemDecapsulationKey,
    KemEncapsulationKey, RootKey, X25519PublicKey, X25519SecretKey, x25519_dh,
};
use mlkb_secrets::{Nonce192, Progress, ProtocolError, WireNonce};
use mlkb_wire::{Frame, IdentityId, MsgType, RatchetMessage, RatchetStep};
use zeroize::Zeroizing;

use crate::entropy::Entropy;
use crate::ratchet::{RatchetState, SkipIndex, SkippedKey, derive_run};

/// Which side of the handshake this session is (spec parent §4.4).
///
/// The only thing it decides is which directional frame key seals and which
/// verifies, so that a peer's own frame reflected back at it does not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The party that sent `InitialMessageV2`.
    Initiator,
    /// The party that answered it.
    Responder,
}

/// A decrypted application message.
///
/// Wraps the `Zeroizing` container [`mlkb_crypto::MessageKey::open`] returns,
/// so dropping an undelivered event still wipes. Parent §8.2's honest
/// limitation applies unchanged: this reduces residency, it does not eliminate
/// it.
pub struct Plaintext(Zeroizing<Vec<u8>>);

impl Plaintext {
    /// The plaintext bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Length only. A plaintext in a log line is the thing this protocol exists to
/// prevent.
impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plaintext({} bytes)", self.0.len())
    }
}

/// What applying a [`Plan`] did (spec parent §8.1).
pub enum Event {
    /// A message was decrypted.
    MessageReceived(Plaintext),
    /// A receiving DH ratchet step was performed; the receiving chain is now
    /// at this generation (spec M1 §A.3, §D.2).
    RatchetAdvanced {
        /// The new receiving-chain generation.
        generation: u64,
    },
    /// This many message keys were derived and filed for later (M1 §D.4).
    KeysSkipped {
        /// How many keys were filed.
        count: u64,
    },
    /// A payload-free keepalive arrived (spec M1 §A.2).
    AckReceived,
    /// The AEAD refused a ciphertext on the one path `classify` cannot
    /// pre-verify: a cached skipped key, which is not readable from `&self`
    /// (see the module docs).
    ///
    /// The cached key is **not** spent — `apply` puts it back — so this event
    /// reports a failed open with no state change at all.
    ///
    /// Deliberately not an error: `apply` cannot fail, and the caller has
    /// already been told everything parent §8.4 permits — namely that
    /// authentication failed, with no payload and no distinction as to why.
    OpenFailed,
}

impl fmt::Debug for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageReceived(pt) => f.debug_tuple("MessageReceived").field(pt).finish(),
            Self::RatchetAdvanced { generation } => f
                .debug_struct("RatchetAdvanced")
                .field("generation", generation)
                .finish(),
            Self::KeysSkipped { count } => {
                f.debug_struct("KeysSkipped").field("count", count).finish()
            }
            Self::AckReceived => f.write_str("AckReceived"),
            Self::OpenFailed => f.write_str("OpenFailed"),
        }
    }
}

/// The AEAD inputs a plan carries when the open happens in `apply` — the
/// cached-key path, and only that path.
struct Sealed {
    aad: CanonicalBytes,
    ct: Ciphertext,
    nonce: WireNonce,
}

/// What [`Session::apply`] is to commit.
///
/// Private, with private fields, because parent §8.1 requires that a `Plan` be
/// obtainable only from `classify`.
enum Commit {
    Ack,
    Cached {
        index: SkipIndex,
        sealed: Sealed,
    },
    Advance {
        skipped: Vec<SkippedKey>,
        next_ck: ChainKey,
        nr: u64,
        plaintext: Zeroizing<Vec<u8>>,
    },
    NewChain {
        skipped_prev: Vec<SkippedKey>,
        /// The previewed successor root key. `apply` assigns it straight over
        /// the old one, which is how the caller's obligation on
        /// [`mlkb_crypto::RootKey::ratchet_preview`] is discharged: no second
        /// root key is ever reachable.
        root: RootKey,
        next_ck: ChainKey,
        dh_remote: X25519PublicKey,
        kem_remote: KemEncapsulationKey,
        generation: u64,
        plaintext: Zeroizing<Vec<u8>>,
    },
}

/// An authenticated, planned state transition (spec parent §8.1, M1 §G.3).
///
/// No public constructor and no public fields: the only way to obtain one is
/// [`Session::classify`], and the only thing that consumes one is
/// [`Session::apply`]. That is what makes "authenticate, then mutate" a shape
/// rather than a discipline.
pub struct Plan(Commit);

/// Variant name only — a plan can hold a plaintext and derived key material.
impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Commit::Ack => "Plan(Ack)",
            Commit::Cached { .. } => "Plan(Cached)",
            Commit::Advance { .. } => "Plan(Advance)",
            Commit::NewChain { .. } => "Plan(NewChain)",
        })
    }
}

/// The two identities a session binds, in the order parent §4.1 fixes them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ends {
    /// This end.
    pub(crate) local: IdentityId,
    /// The peer.
    pub(crate) remote: IdentityId,
}

/// What each role already knows of the other when the ratchet starts
/// (spec M1 §D.2 "Initialization").
///
/// The initiator has the responder's signed prekey and PQ prekey and none of
/// its own ratchet keys — M1 §D.2 has it generate them on its first send. The
/// responder has its own two prekey pairs and, because `InitialMessageV2`
/// carries neither ratchet key, nothing of the initiator's.
pub(crate) struct RatchetKeys {
    /// Our X25519 ratchet secret, if we already have one.
    pub(crate) dh_self: Option<X25519SecretKey>,
    /// The peer's X25519 ratchet public key, if we already know it.
    pub(crate) dh_remote: Option<X25519PublicKey>,
    /// Our ML-KEM-1024 keypair, if we have already published one.
    pub(crate) kem_self: Option<KemDecapsulationKey>,
    /// The peer's ML-KEM-1024 encapsulation key, if we already know it.
    pub(crate) kem_remote: Option<KemEncapsulationKey>,
}

/// One end of an established session (spec parent §8.1, M1 §D).
///
/// Sans-io by construction: no clock, no RNG, no globals. Time never enters at
/// all, and randomness enters only through [`Entropy`] (M1 §G.2, §I.3).
pub struct Session {
    role: Role,
    local: IdentityId,
    remote: IdentityId,
    sid: [u8; 32],
    frame_send: FrameKey,
    frame_recv: FrameKey,
    ratchet: RatchetState,
}

/// No field of a `Session` is printable: two frame keys, a root key and a
/// chain key are secrets, and the identities are already available to any
/// caller that holds one.
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("role", &self.role)
            .field("send_epoch", &self.ratchet.send_epoch)
            .field("recv_generation", &self.ratchet.recv_gen)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Assembles a session from a completed PQXDH run (spec M1 §C.1, §D.2).
    ///
    /// `RK_0 = SK` (M1 §D.2 "Initialization"), and the two directional frame
    /// keys and the `session_id` are the other three parent §4.4 derivations
    /// from that same `SK` — all taken here, once, before the root key is
    /// moved into the ratchet where nothing can read it again.
    ///
    /// Crate-private: `mlkb-protocol`'s only public entries into this type are
    /// [`crate::initiate`] and [`crate::respond`], so a session cannot exist
    /// without a root key that came from [`mlkb_crypto::derive_sk`].
    pub(crate) fn new(role: Role, ends: Ends, root: RootKey, keys: RatchetKeys) -> Self {
        let (frame_send, frame_recv) = match role {
            Role::Initiator => (
                root.derive_frame_key(FrameDirection::InitiatorToResponder),
                root.derive_frame_key(FrameDirection::ResponderToInitiator),
            ),
            Role::Responder => (
                root.derive_frame_key(FrameDirection::ResponderToInitiator),
                root.derive_frame_key(FrameDirection::InitiatorToResponder),
            ),
        };
        let sid = root.derive_session_id();
        Self {
            role,
            local: ends.local,
            remote: ends.remote,
            sid,
            frame_send,
            frame_recv,
            ratchet: RatchetState::new(
                root,
                keys.dh_self,
                keys.dh_remote,
                keys.kem_self,
                keys.kem_remote,
            ),
        }
    }

    /// Which side this is (spec parent §4.4).
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// This end's identity (spec parent §3.5).
    #[must_use]
    pub fn local(&self) -> &IdentityId {
        &self.local
    }

    /// The peer's identity (spec parent §3.5).
    #[must_use]
    pub fn remote(&self) -> &IdentityId {
        &self.remote
    }

    /// `HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)` — the first-contact replay
    /// key of parent §6.3.
    ///
    /// Not a secret: it is a set member in [`crate::HandshakeGuard`]. Two ends
    /// of one handshake agree on it exactly when they agree on `SK`, which is
    /// the only observation of that agreement either end can make — `SK`
    /// itself never leaves [`mlkb_crypto::RootKey`].
    #[must_use]
    pub fn session_id(&self) -> [u8; 32] {
        self.sid
    }

    /// The sending chain's DH-ratchet generation (spec M1 §A.3).
    #[must_use]
    pub fn send_epoch(&self) -> u64 {
        self.ratchet.send_epoch
    }

    /// The receiving chain's generation (spec M1 §A.3).
    #[must_use]
    pub fn recv_generation(&self) -> u64 {
        self.ratchet.recv_gen
    }

    /// How many skipped message keys are currently held (spec M1 §D.4).
    #[must_use]
    pub fn skipped_keys(&self) -> usize {
        self.ratchet.skipped.len()
    }

    /// Parses and authenticates one inbound frame (spec M1 §A.1).
    ///
    /// The directional receive key never leaves this type, so a caller cannot
    /// verify a frame under the wrong direction (parent §4.4).
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] or [`ProtocolError::Unauthenticated`], per
    /// M1 §A.1's seven rules.
    pub fn decode_frame(&self, wire: &[u8]) -> Result<Progress<Frame>, ProtocolError> {
        Frame::decode(wire, &self.frame_recv)
    }

    // -----------------------------------------------------------------
    // Receive (spec parent §8.1)
    // -----------------------------------------------------------------

    /// Plans what an authenticated frame would do. Pure; borrows; cannot
    /// mutate (spec parent §8.1).
    ///
    /// # Errors
    /// - [`ProtocolError::Malformed`] — a payload that is not a well-formed
    ///   [`RatchetMessage`], an `ACK` carrying a payload, an `INITIAL` on an
    ///   established session, or a frame epoch that breaks M1 §A.3's rule.
    /// - [`ProtocolError::ReplayDetected`] — an index whose key has already
    ///   been used, in this chain or a retained one.
    /// - [`ProtocolError::SkippedKeyLimit`] — either M1 §D.4 bound, checked
    ///   before any key material is derived.
    /// - [`ProtocolError::Unauthenticated`] — the AEAD refused, on either of
    ///   the two paths that carry a ciphertext `classify` can key (the current
    ///   chain, and one opening a new chain), or the peer's ratchet key failed
    ///   M1 §C.2's fail-closed DH.
    pub fn classify(&self, frame: &Frame) -> Result<Plan, ProtocolError> {
        match frame.msg_type() {
            MsgType::Ack => {
                if frame.payload().is_empty() {
                    Ok(Plan(Commit::Ack))
                } else {
                    Err(ProtocolError::Malformed)
                }
            }
            // An established session has a root key already. A second PQXDH
            // run is a *new* session (`respond`), not a transition of this
            // one: accepting one here would let a peer reset an established
            // ratchet.
            MsgType::Initial => Err(ProtocolError::Malformed),
            MsgType::Message => self.classify_message(frame),
        }
    }

    fn classify_message(&self, frame: &Frame) -> Result<Plan, ProtocolError> {
        let msg = RatchetMessage::decode(frame.payload())?;
        let epoch = frame.epoch();
        let sealed = Sealed {
            aad: msg.aad(epoch, &self.remote, &self.local)?,
            ct: Ciphertext::from_wire(msg.ct().to_vec()),
            nonce: WireNonce::from_bytes(*msg.nonce().as_bytes()),
        };

        let next_gen = self
            .ratchet
            .recv_gen
            .checked_add(1)
            .ok_or(ProtocolError::Malformed)?;

        if epoch == next_gen {
            self.plan_new_chain(&msg, next_gen, &sealed)
        } else if epoch == self.ratchet.recv_gen {
            self.plan_in_chain(&msg, epoch, sealed)
        } else if epoch < self.ratchet.recv_gen {
            // A message delayed across a ratchet boundary. Its key was filed
            // when we ratcheted past its chain, or the chain has aged out of
            // M1 §D.4's retention window.
            self.plan_cached(&msg, epoch, sealed)
        } else {
            // M1 §A.3: a receiver never advances its own state from a peer's
            // `epoch` alone, and M1 §D.3 puts `"ek"`/`"kc"` on the *first*
            // message of each chain only — so the generations in between
            // cannot be reconstructed and this frame is not processable.
            Err(ProtocolError::Malformed)
        }
    }

    /// A message opening a new receiving chain (spec M1 §D.2, §D.3).
    fn plan_new_chain(
        &self,
        msg: &RatchetMessage,
        generation: u64,
        sealed: &Sealed,
    ) -> Result<Plan, ProtocolError> {
        // M1 §D.3 makes the pairing a parser property, so a message at this
        // epoch without a step is one the parser already refused to give a
        // step to — i.e. `n != 0`, a member of a chain we cannot open because
        // the `"ek"`/`"kc"` that would let us root-step travel only on its
        // `n == 0` sibling. `classify` does not mutate, so a caller may retain
        // the frame and re-offer it once that sibling arrives.
        let step: &RatchetStep = msg.step().ok_or(ProtocolError::Malformed)?;

        // Catch up the chain we are leaving, exactly as in Signal: `"pn"` is
        // how many messages it carried.
        let skip_prev = msg
            .pn()
            .checked_sub(self.ratchet.nr)
            .ok_or(ProtocolError::Malformed)?;
        // Both M1 §D.4 bounds, before any derivation and before any AEAD.
        self.ratchet.check_skip_budget(skip_prev)?;

        let skipped_prev = if let Some(ck) = self.ratchet.ck_recv.as_ref() {
            derive_run(
                ck.clone(),
                self.ratchet.recv_gen,
                self.ratchet.nr,
                skip_prev,
            )?
            .0
        } else {
            // No receiving chain yet: this is the first message of the
            // session. There is nothing to catch up, and a `pn` claiming
            // otherwise is a claim we cannot satisfy.
            if skip_prev != 0 {
                return Err(ProtocolError::Malformed);
            }
            Vec::new()
        };

        // The two halves of the M1 §D.2 root step.
        let dh_remote = X25519PublicKey::from_bytes(*msg.dh());
        let dh_self = self
            .ratchet
            .dh_self
            .as_ref()
            .ok_or(ProtocolError::Malformed)?;
        // M1 §C.2's two fail-closed checks happen inside this call.
        let dh_out = x25519_dh(dh_self, &dh_remote)?;
        let kem_self = self
            .ratchet
            .kem_self
            .as_ref()
            .ok_or(ProtocolError::Malformed)?;
        let kem_ss = kem_self.decapsulate(&KemCiphertext::from_wire(*step.kc));
        let kem_remote = KemEncapsulationKey::from_wire(&step.ek)?;

        // The root step, *previewed*: `RootKey::ratchet_preview` derives the
        // successor `(RK', CK)` from `&self` without consuming the root key,
        // which is what lets the AEAD below happen before anything is
        // committed. See the module docs for the residue this closes. If the
        // open fails, `root` and `next_ck` are dropped here, unwritten.
        let (root, ck) = self.ratchet.root.ratchet_preview(&dh_out, &kem_ss);
        // `n == 0` on a chain-opening message (M1 §D.3), so exactly one chain
        // step — the parser guarantees it by refusing a step on `n != 0`.
        let (next_ck, mk) = ck.step();
        let plaintext = mk
            .open(&sealed.nonce, &sealed.ct, Aad::new(&sealed.aad))
            .map_err(|(_, e)| e)?;

        Ok(Plan(Commit::NewChain {
            skipped_prev,
            root,
            next_ck,
            dh_remote,
            kem_remote,
            generation,
            plaintext,
        }))
    }

    /// A message in the current receiving chain (spec M1 §D.2, §D.4).
    fn plan_in_chain(
        &self,
        msg: &RatchetMessage,
        epoch: u64,
        sealed: Sealed,
    ) -> Result<Plan, ProtocolError> {
        if msg.n() < self.ratchet.nr {
            // Behind the chain pointer: either filed as a skipped key, or
            // already spent.
            return self.plan_cached(msg, epoch, sealed);
        }
        let ck = self
            .ratchet
            .ck_recv
            .as_ref()
            .ok_or(ProtocolError::Malformed)?;
        let skip = msg
            .n()
            .checked_sub(self.ratchet.nr)
            .ok_or(ProtocolError::Malformed)?;
        // Both M1 §D.4 bounds, before any derivation and before any AEAD.
        self.ratchet.check_skip_budget(skip)?;

        // M1 §G.3: plan against a clone; `apply` consumes the original.
        let (skipped, chain) = derive_run(ck.clone(), epoch, self.ratchet.nr, skip)?;
        let (next_ck, mk) = chain.step();
        let plaintext = mk
            .open(&sealed.nonce, &sealed.ct, Aad::new(&sealed.aad))
            .map_err(|(_, e)| e)?;
        let nr = msg.n().checked_add(1).ok_or(ProtocolError::Malformed)?;

        Ok(Plan(Commit::Advance {
            skipped,
            next_ck,
            nr,
            plaintext,
        }))
    }

    /// A message whose key, if it is still live, is in the skipped store
    /// (spec M1 §D.4).
    fn plan_cached(
        &self,
        msg: &RatchetMessage,
        epoch: u64,
        sealed: Sealed,
    ) -> Result<Plan, ProtocolError> {
        let index = (epoch, msg.n());
        // A read, not a take: `classify` cannot mutate. Absence means the key
        // was spent (a replay) or its chain aged out of M1 §D.4's retention
        // window; parent §8.4 has one variant for "already accepted" and this
        // is it.
        if !self.ratchet.skipped.contains_key(&index) {
            return Err(ProtocolError::ReplayDetected);
        }
        Ok(Plan(Commit::Cached { index, sealed }))
    }

    /// Commits a plan. The **only** mutator (spec parent §8.1).
    ///
    /// Infallible by signature, which is why every rejection lives in
    /// [`Session::classify`]. The one outcome `classify` cannot pre-decide —
    /// a cached skipped key, which it cannot read from `&self` — surfaces as
    /// [`Event::OpenFailed`], and costs no state; see the module
    /// documentation.
    #[must_use]
    pub fn apply(mut self, plan: Plan) -> (Self, Vec<Event>) {
        let mut events = Vec::new();
        match plan.0 {
            Commit::Ack => events.push(Event::AckReceived),

            Commit::Cached { index, sealed } => {
                // M1 §D.4, and the audit's D7 defect: take, try, and put back
                // on failure. `MessageKey::open` returns the key in its error
                // arm for exactly this. A cached key is never destroyed by a
                // ciphertext that does not authenticate.
                match self.ratchet.skipped.remove(&index) {
                    Some(mk) => match mk.open(&sealed.nonce, &sealed.ct, Aad::new(&sealed.aad)) {
                        Ok(pt) => events.push(Event::MessageReceived(Plaintext(pt))),
                        Err((mk, _)) => {
                            // Room is guaranteed: we removed this very entry a
                            // moment ago, and nothing else has been inserted.
                            let _ = self.ratchet.skipped.insert(index, mk);
                            events.push(Event::OpenFailed);
                        }
                    },
                    // Unreachable: `classify` checked presence and `self` has
                    // not been mutated since. Reported rather than panicked
                    // (parent §11 gate 7).
                    None => events.push(Event::OpenFailed),
                }
            }

            Commit::Advance {
                skipped,
                next_ck,
                nr,
                plaintext,
            } => {
                self.file_skipped(skipped, &mut events);
                self.ratchet.ck_recv = Some(next_ck);
                self.ratchet.nr = nr;
                events.push(Event::MessageReceived(Plaintext(plaintext)));
            }

            Commit::NewChain {
                skipped_prev,
                root,
                next_ck,
                dh_remote,
                kem_remote,
                generation,
                plaintext,
            } => {
                self.file_skipped(skipped_prev, &mut events);

                // The M1 §D.2 root step, already computed and already
                // authenticated in `classify`. Assigning over the field is
                // what supersedes the old root key: it is dropped here, so a
                // previewed-but-committed step retains no more than the
                // consuming `RootKey::ratchet` would have.
                self.ratchet.root = root;
                self.ratchet.dh_remote = Some(dh_remote);
                self.ratchet.kem_remote = Some(kem_remote);
                self.ratchet.recv_gen = generation;
                // Signal's rule: having received a new chain, ratchet before
                // the next send.
                self.ratchet.ratchet_due = true;
                self.ratchet.prune_skipped(generation);
                events.push(Event::RatchetAdvanced { generation });

                self.ratchet.ck_recv = Some(next_ck);
                self.ratchet.nr = 1;
                events.push(Event::MessageReceived(Plaintext(plaintext)));
            }
        }
        (self, events)
    }

    /// Files derived-but-unused keys. The bounds were checked in `classify`,
    /// before any of them existed (M1 §D.4).
    fn file_skipped(&mut self, keys: Vec<SkippedKey>, events: &mut Vec<Event>) {
        let count = keys.len();
        for (index, mk) in keys {
            // `BoundedMap` fails closed and never evicts, so a refusal here
            // would leave every cached key intact. It cannot happen:
            // `check_skip_budget` reserved the room.
            let _ = self.ratchet.skipped.insert(index, mk);
        }
        if count > 0 {
            events.push(Event::KeysSkipped {
                count: u64::try_from(count).unwrap_or(u64::MAX),
            });
        }
    }

    // -----------------------------------------------------------------
    // Send (spec M1 §D.2, §D.3)
    // -----------------------------------------------------------------

    /// Whether the next [`Session::send`] will perform a DH ratchet step
    /// (spec M1 §D.2).
    #[must_use]
    pub fn ratchet_due(&self) -> bool {
        self.ratchet.ratchet_due || self.ratchet.ck_send.is_none()
    }

    /// Seals one application message (spec M1 §D.2, §D.3).
    ///
    /// Performs a DH ratchet step first whenever one is due — on the first
    /// send, and on the first send after receiving a new chain. A step draws a
    /// fresh X25519 keypair, a fresh ML-KEM-1024 keypair and one encapsulation
    /// to the peer's current `ek` from `entropy`, and publishes the first two
    /// as `"dh"` and `"ek"` on the resulting `n == 0` message.
    ///
    /// **Atomic.** Every fallible operation — the root step included — runs
    /// against locals, and `self` is written only after [`Frame::seal`] has
    /// returned a frame. A `send` that returns `Err` leaves the session exactly
    /// where it was, down to the last byte: same root key, same chain key, same
    /// `Ns`/`PN`/epoch, same ratchet keypairs, and `ratchet_due` still set if it
    /// was set. That is not an incidental property of the ordering below; see
    /// the module docs for what a non-atomic send costs the *peer*.
    ///
    /// What a failed send *does* consume is `entropy`: the keypairs and the
    /// nonce drawn for the attempt are discarded, never reissued. That is the
    /// safe direction — a nonce is drawn once and used at most once (M1 §I.3,
    /// `mlkb_secrets::Nonce192`) — but it means a retry produces a different
    /// frame, not the same one.
    ///
    /// # Errors
    /// - [`ProtocolError::Malformed`] if a ratchet step is due but the peer's
    ///   ratchet keys are not yet known. That is the responder before it has
    ///   received anything: `InitialMessageV2` (M1 §C.3) carries no ML-KEM
    ///   encapsulation key for the initiator, so there is nothing to
    ///   encapsulate to and the initiator necessarily speaks first.
    /// - [`ProtocolError::Malformed`] if the encoded message would exceed
    ///   [`mlkb_wire::MAX_FRAME_PAYLOAD`] (M1 §A.1 rule 2). The plaintext is
    ///   not the only contributor: the AEAD tag, the CBOR framing and — on the
    ///   `n == 0` message of a chain — `ek` and `kc`, 3136 bytes of ML-KEM,
    ///   all count against the bound, so the largest acceptable plaintext is
    ///   smaller on a chain-opening send than on the rest of the chain. A
    ///   caller with messages near the limit should chunk rather than probe;
    ///   this bound is `mlkb-wire`'s and is not a property of the ratchet.
    /// - [`ProtocolError::Unauthenticated`] if the peer's X25519 ratchet key
    ///   fails M1 §C.2's fail-closed DH.
    /// - [`ProtocolError::Internal`] on an encoding fault (M1 §B) or a counter
    ///   overflow, either of which would be this crate's own bug and is never
    ///   an authentication outcome.
    pub fn send<E: Entropy + ?Sized>(
        &mut self,
        plaintext: &[u8],
        entropy: &mut E,
    ) -> Result<Frame, ProtocolError> {
        // The root step, if one is due, is *planned* — computed into a local
        // and not written anywhere. Nothing below touches `self` either.
        let pending = if self.ratchet_due() {
            Some(self.plan_root_step(entropy)?)
        } else {
            None
        };

        // M1 §D.3: a step goes on the `n == 0` message of its chain, and that
        // chain's `pn` is the length of the one being left. Reading these from
        // `pending` rather than from `self` is what keeps the two cases —
        // stepping and not stepping — on one code path with one commit point.
        let (ck, n, pn, epoch, dh) = match pending.as_ref() {
            Some(step) => (
                step.ck_send.clone(),
                0,
                self.ratchet.ns,
                step.epoch,
                step.dh_self.public_key(),
            ),
            None => (
                self.ratchet
                    .ck_send
                    .as_ref()
                    .ok_or(ProtocolError::Malformed)?
                    .clone(),
                self.ratchet.ns,
                self.ratchet.pn,
                self.ratchet.send_epoch,
                self.ratchet
                    .dh_self
                    .as_ref()
                    .ok_or(ProtocolError::Malformed)?
                    .public_key(),
            ),
        };
        let next_ns = n.checked_add(1).ok_or(ProtocolError::Internal)?;

        // M1 §G.3's clone-to-plan, on the sending side: the chain key advances
        // in a local, and the original is replaced only at the commit below.
        let (next_ck, mk) = ck.step();

        let nonce: Nonce192 = entropy.nonce();
        let wire_nonce = WireNonce::from_bytes(*nonce.as_bytes());
        let step = pending.as_ref().map(|p| p.step.clone());

        // The AAD binds `canonical(RatchetMessage without "ct")` (M1 §D.3), so
        // it is computed from a message carrying no ciphertext yet and is
        // unchanged by filling one in.
        let header = build_message(*dh.as_bytes(), n, pn, &wire_nonce, step.clone(), Vec::new())?;
        let aad = header.aad(epoch, &self.local, &self.remote)?;
        let ct = mk.seal(nonce, plaintext, Aad::new(&aad));
        let msg = build_message(
            *dh.as_bytes(),
            n,
            pn,
            &wire_nonce,
            step,
            ct.as_bytes().to_vec(),
        )?;
        // The last thing that can fail, and the reason the commit is below it
        // rather than above: `Frame::seal` refuses a payload over
        // `MAX_FRAME_PAYLOAD`, which a chain-opening message (`ek` + `kc`)
        // reaches ~3 KB sooner than the rest of its chain.
        let frame = Frame::seal(
            epoch,
            MsgType::Message,
            msg.encode()?.into_vec(),
            &self.frame_send,
        )?;

        // COMMIT. Nothing below this line can fail, and nothing above it wrote
        // to `self`.
        if let Some(step) = pending {
            // Assigning over `root` supersedes and drops the old one — the
            // obligation `RootKey::ratchet_preview` puts on its caller.
            self.ratchet.root = step.root;
            self.ratchet.dh_self = Some(step.dh_self);
            self.ratchet.kem_self = Some(step.kem_self);
            self.ratchet.pn = pn;
            self.ratchet.send_epoch = epoch;
            self.ratchet.ratchet_due = false;
        }
        self.ratchet.ck_send = Some(next_ck);
        self.ratchet.ns = next_ns;

        Ok(frame)
    }

    /// Seals a payload-free keepalive (spec M1 §A.2).
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] never in practice: `ACK` carries no
    /// payload, which is the only thing [`Frame::seal`] rejects for this type.
    pub fn ack(&self) -> Result<Frame, ProtocolError> {
        Frame::seal(
            self.ratchet.send_epoch,
            MsgType::Ack,
            Vec::new(),
            &self.frame_send,
        )
    }

    /// One sending DH ratchet step, computed but **not** committed
    /// (spec M1 §D.2).
    ///
    /// Takes `&self`, so it cannot write to the session even by accident;
    /// [`Session::send`] commits the result, or drops it, in one place. The
    /// root step itself is [`mlkb_crypto::RootKey::ratchet_preview`], which is
    /// what makes a `&self` signature possible here at all.
    fn plan_root_step<E: Entropy + ?Sized>(
        &self,
        entropy: &mut E,
    ) -> Result<PendingStep, ProtocolError> {
        let dh_remote = self
            .ratchet
            .dh_remote
            .as_ref()
            .ok_or(ProtocolError::Malformed)?;
        let kem_remote = self
            .ratchet
            .kem_remote
            .as_ref()
            .ok_or(ProtocolError::Malformed)?;

        let dh_self = entropy.x25519_secret();
        let dh_out = x25519_dh(&dh_self, dh_remote)?;
        let kem_self = entropy.kem_keypair();
        let ek = kem_self.encapsulation_key().to_wire();
        let (kc, kem_ss) = entropy.encapsulate(kem_remote);

        let (root, ck_send) = self.ratchet.root.ratchet_preview(&dh_out, &kem_ss);
        let epoch = self
            .ratchet
            .send_epoch
            .checked_add(1)
            .ok_or(ProtocolError::Internal)?;

        Ok(PendingStep {
            root,
            ck_send,
            dh_self,
            kem_self,
            epoch,
            step: RatchetStep {
                ek: Box::new(ek),
                kc: Box::new(*kc.as_bytes()),
            },
        })
    }
}

/// A sending root step that has been computed and not yet committed
/// (spec M1 §D.2; see [`Session::send`]'s atomicity note).
///
/// Every field here is a *replacement* for a field of
/// [`crate::ratchet::RatchetState`]; holding them together is what lets `send`
/// have exactly one commit point, after the last fallible call. Dropping one
/// of these costs the entropy that went into it and nothing else — no chain
/// was advanced, no root key superseded, no epoch consumed.
struct PendingStep {
    /// The previewed successor root key (see
    /// [`mlkb_crypto::RootKey::ratchet_preview`]).
    root: RootKey,
    /// The new sending chain, before its first step.
    ck_send: ChainKey,
    /// The fresh X25519 ratchet secret, published as `"dh"`.
    dh_self: X25519SecretKey,
    /// The fresh ML-KEM-1024 keypair, whose public half is published as
    /// `"ek"`.
    kem_self: KemDecapsulationKey,
    /// The epoch this step moves the sending chain to.
    epoch: u64,
    /// The M1 §D.3 `"ek"`/`"kc"` pair, for the `n == 0` message.
    step: RatchetStep,
}

/// Builds the M1 §D.3 message, choosing the constructor the pairing rule
/// allows: `chain_start` fixes `n = 0` and carries the step, `in_chain` takes a
/// [`NonZeroU64`] and carries none. There is no third shape, so this cannot
/// emit a message the decoder would refuse.
fn build_message(
    dh: [u8; 32],
    n: u64,
    pn: u64,
    nonce: &WireNonce,
    step: Option<RatchetStep>,
    ct: Vec<u8>,
) -> Result<RatchetMessage, ProtocolError> {
    match (NonZeroU64::new(n), step) {
        (None, Some(step)) => Ok(RatchetMessage::chain_start(dh, pn, nonce.clone(), step, ct)),
        (Some(n), None) => Ok(RatchetMessage::in_chain(dh, n, pn, nonce.clone(), ct)),
        // `n == 0` without a step, or `n != 0` with one: M1 §D.3 forbids both,
        // and the send path never constructs either.
        _ => Err(ProtocolError::Internal),
    }
}
