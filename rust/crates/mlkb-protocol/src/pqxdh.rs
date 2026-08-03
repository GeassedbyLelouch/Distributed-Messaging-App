//! PQXDH — the handshake (spec M1 §C.1, §C.2, §C.3, parent §4.1, §4.2, §4.3).
//!
//! # The legs, in one place
//!
//! Spec M1 §C.1 pins them, with **A = initiator, B = responder**. Both sides
//! compute the same four values from opposite ends of each pair, and neither
//! side spells the order: [`mlkb_crypto::DhLegs`] fixes it, and its arity is
//! fixed at construction from `opk_id`, so `DH4` cannot be zero-filled into an
//! `ikm` it does not belong in.
//!
//! # What is verified, and when
//!
//! Parent §4.3: **every signature in a bundle is verified before any key in it
//! is used.** [`verify_bundle`] runs before the first
//! [`mlkb_crypto::x25519_dh`] call in [`initiate`], not after.
//!
//! Two verifications deliberately do **not** happen here:
//!
//! - **`EnrolmentProof`.** Its issuer keys ship as a pinned set in the client
//!   binary and selection is `mlkb-policy`'s (M1 §F); its expiry needs a clock,
//!   which parent §11 gate 6 forbids this crate.
//! - **`PrekeyBundleV2::expires_at_ms`.** Same reason: `BUNDLE_MAX_AGE_MS`
//!   (M1 §I) is compared by the caller, which owns the clock.
//!
//! # The responder reads the payload before the MAC, and why that is safe
//!
//! `K_frame_i2r` is derived from `SK`, and `SK` cannot be computed without the
//! contents of `InitialMessageV2` — so on first contact the frame MAC is not
//! checkable first. [`respond`] therefore takes a **length-directed slice** of
//! the payload (bounds enforced by [`Frame::wire_len_of`], which validates the
//! version and `MAX_FRAME_PAYLOAD` without allocating and without looking at
//! `msg_type`), derives `SK` from it, and only then calls [`Frame::decode`],
//! which re-parses those same bytes and verifies the tag. Nothing is dispatched
//! on the unauthenticated type byte — M1 §A.1 rule 6 — and nothing is committed
//! until both the frame MAC and the parent §4.2 confirmation tag have verified.

use mlkb_crypto::{
    DhLegs, KemCiphertext, KemDecapsulationKey, KemEncapsulationKey, Mac256, MlDsaVerifyingKey,
    SkInfo, X25519PublicKey, X25519SecretKey, derive_sk, x25519_dh,
};
use mlkb_secrets::{Progress, ProtocolError};
use mlkb_wire::{
    FRAME_HEADER_LEN, FRAME_MAC_LEN, Frame, IdentityId, InitialMessageV2, MsgType, PrekeyBundleV2,
    SignedPqPrekey, SignedPrekey,
};

use crate::entropy::Entropy;
use crate::session::{Ends, RatchetKeys, Role, Session};

/// The frame epoch a handshake is sent under (spec M1 §A.3).
///
/// A sending chain's DH-ratchet generation, and no ratchet step has happened
/// yet. The initiator's first *application* message is generation 1.
const HANDSHAKE_EPOCH: u64 = 0;

/// This device's long-term identity (spec parent §3.5, §4.1).
///
/// Holds the X25519 identity **secret**, because M1 §C.1's `DH1` (initiator)
/// and `DH2` (responder) are computed under it. The ML-DSA-65 key is present
/// only as its `SHA-256`: M1's handshake carries no signature by the
/// initiator, so nothing here needs to sign, and parent §3.4's decision not to
/// put the 1952-byte key on the wire is what makes `IdentityId` computable
/// from `InitialMessageV2` alone.
pub struct LocalIdentity {
    ik: X25519SecretKey,
    ik_mldsa_hash: [u8; 32],
    id: IdentityId,
}

/// No secret is printable, and the identity already is.
impl core::fmt::Debug for LocalIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalIdentity")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl LocalIdentity {
    /// Binds an X25519 identity secret to the hash of its ML-DSA-65 public key
    /// (spec parent §3.5).
    #[must_use]
    pub fn new(ik: X25519SecretKey, ik_mldsa_hash: [u8; 32]) -> Self {
        let id = IdentityId::from_ik(ik.public_key().as_bytes(), &ik_mldsa_hash);
        Self {
            ik,
            ik_mldsa_hash,
            id,
        }
    }

    /// This device's identity (spec parent §3.5).
    #[must_use]
    pub fn id(&self) -> IdentityId {
        self.id
    }
}

/// The private halves of the prekeys a responder published
/// (spec parent §4.3, M1 §C.1, §C.3).
///
/// Every id is carried alongside its key so that [`respond`] can refuse a
/// message naming one it does not hold. M1 §C.3: an unknown `pqspk_id`, or one
/// whose private key has been erased, is [`ProtocolError::Malformed`].
pub struct ResponderPrekeys<'a> {
    /// The device this responder is, checked against `to_device_id`
    /// (spec M1 §C.3).
    pub device_id: u32,
    /// The signed-prekey id and its X25519 secret.
    pub spk: (u32, &'a X25519SecretKey),
    /// The PQ-prekey id and its ML-KEM-1024 secret (spec M1 §C.3).
    pub pqspk: (u32, &'a KemDecapsulationKey),
    /// The claimed one-time prekey, if the initiator claimed one.
    ///
    /// M1 §C.1: `DH4` is present **iff** `InitialMessageV2.opk_id` is present,
    /// so a mismatch between this field and that one is refused rather than
    /// papered over — the arity of the `ikm` is not negotiable.
    pub opk: Option<(u32, &'a X25519SecretKey)>,
}

impl core::fmt::Debug for ResponderPrekeys<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponderPrekeys")
            .field("device_id", &self.device_id)
            .field("spk_id", &self.spk.0)
            .field("pqspk_id", &self.pqspk.0)
            .field("opk_id", &self.opk.map(|(id, _)| id))
            .finish_non_exhaustive()
    }
}

/// The initiator's side of a completed handshake.
#[derive(Debug)]
pub struct Initiated {
    /// The established session.
    pub session: Session,
    /// The `0x01` frame to send (spec M1 §A.2).
    pub initial: Frame,
}

/// The responder's side of a completed handshake.
#[derive(Debug)]
pub struct Accepted {
    /// The established session.
    pub session: Session,
    /// `handshake_seq`, for parent §6.3's replay floor. The caller feeds it to
    /// [`crate::HandshakeGuard`] together with
    /// [`Session::session_id`](crate::Session::session_id).
    pub handshake_seq: u64,
}

/// Verifies every signature in a prekey bundle (spec parent §4.3, M1 §E.2).
///
/// Both prekeys are signed by the bundle owner's *hybrid* identity, so both
/// legs of each signature must verify (parent §3.6) and each is checked under
/// its own context (M1 §E.2) — which is what stops a signed X25519 prekey
/// being lifted into the PQ-prekey slot.
///
/// # Errors
/// [`ProtocolError::Unauthenticated`] if either signature fails;
/// [`ProtocolError::Internal`] on an encoding fault.
pub fn verify_bundle(bundle: &PrekeyBundleV2) -> Result<(), ProtocolError> {
    let id = bundle.identity_id();
    let ik = X25519PublicKey::from_bytes(bundle.identity.ik_x25519);
    let ml = MlDsaVerifyingKey::from_wire(&bundle.identity.ik_mldsa);

    bundle.signed_prekey.signature.verify(
        &ik,
        &ml,
        SignedPrekey::CONTEXT,
        id.as_bytes(),
        bundle.signed_prekey.signed_payload()?.as_bytes(),
    )?;
    bundle.pq_prekey.signature.verify(
        &ik,
        &ml,
        SignedPqPrekey::CONTEXT,
        id.as_bytes(),
        bundle.pq_prekey.signed_payload()?.as_bytes(),
    )?;
    Ok(())
}

/// Runs PQXDH as the initiator (spec M1 §C.1, §C.3, parent §4.1, §4.2).
///
/// ```text
/// DH1 = X25519(IK_A_priv, SPK_B)      DH3 = X25519(EK_A_priv, SPK_B)
/// DH2 = X25519(EK_A_priv, IK_B)       DH4 = X25519(EK_A_priv, OPK_B)  iff opk
/// ikm = F || DH1 || DH2 || DH3 [|| DH4] || KEM_SS
/// ```
///
/// # Errors
/// - [`ProtocolError::Unauthenticated`] if a bundle signature fails, or if a
///   DH leg is non-contributory (M1 §C.2).
/// - [`ProtocolError::Malformed`] if a bundle key is not a valid point or a
///   valid ML-KEM encapsulation key (M1 §C.2).
/// - [`ProtocolError::Internal`] on an encoding fault.
pub fn initiate<E: Entropy + ?Sized>(
    local: &LocalIdentity,
    bundle: &PrekeyBundleV2,
    to_device_id: u32,
    handshake_seq: u64,
    entropy: &mut E,
) -> Result<Initiated, ProtocolError> {
    // Parent §4.3, and it is the first thing that happens.
    verify_bundle(bundle)?;

    let remote_id = bundle.identity_id();
    let ik_b = X25519PublicKey::from_bytes(bundle.identity.ik_x25519);
    let spk_b = X25519PublicKey::from_bytes(bundle.signed_prekey.public);

    let ek = entropy.x25519_secret();
    let dh1 = x25519_dh(&local.ik, &spk_b)?;
    let dh2 = x25519_dh(&ek, &ik_b)?;
    let dh3 = x25519_dh(&ek, &spk_b)?;
    let (legs, opk_id) = match bundle.one_time.as_ref() {
        Some(opk) => {
            let dh4 = x25519_dh(&ek, &X25519PublicKey::from_bytes(opk.public))?;
            (DhLegs::with_opk(dh1, dh2, dh3, dh4), Some(opk.id))
        }
        None => (DhLegs::without_opk(dh1, dh2, dh3), None),
    };

    let kem_remote = KemEncapsulationKey::from_wire(&bundle.pq_prekey.ek)?;
    let (kem_ct, kem_ss) = entropy.encapsulate(&kem_remote);

    let root = derive_sk(
        legs,
        kem_ss,
        &SkInfo::new(local.id.as_bytes(), remote_id.as_bytes()),
    );

    // Parent §4.2: the tag is computed over `canonical(InitialMessageV2
    // without confirm)`, so the placeholder below is not in its preimage and
    // its value cannot matter.
    let mut message = InitialMessageV2 {
        to_device_id,
        handshake_seq,
        ik_x25519: *local.ik.public_key().as_bytes(),
        ik_mldsa_hash: local.ik_mldsa_hash,
        ek_x25519: *ek.public_key().as_bytes(),
        kem_ct: alloc::boxed::Box::new(*kem_ct.as_bytes()),
        spk_id: bundle.signed_prekey.id,
        pqspk_id: bundle.pq_prekey.id,
        opk_id,
        confirm: [0u8; 32],
    };
    message.confirm = *root
        .confirm_tag(message.confirm_preimage()?.as_bytes())
        .as_bytes();

    let initial = Frame::seal(
        HANDSHAKE_EPOCH,
        MsgType::Initial,
        message.encode()?.into_vec(),
        &root.derive_frame_key(mlkb_crypto::FrameDirection::InitiatorToResponder),
    )?;

    let session = Session::new(
        Role::Initiator,
        Ends {
            local: local.id,
            remote: remote_id,
        },
        root,
        RatchetKeys {
            // M1 §D.2: the initiator generates its ratchet keypairs on its
            // first send. What it has now is the responder's published pair.
            dh_self: None,
            dh_remote: Some(spk_b),
            kem_self: None,
            kem_remote: Some(kem_remote),
        },
    );

    Ok(Initiated { session, initial })
}

/// Runs PQXDH as the responder (spec M1 §C.1, §C.3, parent §4.2).
///
/// `wire` is one complete `0x01` frame. See the module documentation for why
/// this function reads the payload before the frame MAC and why that is safe.
///
/// # Errors
/// - [`ProtocolError::Malformed`] for a frame that is not exactly one frame,
///   a payload that is not a well-formed `InitialMessageV2`, a `to_device_id`
///   / `spk_id` / `pqspk_id` / `opk_id` this responder does not hold, a
///   `msg_type` other than `INITIAL`, an epoch other than the handshake's, or
///   a peer key that fails M1 §C.2's point validation.
/// - [`ProtocolError::Unauthenticated`] if the frame MAC fails, if the parent
///   §4.2 confirmation tag fails, or if a DH leg is non-contributory.
pub fn respond(
    local: &LocalIdentity,
    prekeys: &ResponderPrekeys<'_>,
    wire: &[u8],
) -> Result<Progress<Accepted>, ProtocolError> {
    let Progress::Complete(total) = Frame::wire_len_of(wire)? else {
        return Ok(Progress::NeedMore);
    };
    if wire.len() < total {
        return Ok(Progress::NeedMore);
    }
    // M1 §A.1 rule 4: no trailing bytes. `Frame::decode` enforces it too; this
    // is here because the slice below must not straddle a second frame.
    if wire.len() > total {
        return Err(ProtocolError::Malformed);
    }
    let payload_end = total
        .checked_sub(FRAME_MAC_LEN)
        .ok_or(ProtocolError::Malformed)?;
    let payload = wire
        .get(FRAME_HEADER_LEN..payload_end)
        .ok_or(ProtocolError::Malformed)?;

    let message = InitialMessageV2::decode(payload)?;

    // Every selector, before any key is used.
    if message.to_device_id != prekeys.device_id
        || message.spk_id != prekeys.spk.0
        || message.pqspk_id != prekeys.pqspk.0
    {
        return Err(ProtocolError::Malformed);
    }
    // M1 §C.1: the arity of the `ikm` follows `opk_id` exactly.
    let opk = match (message.opk_id, prekeys.opk) {
        (None, _) => None,
        (Some(claimed), Some((held, key))) if claimed == held => Some(key),
        (Some(_), _) => return Err(ProtocolError::Malformed),
    };

    let initiator_id = message.identity_id();
    let ik_a = X25519PublicKey::from_bytes(message.ik_x25519);
    let ek_a = X25519PublicKey::from_bytes(message.ek_x25519);

    let dh1 = x25519_dh(prekeys.spk.1, &ik_a)?;
    let dh2 = x25519_dh(&local.ik, &ek_a)?;
    let dh3 = x25519_dh(prekeys.spk.1, &ek_a)?;
    let legs = match opk {
        Some(opk) => DhLegs::with_opk(dh1, dh2, dh3, x25519_dh(opk, &ek_a)?),
        None => DhLegs::without_opk(dh1, dh2, dh3),
    };

    let kem_ss = prekeys
        .pqspk
        .1
        .decapsulate(&KemCiphertext::from_wire(*message.kem_ct));

    let root = derive_sk(
        legs,
        kem_ss,
        &SkInfo::new(initiator_id.as_bytes(), local.id.as_bytes()),
    );

    // Now the frame MAC, under a key only a party that computed `SK` could
    // have derived.
    let frame_key = root.derive_frame_key(mlkb_crypto::FrameDirection::InitiatorToResponder);
    let Progress::Complete(frame) = Frame::decode(wire, &frame_key)? else {
        return Err(ProtocolError::Malformed);
    };
    if frame.msg_type() != MsgType::Initial || frame.epoch() != HANDSHAKE_EPOCH {
        return Err(ProtocolError::Malformed);
    }

    // Parent §4.2. `confirm` proves the sender computed `SK`; the security
    // note there is exact about what it does *not* prove.
    root.verify_confirm_tag(
        message.confirm_preimage()?.as_bytes(),
        &Mac256::from_bytes(message.confirm),
    )?;

    let spk_self = duplicate_x25519(prekeys.spk.1);
    let pqspk_self = duplicate_kem(prekeys.pqspk.1);

    let session = Session::new(
        Role::Responder,
        Ends {
            local: local.id,
            remote: initiator_id,
        },
        root,
        RatchetKeys {
            // M1 §D.2: the responder's initial ratchet keys *are* the prekeys
            // the initiator encapsulated and DH'd to. It learns the
            // initiator's on the first application message.
            dh_self: Some(spk_self),
            dh_remote: None,
            kem_self: Some(pqspk_self),
            kem_remote: None,
        },
    );

    Ok(Progress::Complete(Accepted {
        session,
        handshake_seq: message.handshake_seq,
    }))
}

/// Copies a long-lived prekey secret into the session that will keep it.
///
/// A signed prekey serves many sessions, so the caller keeps the original; the
/// session needs its own because M1 §D.2 makes it the responder's first
/// `dh_self`. `mlkb-crypto` exposes no `Clone` on either key type, and the
/// round-trip through the serialized form it *does* expose is the only route —
/// which is exactly the route `mlkb-store` uses to reload one (parent §9), so
/// this introduces no representation the project did not already have.
fn duplicate_x25519(key: &X25519SecretKey) -> X25519SecretKey {
    X25519SecretKey::from_bytes(*key.to_secret().expose_secret())
}

/// The ML-KEM twin of [`duplicate_x25519`], through the 64-byte FIPS-203
/// `(d, z)` seed that parent §9 already stores.
fn duplicate_kem(key: &KemDecapsulationKey) -> KemDecapsulationKey {
    KemDecapsulationKey::from_seed(&key.to_seed())
}
