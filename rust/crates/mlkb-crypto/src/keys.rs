//! The typed keys and the key schedule (spec M1 §G.1, parent §4.1, §8.2,
//! M1 §D.2).
//!
//! # The invariant this module exists for
//!
//! Spec parent §4.1: it must be impossible to write code that derives a root
//! key without a real ML-KEM output. That is enforced here by three facts
//! together, and it survives only if all three hold:
//!
//! 1. [`KemSharedSecret`] has no public constructor. The only values of that
//!    type in the universe come out of [`crate::KemEncapsulationKey::encapsulate`]
//!    or [`crate::KemDecapsulationKey::decapsulate`].
//! 2. [`derive_sk`] takes one **by value**. Not `Option`, not `&[u8; 32]` — a
//!    byte reference would let a caller pass zeros and silently satisfy "the
//!    KEM leg is present".
//! 3. [`derive_sk`] is the **only** constructor of [`RootKey`], and
//!    [`RootKey::ratchet`] — which likewise consumes a `KemSharedSecret` by
//!    value — is the only other way a `RootKey` comes into existence.
//!
//! Spec M1 §G.1 records why these types live in `mlkb-crypto` rather than in
//! `mlkb-secrets` as parent §7's table says: Rust cannot grant exactly one
//! *other* crate privileged construction, and the invariant outranks the
//! layout.

use core::fmt;

use mlkb_secrets::{Secret32, SecretBytes};

use crate::hash::{Mac256, Prk, hmac_sha256};
use crate::labels;
use crate::util::copy_prefix;

/// The 32-byte `F` prefix of the PQXDH `ikm` (spec parent §4.1).
const F_PREFIX: [u8; 32] = [0xFF; 32];

/// The all-zero HKDF salt of the PQXDH extract (spec parent §4.1).
const ZERO_SALT: [u8; 32] = [0x00; 32];

/// The chain-step constant that derives a message key (spec M1 §D.2).
const CHAIN_MK: [u8; 1] = [0x01];

/// The chain-step constant that advances the chain (spec M1 §D.2).
const CHAIN_CK: [u8; 1] = [0x02];

/// Writes a redacting `Debug` for a typed key (spec M1 §G.1).
macro_rules! redacted_debug {
    ($t:ty, $name:literal) => {
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!($name, "([REDACTED])"))
            }
        }
    };
}

// ---------------------------------------------------------------------------
// KemSharedSecret — the PQ leg, made structural (spec parent §4.1)
// ---------------------------------------------------------------------------

/// An ML-KEM-1024 shared secret (spec parent §4.1, M1 §G.1).
///
/// **No public constructor.** Obtainable only from
/// [`crate::KemEncapsulationKey::encapsulate`] and
/// [`crate::KemDecapsulationKey::decapsulate`], and consumed by value by
/// [`derive_sk`] and [`RootKey::ratchet`]. Not `Clone`: one encapsulation
/// contributes to exactly one derivation.
///
/// [`RootKey::ratchet_preview`] takes one by reference rather than by value.
/// That is not a hole in the above: the missing constructor is what makes the
/// PQ leg unforgeable, and a reference cannot be conjured any more than a
/// value can. See that method for the obligation the borrow moves onto the
/// caller.
pub struct KemSharedSecret(Secret32);

redacted_debug!(KemSharedSecret, "KemSharedSecret");

impl KemSharedSecret {
    /// Mints a shared secret from a real ML-KEM operation.
    ///
    /// Crate-private on purpose: this is the whole of spec parent §4.1's
    /// structural claim. Do not make it `pub`, and do not add a
    /// `From<[u8; 32]>`.
    pub(crate) fn from_kem(secret: Secret32) -> Self {
        Self(secret)
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

// ---------------------------------------------------------------------------
// DhOutput / DhLegs (spec M1 §C.1)
// ---------------------------------------------------------------------------

/// One X25519 Diffie-Hellman output (spec M1 §C.1, §C.2).
///
/// **No public constructor.** Obtainable only from [`crate::x25519_dh`], which
/// is the single DH site in the crate and always performs both fail-closed
/// checks of spec M1 §C.2. Not `Clone`: a leg is consumed by exactly one
/// derivation.
pub struct DhOutput(Secret32);

redacted_debug!(DhOutput, "DhOutput");

impl DhOutput {
    /// Mints a DH output. Crate-private: see [`crate::x25519_dh`].
    pub(crate) fn from_dh(secret: Secret32) -> Self {
        Self(secret)
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// The ordered X25519 legs of one PQXDH run (spec parent §4.1, M1 §C.1).
///
/// The arity is fixed at construction from whether a one-time prekey was
/// used, and there is no way to change it afterwards. `DH4` is **omitted from
/// the `ikm` entirely** when no OPK was used — it is never zero-filled — which
/// is what makes the two `ikm` shapes unambiguous even though neither carries
/// a length prefix.
///
/// The leg definitions themselves (spec M1 §C.1, A = initiator, B =
/// responder) are the caller's to satisfy; this type pins only the order and
/// the arity.
#[derive(Debug)]
pub struct DhLegs {
    dh1: DhOutput,
    dh2: DhOutput,
    dh3: DhOutput,
    dh4: Option<DhOutput>,
}

impl DhLegs {
    /// The three-leg form, used when the bundle carried no one-time prekey
    /// (spec M1 §C.1).
    #[must_use]
    pub fn without_opk(dh1: DhOutput, dh2: DhOutput, dh3: DhOutput) -> Self {
        Self {
            dh1,
            dh2,
            dh3,
            dh4: None,
        }
    }

    /// The four-leg form, used when a one-time prekey was claimed
    /// (spec M1 §C.1).
    #[must_use]
    pub fn with_opk(dh1: DhOutput, dh2: DhOutput, dh3: DhOutput, dh4: DhOutput) -> Self {
        Self {
            dh1,
            dh2,
            dh3,
            dh4: Some(dh4),
        }
    }

    /// How many legs this value carries: 3 or 4 (spec M1 §C.1).
    #[must_use]
    pub fn arity(&self) -> usize {
        if self.dh4.is_some() { 4 } else { 3 }
    }
}

/// The identity binding of the PQXDH info string (spec parent §4.1).
///
/// Identity ordering is initiator-then-responder on both sides; binding both
/// identities into `info` is what defeats unknown-key-share. The values are
/// `IdentityId`s (spec parent §3.5), which this crate treats as opaque
/// 32-byte strings — `mlkb-wire` owns their computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkInfo {
    initiator: [u8; 32],
    responder: [u8; 32],
}

impl SkInfo {
    /// Binds an initiator and a responder identity, in that order
    /// (spec parent §4.1).
    #[must_use]
    pub fn new(initiator: &[u8; 32], responder: &[u8; 32]) -> Self {
        Self {
            initiator: *initiator,
            responder: *responder,
        }
    }
}

// ---------------------------------------------------------------------------
// RootKey (spec parent §4.1, §8.2, M1 §D.2)
// ---------------------------------------------------------------------------

/// The session root key (spec parent §4.1, §8.2).
///
/// Constructed only by [`derive_sk`] and [`RootKey::ratchet`]. Not `Clone`:
/// a root key is either expanded into the §4.4 label table or consumed by a
/// ratchet step, and keeping a copy of a superseded root key would defeat the
/// forward secrecy the ratchet exists for.
///
/// # `SK` does not leave this type, and that is what makes the above true
///
/// Non-`Clone` on its own buys nothing if some accessor hands out the bytes:
/// a caller that can copy `SK` out can recompute, after the ratchet has
/// "consumed" the root key, everything the root key could ever have computed,
/// and the forward-secrecy rationale in the paragraph above becomes a comment
/// rather than a property. So:
///
/// - the field is private and there is **no** accessor for it — no
///   `as_secret`, no `expose_secret`, no `Into<[u8; 32]>`;
/// - there is **no** `as_prk`. [`Prk`] is `Clone` and [`Prk::as_secret`] hands
///   out a `&Secret32` that is `Clone` too, so a PRK view of `SK` *is* a copy
///   of `SK` with extra steps. Returning one would have re-opened exactly the
///   hole the missing `Clone` closes;
/// - the one thing that *does* take `SK` as a subject —
///   [`RootKey::verify_sk_kat`], which parent §5.3's known-answer tests need —
///   is a constant-time **verifier**, not a reader. It answers a 256-bit
///   guess; it does not produce one.
///
/// # The §4.4 label set is closed *because* of that
///
/// Every derivation from `SK` is a **named method on this type**, each pinned
/// to one constant in [`crate::labels`]:
///
/// | method | label |
/// |---|---|
/// | [`RootKey::derive_frame_key`] | `MLKEMBraid/frame/{i2r,r2i}/v2` |
/// | [`RootKey::derive_session_id`] | `MLKEMBraid/sid/v2` |
/// | [`RootKey::confirm_tag`] / [`RootKey::verify_confirm_tag`] | `MLKEMBraid/pqxdh/confirm/v2` |
///
/// That table is the whole of parent §4.4 as it applies to `SK`, and it is
/// enforced rather than documented: with no way to obtain a [`Prk`] over `SK`,
/// no crate can reach [`Prk::expand`] with an `info` of its own choosing, so
/// the unbounded family of keys derivable from `SK` under unregistered labels
/// does not exist. Adding a §4.4 derivation means adding a method here and a
/// constant to [`crate::labels`] — a diff a reviewer can see — not passing a
/// new byte string at a call site.
///
/// `K_chunk` (parent §4.4, [`crate::labels::ERASURE_CHUNK`]) is M2-only and
/// deliberately has no method yet: when the erasure-share layer lands it gets a
/// named derivation here like the rest, not a general escape hatch.
///
/// `K_store` (M1 §G.5) is **not** derived from `SK` and must not be: the store
/// outlives every session, so binding it to one session's root key would make
/// stored blobs unopenable after a ratchet step. It comes from `mlkb-store`'s
/// own master PRK through [`crate::StoreKey::derive`].
pub struct RootKey(Secret32);

redacted_debug!(RootKey, "RootKey");

/// Which direction a frame key protects (spec parent §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameDirection {
    /// `K_frame_i2r` — initiator to responder.
    InitiatorToResponder,
    /// `K_frame_r2i` — responder to initiator.
    ResponderToInitiator,
}

impl FrameDirection {
    fn label(self) -> &'static [u8] {
        match self {
            Self::InitiatorToResponder => labels::FRAME_I2R,
            Self::ResponderToInitiator => labels::FRAME_R2I,
        }
    }
}

/// Derives the PQXDH root key `SK` (spec parent §4.1, M1 §C.1).
///
/// ```text
/// ikm  = F || DH1 || DH2 || DH3 [|| DH4] || KEM_SS      F = 0xFF * 32
/// salt = 0x00 * 32
/// info = "MLKEMBraid/pqxdh/v2" || IdentityId_A || IdentityId_B
/// len  = 32
/// ```
///
/// Both secret arguments are consumed. See the module docs for why the
/// `kem_ss` parameter is by value and why this is the only constructor of
/// [`RootKey`].
// The two secret arguments are by value on purpose and the body only reads
// them: taking them by reference is exactly what spec parent §4.1 forbids, so
// `needless_pass_by_value` is wrong here.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn derive_sk(legs: DhLegs, kem_ss: KemSharedSecret, info: &SkInfo) -> RootKey {
    let prk = match legs.dh4.as_ref() {
        Some(dh4) => Prk::extract(
            Some(&ZERO_SALT),
            &[
                &F_PREFIX,
                legs.dh1.bytes(),
                legs.dh2.bytes(),
                legs.dh3.bytes(),
                dh4.bytes(),
                kem_ss.bytes(),
            ],
        ),
        None => Prk::extract(
            Some(&ZERO_SALT),
            &[
                &F_PREFIX,
                legs.dh1.bytes(),
                legs.dh2.bytes(),
                legs.dh3.bytes(),
                kem_ss.bytes(),
            ],
        ),
    };
    RootKey(prk.expand_secret::<32>(&[labels::SK_INFO_PREFIX, &info.initiator, &info.responder]))
}

impl RootKey {
    /// One hybrid DH + ML-KEM ratchet step (spec M1 §D.2).
    ///
    /// ```text
    /// (RK', CK) = HKDF-SHA256(ikm  = dh_out || kem_ss,
    ///                         salt = RK,
    ///                         info = "MLKEMBraid/ratchet/root/v2",
    ///                         len  = 64)          split 32 || 32
    /// ```
    ///
    /// Consumes the old root key, so a superseded `RK` cannot be re-used, and
    /// consumes the [`KemSharedSecret`] by value, so the PQ leg is
    /// structurally impossible to omit from a ratchet step — spec parent
    /// §4.1's invariant, one layer up.
    ///
    /// This is [`RootKey::ratchet_preview`] plus the consumption of the two
    /// inputs; the schedule itself is written down exactly once, there.
    // By value for the reason `derive_sk`'s arguments are; see the note there.
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn ratchet(self, dh_out: DhOutput, kem_ss: KemSharedSecret) -> (RootKey, ChainKey) {
        self.ratchet_preview(&dh_out, &kem_ss)
    }

    /// The same root step as [`RootKey::ratchet`], computed **without**
    /// consuming this root key (spec M1 §D.2; parent §8.1).
    ///
    /// # Why a non-consuming form has to exist
    ///
    /// Parent §8.1 requires a receiver to authenticate *before* it mutates.
    /// The receiving root step is the one place where that was impossible to
    /// honour: `mlkb_protocol::Session::classify` holds `&self`, `ratchet`
    /// consumes `self`, and [`RootKey`] is deliberately not `Clone` — so the
    /// prospective receiving chain key could not be derived until after the
    /// root key had already been moved out and replaced. The AEAD therefore
    /// landed *after* the root step, and a MAC-valid frame with a bogus
    /// ciphertext permanently desynchronised the receiver.
    ///
    /// That was not merely a "party who knows `SK`" problem. `K_frame_dir`
    /// (parent §3.3) never ratchets, so an attacker who held `SK` **once** and
    /// then lost access retained a one-frame permanent-denial primitive
    /// *past* the post-compromise-security boundary the ratchet exists to
    /// establish. Parent §3.3 disclaims PCS for frame **authentication**; it
    /// does not license a MAC-only-authenticated frame to advance the **root**
    /// ratchet. This method is what lets `classify` derive the prospective
    /// chain key, run the AEAD, and hand `apply` a state transition that is
    /// already known to be genuine.
    ///
    /// # Why it does not weaken parent §4.1
    ///
    /// The §4.1 invariant is that no root key can be *minted* without a real
    /// ML-KEM output, and that no ratchet step can omit the PQ leg. Both still
    /// hold:
    ///
    /// - [`derive_sk`] remains the only way to produce a `RootKey` from
    ///   nothing. This method needs an existing `RootKey` as its receiver, so
    ///   it cannot start a key schedule.
    /// - It still requires a [`KemSharedSecret`], which has no public
    ///   constructor — the only values of that type come out of a real
    ///   encapsulation or decapsulation. A `&` here is not a loosening: there
    ///   is no way to *conjure* the referent, and a caller holding one by
    ///   value could pass it to `ratchet` anyway. What by-value buys in
    ///   `ratchet` — one encapsulation, one derivation — is bought here by the
    ///   caller's obligation below.
    /// - The DH leg is likewise a [`DhOutput`], obtainable only from
    ///   [`crate::x25519_dh`] and therefore only after M1 §C.2's fail-closed
    ///   checks.
    ///
    /// # The caller's obligation
    ///
    /// A preview leaves the old root key alive, so the forward secrecy that
    /// `ratchet`'s consuming signature enforces becomes the caller's to
    /// enforce here: **on commit, overwrite the old root key with the returned
    /// one, and on abandon, drop the returned one.** Keeping both is a
    /// retained superseded `RK`. `mlkb-protocol` discharges this by assigning
    /// straight over its single `RootKey` field, so no second root key is ever
    /// reachable — and by planning against `&self` in `classify`, which cannot
    /// store anything at all.
    ///
    /// Because the step is a pure function of `(RK, dh_out, kem_ss)`, previewing
    /// and then committing is byte-identical to having called `ratchet`.
    #[must_use]
    pub fn ratchet_preview(
        &self,
        dh_out: &DhOutput,
        kem_ss: &KemSharedSecret,
    ) -> (RootKey, ChainKey) {
        let prk = Prk::extract(
            Some(self.0.expose_secret()),
            &[dh_out.bytes(), kem_ss.bytes()],
        );
        let okm: SecretBytes<64> = prk.expand_secret(&[labels::RATCHET_ROOT]);
        let bytes = okm.expose_secret();
        let root = Secret32::from_fill(|out| copy_prefix(out, bytes.get(..32).unwrap_or(&[])));
        let chain = Secret32::from_fill(|out| copy_prefix(out, bytes.get(32..).unwrap_or(&[])));
        (RootKey(root), ChainKey(chain))
    }

    /// Derives a directional frame MAC key (spec parent §4.4).
    ///
    /// `HKDF-Expand(SK, "MLKEMBraid/frame/{i2r,r2i}/v2", 32)`.
    #[must_use]
    pub fn derive_frame_key(&self, direction: FrameDirection) -> FrameKey {
        FrameKey(Prk::from_secret(&self.0).expand_secret::<32>(&[direction.label()]))
    }

    /// Derives the replay-defence session identifier (spec parent §4.4, §6.3).
    ///
    /// `HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)`. Not a secret: it is a map
    /// key in the replay store, so it is returned as plain bytes.
    #[must_use]
    pub fn derive_session_id(&self) -> [u8; 32] {
        let expanded = Prk::from_secret(&self.0).expand_secret::<32>(&[labels::SESSION_ID]);
        *expanded.expose_secret()
    }

    /// The PQXDH confirmation tag over `preimage` (spec parent §4.2).
    ///
    /// ```text
    /// k_cf    = HKDF-Expand(SK, "MLKEMBraid/pqxdh/confirm/v2", 32)
    /// confirm = HMAC-SHA256(k_cf, canonical(InitialMessageV2 without `confirm`))
    /// ```
    ///
    /// `k_cf` is derived, used and dropped inside this call: a separate MAC
    /// key is required (parent §4.2 rejects computing the tag under `SK`
    /// itself), and
    /// never returning it means no caller can put it anywhere.
    #[must_use]
    pub fn confirm_tag(&self, preimage: &[u8]) -> Mac256 {
        let k_cf = Prk::from_secret(&self.0).expand_secret::<32>(&[labels::PQXDH_CONFIRM]);
        hmac_sha256(k_cf.expose_secret(), &[preimage])
    }

    /// Constant-time check of a received confirmation tag (spec parent §4.2).
    ///
    /// # Errors
    /// [`mlkb_secrets::ProtocolError::Unauthenticated`] if the tag does not
    /// match.
    pub fn verify_confirm_tag(
        &self,
        preimage: &[u8],
        received: &Mac256,
    ) -> Result<(), mlkb_secrets::ProtocolError> {
        self.confirm_tag(preimage).verify(received)
    }

    /// Constant-time check of `SK` against a known-answer vector
    /// (spec parent §5.3, §4.1).
    ///
    /// # Why this is a verifier and not an accessor
    ///
    /// Spec parent §5.3 requires the key-schedule KATs be kept, and a KAT has
    /// to pin `SK` itself — not merely something derived from it. The obvious
    /// way to allow that is a public `as_prk`/`as_secret` returning the bytes,
    /// and that is exactly the hole this type's docs describe: it hands every
    /// downstream crate a permanent copy of `SK` and turns the missing `Clone`
    /// into decoration.
    ///
    /// So the KAT gets the *answer* instead of the *value*. Comparing a
    /// caller-supplied 32-byte candidate leaks nothing a caller did not
    /// already have: finding `SK` through this is a 2^256 search, and the
    /// comparison is constant-time (via [`Secret32`]'s
    /// [`subtle::ConstantTimeEq`]-backed equality), so it does not even leak
    /// where a wrong guess first differs.
    ///
    /// Integration tests live in a separate crate and cannot read the private
    /// field, which is why this is `pub` rather than `pub(crate)`.
    ///
    /// # Errors
    /// [`mlkb_secrets::ProtocolError::Unauthenticated`] if `expected` is not
    /// `SK`.
    pub fn verify_sk_kat(&self, expected: &[u8; 32]) -> Result<(), mlkb_secrets::ProtocolError> {
        if self.0 == Secret32::new(*expected) {
            Ok(())
        } else {
            Err(mlkb_secrets::ProtocolError::Unauthenticated)
        }
    }

    /// The complete set of derivations this crate exposes over `SK`
    /// (spec parent §4.4), for the closed-set test below.
    ///
    /// `SK` itself never leaves this type. There is deliberately **no**
    /// `RootKey::as_prk`, no `as_secret`, and no `Clone`; see the type-level
    /// docs for why, and `RootKeyStructuralProbes` for the compile-fail probes
    /// that keep it that way.
    #[cfg(test)]
    fn derivation_label_set() -> [&'static [u8]; 4] {
        [
            labels::FRAME_I2R,
            labels::FRAME_R2I,
            labels::SESSION_ID,
            labels::PQXDH_CONFIRM,
        ]
    }
}

// ---------------------------------------------------------------------------
// ChainKey / MessageKey (spec parent §8.2, M1 §D.2, §G.3)
// ---------------------------------------------------------------------------

/// A symmetric-ratchet chain key (spec parent §8.2, M1 §D.2).
///
/// # Why this is `Clone` and [`MessageKey`] is not
///
/// Spec M1 §G.3: `classify` borrows `&self` while `ChainKey::step` consumes
/// `self`, so planning works on a clone. **Clone only to plan; the original is
/// consumed by `apply` or dropped.** A clone that outlives the plan is a
/// retained chain key, and a retained chain key is a forward-secrecy hole.
///
/// # What that `Clone` costs, stated plainly
///
/// [`ChainKey::step`] is a pure function of the chain-key bytes, so
/// `ck.clone().step()` and `ck.step()` yield two **byte-identical**
/// [`MessageKey`]s. `MessageKey` being non-`Clone` with a consuming `seal`
/// bounds one *value* to one use; it does not stop two equal values existing,
/// and nothing that can be done to `MessageKey` would, while M1 §G.3 keeps
/// this derive.
///
/// That matters because XChaCha20-Poly1305 keystream reuse needs a repeated
/// **(key, nonce) byte pair**. The key half is therefore *not* defended here.
/// The nonce half carries the property alone: `mlkb_secrets::Nonce192` is
/// neither `Copy` nor `Clone` and has no constructor but `random`, so the same
/// 24 bytes cannot be presented to `seal` twice in safe code. Read that type's
/// docs before changing either side of this trade — the two derives are one
/// decision, and this is the only place both halves are written down.
#[derive(Clone)]
pub struct ChainKey(Secret32);

redacted_debug!(ChainKey, "ChainKey");

impl ChainKey {
    /// One symmetric-ratchet step (spec M1 §D.2, parent §8.2).
    ///
    /// ```text
    /// MK  = HMAC-SHA256(CK, 0x01)
    /// CK' = HMAC-SHA256(CK, 0x02)
    /// ```
    ///
    /// Consumes the old chain key, so a stale chain key cannot be re-used
    /// after ratcheting.
    #[must_use]
    pub fn step(self) -> (ChainKey, MessageKey) {
        let key = self.0.expose_secret();
        let mk = hmac_sha256(key, &[&CHAIN_MK]);
        let ck = hmac_sha256(key, &[&CHAIN_CK]);
        (
            ChainKey(Secret32::from_fill(|out| copy_prefix(out, ck.as_bytes()))),
            MessageKey(Secret32::from_fill(|out| copy_prefix(out, mk.as_bytes()))),
        )
    }
}

/// A one-shot AEAD key for a single application message (spec parent §8.3).
///
/// Deliberately **not** `Clone` and not `Copy`: `seal` and `open` consume it,
/// so a second use under the same key does not compile. Spec parent §5.2
/// covers what happens when a *process restart* re-derives one anyway.
pub struct MessageKey(Secret32);

redacted_debug!(MessageKey, "MessageKey");

impl MessageKey {
    /// The raw key bytes, for the AEAD (crate-private).
    pub(crate) fn bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// A frame MAC key (spec parent §4.4, §8.2, M1 §A.1).
///
/// Derived from `SK` and therefore not forward-secret: spec parent §4.4 notes
/// that the frame layer has no post-compromise security. It is a distinct type
/// from [`MessageKey`] so the two cannot be confused at a call site.
pub struct FrameKey(Secret32);

redacted_debug!(FrameKey, "FrameKey");

impl FrameKey {
    /// The frame tag over `preimage` (spec parent §3.3, M1 §A.1).
    ///
    /// The preimage — `b"MLKEMBraid/frame/v2" || wire[..15 + payload_len]` —
    /// is `mlkb-wire`'s to build; this crate owns only the algorithm.
    #[must_use]
    pub fn mac(&self, preimage: &[u8]) -> Mac256 {
        hmac_sha256(self.0.expose_secret(), &[preimage])
    }

    /// Constant-time frame tag check (spec M1 §A.1 rule 5).
    ///
    /// # Errors
    /// [`mlkb_secrets::ProtocolError::Unauthenticated`] on mismatch.
    pub fn verify(
        &self,
        preimage: &[u8],
        received: &Mac256,
    ) -> Result<(), mlkb_secrets::ProtocolError> {
        self.mac(preimage).verify(received)
    }
}

// ---------------------------------------------------------------------------
// Compile-fail probes (spec parent §4.1, §4.4, §8.2)
// ---------------------------------------------------------------------------

/// The structural properties of [`RootKey`] and [`MessageKey`], as tests.
///
/// These are properties by **absence** — a missing derive, a missing accessor
/// — so no unit test can witness them. `compile_fail` doc-tests can, and
/// `cargo test` runs them, so reverting any of the fixes below is a red build.
/// Each negative is paired with a **positive control** so that a block cannot
/// "pass" because of a typo or a renamed item.
///
/// ## `SK` cannot be copied out of a [`RootKey`]
///
/// No PRK view (this is the accessor whose removal closes the
/// forward-secrecy hole; a `Prk` is `Clone` and yields a `&Secret32` that is
/// `Clone`, so this *was* a copy of `SK`):
///
/// ```compile_fail
/// fn retain_sk(rk: &mlkb_crypto::RootKey) -> mlkb_crypto::Prk {
///     rk.as_prk()
/// }
/// ```
///
/// Positive control — the derivations that *are* registered do compile, so the
/// block above fails for the missing method and not for the imports:
///
/// ```
/// fn registered(rk: &mlkb_crypto::RootKey) -> [u8; 32] {
///     let _ = rk.derive_frame_key(mlkb_crypto::FrameDirection::InitiatorToResponder);
///     let _ = rk.confirm_tag(b"preimage");
///     rk.derive_session_id()
/// }
/// ```
///
/// And no root key is `Clone`, so a superseded `RK` cannot be kept:
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<mlkb_crypto::RootKey>();
/// ```
///
/// Positive control that the bound itself is spelled correctly — [`ChainKey`]
/// *is* `Clone`, by spec M1 §G.3:
///
/// ```
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<mlkb_crypto::ChainKey>();
/// ```
///
/// ## The §4.4 label set cannot be extended from outside
///
/// With no `Prk` over `SK`, an unregistered `info` has nothing to expand
/// under:
///
/// ```compile_fail
/// fn unregistered(rk: &mlkb_crypto::RootKey) -> [u8; 32] {
///     let mut out = [0u8; 32];
///     rk.as_prk().expand(&[b"attacker/label/v9"], &mut out).unwrap();
///     out
/// }
/// ```
///
/// ## A ratchet step cannot omit the PQ leg — preview included
///
/// [`RootKey::ratchet_preview`] exists so that `mlkb_protocol`'s `classify`
/// can authenticate a new receiving chain before committing to it (parent
/// §8.1). It takes its [`KemSharedSecret`] by reference, so this block pins
/// the thing that actually carries parent §4.1: there is no way to *make* one.
///
/// No public constructor:
///
/// ```compile_fail
/// fn conjure_pq_leg() -> mlkb_crypto::KemSharedSecret {
///     mlkb_crypto::KemSharedSecret::from_kem(Default::default())
/// }
/// ```
///
/// and no byte string stands in for one at the call site:
///
/// ```compile_fail
/// fn preview_without_pq(
///     rk: &mlkb_crypto::RootKey,
///     dh: &mlkb_crypto::DhOutput,
/// ) -> mlkb_crypto::RootKey {
///     rk.ratchet_preview(dh, &[0u8; 32]).0
/// }
/// ```
///
/// Positive control — with both typed legs in hand the preview compiles, so
/// the two blocks above fail for the missing constructor and the wrong
/// argument type, not for a misspelled method:
///
/// ```
/// fn preview(
///     rk: &mlkb_crypto::RootKey,
///     dh: &mlkb_crypto::DhOutput,
///     ss: &mlkb_crypto::KemSharedSecret,
/// ) -> mlkb_crypto::RootKey {
///     rk.ratchet_preview(dh, ss).0
/// }
/// ```
///
/// And a preview cannot start a key schedule: it is a method on an existing
/// root key, so [`derive_sk`] stays the only way to mint one from nothing.
///
/// ```compile_fail
/// fn mint_from_nothing(
///     dh: &mlkb_crypto::DhOutput,
///     ss: &mlkb_crypto::KemSharedSecret,
/// ) -> mlkb_crypto::RootKey {
///     mlkb_crypto::RootKey::ratchet_preview(dh, ss).0
/// }
/// ```
///
/// ## A [`MessageKey`] is one-shot
///
/// Not `Clone` (spec parent §8.3) — note that this bounds the *value*, not the
/// bytes; the byte-level defence is the nonce's, see `mlkb_secrets::Nonce192`:
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<mlkb_crypto::MessageKey>();
/// ```
///
/// and `seal` consumes it, so the same value cannot seal twice:
///
/// ```compile_fail
/// fn seal_twice(
///     mk: mlkb_crypto::MessageKey,
///     n1: mlkb_secrets::Nonce192,
///     n2: mlkb_secrets::Nonce192,
///     aad: mlkb_crypto::Aad<'_>,
/// ) {
///     let _ = mk.seal(n1, b"first", aad);
///     let _ = mk.seal(n2, b"second", aad);
/// }
/// ```
///
/// Positive control: one seal compiles.
///
/// ```
/// fn seal_once(
///     mk: mlkb_crypto::MessageKey,
///     n: mlkb_secrets::Nonce192,
///     aad: mlkb_crypto::Aad<'_>,
/// ) -> mlkb_crypto::Ciphertext {
///     mk.seal(n, b"first", aad)
/// }
/// ```
#[cfg(doctest)]
#[derive(Debug)]
struct RootKeyStructuralProbes;

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;
    use alloc::format;

    fn dh(seed: u8) -> DhOutput {
        DhOutput::from_dh(Secret32::new([seed; 32]))
    }

    fn kem(seed: u8) -> KemSharedSecret {
        KemSharedSecret::from_kem(Secret32::new([seed; 32]))
    }

    fn info() -> SkInfo {
        SkInfo::new(&[1u8; 32], &[2u8; 32])
    }

    #[test]
    fn arity_is_fixed_at_construction() {
        assert_eq!(DhLegs::without_opk(dh(1), dh(2), dh(3)).arity(), 3);
        assert_eq!(DhLegs::with_opk(dh(1), dh(2), dh(3), dh(4)).arity(), 4);
    }

    /// The three-leg and four-leg `ikm` are different key schedules.
    ///
    /// This is the property that "DH4 is omitted, never zero-filled" buys: a
    /// four-leg run whose DH4 happened to be all-zero must not collide with
    /// the three-leg run.
    #[test]
    fn omitting_dh4_is_not_the_same_as_zero_filling_it() {
        let three = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let four_zero = derive_sk(
            DhLegs::with_opk(dh(1), dh(2), dh(3), dh(0)),
            kem(9),
            &info(),
        );
        assert_ne!(three.0, four_zero.0);

        // And the ordinary case: a four-leg run with a real DH4 is a different
        // key schedule from the three-leg run it shares its first three legs
        // with.
        let four = derive_sk(
            DhLegs::with_opk(dh(1), dh(2), dh(3), dh(4)),
            kem(9),
            &info(),
        );
        assert_ne!(three.0, four.0);
        assert_ne!(four.0, four_zero.0);
    }

    #[test]
    fn derive_sk_is_deterministic_and_depends_on_every_input() {
        let base = derive_sk(
            DhLegs::with_opk(dh(1), dh(2), dh(3), dh(4)),
            kem(9),
            &info(),
        );
        let same = derive_sk(
            DhLegs::with_opk(dh(1), dh(2), dh(3), dh(4)),
            kem(9),
            &info(),
        );
        assert_eq!(base.0, same.0);

        // Each leg, in turn.
        for changed in [
            derive_sk(
                DhLegs::with_opk(dh(9), dh(2), dh(3), dh(4)),
                kem(9),
                &info(),
            ),
            derive_sk(
                DhLegs::with_opk(dh(1), dh(9), dh(3), dh(4)),
                kem(9),
                &info(),
            ),
            derive_sk(
                DhLegs::with_opk(dh(1), dh(2), dh(9), dh(4)),
                kem(9),
                &info(),
            ),
            derive_sk(
                DhLegs::with_opk(dh(1), dh(2), dh(3), dh(9)),
                kem(9),
                &info(),
            ),
            // The KEM leg.
            derive_sk(
                DhLegs::with_opk(dh(1), dh(2), dh(3), dh(4)),
                kem(8),
                &info(),
            ),
        ] {
            assert_ne!(base.0, changed.0);
        }
    }

    /// Leg order is load-bearing: swapping two legs changes `SK`.
    #[test]
    fn leg_order_matters() {
        let a = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let b = derive_sk(DhLegs::without_opk(dh(2), dh(1), dh(3)), kem(9), &info());
        assert_ne!(a.0, b.0);
    }

    /// Identity ordering is initiator-then-responder; reversing it is a
    /// different session (spec parent §4.1, unknown-key-share).
    #[test]
    fn identity_binding_is_ordered() {
        let ab = derive_sk(
            DhLegs::without_opk(dh(1), dh(2), dh(3)),
            kem(9),
            &SkInfo::new(&[1u8; 32], &[2u8; 32]),
        );
        let ba = derive_sk(
            DhLegs::without_opk(dh(1), dh(2), dh(3)),
            kem(9),
            &SkInfo::new(&[2u8; 32], &[1u8; 32]),
        );
        assert_ne!(ab.0, ba.0);
    }

    #[test]
    fn the_root_step_is_deterministic_and_splits_into_two_distinct_halves() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let rk_copy = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let (rk1, ck1) = rk.ratchet(dh(5), kem(6));
        let (rk2, ck2) = rk_copy.ratchet(dh(5), kem(6));
        assert_eq!(rk1.0, rk2.0);
        assert_eq!(ck1.0, ck2.0);
        // The two halves of the 64-byte OKM are different keys.
        assert_ne!(rk1.0, ck1.0);
    }

    #[test]
    fn the_root_step_depends_on_the_old_root_the_dh_and_the_kem_leg() {
        let mk_root = || derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let (base, base_ck) = mk_root().ratchet(dh(5), kem(6));
        let (other_dh, other_dh_ck) = mk_root().ratchet(dh(7), kem(6));
        let (other_kem, other_kem_ck) = mk_root().ratchet(dh(5), kem(7));
        let (other_root, other_root_ck) =
            derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(4)), kem(9), &info())
                .ratchet(dh(5), kem(6));

        assert_ne!(base.0, other_dh.0);
        assert_ne!(base.0, other_kem.0);
        assert_ne!(base.0, other_root.0);
        assert_ne!(base_ck.0, other_dh_ck.0);
        assert_ne!(base_ck.0, other_kem_ck.0);
        assert_ne!(base_ck.0, other_root_ck.0);
    }

    /// A preview is the *same* step, not a second key schedule.
    ///
    /// This is what lets `mlkb_protocol`'s `classify` derive the prospective
    /// receiving chain key, authenticate under it, and have `apply` commit the
    /// previewed root — with the guarantee that the committed state is exactly
    /// what a consuming `ratchet` would have produced.
    #[test]
    fn a_preview_is_byte_identical_to_the_consuming_step() {
        let mk_root = || derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let (preview_root, preview_chain) = mk_root().ratchet_preview(&dh(5), &kem(6));
        let (taken_root, taken_chain) = mk_root().ratchet(dh(5), kem(6));
        assert_eq!(preview_root.0, taken_root.0);
        assert_eq!(preview_chain.0, taken_chain.0);
    }

    /// A preview leaves the receiver usable, and previewing twice is pure —
    /// so an abandoned preview costs the caller nothing but the drop.
    #[test]
    fn a_preview_does_not_disturb_the_root_key_it_previews_from() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        // Abandon the first preview, exactly as `classify` does when the AEAD
        // refuses the ciphertext it was derived to check.
        drop(rk.ratchet_preview(&dh(5), &kem(6)));
        let (preview_root, preview_chain) = rk.ratchet_preview(&dh(5), &kem(6));
        // And the consuming form, from the very same root key, still agrees.
        let (taken_root, taken_chain) = rk.ratchet(dh(5), kem(6));
        assert_eq!(preview_root.0, taken_root.0);
        assert_eq!(preview_chain.0, taken_chain.0);
    }

    /// Successive root steps do not repeat.
    #[test]
    fn successive_root_steps_produce_fresh_chains() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let (rk1, ck1) = rk.ratchet(dh(5), kem(6));
        let (rk2, ck2) = rk1.ratchet(dh(5), kem(6));
        assert_ne!(ck1.0, ck2.0);
        let (_, ck3) = rk2.ratchet(dh(5), kem(6));
        assert_ne!(ck2.0, ck3.0);
    }

    // -----------------------------------------------------------------
    // Chain step (spec M1 §D.2)
    // -----------------------------------------------------------------

    #[test]
    fn a_chain_step_is_deterministic() {
        let ck = ChainKey(Secret32::new([0x11_u8; 32]));
        let (ck_a, mk_a) = ck.clone().step();
        let (ck_b, mk_b) = ck.step();
        assert_eq!(ck_a.0, ck_b.0);
        assert_eq!(mk_a.0, mk_b.0);
    }

    #[test]
    fn two_successive_message_keys_differ() {
        let ck0 = ChainKey(Secret32::new([0x22_u8; 32]));
        let (ck1, mk1) = ck0.step();
        let (ck2, mk2) = ck1.step();
        let (_ck3, mk3) = ck2.step();
        assert_ne!(mk1.0, mk2.0);
        assert_ne!(mk2.0, mk3.0);
        assert_ne!(mk1.0, mk3.0);
    }

    /// `MK` and `CK'` come from the same chain key but must not be equal —
    /// that is what the 0x01 / 0x02 constants are for.
    #[test]
    fn the_message_key_and_the_next_chain_key_are_distinct() {
        let ck0 = ChainKey(Secret32::new([0x33_u8; 32]));
        let ck0_copy = ck0.clone();
        let (ck1, mk1) = ck0.step();
        assert_ne!(ck1.0, mk1.0);
        // And the chain moved.
        assert_ne!(ck1.0, ck0_copy.0);
    }

    #[test]
    fn a_chain_step_matches_the_spec_formula() {
        let raw = [0x44_u8; 32];
        let ck = ChainKey(Secret32::new(raw));
        let (ck1, mk1) = ck.step();
        assert_eq!(
            mk1.0.expose_secret(),
            hmac_sha256(&raw, &[&[0x01]]).as_bytes()
        );
        assert_eq!(
            ck1.0.expose_secret(),
            hmac_sha256(&raw, &[&[0x02]]).as_bytes()
        );
    }

    // -----------------------------------------------------------------
    // The §4.4 label table
    // -----------------------------------------------------------------

    #[test]
    fn every_derivation_from_sk_is_a_different_key() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let i2r = rk.derive_frame_key(FrameDirection::InitiatorToResponder);
        let r2i = rk.derive_frame_key(FrameDirection::ResponderToInitiator);
        let sid = rk.derive_session_id();
        let confirm = rk.confirm_tag(b"");

        assert_ne!(i2r.0, r2i.0);
        assert_ne!(i2r.0.expose_secret(), &sid);
        assert_ne!(r2i.0.expose_secret(), &sid);
        assert_ne!(confirm.as_bytes(), &sid);
        assert_ne!(rk.0.expose_secret(), &sid);
    }

    #[test]
    fn frame_keys_and_session_ids_are_deterministic() {
        let mk = || derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        assert_eq!(
            mk().derive_frame_key(FrameDirection::InitiatorToResponder)
                .0,
            mk().derive_frame_key(FrameDirection::InitiatorToResponder)
                .0
        );
        assert_eq!(mk().derive_session_id(), mk().derive_session_id());
        assert_ne!(
            mk().derive_session_id(),
            derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(9)), kem(9), &info())
                .derive_session_id()
        );
    }

    #[test]
    fn a_frame_mac_verifies_and_rejects_a_tampered_preimage() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let key = rk.derive_frame_key(FrameDirection::InitiatorToResponder);
        let tag = key.mac(b"MLKEMBraid/frame/v2||header||payload");
        assert_eq!(
            key.verify(b"MLKEMBraid/frame/v2||header||payload", &tag),
            Ok(())
        );
        assert_eq!(
            key.verify(b"MLKEMBraid/frame/v2||header||payloaD", &tag),
            Err(mlkb_secrets::ProtocolError::Unauthenticated)
        );
        // A key for the other direction does not verify it.
        let other = rk.derive_frame_key(FrameDirection::ResponderToInitiator);
        assert_eq!(
            other.verify(b"MLKEMBraid/frame/v2||header||payload", &tag),
            Err(mlkb_secrets::ProtocolError::Unauthenticated)
        );
    }

    #[test]
    fn a_confirm_tag_verifies_and_binds_the_preimage() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let tag = rk.confirm_tag(b"canonical(InitialMessageV2 without confirm)");
        assert_eq!(
            rk.verify_confirm_tag(b"canonical(InitialMessageV2 without confirm)", &tag),
            Ok(())
        );
        assert_eq!(
            rk.verify_confirm_tag(b"a different preimage", &tag),
            Err(mlkb_secrets::ProtocolError::Unauthenticated)
        );

        // A different session cannot produce it (parent §4.2).
        let other = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(9)), kem(9), &info());
        assert_eq!(
            other.verify_confirm_tag(b"canonical(InitialMessageV2 without confirm)", &tag),
            Err(mlkb_secrets::ProtocolError::Unauthenticated)
        );
    }

    /// Every derivation `RootKey` exposes is one of the registered §4.4
    /// labels, applied to `SK` as HKDF-Expand and nothing else.
    ///
    /// The closed-set claim of parent §4.4 has two halves. This test pins the
    /// half a runtime test can see: each public derivation is *exactly*
    /// `HKDF-Expand(SK, <registered label>, 32)`, so none of them is a
    /// disguised second spelling. The other half — that no *further*
    /// derivation from `SK` is reachable at all, which is what the removal of
    /// `RootKey::as_prk` bought — is a property by absence and is pinned by
    /// the `compile_fail` probes on `RootKeyStructuralProbes` above.
    #[test]
    fn every_exposed_derivation_is_expand_under_a_registered_label() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        // The reference PRK: what a caller *would* hold if `as_prk` existed.
        let reference = Prk::from_secret(&rk.0);

        let expect = |label: &[u8]| *reference.expand_secret::<32>(&[label]).expose_secret();

        assert_eq!(
            rk.derive_frame_key(FrameDirection::InitiatorToResponder)
                .0
                .expose_secret(),
            &expect(labels::FRAME_I2R)
        );
        assert_eq!(
            rk.derive_frame_key(FrameDirection::ResponderToInitiator)
                .0
                .expose_secret(),
            &expect(labels::FRAME_R2I)
        );
        assert_eq!(rk.derive_session_id(), expect(labels::SESSION_ID));
        assert_eq!(
            rk.confirm_tag(b"m"),
            hmac_sha256(&expect(labels::PQXDH_CONFIRM), &[b"m"])
        );

        // And the set is the one the type documents: four labels, all distinct,
        // all from the registry.
        let set = RootKey::derivation_label_set();
        for (i, a) in set.iter().enumerate() {
            for b in set.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
            assert!(a.starts_with(b"MLKEMBraid/"), "unregistered label");
        }

        // `K_store` is not in it: M1 §G.5's key is not SK-derived, and nothing
        // on `RootKey` produces it.
        assert!(!set.contains(&labels::K_STORE));
        // Nor is the M2 `K_chunk` label, which has no method yet.
        assert!(!set.contains(&labels::ERASURE_CHUNK));
    }

    /// The KAT verifier accepts `SK` and nothing else, and is the *only* thing
    /// on `RootKey` that takes `SK` as a subject.
    ///
    /// It replaced `RootKey::as_prk`, which returned a `Clone` view of `SK`
    /// and so let any downstream crate keep `SK` after the ratchet had
    /// consumed the root key. A verifier cannot: it answers a guess.
    #[test]
    fn the_kat_verifier_accepts_only_sk_and_never_reveals_it() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let sk = *rk.0.expose_secret();
        assert_eq!(rk.verify_sk_kat(&sk), Ok(()));

        // Every single-bit neighbour is rejected.
        for byte in 0..32usize {
            for bit in 0..8u32 {
                let mut bad = sk;
                bad[byte] ^= 1u8 << bit;
                assert_eq!(
                    rk.verify_sk_kat(&bad),
                    Err(mlkb_secrets::ProtocolError::Unauthenticated),
                    "accepted a flip at {byte}:{bit}"
                );
            }
        }
        assert_eq!(
            rk.verify_sk_kat(&[0u8; 32]),
            Err(mlkb_secrets::ProtocolError::Unauthenticated)
        );

        // A different session's root key does not accept this one's `SK`.
        let other = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(9)), kem(9), &info());
        assert_eq!(
            other.verify_sk_kat(&sk),
            Err(mlkb_secrets::ProtocolError::Unauthenticated)
        );
    }

    /// `k_cf` is not `SK` (spec parent §4.2 forbids computing the tag under `SK`).
    #[test]
    fn the_confirm_key_is_not_the_root_key() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let under_k_cf = rk.confirm_tag(b"m");
        let under_sk = hmac_sha256(rk.0.expose_secret(), &[b"m"]);
        assert_ne!(under_k_cf, under_sk);
    }

    // -----------------------------------------------------------------
    // Hygiene
    // -----------------------------------------------------------------

    #[test]
    fn every_typed_key_redacts_its_debug_output() {
        let rk = derive_sk(DhLegs::without_opk(dh(1), dh(2), dh(3)), kem(9), &info());
        let ck = ChainKey(Secret32::new([0xab_u8; 32]));
        let (ck2, mk) = ck.clone().step();
        let fk = rk.derive_frame_key(FrameDirection::InitiatorToResponder);
        for rendered in [
            format!("{rk:?}"),
            format!("{ck:?}"),
            format!("{ck2:?}"),
            format!("{mk:?}"),
            format!("{fk:?}"),
            format!("{:?}", kem(0xab)),
            format!("{:?}", dh(0xab)),
            format!("{:?}", DhLegs::without_opk(dh(0xab), dh(0xab), dh(0xab))),
        ] {
            assert!(rendered.contains("REDACTED"), "leaked: {rendered}");
            assert!(!rendered.contains("ab, ab"), "leaked: {rendered}");
        }
    }
}
