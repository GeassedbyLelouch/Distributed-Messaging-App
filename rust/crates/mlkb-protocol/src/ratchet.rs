//! The M1 hybrid DH + ML-KEM ratchet — state and the two steps
//! (spec M1 §D.1, §D.2, §D.4).
//!
//! # What is hybrid about it
//!
//! Every DH ratchet step mixes **both** a fresh X25519 output and a fresh
//! ML-KEM-1024 encapsulation into the root step, so breaking the chain
//! requires breaking X25519 *and* ML-KEM (M1 §D.1). The mixing itself is
//! [`mlkb_crypto::RootKey::ratchet`], which consumes a
//! [`mlkb_crypto::KemSharedSecret`] by value: the PQ leg is structurally
//! impossible to omit from a step, which is parent §4.1's invariant one layer
//! up.
//!
//! # The directional split is deliberately absent
//!
//! M1 §D.2: the Python implementation's `CK_AtoB`/`CK_BtoA` existed because an
//! SCKA hands both parties the *same* epoch key. A DH/KEM ratchet is
//! asymmetric by construction, so the two directions already have distinct
//! chains and the split would be redundant state.

use alloc::vec::Vec;

use mlkb_bounded::BoundedMap;
use mlkb_crypto::{
    ChainKey, KemDecapsulationKey, KemEncapsulationKey, MessageKey, RootKey, X25519PublicKey,
    X25519SecretKey,
};
use mlkb_secrets::ProtocolError;

/// The largest single catch-up, in message keys (spec M1 §I, §D.4).
pub const MAX_SKIP_PER_CHAIN: u64 = 1000;

/// The largest number of skipped keys one session may hold (spec M1 §I, §D.4).
pub const MAX_SKIPPED_KEYS_PER_SESSION: usize = 2000;

/// How many previous receiving-chain generations stay decryptable
/// (spec M1 §I, §D.4).
pub const RETAINED_RECV_CHAINS: u64 = 1;

/// Where a skipped message key is filed: `(generation, index within chain)`.
///
/// The generation is the *frame* epoch of the chain the key belongs to
/// (M1 §A.3), which is what lets a message delayed across a ratchet boundary
/// still find its key — and what lets [`RatchetState::prune_skipped`] express
/// M1 §D.4's `RETAINED_RECV_CHAINS` as a predicate on the key rather than as a
/// second index.
pub(crate) type SkipIndex = (u64, u64);

/// One derived-but-unused message key, ready to be filed.
pub(crate) type SkippedKey = (SkipIndex, MessageKey);

/// Per-session ratchet state (spec M1 §D.2).
///
/// The `Option`s here mean exactly one thing — *not yet known* — and never
/// *temporarily moved out*. `ChainKey::step` consumes its receiver
/// (parent §8.2), so a chain key is replaced by assigning the successor the
/// step returns; and the root key is never moved out at all, because
/// [`mlkb_crypto::RootKey::ratchet_preview`] derives its successor from
/// `&self`. That is why `root` is a plain [`RootKey`]: a session always has
/// one, there is no window in which it does not, and no `None` arm exists to
/// be reasoned about or to fail closed into.
pub(crate) struct RatchetState {
    /// `RK`. Always present: root steps are computed by preview and committed
    /// by assignment, so this is never vacated.
    pub(crate) root: RootKey,
    /// `CK_send`. `None` until the first sending root step.
    pub(crate) ck_send: Option<ChainKey>,
    /// `CK_recv`. `None` until the first receiving root step.
    pub(crate) ck_recv: Option<ChainKey>,
    /// `Ns` — index of the next message in the current sending chain.
    pub(crate) ns: u64,
    /// `Nr` — index of the next expected message in the current receiving
    /// chain.
    pub(crate) nr: u64,
    /// `PN` — number of messages in the previous sending chain (M1 §D.3).
    pub(crate) pn: u64,
    /// The sending chain's DH-ratchet generation; this is `Frame.epoch`
    /// (M1 §A.3).
    pub(crate) send_epoch: u64,
    /// The receiving chain's generation, advanced only by a receiving root
    /// step.
    pub(crate) recv_gen: u64,
    /// Whether the next send must perform a DH ratchet step.
    pub(crate) ratchet_due: bool,
    /// Our current X25519 ratchet secret. `None` for an initiator that has not
    /// yet sent: M1 §D.2 has it generate one on its first send.
    pub(crate) dh_self: Option<X25519SecretKey>,
    /// The peer's current X25519 ratchet public key.
    pub(crate) dh_remote: Option<X25519PublicKey>,
    /// Our current ML-KEM-1024 keypair — what peers encapsulate to.
    pub(crate) kem_self: Option<KemDecapsulationKey>,
    /// The peer's current ML-KEM-1024 encapsulation key.
    pub(crate) kem_remote: Option<KemEncapsulationKey>,
    /// Derived-but-unused message keys (M1 §D.4). Fails closed, never evicts.
    pub(crate) skipped: BoundedMap<SkipIndex, MessageKey>,
}

impl RatchetState {
    /// The state both roles start from, differing only in what each already
    /// knows of the other (spec M1 §D.2 "Initialization").
    pub(crate) fn new(
        root: RootKey,
        dh_self: Option<X25519SecretKey>,
        dh_remote: Option<X25519PublicKey>,
        kem_self: Option<KemDecapsulationKey>,
        kem_remote: Option<KemEncapsulationKey>,
    ) -> Self {
        Self {
            root,
            ck_send: None,
            ck_recv: None,
            ns: 0,
            nr: 0,
            pn: 0,
            send_epoch: 0,
            recv_gen: 0,
            // Both roles must ratchet before their first send: `RK_0 = SK`
            // seeds the root, and M1 §D.2 gives the sending chain no other
            // source.
            ratchet_due: true,
            dh_self,
            dh_remote,
            kem_self,
            kem_remote,
            skipped: BoundedMap::new(MAX_SKIPPED_KEYS_PER_SESSION, ProtocolError::SkippedKeyLimit),
        }
    }

    /// M1 §D.4's two bounds, **checked before any key material is derived**.
    ///
    /// The ordering is the whole point of the rule: a message that would
    /// overflow either bound is refused *before* a chain step runs and before
    /// an AEAD is attempted, which is what stops a forged message from
    /// advancing state. On overflow the **new** message is refused; a cached
    /// key is never evicted, because evicting one silently and permanently
    /// destroys an authentic delayed message.
    ///
    /// # Errors
    /// [`ProtocolError::SkippedKeyLimit`] if `count` exceeds
    /// [`MAX_SKIP_PER_CHAIN`], or if filing `count` more keys would take the
    /// store past [`MAX_SKIPPED_KEYS_PER_SESSION`].
    pub(crate) fn check_skip_budget(&self, count: u64) -> Result<(), ProtocolError> {
        if count > MAX_SKIP_PER_CHAIN {
            return Err(ProtocolError::SkippedKeyLimit);
        }
        let held = u64::try_from(self.skipped.len()).map_err(|_| ProtocolError::Internal)?;
        let capacity =
            u64::try_from(self.skipped.capacity()).map_err(|_| ProtocolError::Internal)?;
        let after = held
            .checked_add(count)
            .ok_or(ProtocolError::SkippedKeyLimit)?;
        if after > capacity {
            return Err(ProtocolError::SkippedKeyLimit);
        }
        Ok(())
    }

    /// Drops skipped keys older than M1 §D.4's retention window.
    ///
    /// Called only after a receiving root step, with the *new* generation.
    /// This is an owner-directed prune, not a capacity eviction: it is not
    /// reachable from an overflow path, which is the distinction
    /// `mlkb_bounded::BoundedMap::prune` documents.
    pub(crate) fn prune_skipped(&mut self, new_gen: u64) {
        self.skipped.prune(|(generation, _), _| {
            generation
                .checked_add(RETAINED_RECV_CHAINS)
                .is_some_and(|newest_retaining| newest_retaining < new_gen)
        });
    }
}

/// Derives `count` consecutive message keys from `ck`, filing them under
/// `(epoch, from ..)`, and returns the chain key that follows them.
///
/// The chain key is taken **by value** because `ChainKey::step` consumes its
/// receiver. Callers that must not mutate — `classify` (parent §8.1) — pass a
/// clone, which is what M1 §G.3 licenses and bounds: *clone only to plan; the
/// original is consumed by `apply` or dropped*.
///
/// # Errors
/// [`ProtocolError::Malformed`] if the index range would overflow `u64`.
pub(crate) fn derive_run(
    ck: ChainKey,
    epoch: u64,
    from: u64,
    count: u64,
) -> Result<(Vec<SkippedKey>, ChainKey), ProtocolError> {
    let mut out = Vec::new();
    let mut chain = ck;
    let mut index = from;
    for _ in 0..count {
        let (next, mk) = chain.step();
        out.push(((epoch, index), mk));
        chain = next;
        index = index.checked_add(1).ok_or(ProtocolError::Malformed)?;
    }
    Ok((out, chain))
}
