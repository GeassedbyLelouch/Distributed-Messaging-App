//! Serverless containment: two separate allocations (parent spec §6.6).
//!
//! With no issuer there is no issuer-backed scarcity bound, so parent §6.6
//! substitutes **explicit user consent** as the anchor and partitions peers
//! into `Established` (accepted/paired) and `Unknown` (everyone else). The
//! partition *is* the entire mechanism, and the property it buys is:
//!
//! > Flooding the Unknown pool must never evict, degrade, or deny service to
//! > any Established peer.
//!
//! The two pools are therefore separate [`BoundedMap`]s. The Unknown pool fails
//! closed with [`ProtocolError::FirstContactCapacity`] — a distinct,
//! user-actionable error, never a silent drop (parent §6.6 item 4). There is no
//! code path from an Unknown-pool overflow to any Established entry: the
//! Unknown pool cannot borrow from, and cannot evict, Established state.
//!
//! # Caller obligation on `now_ms`
//!
//! Expiry is the Unknown pool's only automatic removal path, which makes
//! `now_ms` its only eviction predicate. `now_ms` **MUST** be a reading of the
//! local clock. It must never be a value derived from a received message: a
//! peer-supplied `now_ms` is a single call that prunes the entire Unknown pool,
//! evicting honest pending first contacts that parent §6.6 requires be
//! removable only by expiry against local time or by a local user action.
//!
//! # Every accessor agrees about expiry
//!
//! Each method that can observe a pending entry takes `now_ms` and applies the
//! same predicate, so no two of them can disagree about whether a record is
//! live. That matters because [`PartitionedPool::classify`] is the natural gate
//! a caller uses to decide what to do with an inbound first contact: were it to
//! report `Unknown` for a record [`PartitionedPool::get_unknown`] already treats
//! as gone, the idiomatic "already pending, ignore it" arm would silently
//! discard an honest new first contact — exactly the silent drop parent §6.6
//! item 4 forbids — and never reclaim a slot that is logically free.

use crate::error::ProtocolError;
use crate::map::BoundedMap;

/// Capacity of the serverless Unknown pool (spec M1 §I `UNKNOWN_POOL_CAPACITY`).
pub const UNKNOWN_POOL_CAPACITY: usize = 64;

/// Lifetime of one pending first contact, in milliseconds
/// (spec M1 §I `UNKNOWN_ENTRY_TTL_MS`).
pub const UNKNOWN_ENTRY_TTL_MS: u64 = 60_000;

/// Which side of the parent §6.6 partition a peer sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PeerClass {
    /// The user has accepted or paired with this peer: full per-peer state.
    Established,
    /// Everyone else: the small, separate, fail-closed first-contact pool.
    Unknown,
}

/// What [`PartitionedPool::promote`] did.
///
/// Promotion is gated on a local user action, so "nothing to promote" is an
/// outcome the caller must handle, not a protocol failure — parent §8.4 names
/// no variant for it and this crate invents none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Promotion {
    /// The pending entry moved from Unknown to Established.
    Promoted,
    /// The peer was already Established. Its Established value was left
    /// **untouched** — containment forbids an Unknown-pool value overwriting
    /// Established state — and the redundant pending entry was discarded.
    AlreadyEstablished,
    /// There was no live pending first contact under that key: it was never
    /// recorded, it was already consumed, or it expired. Both pools are
    /// unchanged.
    NotPending,
}

#[derive(Debug, Clone)]
struct Pending<V> {
    value: V,
    not_after_ms: u64,
}

/// The parent §6.6 two-pool structure.
///
/// Time is passed in as `now_ms`; this crate holds no clock (parent spec §7:
/// `mlkb-bounded` is `no_std`, pure). See the module docs for the obligation
/// `now_ms` carries.
#[derive(Debug, Clone)]
pub struct PartitionedPool<K, V> {
    established: BoundedMap<K, V>,
    unknown: BoundedMap<K, Pending<V>>,
    unknown_ttl_ms: u64,
    established_overflow: ProtocolError,
}

impl<K: Ord, V> PartitionedPool<K, V> {
    /// Build the two pools as two separate allocations.
    ///
    /// Callers in serverless mode pass [`UNKNOWN_POOL_CAPACITY`] and
    /// [`UNKNOWN_ENTRY_TTL_MS`]; the capacities are parameters rather than
    /// baked in so that this crate carries no policy of its own. For the same
    /// reason `established_overflow` is the owner's choice — parent §8.4
    /// forbids conflating one resource's exhaustion with another's, and only
    /// the owner knows what its Established pool means. The Unknown pool's
    /// overflow is *not* a parameter: parent §6.6 item 4 fixes it at
    /// [`ProtocolError::FirstContactCapacity`].
    #[must_use]
    pub const fn new(
        established_capacity: usize,
        established_overflow: ProtocolError,
        unknown_capacity: usize,
        unknown_ttl_ms: u64,
    ) -> Self {
        Self {
            established: BoundedMap::new(established_capacity, established_overflow),
            unknown: BoundedMap::new(unknown_capacity, ProtocolError::FirstContactCapacity),
            unknown_ttl_ms,
            established_overflow,
        }
    }

    /// Established entries currently held.
    #[must_use]
    pub fn established_len(&self) -> usize {
        self.established.len()
    }

    /// Unknown (pending first contact) entries currently held, including any
    /// that are expired but not yet pruned.
    #[must_use]
    pub fn unknown_len(&self) -> usize {
        self.unknown.len()
    }

    /// The Established bound.
    #[must_use]
    pub const fn established_capacity(&self) -> usize {
        self.established.capacity()
    }

    /// The Unknown bound.
    #[must_use]
    pub const fn unknown_capacity(&self) -> usize {
        self.unknown.capacity()
    }

    /// Which pool `key` is in at `now_ms`, if either. Established wins if both.
    ///
    /// An expired pending entry classifies as `None`, in exact agreement with
    /// [`PartitionedPool::get_unknown`] — see the module docs for why the two
    /// must never disagree.
    #[must_use]
    pub fn classify(&self, key: &K, now_ms: u64) -> Option<PeerClass> {
        if self.established.contains_key(key) {
            Some(PeerClass::Established)
        } else if self.is_live_pending(key, now_ms) {
            Some(PeerClass::Unknown)
        } else {
            None
        }
    }

    /// Whether `key` has a pending entry that has not expired at `now_ms`.
    fn is_live_pending(&self, key: &K, now_ms: u64) -> bool {
        self.unknown
            .get(key)
            .is_some_and(|p| p.not_after_ms > now_ms)
    }

    /// Admit a peer the user has accepted (parent spec §6.6, Established row).
    ///
    /// # Errors
    ///
    /// The configured `established_overflow` when the Established pool is full
    /// and `key` is new. This bound is consumed only by the local user's own
    /// accept actions; a remote attacker has no path to it.
    pub fn insert_established(&mut self, key: K, value: V) -> Result<Option<V>, ProtocolError> {
        self.established.insert(key, value)
    }

    /// Record a pending first contact (parent spec §6.6, Unknown row).
    ///
    /// Expired pending entries are pruned first; the pool then fails closed.
    ///
    /// # What `key` must be
    ///
    /// A duplicate `key` is reported as [`ProtocolError::ReplayDetected`], so
    /// `key` **MUST** be a per-attempt value — parent §6.3's derived
    /// `session_id` is the intended one, and a replayed `InitialMessage`
    /// re-derives it, which is precisely the rejection this buys. Keying on a
    /// peer identity instead would report an honest peer's retry as a replay.
    ///
    /// # Errors
    ///
    /// - [`ProtocolError::ReplayDetected`] when `key` is already pending, i.e.
    ///   the first-contact replay rejection above.
    /// - [`ProtocolError::FirstContactCapacity`] when the Unknown pool is full
    ///   of live entries. Parent §6.6 item 4 requires this be distinct and
    ///   user-actionable rather than a silent drop, and §6.6's accepted
    ///   degradation is exactly this: inbound first contact from *new* peers is
    ///   denied for the duration of a flood. No Established peer is affected.
    pub fn insert_unknown(&mut self, key: K, value: V, now_ms: u64) -> Result<(), ProtocolError> {
        let _pruned = self.prune_unknown(now_ms);
        let pending = Pending {
            value,
            not_after_ms: now_ms.saturating_add(self.unknown_ttl_ms),
        };
        self.unknown.insert_if_absent(key, pending)
    }

    /// Borrow an Established peer's state.
    #[must_use]
    pub fn get_established(&self, key: &K) -> Option<&V> {
        self.established.get(key)
    }

    /// Mutably borrow an Established peer's state — the ratchet/replay state a
    /// live session advances on every message.
    pub fn get_established_mut(&mut self, key: &K) -> Option<&mut V> {
        self.established.get_mut(key)
    }

    /// Borrow a pending first contact's state, if it has not expired.
    #[must_use]
    pub fn get_unknown(&self, key: &K, now_ms: u64) -> Option<&V> {
        self.unknown
            .get(key)
            .filter(|p| p.not_after_ms > now_ms)
            .map(|p| &p.value)
    }

    /// Move a pending peer into the Established pool, because the local user
    /// accepted it (parent spec §6.6: the anchor is explicit user consent).
    ///
    /// Expired pendings are pruned first, so promotion can never install state
    /// whose freshness this pool has already declared void: an entry invisible
    /// to [`PartitionedPool::get_unknown`] is [`Promotion::NotPending`] here
    /// too.
    ///
    /// The Established capacity is checked *after* the pending entry is
    /// confirmed and *before* it is removed, so a full Established pool neither
    /// destroys a pending contact nor masks the fact that there was none.
    ///
    /// # Errors
    ///
    /// The configured `established_overflow` if the Established pool is full.
    /// Both pools are left untouched, so the user can retry after unpairing.
    pub fn promote(&mut self, key: K, now_ms: u64) -> Result<Promotion, ProtocolError> {
        let _pruned = self.prune_unknown(now_ms);
        if self.established.contains_key(&key) {
            // Containment: an Unknown-pool value must never overwrite
            // Established state. Drop the redundant pending entry instead.
            let _redundant = self.unknown.remove(&key);
            return Ok(Promotion::AlreadyEstablished);
        }
        if !self.unknown.contains_key(&key) {
            // Checked before capacity: a full Established pool must not be
            // reported as the reason a key that was never pending failed.
            return Ok(Promotion::NotPending);
        }
        if self.established.is_full() {
            return Err(self.established_overflow);
        }
        let Some(pending) = self.unknown.remove(&key) else {
            return Ok(Promotion::NotPending);
        };
        // Cannot fail: `key` is absent from a pool checked non-full above.
        let _displaced = self.established.insert(key, pending.value)?;
        Ok(Promotion::Promoted)
    }

    /// Drop expired pending first contacts and report how many were dropped.
    /// Expiry is the Unknown pool's only automatic removal path.
    ///
    /// # Caller obligation
    ///
    /// `now_ms` **MUST** be a reading of the local clock, and **MUST NOT** be
    /// derived from a received message. It is the Unknown pool's only automatic
    /// eviction predicate, so a peer-supplied `now_ms` is a single call that
    /// empties the pool — evicting honest pending first contacts that parent
    /// §6.6 requires be removable only by expiry against local time or by a
    /// local user action. The Established pool is unreachable from here in
    /// either case.
    pub fn prune_unknown(&mut self, now_ms: u64) -> usize {
        let before = self.unknown.len();
        self.unknown.prune(|_, p| p.not_after_ms <= now_ms);
        before.saturating_sub(self.unknown.len())
    }

    /// Forget a pending first contact — the user declined it, or it completed.
    pub fn remove_unknown(&mut self, key: &K) -> Option<V> {
        self.unknown.remove(key).map(|p| p.value)
    }

    /// Forget an Established peer, because the local user unpaired it.
    ///
    /// This is the *only* way an Established entry is removed, and it is
    /// reachable only from a local user action — never from any Unknown-pool
    /// or capacity path (parent spec §6.6: "no established session may be
    /// evicted").
    pub fn remove_established(&mut self, key: &K) -> Option<V> {
        self.established.remove(key)
    }

    /// Iterate Established peers in key order.
    pub fn established_iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.established.iter()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::{
        PartitionedPool, PeerClass, Promotion, ProtocolError, UNKNOWN_ENTRY_TTL_MS,
        UNKNOWN_POOL_CAPACITY,
    };

    const TTL: u64 = 60_000;
    /// What the serverless caller names its Established bound: the only way
    /// that pool grows is the user accepting a first contact.
    const EST_FULL: ProtocolError = ProtocolError::FirstContactCapacity;

    fn pool() -> PartitionedPool<u32, u32> {
        PartitionedPool::new(4, EST_FULL, 4, TTL)
    }

    #[test]
    fn classify_reports_the_partition() {
        let mut p = pool();
        assert_eq!(p.classify(&1, 0), None);
        assert_eq!(p.insert_unknown(1, 10, 0), Ok(()));
        assert_eq!(p.classify(&1, 0), Some(PeerClass::Unknown));
        assert_eq!(p.promote(1, 0), Ok(Promotion::Promoted));
        assert_eq!(p.classify(&1, 0), Some(PeerClass::Established));
        assert_eq!(p.get_established(&1), Some(&10));
        assert_eq!(p.unknown_len(), 0);
    }

    #[test]
    fn unknown_pool_fails_closed_with_the_named_error() {
        let mut p = pool();
        for k in 0..4u32 {
            assert_eq!(p.insert_unknown(k, k, 0), Ok(()));
        }
        assert_eq!(
            p.insert_unknown(99, 99, 0),
            Err(ProtocolError::FirstContactCapacity)
        );
    }

    #[test]
    fn duplicate_pending_contact_is_a_replay() {
        let mut p = pool();
        assert_eq!(p.insert_unknown(1, 10, 0), Ok(()));
        assert_eq!(
            p.insert_unknown(1, 11, 0),
            Err(ProtocolError::ReplayDetected)
        );
        assert_eq!(p.get_unknown(&1, 0), Some(&10));
    }

    #[test]
    fn pending_contacts_expire() {
        let mut p = pool();
        assert_eq!(p.insert_unknown(1, 10, 0), Ok(()));
        assert_eq!(p.get_unknown(&1, TTL - 1), Some(&10));
        assert_eq!(p.get_unknown(&1, TTL), None, "not_after is exclusive");
        assert_eq!(p.prune_unknown(TTL), 1);
        assert_eq!(p.unknown_len(), 0);
    }

    /// Every accessor must apply the same expiry predicate. `classify`
    /// disagreeing with `get_unknown` is what turns the idiomatic
    /// "already pending, ignore it" arm into a silent drop of an honest first
    /// contact (parent §6.6 item 4).
    #[test]
    fn classify_agrees_with_get_unknown_about_expiry() {
        let mut p: PartitionedPool<u32, u32> =
            PartitionedPool::new(4, EST_FULL, 4, UNKNOWN_ENTRY_TTL_MS);
        assert_eq!(p.insert_unknown(7, 0xBEEF, 0), Ok(()));

        let live = UNKNOWN_ENTRY_TTL_MS - 1;
        assert_eq!(p.get_unknown(&7, live), Some(&0xBEEF));
        assert_eq!(p.classify(&7, live), Some(PeerClass::Unknown));

        // Long expired, and nothing has pruned yet.
        let stale = UNKNOWN_ENTRY_TTL_MS.saturating_mul(100);
        assert_eq!(p.unknown_len(), 1, "still physically present");
        assert_eq!(p.get_unknown(&7, stale), None);
        assert_eq!(
            p.classify(&7, stale),
            None,
            "classify must not report a record get_unknown calls gone"
        );
    }

    /// The slot an expired pending occupies is logically free, and the caller
    /// that consults `classify` first must be able to reclaim it.
    #[test]
    fn an_expired_pending_does_not_block_a_fresh_first_contact() {
        let mut p: PartitionedPool<u32, u32> = PartitionedPool::new(4, EST_FULL, 1, TTL);
        assert_eq!(p.insert_unknown(7, 1, 0), Ok(()));
        let stale = TTL.saturating_mul(10);
        assert_eq!(p.classify(&7, stale), None);
        // Same key, and a different one: both are genuinely new contacts now.
        assert_eq!(p.insert_unknown(7, 2, stale), Ok(()));
        assert_eq!(p.get_unknown(&7, stale), Some(&2));
    }

    /// Promotion must not install state whose freshness the pool has already
    /// declared void.
    #[test]
    fn promote_refuses_an_expired_pending() {
        let mut p: PartitionedPool<u32, u32> =
            PartitionedPool::new(4, EST_FULL, 4, UNKNOWN_ENTRY_TTL_MS);
        assert_eq!(p.insert_unknown(7, 0xBEEF, 0), Ok(()));
        let stale = UNKNOWN_ENTRY_TTL_MS.saturating_mul(100);
        assert_eq!(p.promote(7, stale), Ok(Promotion::NotPending));
        assert_eq!(
            p.get_established(&7),
            None,
            "stale value must not be installed"
        );
        assert_eq!(p.established_len(), 0);
        assert_eq!(p.unknown_len(), 0, "and the dead record is gone");
    }

    #[test]
    fn promote_of_a_stranger_is_not_pending() {
        let mut p = pool();
        assert_eq!(p.promote(42, 0), Ok(Promotion::NotPending));
        assert_eq!(p.established_len(), 0);
    }

    /// A full Established pool must not be reported as the reason a key that
    /// was never pending failed to promote.
    #[test]
    fn a_full_established_pool_does_not_mask_a_stranger() {
        let mut p: PartitionedPool<u32, u32> = PartitionedPool::new(1, EST_FULL, 4, TTL);
        assert_eq!(p.insert_established(0, 0), Ok(None));
        assert_eq!(
            p.promote(55, 0),
            Ok(Promotion::NotPending),
            "55 was never pending; capacity is not the reason"
        );
        // And a key that IS pending still reports the capacity failure.
        assert_eq!(p.insert_unknown(56, 56, 0), Ok(()));
        assert_eq!(p.promote(56, 0), Err(EST_FULL));
    }

    #[test]
    fn promote_never_overwrites_established_state() {
        let mut p = pool();
        assert_eq!(p.insert_established(1, 100), Ok(None));
        // The same key also shows up as a pending first contact.
        assert_eq!(p.insert_unknown(1, 999, 0), Ok(()));
        assert_eq!(p.promote(1, 0), Ok(Promotion::AlreadyEstablished));
        assert_eq!(
            p.get_established(&1),
            Some(&100),
            "Established state must be untouched"
        );
        assert_eq!(p.unknown_len(), 0, "the redundant pending entry is dropped");
    }

    #[test]
    fn promote_into_a_full_established_pool_keeps_the_pending_entry() {
        let mut p: PartitionedPool<u32, u32> = PartitionedPool::new(1, EST_FULL, 4, TTL);
        assert_eq!(p.insert_established(0, 0), Ok(None));
        assert_eq!(p.insert_unknown(1, 10, 0), Ok(()));
        assert_eq!(p.promote(1, 0), Err(EST_FULL));
        assert_eq!(p.get_unknown(&1, 0), Some(&10), "pending entry survives");
        assert_eq!(p.get_established(&0), Some(&0), "Established untouched");
    }

    /// Parent §8.4 forbids conflation: the Established overflow error is the
    /// owner's choice, not one this type picks for it.
    #[test]
    fn established_overflow_error_is_the_one_configured() {
        let mut p: PartitionedPool<u32, u32> =
            PartitionedPool::new(1, ProtocolError::SkippedKeyLimit, 4, TTL);
        assert_eq!(p.insert_established(0, 0), Ok(None));
        assert_eq!(
            p.insert_established(1, 1),
            Err(ProtocolError::SkippedKeyLimit)
        );
        assert_eq!(p.insert_unknown(2, 2, 0), Ok(()));
        assert_eq!(p.promote(2, 0), Err(ProtocolError::SkippedKeyLimit));
        // The Unknown pool's own error is fixed by parent §6.6 item 4 and is
        // therefore still the distinct one.
        for k in 3..6u32 {
            assert_eq!(p.insert_unknown(k, k, 0), Ok(()));
        }
        assert_eq!(
            p.insert_unknown(9, 9, 0),
            Err(ProtocolError::FirstContactCapacity)
        );
    }

    #[test]
    fn established_removal_is_only_by_explicit_user_action() {
        let mut p = pool();
        assert_eq!(p.insert_established(1, 100), Ok(None));
        assert_eq!(p.remove_established(&1), Some(100));
        assert_eq!(p.classify(&1, 0), None);
    }

    #[test]
    fn the_two_pools_have_independent_bounds() {
        let mut p: PartitionedPool<u32, u32> = PartitionedPool::new(2, EST_FULL, 3, TTL);
        assert_eq!(p.established_capacity(), 2);
        assert_eq!(p.unknown_capacity(), 3);
        for k in 0..3u32 {
            assert_eq!(p.insert_unknown(k, k, 0), Ok(()));
        }
        assert_eq!(
            p.insert_unknown(3, 3, 0),
            Err(ProtocolError::FirstContactCapacity)
        );
        // The Established pool is entirely unaffected.
        assert_eq!(p.insert_established(100, 100), Ok(None));
        assert_eq!(p.insert_established(101, 101), Ok(None));
        assert_eq!(p.established_len(), 2);
    }

    #[test]
    fn the_serverless_constants_are_the_spec_ones() {
        // Spec M1 §I; asserted so a caller that passes them gets the shape the
        // flood test exercises.
        let p: PartitionedPool<u32, u32> =
            PartitionedPool::new(8, EST_FULL, UNKNOWN_POOL_CAPACITY, UNKNOWN_ENTRY_TTL_MS);
        assert_eq!(p.unknown_capacity(), UNKNOWN_POOL_CAPACITY);
    }
}
