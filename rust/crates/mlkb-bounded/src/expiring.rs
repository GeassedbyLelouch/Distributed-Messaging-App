//! The `session_id` uniqueness set (parent spec §6.3, §6.4 row 2).
//!
//! First contact has no replay floor yet, so parent §6.3 makes the derived
//! `session_id` the anchor: it is inserted with `insert_if_absent`, and a
//! replayed `InitialMessage` derives the identical `session_id` and is refused
//! as a duplicate.
//!
//! **The hole this type is shaped to close.** Parent §6.3 records that one
//! design track's session table *replaced* a peer's row on re-handshake, which
//! would let a captured no-OPK `InitialMessage` replay cleanly afterwards.
//! Accordingly this type has **no key-directed removal at all**: the only way
//! an entry leaves is [`ExpiringSet::prune`], driven solely by `not_after_ms`.
//! A re-handshake cannot evict, because there is no API with which to try.
//!
//! # Caller obligation on `now_ms`
//!
//! Expiry is this type's only removal path, so `now_ms` is its only eviction
//! predicate. `now_ms` **MUST** be a reading of the local clock. It must never
//! be a value derived from a received message: a peer-supplied `now_ms` is a
//! single call that prunes the whole uniqueness set, evicting honest records
//! that parent §6.3 requires be removable only by expiry against local time.

use alloc::collections::BTreeMap;

use crate::error::ProtocolError;

/// A bounded, expiry-pruned set with `insert_if_absent` semantics.
///
/// The set is bounded per admitted peer by its owner (parent spec §6.4 row 2);
/// scarcity of the principal is what makes the fail-closed bound safe under
/// parent §6.1.
///
/// The overflow error is chosen at construction, as it is for
/// [`crate::BoundedMap`], so that each caller reports the spec-named failure for
/// *its own* resource — parent §8.4 forbids conflation. The §6.3 `session_id`
/// set sits on the serverless first-contact path, where §6.6 item 4 names
/// [`ProtocolError::FirstContactCapacity`] as the distinct, user-actionable
/// error; that caller passes it rather than translating a generic one.
#[derive(Debug, Clone)]
pub struct ExpiringSet<K> {
    /// key -> `not_after_ms`
    entries: BTreeMap<K, u64>,
    capacity: usize,
    overflow: ProtocolError,
}

impl<K: Ord> ExpiringSet<K> {
    /// Create a set bounded at `capacity`, reporting `overflow` when full.
    #[must_use]
    pub const fn new(capacity: usize, overflow: ProtocolError) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity,
            overflow,
        }
    }

    /// The hard bound.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Entries currently held, including any that are expired but not yet
    /// pruned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the set holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop every entry whose `not_after_ms` is at or before `now_ms`, and
    /// report how many were dropped.
    ///
    /// This is the **only** removal path (parent spec §6.3: pruned only by
    /// expiry). Time is passed in; this crate holds no clock.
    ///
    /// # Caller obligation
    ///
    /// `now_ms` **MUST** be a reading of the local clock, and **MUST NOT** be
    /// derived from a received message. It is this type's only eviction
    /// predicate, so a peer-supplied `now_ms` is a single call that empties the
    /// whole uniqueness set — evicting honest records that parent §6.3 requires
    /// be removable only by expiry against local time.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, not_after| *not_after > now_ms);
        before.saturating_sub(self.entries.len())
    }

    /// Whether `key` is present and not yet expired at `now_ms`.
    #[must_use]
    pub fn contains(&self, key: &K, now_ms: u64) -> bool {
        self.entries.get(key).is_some_and(|&na| na > now_ms)
    }

    /// Insert `key` with expiry `not_after_ms`, refusing a live duplicate
    /// (parent spec §6.3).
    ///
    /// Expired entries are pruned first, so a full set recovers on its own once
    /// its entries age out; nothing live is ever displaced to make room.
    ///
    /// # An entry that would be born expired is refused
    ///
    /// `not_after_ms` is supplied per insert, and its natural source is the
    /// incoming record's own declared expiry — attacker-influenced data. An
    /// entry with `not_after_ms <= now_ms` is dead the instant it is written:
    /// [`ExpiringSet::contains`] would report it absent and the next
    /// [`ExpiringSet::prune`] would drop it, so the uniqueness property this
    /// type exists to provide would be silently void and every replay would be
    /// accepted. Such an entry is therefore rejected outright rather than
    /// stored. It is an invalid record, not a duplicate and not a capacity
    /// failure, so it reports [`ProtocolError::Malformed`] — distinct from both
    /// (parent spec §8.4 forbids conflation).
    ///
    /// # Errors
    ///
    /// - [`ProtocolError::Malformed`] if `not_after_ms <= now_ms`, i.e. the
    ///   record has already expired on arrival. Nothing is stored and no
    ///   capacity is consumed.
    /// - [`ProtocolError::ReplayDetected`] if `key` is already present and
    ///   live — this is the first-contact replay rejection.
    /// - The configured overflow error if the set is full of live entries
    ///   (parent spec §6.1 tier 3, fail closed).
    pub fn insert_if_absent(
        &mut self,
        key: K,
        not_after_ms: u64,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        if not_after_ms <= now_ms {
            return Err(ProtocolError::Malformed);
        }
        let _pruned = self.prune(now_ms);
        if self.entries.contains_key(&key) {
            return Err(ProtocolError::ReplayDetected);
        }
        if self.entries.len() >= self.capacity {
            return Err(self.overflow);
        }
        let _displaced = self.entries.insert(key, not_after_ms);
        Ok(())
    }

    /// Iterate `(key, not_after_ms)` in key order, for persistence.
    pub fn iter(&self) -> impl Iterator<Item = (&K, u64)> {
        self.entries.iter().map(|(k, &na)| (k, na))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::{ExpiringSet, ProtocolError};

    const TTL: u64 = 60_000;
    const FULL: ProtocolError = ProtocolError::FirstContactCapacity;

    fn set<K: Ord>(capacity: usize) -> ExpiringSet<K> {
        ExpiringSet::new(capacity, FULL)
    }

    #[test]
    fn insert_then_duplicate_is_a_replay() {
        let mut s: ExpiringSet<u32> = set(4);
        assert_eq!(s.insert_if_absent(1, TTL, 0), Ok(()));
        assert!(s.contains(&1, 0));
        assert_eq!(
            s.insert_if_absent(1, TTL, 0),
            Err(ProtocolError::ReplayDetected)
        );
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn full_of_live_entries_fails_closed() {
        let mut s: ExpiringSet<u32> = set(2);
        assert_eq!(s.insert_if_absent(1, TTL, 0), Ok(()));
        assert_eq!(s.insert_if_absent(2, TTL, 0), Ok(()));
        assert_eq!(s.insert_if_absent(3, TTL, 0), Err(FULL));
        // Nothing was displaced to make room.
        assert!(s.contains(&1, 0));
        assert!(s.contains(&2, 0));
        assert!(!s.contains(&3, 0));
    }

    /// Parent §8.4 forbids conflation: the overflow error is the owner's, not
    /// one this type picks for it.
    #[test]
    fn overflow_error_is_the_one_configured() {
        let mut s: ExpiringSet<u32> = ExpiringSet::new(1, ProtocolError::SkippedKeyLimit);
        assert_eq!(s.insert_if_absent(1, TTL, 0), Ok(()));
        assert_eq!(
            s.insert_if_absent(2, TTL, 0),
            Err(ProtocolError::SkippedKeyLimit)
        );
    }

    #[test]
    fn expiry_is_the_only_removal_path() {
        let mut s: ExpiringSet<u32> = set(2);
        assert_eq!(s.insert_if_absent(1, 100, 0), Ok(()));
        assert_eq!(s.insert_if_absent(2, 200, 0), Ok(()));
        assert_eq!(s.prune(99), 0, "nothing has expired yet");
        assert_eq!(s.prune(100), 1, "not_after_ms == now_ms is expired");
        assert!(!s.contains(&1, 100));
        assert!(s.contains(&2, 100));
        assert_eq!(s.prune(1_000), 1);
        assert!(s.is_empty());
    }

    #[test]
    fn insert_prunes_expired_entries_first() {
        let mut s: ExpiringSet<u32> = set(1);
        assert_eq!(s.insert_if_absent(1, 100, 0), Ok(()));
        assert_eq!(s.insert_if_absent(2, 200, 0), Err(FULL));
        // Once entry 1 ages out the slot is genuinely free.
        assert_eq!(s.insert_if_absent(2, 300, 150), Ok(()));
        assert!(!s.contains(&1, 150));
        assert!(s.contains(&2, 150));
    }

    /// An entry with `not_after_ms <= now_ms` would be born dead: stored,
    /// invisible, and pruned before the next lookup — so the very next replay
    /// of the same key would be *accepted*. It must be refused instead.
    #[test]
    fn an_entry_that_would_be_born_expired_is_refused() {
        let mut s: ExpiringSet<u64> = set(8);
        // Strictly in the past.
        assert_eq!(
            s.insert_if_absent(0x00C0_FFEE, 900_000, 1_000_000),
            Err(ProtocolError::Malformed)
        );
        // Exactly at `now_ms`; `prune` treats this as expired, so insert must
        // agree with it.
        assert_eq!(
            s.insert_if_absent(0x00C0_FFEE, 1_000_000, 1_000_000),
            Err(ProtocolError::Malformed)
        );
        assert!(s.is_empty(), "no capacity may be consumed by a dead entry");
        assert!(!s.contains(&0x00C0_FFEE, 1_000_000));
    }

    /// The property the rejection protects: uniqueness is never silently
    /// absent. Under the old behaviour both calls below returned `Ok(())`.
    #[test]
    fn a_past_expiry_can_never_launder_a_replay_into_acceptance() {
        let mut s: ExpiringSet<u64> = set(8);
        let sid = 42u64;
        let now = 1_000_000u64;
        for _ in 0..8 {
            assert_ne!(
                s.insert_if_absent(sid, now.saturating_sub(1), now),
                Ok(()),
                "a dead entry must never be accepted"
            );
        }
        assert!(s.is_empty());
        // A well-formed record for the same key still works, and is then
        // unique in the way §6.3 requires.
        assert_eq!(s.insert_if_absent(sid, now + TTL, now), Ok(()));
        assert_eq!(
            s.insert_if_absent(sid, now + TTL, now),
            Err(ProtocolError::ReplayDetected)
        );
    }

    /// Parent §6.3, verbatim: "A new handshake from a peer must not evict that
    /// peer's `session_id` record."
    #[test]
    fn a_re_handshake_cannot_evict_the_earlier_session_id() {
        // Two session_ids from the SAME peer; the second is a re-handshake.
        let sid1 = (7u32, 1u32);
        let sid2 = (7u32, 2u32);
        let mut s: ExpiringSet<(u32, u32)> = set(4);
        assert_eq!(s.insert_if_absent(sid1, TTL, 0), Ok(()));
        assert_eq!(s.insert_if_absent(sid2, TTL, 10), Ok(()));

        assert!(s.contains(&sid1, 10), "the first record must survive");
        // The captured no-OPK InitialMessage that derives sid1 still replays
        // into a rejection.
        assert_eq!(
            s.insert_if_absent(sid1, TTL, 20),
            Err(ProtocolError::ReplayDetected)
        );
    }

    #[test]
    fn iter_round_trips_for_persistence() {
        let mut s: ExpiringSet<u32> = set(4);
        assert_eq!(s.insert_if_absent(2, 200, 0), Ok(()));
        assert_eq!(s.insert_if_absent(1, 100, 0), Ok(()));
        let v: alloc::vec::Vec<(u32, u64)> = s.iter().map(|(&k, na)| (k, na)).collect();
        assert_eq!(v, alloc::vec![(1, 100), (2, 200)]);
    }
}
