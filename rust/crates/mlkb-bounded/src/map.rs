//! A capacity-bounded map that **fails closed** (parent spec §6.4 row 3,
//! spec M1 §D.4).
//!
//! Nothing here evicts. Parent §6.1 tier 3 permits fail-closed only when the
//! key is already inside an admitted, scarce principal — for the skipped-key
//! store that principal is the authenticated *session*, so a stranger cannot
//! consume the bound. Spec M1 §D.4 states the consequence directly: evicting a
//! cached key silently and permanently destroys an authentic delayed message,
//! so the **new** entry is refused instead.

use alloc::collections::BTreeMap;

use crate::error::ProtocolError;

/// A `BTreeMap` with a hard capacity and no eviction path.
///
/// The overflow error is chosen at construction so that each caller reports the
/// spec-named failure for its own resource (parent spec §8.4 forbids
/// conflation): the skipped-key store passes
/// [`ProtocolError::SkippedKeyLimit`], the serverless Unknown pool passes
/// [`ProtocolError::FirstContactCapacity`] (parent spec §6.6).
#[derive(Debug, Clone)]
pub struct BoundedMap<K, V> {
    map: BTreeMap<K, V>,
    capacity: usize,
    overflow: ProtocolError,
}

impl<K: Ord, V> BoundedMap<K, V> {
    /// Create a map bounded at `capacity`, reporting `overflow` when full.
    #[must_use]
    pub const fn new(capacity: usize, overflow: ProtocolError) -> Self {
        Self {
            map: BTreeMap::new(),
            capacity,
            overflow,
        }
    }

    /// The hard bound.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Entries currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the map holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Whether the map is at its bound; the next new key will be refused.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.map.len() >= self.capacity
    }

    /// Whether `key` is present.
    #[must_use]
    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Borrow the value for `key`.
    #[must_use]
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Mutably borrow the value for `key`.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    /// Insert, failing closed at capacity (spec M1 §D.4).
    ///
    /// Replacing an existing key does not grow the map and is therefore always
    /// permitted, but the displaced value is **returned to the caller** rather
    /// than dropped here — this crate never destroys an entry silently.
    ///
    /// # Errors
    ///
    /// The configured overflow error when `key` is absent and the map is full.
    /// The map is left untouched, so the *new* entry is the one refused.
    pub fn insert(&mut self, key: K, value: V) -> Result<Option<V>, ProtocolError> {
        if self.is_full() && !self.map.contains_key(&key) {
            return Err(self.overflow);
        }
        Ok(self.map.insert(key, value))
    }

    /// Insert only if `key` is absent.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ReplayDetected`] if `key` is already present; the
    /// configured overflow error if the map is full.
    pub fn insert_if_absent(&mut self, key: K, value: V) -> Result<(), ProtocolError> {
        if self.map.contains_key(&key) {
            return Err(ProtocolError::ReplayDetected);
        }
        if self.is_full() {
            return Err(self.overflow);
        }
        let _displaced = self.map.insert(key, value);
        Ok(())
    }

    /// Take the entry for `key`.
    ///
    /// This is *consumption*, not eviction: the owner asks for a specific entry
    /// it is about to use (a skipped message key is used exactly once).
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.map.remove(key)
    }

    /// Drop the entries for which `drop_if` returns `true`.
    ///
    /// The owner supplies the predicate — e.g. spec M1 §D.4's "chains for
    /// `RETAINED_RECV_CHAINS` previous generations are retained". This is a
    /// deliberate, owner-directed drop, not a capacity eviction: it is never
    /// reachable from an overflow path.
    ///
    /// This is the **only** predicate-driven removal on this type. A `retain`
    /// twin taking the negated predicate used to sit beside it; parent §7 makes
    /// this crate "the only place an eviction can be written", which makes the
    /// removal surface the thing an auditor reads most closely, and two entry
    /// points for one removal distinguished only by the polarity of a closure
    /// double that surface and invite a polarity bug at a call site.
    pub fn prune(&mut self, mut drop_if: impl FnMut(&K, &V) -> bool) {
        self.map.retain(|k, v| !drop_if(k, v));
    }

    /// Drop every entry (session teardown).
    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Iterate entries in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter()
    }

    /// Iterate keys in order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::{BoundedMap, ProtocolError};

    fn map(cap: usize) -> BoundedMap<u32, u32> {
        BoundedMap::new(cap, ProtocolError::SkippedKeyLimit)
    }

    #[test]
    fn insert_and_get() {
        let mut m = map(4);
        assert!(m.is_empty());
        assert_eq!(m.insert(1, 10), Ok(None));
        assert_eq!(m.get(&1), Some(&10));
        assert_eq!(m.len(), 1);
        assert!(!m.is_full());
    }

    #[test]
    fn overflow_refuses_the_new_entry_and_never_evicts() {
        let mut m = map(3);
        for k in 0..3u32 {
            assert_eq!(m.insert(k, k), Ok(None));
        }
        assert!(m.is_full());
        assert_eq!(m.insert(99, 99), Err(ProtocolError::SkippedKeyLimit));
        // Every pre-existing entry survives, byte for byte.
        for k in 0..3u32 {
            assert_eq!(m.get(&k), Some(&k));
        }
        assert_eq!(m.len(), 3);
        assert_eq!(m.get(&99), None);
    }

    #[test]
    fn replacement_at_capacity_returns_the_displaced_value() {
        let mut m = map(2);
        assert_eq!(m.insert(1, 10), Ok(None));
        assert_eq!(m.insert(2, 20), Ok(None));
        assert!(m.is_full());
        // Same key: no growth, and the old value comes back to the caller
        // rather than being dropped here.
        assert_eq!(m.insert(1, 11), Ok(Some(10)));
        assert_eq!(m.get(&1), Some(&11));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn insert_if_absent_rejects_duplicates() {
        let mut m = map(2);
        assert_eq!(m.insert_if_absent(1, 10), Ok(()));
        assert_eq!(
            m.insert_if_absent(1, 99),
            Err(ProtocolError::ReplayDetected)
        );
        assert_eq!(m.get(&1), Some(&10), "the original must not be replaced");
    }

    #[test]
    fn overflow_error_is_the_one_configured() {
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(1, ProtocolError::FirstContactCapacity);
        assert_eq!(m.insert(0, 0), Ok(None));
        assert_eq!(m.insert(1, 1), Err(ProtocolError::FirstContactCapacity));
    }

    #[test]
    fn remove_is_consumption_and_frees_a_slot() {
        let mut m = map(2);
        assert_eq!(m.insert(1, 10), Ok(None));
        assert_eq!(m.insert(2, 20), Ok(None));
        assert_eq!(m.insert(3, 30), Err(ProtocolError::SkippedKeyLimit));
        assert_eq!(m.remove(&1), Some(10));
        assert_eq!(m.remove(&1), None);
        assert_eq!(m.insert(3, 30), Ok(None), "a consumed slot is reusable");
    }

    #[test]
    fn prune_drops_exactly_the_matching_entries_and_frees_their_slots() {
        let mut m = map(8);
        for k in 0..8u32 {
            assert_eq!(m.insert(k, k), Ok(None));
        }
        assert!(m.is_full());
        m.prune(|k, _| k % 2 != 0);
        let kept: alloc::vec::Vec<u32> = m.keys().copied().collect();
        assert_eq!(kept, alloc::vec![0, 2, 4, 6]);
        // An owner-directed drop genuinely reopens the bound.
        assert!(!m.is_full());
        assert_eq!(m.insert(9, 9), Ok(None));
    }

    #[test]
    fn prune_can_drop_everything_or_nothing() {
        let mut m = map(4);
        for k in 0..4u32 {
            assert_eq!(m.insert(k, k), Ok(None));
        }
        m.prune(|_, _| false);
        assert_eq!(m.len(), 4, "a false predicate removes nothing");
        m.prune(|_, _| true);
        assert!(m.is_empty(), "a true predicate removes everything");
    }

    #[test]
    fn clear_empties() {
        let mut m = map(2);
        assert_eq!(m.insert(1, 1), Ok(None));
        m.clear();
        assert!(m.is_empty());
    }

    #[test]
    fn zero_capacity_accepts_nothing() {
        let mut m = map(0);
        assert!(m.is_full());
        assert_eq!(m.insert(0, 0), Err(ProtocolError::SkippedKeyLimit));
        assert!(m.is_empty());
    }
}
