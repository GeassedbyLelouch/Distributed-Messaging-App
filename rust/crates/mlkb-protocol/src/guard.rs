//! Handshake replay defence (spec M1 §C.4, parent §6.3, §6.4 rows 1–2).
//!
//! Two controls, because one of them cannot cover first contact:
//!
//! | control | keyed on | catches |
//! |---|---|---|
//! | [`mlkb_bounded::ReplayWindow`] | admitted peer | a replayed `handshake_seq` from a peer we have seen |
//! | [`mlkb_bounded::ExpiringSet`] of `session_id` | the session | a replayed *first* handshake, where there is no floor yet |
//!
//! Neither is a remembered set that grows per message: the floor is two `u64`s
//! per **admitted** peer (parent §6.1 tier 1 — a stranger cannot cause an
//! allocation), and the `session_id` set is expiry-pruned and fails closed.
//!
//! # A re-handshake must not evict a peer's `session_id`
//!
//! Parent §6.3 records this as a hole a design review actually found: a
//! session table that replaced a peer's row on re-handshake would let a
//! captured no-OPK `InitialMessage` replay cleanly afterwards. `ExpiringSet`
//! is a *set*, held independently of any session, and it never key-evicts —
//! `insert_if_absent` refuses a live duplicate rather than displacing it.

use mlkb_bounded::{BoundedMap, ExpiringSet, ReplayWindow};
use mlkb_secrets::ProtocolError;
use mlkb_wire::IdentityId;

/// Per-responder handshake admission state (spec parent §6.3, §6.4 rows 1–2).
///
/// Sans-io like the rest of the crate: `now_ms` is a parameter, never a
/// reading. `mlkb-bounded` states the caller's obligation for it — it MUST be
/// the local clock and MUST NOT be derived from a received message, because it
/// is the only eviction predicate in the whole crate.
#[derive(Debug)]
pub struct HandshakeGuard {
    floors: BoundedMap<IdentityId, ReplayWindow>,
    sessions: ExpiringSet<[u8; 32]>,
}

impl HandshakeGuard {
    /// Bounds both controls (spec parent §6.1 tier 3, §6.4).
    ///
    /// `max_peers` bounds the floor table and `max_sessions` the first-contact
    /// set. Both report [`ProtocolError::FirstContactCapacity`] on overflow:
    /// parent §6.6 point 4 forbids surfacing that exhaustion as a silent drop,
    /// and conflating it with [`ProtocolError::SkippedKeyLimit`] — a different
    /// resource — is what parent §8.4 forbids.
    #[must_use]
    pub fn new(max_peers: usize, max_sessions: usize) -> Self {
        Self {
            floors: BoundedMap::new(max_peers, ProtocolError::FirstContactCapacity),
            sessions: ExpiringSet::new(max_sessions, ProtocolError::FirstContactCapacity),
        }
    }

    /// Decides one handshake and, if it is accepted, records it
    /// (spec M1 §C.4, parent §6.3).
    ///
    /// # Ordering
    ///
    /// Every check runs against a copy before anything is written, so a
    /// rejected handshake consumes neither a window slot nor a set slot. The
    /// `session_id` set is consulted **after** the floor, because a peer that
    /// fails the floor is one we already know, and admitting its `session_id`
    /// to the set would spend capacity on a message we are refusing anyway.
    ///
    /// # Errors
    /// - [`ProtocolError::ReplayDetected`] if `handshake_seq` is at or below
    ///   the peer's floor or already inside its window, or if `session_id` has
    ///   been seen and has not expired.
    /// - [`ProtocolError::Malformed`] if `not_after_ms <= now_ms`, i.e. the
    ///   record would be born expired and the uniqueness property would be
    ///   silently void.
    /// - [`ProtocolError::FirstContactCapacity`] if either bound is reached.
    pub fn admit(
        &mut self,
        peer: &IdentityId,
        handshake_seq: u64,
        session_id: [u8; 32],
        not_after_ms: u64,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        // `ReplayWindow` is `Copy`, so this decides against a copy and leaves
        // the stored floor untouched until every check has passed.
        let advanced = if let Some(existing) = self.floors.get(peer) {
            let mut candidate = *existing;
            candidate.check_and_update(handshake_seq)?;
            Some(candidate)
        } else {
            // M1 §C.4: a first accepted handshake starts a window. Capacity is
            // *decided* here, not attempted below: a full floor table would
            // otherwise refuse the write after the `session_id` had been
            // recorded, spending a slot of one bounded resource on a failure
            // of another.
            if self.floors.is_full() {
                return Err(ProtocolError::FirstContactCapacity);
            }
            None
        };

        self.sessions
            .insert_if_absent(session_id, not_after_ms, now_ms)?;

        let floor = advanced.unwrap_or_else(|| ReplayWindow::new(handshake_seq));
        self.floors.insert(*peer, floor)?;
        Ok(())
    }

    /// How many peers hold a floor (parent §6.4 row 1).
    #[must_use]
    pub fn peers(&self) -> usize {
        self.floors.len()
    }

    /// How many live `session_id`s are recorded (parent §6.4 row 2).
    #[must_use]
    pub fn sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Drops expired `session_id` records, returning how many went
    /// (parent §6.3).
    ///
    /// `now_ms` must be a reading of the local clock; see the type docs.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        self.sessions.prune(now_ms)
    }
}
