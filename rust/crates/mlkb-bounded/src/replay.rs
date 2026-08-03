//! The 64-bit sliding replay window (spec M1 §C.4, parent spec §6.3).
//!
//! This is parent §6.1's **tier 1** pattern — "unforgeable-small state". The
//! whole per-peer state is two `u64`s, so there is no overflow policy to get
//! wrong and nothing an attacker can cause to grow.

use crate::error::ProtocolError;

/// Width of the sliding window, in bits (spec M1 §I `REPLAY_WINDOW_BITS`).
pub const REPLAY_WINDOW_BITS: u64 = 64;

/// Per-peer handshake replay state (parent spec §6.4 row 1).
///
/// Scoped per `(initiator IdentityId, responder device_id)` by the owner
/// (parent spec §6.3). `Self` is created only for a peer that has already been
/// admitted, so a stranger cannot cause an allocation.
///
/// Bit *i* of the window means `last_seq - i` has been seen; bit 0 is always
/// set (spec M1 §C.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayWindow {
    last_seq: u64,
    window: u64,
}

impl ReplayWindow {
    /// Initial state on a peer's first accepted handshake (spec M1 §C.4).
    #[must_use]
    pub const fn new(first_seq: u64) -> Self {
        Self {
            last_seq: first_seq,
            window: 1,
        }
    }

    /// Rebuild from persisted parts (parent spec §9 durability).
    ///
    /// Bit 0 is re-asserted because spec M1 §C.4 makes it an invariant: a
    /// persisted `0` would otherwise let `last_seq` itself be replayed.
    #[must_use]
    pub const fn from_parts(last_seq: u64, window: u64) -> Self {
        Self {
            last_seq,
            window: window | 1,
        }
    }

    /// The high-water mark.
    #[must_use]
    pub const fn last_seq(&self) -> u64 {
        self.last_seq
    }

    /// The window bitmap, for persistence.
    #[must_use]
    pub const fn window(&self) -> u64 {
        self.window
    }

    /// Decide `seq` and, if accepted, advance the window (spec M1 §C.4).
    ///
    /// The parent spec's `seq <= last_seq - 64` form underflows for every peer
    /// whose `last_seq < 64`; spec M1 §C.4 replaces it and this is that
    /// replacement. Every subtraction below is `checked_*` so the predicate is
    /// total for all of `u64`.
    ///
    /// # Errors
    ///
    /// [`ProtocolError::ReplayDetected`] if `seq` is at or below the floor, or
    /// is inside the window and already marked.
    pub fn check_and_update(&mut self, seq: u64) -> Result<(), ProtocolError> {
        if let Some(delta) = seq.checked_sub(self.last_seq) {
            // `seq >= last_seq`.
            if delta == 0 {
                // Bit 0 is always set, so `last_seq` itself is always a replay.
                return Err(ProtocolError::ReplayDetected);
            }
            self.window = if delta >= REPLAY_WINDOW_BITS {
                1
            } else {
                // `delta < 64`, so the shift is defined.
                (self.window << delta) | 1
            };
            self.last_seq = seq;
            Ok(())
        } else {
            // `seq < last_seq`, so `last_seq - seq` cannot underflow. The
            // `unwrap_or` is unreachable and degrades to "outside the window",
            // i.e. reject — the fail-closed direction.
            let back = self.last_seq.checked_sub(seq).unwrap_or(REPLAY_WINDOW_BITS);
            if back >= REPLAY_WINDOW_BITS {
                // Equivalent to the spec's `seq + 64 <= last_seq`, without the
                // addition that can overflow near `u64::MAX`.
                return Err(ProtocolError::ReplayDetected);
            }
            // `back < 64`, so the shift is defined.
            let bit = 1u64 << back;
            if self.window & bit != 0 {
                return Err(ProtocolError::ReplayDetected);
            }
            self.window |= bit;
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::{ProtocolError, REPLAY_WINDOW_BITS, ReplayWindow};

    fn err() -> ProtocolError {
        ProtocolError::ReplayDetected
    }

    #[test]
    fn first_seq_is_immediately_a_replay() {
        let mut w = ReplayWindow::new(7);
        assert_eq!(w.last_seq(), 7);
        assert_eq!(w.window(), 1);
        assert_eq!(w.check_and_update(7), Err(err()));
    }

    #[test]
    fn in_order_sequence_is_accepted() {
        let mut w = ReplayWindow::new(0);
        for seq in 1..1000u64 {
            assert_eq!(w.check_and_update(seq), Ok(()), "seq {seq}");
        }
        assert_eq!(w.last_seq(), 999);
    }

    #[test]
    fn every_accepted_seq_is_rejected_on_replay() {
        let mut w = ReplayWindow::new(0);
        for seq in 1..64u64 {
            assert_eq!(w.check_and_update(seq), Ok(()));
        }
        // The whole window is now populated; replay each one.
        for seq in 0..64u64 {
            assert_eq!(w.check_and_update(seq), Err(err()), "replay of {seq}");
        }
    }

    #[test]
    fn reordering_within_the_window_is_accepted_once() {
        let mut w = ReplayWindow::new(0);
        assert_eq!(w.check_and_update(10), Ok(()));
        // 1..=9 arrive late, out of order.
        for seq in [5u64, 9, 1, 3, 7, 2, 8, 4, 6] {
            assert_eq!(w.check_and_update(seq), Ok(()), "late {seq}");
            assert_eq!(w.check_and_update(seq), Err(err()), "dup {seq}");
        }
        assert_eq!(w.last_seq(), 10, "a late message must not move the floor");
    }

    /// Spec M1 §C.4 exists because the parent's `seq <= last_seq - 64`
    /// underflows for a freshly admitted peer. This is that case.
    #[test]
    fn small_seq_values_do_not_underflow() {
        for first in 0..REPLAY_WINDOW_BITS {
            let mut w = ReplayWindow::new(first);
            // Anything at or below `first` that is inside the window: the only
            // already-marked one is `first` itself.
            for seq in 0..=first {
                let expect_ok = seq != first;
                assert_eq!(
                    w.check_and_update(seq).is_ok(),
                    expect_ok,
                    "first={first} seq={seq}"
                );
            }
            // Under the parent's buggy form `last_seq - 64` wraps to a huge
            // number and `seq <= that` rejects everything. Here it does not.
            assert_eq!(w.check_and_update(first + 1), Ok(()));
        }
    }

    #[test]
    fn boundary_at_exactly_64_back() {
        let mut w = ReplayWindow::new(0);
        assert_eq!(w.check_and_update(100), Ok(()));
        // seq + 64 <= last_seq  <=>  last_seq - seq >= 64
        assert_eq!(w.check_and_update(36), Err(err()), "100-36 == 64: too old");
        assert_eq!(w.check_and_update(37), Ok(()), "100-37 == 63: in window");
        assert_eq!(w.check_and_update(37), Err(err()), "now a duplicate");
    }

    #[test]
    fn far_future_jump_resets_the_window() {
        let mut w = ReplayWindow::new(0);
        assert_eq!(w.check_and_update(5), Ok(()));
        assert_eq!(w.check_and_update(1_000_000), Ok(()));
        assert_eq!(w.window(), 1, "a >=64 jump clears the bitmap");
        // Everything before the new floor is now unconditionally too old.
        assert_eq!(w.check_and_update(5), Err(err()));
        assert_eq!(w.check_and_update(999_936), Err(err()), "exactly 64 back");
        assert_eq!(w.check_and_update(999_937), Ok(()), "63 back is still live");
    }

    #[test]
    fn jump_of_exactly_63_shifts_rather_than_clears() {
        let mut w = ReplayWindow::new(0);
        assert_eq!(w.check_and_update(63), Ok(()));
        assert_eq!(w.window(), (1u64 << 63) | 1);
        assert_eq!(w.check_and_update(0), Err(err()), "seq 0 is still marked");
    }

    #[test]
    fn saturates_safely_at_the_top_of_u64() {
        let mut w = ReplayWindow::new(u64::MAX - 10);
        assert_eq!(w.check_and_update(u64::MAX), Ok(()));
        assert_eq!(w.check_and_update(u64::MAX), Err(err()));
        // `seq + 64` would overflow here; the checked form must still accept.
        assert_eq!(w.check_and_update(u64::MAX - 5), Ok(()));
        assert_eq!(w.check_and_update(u64::MAX - 63), Ok(()));
        assert_eq!(w.check_and_update(u64::MAX - 64), Err(err()));
    }

    #[test]
    fn from_parts_round_trips_and_forces_bit_zero() {
        let mut w = ReplayWindow::new(500);
        assert_eq!(w.check_and_update(501), Ok(()));
        let restored = ReplayWindow::from_parts(w.last_seq(), w.window());
        assert_eq!(restored, w);

        // A corrupt/zero bitmap must not make `last_seq` replayable.
        let mut z = ReplayWindow::from_parts(9, 0);
        assert_eq!(z.check_and_update(9), Err(err()));
    }

    /// Property: over an arbitrary interleaving, a sequence number is accepted
    /// at most once, and never after the floor has moved 64 past it.
    #[test]
    fn property_accepts_each_seq_at_most_once() {
        // A deterministic LCG stands in for a property-test driver; the crate
        // is pure and takes no RNG (parent spec §7).
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            state
        };

        for _ in 0..64 {
            let mut w = ReplayWindow::new(0);
            let mut accepted = alloc::collections::BTreeSet::new();
            accepted.insert(0u64);
            for _ in 0..2000 {
                let seq = next() % 400;
                let before_floor = w.last_seq();
                let res = w.check_and_update(seq);
                if res.is_ok() {
                    assert!(accepted.insert(seq), "seq {seq} accepted twice");
                    assert!(
                        seq + REPLAY_WINDOW_BITS > before_floor,
                        "accepted a seq at/below the floor"
                    );
                } else {
                    assert!(
                        accepted.contains(&seq) || seq + REPLAY_WINDOW_BITS <= before_floor,
                        "rejected a fresh, in-window seq {seq} (floor {before_floor})"
                    );
                }
            }
        }
    }
}
