//! Every capacity-bounded structure in ML-KEM-Braid — and the only place in the
//! project an eviction may be written (parent spec §6, §7 crate table).
//!
//! # Why this crate exists
//!
//! Two rounds of Python patching oscillated (parent spec §6): round 1 made the
//! bounded security caches **evict** on overflow, so an attacker flooded them,
//! the victim's entry was evicted, and the original attack was restored; round 2
//! made them **reject**, so an attacker flooded them and the victim was locked
//! out. The root cause was that every control was keyed on a *free-to-mint*
//! identity, and with a free principal **both** overflow policies lose.
//!
//! # The resolution hierarchy (parent spec §6.1)
//!
//! Each type here declares which tier it implements, and the tier is what makes
//! its overflow policy defensible:
//!
//! | Type | Tier | Policy |
//! |---|---|---|
//! | [`ReplayWindow`] | 1 — unforgeable-small state | none needed; state is two `u64`s |
//! | [`ExpiringSet`] | 2 + 3 — scarce principal, then fail closed | expiry-pruned; never key-evicted |
//! | [`BoundedMap`] | 3 — fail closed | refuses the *new* entry; never evicts |
//! | [`PartitionedPool`] | 2 — partition per principal class | separate allocations; Unknown fails closed |
//!
//! # Purity
//!
//! `no_std` + `alloc`, no clock, no RNG, no global state (parent spec §7). Time
//! enters as a `now_ms: u64` parameter so that every bound is deterministically
//! testable.
//!
//! **`now_ms` is a caller obligation, not a free parameter.** It is the only
//! eviction predicate this crate has, so it MUST be a reading of the local
//! clock and MUST NOT be derived from a received message; see the type docs on
//! [`ExpiringSet::prune`] and [`PartitionedPool::prune_unknown`].
//!
//! # Errors
//!
//! This crate defines no error type. Parent §8.4's [`ProtocolError`] is defined
//! once, in `mlkb-secrets`, and re-exported here; every bounded type takes the
//! spec-named error for *its own* resource from its owner at construction,
//! because §8.4 forbids conflating one resource's exhaustion with another's.
//!
//! # Testing obligation
//!
//! Parent spec §11 gate 5 makes a flood test mandatory for every bounded
//! resource, **in both directions**: fill/overflow the resource, then assert the
//! *original* attack is still rejected **and** an honest peer is still served.
//! Those tests live in `tests/flood.rs`; their absence is why the Python rounds
//! oscillated.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Parent spec §11 gate 7: the panic-free policy is enforced against the code,
// not merely declared. Tests re-allow locally.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::exit
)]
#![deny(missing_docs)]

extern crate alloc;

mod error;
mod expiring;
mod map;
mod pool;
mod replay;

pub use error::ProtocolError;
pub use expiring::ExpiringSet;
pub use map::BoundedMap;
pub use pool::{
    PartitionedPool, PeerClass, Promotion, UNKNOWN_ENTRY_TTL_MS, UNKNOWN_POOL_CAPACITY,
};
pub use replay::{REPLAY_WINDOW_BITS, ReplayWindow};
