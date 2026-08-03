//! Where the project error type lives — which is **not here** (parent spec
//! §8.4).
//!
//! # Why this module defines nothing
//!
//! Parent §8.4 specifies one `ProtocolError` and does not assign it a crate.
//! This crate previously defined a second one, which diverged from
//! [`mlkb_secrets`]'s in variant set, `Display` strings, and derives — the
//! duplicate-implementation class parent §7's choke-point table exists to
//! prevent. `mlkb-secrets` already owns `Progress<T>`, the other half of §8.4,
//! and its variant set is exactly the one §8.4 names, so it is the single home.
//!
//! This crate therefore re-exports rather than redefines (rule zero: one
//! definition). The DAG edge is new but acyclic: `mlkb-secrets` has no internal
//! dependencies and both crates are `no_std` + pure.
//!
//! # Consequence: this crate invents no variants
//!
//! The discarded local definition carried two variants §8.4 does not name,
//! `Capacity` and `NotFound`. Neither is reintroduced:
//!
//! - the generic capacity error is gone because every bounded type here now
//!   takes its overflow error from its owner at construction, which is what
//!   §8.4's no-conflation rule asks for ([`crate::BoundedMap`] already did);
//! - the not-found error is gone because "that key was not pending" is an
//!   outcome, not a failure — see [`crate::Promotion::NotPending`].

pub use mlkb_secrets::ProtocolError;
