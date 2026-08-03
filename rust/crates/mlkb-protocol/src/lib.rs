//! Every ML-KEM-Braid state transition and key schedule — sans-io
//! (spec parent §7, §8, M1 §C, §D).
//!
//! # What this crate owns
//!
//! Parent §7 gives it one choke point: *every state transition and key
//! schedule; sans-io, no clock/RNG/global*, against the defect classes audit
//! M1 (state advanced on unauthenticated input), audit M2, and the §4
//! invariants. Concretely:
//!
//! - **PQXDH**, initiator and responder, with M1 §C.1's legs pinned in one
//!   place and every bundle signature verified before any key in it is used
//!   ([`initiate`], [`respond`], [`verify_bundle`]).
//! - **The M1 §D hybrid ratchet** — the one part of this protocol with no
//!   Python ancestor. Each DH ratchet step mixes a fresh X25519 output *and* a
//!   fresh ML-KEM-1024 encapsulation into the root step, so breaking the chain
//!   requires breaking both (M1 §D.1).
//! - **Classify / apply**, so that "authenticate, then mutate" is a shape
//!   rather than a discipline (parent §8.1, [`Session::classify`],
//!   [`Session::apply`], [`Plan`]).
//! - **The skipped-key store**, which fails closed and never evicts
//!   (M1 §D.4).
//! - **Handshake replay defence**, floor plus first-contact `session_id`
//!   ([`HandshakeGuard`], M1 §C.4, parent §6.3).
//!
//! # Sans-io, and what that costs the caller
//!
//! There is no clock and no RNG here, and no global of any kind.
//!
//! - **Time** never enters at all. Expiry of a prekey bundle
//!   (`BUNDLE_MAX_AGE_MS`) and of an `EnrolmentProof` are the caller's, and
//!   [`HandshakeGuard`] takes `now_ms` as an argument.
//! - **Randomness** enters through [`Entropy`] and nowhere else (M1 §G.2,
//!   §I.3). That trait is the whole of this crate's dependency on chance, and
//!   its implementer carries the obligation M1 §I.3 spells out.
//! - **I/O and durability** are `mlkb-transport`'s and `mlkb-store`'s. A
//!   [`Session`] is a value; persisting one is parent §9's problem, and the
//!   rollback defence of parent §5.2 lives there.
//!
//! # The order of operations, once
//!
//! A receiver runs exactly three steps, and the boundaries between them are
//! where the security properties sit:
//!
//! ```text
//! Session::decode_frame  ->  Session::classify  ->  Session::apply
//!   frame MAC (M1 §A.1)      everything else        the only mutation
//!   msg_type after it        borrows; cannot        (parent §8.1)
//!   (rule 6)                 mutate
//! ```
//!
//! Nothing between `decode_frame` and `apply` writes to the session, so a
//! frame that is refused at any point leaves no trace — which is the property
//! M1 §D.4 calls load-bearing, and the reason its two bounds are checked
//! before a single key is derived.

#![no_std]
#![forbid(unsafe_code)]
// Spec parent §11 gate 7: the panic-free lint policy is enforced against the
// code, not merely declared. Test modules re-allow these locally.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
#![deny(missing_docs)]

extern crate alloc;

mod entropy;
mod guard;
mod pqxdh;
mod ratchet;
mod session;

#[cfg(test)]
mod testkit;
#[cfg(test)]
mod tests;

pub use entropy::Entropy;
pub use guard::HandshakeGuard;
pub use pqxdh::{
    Accepted, Initiated, LocalIdentity, ResponderPrekeys, initiate, respond, verify_bundle,
};
pub use ratchet::{MAX_SKIP_PER_CHAIN, MAX_SKIPPED_KEYS_PER_SESSION, RETAINED_RECV_CHAINS};
pub use session::{Event, Plaintext, Plan, Role, Session};
