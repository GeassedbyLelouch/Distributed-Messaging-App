//! Every wire type and its exact-length parser (spec parent §3, M1 §A, §C.3,
//! §D.3, §F).
//!
//! # What this crate is for
//!
//! Parent §7 gives this crate one choke point — "every wire type and its
//! exact-length parser" — against three named defect classes: audit M1 (a MAC
//! that did not cover the framing), audit L7 (trailing bytes accepted), and
//! parser denial of service. Everything here is written for hostile input:
//! there is no `Default`, no lenient mode, and nothing is ever normalized.
//!
//! # The two encodings, and where the boundary is
//!
//! - [`Frame`] is a **fixed big-endian layout** (M1 §A.1). It is the sole
//!   exception to parent §3.2, and the reason is that parent §3.3's MAC input
//!   *is* the transmitted bytes: under CBOR the preimage and the wire bytes
//!   would differ and every implementer would have to invent a reconstruction
//!   step.
//! - Every **payload** structure — [`InitialMessageV2`], [`RatchetMessage`],
//!   [`PrekeyBundleV2`], [`EnrolmentProof`] — is deterministic CBOR, produced
//!   and checked by `mlkb-codec` (M1 §B). This crate contains no second
//!   encoder; it names map keys and field widths and nothing else.
//!
//! # Rules that are parser properties here, not caller discipline
//!
//! | Rule | Where |
//! |---|---|
//! | `msg_type` is validated only *after* the MAC verifies (M1 §A.1 rule 6) | [`Frame::decode`] |
//! | A payload-free `msg_type` may not declare a length (M1 §A.1 rule 7) | [`Frame::decode`], [`Frame::seal`] |
//! | A short buffer is `NeedMore`, not an error (M1 §A.1 rule 3) | [`Frame::decode`] |
//! | Trailing bytes are refused (M1 §A.1 rule 4, parent §3.2 rule 5) | [`Frame::decode`], every payload decoder |
//! | `"ek"`/`"kc"` present together and exactly when `n == 0` (M1 §D.3) | [`RatchetMessage`] |
//! | An absent value omits its key; `null` does not exist (M1 §B.3) | `mlkb-codec` |
//!
//! # Allocation discipline
//!
//! No wire-declared length is ever used as an allocation hint (M1 §A.1
//! rule 2). [`Frame::decode`] refuses an oversized `payload_len` before it
//! touches the heap and allocates the payload only after the MAC verifies;
//! `mlkb-codec`'s decoder bounds every CBOR allocation by the length of the
//! input it was actually given. `tests/alloc_amplification.rs` measures both.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Spec parent §11 gate 7: the panic-free lint policy is enforced against the
// code, not merely declared. Tests re-allow these locally.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

extern crate alloc;

pub mod labels;

mod bundle;
mod enrolment;
mod frame;
mod identity;
mod initial;
mod ratchet;
#[cfg(test)]
mod testkit;
mod util;

pub use bundle::{
    HybridIdentityPublic, OneTimePrekey, PrekeyBundleV2, SignedPqPrekey, SignedPrekey,
};
pub use enrolment::EnrolmentProof;
pub use frame::{FRAME_HEADER_LEN, FRAME_MAC_LEN, Frame, MAX_FRAME_PAYLOAD, MsgType};
pub use identity::IdentityId;
pub use initial::InitialMessageV2;
pub use ratchet::{RatchetMessage, RatchetStep};

/// The one protocol version (spec parent §3.1, M1 §I).
///
/// Every top-level wire struct begins with it and a mismatch is a hard reject:
/// there is no negotiation, because negotiation is a downgrade surface.
///
/// No structure in this crate stores it in a field. It is a constant of the
/// format, so there is nothing for a caller to set wrongly and nothing for a
/// decoder to carry forward; each type exposes it through a `version()` that
/// returns this constant, and each decoder refuses anything else.
pub const PROTOCOL_VERSION: u16 = 0x0200;
