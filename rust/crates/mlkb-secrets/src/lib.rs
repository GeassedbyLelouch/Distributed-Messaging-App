//! Secret containers, the injected AEAD nonce, and the protocol error type.
//!
//! # What lives here, and what deliberately does not
//!
//! Per spec M1 §G.1 this crate owns the *containers* only — the byte-holding
//! wrappers with constant-time equality, redacting `Debug`, and zeroize-on-drop
//! (spec parent §8.2). The *typed* keys built on those containers
//! (`KemSharedSecret`, `RootKey`, `ChainKey`, `MessageKey`, `FrameKey`) live in
//! `mlkb-crypto`, because parent §4.1 requires that each have exactly one
//! private constructor and Rust cannot grant one *other* crate that privilege.
//! M1 §G.1 resolves the conflict in favour of the invariant. Do not add typed
//! keys here.
//!
//! `CanonicalBytes` and `Aad` (M1 §G.3) likewise do not live here: they are
//! constructible only by `mlkb_codec::encode_canonical`, so they belong to
//! `mlkb-codec`.
//!
//! This crate is `no_std`; it links `alloc` only so that its own tests can
//! format strings.

#![no_std]
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

#[cfg(test)]
extern crate alloc;

mod error;
mod nonce;
mod secret;

pub use error::{Progress, ProtocolError};
pub use nonce::{Nonce192, WireNonce};
pub use secret::{Secret32, SecretBytes};
