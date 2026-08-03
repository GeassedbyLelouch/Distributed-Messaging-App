//! Every algorithm and nonce choice in ML-KEM-Braid (spec parent §5, M1 §E,
//! §G).
//!
//! # What this crate is for
//!
//! One place per primitive, and no second spelling of any of them. Concretely:
//!
//! - The **only** X25519 Diffie-Hellman is [`x25519_dh`], and it performs both
//!   fail-closed checks of spec M1 §C.2 on every call. `x25519-dalek` is not
//!   re-exported (M1 §C.2, §H Q5: it returns the all-zero shared secret for a
//!   low-order peer key rather than failing).
//! - The **only** source of a [`KemSharedSecret`] is a real ML-KEM-1024
//!   operation in [`kem`], and [`derive_sk`] consumes one by value. That is
//!   what makes spec parent §4.1's "no root key without the PQ leg" structural
//!   rather than advisory.
//! - The **only** signature-context values are [`SigContext`]'s (M1 §E.2), and
//!   the **only** HKDF labels are [`labels`]'s (parent §4.4). Nothing else in
//!   the workspace writes one of those byte strings.
//! - The **only** AEAD is XChaCha20-Poly1305 (parent §5.1), reachable only
//!   through [`MessageKey::seal`]/[`MessageKey::open`] and
//!   [`StoreKey`], all of which take their associated data as an [`Aad`]
//!   (parent §8.3, M1 §G.3) and their nonce as an injected value (M1 §G.2).
//!
//! # `no_std`
//!
//! `no_std + alloc`, per spec M1 §G.4, along with the rest of the subtree.
//! `alloc` is needed unconditionally: [`HybridSignature`] and the AEAD both
//! return owned buffers.

#![no_std]
#![forbid(unsafe_code)]
// Spec parent §11 gate 7: the panic-free lint policy is enforced against the
// code, not merely declared. Test modules re-allow these locally.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

extern crate alloc;

pub mod labels;

mod aead;
mod hash;
mod hybrid;
mod kem;
mod keys;
mod mldsa;
mod util;
mod x25519;

/// XEd25519 (spec parent §3.6, §5.4), a module rather than a type because its
/// raw and framed paths are two named functions.
pub mod xeddsa;

pub use aead::{AEAD_KEY_LEN, AEAD_NONCE_LEN, AEAD_TAG_LEN, Aad, Ciphertext, StoreKey};
pub use hash::{
    HKDF_MAX_OKM, Mac256, Prk, SHA256_LEN, SHA512_LEN, hkdf_sha256, hmac_sha256, sha256, sha512,
};
pub use hybrid::{
    HYBRID_SIGNATURE_LEN, HYBRID_SIGNATURE_SUITE, HYBRID_SIGNATURE_VERSION, HybridSignature,
    signed_message,
};
pub use kem::{
    KEM_CIPHERTEXT_LEN, KEM_ENCAPSULATION_KEY_LEN, KEM_SEED_LEN, KEM_SHARED_SECRET_LEN,
    KemCiphertext, KemDecapsulationKey, KemEncapsulationKey,
};
pub use keys::{
    ChainKey, DhLegs, DhOutput, FrameDirection, FrameKey, KemSharedSecret, MessageKey, RootKey,
    SkInfo, derive_sk,
};
pub use labels::SigContext;
pub use mldsa::{
    MLDSA_MAX_CONTEXT_LEN, MLDSA_SEED_LEN, MLDSA_SIGNATURE_LEN, MLDSA_VERIFYING_KEY_LEN,
    MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey,
};
pub use x25519::{X25519PublicKey, X25519SecretKey, x25519_dh};
pub use xeddsa::XEDDSA_SIGNATURE_LEN;
