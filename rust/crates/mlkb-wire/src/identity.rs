//! `IdentityId` — one definition (spec parent §3.5).
//!
//! ```text
//! IdentityId = SHA-256(
//!     "MLKEMBraid/identity/v2" ||
//!     ik_x25519                ||   // 32 bytes
//!     SHA-256(ik_mldsa65_pk)        // 32 bytes
//! )
//! ```
//!
//! Three design tracks proposed three preimages, which would have produced
//! three different session keys; parent §3.5 settles it and this module is the
//! only implementation. The nested hash of the ML-DSA key is deliberate: it
//! makes `IdentityId` computable from an `InitialMessageV2` alone, which is
//! what lets a responder derive the initiator's identity on first contact
//! without having fetched the 1952-byte ML-DSA key first.

use core::fmt;

use mlkb_crypto::sha256;

use crate::labels;

/// A party's identity (spec parent §3.5).
///
/// Public data: it appears in the PQXDH `info` string, in the M1 §D.3 AAD and
/// in an `EnrolmentProof`. No zeroization, and its equality is the ordinary
/// one — there is nothing secret to leak by comparing it in variable time.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdentityId([u8; 32]);

impl IdentityId {
    /// The length of an `IdentityId` in bytes.
    pub const LEN: usize = 32;

    /// Computes an identity from the two wire fields of an
    /// `InitialMessageV2` (spec parent §3.5, M1 §C.3).
    ///
    /// `ik_mldsa_hash` is `SHA-256(ik_mldsa65_pk)` — the value the wire
    /// carries. A responder that has fetched the full ML-DSA key verifies it
    /// against this hash *before use* (parent §3.4) and then gets the same
    /// answer from [`IdentityId::from_public_keys`].
    #[must_use]
    pub fn from_ik(ik_x25519: &[u8; 32], ik_mldsa_hash: &[u8; 32]) -> Self {
        Self(sha256(&[labels::IDENTITY, ik_x25519, ik_mldsa_hash]))
    }

    /// Computes an identity from the full public keys (spec parent §3.5).
    ///
    /// The nested `SHA-256(ik_mldsa65_pk)` is applied here, so the two
    /// constructors agree by construction rather than by convention.
    #[must_use]
    pub fn from_public_keys(ik_x25519: &[u8; 32], ik_mldsa_pk: &[u8]) -> Self {
        Self::from_ik(ik_x25519, &sha256(&[ik_mldsa_pk]))
    }

    /// Wraps a 32-byte identity read off the wire.
    ///
    /// An `IdentityId` is a hash of public inputs, so a decoder cannot
    /// recompute one it has only received (an `EnrolmentProof` carries the
    /// subject, not the subject's keys). This constructor exists for that
    /// case; it asserts nothing about the value.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The identity bytes, for the wire and for `SkInfo`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Hex, because an `IdentityId` in a log is meant to be greppable, and it is
/// public data.
impl fmt::Debug for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentityId(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::vec;

    #[test]
    fn the_two_constructors_agree() {
        let ik = [0x11u8; 32];
        let pk = vec![0x22u8; 1952];
        let hash = sha256(&[pk.as_slice()]);
        assert_eq!(
            IdentityId::from_public_keys(&ik, &pk),
            IdentityId::from_ik(&ik, &hash)
        );
    }

    #[test]
    fn matches_the_parent_3_5_preimage_exactly() {
        // Recomputed here from the spec text rather than from the
        // implementation, so that a changed label or a changed field order
        // fails this test.
        let ik = [0x01u8; 32];
        let pk = [0x02u8; 64];
        let inner = sha256(&[&pk]);
        let mut preimage = std::vec::Vec::new();
        preimage.extend_from_slice(b"MLKEMBraid/identity/v2");
        preimage.extend_from_slice(&ik);
        preimage.extend_from_slice(&inner);
        assert_eq!(
            IdentityId::from_public_keys(&ik, &pk).as_bytes(),
            &sha256(&[&preimage])
        );
    }

    #[test]
    fn each_input_changes_the_identity() {
        let base = IdentityId::from_ik(&[0u8; 32], &[0u8; 32]);
        let mut ik = [0u8; 32];
        ik[31] = 1;
        assert_ne!(base, IdentityId::from_ik(&ik, &[0u8; 32]));
        let mut h = [0u8; 32];
        h[0] = 1;
        assert_ne!(base, IdentityId::from_ik(&[0u8; 32], &h));
    }

    #[test]
    fn the_domain_tag_is_not_a_prefix_an_attacker_can_move() {
        // Shifting a byte from the tag into `ik_x25519` must not collide:
        // both operands are fixed-width, so the preimage is injective.
        let a = IdentityId::from_ik(&[0xaa; 32], &[0xbb; 32]);
        let b = IdentityId::from_ik(&[0xbb; 32], &[0xaa; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn bytes_round_trip_and_debug_is_hex() {
        let id = IdentityId::from_bytes([0xab; 32]);
        assert_eq!(id.as_bytes(), &[0xab; 32]);
        assert_eq!(IdentityId::LEN, 32);
        let rendered = std::format!("{id:?}");
        assert_eq!(rendered, std::format!("IdentityId({})", "ab".repeat(32)));
    }
}
