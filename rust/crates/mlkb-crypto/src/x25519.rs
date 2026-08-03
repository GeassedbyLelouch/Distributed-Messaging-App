//! X25519, failing closed (spec M1 §C.2).
//!
//! # The defect this module exists to close
//!
//! Spec M1 §C.2, empirical (M1 §H, Q5): `x25519-dalek 3.0.0` does **not**
//! reject low-order or non-contributory peer keys.
//! `StaticSecret::diffie_hellman(&PublicKey::from([0u8; 32]))` returns the
//! all-zero shared secret and merely sets `was_contributory() == false`; the
//! free `x25519()` function checks nothing at all. A peer that sends an
//! identity or prekey of `[0u8; 32]` would otherwise drive a DH leg to a
//! constant the attacker knows.
//!
//! There is therefore exactly **one** DH function in this crate,
//! [`x25519_dh`], it always performs both checks, and the raw `x25519-dalek`
//! API is not re-exported.

use curve25519_dalek::montgomery::MontgomeryPoint;
use mlkb_secrets::{ProtocolError, Secret32};
use rand_core::CryptoRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::keys::DhOutput;
use crate::util::copy_prefix;

/// An X25519 public key in its 32-byte wire form (spec M1 §C.1).
///
/// Wrapping the bytes rather than a `MontgomeryPoint` is deliberate: a public
/// key off the wire is untrusted until [`x25519_dh`] validates it, and there
/// is no constructor that implies otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    /// The wire length of an X25519 public key.
    pub const LEN: usize = 32;

    /// Wraps 32 bytes read off the wire (spec M1 §C.1).
    ///
    /// This performs no validation, on purpose — validation happens once, at
    /// the DH site, so there is no second place for it to be forgotten.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// An X25519 private key (spec M1 §C.1).
///
/// The bytes are stored unclamped, which is what `x25519-dalek` and Signal's
/// XEdDSA both expect: clamping happens at each use.
pub struct X25519SecretKey(StaticSecret);

/// Redacting (spec M1 §G.1).
impl core::fmt::Debug for X25519SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519SecretKey([REDACTED])")
    }
}

impl X25519SecretKey {
    /// Draws a fresh private key from `rng` (spec M1 §C.1).
    #[must_use]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(StaticSecret::random_from_rng(rng))
    }

    /// Loads a stored private key (spec parent §9).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }

    /// The private key bytes, for sealing into the store (spec M1 §G.5).
    #[must_use]
    pub fn to_secret(&self) -> Secret32 {
        Secret32::new(self.0.to_bytes())
    }

    /// The matching public key (spec M1 §C.1).
    #[must_use]
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(PublicKey::from(&self.0).to_bytes())
    }

    /// The raw scalar bytes, for XEdDSA's clamping step (crate-private).
    pub(crate) fn scalar_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Validates a peer's X25519 public key (spec M1 §C.2 check 2).
///
/// The check is done on the **Edwards** side. M1 §E.4 records the trap:
/// `MontgomeryPoint([0; 32]).to_edwards(0)` returns `Some`, so the
/// Montgomery→Edwards conversion is not itself a validity filter; it is the
/// torsion and small-order tests on the resulting point that reject.
///
/// # Canonicality (security audit 2026-08-02, MEDIUM)
///
/// A third check runs *first*: the 32 bytes must be the canonical
/// little-endian encoding of a field element, i.e. bit 255 clear and
/// `u < p = 2^255 - 19`.
///
/// Without it, `FieldElement::from_bytes` masks bit 255 and reduces mod `p`, so
/// **every** peer key has at least two distinct 32-byte encodings that decode to
/// the same point (plus a third, `u + p`, for the 19 values `u < 19`). That is
/// harmless for the DH output — it is identical either way — but it is not
/// harmless for identity: parent §3.5 derives `IdentityId` from these *raw wire
/// bytes*, and `IdentityId` is the scarce principal that the §6.3 replay floor,
/// the §6.2 enrolment subject and every §6.4 per-principal quota are keyed on.
/// One key pair could therefore present under several `IdentityId`s, so a peer
/// the user had declined could return as a fresh Unknown peer, and one enrolment
/// could occupy two slots in every per-principal bound.
///
/// This is a rejection at the §C.2 DH site, which already performs two
/// deliberate rejections. It is emphatically **not** added inside
/// `xeddsa::verify`, which parent §5.4 forbids.
///
/// # Errors
/// [`ProtocolError::Malformed`] if the `u` coordinate is not canonically
/// encoded, is not on the curve, is small-order, or is not in the prime-order
/// subgroup.
fn validate_peer(peer: &X25519PublicKey) -> Result<(), ProtocolError> {
    if !is_canonical_u(&peer.0) {
        return Err(ProtocolError::Malformed);
    }
    let point = MontgomeryPoint(peer.0)
        .to_edwards(0)
        .ok_or(ProtocolError::Malformed)?;
    if point.is_small_order() || !point.is_torsion_free() {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}

/// Whether `u` is the canonical little-endian encoding of a field element.
///
/// Constant-time in the value of `u`: the comparison against `p` is a full
/// borrow-propagating pass with no early exit, so it reveals nothing about
/// where a rejected key first differs.
fn is_canonical_u(u: &[u8; 32]) -> bool {
    // p = 2^255 - 19, little-endian.
    const P: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    // High bit must be clear: with it set the encoding is non-canonical even
    // when the low 255 bits are reduced.
    let high_bit_clear = u.last().is_some_and(|b| b & 0x80 == 0);

    // Constant-time `u < P`: subtract P from u least-significant byte first and
    // keep the borrow. A borrow out of the top byte means u < P. Every byte is
    // visited on every call, so timing does not depend on where they differ.
    let mut borrow = 0u16;
    for (a, b) in u.iter().zip(P.iter()) {
        let diff = u16::from(*a)
            .wrapping_sub(u16::from(*b))
            .wrapping_sub(borrow);
        borrow = (diff >> 8) & 1;
    }
    // Non-short-circuiting `&` on purpose: `&&` would branch on
    // `high_bit_clear`, making the running time depend on the key.
    #[allow(clippy::needless_bitwise_bool)]
    {
        high_bit_clear & (borrow == 1)
    }
}

/// The one X25519 Diffie-Hellman in ML-KEM-Braid (spec M1 §C.1, §C.2).
///
/// Both fail-closed checks of M1 §C.2 are performed on every call, before the
/// output is available to the caller:
///
/// 1. the peer key must decode to a torsion-free, non-small-order point, else
///    [`ProtocolError::Malformed`];
/// 2. the shared secret must be contributory, else
///    [`ProtocolError::Unauthenticated`].
///
/// # Errors
/// As above. The two are distinguishable because a malformed key is a
/// decoding fault while a non-contributory result is an attack signal
/// (spec parent §8.4).
pub fn x25519_dh(
    secret: &X25519SecretKey,
    peer: &X25519PublicKey,
) -> Result<DhOutput, ProtocolError> {
    validate_peer(peer)?;
    let shared = secret.0.diffie_hellman(&PublicKey::from(peer.0));
    if !shared.was_contributory() {
        return Err(ProtocolError::Unauthenticated);
    }
    Ok(DhOutput::from_dh(Secret32::from_fill(|out| {
        copy_prefix(out, shared.as_bytes());
    })))
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;
    use alloc::format;

    fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn dh_agrees_in_both_directions() {
        let mut r = rng();
        let a = X25519SecretKey::random(&mut r);
        let b = X25519SecretKey::random(&mut r);
        let ab = x25519_dh(&a, &b.public_key()).unwrap();
        let ba = x25519_dh(&b, &a.public_key()).unwrap();
        assert_eq!(ab.bytes(), ba.bytes());
    }

    #[test]
    fn distinct_pairs_give_distinct_outputs() {
        let mut r = rng();
        let a = X25519SecretKey::random(&mut r);
        let b = X25519SecretKey::random(&mut r);
        let c = X25519SecretKey::random(&mut r);
        let ab = x25519_dh(&a, &b.public_key()).unwrap();
        let ac = x25519_dh(&a, &c.public_key()).unwrap();
        assert_ne!(ab.bytes(), ac.bytes());
    }

    #[test]
    fn a_private_key_round_trips_through_its_bytes() {
        let mut r = rng();
        let a = X25519SecretKey::random(&mut r);
        let restored = X25519SecretKey::from_bytes(*a.to_secret().expose_secret());
        assert_eq!(a.public_key(), restored.public_key());
    }

    /// Spec M1 §C.2: the all-zero peer key must be rejected.
    ///
    /// Without the checks this returns the all-zero shared secret and only
    /// flags `was_contributory() == false` (M1 §H, Q5).
    #[test]
    fn the_all_zero_peer_key_is_rejected() {
        let mut r = rng();
        let a = X25519SecretKey::random(&mut r);
        let zero = X25519PublicKey::from_bytes([0u8; 32]);
        assert_eq!(x25519_dh(&a, &zero).unwrap_err(), ProtocolError::Malformed);
    }

    /// Every small-order point on Curve25519, in its `u`-coordinate form.
    ///
    /// These are the eight low-order points of the standard test set; each one
    /// drives an unchecked X25519 to a value the attacker knows.
    #[test]
    fn every_small_order_peer_key_is_rejected() {
        const SMALL_ORDER: [[u8; 32]; 7] = [
            // u = 0 (order 4). M1 §E.4's trap: `to_edwards(0)` returns `Some`.
            [0u8; 32],
            // u = 1 (order 4).
            [
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ],
            // u = 325606250916557431795983626356110631294008115727848805560023387167927233504
            [
                224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9,
                141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0,
            ],
            // u = 39382357235489614581723060781553021112529911719440698176882885853963445705823
            [
                95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68,
                92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87,
            ],
            // p - 1 (order 2).
            [
                236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
            ],
            // p (== 0, order 4).
            [
                237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
            ],
            // p + 1 (== 1, order 4).
            [
                238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
            ],
        ];

        let mut r = rng();
        let a = X25519SecretKey::random(&mut r);
        for u in SMALL_ORDER {
            let peer = X25519PublicKey::from_bytes(u);
            let outcome = x25519_dh(&a, &peer);
            assert!(
                outcome.is_err(),
                "accepted a small-order peer key {:?}",
                &u[..4]
            );
            // Never `Ok`, and never a silent all-zero secret.
            assert_eq!(outcome.unwrap_err(), ProtocolError::Malformed);
        }
    }

    /// A `u` coordinate that is not on the curve is rejected too.
    #[test]
    fn a_non_curve_peer_key_is_rejected() {
        let mut r = rng();
        let a = X25519SecretKey::random(&mut r);
        // Search for a `u` whose Edwards conversion has no square root.
        let mut found = false;
        for i in 2u8..64 {
            let mut u = [0u8; 32];
            u[0] = i;
            if MontgomeryPoint(u).to_edwards(0).is_none() {
                assert_eq!(
                    x25519_dh(&a, &X25519PublicKey::from_bytes(u)).unwrap_err(),
                    ProtocolError::Malformed
                );
                found = true;
                break;
            }
        }
        assert!(found, "no off-curve u found in the search range");
    }

    /// An honest peer key is still accepted; the checks are not vacuous.
    #[test]
    fn honest_peer_keys_are_accepted() {
        let mut r = rng();
        let a = X25519SecretKey::random(&mut r);
        for _ in 0..32 {
            let b = X25519SecretKey::random(&mut r);
            assert!(x25519_dh(&a, &b.public_key()).is_ok());
        }
    }

    #[test]
    fn the_private_key_debug_is_redacted() {
        let mut r = rng();
        let a = X25519SecretKey::random(&mut r);
        let rendered = format!("{a:?}");
        assert!(rendered.contains("REDACTED"));
    }

    /// Security audit 2026-08-02 (MEDIUM): one key pair must not be presentable
    /// under several `IdentityId`s.
    ///
    /// Parent §3.5 hashes the *raw wire bytes* of `ik_x25519` into `IdentityId`,
    /// and `IdentityId` is the scarce principal every §6.4 per-principal bound is
    /// keyed on. Before the canonicality check, 200/200 honest keys had at least
    /// two distinct encodings that both passed `x25519_dh` and produced a
    /// byte-identical shared secret. Reverting the check fails this test.
    #[test]
    fn non_canonical_peer_encodings_are_rejected() {
        let mut r = rng();
        let peer = X25519SecretKey::random(&mut r);
        let canonical = peer.public_key();
        let us = X25519SecretKey::random(&mut r);

        // The canonical encoding is accepted.
        assert!(x25519_dh(&us, &canonical).is_ok());

        // Alias 1: bit 255 set. `FieldElement::from_bytes` masks it away, so
        // this decodes to the same point and would yield the same DH output.
        let mut high_bit = *canonical.as_bytes();
        let last = high_bit.len() - 1;
        high_bit[last] |= 0x80;
        assert_ne!(high_bit, *canonical.as_bytes());
        assert_eq!(
            x25519_dh(&us, &X25519PublicKey::from_bytes(high_bit)).err(),
            Some(ProtocolError::Malformed),
            "high-bit alias must be rejected",
        );

        // Alias 2: u + p, which does not involve the high bit, so a naive
        // "clear bit 255" fix would not catch it. Only exists for u < 19.
        for u_small in [9u8, 16u8] {
            let mut alias = [0u8; 32];
            alias[0] = u_small.wrapping_add(0xed);
            alias[1] = if u_small >= 19 { 0xff } else { 0xfe };
            for b in alias.iter_mut().take(31).skip(2) {
                *b = 0xff;
            }
            alias[31] = 0x7f;
            assert_eq!(
                x25519_dh(&us, &X25519PublicKey::from_bytes(alias)).err(),
                Some(ProtocolError::Malformed),
                "u+p alias for u={u_small} must be rejected",
            );
        }
    }

    /// `p` itself, `p+1` and `2^255-1` are all non-canonical or out of range.
    #[test]
    fn boundary_encodings_are_rejected() {
        let mut p_bytes = [0xffu8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        assert!(!is_canonical_u(&p_bytes), "p is not < p");

        let mut p_plus_1 = p_bytes;
        p_plus_1[0] = 0xee;
        assert!(!is_canonical_u(&p_plus_1));

        let all_ones = [0xffu8; 32];
        assert!(!is_canonical_u(&all_ones));

        let mut p_minus_1 = p_bytes;
        p_minus_1[0] = 0xec;
        assert!(is_canonical_u(&p_minus_1), "p-1 is canonical");
        assert!(is_canonical_u(&[0u8; 32]), "zero is canonically encoded");
    }
}
