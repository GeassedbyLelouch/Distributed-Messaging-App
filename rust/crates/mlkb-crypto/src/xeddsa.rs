//! XEd25519 (XEdDSA), byte-for-byte as Signal defines it
//! (spec parent §5.4, M1 §E.4).
//!
//! # Which Signal convention this is
//!
//! The vendored C exposes two signature conventions, and only one of them is
//! actually bound into the reference implementation. `_curve25519module.c`
//! lines 27 and 37 bind `calculateSignature`/`verifySignature` to
//! **`curve_sigs.c`'s `curve25519_sign`/`curve25519_verify`**.
//! `xeddsa.c`'s `xed25519_sign`/`xed25519_verify` are compiled but never
//! exposed. The two differ, and this module implements the bound one:
//!
//! | | `curve25519_sign` (bound) | `xed25519_sign` (not bound) |
//! |---|---|---|
//! | `A`'s Edwards sign bit | **kept**, stashed in `sig[63]` | forced to 0 by negating `a` |
//! | verifier's `A` | sign bit read back from `sig[63]` | always sign bit 0 |
//!
//! Concretely, `curve25519_sign` computes `A = aB` and keeps whatever sign bit
//! falls out (`curve_sigs.c:26`), then folds it into the signature's unused
//! high bit: `signature_out[63] &= 0x7F; signature_out[63] |= sign_bit`
//! (`curve_sigs.c:34-35`). `curve25519_verify` reverses that before verifying:
//! `ed_pubkey[31] |= (signature[63] & 0x80); verifybuf[63] &= 0x7F`
//! (`curve_sigs.c:77-80`). Since `A`'s sign bit is essentially a coin flip,
//! about **half** of all signatures Signal produces carry `sig[63] & 0x80`; a
//! verifier that assumed sign bit 0 would reject every one of them.
//!
//! The second consequence of the bound convention is what goes into `hash_1`:
//! `crypto_sign_modified` hashes the **private key bytes verbatim** —
//! `memmove(sm + 32, sk, 32)` (`sign_modified.c:26`) — where `sk` is the
//! *clamped 32-byte key*, not the scalar reduced modulo the group order. A
//! clamped key always exceeds the group order, so feeding `hash_1` a reduced
//! scalar produces a different (still self-consistent, but non-interoperable)
//! nonce. `sc_muladd` at `sign_modified.c:46` then uses those same raw bytes as
//! the scalar, which *is* equivalent to the reduced scalar because the
//! reduction happens inside `sc_muladd`.
//!
//! # Do not add rejections Signal does not perform
//!
//! Spec parent §5.4 is explicit: [`verify`] must match the vendored Signal C
//! exactly, and an added rejection is a *defect*, not hardening. The checks
//! `curve25519_verify` plus `crypto_sign_open_modified` actually perform, and
//! the only ones performed here, are:
//!
//! 1. the top three bits of the *masked* `s` must be clear — `open_modified.c:24`
//!    tests `sm[63] & 224` after `curve_sigs.c:80` has already cleared bit 7,
//!    so this is effectively `sig[63] & 0x60`;
//! 2. the sign-bit-restored public key must decode to a point on the curve
//!    (`ge_frombytes_negate_vartime`, `open_modified.c:25`).
//!
//! Notably absent, on purpose: `s` is **not** required to be canonical modulo
//! the group order, `R` is **not** required to be canonical, `A` is **not**
//! required to be torsion-free, and the Montgomery `u` coordinate is **not**
//! required to be reduced modulo `p`. That last one is a real difference
//! between the two conventions: `xed25519_verify` does call `fe_isreduced`
//! (`xeddsa.c:65`) but `curve25519_verify` does not, so adding it here would
//! reject inputs the bound C accepts. Adding any of these changes the accepted
//! set.
//!
//! Stricter checks live in [`verify_raw`], which is a separately named
//! function with its own tests, exactly as parent §5.4 requires.
//!
//! M1 §E.4's trap applies to spec M1 §C.2's DH validation and not to this
//! module: `MontgomeryPoint([0; 32]).to_edwards(0)` returns `Some`, so the
//! Montgomery→Edwards conversion is not a validity filter — but filtering here
//! is precisely what parent §5.4 forbids.
//!
//! Cross-vectors generated from the vendored C extension itself pin all of
//! this in `tests/xeddsa_kat.rs` (spec parent §11 gate 1) — including a
//! `NO_REJECT` table of inputs the C *accepts* despite being malformed (a
//! non-canonical `s`, an unreduced `u`, a small-order `A`), so that adding any
//! of the rejections listed above fails the suite instead of passing it.

// Curve25519 scalar and point arithmetic. `clippy::arithmetic_side_effects` —
// denied crate-wide for spec parent §11 gate 7 — reads `+`, `-` and `*` here as
// integer operations that could overflow. They are not: they are the group and
// field operations of `curve25519-dalek`, which reduce modulo the group order
// and the field prime by construction and have no overflow case. The lint is
// left on everywhere else.
#![allow(clippy::arithmetic_side_effects)]

use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use mlkb_secrets::ProtocolError;
use rand_core::CryptoRng;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::hash::sha512;
use crate::labels;
use crate::x25519::{X25519PublicKey, X25519SecretKey};

/// An XEd25519 signature: `R || s`, 64 bytes (spec parent §5.4).
pub const XEDDSA_SIGNATURE_LEN: usize = 64;

/// The `hash_1` prefix of the Signal XEdDSA specification.
///
/// `2^256 - 1 - i` with `i = 1`, little-endian: `0xFE` then 31 × `0xFF`. It is
/// what keeps the nonce hash disjoint from the challenge hash, which uses no
/// prefix at all.
const HASH1_PREFIX: [u8; 32] = [
    0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// The mask `crypto_sign_open_modified` applies to `s`'s top byte
/// (`open_modified.c:24`, `sm[63] & 224`).
const S_HIGH_BITS: u8 = 0b1110_0000;

/// The Edwards sign bit, in the position both `A[31]` and `sig[63]` hold it.
const SIGN_BIT: u8 = 0b1000_0000;

/// Derives the XEdDSA key material from an X25519 private key.
///
/// Returns `(clamped, a, A)` where `clamped` is the clamped 32-byte private
/// key **verbatim**, `a` is the same value reduced to a scalar, and `A` is the
/// compressed Edwards public point *with its sign bit intact*.
///
/// The three are deliberately distinct. `curve25519_sign` feeds `hash_1` the
/// raw clamped bytes (`sign_modified.c:26`) and only the group arithmetic sees
/// the reduced scalar (`sign_modified.c:46`, inside `sc_muladd`); and it does
/// **not** negate `a` to normalise `A`'s sign — that is `xed25519_sign`'s
/// convention (`xeddsa.c:29-33`), which is not the one bound.
fn key_material(secret: &X25519SecretKey) -> (Zeroizing<[u8; 32]>, Scalar, [u8; 32]) {
    let clamped = Zeroizing::new(clamp_integer(secret.scalar_bytes()));
    // `ge_scalarmult_base` takes the clamped bytes as an integer; reducing
    // first is the same point, because the basepoint has order `q`.
    let a = Scalar::from_bytes_mod_order(*clamped);
    let big_a = EdwardsPoint::mul_base(&a).compress().to_bytes();
    (clamped, a, big_a)
}

/// The XEdDSA challenge scalar `h = H(R || A || M) mod q`.
fn challenge(big_r: &[u8], big_a: &[u8], msg: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&sha512(&[big_r, big_a, msg]))
}

/// Signs `msg` with an X25519 private key (spec parent §5.4).
///
/// ```text
/// k    = clamp(privkey)                   the 32 clamped bytes, verbatim
/// A    = (k mod q)B                       sign bit KEPT, not normalised
/// r    = H(0xFE || 0xFF*31 || k || M || Z) mod q      Z = 64 random bytes
/// R    = rB
/// h    = H(R || A || M) mod q
/// s    = r + h*k
/// sig  = R || s, then sig[63] = (s[31] & 0x7F) | (A[31] & 0x80)
/// ```
///
/// Note `k` — not `k mod q` — in the `hash_1` line: that is
/// `sign_modified.c:26`, and it is what makes these bytes reproduce the
/// vendored C's.
///
/// Randomised: XEdDSA hedges the nonce with `Z`, so two signatures over the
/// same message differ. That is Signal's design, not an accident, and callers
/// must not assume determinism.
// `a`, `r`, `s`, `h` and `z` are the Signal XEdDSA specification's own names
// for these quantities; renaming them would make the code harder to check
// against the spec, not easier.
#[allow(clippy::many_single_char_names)]
#[must_use]
pub fn sign<R: CryptoRng + ?Sized>(
    secret: &X25519SecretKey,
    msg: &[u8],
    rng: &mut R,
) -> [u8; XEDDSA_SIGNATURE_LEN] {
    let (clamped, a, big_a) = key_material(secret);
    // `curve_sigs.c:26` — the sign bit that will be stashed in `sig[63]`.
    let sign_bit = big_a.last().copied().unwrap_or(0) & SIGN_BIT;

    let mut z = Zeroizing::new([0u8; 64]);
    rng.fill_bytes(z.as_mut_slice());

    // `sign_modified.c:26` — the clamped private key bytes verbatim, *not*
    // `a.to_bytes()`. Using the reduced scalar here is the one change that
    // silently breaks interoperability while still round-tripping locally.
    let nonce_hash = Zeroizing::new(sha512(&[
        &HASH1_PREFIX,
        clamped.as_slice(),
        msg,
        z.as_slice(),
    ]));
    let r = Scalar::from_bytes_mod_order_wide(&nonce_hash);
    let big_r = EdwardsPoint::mul_base(&r).compress().to_bytes();

    let h = challenge(&big_r, &big_a, msg);
    let s = r + h * a;

    let mut sig = [0u8; XEDDSA_SIGNATURE_LEN];
    crate::util::copy_prefix(&mut sig, &big_r);
    if let Some(tail) = sig.get_mut(32..) {
        crate::util::copy_prefix(tail, &s.to_bytes());
    }
    // `curve_sigs.c:34-35`. `s` is canonical and so below 2^252; the mask is
    // Signal's own belt-and-braces, kept so the code reads like the C.
    if let Some(top) = sig.last_mut() {
        *top = (*top & !SIGN_BIT) | sign_bit;
    }
    sig
}

/// The public key a signature made by [`sign`] verifies under.
///
/// Convenience only: it is the ordinary X25519 public key.
#[must_use]
pub fn public_key(secret: &X25519SecretKey) -> X25519PublicKey {
    secret.public_key()
}

/// Verifies an XEd25519 signature (spec parent §5.4).
///
/// Performs exactly the checks Signal performs — see the module docs. Do not
/// add another one here.
///
/// # Errors
/// [`ProtocolError::Unauthenticated`] on any failure, with no distinction
/// between them (spec parent §8.4).
pub fn verify(
    public: &X25519PublicKey,
    msg: &[u8],
    signature: &[u8; XEDDSA_SIGNATURE_LEN],
) -> Result<(), ProtocolError> {
    let big_r = signature
        .first_chunk::<32>()
        .ok_or(ProtocolError::Unauthenticated)?;

    // `curve_sigs.c:78-80`: split `sig[63]` back into the public key's sign
    // bit and the top byte of `s`.
    let mut s_bytes = *signature
        .last_chunk::<32>()
        .ok_or(ProtocolError::Unauthenticated)?;
    let sign_bit = s_bytes.last().copied().unwrap_or(0) & SIGN_BIT;
    if let Some(top) = s_bytes.last_mut() {
        *top &= !SIGN_BIT;
    }

    // Signal check 1 (`open_modified.c:24`): the top three bits of the masked
    // `s` must be clear. Bit 7 is already clear, so this bites on bits 5 and 6.
    if s_bytes.last().copied().unwrap_or(0) & S_HIGH_BITS != 0 {
        return Err(ProtocolError::Unauthenticated);
    }

    // Recover `A`'s encoding exactly as `curve_sigs.c:72-78` does: the
    // Montgomery `u` gives the Edwards `y`, and the sign bit comes from the
    // signature. The bytes are rebuilt rather than re-derived by compressing a
    // point, because for `u = 0` the recovered `x` is 0 and compression would
    // report sign bit 0 while the C hashes the byte with bit 7 set.
    let mut big_a_bytes = MontgomeryPoint(*public.as_bytes())
        .to_edwards(0)
        .ok_or(ProtocolError::Unauthenticated)?
        .compress()
        .to_bytes();
    if let Some(top) = big_a_bytes.last_mut() {
        *top = (*top & !SIGN_BIT) | sign_bit;
    }

    // Signal check 2 (`open_modified.c:25`): `A` must decode to a curve point.
    // Reducing `s` mod q rather than rejecting a non-canonical one is what
    // keeps the accepted set identical to Signal's: `sB` is unchanged by the
    // reduction because `B` has order `q`.
    let big_a = CompressedEdwardsY(big_a_bytes)
        .decompress()
        .ok_or(ProtocolError::Unauthenticated)?;

    let s = Scalar::from_bytes_mod_order(s_bytes);
    let h = challenge(big_r, &big_a_bytes, msg);
    let check = EdwardsPoint::mul_base(&s) - big_a * h;

    if bool::from(check.compress().to_bytes().ct_eq(big_r)) {
        Ok(())
    } else {
        Err(ProtocolError::Unauthenticated)
    }
}

/// The *raw* (unframed) signing path (spec parent §3.6).
///
/// Identical to [`sign`] except that it refuses any message beginning with the
/// framed-signature domain tag, which is what keeps the framed and raw
/// byte-spaces disjoint. This is the "separately named function" parent §5.4
/// requires: the extra rejection is here and never inside [`verify`].
///
/// # Errors
/// [`ProtocolError::Malformed`] if `msg` starts with
/// [`crate::labels::XEDDSA_DOMAIN`].
pub fn sign_raw<R: CryptoRng + ?Sized>(
    secret: &X25519SecretKey,
    msg: &[u8],
    rng: &mut R,
) -> Result<[u8; XEDDSA_SIGNATURE_LEN], ProtocolError> {
    if msg.starts_with(labels::XEDDSA_DOMAIN) {
        return Err(ProtocolError::Malformed);
    }
    Ok(sign(secret, msg, rng))
}

/// The *raw* (unframed) verification path (spec parent §3.6).
///
/// See [`sign_raw`]. A framed message presented to the raw path is rejected
/// before any cryptographic work.
///
/// # Errors
/// [`ProtocolError::Malformed`] for a framed message;
/// [`ProtocolError::Unauthenticated`] for a bad signature.
pub fn verify_raw(
    public: &X25519PublicKey,
    msg: &[u8],
    signature: &[u8; XEDDSA_SIGNATURE_LEN],
) -> Result<(), ProtocolError> {
    if msg.starts_with(labels::XEDDSA_DOMAIN) {
        return Err(ProtocolError::Malformed);
    }
    verify(public, msg, signature)
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
    use alloc::vec::Vec;

    fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let mut r = rng();
        let sk = X25519SecretKey::random(&mut r);
        let pk = public_key(&sk);
        for msg in [
            &b""[..],
            b"m",
            b"a longer message than one block of sha-512 input padding",
        ] {
            let sig = sign(&sk, msg, &mut r);
            assert_eq!(sig.len(), XEDDSA_SIGNATURE_LEN);
            assert_eq!(verify(&pk, msg, &sig), Ok(()));
        }
    }

    /// XEdDSA is hedged: the same message signs to different bytes each time,
    /// and every one of them verifies.
    #[test]
    fn signing_is_randomised_and_every_signature_verifies() {
        let mut r = rng();
        let sk = X25519SecretKey::random(&mut r);
        let pk = public_key(&sk);
        let sigs: Vec<[u8; 64]> = (0..8).map(|_| sign(&sk, b"m", &mut r)).collect();
        for (i, a) in sigs.iter().enumerate() {
            assert_eq!(verify(&pk, b"m", a), Ok(()));
            for b in sigs.iter().skip(i + 1) {
                assert_ne!(a, b, "the nonce repeated");
            }
        }
    }

    #[test]
    fn a_tampered_message_or_signature_or_key_fails() {
        let mut r = rng();
        let sk = X25519SecretKey::random(&mut r);
        let pk = public_key(&sk);
        let sig = sign(&sk, b"message", &mut r);

        assert_eq!(
            verify(&pk, b"messagE", &sig),
            Err(ProtocolError::Unauthenticated)
        );

        let other = X25519SecretKey::random(&mut r);
        assert_eq!(
            verify(&public_key(&other), b"message", &sig),
            Err(ProtocolError::Unauthenticated)
        );

        // Every byte of R, and every byte of s below the masked bits.
        for i in 0..64usize {
            let mut bad = sig;
            bad[i] ^= 1;
            assert_eq!(
                verify(&pk, b"message", &bad),
                Err(ProtocolError::Unauthenticated),
                "accepted a flip at byte {i}"
            );
        }
    }

    /// Signal's only structural check on `s`: after bit 7 is split off as the
    /// public key's sign bit, the top three bits of what remains must be clear
    /// (`open_modified.c:24`). Only bits 5 and 6 are reachable by that check —
    /// bit 7 is not part of `s` at all under the bound convention.
    #[test]
    fn the_s_high_bit_check_is_present() {
        let mut r = rng();
        let sk = X25519SecretKey::random(&mut r);
        let pk = public_key(&sk);
        let sig = sign(&sk, b"m", &mut r);

        for bit in 5..7u32 {
            let mut bad = sig;
            bad[63] |= 1u8 << bit;
            assert_eq!(
                verify(&pk, b"m", &bad),
                Err(ProtocolError::Unauthenticated),
                "high bit {bit} of s was not rejected"
            );
        }
    }

    /// Bit 7 of `sig[63]` is the *public key's* Edwards sign bit, not part of
    /// `s`. `sign` emits whichever value `A` actually has, and `verify` reads
    /// it back — so both values occur in practice and both must verify.
    ///
    /// This is the case a sign-bit-0-only verifier (the `xed25519_*`
    /// convention, `xeddsa.c:29-33`) rejects half the time.
    #[test]
    fn both_values_of_the_sign_bit_are_produced_and_accepted() {
        let mut r = rng();
        let mut seen = [0usize; 2];
        for _ in 0..64 {
            let sk = X25519SecretKey::random(&mut r);
            let pk = public_key(&sk);
            let sig = sign(&sk, b"m", &mut r);

            let bit = usize::from(sig[63] >> 7);
            seen[bit] += 1;
            assert_eq!(verify(&pk, b"m", &sig), Ok(()), "sign bit {bit} rejected");

            // The bit is load-bearing: flipping it makes the verifier
            // reconstruct -A, and the signature must then fail.
            let mut flipped = sig;
            flipped[63] ^= 0x80;
            assert_eq!(
                verify(&pk, b"m", &flipped),
                Err(ProtocolError::Unauthenticated)
            );
        }
        assert!(
            seen[0] > 0 && seen[1] > 0,
            "expected both sign bits over 64 keys, saw {seen:?}"
        );
    }

    /// Spec parent §5.4: `verify` adds no rejection Signal does not perform.
    ///
    /// `u = 0` — M1 §E.4's trap point — converts to the order-2 Edwards
    /// point. A forged signature under it (`R = rB`, `s = r`) satisfies
    /// `sB - hA == R` exactly when `h` is even, because `A` has order 2. Signal
    /// **accepts** such a signature; so must this `verify`. If anyone adds a
    /// small-order or torsion rejection to `verify`, this test fails, which is
    /// the whole point of writing it.
    #[test]
    fn verify_accepts_a_small_order_public_key_exactly_as_signal_does() {
        let small = X25519PublicKey::from_bytes([0u8; 32]);
        let big_a = MontgomeryPoint(*small.as_bytes())
            .to_edwards(0)
            .expect("M1 §E.4: the conversion is not a filter");
        assert!(big_a.is_small_order(), "expected a small-order point");
        assert!(!big_a.is_torsion_free());

        let r_scalar = Scalar::from_bytes_mod_order([7u8; 32]);
        let big_r = EdwardsPoint::mul_base(&r_scalar).compress().to_bytes();
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&r_scalar.to_bytes());

        // Find a message whose challenge scalar is even, so that h*A is the
        // identity and the equation holds.
        let mut accepted = false;
        for i in 0u16..256 {
            let msg = i.to_be_bytes();
            let h = challenge(&big_r, &big_a.compress().to_bytes(), &msg);
            if h.to_bytes()[0] & 1 == 0 {
                assert_eq!(
                    verify(&small, &msg, &sig),
                    Ok(()),
                    "verify added a rejection Signal does not perform"
                );
                accepted = true;
                break;
            }
        }
        assert!(accepted, "no even challenge found in the search range");
    }

    /// A `u` coordinate with no curve point is the one conversion failure
    /// Signal also has (`ge_frombytes_negate_vartime` returning non-zero).
    #[test]
    fn an_off_curve_public_key_fails_verification() {
        let mut found = false;
        for i in 2u8..64 {
            let mut u = [0u8; 32];
            u[0] = i;
            if MontgomeryPoint(u).to_edwards(0).is_none() {
                assert_eq!(
                    verify(&X25519PublicKey::from_bytes(u), b"m", &[0u8; 64]),
                    Err(ProtocolError::Unauthenticated)
                );
                found = true;
                break;
            }
        }
        assert!(found, "no off-curve u found in the search range");
    }

    /// `curve25519_sign` does **not** normalise `A`'s sign bit — that is the
    /// unbound `xed25519_sign`'s behaviour. `A` keeps whatever sign falls out,
    /// and the verifier reconstructs exactly that encoding from the Montgomery
    /// `u` plus `sig[63]`.
    #[test]
    fn the_signers_public_point_is_not_sign_normalised() {
        let mut r = rng();
        let mut signs = [0usize; 2];
        for _ in 0..64 {
            let sk = X25519SecretKey::random(&mut r);
            let (clamped, a, big_a) = key_material(&sk);

            // The scalar is the clamped bytes reduced, never negated.
            assert_eq!(a, Scalar::from_bytes_mod_order(*clamped));
            assert_eq!(EdwardsPoint::mul_base(&a).compress().to_bytes(), big_a);

            let bit = usize::from(big_a[31] >> 7);
            signs[bit] += 1;

            // The verifier rebuilds the identical encoding.
            let mut recovered = MontgomeryPoint(*public_key(&sk).as_bytes())
                .to_edwards(0)
                .unwrap()
                .compress()
                .to_bytes();
            recovered[31] = (recovered[31] & 0x7F) | (big_a[31] & 0x80);
            assert_eq!(recovered, big_a);
        }
        assert!(
            signs[0] > 0 && signs[1] > 0,
            "A's sign bit was normalised away, saw {signs:?}"
        );
    }

    /// `hash_1` is fed the clamped private key *bytes*, not the reduced
    /// scalar (`sign_modified.c:26`). The two differ because a clamped key
    /// always exceeds the group order — assert that premise, so this test
    /// cannot quietly become vacuous.
    #[test]
    fn hash_one_consumes_the_unreduced_clamped_key() {
        let mut r = rng();
        for _ in 0..16 {
            let sk = X25519SecretKey::random(&mut r);
            let (clamped, a, _) = key_material(&sk);
            assert_ne!(
                *clamped,
                a.to_bytes(),
                "clamped key equalled its reduction; the KAT would not discriminate"
            );
        }
    }

    // -----------------------------------------------------------------
    // The raw path (spec parent §3.6)
    // -----------------------------------------------------------------

    #[test]
    fn the_raw_path_refuses_a_framed_message() {
        let mut r = rng();
        let sk = X25519SecretKey::random(&mut r);
        let pk = public_key(&sk);

        let mut framed = labels::XEDDSA_DOMAIN.to_vec();
        framed.extend_from_slice(b"\x00\x15some framed payload");

        assert_eq!(
            sign_raw(&sk, &framed, &mut r).unwrap_err(),
            ProtocolError::Malformed
        );

        // Even a genuine signature over those bytes is refused by the raw
        // verifier, so the two byte-spaces stay disjoint.
        let sig = sign(&sk, &framed, &mut r);
        assert_eq!(verify(&pk, &framed, &sig), Ok(()));
        assert_eq!(
            verify_raw(&pk, &framed, &sig),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn the_raw_path_accepts_anything_else() {
        let mut r = rng();
        let sk = X25519SecretKey::random(&mut r);
        let pk = public_key(&sk);
        // A near miss: the domain tag without its trailing NUL.
        let near = &labels::XEDDSA_DOMAIN[..labels::XEDDSA_DOMAIN.len() - 1];
        let sig = sign_raw(&sk, near, &mut r).unwrap();
        assert_eq!(verify_raw(&pk, near, &sig), Ok(()));
    }
}
