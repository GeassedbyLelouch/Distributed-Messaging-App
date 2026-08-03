//! `HybridSignature` — both legs, or nothing (spec parent §3.6, M1 §E.1,
//! §E.2).
//!
//! ```text
//! HybridSignature = u16(version) || u16(suite)
//!                || u16(len_ed) || sig_xeddsa
//!                || u16(len_ml) || sig_mldsa
//! ```
//!
//! All integers are big-endian, the project's fixed-layout byte order
//! (spec M1 §A.1). The one-value registry — `version = 0x0200`,
//! `suite = 0x0001` meaning exactly (XEd25519, ML-DSA-65) — makes the
//! no-downgrade claim a property of the parser rather than of a review
//! comment.

use alloc::vec::Vec;

use mlkb_secrets::ProtocolError;
use rand_core::CryptoRng;

use crate::labels::{self, SigContext};
use crate::mldsa::{MLDSA_SIGNATURE_LEN, MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey};
use crate::x25519::{X25519PublicKey, X25519SecretKey};
use crate::xeddsa::{self, XEDDSA_SIGNATURE_LEN};

/// The only accepted `version` (spec M1 §E.1, §I).
pub const HYBRID_SIGNATURE_VERSION: u16 = 0x0200;

/// The only accepted `suite`: (XEd25519, ML-DSA-65) (spec M1 §E.1).
pub const HYBRID_SIGNATURE_SUITE: u16 = 0x0001;

/// The exact encoded length of a `HybridSignature` (spec M1 §E.1).
pub const HYBRID_SIGNATURE_LEN: usize = 2 + 2 + 2 + XEDDSA_SIGNATURE_LEN + 2 + MLDSA_SIGNATURE_LEN;

/// A hybrid (XEd25519 + ML-DSA-65) signature (spec parent §3.6, M1 §E.1).
///
/// There is no accessor for one leg on its own, and [`HybridSignature::verify`]
/// has no variant that succeeds on one leg. Both verify, or the signature is
/// invalid.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature {
    xeddsa: [u8; XEDDSA_SIGNATURE_LEN],
    mldsa: MlDsaSignature,
}

impl core::fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HybridSignature({HYBRID_SIGNATURE_LEN} bytes)")
    }
}

/// A big-endian `u16` length prefix (spec M1 §E.1, §A.1).
///
/// Total, and saturating rather than truncating: every length it is called
/// with is a compile-time constant well inside `u16`, and
/// [`HybridSignature::from_bytes`] re-checks each prefix against the suite's
/// fixed size, so a saturated value could only ever be rejected.
fn len_prefix(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
}

/// Builds the signed byte string of spec parent §3.6 / M1 §E.2.
///
/// ```text
/// signed_msg = "MLKEMBraid/xeddsa/v2\x00" || u16(len(ctx)) || ctx
///           || IdentityId || payload
/// ```
///
/// The length prefix on `ctx` is what makes the encoding injective across
/// contexts of different lengths; the domain tag is what keeps it disjoint
/// from the raw signing path (see [`crate::xeddsa::sign_raw`]).
#[must_use]
pub fn signed_message(ctx: SigContext, identity: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    let ctx_bytes = ctx.as_bytes();
    let ctx_len = len_prefix(ctx_bytes.len());
    let mut out = Vec::with_capacity(
        labels::XEDDSA_DOMAIN
            .len()
            .saturating_add(2)
            .saturating_add(ctx_bytes.len())
            .saturating_add(32)
            .saturating_add(payload.len()),
    );
    out.extend_from_slice(labels::XEDDSA_DOMAIN);
    out.extend_from_slice(&ctx_len);
    out.extend_from_slice(ctx_bytes);
    out.extend_from_slice(identity);
    out.extend_from_slice(payload);
    out
}

impl HybridSignature {
    /// Signs `payload` under `ctx`, bound to `identity`
    /// (spec parent §3.6, M1 §E.1, §E.2, §E.3).
    ///
    /// The ML-DSA leg also carries `ctx` as its FIPS-204 context string, so
    /// the context binds twice: once inside the signed bytes and once inside
    /// the ML-DSA challenge.
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] if the ML-DSA leg refuses the context.
    pub fn sign<R: CryptoRng + ?Sized>(
        xeddsa_key: &X25519SecretKey,
        mldsa_key: &MlDsaSigningKey,
        ctx: SigContext,
        identity: &[u8; 32],
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Self, ProtocolError> {
        let msg = signed_message(ctx, identity, payload);
        Ok(Self {
            xeddsa: xeddsa::sign(xeddsa_key, &msg, rng),
            mldsa: mldsa_key.sign(&msg, ctx.as_bytes())?,
        })
    }

    /// Verifies **both** legs (spec parent §3.6, M1 §E.1).
    ///
    /// Both legs are always evaluated and their outcomes combined with a
    /// non-short-circuiting `&`, so there is no code path that returns success
    /// having checked one leg, and no early return that would tell an observer
    /// which leg failed.
    ///
    /// # Errors
    /// [`ProtocolError::Unauthenticated`] if either leg fails.
    pub fn verify(
        &self,
        xeddsa_key: &X25519PublicKey,
        mldsa_key: &MlDsaVerifyingKey,
        ctx: SigContext,
        identity: &[u8; 32],
        payload: &[u8],
    ) -> Result<(), ProtocolError> {
        let msg = signed_message(ctx, identity, payload);
        let ed_ok = xeddsa::verify(xeddsa_key, &msg, &self.xeddsa).is_ok();
        let ml_ok = mldsa_key.verify(&msg, ctx.as_bytes(), &self.mldsa).is_ok();
        if ed_ok & ml_ok {
            Ok(())
        } else {
            Err(ProtocolError::Unauthenticated)
        }
    }

    /// The encoded form (spec M1 §E.1).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_SIGNATURE_LEN);
        out.extend_from_slice(&HYBRID_SIGNATURE_VERSION.to_be_bytes());
        out.extend_from_slice(&HYBRID_SIGNATURE_SUITE.to_be_bytes());
        out.extend_from_slice(&len_prefix(XEDDSA_SIGNATURE_LEN));
        out.extend_from_slice(&self.xeddsa);
        out.extend_from_slice(&len_prefix(MLDSA_SIGNATURE_LEN));
        out.extend_from_slice(self.mldsa.as_bytes());
        out
    }

    /// Parses an encoded `HybridSignature` (spec M1 §E.1).
    ///
    /// Every check happens **before any cryptographic work**:
    /// `version != 0x0200` or `suite != 0x0001` is rejected outright, and the
    /// two length prefixes are checked against the suite's fixed sizes rather
    /// than trusted. Trailing bytes are rejected.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] for any of the above.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        use crate::util::{take, take_u16_be};

        let (version, rest) = take_u16_be(bytes).ok_or(ProtocolError::Malformed)?;
        if version != HYBRID_SIGNATURE_VERSION {
            return Err(ProtocolError::Malformed);
        }
        let (suite, rest) = take_u16_be(rest).ok_or(ProtocolError::Malformed)?;
        if suite != HYBRID_SIGNATURE_SUITE {
            return Err(ProtocolError::Malformed);
        }

        let (len_ed, rest) = take_u16_be(rest).ok_or(ProtocolError::Malformed)?;
        if usize::from(len_ed) != XEDDSA_SIGNATURE_LEN {
            return Err(ProtocolError::Malformed);
        }
        let (ed, rest) = take(rest, XEDDSA_SIGNATURE_LEN).ok_or(ProtocolError::Malformed)?;

        let (len_ml, rest) = take_u16_be(rest).ok_or(ProtocolError::Malformed)?;
        if usize::from(len_ml) != MLDSA_SIGNATURE_LEN {
            return Err(ProtocolError::Malformed);
        }
        let (ml, rest) = take(rest, MLDSA_SIGNATURE_LEN).ok_or(ProtocolError::Malformed)?;

        if !rest.is_empty() {
            return Err(ProtocolError::Malformed);
        }

        let mut xeddsa = [0u8; XEDDSA_SIGNATURE_LEN];
        crate::util::copy_prefix(&mut xeddsa, ed);
        let mut mldsa = [0u8; MLDSA_SIGNATURE_LEN];
        crate::util::copy_prefix(&mut mldsa, ml);
        Ok(Self {
            xeddsa,
            mldsa: MlDsaSignature::from_bytes(mldsa),
        })
    }
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

    struct Signer {
        ed: X25519SecretKey,
        ml: MlDsaSigningKey,
    }

    impl Signer {
        fn new<R: CryptoRng + ?Sized>(r: &mut R) -> Self {
            Self {
                ed: X25519SecretKey::random(r),
                ml: MlDsaSigningKey::generate(r),
            }
        }

        fn sign<R: CryptoRng + ?Sized>(
            &self,
            ctx: SigContext,
            id: &[u8; 32],
            payload: &[u8],
            r: &mut R,
        ) -> HybridSignature {
            HybridSignature::sign(&self.ed, &self.ml, ctx, id, payload, r).unwrap()
        }

        fn verify(
            &self,
            sig: &HybridSignature,
            ctx: SigContext,
            id: &[u8; 32],
            payload: &[u8],
        ) -> Result<(), ProtocolError> {
            sig.verify(
                &self.ed.public_key(),
                &self.ml.verifying_key(),
                ctx,
                id,
                payload,
            )
        }
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let id = [0x11_u8; 32];
        let sig = s.sign(SigContext::SignedPrekey, &id, b"prekey bytes", &mut r);
        assert_eq!(
            s.verify(&sig, SigContext::SignedPrekey, &id, b"prekey bytes"),
            Ok(())
        );
    }

    /// M1 §E.1: both legs verify, or the signature is invalid. Each leg is
    /// mutated separately and both mutations must fail.
    #[test]
    fn mutating_either_leg_alone_makes_the_signature_invalid() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let id = [0x22_u8; 32];
        let sig = s.sign(SigContext::Enrolment, &id, b"proof", &mut r);
        assert_eq!(s.verify(&sig, SigContext::Enrolment, &id, b"proof"), Ok(()));

        // XEdDSA leg only.
        let mut ed_broken = sig.clone();
        ed_broken.xeddsa[0] ^= 1;
        assert_eq!(
            s.verify(&ed_broken, SigContext::Enrolment, &id, b"proof"),
            Err(ProtocolError::Unauthenticated),
            "a signature with a broken XEdDSA leg verified"
        );

        // ML-DSA leg only.
        let mut ml_bytes = *sig.mldsa.as_bytes();
        ml_bytes[0] ^= 1;
        let ml_broken = HybridSignature {
            xeddsa: sig.xeddsa,
            mldsa: MlDsaSignature::from_bytes(ml_bytes),
        };
        assert_eq!(
            s.verify(&ml_broken, SigContext::Enrolment, &id, b"proof"),
            Err(ProtocolError::Unauthenticated),
            "a signature with a broken ML-DSA leg verified"
        );
    }

    /// A cross-suite forgery: a valid XEdDSA leg from one signer glued to a
    /// valid ML-DSA leg from another verifies under neither.
    #[test]
    fn legs_from_two_signers_cannot_be_glued_together() {
        let mut r = rng();
        let a = Signer::new(&mut r);
        let b = Signer::new(&mut r);
        let id = [0x33_u8; 32];
        let sig_a = a.sign(SigContext::SignedPrekey, &id, b"p", &mut r);
        let sig_b = b.sign(SigContext::SignedPrekey, &id, b"p", &mut r);

        let glued = HybridSignature {
            xeddsa: sig_a.xeddsa,
            mldsa: sig_b.mldsa.clone(),
        };
        assert_eq!(
            a.verify(&glued, SigContext::SignedPrekey, &id, b"p"),
            Err(ProtocolError::Unauthenticated)
        );
        assert_eq!(
            b.verify(&glued, SigContext::SignedPrekey, &id, b"p"),
            Err(ProtocolError::Unauthenticated)
        );
    }

    #[test]
    fn the_context_the_identity_and_the_payload_are_all_bound() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let id = [0x44_u8; 32];
        let sig = s.sign(SigContext::SignedPrekey, &id, b"payload", &mut r);

        assert_eq!(
            s.verify(&sig, SigContext::PqSignedPrekey, &id, b"payload"),
            Err(ProtocolError::Unauthenticated),
            "a signed prekey was liftable into a PQ-prekey slot"
        );
        assert_eq!(
            s.verify(&sig, SigContext::SignedPrekey, &[0x45_u8; 32], b"payload"),
            Err(ProtocolError::Unauthenticated)
        );
        assert_eq!(
            s.verify(&sig, SigContext::SignedPrekey, &id, b"payloaD"),
            Err(ProtocolError::Unauthenticated)
        );
    }

    // -----------------------------------------------------------------
    // Encoding (spec M1 §E.1)
    // -----------------------------------------------------------------

    #[test]
    fn the_encoding_round_trips_and_has_the_exact_length() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let id = [0x55_u8; 32];
        let sig = s.sign(SigContext::Enrolment, &id, b"e", &mut r);
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), HYBRID_SIGNATURE_LEN);
        assert_eq!(HYBRID_SIGNATURE_LEN, 3381);

        let parsed = HybridSignature::from_bytes(&bytes).unwrap();
        assert_eq!(parsed, sig);
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(s.verify(&parsed, SigContext::Enrolment, &id, b"e"), Ok(()));
    }

    #[test]
    fn the_header_fields_are_big_endian_and_at_the_pinned_offsets() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let bytes = s
            .sign(SigContext::Enrolment, &[0u8; 32], b"", &mut r)
            .to_bytes();
        assert_eq!(&bytes[0..2], &[0x02, 0x00]);
        assert_eq!(&bytes[2..4], &[0x00, 0x01]);
        assert_eq!(&bytes[4..6], &[0x00, 0x40]); // 64
        assert_eq!(&bytes[70..72], &[0x0c, 0xed]); // 3309
    }

    #[test]
    fn an_unknown_version_or_suite_is_rejected() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let good = s
            .sign(SigContext::Enrolment, &[0u8; 32], b"", &mut r)
            .to_bytes();

        for version in [0u16, 0x0100, 0x0201, 0xffff] {
            let mut bad = good.clone();
            bad[0..2].copy_from_slice(&version.to_be_bytes());
            assert_eq!(
                HybridSignature::from_bytes(&bad).unwrap_err(),
                ProtocolError::Malformed,
                "accepted version {version:#06x}"
            );
        }
        for suite in [0u16, 2, 0xffff] {
            let mut bad = good.clone();
            bad[2..4].copy_from_slice(&suite.to_be_bytes());
            assert_eq!(
                HybridSignature::from_bytes(&bad).unwrap_err(),
                ProtocolError::Malformed,
                "accepted suite {suite:#06x}"
            );
        }
    }

    /// M1 §E.1: the prefixes are checked against the suite's fixed sizes, not
    /// trusted. A prefix that disagrees is rejected even when the buffer is
    /// otherwise the right length.
    #[test]
    fn a_lying_length_prefix_is_rejected() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let good = s
            .sign(SigContext::Enrolment, &[0u8; 32], b"", &mut r)
            .to_bytes();

        for len_ed in [0u16, 32, 63, 65, 3309] {
            let mut bad = good.clone();
            bad[4..6].copy_from_slice(&len_ed.to_be_bytes());
            assert_eq!(
                HybridSignature::from_bytes(&bad).unwrap_err(),
                ProtocolError::Malformed,
                "accepted len_ed {len_ed}"
            );
        }
        for len_ml in [0u16, 64, 3308, 3310] {
            let mut bad = good.clone();
            bad[70..72].copy_from_slice(&len_ml.to_be_bytes());
            assert_eq!(
                HybridSignature::from_bytes(&bad).unwrap_err(),
                ProtocolError::Malformed,
                "accepted len_ml {len_ml}"
            );
        }
    }

    #[test]
    fn truncated_and_trailing_input_is_rejected() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let good = s
            .sign(SigContext::Enrolment, &[0u8; 32], b"", &mut r)
            .to_bytes();

        for cut in [0usize, 1, 2, 4, 6, 70, HYBRID_SIGNATURE_LEN - 1] {
            assert_eq!(
                HybridSignature::from_bytes(&good[..cut]).unwrap_err(),
                ProtocolError::Malformed,
                "accepted a {cut}-byte prefix"
            );
        }

        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            HybridSignature::from_bytes(&trailing).unwrap_err(),
            ProtocolError::Malformed
        );
    }

    // -----------------------------------------------------------------
    // The signed byte string (spec parent §3.6)
    // -----------------------------------------------------------------

    #[test]
    fn the_signed_message_has_the_pinned_layout() {
        let msg = signed_message(SigContext::SignedPrekey, &[7u8; 32], b"payload");
        let tag = labels::XEDDSA_DOMAIN;
        let ctx = labels::CTX_SPK;
        assert!(msg.starts_with(tag));
        let after_tag = &msg[tag.len()..];
        assert_eq!(&after_tag[0..2], &len_prefix(ctx.len()));
        assert_eq!(&after_tag[2..2 + ctx.len()], ctx);
        assert_eq!(&after_tag[2 + ctx.len()..2 + ctx.len() + 32], &[7u8; 32]);
        assert_eq!(&after_tag[2 + ctx.len() + 32..], b"payload");
        assert_eq!(msg.len(), tag.len() + 2 + ctx.len() + 32 + 7);
    }

    /// The encoding is injective across the registry: no two (ctx, identity,
    /// payload) triples collide.
    #[test]
    fn the_signed_message_is_injective() {
        let mut seen: alloc::vec::Vec<alloc::vec::Vec<u8>> = alloc::vec::Vec::new();
        for ctx in SigContext::ALL {
            for id in [[0u8; 32], [1u8; 32]] {
                for payload in [&b""[..], b"a", b"ab", b"MLKEMBraid/xeddsa/v2\x00"] {
                    let m = signed_message(ctx, &id, payload);
                    assert!(!seen.contains(&m), "collision on {ctx:?}");
                    seen.push(m);
                }
            }
        }
    }

    #[test]
    fn the_debug_output_names_no_bytes() {
        let mut r = rng();
        let s = Signer::new(&mut r);
        let sig = s.sign(SigContext::Enrolment, &[0u8; 32], b"", &mut r);
        assert_eq!(format!("{sig:?}"), "HybridSignature(3381 bytes)");
    }
}
