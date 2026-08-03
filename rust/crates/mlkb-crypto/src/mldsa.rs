//! ML-DSA-65, with a context string that is always load-bearing
//! (spec M1 §E.3, §H Q3).
//!
//! # Why this wrapper exists rather than the raw crate
//!
//! Spec M1 §E.3, empirical: `ml-dsa 0.1.1`'s `Signer::sign` is deterministic
//! and **hardcodes an empty context**, and its `VerifyingKey::verify_with_context`
//! returns a bare `bool` — a dangerously ignorable value. Because M1 §E.2
//! makes the context load-bearing (it is what stops a signed prekey being
//! lifted into a PQ-prekey slot), every signature here routes through
//! `ExpandedSigningKey::sign_deterministic(msg, ctx)`, every verification
//! routes through `verify_with_context`, and the `bool` is wrapped so the only
//! reachable form is a `Result`. The raw API is not re-exported.
//!
//! FIPS-204 pre-hash (HashML-DSA) does not exist in this crate and nothing in
//! the specification requires it (M1 §E.3).

use ml_dsa::{
    Generate, KeyExport, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey,
    common::array::Array,
    common::array::sizes::{U32, U1952, U3309},
};
use mlkb_secrets::{ProtocolError, Secret32};
use rand_core::CryptoRng;

use crate::util::copy_prefix;

/// ML-DSA-65 verifying key length in bytes (spec M1 §I).
pub const MLDSA_VERIFYING_KEY_LEN: usize = 1952;

/// ML-DSA-65 signature length in bytes (spec M1 §I, §E.1).
pub const MLDSA_SIGNATURE_LEN: usize = 3309;

/// ML-DSA-65 private key seed length in bytes (spec M1 §I, §E.3).
pub const MLDSA_SEED_LEN: usize = 32;

/// The FIPS-204 bound on a signing context string (spec M1 §E.3).
pub const MLDSA_MAX_CONTEXT_LEN: usize = 255;

/// An ML-DSA-65 signature, in its 3309-byte encoded form (spec M1 §E.1).
#[derive(Clone)]
pub struct MlDsaSignature([u8; MLDSA_SIGNATURE_LEN]);

impl core::fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MlDsaSignature({} bytes)", self.0.len())
    }
}

impl PartialEq for MlDsaSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice() == other.0.as_slice()
    }
}

impl Eq for MlDsaSignature {}

impl MlDsaSignature {
    /// Wraps 3309 signature bytes read off the wire (spec M1 §E.1).
    #[must_use]
    pub fn from_bytes(bytes: [u8; MLDSA_SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MLDSA_SIGNATURE_LEN] {
        &self.0
    }
}

/// An ML-DSA-65 signing key (spec M1 §E.3).
///
/// Stored as the 32-byte seed ξ, which M1 §H confirms is the crate's canonical
/// private-key serialization, and expanded on load.
pub struct MlDsaSigningKey(SigningKey<MlDsa65>);

/// Redacting (spec M1 §G.1).
impl core::fmt::Debug for MlDsaSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MlDsaSigningKey([REDACTED])")
    }
}

impl MlDsaSigningKey {
    /// Generates a fresh signing key (spec M1 §E.3).
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(SigningKey::<MlDsa65>::generate_from_rng(rng))
    }

    /// Rebuilds a signing key from its stored 32-byte seed ξ
    /// (spec M1 §E.3, parent §9 item 5).
    #[must_use]
    pub fn from_seed(seed: &Secret32) -> Self {
        let bytes = seed.expose_secret();
        let xi = Array::<u8, U32>::from_fn(|i| bytes.get(i).copied().unwrap_or(0));
        Self(SigningKey::<MlDsa65>::from_seed(&xi))
    }

    /// The 32-byte seed, for sealing into the store (spec M1 §G.5).
    #[must_use]
    pub fn to_seed(&self) -> Secret32 {
        let xi = self.0.to_bytes();
        Secret32::from_fill(|out| copy_prefix(out, &xi))
    }

    /// The matching verifying key (spec M1 §E.3).
    #[must_use]
    pub fn verifying_key(&self) -> MlDsaVerifyingKey {
        MlDsaVerifyingKey(self.0.verifying_key())
    }

    /// Signs `msg` under `ctx` (spec M1 §E.3).
    ///
    /// Routed through `ExpandedSigningKey::sign_deterministic` because
    /// `Signer::sign` would silently substitute an empty context.
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] if `ctx` is longer than
    /// [`MLDSA_MAX_CONTEXT_LEN`], which FIPS-204 does not define a signature
    /// for. Every context in [`crate::labels::SigContext`] is well inside the
    /// bound, so this is reachable only from a caller that invented one.
    pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> Result<MlDsaSignature, ProtocolError> {
        let signature = self
            .0
            .expanded_key()
            .sign_deterministic(msg, ctx)
            .map_err(|_| ProtocolError::Internal)?;
        let encoded = signature.encode();
        let mut out = [0u8; MLDSA_SIGNATURE_LEN];
        copy_prefix(&mut out, &encoded);
        Ok(MlDsaSignature(out))
    }
}

/// An ML-DSA-65 verifying key (spec M1 §E.3).
#[derive(Debug, Clone)]
pub struct MlDsaVerifyingKey(VerifyingKey<MlDsa65>);

impl MlDsaVerifyingKey {
    /// Decodes a verifying key from its 1952-byte wire form (spec M1 §I).
    #[must_use]
    pub fn from_wire(bytes: &[u8; MLDSA_VERIFYING_KEY_LEN]) -> Self {
        let array = Array::<u8, U1952>::from_fn(|i| bytes.get(i).copied().unwrap_or(0));
        Self(VerifyingKey::<MlDsa65>::decode(&array))
    }

    /// The 1952-byte wire form (spec M1 §I).
    #[must_use]
    pub fn to_wire(&self) -> [u8; MLDSA_VERIFYING_KEY_LEN] {
        let encoded = self.0.encode();
        let mut out = [0u8; MLDSA_VERIFYING_KEY_LEN];
        copy_prefix(&mut out, &encoded);
        out
    }

    /// Verifies `signature` over `msg` under `ctx` (spec M1 §E.3).
    ///
    /// The upstream `verify_with_context` returns `bool`; this is the only
    /// reachable form, and it returns a `Result` so that dropping the outcome
    /// is a `#[must_use]` warning rather than a silent accept.
    ///
    /// # Errors
    /// [`ProtocolError::Unauthenticated`] if the signature does not decode, or
    /// does not verify, or was made under a different context. The three are
    /// deliberately indistinguishable (spec parent §8.4).
    pub fn verify(
        &self,
        msg: &[u8],
        ctx: &[u8],
        signature: &MlDsaSignature,
    ) -> Result<(), ProtocolError> {
        let array = Array::<u8, U3309>::from_fn(|i| signature.0.get(i).copied().unwrap_or(0));
        let decoded = Signature::<MlDsa65>::decode(&array).ok_or(ProtocolError::Unauthenticated)?;
        if self.0.verify_with_context(msg, ctx, &decoded) {
            Ok(())
        } else {
            Err(ProtocolError::Unauthenticated)
        }
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
    use crate::labels::SigContext;
    use alloc::format;

    fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let mut r = rng();
        let sk = MlDsaSigningKey::generate(&mut r);
        let vk = sk.verifying_key();
        let ctx = SigContext::SignedPrekey.as_bytes();
        let sig = sk.sign(b"payload", ctx).unwrap();
        assert_eq!(sig.as_bytes().len(), MLDSA_SIGNATURE_LEN);
        assert_eq!(vk.verify(b"payload", ctx, &sig), Ok(()));
    }

    /// The negative that M1 §E.3 exists for: a signature made under one
    /// context must not verify under another.
    #[test]
    fn a_signature_does_not_verify_under_a_different_context() {
        let mut r = rng();
        let sk = MlDsaSigningKey::generate(&mut r);
        let vk = sk.verifying_key();
        let sig = sk
            .sign(b"prekey", SigContext::SignedPrekey.as_bytes())
            .unwrap();

        assert_eq!(
            vk.verify(b"prekey", SigContext::PqSignedPrekey.as_bytes(), &sig),
            Err(ProtocolError::Unauthenticated),
            "a signed prekey was liftable into a PQ-prekey slot"
        );
        assert_eq!(
            vk.verify(b"prekey", SigContext::Enrolment.as_bytes(), &sig),
            Err(ProtocolError::Unauthenticated)
        );
        // And the empty context — which `Signer::sign` would have used — is
        // just as wrong.
        assert_eq!(
            vk.verify(b"prekey", b"", &sig),
            Err(ProtocolError::Unauthenticated)
        );
    }

    /// Every ordered pair of distinct registry contexts, both directions.
    #[test]
    fn no_pair_of_registry_contexts_is_interchangeable() {
        let mut r = rng();
        let sk = MlDsaSigningKey::generate(&mut r);
        let vk = sk.verifying_key();
        for signing in SigContext::ALL {
            let sig = sk.sign(b"m", signing.as_bytes()).unwrap();
            for verifying in SigContext::ALL {
                let outcome = vk.verify(b"m", verifying.as_bytes(), &sig);
                if signing == verifying {
                    assert_eq!(outcome, Ok(()));
                } else {
                    assert_eq!(outcome, Err(ProtocolError::Unauthenticated));
                }
            }
        }
    }

    #[test]
    fn a_tampered_message_or_signature_or_key_fails() {
        let mut r = rng();
        let sk = MlDsaSigningKey::generate(&mut r);
        let vk = sk.verifying_key();
        let ctx = SigContext::Enrolment.as_bytes();
        let sig = sk.sign(b"message", ctx).unwrap();

        assert_eq!(
            vk.verify(b"messagE", ctx, &sig),
            Err(ProtocolError::Unauthenticated)
        );

        let mut bad = *sig.as_bytes();
        bad[0] ^= 1;
        assert_eq!(
            vk.verify(b"message", ctx, &MlDsaSignature::from_bytes(bad)),
            Err(ProtocolError::Unauthenticated)
        );

        let other = MlDsaSigningKey::generate(&mut r).verifying_key();
        assert_eq!(
            other.verify(b"message", ctx, &sig),
            Err(ProtocolError::Unauthenticated)
        );
    }

    #[test]
    fn a_seed_round_trip_reproduces_the_same_signing_key() {
        let mut r = rng();
        let sk = MlDsaSigningKey::generate(&mut r);
        let seed = sk.to_seed();
        let restored = MlDsaSigningKey::from_seed(&seed);
        assert_eq!(restored.to_seed(), seed);
        assert_eq!(
            restored.verifying_key().to_wire(),
            sk.verifying_key().to_wire()
        );

        // Signing is deterministic (M1 §E.3), so the two keys agree byte for
        // byte on the same input.
        let ctx = SigContext::SignedPrekey.as_bytes();
        assert_eq!(
            sk.sign(b"m", ctx).unwrap(),
            restored.sign(b"m", ctx).unwrap()
        );
    }

    #[test]
    fn a_verifying_key_round_trips_through_the_wire() {
        let mut r = rng();
        let sk = MlDsaSigningKey::generate(&mut r);
        let wire = sk.verifying_key().to_wire();
        assert_eq!(wire.len(), MLDSA_VERIFYING_KEY_LEN);
        let vk = MlDsaVerifyingKey::from_wire(&wire);
        let ctx = SigContext::SignedPrekey.as_bytes();
        assert_eq!(vk.verify(b"m", ctx, &sk.sign(b"m", ctx).unwrap()), Ok(()));
        assert_eq!(vk.to_wire(), wire);
    }

    #[test]
    fn an_over_long_context_is_refused_rather_than_truncated() {
        let mut r = rng();
        let sk = MlDsaSigningKey::generate(&mut r);
        assert_eq!(
            sk.sign(b"m", &[0u8; MLDSA_MAX_CONTEXT_LEN + 1]),
            Err(ProtocolError::Internal)
        );
        assert!(sk.sign(b"m", &[0u8; MLDSA_MAX_CONTEXT_LEN]).is_ok());
    }

    #[test]
    fn the_signing_key_debug_is_redacted() {
        let mut r = rng();
        let sk = MlDsaSigningKey::generate(&mut r);
        assert!(format!("{sk:?}").contains("REDACTED"));
    }

    #[test]
    fn the_constants_match_the_spec_table() {
        assert_eq!(MLDSA_VERIFYING_KEY_LEN, 1952);
        assert_eq!(MLDSA_SIGNATURE_LEN, 3309);
        assert_eq!(MLDSA_SEED_LEN, 32);
    }
}
