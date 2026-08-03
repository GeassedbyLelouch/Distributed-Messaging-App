//! ML-KEM-1024, the PQ leg (spec parent §5.3, M1 §H Q1).
//!
//! This module is the only source of [`KemSharedSecret`] values, which is what
//! makes spec parent §4.1's invariant structural: no root key can be derived
//! without one, and one can only come from a real ML-KEM operation performed
//! here.

use ml_kem::array::Array;
use ml_kem::array::sizes::{U64, U1568};
use ml_kem::kem::{Decapsulate, Encapsulate, Generate, KeyExport, KeyInit};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem1024};
use mlkb_secrets::{ProtocolError, Secret32, SecretBytes};
use rand_core::CryptoRng;

use crate::keys::KemSharedSecret;
use crate::util::copy_prefix;

/// ML-KEM-1024 encapsulation key length in bytes (spec M1 §I).
pub const KEM_ENCAPSULATION_KEY_LEN: usize = 1568;

/// ML-KEM-1024 ciphertext length in bytes (spec M1 §I).
pub const KEM_CIPHERTEXT_LEN: usize = 1568;

/// ML-KEM-1024 shared secret length in bytes (spec M1 §I).
pub const KEM_SHARED_SECRET_LEN: usize = 32;

/// ML-KEM-1024 decapsulation key seed length in bytes (spec M1 §I).
///
/// This is FIPS-203's `(d, z)` seed, **not** the 3168-byte expanded form,
/// which `ml-kem 0.3.2` deprecates (M1 §H, Q1).
pub const KEM_SEED_LEN: usize = 64;

/// An ML-KEM-1024 encapsulation key (spec M1 §I, §H Q1).
#[derive(Debug, Clone, PartialEq)]
pub struct KemEncapsulationKey(EncapsulationKey<MlKem1024>);

impl KemEncapsulationKey {
    /// Decodes an encapsulation key from its 1568-byte wire form
    /// (spec M1 §H, Q1).
    ///
    /// # This is not key confirmation
    ///
    /// M1 §H records the caveat and it is repeated here because it is the kind
    /// of thing a caller assumes away: the validation `ml-kem` performs is the
    /// **FIPS-203 §6.2 modulus check only**. The trailing 32-byte `rho` is not
    /// range-checked, so flipping a byte inside it still decodes. A successful
    /// decode means "these bytes are a syntactically valid key", not "the peer
    /// holds the matching private key". Possession is proved by the signature
    /// over the prekey (spec M1 §E.2) and by the confirmation tag
    /// (spec parent §4.2) — never by this function returning `Ok`.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] if any coefficient is out of range.
    pub fn from_wire(bytes: &[u8; KEM_ENCAPSULATION_KEY_LEN]) -> Result<Self, ProtocolError> {
        let array = Array::<u8, U1568>::from_fn(|i| bytes.get(i).copied().unwrap_or(0));
        EncapsulationKey::<MlKem1024>::new(&array)
            .map(Self)
            .map_err(|_| ProtocolError::Malformed)
    }

    /// The 1568-byte wire form (spec M1 §H, Q1).
    #[must_use]
    pub fn to_wire(&self) -> [u8; KEM_ENCAPSULATION_KEY_LEN] {
        let encoded = self.0.to_bytes();
        let mut out = [0u8; KEM_ENCAPSULATION_KEY_LEN];
        copy_prefix(&mut out, &encoded);
        out
    }

    /// Encapsulates to this key (spec parent §4.1, M1 §D.2).
    ///
    /// The returned [`KemSharedSecret`] is the only kind of value
    /// [`crate::derive_sk`] and [`crate::RootKey::ratchet`] accept for the PQ
    /// leg.
    #[must_use]
    pub fn encapsulate<R: CryptoRng + ?Sized>(
        &self,
        rng: &mut R,
    ) -> (KemCiphertext, KemSharedSecret) {
        let (ct, ss) = self.0.encapsulate_with_rng(rng);
        let mut ct_bytes = [0u8; KEM_CIPHERTEXT_LEN];
        copy_prefix(&mut ct_bytes, &ct);
        (
            KemCiphertext(ct_bytes),
            KemSharedSecret::from_kem(Secret32::from_fill(|out| copy_prefix(out, &ss))),
        )
    }
}

/// An ML-KEM-1024 ciphertext (spec M1 §I).
#[derive(Clone)]
pub struct KemCiphertext([u8; KEM_CIPHERTEXT_LEN]);

impl core::fmt::Debug for KemCiphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KemCiphertext({} bytes)", self.0.len())
    }
}

impl KemCiphertext {
    /// Wraps 1568 ciphertext bytes read off the wire (spec M1 §C.3).
    ///
    /// A ciphertext is public and carries no structure to validate: ML-KEM's
    /// implicit rejection means a wrong ciphertext yields a wrong shared
    /// secret rather than an error, and the resulting key schedule simply
    /// fails to authenticate.
    #[must_use]
    pub fn from_wire(bytes: [u8; KEM_CIPHERTEXT_LEN]) -> Self {
        Self(bytes)
    }

    /// The wire bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEM_CIPHERTEXT_LEN] {
        &self.0
    }
}

/// An ML-KEM-1024 decapsulation key (spec M1 §I, §H Q1).
///
/// Serialised as the 64-byte FIPS-203 `(d, z)` seed, which is what
/// spec parent §9 stores.
pub struct KemDecapsulationKey(DecapsulationKey<MlKem1024>);

/// Redacting (spec M1 §G.1).
impl core::fmt::Debug for KemDecapsulationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KemDecapsulationKey([REDACTED])")
    }
}

impl KemDecapsulationKey {
    /// Generates a fresh ML-KEM-1024 key pair (spec M1 §D.2).
    #[must_use]
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self(DecapsulationKey::<MlKem1024>::generate_from_rng(rng))
    }

    /// Rebuilds a key pair from its stored 64-byte seed (spec parent §9).
    #[must_use]
    pub fn from_seed(seed: &SecretBytes<KEM_SEED_LEN>) -> Self {
        let bytes = seed.expose_secret();
        let array = Array::<u8, U64>::from_fn(|i| bytes.get(i).copied().unwrap_or(0));
        Self(DecapsulationKey::<MlKem1024>::new(&array))
    }

    /// The 64-byte seed, for sealing into the store (spec M1 §G.5).
    #[must_use]
    pub fn to_seed(&self) -> SecretBytes<KEM_SEED_LEN> {
        let seed = self.0.to_bytes();
        SecretBytes::<KEM_SEED_LEN>::from_fill(|out| copy_prefix(out, &seed))
    }

    /// The matching encapsulation key (spec M1 §D.2).
    #[must_use]
    pub fn encapsulation_key(&self) -> KemEncapsulationKey {
        KemEncapsulationKey(self.0.encapsulation_key().clone())
    }

    /// Decapsulates (spec parent §4.1, M1 §C.1, §D.2).
    ///
    /// Infallible by design: FIPS-203 ML-KEM uses **implicit rejection**, so a
    /// ciphertext that was not produced for this key yields a pseudo-random
    /// shared secret rather than an error. That is deliberate — an explicit
    /// rejection here would be a decryption oracle (spec parent §8.4). The
    /// wrong secret is caught downstream when the confirmation tag or the AEAD
    /// tag fails.
    #[must_use]
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> KemSharedSecret {
        let array = Array::<u8, U1568>::from_fn(|i| ciphertext.0.get(i).copied().unwrap_or(0));
        let ss = self.0.decapsulate(&array);
        KemSharedSecret::from_kem(Secret32::from_fill(|out| copy_prefix(out, &ss)))
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

    #[test]
    fn encapsulation_and_decapsulation_agree() {
        let mut r = rng();
        let dk = KemDecapsulationKey::generate(&mut r);
        let ek = dk.encapsulation_key();
        let (ct, ss_send) = ek.encapsulate(&mut r);
        let ss_recv = dk.decapsulate(&ct);
        assert_eq!(ss_send.bytes(), ss_recv.bytes());
        assert_eq!(ss_send.bytes().len(), KEM_SHARED_SECRET_LEN);
    }

    #[test]
    fn agreement_survives_the_wire_round_trip() {
        let mut r = rng();
        let dk = KemDecapsulationKey::generate(&mut r);
        let ek_wire = dk.encapsulation_key().to_wire();
        assert_eq!(ek_wire.len(), KEM_ENCAPSULATION_KEY_LEN);

        let ek = KemEncapsulationKey::from_wire(&ek_wire).unwrap();
        assert_eq!(ek, dk.encapsulation_key());

        let (ct, ss_send) = ek.encapsulate(&mut r);
        assert_eq!(ct.as_bytes().len(), KEM_CIPHERTEXT_LEN);
        let ct_again = KemCiphertext::from_wire(*ct.as_bytes());
        assert_eq!(dk.decapsulate(&ct_again).bytes(), ss_send.bytes());
    }

    #[test]
    fn two_encapsulations_to_one_key_differ() {
        let mut r = rng();
        let dk = KemDecapsulationKey::generate(&mut r);
        let ek = dk.encapsulation_key();
        let (ct1, ss1) = ek.encapsulate(&mut r);
        let (ct2, ss2) = ek.encapsulate(&mut r);
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_ne!(ss1.bytes(), ss2.bytes());
    }

    #[test]
    fn a_seed_round_trip_reproduces_the_same_key_pair() {
        let mut r = rng();
        let dk = KemDecapsulationKey::generate(&mut r);
        let seed = dk.to_seed();
        assert_eq!(seed.expose_secret().len(), KEM_SEED_LEN);

        let restored = KemDecapsulationKey::from_seed(&seed);
        assert_eq!(restored.encapsulation_key(), dk.encapsulation_key());

        let (ct, ss) = dk.encapsulation_key().encapsulate(&mut r);
        assert_eq!(restored.decapsulate(&ct).bytes(), ss.bytes());
    }

    /// A ciphertext meant for another key decapsulates to a *different* secret
    /// rather than to an error (implicit rejection, FIPS-203).
    #[test]
    fn a_foreign_ciphertext_yields_a_different_secret_not_an_error() {
        let mut r = rng();
        let mine = KemDecapsulationKey::generate(&mut r);
        let theirs = KemDecapsulationKey::generate(&mut r);
        let (ct, ss) = theirs.encapsulation_key().encapsulate(&mut r);
        assert_ne!(mine.decapsulate(&ct).bytes(), ss.bytes());
    }

    /// A corrupted ciphertext decapsulates to a different secret, again with
    /// no error to serve as an oracle.
    #[test]
    fn a_corrupted_ciphertext_yields_a_different_secret() {
        let mut r = rng();
        let dk = KemDecapsulationKey::generate(&mut r);
        let (ct, ss) = dk.encapsulation_key().encapsulate(&mut r);
        let mut bad = *ct.as_bytes();
        bad[0] ^= 1;
        assert_ne!(
            dk.decapsulate(&KemCiphertext::from_wire(bad)).bytes(),
            ss.bytes()
        );
    }

    #[test]
    fn a_non_canonical_encapsulation_key_is_rejected() {
        // All-0xFF decodes to coefficients >= q (FIPS-203 §6.2).
        let bad = [0xff_u8; KEM_ENCAPSULATION_KEY_LEN];
        assert_eq!(
            KemEncapsulationKey::from_wire(&bad).unwrap_err(),
            ProtocolError::Malformed
        );
    }

    /// The caveat in the `from_wire` docs, made a test so it cannot rot: a
    /// successful decode is **not** key confirmation.
    #[test]
    fn decoding_is_not_key_confirmation() {
        let mut r = rng();
        let dk = KemDecapsulationKey::generate(&mut r);
        let mut wire = dk.encapsulation_key().to_wire();
        // The last 32 bytes are `rho`, which is not range-checked.
        wire[KEM_ENCAPSULATION_KEY_LEN - 1] ^= 0xff;
        let decoded = KemEncapsulationKey::from_wire(&wire);
        assert!(
            decoded.is_ok(),
            "M1 §H says rho is not range-checked; if this now fails the caveat \
             in `from_wire` needs revisiting"
        );
        // And it is a *different* key: encapsulating to it does not give the
        // real holder a usable secret.
        let ek = decoded.unwrap();
        assert_ne!(ek, dk.encapsulation_key());
        let (ct, ss) = ek.encapsulate(&mut r);
        assert_ne!(dk.decapsulate(&ct).bytes(), ss.bytes());
    }

    #[test]
    fn the_decapsulation_key_debug_is_redacted() {
        let mut r = rng();
        let dk = KemDecapsulationKey::generate(&mut r);
        assert!(format!("{dk:?}").contains("REDACTED"));
        let ct = KemCiphertext::from_wire([0u8; KEM_CIPHERTEXT_LEN]);
        assert_eq!(format!("{ct:?}"), "KemCiphertext(1568 bytes)");
    }

    #[test]
    fn the_constants_match_the_spec_table() {
        assert_eq!(KEM_ENCAPSULATION_KEY_LEN, 1568);
        assert_eq!(KEM_CIPHERTEXT_LEN, 1568);
        assert_eq!(KEM_SHARED_SECRET_LEN, 32);
        assert_eq!(KEM_SEED_LEN, 64);
    }
}
