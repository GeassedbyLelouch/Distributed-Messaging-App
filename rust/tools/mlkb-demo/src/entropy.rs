//! The demo's randomness source (spec M1 §G.2, §I.3).
//!
//! `mlkb-protocol` takes all of its randomness through [`Entropy`] and nothing
//! else. M1 §I.3 makes the implementer of that trait solely responsible for
//! nonce uniqueness, and records that the deterministic implementation used for
//! KATs must never be reachable from a production constructor.
//!
//! This module is the demo's answer: [`OsEntropy`] is backed by the platform
//! CSPRNG on every method, there is no seeded variant anywhere in this binary,
//! and there is no constructor that takes a seed. **Nothing in this tool is
//! mocked** — every key, nonce and encapsulation the UI shows came from
//! `getrandom`.

use core::convert::Infallible;

use mlkb_crypto::{
    KemCiphertext, KemDecapsulationKey, KemEncapsulationKey, KemSharedSecret, X25519SecretKey,
};
use mlkb_protocol::Entropy;
use mlkb_secrets::Nonce192;

/// The platform CSPRNG, as the infallible `rand_core` traits.
///
/// `getrandom::SysRng` already implements `TryRng`, but with
/// `Error = getrandom::Error`, and `mlkb-crypto`'s constructors take
/// `CryptoRng`, which is `TryCryptoRng<Error = Infallible>`. This wrapper is
/// the adaptor.
///
/// # What a failure does
///
/// `getrandom::fill` fails only when the OS entropy source is unavailable,
/// which for a local demo is not a recoverable condition and must never be
/// papered over with a fallback: silently substituting weaker randomness is
/// precisely how nonce reuse happens (M1 §I.3). This aborts the process
/// instead. That is a choice a *demo binary* may make and a library may not,
/// which is one reason this crate is in `tools/`.
pub(crate) struct OsRng;

impl OsRng {
    fn fill(dst: &mut [u8]) {
        if getrandom::fill(dst).is_err() {
            // Fail loudly rather than continue with unknown bytes.
            eprintln!("mlkb-demo: the platform CSPRNG is unavailable; refusing to continue");
            std::process::exit(70);
        }
    }
}

impl core::fmt::Debug for OsRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OsRng")
    }
}

impl rand_core::TryRng for OsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        Self::fill(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        Self::fill(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        Self::fill(dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for OsRng {}

/// The M1 §G.2 randomness boundary, backed by the platform CSPRNG.
///
/// In the shipping client this role belongs to `mlkb-session` (M1 §I.3). Here
/// it belongs to the demo, and it is deliberately the only implementation this
/// binary contains.
#[derive(Debug)]
pub(crate) struct OsEntropy;

impl Entropy for OsEntropy {
    fn x25519_secret(&mut self) -> X25519SecretKey {
        X25519SecretKey::random(&mut OsRng)
    }

    fn kem_keypair(&mut self) -> KemDecapsulationKey {
        KemDecapsulationKey::generate(&mut OsRng)
    }

    fn nonce(&mut self) -> Nonce192 {
        Nonce192::random(&mut OsRng)
    }

    fn encapsulate(&mut self, to: &KemEncapsulationKey) -> (KemCiphertext, KemSharedSecret) {
        to.encapsulate(&mut OsRng)
    }
}
