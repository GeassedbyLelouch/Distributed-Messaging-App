//! Test-only fixtures. Compiled under `cfg(test)` and never shipped.
//!
//! This is deliberately *not* `mlkb-testkit`: nothing here is reachable from a
//! production constructor, because the module does not exist outside a test
//! build (M1 §I.3, and the `client/anonymous_transport.py:30-35` defect class
//! it names).
//!
//! # Everything here is real cryptography
//!
//! `mlkb-wire`'s fixtures build *well-formed* signature bytes without signing,
//! because that crate only parses. This crate **verifies** — parent §4.3 is one
//! of the properties under test — so every prekey here carries a genuine hybrid
//! signature over the real `canonical(<part> without "s")` payload, and every
//! handshake performs a real ML-KEM encapsulation. The only synthetic
//! signature is the `EnrolmentProof`'s, which no code path in this crate
//! checks: its issuer keys are pinned in the client binary and its verification
//! is `mlkb-policy`'s (M1 §F).
//!
//! # The RNG is deterministic on purpose
//!
//! A failing key has to reproduce. The determinism is also load-bearing for one
//! test: running [`initiate`](crate::initiate) twice from the same seed yields
//! two sessions with the *same* `SK` — hence the same frame keys — which is the
//! only way to build a frame that passes the M1 §A.1 MAC while carrying a
//! ciphertext sealed under a different chain key. That is the forgery the
//! audit's D7 test needs.

#![allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    // Fixture code: an RNG narrowing and two compile-time length constants.
    clippy::cast_possible_truncation
)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::Infallible;

use mlkb_crypto::{
    HYBRID_SIGNATURE_VERSION, HybridSignature, KemCiphertext, KemDecapsulationKey,
    KemEncapsulationKey, KemSharedSecret, MLDSA_SIGNATURE_LEN, MlDsaSigningKey, X25519SecretKey,
    XEDDSA_SIGNATURE_LEN, sha256,
};
use mlkb_secrets::Nonce192;
use mlkb_wire::{
    EnrolmentProof, HybridIdentityPublic, IdentityId, OneTimePrekey, PrekeyBundleV2,
    SignedPqPrekey, SignedPrekey,
};

use crate::entropy::Entropy;
use crate::pqxdh::{LocalIdentity, ResponderPrekeys};

// ---------------------------------------------------------------------------
// a deterministic RNG
// ---------------------------------------------------------------------------

/// splitmix64. Deterministic so that a failing key is reproducible, and
/// test-only so it can never be reached from a production constructor
/// (M1 §I.3).
pub(crate) struct DetRng(u64);

impl DetRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

impl rand_core::TryRng for DetRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&word[..n]);
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for DetRng {}

/// The test implementation of the M1 §I.3 randomness boundary.
///
/// Production supplies this from the platform CSPRNG at exactly one place
/// (`mlkb-session`); this one is seeded, and lives behind `#[cfg(test)]` so it
/// cannot be reached from anywhere else.
pub(crate) struct TestEntropy(DetRng);

impl TestEntropy {
    pub(crate) fn new(seed: u64) -> Self {
        Self(DetRng::new(seed))
    }
}

impl Entropy for TestEntropy {
    fn x25519_secret(&mut self) -> X25519SecretKey {
        X25519SecretKey::random(&mut self.0)
    }

    fn kem_keypair(&mut self) -> KemDecapsulationKey {
        KemDecapsulationKey::generate(&mut self.0)
    }

    fn nonce(&mut self) -> Nonce192 {
        Nonce192::random(&mut self.0)
    }

    fn encapsulate(&mut self, to: &KemEncapsulationKey) -> (KemCiphertext, KemSharedSecret) {
        to.encapsulate(&mut self.0)
    }
}

/// [`TestEntropy`] except that `encapsulate` ignores the key it is handed and
/// encapsulates to a decoy of its own instead.
///
/// Everything else about the resulting message is genuine — the frame MAC
/// verifies under the real `K_frame_dir`, the M1 §D.3 pairing holds, `dh` is a
/// real public key and `kc` is a real ML-KEM ciphertext — but the receiver
/// decapsulates `kc` under *its* decapsulation key and gets a shared secret
/// that has nothing to do with the sender's. So the root step the receiver
/// would take is not the one the sender took, and the AEAD must refuse.
///
/// That is the exact shape of a MAC-valid frame opening a new receiving chain
/// that cannot be opened: the thing parent §8.1 has to survive without moving
/// state, and the thing a party who held `SK` once and lost it could still
/// manufacture. It is also, from the other side, the behavioural witness for
/// parent §4.1 — if the ML-KEM leg were not load-bearing in the root step, a
/// message built this way would decrypt.
pub(crate) struct MisdirectedKemEntropy {
    rng: DetRng,
    decoy: KemDecapsulationKey,
}

impl MisdirectedKemEntropy {
    pub(crate) fn new(seed: u64) -> Self {
        let mut decoy_rng = DetRng::new(seed ^ 0x00de_c0de_0000_0000);
        Self {
            decoy: KemDecapsulationKey::generate(&mut decoy_rng),
            rng: DetRng::new(seed),
        }
    }
}

impl Entropy for MisdirectedKemEntropy {
    fn x25519_secret(&mut self) -> X25519SecretKey {
        X25519SecretKey::random(&mut self.rng)
    }

    fn kem_keypair(&mut self) -> KemDecapsulationKey {
        KemDecapsulationKey::generate(&mut self.rng)
    }

    fn nonce(&mut self) -> Nonce192 {
        Nonce192::random(&mut self.rng)
    }

    fn encapsulate(&mut self, _to: &KemEncapsulationKey) -> (KemCiphertext, KemSharedSecret) {
        // Ignores the target the state machine chose.
        self.decoy.encapsulation_key().encapsulate(&mut self.rng)
    }
}

// ---------------------------------------------------------------------------
// parties
// ---------------------------------------------------------------------------

/// The id a fixture bundle publishes its signed prekey under.
pub(crate) const SPK_ID: u32 = 11;
/// The id a fixture bundle publishes its ML-KEM prekey under (M1 §C.3).
pub(crate) const PQSPK_ID: u32 = 12;
/// The id a fixture bundle publishes its one-time prekey under.
pub(crate) const OPK_ID: u32 = 13;

/// One device, with every private key a handshake can need.
pub(crate) struct Party {
    ik: X25519SecretKey,
    mldsa: MlDsaSigningKey,
    spk: X25519SecretKey,
    pqspk: KemDecapsulationKey,
    opk: X25519SecretKey,
    /// The device this party is (spec M1 §C.3 `to_device_id`).
    pub(crate) device_id: u32,
}

impl Party {
    pub(crate) fn generate(rng: &mut DetRng, device_id: u32) -> Self {
        Self {
            ik: X25519SecretKey::random(rng),
            mldsa: MlDsaSigningKey::generate(rng),
            spk: X25519SecretKey::random(rng),
            pqspk: KemDecapsulationKey::generate(rng),
            opk: X25519SecretKey::random(rng),
            device_id,
        }
    }

    fn ik_mldsa_hash(&self) -> [u8; 32] {
        sha256(&[&self.mldsa.verifying_key().to_wire()])
    }

    pub(crate) fn identity(&self) -> LocalIdentity {
        LocalIdentity::new(
            X25519SecretKey::from_bytes(*self.ik.to_secret().expose_secret()),
            self.ik_mldsa_hash(),
        )
    }

    pub(crate) fn id(&self) -> IdentityId {
        IdentityId::from_public_keys(
            self.ik.public_key().as_bytes(),
            &self.mldsa.verifying_key().to_wire(),
        )
    }

    /// The private halves, as [`crate::respond`] wants them.
    pub(crate) fn prekeys(&self, with_opk: bool) -> ResponderPrekeys<'_> {
        ResponderPrekeys {
            device_id: self.device_id,
            spk: (SPK_ID, &self.spk),
            pqspk: (PQSPK_ID, &self.pqspk),
            opk: with_opk.then_some((OPK_ID, &self.opk)),
        }
    }

    /// A genuinely signed `PrekeyBundleV2` (spec parent §4.3, M1 §E.2).
    ///
    /// Each part is signed twice over in the sense that matters: under its own
    /// M1 §E.2 context, and over a payload that includes its own id — the
    /// context separates *kinds* of prekey, the id separates *instances*.
    pub(crate) fn bundle(&self, rng: &mut DetRng, with_opk: bool) -> PrekeyBundleV2 {
        let id = self.id();

        let mut signed_prekey = SignedPrekey {
            id: SPK_ID,
            public: *self.spk.public_key().as_bytes(),
            signature: synthetic_signature(0x20),
        };
        signed_prekey.signature = Box::new(
            HybridSignature::sign(
                &self.ik,
                &self.mldsa,
                SignedPrekey::CONTEXT,
                id.as_bytes(),
                signed_prekey.signed_payload().unwrap().as_bytes(),
                rng,
            )
            .unwrap(),
        );

        let mut pq_prekey = SignedPqPrekey {
            id: PQSPK_ID,
            ek: Box::new(self.pqspk.encapsulation_key().to_wire()),
            signature: synthetic_signature(0x30),
        };
        pq_prekey.signature = Box::new(
            HybridSignature::sign(
                &self.ik,
                &self.mldsa,
                SignedPqPrekey::CONTEXT,
                id.as_bytes(),
                pq_prekey.signed_payload().unwrap().as_bytes(),
                rng,
            )
            .unwrap(),
        );

        PrekeyBundleV2 {
            identity: HybridIdentityPublic {
                ik_x25519: *self.ik.public_key().as_bytes(),
                ik_mldsa: Box::new(self.mldsa.verifying_key().to_wire()),
            },
            signed_prekey,
            pq_prekey,
            one_time: with_opk.then_some(OneTimePrekey {
                id: OPK_ID,
                public: *self.opk.public_key().as_bytes(),
            }),
            // Not verified anywhere in this crate: the issuer keys are pinned
            // in the client binary and the check is `mlkb-policy`'s (M1 §F).
            enrolment: EnrolmentProof {
                issuer_epoch: 12,
                issuer_key_id: 3,
                not_after_ms: 1_800_000_000_000,
                subject: id,
                tier: 1,
                signature: synthetic_signature(0x10),
            },
            expires_at_ms: 1_800_000_000_000,
        }
    }
}

/// A well-formed but cryptographically meaningless `HybridSignature`
/// (spec M1 §E.1): correct version, suite and length prefixes.
pub(crate) fn synthetic_signature(fill: u8) -> Box<HybridSignature> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&HYBRID_SIGNATURE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&(XEDDSA_SIGNATURE_LEN as u16).to_be_bytes());
    bytes.extend_from_slice(&[fill; XEDDSA_SIGNATURE_LEN]);
    bytes.extend_from_slice(&(MLDSA_SIGNATURE_LEN as u16).to_be_bytes());
    bytes.extend_from_slice(&[fill ^ 0xff; MLDSA_SIGNATURE_LEN]);
    Box::new(HybridSignature::from_bytes(&bytes).expect("the fixture is well-formed"))
}
