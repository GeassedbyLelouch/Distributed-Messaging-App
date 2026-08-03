//! Test-only fixtures. Compiled under `cfg(test)` and never shipped.
//!
//! This is deliberately *not* `mlkb-testkit`: nothing here is reachable from a
//! production constructor, because the module does not exist outside a test
//! build (M1 §I.3, and the `client/anonymous_transport.py:30-35` defect class
//! it names).
//!
//! # Why the signatures here are synthetic
//!
//! `HybridSignature::from_bytes` is the M1 §E.1 parser, and it is the only
//! thing this crate does with a signature: `mlkb-wire` parses, `mlkb-protocol`
//! verifies. The fixtures therefore build *well-formed* signature bytes rather
//! than signing anything, which keeps the wire tests free of an ML-DSA keygen
//! and makes what they cover unambiguous — the layout, not the cryptography.
//!
//! A `FrameKey` cannot be faked the same way: it has no public constructor and
//! is reachable only through `derive_sk`, which consumes a real
//! `KemSharedSecret`. So the fixture performs an actual ML-KEM encapsulation,
//! driven by a deterministic RNG so that a failure reproduces.

#![allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    // Fixture code: the two casts below are a 64→32 bit RNG narrowing and two
    // compile-time constants that are 64 and 3309.
    clippy::cast_possible_truncation
)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::convert::Infallible;

use mlkb_crypto::{
    DhLegs, FrameDirection, FrameKey, HYBRID_SIGNATURE_VERSION, HybridSignature,
    KEM_CIPHERTEXT_LEN, KEM_ENCAPSULATION_KEY_LEN, KemDecapsulationKey, MLDSA_SIGNATURE_LEN,
    MLDSA_VERIFYING_KEY_LEN, RootKey, SkInfo, X25519SecretKey, XEDDSA_SIGNATURE_LEN, derive_sk,
    x25519_dh,
};
use mlkb_secrets::WireNonce;

use crate::bundle::{
    HybridIdentityPublic, OneTimePrekey, PrekeyBundleV2, SignedPqPrekey, SignedPrekey,
};
use crate::enrolment::EnrolmentProof;
use crate::identity::IdentityId;
use crate::initial::InitialMessageV2;
use crate::ratchet::RatchetStep;

// ---------------------------------------------------------------------------
// a deterministic RNG
// ---------------------------------------------------------------------------

/// splitmix64. Deterministic so that a failing key is reproducible, and
/// test-only so it can never be reached from a production constructor
/// (M1 §I.3).
pub(crate) struct DetRng(u64);

impl DetRng {
    fn new(seed: u64) -> Self {
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

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

/// One deterministic PQXDH root key, so that the two frame keys below are the
/// two *directions* of the same session rather than two unrelated secrets.
fn root_key() -> RootKey {
    let mut rng = DetRng::new(0x0a11_ce0b_0b00);
    let peer = X25519SecretKey::random(&mut rng);
    let peer_pub = peer.public_key();
    let mut leg = || {
        let s = X25519SecretKey::random(&mut rng);
        x25519_dh(&s, &peer_pub).expect("a fresh keypair is contributory")
    };
    let legs = DhLegs::without_opk(leg(), leg(), leg());

    let dk = KemDecapsulationKey::generate(&mut rng);
    let (_ct, ss) = dk.encapsulation_key().encapsulate(&mut rng);

    derive_sk(legs, ss, &SkInfo::new(&[0x11; 32], &[0x22; 32]))
}

/// The initiator→responder frame key.
pub(crate) fn test_frame_key() -> FrameKey {
    root_key().derive_frame_key(FrameDirection::InitiatorToResponder)
}

/// The responder→initiator frame key of the **same** session (parent §4.4).
pub(crate) fn other_frame_key() -> FrameKey {
    root_key().derive_frame_key(FrameDirection::ResponderToInitiator)
}

// ---------------------------------------------------------------------------
// wire fixtures
// ---------------------------------------------------------------------------

/// A well-formed `HybridSignature` (spec M1 §E.1) — correct version, suite and
/// length prefixes, arbitrary signature bytes.
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

/// A 24-byte received nonce.
pub(crate) fn wire_nonce(fill: u8) -> WireNonce {
    WireNonce::from_bytes([fill; 24])
}

/// The `"ek"`/`"kc"` pair of a chain-opening `RatchetMessage`.
pub(crate) fn sample_step() -> RatchetStep {
    RatchetStep {
        ek: Box::new([0x33; KEM_ENCAPSULATION_KEY_LEN]),
        kc: Box::new([0x44; KEM_CIPHERTEXT_LEN]),
    }
}

/// An `InitialMessageV2`, with or without a claimed one-time prekey.
pub(crate) fn sample_initial(opk_id: Option<u32>) -> InitialMessageV2 {
    InitialMessageV2 {
        to_device_id: 0x0102_0304,
        handshake_seq: 0x0506_0708_090a_0b0c,
        ik_x25519: [0x01; 32],
        ik_mldsa_hash: [0x02; 32],
        ek_x25519: [0x03; 32],
        kem_ct: Box::new([0x04; KEM_CIPHERTEXT_LEN]),
        spk_id: 7,
        pqspk_id: 8,
        opk_id,
        confirm: [0x05; 32],
    }
}

/// An `EnrolmentProof`.
pub(crate) fn sample_enrolment() -> EnrolmentProof {
    EnrolmentProof {
        issuer_epoch: 12,
        issuer_key_id: 3,
        not_after_ms: 1_700_000_000_000,
        subject: IdentityId::from_bytes([0x77; 32]),
        tier: 1,
        signature: synthetic_signature(0x10),
    }
}

/// A `PrekeyBundleV2`, with or without a one-time prekey.
pub(crate) fn sample_bundle(with_opk: bool) -> PrekeyBundleV2 {
    PrekeyBundleV2 {
        identity: HybridIdentityPublic {
            ik_x25519: [0x0a; 32],
            ik_mldsa: Box::new([0x0b; MLDSA_VERIFYING_KEY_LEN]),
        },
        signed_prekey: SignedPrekey {
            id: 11,
            public: [0x0c; 32],
            signature: synthetic_signature(0x20),
        },
        pq_prekey: SignedPqPrekey {
            id: 12,
            ek: Box::new([0x0d; KEM_ENCAPSULATION_KEY_LEN]),
            signature: synthetic_signature(0x30),
        },
        one_time: with_opk.then_some(OneTimePrekey {
            id: 13,
            public: [0x0e; 32],
        }),
        enrolment: sample_enrolment(),
        expires_at_ms: 1_800_000_000_000,
    }
}

// ---------------------------------------------------------------------------
// hostile inputs, applied to every CBOR structure
// ---------------------------------------------------------------------------

/// The corruptions every payload decoder in this crate must refuse.
///
/// One list, applied to each structure, so that adding a structure without the
/// hostile-input tests is not possible by accident:
///
/// - **empty**, **truncated by one byte**, **extended by one byte** — the
///   three shapes parent §11 gate 3 fuzzes;
/// - **a length prefix claiming a huge size** — the allocation-hint attack of
///   M1 §A.1 rule 2, in two forms (a byte string and a map). The measured
///   memory cost is in `tests/alloc_amplification.rs`; here the assertion is
///   just that they are refused;
/// - **a non-canonical map head** — the same value re-encoded with a
///   non-shortest length. M1 §B.4 requires that this be *rejected*, not
///   normalized, and it is the cheapest input that proves the round-trip check
///   is actually running.
pub(crate) fn corrupt_cases(good: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut cases = Vec::new();

    cases.push(("empty", Vec::new()));
    cases.push((
        "truncated by one byte",
        good[..good.len().saturating_sub(1)].to_vec(),
    ));
    cases.push(("extended by one byte", {
        let mut v = good.to_vec();
        v.push(0x00);
        v
    }));

    // {"ct": bstr(2^64 - 1)} — a huge declared length with nothing behind it.
    cases.push(("huge byte-string length", {
        let mut v = vec![0xa1, 0x62, b'c', b't', 0x5b];
        v.extend_from_slice(&u64::MAX.to_be_bytes());
        v
    }));
    // map(2^64 - 1)
    cases.push(("huge map length", {
        let mut v = vec![0xbb];
        v.extend_from_slice(&u64::MAX.to_be_bytes());
        v
    }));
    // array(2^64 - 1) where a map belongs
    cases.push(("huge array length", {
        let mut v = vec![0x9b];
        v.extend_from_slice(&u64::MAX.to_be_bytes());
        v
    }));

    // The top-level map head, re-encoded in a longer form. Same value, so a
    // normalizing decoder would accept it.
    let head = good.first().copied().unwrap_or(0);
    assert_eq!(head >> 5, 5, "the fixture is a CBOR map");
    let pairs = head & 0x1f;
    assert!(pairs <= 23, "the fixture's head is the one-byte form");
    cases.push(("non-canonical map head", {
        let mut v = vec![0xb8, pairs];
        v.extend_from_slice(&good[1..]);
        v
    }));

    cases
}
