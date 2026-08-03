//! The PQXDH `ikm` layout, byte for byte, recomputed from the raw primitives
//! (spec M1 §C.1, parent §4.1, §4.4).
//!
//! # Why this file exists
//!
//! Every other handshake test in this crate is **differential**. The `c1_*`
//! tests in `src/tests.rs` assert that the two ends *agree*, and that the OPK
//! and no-OPK paths *differ*. That proves the schedule is injective and that
//! both sides implement the same function. It cannot detect that the function
//! is the **wrong** one.
//!
//! An external review demonstrated the gap by swapping `DH1` and `DH2` in both
//! [`initiate`] and [`respond`] — a spec violation and an interop break, since
//! any second implementation would then derive a different `SK` — and the whole
//! `mlkb-protocol` suite still passed. Self-consistency is not correctness.
//! This is the same class of defect that `mlkb-crypto/tests/key_schedule_kat.rs`
//! was written to close one layer down, arriving one layer up.
//!
//! # How the expected answer is produced
//!
//! **Not by this workspace's key schedule.** Deriving the expectation with the
//! code that produced the observation is circular. Everything below is
//! recomputed from the primitives the spec names, through crates this library
//! does not use for it:
//!
//! - each `DH` leg by `x25519_dalek::StaticSecret::diffie_hellman`, not by
//!   `mlkb_crypto::x25519_dh`;
//! - `KEM_SS` by `ml_kem`'s `DecapsulationKey::decapsulate` on the FIPS-203
//!   `(d, z)` seed, not by `mlkb_crypto::KemDecapsulationKey::decapsulate`;
//! - `SK` by the `hkdf` crate's RFC 5869 Extract-then-Expand, not by
//!   `mlkb_crypto::derive_sk` (whose Expand is a hand-rolled loop, so even the
//!   expansion is a second implementation here).
//!
//! `mlkb-protocol` is used for exactly one thing: running the handshake whose
//! answer is under test.
//!
//! # How a root key with no accessor is observed
//!
//! `SK` never leaves `RootKey`. Its one public observable is
//! [`Session::session_id`], defined by parent §4.4 as
//! `HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)`. Two different `SK` values
//! produce two different session ids except with negligible probability, so
//! equality there is equality of `SK`, and that is what every assertion below
//! compares.
//!
//! # Sensitivity, which is the whole point
//!
//! A KAT that only ever asserts the *correct* layout matches proves nothing
//! about what it would reject. Every plausible mis-layout is therefore asserted
//! **not** to match — `F` omitted, doubled, trailing, or all-zero rather than
//! `0xFF * 32`; each adjacent pair of legs transposed; `KEM_SS` moved to the
//! front or dropped; `DH4` dropped when
//! an OPK was claimed; `DH4` zero-filled instead of omitted when one was not;
//! and the two identities transposed in `info`. Each of those is a real
//! implementation error someone could make, and each would break interop
//! silently. `the_six_ikm_components_are_pairwise_distinct` keeps the
//! transposition cases from passing vacuously.

// Tests may panic; the panic-free policy of spec parent §11 gate 7 is a
// property of library code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::convert::Infallible;

use hkdf::Hkdf;
use ml_kem::MlKem1024;
use ml_kem::array::Array;
use ml_kem::array::sizes::{U64, U1568};
use ml_kem::kem::{Decapsulate, KeyInit};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use mlkb_crypto::{
    HYBRID_SIGNATURE_VERSION, HybridSignature, KemCiphertext, KemDecapsulationKey,
    KemEncapsulationKey, KemSharedSecret, MLDSA_SIGNATURE_LEN, MlDsaSigningKey, X25519SecretKey,
    XEDDSA_SIGNATURE_LEN, sha256,
};
use mlkb_protocol::{Entropy, LocalIdentity, ResponderPrekeys, initiate, respond};
use mlkb_secrets::Nonce192;
use mlkb_wire::{
    EnrolmentProof, HybridIdentityPublic, IdentityId, OneTimePrekey, PrekeyBundleV2,
    SignedPqPrekey, SignedPrekey,
};

// ---------------------------------------------------------------------------
// the spec constants, spelled here rather than imported
// ---------------------------------------------------------------------------

/// `F`, the 32-byte prefix of the PQXDH `ikm` (spec parent §4.1, M1 §C.1).
///
/// Its job is to keep the `ikm` byte-space disjoint from a bare X25519 output,
/// exactly as X3DH's `F` does.
const F: [u8; 32] = [0xFF; 32];

/// The HKDF-Extract salt of the PQXDH derivation (spec parent §4.1).
const ZERO_SALT: [u8; 32] = [0x00; 32];

/// `"MLKEMBraid/pqxdh/v2"`, the prefix of the `SK` info string
/// (spec parent §4.1, §4.4).
///
/// Written as a literal on purpose: importing `mlkb_crypto::labels` would make
/// this oracle share a definition with the code it checks, and a mistyped label
/// would then agree with itself. `the_labels_pinned_here_are_the_registry_labels`
/// ties the two spellings together so the duplicate cannot drift in silence,
/// which is the failure mode M1 §I.2's one-home rule exists to prevent.
const SK_INFO_PREFIX: &[u8] = b"MLKEMBraid/pqxdh/v2";

/// `"MLKEMBraid/sid/v2"`, the `session_id` label (spec parent §4.4, §6.3).
/// See the note on [`SK_INFO_PREFIX`].
const SID_LABEL: &[u8] = b"MLKEMBraid/sid/v2";

/// The initiator ephemeral this file scripts, so that `DH2`, `DH3` and `DH4`
/// can be recomputed from outside.
const SCRIPTED_EK_A: [u8; 32] = [0x5A; 32];

// ---------------------------------------------------------------------------
// the second implementation
// ---------------------------------------------------------------------------

/// One X25519 shared secret, straight from `x25519-dalek`.
fn dh(secret: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    StaticSecret::from(*secret)
        .diffie_hellman(&PublicKey::from(*public))
        .to_bytes()
}

/// `SK = HKDF-SHA256(ikm, salt = 0x00*32, info = label || id_a || id_b, 32)`,
/// as RFC 5869 defines it (spec parent §4.1).
fn sk_from_ikm(ikm: &[u8], id_a: &[u8; 32], id_b: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&ZERO_SALT), ikm);
    let mut info = Vec::new();
    info.extend_from_slice(SK_INFO_PREFIX);
    info.extend_from_slice(id_a);
    info.extend_from_slice(id_b);
    let mut sk = [0u8; 32];
    hk.expand(&info, &mut sk).unwrap();
    sk
}

/// `session_id = HKDF-Expand(SK, "MLKEMBraid/sid/v2", 32)` (spec parent §4.4).
///
/// `SK` is already uniform, so this is expand-from-PRK (RFC 5869 §3.3) — the
/// same shape `RootKey::derive_session_id` uses, arrived at independently.
fn sid_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::from_prk(sk).unwrap();
    let mut sid = [0u8; 32];
    hk.expand(SID_LABEL, &mut sid).unwrap();
    sid
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/// splitmix64. Deterministic so a failing key reproduces, and confined to this
/// test binary so it can never be reached from a production constructor
/// (M1 §I.3).
struct DetRng(u64);

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

/// An [`Entropy`] that hands out a *known* X25519 ephemeral and records every
/// ML-KEM ciphertext it produced.
///
/// Both are needed to recompute the `ikm` from outside: the ephemeral gives
/// `DH2`, `DH3` and `DH4`, and the ciphertext gives `KEM_SS` when decapsulated
/// under the responder's PQ prekey seed. Nothing here weakens what the
/// handshake does — it is a real encapsulation against a real key — it only
/// makes the inputs observable.
struct SpyEntropy {
    rng: DetRng,
    /// Pre-seeded X25519 secrets, handed out in order, then random.
    scripted_x25519: Vec<[u8; 32]>,
    encapsulations: Vec<[u8; 1568]>,
}

impl SpyEntropy {
    fn scripted(seed: u64, secrets: Vec<[u8; 32]>) -> Self {
        Self {
            rng: DetRng::new(seed),
            scripted_x25519: secrets,
            encapsulations: Vec::new(),
        }
    }
}

impl Entropy for SpyEntropy {
    fn x25519_secret(&mut self) -> X25519SecretKey {
        if self.scripted_x25519.is_empty() {
            X25519SecretKey::random(&mut self.rng)
        } else {
            X25519SecretKey::from_bytes(self.scripted_x25519.remove(0))
        }
    }

    fn kem_keypair(&mut self) -> KemDecapsulationKey {
        KemDecapsulationKey::generate(&mut self.rng)
    }

    fn nonce(&mut self) -> Nonce192 {
        Nonce192::random(&mut self.rng)
    }

    fn encapsulate(&mut self, to: &KemEncapsulationKey) -> (KemCiphertext, KemSharedSecret) {
        let (ct, ss) = to.encapsulate(&mut self.rng);
        self.encapsulations.push(*ct.as_bytes());
        (ct, ss)
    }
}

const SPK_ID: u32 = 11;
const PQSPK_ID: u32 = 12;
const OPK_ID: u32 = 13;

/// One device, with every private key a handshake can need. Every prekey
/// signature below is genuine: [`initiate`] verifies the bundle before it
/// touches a key in it (parent §4.3), so a synthetic one would not get far
/// enough to derive anything.
struct Party {
    ik: X25519SecretKey,
    mldsa: MlDsaSigningKey,
    spk: X25519SecretKey,
    pqspk: KemDecapsulationKey,
    opk: X25519SecretKey,
    device_id: u32,
}

impl Party {
    fn generate(rng: &mut DetRng, device_id: u32) -> Self {
        Self {
            ik: X25519SecretKey::random(rng),
            mldsa: MlDsaSigningKey::generate(rng),
            spk: X25519SecretKey::random(rng),
            pqspk: KemDecapsulationKey::generate(rng),
            opk: X25519SecretKey::random(rng),
            device_id,
        }
    }

    fn identity(&self) -> LocalIdentity {
        LocalIdentity::new(
            X25519SecretKey::from_bytes(*self.ik.to_secret().expose_secret()),
            sha256(&[&self.mldsa.verifying_key().to_wire()]),
        )
    }

    fn id(&self) -> IdentityId {
        IdentityId::from_public_keys(
            self.ik.public_key().as_bytes(),
            &self.mldsa.verifying_key().to_wire(),
        )
    }

    fn prekeys(&self, with_opk: bool) -> ResponderPrekeys<'_> {
        ResponderPrekeys {
            device_id: self.device_id,
            spk: (SPK_ID, &self.spk),
            pqspk: (PQSPK_ID, &self.pqspk),
            opk: with_opk.then_some((OPK_ID, &self.opk)),
        }
    }

    fn bundle(&self, rng: &mut DetRng, with_opk: bool) -> PrekeyBundleV2 {
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
            // Not verified anywhere in `mlkb-protocol`: its issuer keys are
            // pinned in the client binary and the check is `mlkb-policy`'s
            // (M1 §F).
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
fn synthetic_signature(fill: u8) -> Box<HybridSignature> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&HYBRID_SIGNATURE_VERSION.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&(XEDDSA_SIGNATURE_LEN as u16).to_be_bytes());
    bytes.extend_from_slice(&[fill; XEDDSA_SIGNATURE_LEN]);
    bytes.extend_from_slice(&(MLDSA_SIGNATURE_LEN as u16).to_be_bytes());
    bytes.extend_from_slice(&[fill ^ 0xff; MLDSA_SIGNATURE_LEN]);
    Box::new(HybridSignature::from_bytes(&bytes).unwrap())
}

// ---------------------------------------------------------------------------
// one handshake, plus every input to it, from outside
// ---------------------------------------------------------------------------

/// A completed handshake together with the six `ikm` components as an outside
/// observer computes them.
struct Run {
    /// `Session::session_id()` as the initiator derived it.
    sid_initiator: [u8; 32],
    /// `Session::session_id()` as the responder derived it.
    sid_responder: [u8; 32],
    /// `DH1 = X25519(IK_A, SPK_B)` (spec M1 §C.1).
    dh1: [u8; 32],
    /// `DH2 = X25519(EK_A, IK_B)`.
    dh2: [u8; 32],
    /// `DH3 = X25519(EK_A, SPK_B)`.
    dh3: [u8; 32],
    /// `DH4 = X25519(EK_A, OPK_B)`, present iff an OPK was claimed.
    dh4: Option<[u8; 32]>,
    /// The ML-KEM-1024 shared secret, from raw decapsulation.
    kem_ss: [u8; 32],
    /// The initiator's `IdentityId`.
    id_a: [u8; 32],
    /// The responder's `IdentityId`.
    id_b: [u8; 32],
}

impl Run {
    /// The `session_id` that *would* follow from `ikm`, computed entirely
    /// outside this workspace's key schedule.
    fn sid_for(&self, ikm: &[u8]) -> [u8; 32] {
        sid_from_sk(&sk_from_ikm(ikm, &self.id_a, &self.id_b))
    }

    /// The M1 §C.1 layout: `F || DH1 || DH2 || DH3 [|| DH4] || KEM_SS`.
    fn spec_ikm(&self) -> Vec<u8> {
        match self.dh4.as_ref() {
            Some(dh4) => cat(&[&F, &self.dh1, &self.dh2, &self.dh3, dh4, &self.kem_ss]),
            None => cat(&[&F, &self.dh1, &self.dh2, &self.dh3, &self.kem_ss]),
        }
    }
}

fn run(with_opk: bool) -> Run {
    let mut rng = DetRng::new(0x0abc_0001);
    let alice = Party::generate(&mut rng, 1);
    let bob = Party::generate(&mut rng, 2);
    let bundle = bob.bundle(&mut rng, with_opk);

    let mut entropy = SpyEntropy::scripted(0xdead, vec![SCRIPTED_EK_A]);

    let initiated = initiate(&alice.identity(), &bundle, bob.device_id, 7, &mut entropy).unwrap();
    let wire = initiated.initial.to_wire();
    let accepted = respond(&bob.identity(), &bob.prekeys(with_opk), &wire)
        .unwrap()
        .complete()
        .unwrap();

    // Raw ML-KEM decapsulation of the ciphertext the handshake actually sent,
    // under the responder's FIPS-203 `(d, z)` seed. `mlkb_crypto::kem` is not
    // involved beyond handing over those 64 bytes.
    let ct = entropy.encapsulations[0];
    let seed = bob.pqspk.to_seed();
    let seed_bytes = seed.expose_secret();
    let dk =
        <ml_kem::DecapsulationKey<MlKem1024> as KeyInit>::new(&Array::<u8, U64>::from_fn(|i| {
            seed_bytes[i]
        }));
    let ss = dk.decapsulate(&Array::<u8, U1568>::from_fn(|i| ct[i]));
    let mut kem_ss = [0u8; 32];
    kem_ss.copy_from_slice(&ss);

    let ik_a = *alice.ik.to_secret().expose_secret();
    let spk_b_pub = *bob.spk.public_key().as_bytes();
    let ik_b_pub = *bob.ik.public_key().as_bytes();

    Run {
        sid_initiator: initiated.session.session_id(),
        sid_responder: accepted.session.session_id(),
        dh1: dh(&ik_a, &spk_b_pub),
        dh2: dh(&SCRIPTED_EK_A, &ik_b_pub),
        dh3: dh(&SCRIPTED_EK_A, &spk_b_pub),
        dh4: with_opk.then(|| dh(&SCRIPTED_EK_A, bob.opk.public_key().as_bytes())),
        kem_ss,
        id_a: *alice.id().as_bytes(),
        id_b: *bob.id().as_bytes(),
    }
}

// ---------------------------------------------------------------------------
// the known-answer tests
// ---------------------------------------------------------------------------

#[test]
fn ikm_is_exactly_f_dh1_dh2_dh3_dh4_kemss_when_an_opk_is_claimed() {
    let r = run(true);
    assert_eq!(
        r.sid_initiator, r.sid_responder,
        "the two ends disagree, so nothing below is meaningful"
    );
    assert!(r.dh4.is_some(), "the fixture claimed an OPK");

    assert_eq!(
        r.sid_for(&r.spec_ikm()),
        r.sid_initiator,
        "ikm is not F || DH1 || DH2 || DH3 || DH4 || KEM_SS (M1 §C.1)"
    );
}

#[test]
fn ikm_omits_dh4_entirely_when_no_opk_is_claimed() {
    let r = run(false);
    assert_eq!(r.sid_initiator, r.sid_responder);
    assert!(r.dh4.is_none(), "the fixture claimed no OPK");

    assert_eq!(
        r.sid_for(&r.spec_ikm()),
        r.sid_initiator,
        "ikm is not F || DH1 || DH2 || DH3 || KEM_SS (M1 §C.1)"
    );
}

/// M1 §C.1: the arity of the `ikm` follows `opk_id`. A 32-byte hole is not the
/// same string as no hole, and a schedule that filled one would interoperate
/// with nothing.
#[test]
fn the_no_opk_path_does_not_zero_fill_dh4() {
    let r = run(false);
    let zero_filled = r.sid_for(&cat(&[&F, &r.dh1, &r.dh2, &r.dh3, &[0u8; 32], &r.kem_ss]));
    assert_ne!(
        zero_filled, r.sid_initiator,
        "DH4 was zero-filled rather than omitted"
    );
}

/// Guards every transposition case below: if two components happened to be
/// equal, swapping them would produce the same `ikm` and the corresponding
/// `assert_ne!` would pass without testing anything.
#[test]
fn the_six_ikm_components_are_pairwise_distinct() {
    let r = run(true);
    let parts: [(&str, [u8; 32]); 6] = [
        ("F", F),
        ("DH1", r.dh1),
        ("DH2", r.dh2),
        ("DH3", r.dh3),
        ("DH4", r.dh4.unwrap()),
        ("KEM_SS", r.kem_ss),
    ];
    for (i, (na, a)) in parts.iter().enumerate() {
        assert_ne!(*a, [0u8; 32], "{na} is all-zero");
        for (nb, b) in parts.iter().skip(i + 1) {
            assert_ne!(a, b, "{na} and {nb} collide; the swap tests are vacuous");
        }
    }
}

/// The KAT above is only worth having if it rejects the mistakes it is meant
/// to catch. Each entry is a layout a reasonable implementer could have
/// written, and each must derive a *different* `SK`.
#[test]
fn the_kat_rejects_every_plausible_mislayout() {
    let r = run(true);
    let dh4 = r.dh4.unwrap();
    let good = r.sid_initiator;

    // Sanity: the correct layout does match, so an `assert_ne!` below failing
    // means the schedule accepts that variant, not that the oracle is broken.
    assert_eq!(r.sid_for(&r.spec_ikm()), good);

    let variants: Vec<(&str, Vec<u8>)> = vec![
        ("F omitted", cat(&[&r.dh1, &r.dh2, &r.dh3, &dh4, &r.kem_ss])),
        (
            "F doubled",
            cat(&[&F, &F, &r.dh1, &r.dh2, &r.dh3, &dh4, &r.kem_ss]),
        ),
        (
            "F trailing instead of leading",
            cat(&[&r.dh1, &r.dh2, &r.dh3, &dh4, &r.kem_ss, &F]),
        ),
        (
            "F all-zero instead of 0xFF*32",
            cat(&[&[0u8; 32], &r.dh1, &r.dh2, &r.dh3, &dh4, &r.kem_ss]),
        ),
        (
            "DH1 <-> DH2 swapped",
            cat(&[&F, &r.dh2, &r.dh1, &r.dh3, &dh4, &r.kem_ss]),
        ),
        (
            "DH2 <-> DH3 swapped",
            cat(&[&F, &r.dh1, &r.dh3, &r.dh2, &dh4, &r.kem_ss]),
        ),
        (
            "DH3 <-> DH4 swapped",
            cat(&[&F, &r.dh1, &r.dh2, &dh4, &r.dh3, &r.kem_ss]),
        ),
        (
            "KEM_SS first instead of last",
            cat(&[&F, &r.kem_ss, &r.dh1, &r.dh2, &r.dh3, &dh4]),
        ),
        ("KEM_SS omitted", cat(&[&F, &r.dh1, &r.dh2, &r.dh3, &dh4])),
        (
            "DH4 dropped though an OPK was claimed",
            cat(&[&F, &r.dh1, &r.dh2, &r.dh3, &r.kem_ss]),
        ),
    ];

    for (name, ikm) in variants {
        assert_ne!(
            r.sid_for(&ikm),
            good,
            "the mis-layout `{name}` derives the same SK, so this KAT would not catch it"
        );
    }
}

/// Parent §4.1: `info = label || IdentityId_A || IdentityId_B` with
/// **A = initiator, B = responder**. Transposing them is the difference
/// between two implementations that never agree.
#[test]
fn sk_info_binds_the_identities_initiator_then_responder() {
    let r = run(true);
    let ikm = r.spec_ikm();

    assert_eq!(r.sid_for(&ikm), r.sid_initiator);
    assert_ne!(
        r.id_a, r.id_b,
        "the two identities collide; the swap below is vacuous"
    );

    let swapped = sid_from_sk(&sk_from_ikm(&ikm, &r.id_b, &r.id_a));
    assert_ne!(
        swapped, r.sid_initiator,
        "the identity order in `info` is not bound"
    );
}

/// The two labels this file spells as literals are the registry's.
///
/// The literals above are deliberately not imported — an oracle that shared a
/// definition with the code under test would agree with a typo. This test is
/// what keeps that duplication honest: change `mlkb_crypto::labels` and the
/// duplicate is reported here rather than silently diverging (M1 §I.2).
#[test]
fn the_labels_pinned_here_are_the_registry_labels() {
    assert_eq!(SK_INFO_PREFIX, mlkb_crypto::labels::SK_INFO_PREFIX);
    assert_eq!(SID_LABEL, mlkb_crypto::labels::SESSION_ID);
}
