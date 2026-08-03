//! Absolute-byte known-answer tests for the whole key schedule and the whole
//! domain-separation registry (spec parent §4.1, §4.2, §4.4, §3.6; M1 §D.2,
//! §E.2, §G.5).
//!
//! # Why this file exists
//!
//! Every other test of the key schedule is *differential*: it asserts that
//! different inputs give different outputs. That proves each derivation is
//! injective. It cannot detect that the whole schedule is **shifted** — a
//! mistyped label, a swapped leg order, a missing `F` prefix, an
//! extract-where-the-spec-says-expand. Six wire-breaking mutations were
//! demonstrated that pass the entire differential suite.
//!
//! These bytes are what two independent implementations must agree on, so they
//! are pinned absolutely.
//!
//! # Where the expected values come from
//!
//! **Not from this crate.** Pinning what our own code currently emits is
//! circular. Every constant in `vectors/key_schedule_vectors.rs` is produced by
//! `vectors/generate.py`, which re-derives it from the specification text using
//! only the Python standard library — a from-scratch RFC 5869 HKDF, a
//! from-scratch RFC 7748 X25519, a from-scratch RFC 8439 / `XChaCha` AEAD, and
//! one line of FIPS 203 — each self-tested against that document's own
//! published vectors before a single project value is computed. That script
//! never reads the Rust.
//!
//! **If a test here fails, the Rust is wrong.** Do not adjust the vectors.
//!
//! # How a secret with no accessor is pinned
//!
//! `RootKey`, `FrameKey`, `ChainKey` and `MessageKey` deliberately expose no
//! bytes — `SK` never leaves its type. Each is therefore pinned through the one
//! public function that consumes it:
//!
//! - `RootKey` — by the complete set of §4.4 derivations over it:
//!   `derive_session_id`, `confirm_tag`, and both `derive_frame_key`
//!   directions. Four independent HKDF-Expand outputs of the same 32 bytes,
//!   under four different labels, agreeing with the oracle simultaneously is
//!   what pins `SK`; the oracle emits the root key itself as `SK_*` for a
//!   second implementation to check directly.
//! - `FrameKey` — by its HMAC over a fixed preimage.
//! - `ChainKey`/`MessageKey` — by opening a ciphertext the oracle produced. A
//!   wrong message key cannot authenticate it, so a successful open pins all 32
//!   bytes, and transitively the `CK` half of the root step.
//!
//! This is also why the tests live in `tests/` rather than in a `#[cfg(test)]`
//! module: they see exactly the public surface a second implementation would.

// Tests may panic; the panic-free policy of spec parent §11 gate 7 is a
// property of library code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    dead_code
)]

use mlkb_codec::{Value, encode_canonical};
use mlkb_crypto::{
    Aad, Ciphertext, DhLegs, DhOutput, FrameDirection, KEM_CIPHERTEXT_LEN, KemCiphertext,
    KemDecapsulationKey, KemSharedSecret, Prk, RootKey, SigContext, SkInfo, StoreKey,
    X25519PublicKey, X25519SecretKey, derive_sk, hmac_sha256, labels, signed_message, x25519_dh,
};
use mlkb_secrets::{Secret32, SecretBytes, WireNonce};

// The generated oracle output. Regenerate with
// `uv run python rust/crates/mlkb-crypto/tests/vectors/generate.py`.
include!("vectors/key_schedule_vectors.rs");

// ---------------------------------------------------------------------------
// The fixed inputs, spelled here and in `generate.py` and nowhere else
// ---------------------------------------------------------------------------

/// `IdentityId_A` (spec parent §3.5) — opaque 32 bytes to this crate.
const ID_A_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
/// `IdentityId_B`.
const ID_B_HEX: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

/// The ML-KEM-1024 decapsulation key seed `(d, z)` (spec M1 §I): bytes 0..64.
const KEM_SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                            202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

/// The 24-byte AEAD nonce (spec M1 §G.2): bytes 0..24.
const NONCE_HEX: &str = "000102030405060708090a0b0c0d0e0f1011121314151617";

const FRAME_PREIMAGE: &[u8] = b"MLKEMBraid/frame/v2|KAT|frame preimage";
const CONFIRM_PREIMAGE: &[u8] = b"canonical(InitialMessageV2 without confirm)|KAT";
const MK1_PLAINTEXT: &[u8] = b"KAT: the first message key of the first chain";
const MK2_PLAINTEXT: &[u8] = b"KAT: the second message key of the first chain";
const STORE_PLAINTEXT: &[u8] = b"KAT: a sealed value at rest";
const SIGNED_PAYLOAD: &[u8] = b"KAT payload";

/// The store master PRK the `K_store` vector is expanded from (spec M1 §G.5).
const STORE_MASTER_PRK: [u8; 32] = [0x5A; 32];

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::new();
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn unhex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(cleaned.len() % 2, 0, "odd-length hex");
    (0..cleaned.len() / 2)
        .map(|i| u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).expect("bad hex"))
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    let v = unhex(s);
    let mut out = [0u8; 32];
    assert_eq!(v.len(), 32, "expected 32 bytes");
    out.copy_from_slice(&v);
    out
}

fn arr24(s: &str) -> [u8; 24] {
    let v = unhex(s);
    let mut out = [0u8; 24];
    assert_eq!(v.len(), 24, "expected 24 bytes");
    out.copy_from_slice(&v);
    out
}

/// Whether a `RootKey`'s `SK` is the oracle's value.
///
/// A `RootKey` has no accessor for `SK` — deliberately, since one would hand
/// every downstream crate a permanent copy and defeat the forward-secrecy
/// rationale for `RootKey` not being `Clone`. `verify_sk_kat` is the
/// constant-time verifier that replaces it: a KAT can still pin `SK` exactly,
/// because checking a 32-byte candidate reveals nothing a caller did not
/// already hold.
fn root_is(rk: &RootKey, expected_hex: &str) -> bool {
    rk.verify_sk_kat(&arr32(expected_hex)).is_ok()
}

/// One X25519 leg, from a fixed private key and a fixed peer private key.
///
/// The peer's **public** key is checked against the oracle first, so an X25519
/// disagreement is reported as an X25519 disagreement rather than surfacing
/// later as a mysterious `SK` mismatch.
fn dh_leg(mine: u8, peer: u8, expected_peer_pub: &str) -> DhOutput {
    let peer_secret = X25519SecretKey::from_bytes([peer; 32]);
    let peer_public: X25519PublicKey = peer_secret.public_key();
    assert_eq!(
        hex(peer_public.as_bytes()),
        expected_peer_pub,
        "X25519 base-point multiplication disagrees with RFC 7748"
    );
    x25519_dh(&X25519SecretKey::from_bytes([mine; 32]), &peer_public)
        .expect("an honest peer key must pass the M1 §C.2 checks")
}

/// A `KemSharedSecret` with an independently known value.
///
/// FIPS 203 Algorithm 18: a ciphertext that fails the re-encryption check
/// decapsulates to `J(z || c) = SHAKE256(z || c, 32)` — the implicit-rejection
/// branch. `c` here is pseudo-random, so that branch is taken with
/// overwhelming probability, and the resulting 32 bytes are computable from one
/// line of the standard with no ML-KEM implementation at all. (`generate.py`
/// additionally cross-checks the value against `kyber-py`, an unrelated
/// pure-Python FIPS 203 implementation.)
fn kem_ss(ciphertext_hex: &str) -> KemSharedSecret {
    let seed = unhex(KEM_SEED_HEX);
    let mut seed64 = [0u8; 64];
    assert_eq!(seed.len(), 64);
    seed64.copy_from_slice(&seed);

    let ct_bytes = unhex(ciphertext_hex);
    assert_eq!(ct_bytes.len(), KEM_CIPHERTEXT_LEN);
    let mut ct = [0u8; KEM_CIPHERTEXT_LEN];
    ct.copy_from_slice(&ct_bytes);

    KemDecapsulationKey::from_seed(&SecretBytes::<64>::new(seed64))
        .decapsulate(&KemCiphertext::from_wire(ct))
}

/// The four PQXDH legs, in spec parent §4.1 order.
fn legs() -> [DhOutput; 4] {
    [
        dh_leg(1, 0x11, PEER_PUB_1),
        dh_leg(2, 0x12, PEER_PUB_2),
        dh_leg(3, 0x13, PEER_PUB_3),
        dh_leg(4, 0x14, PEER_PUB_4),
    ]
}

fn info() -> SkInfo {
    SkInfo::new(&arr32(ID_A_HEX), &arr32(ID_B_HEX))
}

/// `SK` for the four-leg run — the root key every §4.4 vector expands from.
fn sk_four_leg() -> RootKey {
    let [l1, l2, l3, l4] = legs();
    derive_sk(
        DhLegs::with_opk(l1, l2, l3, l4),
        kem_ss(KEM_CT_PQXDH),
        &info(),
    )
}

// ===========================================================================
// 1. The label registry — literal bytes, checked against the spec documents
// ===========================================================================
//
// docs/specs/2026-07-31-rust-rewrite-spec.md §4.1, §4.2, §4.4, §3.6
// docs/specs/2026-08-01-m1-normative-resolutions.md §D.2, §E.2, §G.5
//
// Encoding, stated once by M1 §E.2 for the whole project: the literal ASCII
// bytes, with NO terminator and NO length prefix. The one embedded NUL in
// `XEDDSA_DOMAIN` is part of the literal.

/// Every HKDF label, byte for byte.
#[test]
fn every_hkdf_label_is_the_exact_string_the_spec_prints() {
    // parent §4.1: info = "MLKEMBraid/pqxdh/v2" || IdentityId_A || IdentityId_B
    assert_eq!(labels::SK_INFO_PREFIX, b"MLKEMBraid/pqxdh/v2");
    // parent §4.4 table
    assert_eq!(labels::FRAME_I2R, b"MLKEMBraid/frame/i2r/v2");
    assert_eq!(labels::FRAME_R2I, b"MLKEMBraid/frame/r2i/v2");
    assert_eq!(labels::PQXDH_CONFIRM, b"MLKEMBraid/pqxdh/confirm/v2");
    assert_eq!(labels::SESSION_ID, b"MLKEMBraid/sid/v2");
    assert_eq!(labels::ERASURE_CHUNK, b"MLKEMBraid/erasure-chunk/v2");
    // M1 §D.2
    assert_eq!(labels::RATCHET_ROOT, b"MLKEMBraid/ratchet/root/v2");
    // M1 §G.5 / §J row 9. NOTE: neither section spells this string — the
    // registry fixes it. It is pinned here so it cannot drift silently, but
    // unlike the others it is an implementation decision, not a spec quotation.
    assert_eq!(labels::K_STORE, b"MLKEMBraid/store/v2");
}

/// The labels again as hex, so a homoglyph or a stray byte cannot hide inside
/// a string literal that merely *looks* right in both places.
#[test]
fn every_hkdf_label_has_the_exact_bytes_the_spec_prints() {
    assert_eq!(
        hex(labels::SK_INFO_PREFIX),
        "4d4c4b454d42726169642f70717864682f7632"
    );
    assert_eq!(
        hex(labels::FRAME_I2R),
        "4d4c4b454d42726169642f6672616d652f6932722f7632"
    );
    assert_eq!(
        hex(labels::FRAME_R2I),
        "4d4c4b454d42726169642f6672616d652f7232692f7632"
    );
    assert_eq!(
        hex(labels::PQXDH_CONFIRM),
        "4d4c4b454d42726169642f70717864682f636f6e6669726d2f7632"
    );
    assert_eq!(
        hex(labels::SESSION_ID),
        "4d4c4b454d42726169642f7369642f7632"
    );
    assert_eq!(
        hex(labels::ERASURE_CHUNK),
        "4d4c4b454d42726169642f657261737572652d6368756e6b2f7632"
    );
    assert_eq!(
        hex(labels::RATCHET_ROOT),
        "4d4c4b454d42726169642f726174636865742f726f6f742f7632"
    );
    assert_eq!(
        hex(labels::K_STORE),
        "4d4c4b454d42726169642f73746f72652f7632"
    );
}

/// The signature-context registry (M1 §E.2) and the framed domain tag
/// (parent §3.6), byte for byte.
#[test]
fn every_signature_context_is_the_exact_string_the_spec_prints() {
    assert_eq!(labels::CTX_SPK, b"MLKEMBraid/ctx/spk/v2");
    assert_eq!(labels::CTX_PQSPK, b"MLKEMBraid/ctx/pqspk/v2");
    assert_eq!(labels::CTX_ENROLMENT, b"MLKEMBraid/ctx/enrolment/v2");
    assert_eq!(
        hex(labels::CTX_SPK),
        "4d4c4b454d42726169642f6374782f73706b2f7632"
    );
    assert_eq!(
        hex(labels::CTX_PQSPK),
        "4d4c4b454d42726169642f6374782f707173706b2f7632"
    );
    assert_eq!(
        hex(labels::CTX_ENROLMENT),
        "4d4c4b454d42726169642f6374782f656e726f6c6d656e742f7632"
    );

    // parent §3.6 / M1 §E.2: the trailing NUL is part of the literal.
    assert_eq!(labels::XEDDSA_DOMAIN, b"MLKEMBraid/xeddsa/v2\x00");
    assert_eq!(labels::XEDDSA_DOMAIN.len(), 21);
    assert_eq!(labels::XEDDSA_DOMAIN[20], 0x00);
    assert_eq!(
        hex(labels::XEDDSA_DOMAIN),
        "4d4c4b454d42726169642f7865646473612f763200"
    );

    // The enum is the only way to spell a context, so it must map onto the
    // registry and onto nothing else (M1 §E.2).
    assert_eq!(
        SigContext::SignedPrekey.as_bytes(),
        b"MLKEMBraid/ctx/spk/v2"
    );
    assert_eq!(
        SigContext::PqSignedPrekey.as_bytes(),
        b"MLKEMBraid/ctx/pqspk/v2"
    );
    assert_eq!(
        SigContext::Enrolment.as_bytes(),
        b"MLKEMBraid/ctx/enrolment/v2"
    );
    assert_eq!(SigContext::ALL.len(), 3, "M1 §E.2 is a closed set of three");
}

/// The registry is closed at twelve labels.
///
/// This cannot be enforced from outside the crate — `labels::ALL_LABELS` is
/// `cfg(test)`-private — so it is recorded instead: a thirteenth label means
/// this file, `generate.py` and the spec table all need an entry, and this
/// assertion is where a reviewer is told so.
#[test]
fn the_registry_this_file_pins_is_the_whole_registry() {
    let pinned: [&[u8]; 12] = [
        labels::SK_INFO_PREFIX,
        labels::FRAME_I2R,
        labels::FRAME_R2I,
        labels::PQXDH_CONFIRM,
        labels::SESSION_ID,
        labels::ERASURE_CHUNK,
        labels::RATCHET_ROOT,
        labels::K_STORE,
        labels::XEDDSA_DOMAIN,
        labels::CTX_SPK,
        labels::CTX_PQSPK,
        labels::CTX_ENROLMENT,
    ];
    assert_eq!(pinned.len(), 12);
    for (i, a) in pinned.iter().enumerate() {
        for b in pinned.iter().skip(i + 1) {
            assert_ne!(a, b);
        }
    }
}

// ===========================================================================
// 2. parent §3.6 / M1 §E.2 — the framed signing input, absolute bytes
// ===========================================================================

/// `signed_msg = "MLKEMBraid/xeddsa/v2\x00" || u16(len(ctx)) || ctx
///            || IdentityId || payload`
#[test]
fn the_framed_signing_input_matches_the_oracle_byte_for_byte() {
    let identity = arr32(ID_A_HEX);
    for (ctx, expected) in [
        (SigContext::SignedPrekey, SIGNED_MSG_SPK),
        (SigContext::PqSignedPrekey, SIGNED_MSG_PQSPK),
        (SigContext::Enrolment, SIGNED_MSG_ENROLMENT),
    ] {
        let got = signed_message(ctx, &identity, SIGNED_PAYLOAD);
        assert_eq!(hex(&got), expected, "framed signing input for {ctx:?}");
    }
}

// ===========================================================================
// 3. parent §4.1 — `derive_sk`, three legs and four
// ===========================================================================

/// ```text
/// ikm  = F || DH1 || DH2 || DH3 || KEM_SS          F = 0xFF * 32
/// salt = 0x00 * 32
/// info = "MLKEMBraid/pqxdh/v2" || IdentityId_A || IdentityId_B
/// len  = 32
/// ```
#[test]
fn derive_sk_three_legs_matches_the_oracle() {
    let [l1, l2, l3, _] = legs();
    let sk = derive_sk(
        DhLegs::without_opk(l1, l2, l3),
        kem_ss(KEM_CT_PQXDH),
        &info(),
    );
    assert!(
        root_is(&sk, SK_THREE_LEG),
        "three-leg SK is not the oracle's"
    );
    // And every §4.4 derivation over it, so a failure says *which* derivation
    // moved rather than only that something did.
    assert_table(&sk, THREE_LEG_TABLE);
}

/// The four §4.4 / §4.2 derivations of one `RootKey`, in the order
/// [`assert_table`] takes them: `session_id`, confirm, frame i2r, frame r2i.
type DerivationTable = [&'static str; 4];

const THREE_LEG_TABLE: DerivationTable = [
    THREE_LEG_SESSION_ID,
    THREE_LEG_CONFIRM_TAG,
    THREE_LEG_FRAME_MAC_I2R,
    THREE_LEG_FRAME_MAC_R2I,
];
const FOUR_LEG_TABLE: DerivationTable = [
    FOUR_LEG_SESSION_ID,
    FOUR_LEG_CONFIRM_TAG,
    FOUR_LEG_FRAME_MAC_I2R,
    FOUR_LEG_FRAME_MAC_R2I,
];
const RATCHET_RK1_TABLE: DerivationTable = [
    RATCHET_RK1_SESSION_ID,
    RATCHET_RK1_CONFIRM_TAG,
    RATCHET_RK1_FRAME_MAC_I2R,
    RATCHET_RK1_FRAME_MAC_R2I,
];

/// Every derivation spec parent §4.4 and §4.2 define over a root key, against
/// the oracle.
///
/// Frame keys have no accessor, so each is pinned by its HMAC over
/// [`FRAME_PREIMAGE`]; `k_cf` likewise never leaves `confirm_tag`.
fn assert_table(rk: &RootKey, expected: DerivationTable) {
    assert_eq!(hex(&rk.derive_session_id()), expected[0], "session_id");
    assert_eq!(
        hex(rk.confirm_tag(CONFIRM_PREIMAGE).as_bytes()),
        expected[1],
        "confirm tag"
    );
    assert_eq!(
        hex(rk
            .derive_frame_key(FrameDirection::InitiatorToResponder)
            .mac(FRAME_PREIMAGE)
            .as_bytes()),
        expected[2],
        "K_frame_i2r"
    );
    assert_eq!(
        hex(rk
            .derive_frame_key(FrameDirection::ResponderToInitiator)
            .mac(FRAME_PREIMAGE)
            .as_bytes()),
        expected[3],
        "K_frame_r2i"
    );
}

/// The four-leg form. `DH4` is concatenated into `ikm`; it is never
/// zero-filled, and the two shapes carry no length prefix, which is exactly why
/// their absolute values have to be pinned separately.
#[test]
fn derive_sk_four_legs_matches_the_oracle() {
    let sk = sk_four_leg();
    assert!(root_is(&sk, SK_FOUR_LEG), "four-leg SK is not the oracle's");
    assert_table(&sk, FOUR_LEG_TABLE);
}

/// The two shapes are genuinely different key schedules, at absolute values.
#[test]
fn the_three_and_four_leg_schedules_are_different_absolute_keys() {
    assert_ne!(SK_THREE_LEG, SK_FOUR_LEG);
}

// ===========================================================================
// 4. parent §4.4 — the label table, expanded from `SK`
// ===========================================================================

// The four derivations themselves are asserted by `assert_table` above, once
// per root key. What follows is what that helper cannot say.

/// `K_frame_i2r` and `K_frame_r2i` are not merely different — each is the
/// *specific* key the spec's label names. Swapping the two labels in
/// `labels.rs` is a wire break that every differential test accepts, and it
/// changes both pinned MACs.
#[test]
fn the_two_frame_directions_are_not_interchangeable() {
    assert_ne!(FOUR_LEG_FRAME_MAC_I2R, FOUR_LEG_FRAME_MAC_R2I);
    assert_ne!(THREE_LEG_FRAME_MAC_I2R, THREE_LEG_FRAME_MAC_R2I);
}

/// No two labels in the §4.4 table expand the same root key to the same bytes.
#[test]
fn the_four_derivations_of_one_root_key_are_four_different_values() {
    for table in [THREE_LEG_TABLE, FOUR_LEG_TABLE, RATCHET_RK1_TABLE] {
        for (i, a) in table.iter().enumerate() {
            for b in table.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}

/// The tag the wire carries verifies against the pinned bytes, so the *verify*
/// path is pinned and not only the compute path (spec parent §4.2).
#[test]
fn a_pinned_confirmation_tag_verifies() {
    use mlkb_crypto::Mac256;
    let received = Mac256::from_bytes(arr32(FOUR_LEG_CONFIRM_TAG));
    assert_eq!(
        sk_four_leg().verify_confirm_tag(CONFIRM_PREIMAGE, &received),
        Ok(())
    );
    // A tag from the *three*-leg session does not verify under the four-leg
    // one: the two sessions are different absolute keys, not merely unequal.
    let foreign = Mac256::from_bytes(arr32(THREE_LEG_CONFIRM_TAG));
    assert_eq!(
        sk_four_leg().verify_confirm_tag(CONFIRM_PREIMAGE, &foreign),
        Err(mlkb_secrets::ProtocolError::Unauthenticated)
    );
}

// ===========================================================================
// 5. M1 §D.2 — the hybrid root step and the chain step
// ===========================================================================

/// ```text
/// (RK', CK) = HKDF-SHA256(ikm  = dh_out || kem_ss,
///                         salt = RK,
///                         info = "MLKEMBraid/ratchet/root/v2",
///                         len  = 64)          split 32 || 32
/// ```
///
/// The `RK'` half is pinned directly here; the `CK` half is pinned by the
/// chain-step tests below, which can only pass if this `CK` is byte-exact.
#[test]
fn the_hybrid_root_step_matches_the_oracle() {
    let dh = dh_leg(5, 0x15, PEER_PUB_RATCHET);
    let (rk1, _ck) = sk_four_leg().ratchet(dh, kem_ss(KEM_CT_RATCHET));
    assert!(root_is(&rk1, RATCHET_RK1), "RK' is not the oracle's");
    // `RK'` is a root key like any other, so the whole §4.4 table over it is
    // pinned too — that is what rules out a 32-byte offset in the 64-byte OKM
    // split, which every differential test accepts.
    assert_table(&rk1, RATCHET_RK1_TABLE);
}

/// `MK = HMAC-SHA256(CK, 0x01)`, pinned absolutely.
///
/// A `MessageKey` has no byte accessor, so the pin is an AEAD open: the
/// ciphertext was produced by the oracle under the oracle's `MK`, and
/// XChaCha20-Poly1305 authenticates, so it opens under this key only if all 32
/// bytes agree. That transitively pins the `CK` half of the root step as well.
#[test]
fn the_first_message_key_of_the_first_chain_matches_the_oracle() {
    let aad = encode_canonical(&Value::uint(0)).unwrap();
    assert_eq!(
        aad.as_bytes(),
        &[0x00],
        "the oracle assumes this AAD encodes to the single byte 0x00"
    );

    let dh = dh_leg(5, 0x15, PEER_PUB_RATCHET);
    let (_rk1, ck0) = sk_four_leg().ratchet(dh, kem_ss(KEM_CT_RATCHET));
    let (_ck1, mk1) = ck0.step();

    let opened = mk1
        .open(
            &WireNonce::from_bytes(arr24(NONCE_HEX)),
            &Ciphertext::from_wire(unhex(MK1_CIPHERTEXT)),
            Aad::new(&aad),
        )
        .expect("MK1 disagrees with the oracle: the chain step or the root step is wrong");
    assert_eq!(opened.as_slice(), MK1_PLAINTEXT);
}

/// `CK' = HMAC-SHA256(CK, 0x02)`, pinned absolutely — by taking a *second*
/// step, which is reachable only if `CK'` itself is byte-exact.
#[test]
fn the_second_message_key_of_the_first_chain_matches_the_oracle() {
    let aad = encode_canonical(&Value::uint(0)).unwrap();
    let dh = dh_leg(5, 0x15, PEER_PUB_RATCHET);
    let (_rk1, ck0) = sk_four_leg().ratchet(dh, kem_ss(KEM_CT_RATCHET));
    let (ck1, _mk1) = ck0.step();
    let (_ck2, mk2) = ck1.step();

    let opened = mk2
        .open(
            &WireNonce::from_bytes(arr24(NONCE_HEX)),
            &Ciphertext::from_wire(unhex(MK2_CIPHERTEXT)),
            Aad::new(&aad),
        )
        .expect("MK2 disagrees with the oracle: CK' = HMAC(CK, 0x02) is wrong");
    assert_eq!(opened.as_slice(), MK2_PLAINTEXT);
}

/// The oracle's own chain arithmetic, re-checked against this crate's HMAC.
///
/// Every value in this assertion comes from `generate.py`; the only thing the
/// Rust supplies is `hmac_sha256`, which carries RFC 4231 known-answer tests of
/// its own. It is what tells a reader that `RATCHET_CK0`, `CHAIN_MK1` and
/// `CHAIN_CK1` are consistent, and it localises a failure of the two tests
/// above to the root step rather than to the chain step.
#[test]
fn the_pinned_chain_values_are_consistent_under_hmac() {
    let ck0 = arr32(RATCHET_CK0);
    assert_eq!(hex(hmac_sha256(&ck0, &[&[0x01]]).as_bytes()), CHAIN_MK1);
    assert_eq!(hex(hmac_sha256(&ck0, &[&[0x02]]).as_bytes()), CHAIN_CK1);
    let ck1 = arr32(CHAIN_CK1);
    assert_eq!(hex(hmac_sha256(&ck1, &[&[0x01]]).as_bytes()), CHAIN_MK2);
    assert_eq!(hex(hmac_sha256(&ck1, &[&[0x02]]).as_bytes()), CHAIN_CK2);
}

// ===========================================================================
// 6. M1 §G.5 — `K_store`, which also anchors the AEAD used above
// ===========================================================================

/// `K_store = HKDF-Expand(prk, "MLKEMBraid/store/v2", 32)`.
///
/// This test is deliberately independent of the whole PQXDH schedule: it starts
/// from a literal PRK. If it passes while the message-key tests fail, the
/// oracle's HKDF-Expand and its AEAD are both sound and the fault is in the key
/// schedule; if it fails too, suspect the AEAD first.
#[test]
fn the_store_key_matches_the_oracle() {
    let aad = encode_canonical(&Value::uint(0)).unwrap();
    let key = StoreKey::derive(&Prk::from_secret(&Secret32::new(STORE_MASTER_PRK)));
    let opened = key
        .open_at_rest(
            &WireNonce::from_bytes(arr24(NONCE_HEX)),
            &Ciphertext::from_wire(unhex(STORE_CIPHERTEXT)),
            Aad::new(&aad),
        )
        .expect("K_store disagrees with the oracle");
    assert_eq!(opened.as_slice(), STORE_PLAINTEXT);
}

// ===========================================================================
// 7. Guards on the inputs themselves
// ===========================================================================

/// The fixed inputs really are what `generate.py` says they are.
///
/// A KAT is only as good as its inputs: if the peer public keys or the ML-KEM
/// ciphertexts drifted, every vector above would still be self-consistent and
/// still be wrong.
#[test]
fn the_fixed_inputs_are_the_ones_the_oracle_used() {
    assert_eq!(unhex(KEM_CT_PQXDH).len(), KEM_CIPHERTEXT_LEN);
    assert_eq!(unhex(KEM_CT_RATCHET).len(), KEM_CIPHERTEXT_LEN);
    assert_ne!(KEM_CT_PQXDH, KEM_CT_RATCHET);
    assert_eq!(unhex(ID_A_HEX).len(), 32);
    assert_eq!(unhex(ID_B_HEX).len(), 32);
    assert_ne!(ID_A_HEX, ID_B_HEX);
    assert_eq!(unhex(NONCE_HEX).len(), 24);

    // Each peer public key is a real X25519 base-point multiple, and `x25519_dh`
    // accepts it (spec M1 §C.2 — the checks are not vacuous on these inputs).
    let _ = legs();
    let _ = dh_leg(5, 0x15, PEER_PUB_RATCHET);
}

/// `SkInfo` binds initiator-then-responder. Reversing the identities is a
/// different absolute key, not merely a different one — pinned so that a
/// swapped ordering in `derive_sk` cannot pass.
#[test]
fn reversing_the_identity_order_does_not_reach_the_pinned_key() {
    let [l1, l2, l3, l4] = legs();
    let reversed = derive_sk(
        DhLegs::with_opk(l1, l2, l3, l4),
        kem_ss(KEM_CT_PQXDH),
        &SkInfo::new(&arr32(ID_B_HEX), &arr32(ID_A_HEX)),
    );
    assert!(!root_is(&reversed, SK_FOUR_LEG));
}

/// Leg order is load-bearing at absolute values: the pinned `SK` is reachable
/// only with the legs in spec parent §4.1's order.
#[test]
fn permuting_the_legs_does_not_reach_the_pinned_key() {
    let [l1, l2, l3, l4] = legs();
    let swapped = derive_sk(
        DhLegs::with_opk(l2, l1, l3, l4),
        kem_ss(KEM_CT_PQXDH),
        &info(),
    );
    assert!(!root_is(&swapped, SK_FOUR_LEG));
}
