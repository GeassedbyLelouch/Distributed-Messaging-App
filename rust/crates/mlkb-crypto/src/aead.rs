//! XChaCha20-Poly1305, the one AEAD (spec parent §5.1, §8.3, M1 §G.2, §G.3,
//! §G.5).
//!
//! # The three properties this module is built to hold
//!
//! 1. **The nonce is injected, never generated here** (spec M1 §G.2). There is
//!    no RNG in this module and no way to reach one: [`MessageKey::seal`] takes
//!    a [`Nonce192`], which is mintable only by `Nonce192::random`, and
//!    [`MessageKey::open`] takes a [`WireNonce`], which is mintable only by the
//!    decoder. The two types do not convert into one another, so the sealing
//!    side cannot be handed an attacker-chosen nonce.
//!
//! 2. **A key seals once** (spec parent §8.3). [`MessageKey::seal`] and
//!    [`MessageKey::open`] both consume `self`, so a second use of one message
//!    key is a compile error rather than a review comment. Spec parent §5.2
//!    covers the remaining case — a *process restart* that re-derives the same
//!    key — and is why the nonce is random rather than a counter.
//!
//!    Read that as bounding one *value*, not the bytes. `ChainKey` is `Clone`
//!    by spec M1 §G.3 and `step` is pure, so `ck.clone().step()` and
//!    `ck.step()` produce two byte-identical `MessageKey`s in safe external
//!    code, and [`StoreKey`] is reused by design. What actually stops
//!    XChaCha20-Poly1305 keystream reuse in both paths is that the *nonce*
//!    cannot be duplicated: [`Nonce192`] is neither `Copy` nor `Clone` and
//!    `random` is its only constructor. That single property is the one this
//!    module's safety rests on — see [`StoreKey`] and
//!    `mlkb_secrets::Nonce192`.
//!
//! 3. **The associated data cannot be concatenated by hand** (spec parent §8.3,
//!    M1 §G.3). [`Aad`] borrows a [`CanonicalBytes`], and `CanonicalBytes` is
//!    constructible only by `mlkb_codec::encode_canonical`. There is **no**
//!    constructor of [`Aad`] from a `&[u8]`: parent §8.3 rejects the raw-slice
//!    form by name, because reopening it reopens the ad-hoc concatenation of
//!    audit finding L6. Do not add one, not even a `#[doc(hidden)]` one for
//!    tests — the tests in this module build their AAD through the codec, which
//!    is the point.

use alloc::vec::Vec;

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{Key, KeyInit, Tag, XChaCha20Poly1305, XNonce};
use mlkb_codec::CanonicalBytes;
use mlkb_secrets::{Nonce192, ProtocolError, Secret32, WireNonce};
use zeroize::Zeroizing;

use crate::hash::Prk;
use crate::keys::MessageKey;
use crate::labels;

/// XChaCha20-Poly1305 key length in bytes (spec M1 §I).
pub const AEAD_KEY_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce length in bytes (spec M1 §I, §G.2).
pub const AEAD_NONCE_LEN: usize = 24;

/// Poly1305 tag length in bytes (spec M1 §I).
pub const AEAD_TAG_LEN: usize = 16;

// ---------------------------------------------------------------------------
// Aad (spec parent §8.3, M1 §G.3, §D.3)
// ---------------------------------------------------------------------------

/// The associated data of one AEAD operation (spec parent §8.3, M1 §G.3).
///
/// A transparent borrow of a canonical encoding. The single value it carries in
/// the message path is defined by M1 §D.3; `mlkb-protocol` builds it, this
/// crate only consumes it.
///
/// # There is no `Aad::from(&[u8])`
///
/// That absence *is* the type. Spec parent §8.3 rejects a `seal` taking a raw
/// slice, and M1 §G.3 restates it: `Aad` exists to make the ad-hoc
/// concatenation of audit L6 unrepresentable. A byte-slice constructor here
/// would restore exactly the shape the type was introduced to delete.
///
/// This is a property by *absence*, so no test in this crate can witness it: a
/// unit test cannot observe a constructor that does not exist. Any commit that
/// adds one breaks parent §8.3 and no test will say so.
#[derive(Debug, Clone, Copy)]
pub struct Aad<'a>(&'a CanonicalBytes);

impl<'a> Aad<'a> {
    /// Borrows a canonical encoding as associated data (spec M1 §G.3).
    #[must_use]
    pub fn new(bytes: &'a CanonicalBytes) -> Self {
        Self(bytes)
    }

    /// The borrowed bytes, for the cipher.
    fn as_slice(self) -> &'a [u8] {
        self.0.as_bytes()
    }
}

/// The one conversion, and it starts from a canonical encoding
/// (spec M1 §G.3).
impl<'a> From<&'a CanonicalBytes> for Aad<'a> {
    fn from(bytes: &'a CanonicalBytes) -> Self {
        Self(bytes)
    }
}

// ---------------------------------------------------------------------------
// Ciphertext
// ---------------------------------------------------------------------------

/// An AEAD ciphertext with its 16-byte Poly1305 tag appended (spec M1 §D.3).
///
/// The tag-appended layout is M1 §D.3's `"ct"` field verbatim, so encoding a
/// sealed message is a byte copy and nothing has to re-derive where the tag
/// starts.
///
/// Public data: no zeroize, no constant-time equality. `Debug` prints the
/// length only, because a ciphertext in a log line is still a correlatable
/// identifier.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext(Vec<u8>);

impl core::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ciphertext({} bytes)", self.0.len())
    }
}

impl Ciphertext {
    /// Wraps the bytes of a decoded `"ct"` field (spec M1 §D.3).
    ///
    /// No validation, deliberately: a ciphertext carries no structure that can
    /// be checked without the key, and every rejection belongs in
    /// [`MessageKey::open`] where it collapses to one error (spec parent §8.4).
    #[must_use]
    pub fn from_wire(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The wire bytes: ciphertext followed by the tag (spec M1 §D.3).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper, yielding the wire bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    /// The encoded length in bytes: plaintext length plus [`AEAD_TAG_LEN`].
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the encoding is empty.
    ///
    /// A sealed value never is — it always carries at least a tag — so this is
    /// true only of the fail-closed value described on [`MessageKey::seal`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------------------
// The primitive, once (spec parent §5.1)
// ---------------------------------------------------------------------------

/// Seals `pt` in place and appends the tag.
///
/// `None` only if the AEAD refuses the plaintext length. XChaCha20-Poly1305's
/// bound is `64 * (2^32 - 1)` bytes, which no message this protocol can carry
/// approaches (M1 §I bounds a frame payload at 65536), so the `None` arm is
/// unreachable in practice — but it is returned rather than unwrapped, because
/// spec parent §11 gate 7 admits no panicking path in library code.
fn seal_bytes(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    pt: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let mut buf: Vec<u8> = Vec::with_capacity(pt.len().saturating_add(AEAD_TAG_LEN));
    buf.extend_from_slice(pt);
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(*nonce), aad, buf.as_mut_slice().into())
        .ok()?;
    buf.extend_from_slice(&tag);
    Some(buf)
}

/// Opens `wire` (ciphertext followed by tag).
///
/// Every failure — a buffer too short to hold a tag, a tampered ciphertext, a
/// tampered AAD, the wrong nonce, the wrong key — returns the same
/// [`ProtocolError::Unauthenticated`] with no payload, which is spec parent
/// §8.4's requirement that this variant carry zero information.
fn open_bytes(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    wire: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let split = wire
        .len()
        .checked_sub(AEAD_TAG_LEN)
        .ok_or(ProtocolError::Unauthenticated)?;
    let (body, tag) = wire
        .split_at_checked(split)
        .ok_or(ProtocolError::Unauthenticated)?;
    let tag = tag
        .first_chunk::<AEAD_TAG_LEN>()
        .ok_or(ProtocolError::Unauthenticated)?;

    let cipher = XChaCha20Poly1305::new(&Key::from(*key));
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(body.to_vec());
    cipher
        .decrypt_inout_detached(
            &XNonce::from(*nonce),
            aad,
            buf.as_mut_slice().into(),
            &Tag::from(*tag),
        )
        .map_err(|_| ProtocolError::Unauthenticated)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// MessageKey — the ratchet path (spec parent §8.3, M1 §G.2)
// ---------------------------------------------------------------------------

impl MessageKey {
    /// Seals one application message (spec parent §5.1, §8.3, M1 §G.2).
    ///
    /// ```text
    /// ct = XChaCha20-Poly1305-Seal(MK, nonce, pt, aad) || tag
    /// ```
    ///
    /// Consumes both the key and the nonce, so neither can be used a second
    /// time within this process. The signature is M1 §G.2's verbatim, including
    /// its infallibility.
    ///
    /// # The unreachable branch, and how it fails
    ///
    /// The underlying AEAD is fallible for one reason only: a plaintext past
    /// `64 * (2^32 - 1)` bytes. Rather than panic (spec parent §11 gate 7) or
    /// widen M1 §G.2's pinned signature, that branch returns an **empty**
    /// [`Ciphertext`], which is shorter than a tag and therefore rejected by
    /// [`MessageKey::open`] under every key. It fails closed, and it never
    /// returns the plaintext.
    // The nonce is by value because consuming it is the point (spec M1 §G.2);
    // `needless_pass_by_value` is wrong here.
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn seal(self, nonce: Nonce192, pt: &[u8], aad: Aad<'_>) -> Ciphertext {
        match seal_bytes(self.bytes(), nonce.as_bytes(), pt, aad.as_slice()) {
            Some(bytes) => Ciphertext(bytes),
            None => Ciphertext(Vec::new()),
        }
    }

    /// Opens one received application message (spec parent §8.3, §8.4).
    ///
    /// Consumes the key on **success**. On failure the key is handed back, so a
    /// failed attempt does not spend it.
    ///
    /// # Why failure returns the key (security audit 2026-08-02)
    ///
    /// This is the Python audit's D7 defect one layer up. An unconditionally
    /// consuming `open` means a *forged* ciphertext aimed at a cached skipped
    /// message key destroys that key, and the authentic delayed message it
    /// belongs to becomes permanently undecryptable — silently. The Python
    /// implementation hit exactly this and its fix was to verify the AEAD
    /// **before** evicting the cached key
    /// (`core/double_ratchet.py:308-319`); M1 §D.4 carries the same rule
    /// forward, and it is why the skipped-key store refuses rather than evicts.
    ///
    /// Returning `(Self, ProtocolError)` makes that rule enforceable by the type
    /// rather than by the caller remembering: the skipped-key path can only put
    /// the key back if it still has it. The one-shot property parent §8.3 wants
    /// is unaffected — a *successful* open still consumes, so no key ever opens
    /// two ciphertexts.
    ///
    /// The nonce is a [`WireNonce`] because a received nonce is not one this
    /// side minted; there is no conversion from it into a [`Nonce192`], so the
    /// sealing path cannot be fed attacker-chosen bytes (spec M1 §G.2).
    ///
    /// The plaintext is returned in a `Zeroizing` container so that dropping it
    /// wipes it. Spec parent §8.2's honest limitation applies: this reduces
    /// residency, it does not eliminate it.
    ///
    /// # Errors
    /// [`ProtocolError::Unauthenticated`], with no payload and no distinction
    /// between a short buffer, a tampered ciphertext, a tampered AAD, a wrong
    /// nonce and a wrong key (spec parent §8.4).
    pub fn open(
        self,
        nonce: &WireNonce,
        ciphertext: &Ciphertext,
        aad: Aad<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, (Self, ProtocolError)> {
        match open_bytes(
            self.bytes(),
            nonce.as_bytes(),
            ciphertext.as_bytes(),
            aad.as_slice(),
        ) {
            Ok(pt) => Ok(pt),
            Err(e) => Err((self, e)),
        }
    }
}

// ---------------------------------------------------------------------------
// StoreKey — value-level sealing at rest (spec M1 §G.5)
// ---------------------------------------------------------------------------

/// `K_store`, the at-rest value-sealing key (spec M1 §G.5, §J row 10).
///
/// M1 §G.5 layers value-level XChaCha20-Poly1305 *under* SQLCipher: every
/// secret blob is sealed with this key before it is bound into a SQL statement,
/// so a SQLCipher container-key compromise alone yields no key material.
///
/// # Why this key is not one-shot
///
/// Unlike [`MessageKey`], a `StoreKey` seals many values, so `seal_at_rest`
/// takes `&self`. That is safe for exactly the reason spec parent §5.1 gives
/// for choosing a 192-bit random nonce: uniqueness comes from the nonce, not
/// from the key being spent, and there is no durable counter to roll back
/// (parent §5.2).
///
/// # The whole of the at-rest nonce argument
///
/// Because the key is reused by design, this path has **no** defence but the
/// nonce — and the plaintexts here are the long-term secrets M1 §G.5 exists to
/// protect: ratchet state, identity private keys, the ML-DSA seed ξ. A
/// repeated `(K_store, nonce)` byte pair is keystream reuse over exactly those.
///
/// `mlkb-store` must therefore draw a **fresh** [`Nonce192`] per value, and
/// three facts together — not one — make that the only option:
///
/// 1. [`StoreKey::seal_at_rest`] takes the nonce **by value** and consumes it;
/// 2. `Nonce192::random` is its only constructor — there is no
///    `from_bytes`, no `From<[u8; 24]>`, and no conversion from the
///    [`WireNonce`] that `open_at_rest` accepts;
/// 3. `Nonce192` is neither `Copy` nor `Clone`.
///
/// Point 3 is load-bearing and was once absent. Without it points 1 and 2 are
/// worth nothing: `n.clone()` yields a second sealable nonce with identical
/// bytes, and this doc's claim would be false while looking true. The
/// compile-fail probes on `AeadStructuralProbes` below hold all three.
///
/// The residual is `mlkb_secrets::Nonce192`'s and is stated there: `CryptoRng`
/// is a marker trait, so a caller that supplies a constant "RNG" still repeats
/// nonces. The type cannot close that; the single RNG boundary is the answer.
pub struct StoreKey(Secret32);

/// Redacting (spec M1 §G.1).
impl core::fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StoreKey([REDACTED])")
    }
}

impl StoreKey {
    /// Derives `K_store` from a store master PRK (spec M1 §G.5, §J row 9).
    ///
    /// ```text
    /// K_store = HKDF-Expand(prk, "MLKEMBraid/store/v2", 32)
    /// ```
    ///
    /// The label is [`crate::labels::K_STORE`]; `mlkb-store` owns where the
    /// PRK comes from and never writes the label itself.
    #[must_use]
    pub fn derive(prk: &Prk) -> Self {
        Self(prk.expand_secret::<AEAD_KEY_LEN>(&[labels::K_STORE]))
    }

    /// Seals one secret blob before it reaches SQL (spec M1 §G.5).
    ///
    /// The associated data is an [`Aad`] for the same reason the message path's
    /// is (spec parent §8.3): the row identity a stored blob is bound to must
    /// be a canonical encoding, not a hand-built concatenation.
    ///
    /// The unreachable-failure behaviour is [`MessageKey::seal`]'s: an empty
    /// [`Ciphertext`], which never opens.
    // By value for the reason `MessageKey::seal`'s nonce is.
    #[allow(clippy::needless_pass_by_value)]
    #[must_use]
    pub fn seal_at_rest(&self, nonce: Nonce192, pt: &[u8], aad: Aad<'_>) -> Ciphertext {
        match seal_bytes(self.0.expose_secret(), nonce.as_bytes(), pt, aad.as_slice()) {
            Some(bytes) => Ciphertext(bytes),
            None => Ciphertext(Vec::new()),
        }
    }

    /// Opens one stored blob (spec M1 §G.5).
    ///
    /// # Errors
    /// [`ProtocolError::Unauthenticated`], carrying nothing (spec parent §8.4).
    pub fn open_at_rest(
        &self,
        nonce: &WireNonce,
        ciphertext: &Ciphertext,
        aad: Aad<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
        open_bytes(
            self.0.expose_secret(),
            nonce.as_bytes(),
            ciphertext.as_bytes(),
            aad.as_slice(),
        )
    }
}

// ---------------------------------------------------------------------------
// Compile-fail probes (spec parent §5.1, §8.3, M1 §G.2, §G.5)
// ---------------------------------------------------------------------------

/// The structural properties of the two sealing paths, as tests.
///
/// The at-rest path of M1 §G.5 has no defence but the nonce — `seal_at_rest`
/// takes `&self` and `K_store` is reused by design — so the probes that matter
/// most here are the ones that stop a caller presenting the same 24 bytes
/// twice. They are properties by **absence**, which a unit test cannot see; a
/// `compile_fail` doc-test can, and `cargo test` runs it.
///
/// A nonce cannot be duplicated for a second `seal_at_rest` — this is the
/// exact two-time pad over the ML-DSA seed and the identity keys:
///
/// ```compile_fail
/// fn seal_two_secrets_under_one_nonce(
///     k: &mlkb_crypto::StoreKey,
///     n: mlkb_secrets::Nonce192,
///     aad: mlkb_crypto::Aad<'_>,
/// ) -> (mlkb_crypto::Ciphertext, mlkb_crypto::Ciphertext) {
///     let a = k.seal_at_rest(n.clone(), b"the ML-DSA seed", aad);
///     let b = k.seal_at_rest(n, b"the identity key", aad);
///     (a, b)
/// }
/// ```
///
/// Positive control: sealing two values under two *drawn* nonces compiles,
/// so the block above fails for the missing `Clone` and not for its shape.
///
/// ```
/// fn seal_two_secrets_properly<R: rand_core::CryptoRng>(
///     k: &mlkb_crypto::StoreKey,
///     rng: &mut R,
///     aad: mlkb_crypto::Aad<'_>,
/// ) -> (mlkb_crypto::Ciphertext, mlkb_crypto::Ciphertext) {
///     let a = k.seal_at_rest(mlkb_secrets::Nonce192::random(rng), b"the ML-DSA seed", aad);
///     let b = k.seal_at_rest(mlkb_secrets::Nonce192::random(rng), b"the identity key", aad);
///     (a, b)
/// }
/// ```
///
/// The same probe on the message path, where two byte-identical `MessageKey`s
/// *are* obtainable (`ChainKey` is `Clone` by M1 §G.3) and only the nonce
/// stands between them and a two-time pad:
///
/// ```compile_fail
/// fn two_time_pad(
///     ck: mlkb_crypto::ChainKey,
///     n: mlkb_secrets::Nonce192,
///     aad: mlkb_crypto::Aad<'_>,
/// ) -> (mlkb_crypto::Ciphertext, mlkb_crypto::Ciphertext) {
///     let (_, mk1) = ck.clone().step();
///     let (_, mk2) = ck.step();
///     // mk1 and mk2 are byte-identical; if the nonce could be duplicated the
///     // two ciphertexts below would share a keystream.
///     (mk1.seal(n.clone(), b"plaintext one", aad),
///      mk2.seal(n, b"plaintext two", aad))
/// }
/// ```
///
/// Positive control for the *keys* half of that — the clone really does
/// compile, so the block above is failing on the nonce and not on the chain
/// key:
///
/// ```
/// fn two_identical_message_keys(
///     ck: mlkb_crypto::ChainKey,
/// ) -> (mlkb_crypto::MessageKey, mlkb_crypto::MessageKey) {
///     let (_, mk1) = ck.clone().step();
///     let (_, mk2) = ck.step();
///     (mk1, mk2)
/// }
/// ```
///
/// A received nonce cannot be turned into a sealing nonce, so a peer cannot
/// choose the nonce this side seals under (spec M1 §G.2):
///
/// ```compile_fail
/// fn seal_under_a_received_nonce(
///     k: &mlkb_crypto::StoreKey,
///     w: mlkb_secrets::WireNonce,
///     aad: mlkb_crypto::Aad<'_>,
/// ) -> mlkb_crypto::Ciphertext {
///     k.seal_at_rest(w.into(), b"pt", aad)
/// }
/// ```
///
/// And the AAD still cannot be a raw slice (spec parent §8.3, M1 §G.3) — the
/// absence documented on [`Aad`], now with a probe:
///
/// ```compile_fail
/// fn hand_built_aad(
///     k: &mlkb_crypto::StoreKey,
///     n: mlkb_secrets::Nonce192,
/// ) -> mlkb_crypto::Ciphertext {
///     k.seal_at_rest(n, b"pt", mlkb_crypto::Aad::new(b"row-id" as &[u8]))
/// }
/// ```
///
/// Positive control: an `Aad` built through the codec, which is the only way.
///
/// ```
/// let mut m = mlkb_codec::CanonicalMap::new();
/// m.insert("v", mlkb_codec::Value::uint(0x0200)).unwrap();
/// let bytes = mlkb_codec::encode_canonical(&mlkb_codec::Value::map(m)).unwrap();
/// let _aad = mlkb_crypto::Aad::new(&bytes);
/// ```
#[cfg(doctest)]
#[derive(Debug)]
struct AeadStructuralProbes;

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;
    use crate::keys::{ChainKey, DhLegs, DhOutput, KemSharedSecret, SkInfo, derive_sk};
    use alloc::format;
    use mlkb_codec::{CanonicalMap, Value, encode_canonical};

    fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }

    /// A canonical AAD shaped like M1 §D.3's, built through the codec because
    /// that is the only way an `Aad` can come into existence.
    fn aad_bytes(sender: u8) -> CanonicalBytes {
        let mut m = CanonicalMap::new();
        m.insert("e", Value::uint(7)).unwrap();
        m.insert("h", Value::bytes(alloc::vec![0xab; 8])).unwrap();
        m.insert("r", Value::bytes(alloc::vec![0x02; 32])).unwrap();
        m.insert("s", Value::bytes(alloc::vec![sender; 32]))
            .unwrap();
        m.insert("v", Value::uint(0x0200)).unwrap();
        encode_canonical(&Value::map(m)).unwrap()
    }

    /// A chain key reached through the real key schedule — there is no other
    /// way to get one, which is spec parent §4.1's invariant doing its job even
    /// inside this crate's own tests.
    fn chain(seed: u8) -> ChainKey {
        let dh = |s: u8| DhOutput::from_dh(Secret32::new([s; 32]));
        let kem = |s: u8| KemSharedSecret::from_kem(Secret32::new([s; 32]));
        let root = derive_sk(
            DhLegs::without_opk(dh(1), dh(2), dh(3)),
            kem(9),
            &SkInfo::new(&[1u8; 32], &[2u8; 32]),
        );
        let (_, ck) = root.ratchet(dh(seed), kem(seed));
        ck
    }

    /// The same message key twice, for the tests that need to seal and then
    /// open: `seal` and `open` each consume a `MessageKey`, so a round trip
    /// needs two identical ones. Stepping a cloned chain key is the documented
    /// way to get them (spec M1 §G.3, "clone only to plan").
    fn key_pair(seed: u8) -> (MessageKey, MessageKey) {
        let ck = chain(seed);
        let (_, a) = ck.clone().step();
        let (_, b) = ck.step();
        (a, b)
    }

    // -----------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------

    #[test]
    fn seal_then_open_round_trips() {
        let mut r = rng();
        let aad = aad_bytes(1);
        for pt in [
            &b""[..],
            b"m",
            b"a longer application payload than one block",
        ] {
            let (k_send, k_recv) = key_pair(0x11);
            let nonce = Nonce192::random(&mut r);
            let wire = WireNonce::from_bytes(*nonce.as_bytes());
            let ct = k_send.seal(nonce, pt, Aad::new(&aad));
            assert_eq!(ct.len(), pt.len() + AEAD_TAG_LEN);
            let opened = k_recv.open(&wire, &ct, Aad::new(&aad)).unwrap();
            assert_eq!(opened.as_slice(), pt);
        }
    }

    #[test]
    fn the_ciphertext_survives_a_wire_round_trip() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let (k_send, k_recv) = key_pair(0x12);
        let nonce = Nonce192::random(&mut r);
        let wire = WireNonce::from_bytes(*nonce.as_bytes());
        let ct = k_send.seal(nonce, b"payload", Aad::new(&aad));
        let round_tripped = Ciphertext::from_wire(ct.as_bytes().to_vec());
        assert_eq!(round_tripped, ct);
        assert_eq!(
            k_recv
                .open(&wire, &round_tripped, Aad::new(&aad))
                .unwrap()
                .as_slice(),
            b"payload"
        );
    }

    // -----------------------------------------------------------------
    // Negatives (spec parent §8.4: one error, no detail)
    // -----------------------------------------------------------------

    #[test]
    fn a_tampered_ciphertext_is_rejected() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let (k_send, _) = key_pair(0x13);
        let nonce = Nonce192::random(&mut r);
        let wire = WireNonce::from_bytes(*nonce.as_bytes());
        let ct = k_send.seal(nonce, b"payload", Aad::new(&aad));

        // Every byte, body and tag alike.
        for i in 0..ct.len() {
            let mut bad = ct.as_bytes().to_vec();
            bad[i] ^= 1;
            let (_, k) = key_pair(0x13);
            assert_eq!(
                k.open(&wire, &Ciphertext::from_wire(bad), Aad::new(&aad))
                    .map_err(|(_k, e)| e),
                Err(ProtocolError::Unauthenticated),
                "accepted a flip at byte {i}"
            );
        }
    }

    #[test]
    fn a_tampered_aad_is_rejected() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let other = aad_bytes(2);
        assert_ne!(aad.as_bytes(), other.as_bytes());

        let (k_send, k_recv) = key_pair(0x14);
        let nonce = Nonce192::random(&mut r);
        let wire = WireNonce::from_bytes(*nonce.as_bytes());
        let ct = k_send.seal(nonce, b"payload", Aad::new(&aad));
        assert_eq!(
            k_recv
                .open(&wire, &ct, Aad::new(&other))
                .map_err(|(_k, e)| e),
            Err(ProtocolError::Unauthenticated)
        );
    }

    #[test]
    fn the_wrong_nonce_or_the_wrong_key_is_rejected() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let (k_send, k_recv) = key_pair(0x15);
        let nonce = Nonce192::random(&mut r);
        let other_nonce = WireNonce::from_bytes(*Nonce192::random(&mut r).as_bytes());
        let wire = WireNonce::from_bytes(*nonce.as_bytes());
        let ct = k_send.seal(nonce, b"payload", Aad::new(&aad));

        assert_eq!(
            k_recv
                .open(&other_nonce, &ct, Aad::new(&aad))
                .map_err(|(_k, e)| e),
            Err(ProtocolError::Unauthenticated)
        );

        let (_, foreign) = key_pair(0x16);
        assert_eq!(
            foreign
                .open(&wire, &ct, Aad::new(&aad))
                .map_err(|(_k, e)| e),
            Err(ProtocolError::Unauthenticated)
        );
    }

    /// A buffer with no room for a tag collapses to the same error as a forged
    /// one — spec parent §8.4 admits no second variant here.
    #[test]
    fn a_buffer_shorter_than_a_tag_is_rejected_with_the_same_error() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let wire = WireNonce::from_bytes(*Nonce192::random(&mut r).as_bytes());
        for len in 0..AEAD_TAG_LEN {
            let (_, k) = key_pair(0x17);
            assert_eq!(
                k.open(
                    &wire,
                    &Ciphertext::from_wire(alloc::vec![0u8; len]),
                    Aad::new(&aad)
                )
                .map_err(|(_k, e)| e),
                Err(ProtocolError::Unauthenticated),
                "accepted a {len}-byte buffer"
            );
        }
    }

    /// The fail-closed value of [`MessageKey::seal`]'s unreachable branch: an
    /// empty `Ciphertext` opens under nothing.
    #[test]
    fn the_empty_ciphertext_never_opens() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let wire = WireNonce::from_bytes(*Nonce192::random(&mut r).as_bytes());
        let (_, k) = key_pair(0x18);
        let empty = Ciphertext::from_wire(Vec::new());
        assert!(empty.is_empty());
        assert_eq!(
            k.open(&wire, &empty, Aad::new(&aad)).map_err(|(_k, e)| e),
            Err(ProtocolError::Unauthenticated)
        );
    }

    // -----------------------------------------------------------------
    // Nonce and key separation (spec parent §5.1, §5.2)
    // -----------------------------------------------------------------

    /// The property parent §5.2 leans on: the same key and the same plaintext
    /// under a different nonce produce different ciphertext bytes, so a
    /// re-derived key after a rollback is a benign duplicate rather than a
    /// two-time pad.
    #[test]
    fn a_different_nonce_changes_the_ciphertext_for_the_same_plaintext() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let (a, b) = key_pair(0x19);
        let n1 = Nonce192::random(&mut r);
        let n2 = Nonce192::random(&mut r);
        assert_ne!(n1, n2);
        let ct1 = a.seal(n1, b"same plaintext", Aad::new(&aad));
        let ct2 = b.seal(n2, b"same plaintext", Aad::new(&aad));
        assert_ne!(ct1.as_bytes(), ct2.as_bytes());
        assert_eq!(ct1.len(), ct2.len());
    }

    /// Sealing is deterministic in (key, nonce, aad, plaintext) — there is no
    /// hidden randomness in this module (spec M1 §G.2).
    ///
    /// Note what this test had to do to seal twice under one nonce: drop to
    /// the crate-private [`seal_bytes`]. `MessageKey::seal` takes a
    /// [`Nonce192`] by value and a `Nonce192` cannot be duplicated, so the
    /// public API has no way to express this at all. That is the point, and
    /// `sealing_the_same_plaintext_twice_needs_two_nonces` below is its
    /// positive statement.
    #[test]
    fn sealing_is_deterministic_in_its_arguments() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let nonce = Nonce192::random(&mut r);
        let (a, b) = key_pair(0x1a);
        let ct1 = seal_bytes(a.bytes(), nonce.as_bytes(), b"p", aad.as_bytes()).unwrap();
        let ct2 = seal_bytes(b.bytes(), nonce.as_bytes(), b"p", aad.as_bytes()).unwrap();
        assert_eq!(ct1, ct2);
    }

    /// The AAD is bound: the same key, nonce and plaintext under a different
    /// AAD is a different ciphertext.
    ///
    /// Same note as above — the fixed nonce is reached through the private
    /// primitive because the public one forbids it.
    #[test]
    fn the_aad_is_bound_into_the_tag() {
        let mut r = rng();
        let nonce = Nonce192::random(&mut r);
        let (a, b) = key_pair(0x1b);
        let aad1 = aad_bytes(1);
        let aad2 = aad_bytes(2);
        let ct1 = seal_bytes(a.bytes(), nonce.as_bytes(), b"p", aad1.as_bytes()).unwrap();
        let ct2 = seal_bytes(b.bytes(), nonce.as_bytes(), b"p", aad2.as_bytes()).unwrap();
        // Same stream, so the bodies match; the tags must not.
        assert_eq!(ct1[..1], ct2[..1]);
        assert_ne!(ct1, ct2);
    }

    // -----------------------------------------------------------------
    // The two-time pad, and why it is not constructible (spec parent §5.1,
    // §8.3, M1 §G.2, §G.3)
    // -----------------------------------------------------------------

    /// Two **byte-identical** message keys do not share a keystream, because
    /// each seal costs a fresh nonce.
    ///
    /// This is the runtime half of the finding the `compile_fail` probes on
    /// `AeadStructuralProbes` cover. `ChainKey` is `Clone` by spec M1 §G.3 and
    /// `step` is pure, so `mk1` and `mk2` here are the same 32 bytes — the
    /// key half of `(key, nonce)` really is repeatable in safe code. The test
    /// then shows the attack still fails: with distinct nonces the two
    /// keystreams are independent, so `ct1 ^ ct2` does **not** reveal
    /// `pt1 ^ pt2`, which is exactly what a two-time pad would hand an
    /// attacker.
    ///
    /// If `Nonce192` regained `Clone`, the `compile_fail` probe would go green
    /// (i.e. fail) and this test's premise would be reachable with one nonce.
    #[test]
    fn byte_identical_message_keys_do_not_share_a_keystream() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let ck = chain(0x40);
        let (_, mk1) = ck.clone().step();
        let (_, mk2) = ck.step();

        // The premise: the two keys are byte-identical. Sealing the same
        // plaintext under the same nonce bytes would give the same ciphertext.
        let probe = Nonce192::random(&mut r);
        assert_eq!(
            seal_bytes(mk1.bytes(), probe.as_bytes(), b"x", aad.as_bytes()),
            seal_bytes(mk2.bytes(), probe.as_bytes(), b"x", aad.as_bytes()),
            "the premise of this test is wrong: the two message keys differ"
        );

        // The public path: each seal consumes its own drawn nonce.
        let pt1 = b"attack at dawn..";
        let pt2 = b"retreat at dusk.";
        let ct1 = mk1.seal(Nonce192::random(&mut r), pt1, Aad::new(&aad));
        let ct2 = mk2.seal(Nonce192::random(&mut r), pt2, Aad::new(&aad));

        let body1 = &ct1.as_bytes()[..pt1.len()];
        let body2 = &ct2.as_bytes()[..pt2.len()];
        let ct_xor: Vec<u8> = body1.iter().zip(body2).map(|(a, b)| a ^ b).collect();
        let pt_xor: Vec<u8> = pt1.iter().zip(pt2).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            ct_xor, pt_xor,
            "keystream reuse: the ciphertexts XOR to the plaintexts"
        );
        assert_ne!(body1, body2);
    }

    /// The same statement for the at-rest path of M1 §G.5, which is the worse
    /// case: `seal_at_rest` takes `&self`, so `K_store` is *deliberately*
    /// reused and the nonce is the only thing separating two sealings of the
    /// long-term secrets.
    #[test]
    fn one_store_key_sealing_two_secrets_does_not_share_a_keystream() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let key = StoreKey::derive(&Prk::from_secret(&Secret32::new([0x5f; 32])));

        let pt1 = b"the ML-DSA seed.";
        let pt2 = b"the identity key";
        let ct1 = key.seal_at_rest(Nonce192::random(&mut r), pt1, Aad::new(&aad));
        let ct2 = key.seal_at_rest(Nonce192::random(&mut r), pt2, Aad::new(&aad));

        let ct_xor: Vec<u8> = ct1.as_bytes()[..pt1.len()]
            .iter()
            .zip(&ct2.as_bytes()[..pt2.len()])
            .map(|(a, b)| a ^ b)
            .collect();
        let pt_xor: Vec<u8> = pt1.iter().zip(pt2).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            ct_xor, pt_xor,
            "keystream reuse under K_store: the ciphertexts XOR to the plaintexts"
        );
    }

    /// Sealing the same plaintext twice costs two nonces, and the second one
    /// has to be drawn.
    ///
    /// The `Nonce192` moved into the first `seal` is gone; there is no
    /// `clone`, no `Copy` and no way back from `as_bytes`. Every repetition in
    /// this loop is therefore a fresh draw, and every ciphertext differs.
    #[test]
    fn sealing_the_same_plaintext_twice_needs_two_nonces() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let ck = chain(0x41);
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let mut chain_key = ck;
        for _ in 0..8 {
            let (next, mk) = chain_key.clone().step();
            let ct = mk.seal(
                Nonce192::random(&mut r),
                b"identical plaintext",
                Aad::new(&aad),
            );
            assert!(
                !seen.contains(&ct.as_bytes().to_vec()),
                "a (key, nonce) pair repeated"
            );
            seen.push(ct.into_vec());
            chain_key = next;
        }
    }

    // -----------------------------------------------------------------
    // At rest (spec M1 §G.5)
    // -----------------------------------------------------------------

    #[test]
    fn a_stored_blob_round_trips_under_k_store() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let key = StoreKey::derive(&Prk::from_secret(&Secret32::new([0x5a; 32])));
        let nonce = Nonce192::random(&mut r);
        let wire = WireNonce::from_bytes(*nonce.as_bytes());
        let ct = key.seal_at_rest(nonce, b"the ML-DSA seed", Aad::new(&aad));
        assert_eq!(
            key.open_at_rest(&wire, &ct, Aad::new(&aad))
                .unwrap()
                .as_slice(),
            b"the ML-DSA seed"
        );
    }

    #[test]
    fn a_store_key_seals_many_values_under_distinct_nonces() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let key = StoreKey::derive(&Prk::from_secret(&Secret32::new([0x5b; 32])));
        let mut seen: Vec<Vec<u8>> = Vec::new();
        for _ in 0..8 {
            let nonce = Nonce192::random(&mut r);
            let wire = WireNonce::from_bytes(*nonce.as_bytes());
            let ct = key.seal_at_rest(nonce, b"identical plaintext", Aad::new(&aad));
            assert!(!seen.contains(&ct.as_bytes().to_vec()), "a nonce repeated");
            assert_eq!(
                key.open_at_rest(&wire, &ct, Aad::new(&aad))
                    .unwrap()
                    .as_slice(),
                b"identical plaintext"
            );
            seen.push(ct.into_vec());
        }
    }

    /// `K_store` is domain-separated: a different PRK is a different key, and
    /// the derivation is not the PRK itself.
    #[test]
    fn k_store_is_derived_and_domain_separated() {
        let master = Secret32::new([0x5c; 32]);
        let a = StoreKey::derive(&Prk::from_secret(&master));
        let b = StoreKey::derive(&Prk::from_secret(&Secret32::new([0x5d; 32])));
        assert_ne!(a.0, b.0);
        assert_ne!(&a.0, &master);
        // Deterministic.
        assert_eq!(a.0, StoreKey::derive(&Prk::from_secret(&master)).0);
        // And it is the §4.4 label, not some other expansion of the same PRK.
        let under_another_label =
            Prk::from_secret(&master).expand_secret::<32>(&[labels::SESSION_ID]);
        assert_ne!(a.0, under_another_label);
    }

    /// A store ciphertext does not open under a message key, and vice versa —
    /// the two paths use the same primitive but never the same key.
    #[test]
    fn a_stored_blob_does_not_open_under_a_message_key() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let key = StoreKey::derive(&Prk::from_secret(&Secret32::new([0x5e; 32])));
        let nonce = Nonce192::random(&mut r);
        let wire = WireNonce::from_bytes(*nonce.as_bytes());
        let ct = key.seal_at_rest(nonce, b"secret", Aad::new(&aad));
        let (_, mk) = key_pair(0x1c);
        assert_eq!(
            mk.open(&wire, &ct, Aad::new(&aad)).map_err(|(_k, e)| e),
            Err(ProtocolError::Unauthenticated)
        );
    }

    // -----------------------------------------------------------------
    // Hygiene
    // -----------------------------------------------------------------

    #[test]
    fn the_debug_output_names_no_bytes() {
        let mut r = rng();
        let aad = aad_bytes(1);
        let key = StoreKey::derive(&Prk::from_secret(&Secret32::new([0xab; 32])));
        assert!(format!("{key:?}").contains("REDACTED"));
        let nonce = Nonce192::random(&mut r);
        let ct = key.seal_at_rest(nonce, b"1234", Aad::new(&aad));
        assert_eq!(format!("{ct:?}"), "Ciphertext(20 bytes)");
    }

    #[test]
    fn the_constants_match_the_spec_table() {
        assert_eq!(AEAD_KEY_LEN, 32);
        assert_eq!(AEAD_NONCE_LEN, 24);
        assert_eq!(AEAD_TAG_LEN, 16);
        assert_eq!(AEAD_NONCE_LEN, Nonce192::LEN);
    }

    /// Security audit 2026-08-02: a forged ciphertext must not spend a cached
    /// skipped message key.
    ///
    /// This is the Python audit's D7 defect one layer up. If `open` consumed the
    /// key unconditionally, an attacker who guesses a cached `(epoch, index)`
    /// slot destroys the key for the authentic delayed message — silently and
    /// permanently. The Python fix was to verify before evicting
    /// (`core/double_ratchet.py:308-319`); here the type enforces it.
    #[test]
    fn a_failed_open_hands_the_key_back_and_it_still_opens_the_real_message() {
        let mut r = rng();
        let aad = aad_bytes(0x21);
        let (k_send, k_recv) = key_pair(0x21);
        let nonce = Nonce192::random(&mut r);
        let wire = WireNonce::from_bytes(*nonce.as_bytes());
        let real = k_send.seal(nonce, b"the authentic delayed message", Aad::new(&aad));

        // A forgery aimed at this slot.
        let mut forged = real.as_bytes().to_vec();
        forged[0] ^= 0xff;

        let k_recv = match k_recv.open(&wire, &Ciphertext::from_wire(forged), Aad::new(&aad)) {
            Ok(_) => panic!("forgery must not open"),
            Err((k, e)) => {
                assert_eq!(e, ProtocolError::Unauthenticated);
                k
            }
        };

        // The key survived, so the genuine message still decrypts.
        let pt = k_recv
            .open(&wire, &real, Aad::new(&aad))
            .map_err(|(_k, e)| e)
            .expect("the authentic message must still open after a forgery");
        assert_eq!(&pt[..], b"the authentic delayed message");
    }
}
