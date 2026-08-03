//! The injected 192-bit AEAD nonce, in its two directions (spec M1 §G.2):
//! [`Nonce192`] for the send path and [`WireNonce`] for the receive path.

use rand_core::CryptoRng;

/// A 192-bit XChaCha20-Poly1305 nonce (spec M1 §G.2).
///
/// # Why this type exists
///
/// Spec M1 §G.2 resolves a three-way conflict in the parent spec by *injecting*
/// the nonce rather than generating it inside the sealing crate:
/// `seal(self, nonce: Nonce192, pt, aad)`. `mlkb-protocol` therefore stays free
/// of an RNG, and the one place a nonce can be freshly minted is
/// [`Nonce192::random`].
///
/// There is no `Nonce192::new([u8; 24])`. Anything that wants a *fresh* nonce
/// must hold an RNG.
///
/// # Not a secret
///
/// A nonce is public — it travels in the ratchet header. It is therefore
/// **not** zeroize-on-drop, its `Debug` shows its bytes, and its equality is
/// ordinary (variable-time) equality. Do not "harden" this type; doing so would
/// only imply a confidentiality property it does not have.
///
/// # Neither `Copy` nor `Clone`, and that is the whole security argument
///
/// XChaCha20-Poly1305 keystream reuse — and Poly1305 one-time-key recovery
/// with it — needs a repeated **(key, nonce)** *byte* pair. Note *byte*: it is
/// not enough that one key *value* seals once.
///
/// The key half of that pair is not defended by a type, and cannot be. Spec
/// M1 §G.3 makes `ChainKey` `Clone` so that `classify` can plan without
/// mutating while `apply` consumes, and `ChainKey::step` is a pure function of
/// the chain-key bytes. Therefore `ck.clone().step()` and `ck.step()` hand out
/// two **byte-identical** `MessageKey`s in safe code, and no change to
/// `MessageKey` can prevent it: its non-`Clone`, consuming `seal` stops one
/// *value* being spent twice, not two equal values existing.
///
/// The nonce half therefore carries the property **alone**, and this is the
/// deliberate resolution of that conflict — M1 §G.3 keeps its `Clone`, and the
/// two-time pad is closed here instead. Within one process there is no way to
/// *duplicate* a minted nonce in safe code — note this is a statement about
/// duplication, not about the byte values, which the injected RNG ultimately
/// decides (see "The residual, stated honestly" below):
///
/// - [`Nonce192::random`] is the only mint point, and it draws afresh;
/// - [`Nonce192::as_bytes`] only *borrows* — there is no
///   `Nonce192::from_bytes`, no `From<[u8; 24]>`, and no conversion from
///   [`WireNonce`], so bytes read out cannot be fed back in;
/// - the type is neither `Copy` nor `Clone`, so a second nonce is a second
///   draw.
///
/// Adding `Clone` or `Copy` here re-opens a two-time pad in safe external code
/// — in the message path (`MessageKey::seal`) and in the at-rest path
/// (`StoreKey::seal_at_rest`, which takes `&self` and so has no other
/// defence) both. Do not add them. No caller needs one: a nonce is minted
/// per-seal and consumed by that seal. The compile-fail probes on
/// `NonceStructuralProbes`, at the foot of this file, turn either derive
/// coming back into a `cargo test` failure.
///
/// ## The residual, stated honestly
///
/// This reduces the assumption to the RNG: [`Nonce192::random`] fills from a
/// caller-supplied `impl CryptoRng`, and `CryptoRng` is a marker trait that
/// safe code can implement with a lie. A caller that injects a constant "RNG"
/// still gets repeated nonces. That is inherent to M1 §G.2's injected-nonce
/// resolution, and it is why the RNG is supplied at one boundary
/// (`mlkb-session`) rather than at each call site.
///
/// # The receive path does not use this type
///
/// A nonce parsed out of the `"nc"` header (spec M1 §D.3) is a [`WireNonce`],
/// which has no conversion into this type. Opening takes the wire type;
/// sealing takes this one. That is what keeps "obtainable only from
/// [`Nonce192::random`]" a property of the type rather than of a comment.
///
/// [`Nonce192::random`]: Nonce192::random
//
// The derive list is load-bearing by *omission*: no `Clone`, no `Copy`. See
// the "Neither `Copy` nor `Clone`" section above and the compile-fail probes
// at the foot of this file before touching it.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Nonce192([u8; 24]);

impl Nonce192 {
    /// The number of bytes in a `Nonce192` (spec M1 §G.2).
    pub const LEN: usize = 24;

    /// Draws a fresh nonce from `rng` — the only way to mint one
    /// (spec M1 §G.2).
    ///
    /// The RNG is supplied at the `mlkb-session` boundary in production and by
    /// `mlkb-testkit` for KATs and fuzzing.
    #[must_use]
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut bytes = [0u8; Self::LEN];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Borrows the nonce bytes for encoding (spec M1 §G.2).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// A 24-byte nonce parsed off the wire (spec M1 §D.3, §G.2).
///
/// # Why this is a separate type
///
/// Spec M1 §G.2 requires that a [`Nonce192`] be obtainable *only* from
/// [`Nonce192::random`]. The decoder still has to parse the mandatory `"nc"`
/// header field (spec M1 §D.3) and hand the result to the opening side, so the
/// received bytes get their own type instead of a second constructor on
/// `Nonce192`.
///
/// There is deliberately **no** conversion between the two — no `From`, no
/// `Into`, no accessor returning a `Nonce192`. A sealing signature that takes
/// `Nonce192` therefore cannot be fed an attacker-chosen value, and an opening
/// signature that takes `WireNonce` cannot be fed the sender's own fresh nonce
/// by mistake.
///
/// Like [`Nonce192`] this is public data: no zeroize, no constant-time
/// equality, no redacting `Debug`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WireNonce([u8; Nonce192::LEN]);

impl WireNonce {
    /// Wraps the bytes of a decoded `"nc"` field (spec M1 §D.3).
    ///
    /// This is the decoder's entry point and the only way to build one.
    #[must_use]
    pub fn from_bytes(bytes: [u8; Nonce192::LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the received nonce bytes for the AEAD (spec M1 §G.2).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; Nonce192::LEN] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Compile-fail probes (spec M1 §G.2)
// ---------------------------------------------------------------------------

/// The structural properties of [`Nonce192`], as tests.
///
/// "A nonce cannot be duplicated" is a property by **absence**: no unit test
/// can witness a trait impl that is not there, and `tests/` cannot either —
/// asserting `!implements_clone!(Nonce192)` at runtime only proves the
/// *inherent* method is missing at that instant, and says nothing about a
/// blanket impl. A `compile_fail` doc-test does prove it, and `cargo test`
/// executes it, so re-adding `#[derive(Clone)]` or `#[derive(Copy)]` to
/// `Nonce192` turns red instead of turning into a two-time pad.
///
/// Every negative probe below is paired with a **positive control** on
/// [`WireNonce`] — which *is* `Clone`, because a received nonce is public data
/// that no one seals under. Without the control a `compile_fail` block would
/// also "pass" if it failed for a typo, a moved item or a renamed crate.
///
/// A nonce is not `Clone` — this is the two-time pad, closed:
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<mlkb_secrets::Nonce192>();
/// ```
///
/// Positive control: the wire type is:
///
/// ```
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<mlkb_secrets::WireNonce>();
/// ```
///
/// A nonce is not `Copy` either, so it cannot be duplicated by a move that
/// silently is not one:
///
/// ```compile_fail
/// fn needs_copy<T: Copy>() {}
/// needs_copy::<mlkb_secrets::Nonce192>();
/// ```
///
/// And the method form, which is how the mistake actually gets written — two
/// sealable nonces out of one draw:
///
/// ```compile_fail
/// fn two_from_one(n: mlkb_secrets::Nonce192)
///     -> (mlkb_secrets::Nonce192, mlkb_secrets::Nonce192)
/// {
///     (n.clone(), n)
/// }
/// ```
///
/// Positive control for that shape: it compiles for [`WireNonce`], so the
/// block above fails for the missing impl and not for its syntax:
///
/// ```
/// fn two_from_one(n: mlkb_secrets::WireNonce)
///     -> (mlkb_secrets::WireNonce, mlkb_secrets::WireNonce)
/// {
///     (n.clone(), n)
/// }
/// ```
///
/// Bytes read out of a nonce cannot be fed back in to rebuild it — the
/// borrow-only accessor is the other half of "a second nonce is a second
/// draw":
///
/// ```compile_fail
/// fn recycle(n: &mlkb_secrets::Nonce192) -> mlkb_secrets::Nonce192 {
///     mlkb_secrets::Nonce192::from_bytes(*n.as_bytes())
/// }
/// ```
///
/// Nor can a received nonce be lifted into the sealing type (spec M1 §G.2):
///
/// ```compile_fail
/// fn lift(w: mlkb_secrets::WireNonce) -> mlkb_secrets::Nonce192 {
///     w.into()
/// }
/// ```
///
/// Positive control that a `WireNonce` *is* reachable from bytes, which is the
/// decoder's entry point:
///
/// ```
/// let w = mlkb_secrets::WireNonce::from_bytes([7u8; 24]);
/// assert_eq!(w.as_bytes(), &[7u8; 24]);
/// ```
#[cfg(doctest)]
#[derive(Debug)]
struct NonceStructuralProbes;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use core::convert::Infallible;
    use rand_core::{TryCryptoRng, TryRng};

    /// A counting stand-in RNG. Not secure — it exists to prove that
    /// `Nonce192::random` consumes exactly `LEN` fresh bytes, in order, on
    /// every call, and caches nothing.
    struct CountingRng(u8);

    impl TryRng for CountingRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for slot in dst.iter_mut() {
                *slot = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for CountingRng {}

    #[test]
    fn random_fills_all_bytes_from_the_rng() {
        let mut rng = CountingRng(0);
        let n = Nonce192::random(&mut rng);
        let expected: [u8; 24] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        assert_eq!(n.as_bytes(), &expected);
    }

    #[test]
    fn random_does_not_repeat_across_calls() {
        let mut rng = CountingRng(0);
        let a = Nonce192::random(&mut rng);
        let b = Nonce192::random(&mut rng);
        let c = Nonce192::random(&mut rng);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        // Second draw must be the *next* 24 bytes, not a cached replay.
        let expected_b: [u8; 24] = core::array::from_fn(|i| u8::try_from(i + 24).unwrap());
        assert_eq!(b.as_bytes(), &expected_b);
    }

    #[test]
    fn random_does_not_repeat_with_the_system_rng() {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let a = Nonce192::random(&mut rng);
        let b = Nonce192::random(&mut rng);
        assert_ne!(a, b, "the system CSPRNG repeated a 192-bit draw");
        // And the draws are not degenerate.
        assert_ne!(a.as_bytes(), &[0u8; 24]);
        assert_ne!(b.as_bytes(), &[0u8; 24]);
    }

    #[test]
    fn many_system_draws_are_all_distinct() {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let draws: [Nonce192; 64] = core::array::from_fn(|_| Nonce192::random(&mut rng));
        for (i, a) in draws.iter().enumerate() {
            for (j, b) in draws.iter().enumerate().skip(i + 1) {
                assert_ne!(a, b, "collision at {i},{j}");
            }
        }
    }

    #[test]
    fn wire_nonce_round_trips() {
        let bytes: [u8; 24] = core::array::from_fn(|i| u8::try_from(i * 7 % 251).unwrap());
        let n = WireNonce::from_bytes(bytes);
        assert_eq!(n.as_bytes(), &bytes);
        assert_eq!(WireNonce::from_bytes(*n.as_bytes()), n);
    }

    #[test]
    fn wire_nonce_is_injective_over_a_sample() {
        // Distinct wire encodings must give distinct nonces.
        for i in 0..24usize {
            let mut a = [0u8; 24];
            let mut b = [0u8; 24];
            b[i] = 1;
            assert_ne!(WireNonce::from_bytes(a), WireNonce::from_bytes(b));
            a[i] = 1;
            assert_eq!(WireNonce::from_bytes(a), WireNonce::from_bytes(b));
        }
    }

    #[test]
    fn a_sent_nonce_round_trips_through_the_wire_type_bytewise() {
        // The encoder writes `Nonce192::as_bytes`; the peer's decoder reads it
        // back as a `WireNonce`. The bytes survive; the *type* does not.
        let mut rng = CountingRng(9);
        let sent = Nonce192::random(&mut rng);
        let received = WireNonce::from_bytes(*sent.as_bytes());
        assert_eq!(received.as_bytes(), sent.as_bytes());
    }

    #[test]
    fn len_matches_the_wire_width() {
        assert_eq!(Nonce192::LEN, 24);
        assert_eq!(WireNonce::from_bytes([0u8; 24]).as_bytes().len(), 24);
        let mut rng = CountingRng(0);
        assert_eq!(Nonce192::random(&mut rng).as_bytes().len(), Nonce192::LEN);
    }
}
