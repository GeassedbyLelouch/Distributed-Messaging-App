//! The secret byte container (spec M1 §G.1, parent §8.2).

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A fixed-size buffer of secret bytes (spec M1 §G.1).
///
/// This is the container the typed keys of `mlkb-crypto` are built from. It
/// provides, and is the reason this crate exists:
///
/// - **zeroize on drop** — the bytes are wiped when the value is dropped.
/// - **constant-time equality** — `PartialEq`/`Eq` compare via
///   [`subtle::ConstantTimeEq`], so comparing a candidate key against a stored
///   one leaks no timing information about where they first differ.
/// - **a redacting `Debug`** — the bytes never reach a log line.
/// - **no `Deref`** — there is exactly one way to reach the bytes,
///   [`SecretBytes::expose_secret`], named so that `grep expose_secret` finds
///   every place a secret escapes the container.
///
/// The last of those is a property by *absence* and so has no behavioural
/// test; `tests/structural_negatives.rs` asserts it, along with the absence of
/// `AsRef`, `Into<[u8; N]>` and `Copy`, from outside the crate.
///
/// # Honest limitation
///
/// Spec parent §8.2 states it and it is restated here only by citation: wiping
/// on drop reduces residency, it does not eliminate it. In particular
/// [`SecretBytes::new`] receives an array *by value*, and that caller-owned
/// copy is not wiped by this type. Prefer [`SecretBytes::from_fill`] or
/// [`SecretBytes::try_from_fill`] to derive directly into the container.
pub struct SecretBytes<const N: usize>(Zeroizing<[u8; N]>);

impl<const N: usize> SecretBytes<N> {
    /// Wraps an already-materialised array (spec M1 §G.1).
    ///
    /// See the type-level note: the caller's copy is not wiped by this call.
    #[must_use]
    pub fn new(bytes: [u8; N]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// An all-zero container (spec M1 §G.1).
    #[must_use]
    pub fn zeroed() -> Self {
        Self(Zeroizing::new([0u8; N]))
    }

    /// Builds a container by writing into it in place (spec M1 §G.1).
    ///
    /// This lets a KDF expand straight into the wiped buffer, avoiding the
    /// intermediate copy that spec parent §8.2 flags as the residual exposure.
    ///
    /// The mutable borrow is scoped to `f`: once the value exists there is no
    /// public path that mutates its bytes again, so a typed key wrapping this
    /// container cannot be overwritten after birth (spec parent §4.1).
    #[must_use]
    pub fn from_fill(f: impl FnOnce(&mut [u8; N])) -> Self {
        let mut this = Self::zeroed();
        f(&mut this.0);
        this
    }

    /// [`SecretBytes::from_fill`] for a fallible writer (spec M1 §G.1).
    ///
    /// On `Err` the partially written buffer is dropped, and therefore wiped,
    /// before the error is returned.
    pub fn try_from_fill<E>(f: impl FnOnce(&mut [u8; N]) -> Result<(), E>) -> Result<Self, E> {
        let mut this = Self::zeroed();
        f(&mut this.0)?;
        Ok(this)
    }

    /// The only way to read the secret bytes (spec M1 §G.1).
    ///
    /// Deliberately verbose and deliberately greppable; there is no `Deref`,
    /// no `AsRef`, and no `Into<[u8; N]>`.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8; N] {
        &self.0
    }
}

/// Constant-time equality (spec M1 §G.1).
impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

/// Prints a fixed placeholder and never the bytes (spec M1 §G.1).
impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{N}>([REDACTED])")
    }
}

impl<const N: usize> Clone for SecretBytes<N> {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(*self.0))
    }
}

impl<const N: usize> Zeroize for SecretBytes<N> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Marker: the inner [`Zeroizing`] wipes on drop (spec M1 §G.1).
impl<const N: usize> ZeroizeOnDrop for SecretBytes<N> {}

/// The 32-byte container every ML-KEM-Braid symmetric secret is built on
/// (spec M1 §G.1, parent §8.2).
pub type Secret32 = SecretBytes<32>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn debug_is_redacted_and_leaks_no_bytes() {
        // 0xab = 171 decimal. Neither spelling may appear in the output.
        let s = Secret32::new([0xab_u8; 32]);
        let rendered = format!("{s:?}");
        assert!(rendered.contains("REDACTED"), "got {rendered}");
        assert!(!rendered.contains("ab"), "hex byte leaked: {rendered}");
        assert!(!rendered.contains("171"), "decimal byte leaked: {rendered}");

        // Also check the alternate (pretty) formatter, which is what
        // `#[derive(Debug)]` on an enclosing struct will reach for.
        let pretty = format!("{s:#?}");
        assert!(pretty.contains("REDACTED"), "got {pretty}");
        assert!(!pretty.contains("171"), "decimal byte leaked: {pretty}");
    }

    #[test]
    fn debug_of_distinct_secrets_is_indistinguishable() {
        let a = Secret32::new([0x00_u8; 32]);
        let b = Secret32::new([0xff_u8; 32]);
        assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    /// Correctness of equality only.
    ///
    /// This deliberately does **not** claim to test constant-timeness: every
    /// assertion below also holds for a short-circuiting `#[derive(PartialEq)]`.
    /// The timing property is structural — `PartialEq` is implemented in terms
    /// of [`subtle::ConstantTimeEq`] and nothing else — and is a review item,
    /// the same way spec parent §8.4 records that the `size_of` property of
    /// `ProtocolError` has no runnable test.
    #[test]
    fn eq_is_correct_at_every_difference_position() {
        let a = Secret32::new([7u8; 32]);
        let b = Secret32::new([7u8; 32]);
        assert_eq!(a, b);
        assert!(a == b);

        // Every single-byte difference, at every position.
        for i in 0..32usize {
            let mut differs = [7u8; 32];
            differs[i] = 8;
            assert_ne!(a, Secret32::new(differs), "missed a difference at {i}");
        }

        // Differing everywhere.
        assert_ne!(a, Secret32::new([8u8; 32]));
    }

    #[test]
    fn eq_is_reflexive_symmetric_transitive_over_a_sample() {
        for i in 0..32u8 {
            let mut bytes = [0u8; 32];
            bytes[usize::from(i)] = i;
            let a = Secret32::new(bytes);
            let b = Secret32::new(bytes);
            let c = Secret32::new(bytes);
            assert_eq!(a, a);
            assert_eq!(a == b, b == a);
            assert!(a == b && b == c && a == c);

            let mut other = bytes;
            other[usize::from(i)] = i.wrapping_add(1);
            assert_ne!(a, Secret32::new(other));
        }
    }

    #[test]
    fn expose_secret_round_trips_every_construction_path() {
        let bytes = [0x5a_u8; 32];
        assert_eq!(Secret32::new(bytes).expose_secret(), &bytes);
        assert_eq!(Secret32::zeroed().expose_secret(), &[0u8; 32]);

        let filled = Secret32::from_fill(|b| b.copy_from_slice(&bytes));
        assert_eq!(filled.expose_secret(), &bytes);
        assert_eq!(filled, Secret32::new(bytes));
    }

    #[test]
    fn from_fill_starts_from_a_wiped_buffer() {
        // The writer sees zeros, so a KDF that writes only a prefix cannot
        // inherit stale bytes from this type.
        let partial = Secret32::from_fill(|b| b[0] = 1);
        let mut expected = [0u8; 32];
        expected[0] = 1;
        assert_eq!(partial.expose_secret(), &expected);
    }

    #[test]
    fn try_from_fill_propagates_the_writers_error() {
        let ok: Result<Secret32, ()> = Secret32::try_from_fill(|b| {
            b.copy_from_slice(&[9u8; 32]);
            Ok(())
        });
        assert_eq!(ok, Ok(Secret32::new([9u8; 32])));

        // A failing writer yields no container at all, so the partially
        // written buffer is dropped (and wiped) rather than returned.
        let err: Result<Secret32, u8> = Secret32::try_from_fill(|b| {
            b[0] = 0xff;
            Err(3)
        });
        assert_eq!(err, Err(3));
    }

    #[test]
    fn clone_is_an_independent_copy() {
        let a = Secret32::new([3u8; 32]);
        let mut b = a.clone();
        assert_eq!(a, b);
        // The only public mutation left is a whole-container wipe.
        b.zeroize();
        assert_ne!(a, b);
        assert_eq!(a.expose_secret(), &[3u8; 32]);
    }

    #[test]
    fn zeroize_clears_the_container() {
        let mut a = Secret32::new([0xff_u8; 32]);
        a.zeroize();
        assert_eq!(a.expose_secret(), &[0u8; 32]);
        assert_eq!(a, Secret32::zeroed());
    }

    #[test]
    fn generic_widths_other_than_32_work() {
        let a: SecretBytes<64> = SecretBytes::new([1u8; 64]);
        let b: SecretBytes<64> = SecretBytes::new([1u8; 64]);
        assert_eq!(a, b);
        assert_eq!(a.expose_secret().len(), 64);
        assert!(format!("{a:?}").contains("REDACTED"));
    }
}
