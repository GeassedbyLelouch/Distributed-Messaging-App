//! Compile-time guards for the properties this crate provides by *absence*.
//!
//! Spec M1 §G.1 ("no `Deref` to the raw bytes") and §G.2 ("no public
//! constructor … obtainable only from `Nonce192::random`") are load-bearing
//! negatives: nothing in an ordinary behavioural test fails if someone later
//! adds `impl Deref for SecretBytes` or `#[derive(Copy)]` on `Nonce192`. The
//! properties would simply vanish.
//!
//! This file turns each negative into a checked fact. It lives in `tests/` so
//! it sees exactly the public API an outside crate sees.
//!
//! # How the probe works
//!
//! For each trait there is a private inherent method on `Probe<T>` bounded on
//! that trait, plus a fallback method of the same name supplied by a blanket
//! trait impl. Rust's method resolution tries the inherent candidate first and
//! discards it when its bound is unsatisfied, so the call site evaluates to
//! `true` exactly when `T` implements the trait. Each assertion below is
//! paired with a positive control, so a probe that silently stopped detecting
//! anything would itself fail the test.

// The `&self` receivers below carry no data and are never read. They are still
// required: the inherent-before-trait preference this file relies on is part of
// *method* resolution, and an associated function would not get it.
#![allow(clippy::unused_self)]

use core::marker::PhantomData;
use core::ops::Deref;

use mlkb_secrets::{Nonce192, Secret32, SecretBytes, WireNonce};

/// One-type probe carrier.
struct Probe<T: ?Sized>(PhantomData<*const T>);

impl<T: ?Sized> Probe<T> {
    fn new() -> Self {
        Self(PhantomData)
    }
}

/// Two-type probe carrier, for traits with a parameter (`AsRef<U>`, `Into<U>`).
struct Probe2<T: ?Sized, U: ?Sized>(PhantomData<(*const T, *const U)>);

impl<T: ?Sized, U: ?Sized> Probe2<T, U> {
    fn new() -> Self {
        Self(PhantomData)
    }
}

trait CopyFallback {
    fn probe_copy(&self) -> bool {
        false
    }
}
impl<T: ?Sized> CopyFallback for Probe<T> {}
impl<T: Copy> Probe<T> {
    fn probe_copy(&self) -> bool {
        true
    }
}

trait DerefFallback {
    fn probe_deref(&self) -> bool {
        false
    }
}
impl<T: ?Sized> DerefFallback for Probe<T> {}
impl<T: Deref> Probe<T> {
    fn probe_deref(&self) -> bool {
        true
    }
}

trait AsRefFallback {
    fn probe_as_ref(&self) -> bool {
        false
    }
}
impl<T: ?Sized, U: ?Sized> AsRefFallback for Probe2<T, U> {}
impl<T: AsRef<U> + ?Sized, U: ?Sized> Probe2<T, U> {
    fn probe_as_ref(&self) -> bool {
        true
    }
}

trait IntoFallback {
    fn probe_into(&self) -> bool {
        false
    }
}
impl<T: ?Sized, U: ?Sized> IntoFallback for Probe2<T, U> {}
impl<T: Into<U>, U> Probe2<T, U> {
    fn probe_into(&self) -> bool {
        true
    }
}

// These must be macros, not generic functions. Method resolution happens once,
// against the *declared* bounds at the definition site; inside a generic `fn
// f<T>()` the compiler cannot see that `T: Copy` holds, so the inherent
// candidate is discarded for every `T` and the probe reads `false` always. A
// macro expands at the call site with the concrete type, which is what the
// resolution needs.

macro_rules! implements_copy {
    ($t:ty) => {
        Probe::<$t>::new().probe_copy()
    };
}

macro_rules! implements_deref {
    ($t:ty) => {
        Probe::<$t>::new().probe_deref()
    };
}

macro_rules! implements_as_ref {
    ($t:ty, $u:ty) => {
        Probe2::<$t, $u>::new().probe_as_ref()
    };
}

macro_rules! implements_into {
    ($t:ty, $u:ty) => {
        Probe2::<$t, $u>::new().probe_into()
    };
}

#[test]
fn the_probes_actually_detect_something() {
    // Positive controls. If these ever read `false`, every negative assertion
    // in this file is vacuous and must not be trusted.
    assert!(implements_copy!([u8; 32]));
    assert!(implements_deref!(String));
    assert!(implements_as_ref!(Vec<u8>, [u8]));
    assert!(implements_into!([u8; 32], [u8; 32]));
}

#[test]
fn secret_bytes_has_no_implicit_path_to_the_raw_bytes() {
    // Spec M1 §G.1: no `Deref`. Plus the two neighbours the type docs promise,
    // which would each reintroduce an un-greppable escape hatch.
    assert!(!implements_deref!(Secret32));
    assert!(!implements_deref!(SecretBytes<64>));

    assert!(!implements_as_ref!(Secret32, [u8]));
    assert!(!implements_as_ref!(Secret32, [u8; 32]));
    assert!(!implements_as_ref!(SecretBytes<64>, [u8]));

    assert!(!implements_into!(Secret32, [u8; 32]));
    assert!(!implements_into!(SecretBytes<64>, [u8; 64]));

    // `expose_secret` remains the one way through, and it borrows.
    assert_eq!(Secret32::zeroed().expose_secret(), &[0u8; 32]);
}

#[test]
fn secret_bytes_is_not_copy() {
    // A `Copy` secret could be duplicated past a consuming API and would leave
    // un-wiped duplicates behind, defeating the drop wipe (spec parent §8.2).
    assert!(!implements_copy!(Secret32));
    assert!(!implements_copy!(SecretBytes<64>));
}

#[test]
fn nonce192_is_not_copy() {
    // Spec M1 §G.2 / the type docs: sealing consumes the nonce by value, so
    // reusing one must cost an explicit `clone()`.
    assert!(!implements_copy!(Nonce192));
}

#[test]
fn nothing_converts_into_a_nonce192() {
    // Spec M1 §G.2: a `Nonce192` is obtainable *only* from `Nonce192::random`.
    // A received nonce is a `WireNonce` and stays one.
    assert!(!implements_into!(WireNonce, Nonce192));
    assert!(!implements_into!(Nonce192, WireNonce));
    assert!(!implements_into!([u8; 24], Nonce192));

    // The wire type is still fully usable for what the decoder needs.
    let received = WireNonce::from_bytes([4u8; 24]);
    assert_eq!(received.as_bytes(), &[4u8; 24]);
}
