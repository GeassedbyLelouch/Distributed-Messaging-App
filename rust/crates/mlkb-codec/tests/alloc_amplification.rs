//! Measured regression guard: the decoder must not treat a wire-declared length
//! as an allocation hint (spec M1 §A.1 rule 2, applied to the M1 §B decoder).
//!
//! This lives in an integration test rather than in `src/lib.rs` because
//! measuring it needs a `#[global_allocator]`, and `GlobalAlloc` can only be
//! implemented with `unsafe`. The library crate is `#![forbid(unsafe_code)]`,
//! which cannot be locally overridden — but a `tests/` file is its own crate
//! root, so the library's guarantee is untouched. Nothing here is compiled into
//! the library.
//!
//! This file also doubles as the public-API check for the M1 §G.3 / parent §3.2
//! "exactly one implementation" property: it is an external consumer of
//! `mlkb-codec`, and `mlkb_codec::Encoder` is deliberately not nameable from
//! here — `encode_canonical` is the only way out.
//!
//! There is exactly **one** `#[test]` in this file on purpose. The counters
//! below are process-global, so a second test running concurrently would have
//! its allocations folded into the measurement.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// The workspace sets `unsafe_code = "deny"`. It is re-allowed here, and only
// here, for the `GlobalAlloc` impl below — the same local-re-allow pattern the
// workspace lint table already sanctions for test targets. The library crate
// keeps its unconditional `#![forbid(unsafe_code)]`.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use mlkb_codec::{CodecError, MAX_NESTING_DEPTH, decode_canonical, encode_canonical};

// ---------------------------------------------------------------------------
// counting allocator
// ---------------------------------------------------------------------------

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// A pass-through allocator that tracks live and peak-live bytes.
#[derive(Debug)]
struct Counting;

fn bump(n: usize) {
    let now = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

fn drop_live(n: usize) {
    LIVE.fetch_sub(n, Ordering::Relaxed);
}

// SAFETY: every method forwards to `System`, unchanged, passing exactly the
// pointer, layout and size it was called with, and only adds atomic counter
// updates around the call. `System`'s own contract is therefore what holds.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            bump(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            bump(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        drop_live(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if p.is_null() {
            return p;
        }
        drop_live(layout.size());
        bump(new_size);
        p
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Run `f`, returning its value and the high-water mark of live bytes above the
/// live figure at entry.
fn peak_extra_bytes<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let out = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (out, peak.saturating_sub(before))
}

// ---------------------------------------------------------------------------
// inputs
// ---------------------------------------------------------------------------

const TOTAL: usize = 65_536;

/// The padding byte is `0xff`, a CBOR break.
///
/// That matters: it makes element 0 of the innermost array invalid, so a
/// decoder that does not pre-reserve stops having read three bytes and
/// allocates essentially nothing, while a decoder that pre-reserves has already
/// committed `declared_len * size_of::<Value>()` at every level on the way
/// down. Padding with `0x00` would instead be 65 KiB of perfectly valid
/// one-byte `Uint(0)` elements, and both decoders would honestly pay for them.
const PAD: u8 = 0xff;

/// `MAX_NESTING_DEPTH - 1` nested `0x99 <u16 len>` array heads, each declaring a
/// length equal to the bytes remaining after its own head, padded to `TOTAL`.
///
/// Every declared length passes the decoder's per-level `<= remaining` check —
/// that bound is per level, not cumulative, which is why nesting multiplies it.
fn nested_array_bomb() -> Vec<u8> {
    let heads = usize::try_from(MAX_NESTING_DEPTH).expect("fits") - 1;
    let mut input = Vec::new();
    for i in 0..heads {
        let n = u16::try_from(TOTAL - (i + 1) * 3).expect("fits in u16");
        input.push(0x99);
        input.extend_from_slice(&n.to_be_bytes());
    }
    input.resize(TOTAL, PAD);
    assert_eq!(input.len(), TOTAL);
    input
}

/// One array head declaring `TOTAL - 3` elements, padded to `TOTAL`.
fn flat_array_bomb() -> Vec<u8> {
    let n = u16::try_from(TOTAL - 3).expect("fits in u16");
    let mut input = vec![0x99];
    input.extend_from_slice(&n.to_be_bytes());
    input.resize(TOTAL, PAD);
    input
}

// ---------------------------------------------------------------------------
// the measurement
// ---------------------------------------------------------------------------

/// Peak live heap during a refused decode, as a multiple of the input size.
///
/// The reviewed defect measured 64,964,096 bytes for the nested case — 991x the
/// 64 KiB input — from `Vec::with_capacity(declared_len)` in the array arm.
/// Refusing at element 0 costs a rounding error by comparison, so this is set
/// tight rather than merely below 991x.
const AMPLIFICATION_LIMIT: usize = 2;

#[test]
fn decoder_does_not_reserve_on_a_wire_declared_length() {
    // (0) The probe has to be able to see an allocation at all, or every
    //     assertion below would pass vacuously.
    let (v, seen) = peak_extra_bytes(|| vec![0u8; 4 * TOTAL]);
    assert_eq!(v.len(), 4 * TOTAL);
    assert!(
        seen >= 4 * TOTAL,
        "the counting allocator reported {seen} bytes for a {}-byte Vec",
        4 * TOTAL
    );
    drop(v);

    // (1) Nesting must not multiply the per-level length bound into memory.
    let input = nested_array_bomb();
    let (result, extra) = peak_extra_bytes(|| decode_canonical(&input));
    assert_eq!(result, Err(CodecError::IndefiniteLength));
    assert!(
        extra < TOTAL * AMPLIFICATION_LIMIT,
        "a {TOTAL}-byte nested-array bomb peaked at {extra} extra live bytes \
         ({}x input); the decoder is reserving on a wire-declared length",
        extra / TOTAL,
    );

    // (2) The flat case: one head, no nesting, still must not pre-reserve.
    let input = flat_array_bomb();
    let (result, extra) = peak_extra_bytes(|| decode_canonical(&input));
    assert_eq!(result, Err(CodecError::IndefiniteLength));
    assert!(
        extra < TOTAL * AMPLIFICATION_LIMIT,
        "a {TOTAL}-byte flat-array bomb peaked at {extra} extra live bytes \
         ({}x input); the decoder is reserving on a wire-declared length",
        extra / TOTAL,
    );

    // (3) Not reserving must not break honest decoding of a large, satisfiable
    //     array: 60000 one-byte `Uint(0)` elements, which really do cost
    //     60000 * size_of::<Value>() and are supposed to.
    let n: u16 = 60_000;
    let mut input = vec![0x99];
    input.extend_from_slice(&n.to_be_bytes());
    input.resize(3 + usize::from(n), 0x00);

    let value = decode_canonical(&input).expect("a satisfiable array decodes");
    assert_eq!(value.as_array().expect("array").len(), usize::from(n));
    assert_eq!(
        encode_canonical(&value).expect("re-encodes").as_bytes(),
        input.as_slice(),
        "M1 §B.4: the re-encoding must be byte-identical"
    );
}
