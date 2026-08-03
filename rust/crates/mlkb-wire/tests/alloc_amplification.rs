//! Measured regression guard: no parser in this crate treats a wire-declared
//! length as an allocation hint (spec M1 §A.1 rule 2), and [`Frame::decode`]
//! does not copy the payload of a frame whose MAC has not verified.
//!
//! This lives in an integration test rather than in `src/` because measuring
//! it needs a `#[global_allocator]`, and `GlobalAlloc` can only be implemented
//! with `unsafe`. The library crate is `#![forbid(unsafe_code)]`, which cannot
//! be locally overridden — but a `tests/` file is its own crate root, so the
//! library's guarantee is untouched. Nothing here is compiled into the
//! library.
//!
//! There is exactly **one** `#[test]` in this file on purpose: the counters
//! below are process-global, so a second test running concurrently would have
//! its allocations folded into the measurement.
//!
//! This file is also the external-consumer check on the public API: it builds
//! a `FrameKey` the only way there is one — `derive_sk` over a real ML-KEM
//! encapsulation — and reaches every decoder from outside the crate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// The workspace sets `unsafe_code = "deny"`. It is re-allowed here, and only
// here, for the `GlobalAlloc` impl below.
#![allow(unsafe_code)]
// The RNG below narrows 64 bits to 32 on purpose; that is what `next_u32` is.
#![allow(clippy::cast_possible_truncation)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};

use mlkb_crypto::{
    DhLegs, FrameDirection, FrameKey, KemDecapsulationKey, SkInfo, X25519SecretKey, derive_sk,
    x25519_dh,
};
use mlkb_secrets::{Progress, ProtocolError};
use mlkb_wire::{
    EnrolmentProof, FRAME_HEADER_LEN, Frame, InitialMessageV2, MAX_FRAME_PAYLOAD, MsgType,
    PrekeyBundleV2, RatchetMessage,
};

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

/// Run `f`, returning its value and the high-water mark of live bytes above
/// the live figure at entry.
fn peak_extra_bytes<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let out = f();
    let peak = PEAK.load(Ordering::Relaxed);
    (out, peak.saturating_sub(before))
}

// ---------------------------------------------------------------------------
// a frame key, the only way there is one
// ---------------------------------------------------------------------------

struct DetRng(u64);

impl DetRng {
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

fn frame_key() -> FrameKey {
    let mut rng = DetRng(0x5eed);
    let peer = X25519SecretKey::random(&mut rng).public_key();
    let mut leg = || {
        let s = X25519SecretKey::random(&mut rng);
        x25519_dh(&s, &peer).expect("a fresh keypair is contributory")
    };
    let legs = DhLegs::without_opk(leg(), leg(), leg());
    let dk = KemDecapsulationKey::generate(&mut rng);
    let (_ct, ss) = dk.encapsulation_key().encapsulate(&mut rng);
    derive_sk(legs, ss, &SkInfo::new(&[1; 32], &[2; 32]))
        .derive_frame_key(FrameDirection::InitiatorToResponder)
}

// ---------------------------------------------------------------------------
// inputs
// ---------------------------------------------------------------------------

/// A 15-byte frame header declaring the largest `payload_len` a `u32` can
/// hold. Nothing follows it.
fn frame_header_claiming(payload_len: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0200u16.to_be_bytes());
    v.extend_from_slice(&7u64.to_be_bytes());
    v.push(MsgType::Message.to_u8());
    v.extend_from_slice(&payload_len.to_be_bytes());
    assert_eq!(v.len(), FRAME_HEADER_LEN);
    v
}

/// `{"ct": bstr(2^64 - 1)}` — a nine-byte length prefix over an empty tail.
fn huge_byte_string() -> Vec<u8> {
    let mut v = vec![0xa1, 0x62, b'c', b't', 0x5b];
    v.extend_from_slice(&u64::MAX.to_be_bytes());
    v
}

/// A CBOR map head declaring 2^63 - 1 pairs.
fn huge_map() -> Vec<u8> {
    let mut v = vec![0xbb];
    v.extend_from_slice(&(u64::MAX / 2).to_be_bytes());
    v
}

/// The budget for an input that must be refused without ever believing its own
/// length prefix. Generous: the point is the difference between "a few hundred
/// bytes" and "gigabytes", not the exact figure.
const NO_ALLOC_BUDGET: usize = 4096;

#[test]
fn no_parser_reserves_on_a_wire_declared_length() {
    let key = frame_key();

    // (0) The probe has to be able to see an allocation at all, or every
    //     assertion below would pass vacuously.
    let (v, seen) = peak_extra_bytes(|| vec![0u8; 1 << 20]);
    assert_eq!(v.len(), 1 << 20);
    assert!(seen >= (1 << 20), "the counting allocator saw {seen} bytes");
    drop(v);

    // (1) M1 §A.1 rule 2: an oversized `payload_len` is refused *before*
    //     allocating. `u32::MAX` would be 4 GiB if it were believed.
    for declared in [u32::MAX, 0x7fff_ffff, 0x0010_0000] {
        let header = frame_header_claiming(declared);
        let (result, extra) = peak_extra_bytes(|| Frame::decode(&header, &key));
        assert_eq!(result, Err(ProtocolError::Malformed));
        assert!(
            extra < NO_ALLOC_BUDGET,
            "a header claiming {declared} bytes cost {extra} live bytes"
        );
    }

    // (2) A legal-but-unmet `payload_len` is `NeedMore`, and still costs
    //     nothing: the decoder does not pre-reserve while it waits.
    let header = frame_header_claiming(u32::try_from(MAX_FRAME_PAYLOAD).expect("fits"));
    let (result, extra) = peak_extra_bytes(|| Frame::decode(&header, &key));
    assert_eq!(result, Ok(Progress::NeedMore));
    assert!(extra < NO_ALLOC_BUDGET, "NeedMore cost {extra} live bytes");

    // (3) A full-size frame whose MAC does not verify must not have its
    //     payload copied out. The decoder's only allocation is the MAC
    //     preimage, which is bounded by the input it was handed; a decoder
    //     that also copied the payload would land near 2x.
    let frame =
        Frame::seal(1, MsgType::Message, vec![0xa5; MAX_FRAME_PAYLOAD], &key).expect("seals");
    let mut wire = frame.to_wire();
    let last = wire.len() - 1;
    wire[last] ^= 0x01;
    let input = wire.len();
    let (result, extra) = peak_extra_bytes(|| Frame::decode(&wire, &key));
    assert_eq!(result, Err(ProtocolError::Unauthenticated));
    assert!(
        extra < input + input / 2,
        "a {input}-byte frame with a bad MAC cost {extra} live bytes; the \
         payload is being copied before the tag is checked"
    );

    // (4) Every CBOR payload decoder, on a length prefix claiming a huge size.
    let bomb = huge_byte_string();
    for (name, result, extra) in [
        {
            let (r, e) = peak_extra_bytes(|| InitialMessageV2::decode(&bomb).err());
            ("InitialMessageV2", r, e)
        },
        {
            let (r, e) = peak_extra_bytes(|| RatchetMessage::decode(&bomb).err());
            ("RatchetMessage", r, e)
        },
        {
            let (r, e) = peak_extra_bytes(|| PrekeyBundleV2::decode(&bomb).err());
            ("PrekeyBundleV2", r, e)
        },
        {
            let (r, e) = peak_extra_bytes(|| EnrolmentProof::decode(&bomb).err());
            ("EnrolmentProof", r, e)
        },
    ] {
        assert_eq!(result, Some(ProtocolError::Malformed), "{name}");
        assert!(
            extra < NO_ALLOC_BUDGET,
            "{name} spent {extra} live bytes on a 2^64-1 byte-string length"
        );
    }

    // (5) The same, for a map head declaring 2^63 - 1 pairs.
    let bomb = huge_map();
    let (result, extra) = peak_extra_bytes(|| InitialMessageV2::decode(&bomb).err());
    assert_eq!(result, Some(ProtocolError::Malformed));
    assert!(
        extra < NO_ALLOC_BUDGET,
        "a 2^63-1 pair map head cost {extra} live bytes"
    );

    // (6) Not reserving must not break honest decoding: a real frame of the
    //     maximum payload still round-trips.
    let wire = frame.to_wire();
    let back = Frame::decode(&wire, &key)
        .expect("decodes")
        .complete()
        .expect("complete");
    assert_eq!(back.payload().len(), MAX_FRAME_PAYLOAD);
}
