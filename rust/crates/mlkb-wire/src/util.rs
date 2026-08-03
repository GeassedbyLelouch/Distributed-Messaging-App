//! Shared helpers for the fixed-layout and CBOR parsers.
//!
//! Nothing here is public. These are the two or three moves every decoder in
//! this crate makes, written once so that a per-structure decoder is a list of
//! fields and their widths and nothing else.
//!
//! # The three properties the helpers exist to hold
//!
//! 1. **Every decode is destructive.** A field is `remove`d from the decoded
//!    map, never borrowed and cloned, so [`finish`] can end each decoder by
//!    asserting the map is *empty*. That is how "an unknown key is a hard
//!    reject" becomes one line per structure rather than a list of key names
//!    to keep in sync.
//! 2. **A width is checked by conversion, not by comparison.** A 32-byte field
//!    decodes into `[u8; 32]`; a 1568-byte field into `Box<[u8; 1568]>`. A
//!    wrong length cannot survive the conversion, so no later code has to
//!    re-check it.
//! 3. **An encode failure is `Internal`, a decode failure is `Malformed`.**
//!    The encoder only fails on nesting depth and duplicate keys, both of
//!    which would be this crate's own bug and neither of which is an
//!    authentication outcome (parent §8.5).

use alloc::boxed::Box;
use alloc::vec::Vec;

use mlkb_codec::{CanonicalBytes, CanonicalMap, CodecError, Value, decode_canonical};
use mlkb_secrets::ProtocolError;

use crate::PROTOCOL_VERSION;

/// The CBOR map key every top-level structure carries its version under
/// (spec M1 §C.3, §F).
pub(crate) const KEY_VERSION: &str = "v";

// ---------------------------------------------------------------------------
// encoding
// ---------------------------------------------------------------------------

/// Encode a value that this crate built itself (spec M1 §B).
///
/// A failure here is a bug in this crate — the only two causes are nesting
/// past `mlkb_codec::MAX_NESTING_DEPTH`, which no structure approaches, and a
/// duplicate key, which the callers below make unrepresentable by using a
/// distinct constant per field. Parent §8.5: a local fault is never reported
/// as an authentication outcome.
pub(crate) fn encode(value: &Value) -> Result<CanonicalBytes, ProtocolError> {
    mlkb_codec::encode_canonical(value).map_err(internal)
}

fn internal(_: CodecError) -> ProtocolError {
    ProtocolError::Internal
}

/// Insert a present field.
pub(crate) fn put(map: &mut CanonicalMap, key: &str, value: Value) -> Result<(), ProtocolError> {
    map.insert(key, value).map_err(internal)
}

/// Insert a field that may be absent (spec M1 §B.3: `None` omits the key).
pub(crate) fn put_opt(
    map: &mut CanonicalMap,
    key: &str,
    value: Option<Value>,
) -> Result<(), ProtocolError> {
    map.insert_opt(key, value).map_err(internal)
}

/// Insert the `"v"` field (spec parent §3.1).
pub(crate) fn put_version(map: &mut CanonicalMap) -> Result<(), ProtocolError> {
    put(map, KEY_VERSION, Value::Uint(u64::from(PROTOCOL_VERSION)))
}

// ---------------------------------------------------------------------------
// decoding
// ---------------------------------------------------------------------------

/// Decode canonical CBOR into a map (spec M1 §B, §B.4).
///
/// `decode_canonical` already refuses indefinite lengths, non-shortest
/// integers, floats, `null`, tags, negative integers, non-text, duplicate and
/// out-of-order map keys, trailing bytes, and any input whose re-encoding is
/// not byte-identical. Non-canonical input is rejected, never normalized.
pub(crate) fn decode_map(bytes: &[u8]) -> Result<CanonicalMap, ProtocolError> {
    into_map(decode_canonical(bytes).map_err(|_| ProtocolError::Malformed)?)
}

/// A decoded value as a map.
pub(crate) fn into_map(value: Value) -> Result<CanonicalMap, ProtocolError> {
    match value {
        Value::Map(m) => Ok(m),
        _ => Err(ProtocolError::Malformed),
    }
}

/// Remove a mandatory field.
pub(crate) fn take(map: &mut CanonicalMap, key: &str) -> Result<Value, ProtocolError> {
    map.remove(key).ok_or(ProtocolError::Malformed)
}

/// Remove an optional field (spec M1 §B.3: absence is the missing key).
pub(crate) fn take_opt(map: &mut CanonicalMap, key: &str) -> Option<Value> {
    map.remove(key)
}

/// Assert every key has been consumed — i.e. that the input carried no field
/// this structure does not define.
pub(crate) fn finish(map: &CanonicalMap) -> Result<(), ProtocolError> {
    if map.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::Malformed)
    }
}

/// Remove and check the `"v"` field (spec parent §3.1: a mismatch is a hard
/// reject, and there is no negotiation).
pub(crate) fn take_version(map: &mut CanonicalMap) -> Result<(), ProtocolError> {
    if as_u16(take(map, KEY_VERSION)?)? == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::Malformed)
    }
}

// ---------------------------------------------------------------------------
// widths
// ---------------------------------------------------------------------------

/// A CBOR unsigned integer (spec M1 §B.5).
///
/// By value, like every other extractor here, and the uniformity is the point:
/// a field is `take`n out of the map and then consumed, so no decoder can read
/// one twice or leave one behind for `finish` to trip over.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn as_uint(value: Value) -> Result<u64, ProtocolError> {
    value.as_uint().ok_or(ProtocolError::Malformed)
}

/// A `u64` field narrowed to `u32` (spec M1 §C.3: the id fields).
pub(crate) fn as_u32(value: Value) -> Result<u32, ProtocolError> {
    u32::try_from(as_uint(value)?).map_err(|_| ProtocolError::Malformed)
}

/// A `u64` field narrowed to `u16` (spec parent §3.1: `version`).
pub(crate) fn as_u16(value: Value) -> Result<u16, ProtocolError> {
    u16::try_from(as_uint(value)?).map_err(|_| ProtocolError::Malformed)
}

/// A `u64` field narrowed to `u8` (spec M1 §F: `tier`).
pub(crate) fn as_u8(value: Value) -> Result<u8, ProtocolError> {
    u8::try_from(as_uint(value)?).map_err(|_| ProtocolError::Malformed)
}

/// A byte string of any length (spec M1 §D.3: `"ct"`).
pub(crate) fn as_vec(value: Value) -> Result<Vec<u8>, ProtocolError> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(ProtocolError::Malformed),
    }
}

/// A byte string of exactly `N` bytes, on the stack.
///
/// Used for the 32-byte and 24-byte fields. The conversion *is* the length
/// check.
pub(crate) fn as_array<const N: usize>(value: Value) -> Result<[u8; N], ProtocolError> {
    let bytes = as_vec(value)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| ProtocolError::Malformed)
}

/// A byte string of exactly `N` bytes, on the heap.
///
/// Used for the 1568-byte ML-KEM fields, the 1952-byte ML-DSA key and the
/// signatures: keeping them boxed is what stops a decoded `PrekeyBundleV2`
/// from being a ~14 KB value on a `thumbv7em-none-eabi` stack (M1 §G.4).
/// The conversion is exact, so it reuses the decoder's allocation rather than
/// copying.
pub(crate) fn as_boxed_array<const N: usize>(value: Value) -> Result<Box<[u8; N]>, ProtocolError> {
    let bytes = as_vec(value)?;
    Box::<[u8]>::try_into(bytes.into_boxed_slice()).map_err(|_| ProtocolError::Malformed)
}

// ---------------------------------------------------------------------------
// fixed-layout reads (spec M1 §A.1)
// ---------------------------------------------------------------------------

/// A big-endian `u16` at `at`, if the buffer reaches that far.
pub(crate) fn be_u16(buf: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    Some(u16::from_be_bytes(
        <[u8; 2]>::try_from(buf.get(at..end)?).ok()?,
    ))
}

/// A big-endian `u32` at `at`, if the buffer reaches that far.
pub(crate) fn be_u32(buf: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    Some(u32::from_be_bytes(
        <[u8; 4]>::try_from(buf.get(at..end)?).ok()?,
    ))
}

/// A big-endian `u64` at `at`, if the buffer reaches that far.
pub(crate) fn be_u64(buf: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    Some(u64::from_be_bytes(
        <[u8; 8]>::try_from(buf.get(at..end)?).ok()?,
    ))
}
