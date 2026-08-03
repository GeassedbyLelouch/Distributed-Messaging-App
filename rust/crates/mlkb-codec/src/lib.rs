//! The single canonical deterministic-CBOR codec.
//!
//! This crate *is* the encoding profile of spec M1 §B: a hand-written writer for
//! the closed CBOR subset of M1 §B.1 and a strict reader that rejects everything
//! outside it. It depends on no serialization crate (M1 §B.1, parent §3.2).
//!
//! Entry points: [`encode_canonical`] and [`decode_canonical`].

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
// Parent spec §11 gate 7 names this crate explicitly alongside `mlkb-crypto`
// and `mlkb-wire`, and requires the lint policy to be enforced against the code
// rather than merely declared. Re-allowed inside `#[cfg(test)]` only.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

/// Maximum nesting depth accepted by the encoder and the decoder.
///
/// This bound is **not** a spec constant (it appears in neither M1 §I nor the
/// parent): it is an implementation-defined limit that keeps the recursive walk
/// over [`Value`] within a bounded stack, so that hostile input cannot turn a
/// decode into a stack overflow. No structure in the protocol comes close to it.
pub const MAX_NESTING_DEPTH: u32 = 32;

// CBOR major types. All eight are named so the decoder can say what it rejects
// (spec M1 §B.1 table).
const MT_UINT: u8 = 0;
const MT_NEGINT: u8 = 1;
const MT_BYTES: u8 = 2;
const MT_TEXT: u8 = 3;
const MT_ARRAY: u8 = 4;
const MT_MAP: u8 = 5;
const MT_TAG: u8 = 6;
const MT_SIMPLE: u8 = 7;

/// Every way this crate can refuse to encode or decode.
///
/// Each variant names a rule of spec M1 §B. There is no variant meaning
/// "recovered by normalizing", because M1 §B.4 forbids normalizing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CodecError {
    /// Input ended inside an item (M1 §B.1: definite lengths, and they must be
    /// backed by actual bytes).
    UnexpectedEof,
    /// An integer or a length was not in the shortest form (M1 §B.1, M1 §B.5).
    NonShortestInt,
    /// An indefinite-length byte string, text string, array or map (M1 §B.1).
    IndefiniteLength,
    /// Additional-information values 28..=30, which RFC 8949 reserves.
    ReservedAdditionalInfo,
    /// Major type 1, negative integer — rejected by M1 §B.1.
    NegativeInt,
    /// Major type 6, tag — rejected by M1 §B.1.
    Tag,
    /// Major type 7: floats and the simple values `false`, `true`, `null` and
    /// `undefined` — all rejected by M1 §B.1 and M1 §B.3.
    FloatOrSimple,
    /// A text string, or a map key, that is not valid UTF-8 (M1 §B.1).
    InvalidUtf8,
    /// A map key that is not a text string (parent §3.2 rule 3).
    NonTextMapKey,
    /// The same map key twice (M1 §B.2: a hard reject).
    DuplicateMapKey,
    /// Map keys not in the M1 §B.2 order.
    MapKeysOutOfOrder,
    /// Bytes remained after the top-level item (parent §3.2 rule 5, audit L7).
    TrailingBytes,
    /// Nesting deeper than [`MAX_NESTING_DEPTH`].
    DepthExceeded,
    /// A declared length that cannot be addressed on this platform.
    LengthOverflow,
    /// The round-trip check of M1 §B.4 failed: re-encoding the decoded value
    /// did not reproduce the input byte for byte.
    ///
    /// Expected to be unreachable, and deliberately kept anyway: the strict
    /// reader already refuses every non-canonical encoding it can name, so this
    /// is the backstop parent §3.2 rule 5 asks for against a reader bug, not
    /// dead code to be pruned.
    NotCanonical,
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::UnexpectedEof => "unexpected end of input",
            Self::NonShortestInt => "integer or length not in shortest form",
            Self::IndefiniteLength => "indefinite-length item",
            Self::ReservedAdditionalInfo => "reserved additional information",
            Self::NegativeInt => "negative integer is not in the supported subset",
            Self::Tag => "tag is not in the supported subset",
            Self::FloatOrSimple => "float or simple value is not in the supported subset",
            Self::InvalidUtf8 => "text string is not valid UTF-8",
            Self::NonTextMapKey => "map key is not a text string",
            Self::DuplicateMapKey => "duplicate map key",
            Self::MapKeysOutOfOrder => "map keys are not in canonical order",
            Self::TrailingBytes => "trailing bytes after the top-level item",
            Self::DepthExceeded => "nesting deeper than MAX_NESTING_DEPTH",
            Self::LengthOverflow => "declared length exceeds the addressable range",
            Self::NotCanonical => "input is not the canonical encoding of its own value",
        };
        f.write_str(s)
    }
}

impl core::error::Error for CodecError {}

// ---------------------------------------------------------------------------
// CanonicalBytes (spec M1 §G.3)
// ---------------------------------------------------------------------------

/// Bytes that are the output of this crate's canonical encoder, and nothing else.
///
/// Spec M1 §G.3: constructible **only** by [`encode_canonical`]. The field is
/// private, there is no `From<&[u8]>`, no public constructor, and the low-level
/// writer that could be driven out of M1 §B.2 order is crate-private, so it is
/// not reachable to mint this type either. This is what makes `Aad`
/// un-forgeable downstream.
///
/// This negative claim is a type-level invariant, not something the test suite
/// can observe from inside the crate: a Rust unit test cannot witness the
/// absence of a constructor. Any commit adding a public constructor, a
/// `From` impl, or a public `&mut Vec<u8>` accessor to this type breaks
/// M1 §G.3, and no test will say so.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalBytes(Vec<u8>);

impl CanonicalBytes {
    /// The encoded bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the encoding is empty. It never is — every [`Value`] encodes to
    /// at least one byte — but the question is cheap to answer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the wrapper. One-way: there is no route back in.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for CanonicalBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for CanonicalBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for CanonicalBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalBytes({} bytes)", self.0.len())
    }
}

// ---------------------------------------------------------------------------
// Value (spec M1 §B.1, M1 §B.3)
// ---------------------------------------------------------------------------

/// A value in the supported subset of spec M1 §B.1.
///
/// The enum has exactly one variant per supported major type. There is no
/// `Null`, no `Bool`, and no negative or floating variant — which is how M1 §B.3
/// ("an absent value means the key is omitted entirely") is enforced: emitting
/// CBOR `null` is not merely discouraged, it is unrepresentable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Major type 0, unsigned integer (M1 §B.5: every integer and timestamp).
    Uint(u64),
    /// Major type 2, byte string — *not* an array of integers (M1 §B.1).
    Bytes(Vec<u8>),
    /// Major type 3, text string.
    Text(String),
    /// Major type 4, array.
    Array(Vec<Value>),
    /// Major type 5, map with text keys ordered per M1 §B.2.
    Map(CanonicalMap),
}

impl Value {
    /// An unsigned integer (M1 §B.5).
    #[must_use]
    pub fn uint(v: u64) -> Self {
        Self::Uint(v)
    }

    /// A byte string (M1 §B.1, major type 2).
    #[must_use]
    pub fn bytes(b: impl Into<Vec<u8>>) -> Self {
        Self::Bytes(b.into())
    }

    /// A text string (M1 §B.1, major type 3).
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self::Text(s.into())
    }

    /// An array (M1 §B.1, major type 4).
    #[must_use]
    pub fn array(items: impl Into<Vec<Self>>) -> Self {
        Self::Array(items.into())
    }

    /// A map (M1 §B.1, major type 5; key order per M1 §B.2).
    #[must_use]
    pub fn map(m: CanonicalMap) -> Self {
        Self::Map(m)
    }

    /// The integer, if this is one.
    #[must_use]
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(v) => Some(*v),
            _ => None,
        }
    }

    /// The byte string, if this is one.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// The text string, if this is one.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s),
            _ => None,
        }
    }

    /// The array, if this is one.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The map, if this is one.
    #[must_use]
    pub fn as_map(&self) -> Option<&CanonicalMap> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }
}

impl From<CanonicalMap> for Value {
    fn from(m: CanonicalMap) -> Self {
        Self::Map(m)
    }
}

// ---------------------------------------------------------------------------
// CanonicalMap (spec M1 §B.2, M1 §B.3)
// ---------------------------------------------------------------------------

/// A CBOR map whose text keys are held in the order of spec M1 §B.2.
///
/// The ordering invariant is structural: entries are kept sorted by
/// [`encoded_text_key_cmp`] at every insertion, and a repeated key is refused
/// rather than overwritten (M1 §B.2: duplicate keys are a hard reject).
/// Absence is expressed by [`CanonicalMap::insert_opt`] omitting the key
/// entirely (M1 §B.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CanonicalMap {
    // Invariant: strictly increasing under `encoded_text_key_cmp`.
    entries: Vec<(String, Value)>,
}

impl CanonicalMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a key that is present.
    ///
    /// # Errors
    /// [`CodecError::DuplicateMapKey`] if the key is already there (M1 §B.2).
    pub fn insert(&mut self, key: &str, value: Value) -> Result<(), CodecError> {
        match self
            .entries
            .binary_search_by(|(k, _)| encoded_text_key_cmp(k, key))
        {
            Ok(_) => Err(CodecError::DuplicateMapKey),
            Err(idx) => {
                // `binary_search_by` guarantees `idx <= self.entries.len()`.
                self.entries.insert(idx, (String::from(key), value));
                Ok(())
            }
        }
    }

    /// Insert a value that may be absent.
    ///
    /// Spec M1 §B.3: `None` omits the key entirely. This is the only sanctioned
    /// way to express absence, and it is why no `null` encoding exists.
    ///
    /// # Errors
    /// [`CodecError::DuplicateMapKey`], as [`CanonicalMap::insert`].
    pub fn insert_opt(&mut self, key: &str, value: Option<Value>) -> Result<(), CodecError> {
        match value {
            Some(v) => self.insert(key, v),
            None => Ok(()),
        }
    }

    /// Look a key up.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries
            .binary_search_by(|(k, _)| encoded_text_key_cmp(k, key))
            .ok()
            .and_then(|idx| self.entries.get(idx))
            .map(|(_, v)| v)
    }

    /// Whether a key is present.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Remove a key, returning its value.
    ///
    /// The use the spec names is parent §4.2's
    /// `canonical(InitialMessageV2 without confirm)` (M1 §B.3): the full map
    /// with one key taken out, not a map with a placeholder.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        self.entries
            .binary_search_by(|(k, _)| encoded_text_key_cmp(k, key))
            .ok()
            .map(|idx| self.entries.remove(idx).1)
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries in M1 §B.2 order — which is the order they are encoded in.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl<'a> IntoIterator for &'a CanonicalMap {
    type Item = (&'a str, &'a Value);
    type IntoIter = core::iter::Map<
        core::slice::Iter<'a, (String, Value)>,
        fn(&'a (String, Value)) -> (&'a str, &'a Value),
    >;
    fn into_iter(self) -> Self::IntoIter {
        fn project(e: &(String, Value)) -> (&str, &Value) {
            (e.0.as_str(), &e.1)
        }
        self.entries.iter().map(project as fn(_) -> _)
    }
}

/// Order two map keys as spec M1 §B.2 requires.
///
/// RFC 8949 §4.2.1 bytewise lexicographic comparison of the **fully encoded**
/// key, head byte included. Because the head byte encodes the length, a shorter
/// key sorts before a longer one regardless of content — `"b"` precedes `"aa"`,
/// which plain string ordering gets backwards.
#[must_use]
pub fn encoded_text_key_cmp(a: &str, b: &str) -> Ordering {
    let (ha, na) = head_bytes(MT_TEXT, len_as_arg(a.len()));
    let (hb, nb) = head_bytes(MT_TEXT, len_as_arg(b.len()));
    let lhs = ha.get(..na).unwrap_or(&[]).iter().chain(a.as_bytes());
    let rhs = hb.get(..nb).unwrap_or(&[]).iter().chain(b.as_bytes());
    lhs.cmp(rhs)
}

// ---------------------------------------------------------------------------
// head encoding, shared by the writer and the key comparator
// ---------------------------------------------------------------------------

/// A length as a CBOR head argument.
///
/// `usize` is at most 64 bits on every target this crate is built for, so the
/// conversion never fails; the fallback exists only so that no panicking path is
/// written (parent §11 gate 7).
fn len_as_arg(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The shortest-form head for `major` carrying `arg`, and its length in bytes.
///
/// Spec M1 §B.1 / §B.5: shortest form only, definite lengths only.
fn head_bytes(major: u8, arg: u64) -> ([u8; 9], usize) {
    let mb = major << 5;
    let be = arg.to_be_bytes();
    let mut out = [0u8; 9];
    if arg <= 23 {
        out[0] = mb | be[7];
        (out, 1)
    } else if u8::try_from(arg).is_ok() {
        out[0] = mb | 0x18;
        out[1] = be[7];
        (out, 2)
    } else if u16::try_from(arg).is_ok() {
        out[0] = mb | 0x19;
        out[1] = be[6];
        out[2] = be[7];
        (out, 3)
    } else if u32::try_from(arg).is_ok() {
        out[0] = mb | 0x1a;
        out[1] = be[4];
        out[2] = be[5];
        out[3] = be[6];
        out[4] = be[7];
        (out, 5)
    } else {
        out[0] = mb | 0x1b;
        out[1] = be[0];
        out[2] = be[1];
        out[3] = be[2];
        out[4] = be[3];
        out[5] = be[4];
        out[6] = be[5];
        out[7] = be[6];
        out[8] = be[7];
        (out, 9)
    }
}

// ---------------------------------------------------------------------------
// Encoder (spec M1 §B.1)
// ---------------------------------------------------------------------------

/// The deterministic writer of spec M1 §B.1: shortest-form integers, definite
/// lengths, and no way to name a major type outside the supported subset.
///
/// Crate-private on purpose. Its primitives are low-level enough to be driven
/// out of M1 §B.2 order — or to declare an array length it never fills — so
/// exposing them would give the rest of the workspace a second way to put bytes
/// on the wire, and parent §3.2's "exactly one implementation" would stop being
/// true. [`encode_canonical`] is the only public entry point, and it walks a
/// [`Value`] whose maps are sorted by construction.
#[derive(Clone, Debug, Default)]
pub(crate) struct Encoder {
    out: Vec<u8>,
}

impl Encoder {
    /// A writer with an empty buffer.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self { out: Vec::new() }
    }

    fn head(&mut self, major: u8, arg: u64) {
        let (buf, n) = head_bytes(major, arg);
        self.out.extend_from_slice(buf.get(..n).unwrap_or(&[]));
    }

    /// Write an unsigned integer: major type 0, shortest form (M1 §B.5).
    pub(crate) fn u64(&mut self, v: u64) {
        self.head(MT_UINT, v);
    }

    /// Write a byte string: major type 2, definite length (M1 §B.1).
    pub(crate) fn bytes(&mut self, b: &[u8]) {
        self.head(MT_BYTES, len_as_arg(b.len()));
        self.out.extend_from_slice(b);
    }

    /// Write a text string: major type 3, definite length (M1 §B.1).
    pub(crate) fn text(&mut self, s: &str) {
        self.head(MT_TEXT, len_as_arg(s.len()));
        self.out.extend_from_slice(s.as_bytes());
    }

    /// Write an array head of exactly `len` items (M1 §B.1: definite only).
    ///
    /// Only [`Encoder::write_value`] may call this: the head is a promise the
    /// caller has to keep by writing exactly `len` items after it.
    pub(crate) fn array(&mut self, len: usize) {
        self.head(MT_ARRAY, len_as_arg(len));
    }

    /// Write a map head of exactly `len` pairs (M1 §B.1: definite only).
    ///
    /// Only [`Encoder::write_value`] may call this: besides the length promise,
    /// the pairs that follow have to be in M1 §B.2 order, which only a
    /// [`CanonicalMap`] guarantees.
    pub(crate) fn map(&mut self, len: usize) {
        self.head(MT_MAP, len_as_arg(len));
    }

    /// Write a whole [`Value`], maps in M1 §B.2 order.
    ///
    /// # Errors
    /// [`CodecError::DepthExceeded`] past [`MAX_NESTING_DEPTH`].
    pub(crate) fn value(&mut self, value: &Value) -> Result<(), CodecError> {
        self.write_value(value, 0)
    }

    fn write_value(&mut self, value: &Value, depth: u32) -> Result<(), CodecError> {
        if depth >= MAX_NESTING_DEPTH {
            return Err(CodecError::DepthExceeded);
        }
        match value {
            Value::Uint(v) => self.u64(*v),
            Value::Bytes(b) => self.bytes(b),
            Value::Text(s) => self.text(s),
            Value::Array(items) => {
                self.array(items.len());
                for item in items {
                    self.write_value(item, depth.saturating_add(1))?;
                }
            }
            Value::Map(m) => {
                self.map(m.len());
                for (k, v) in m.iter() {
                    self.text(k);
                    self.write_value(v, depth.saturating_add(1))?;
                }
            }
        }
        Ok(())
    }

    /// Take the raw bytes written so far.
    ///
    /// Not [`CanonicalBytes`] — see the type-level note on [`Encoder`].
    #[must_use]
    pub(crate) fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Encode a [`Value`] to its one canonical form (spec M1 §B, parent §3.2).
///
/// This is the only constructor of [`CanonicalBytes`] (M1 §G.3).
///
/// # Errors
/// [`CodecError::DepthExceeded`] past [`MAX_NESTING_DEPTH`].
pub fn encode_canonical(value: &Value) -> Result<CanonicalBytes, CodecError> {
    let mut enc = Encoder::new();
    enc.value(value)?;
    Ok(CanonicalBytes(enc.finish()))
}

// ---------------------------------------------------------------------------
// Decoder (spec M1 §B.1, §B.2, §B.4)
// ---------------------------------------------------------------------------

/// The strict reader of spec M1 §B.
///
/// Rejects non-shortest-form integers, indefinite lengths, major types 1, 6 and
/// 7 (so `false`, `true` and `null` too, per M1 §B.3), non-text and duplicate
/// and out-of-order map keys, non-UTF-8 text, and — via [`Decoder::finish`] —
/// trailing bytes.
#[derive(Clone, Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// A reader positioned at the start of `input`.
    #[must_use]
    pub fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    /// Offset of the next unread byte.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::LengthOverflow)?;
        let slice = self
            .input
            .get(self.pos..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }

    fn take_one(&mut self) -> Result<u8, CodecError> {
        let b = *self.input.get(self.pos).ok_or(CodecError::UnexpectedEof)?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    fn read_be(&mut self, n: usize) -> Result<u64, CodecError> {
        let mut v: u64 = 0;
        for b in self.take(n)? {
            v = (v << 8) | u64::from(*b);
        }
        Ok(v)
    }

    /// Read a head, returning `(major, argument)`, enforcing M1 §B.1's
    /// definite-length and shortest-form rules on the argument itself.
    fn head(&mut self) -> Result<(u8, u64), CodecError> {
        let initial = self.take_one()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;
        let arg = match ai {
            0..=23 => u64::from(ai),
            24 => {
                let v = u64::from(self.take_one()?);
                if v < 24 {
                    return Err(CodecError::NonShortestInt);
                }
                v
            }
            25 => {
                let v = self.read_be(2)?;
                if u8::try_from(v).is_ok() {
                    return Err(CodecError::NonShortestInt);
                }
                v
            }
            26 => {
                let v = self.read_be(4)?;
                if u16::try_from(v).is_ok() {
                    return Err(CodecError::NonShortestInt);
                }
                v
            }
            27 => {
                let v = self.read_be(8)?;
                if u32::try_from(v).is_ok() {
                    return Err(CodecError::NonShortestInt);
                }
                v
            }
            28..=30 => return Err(CodecError::ReservedAdditionalInfo),
            _ => return Err(CodecError::IndefiniteLength),
        };
        Ok((major, arg))
    }

    /// Turn a declared length into a `usize`, refusing anything the remaining
    /// input could not possibly contain. `min_item_bytes` is the smallest number
    /// of bytes one element occupies, which bounds every allocation below by the
    /// length of the input.
    fn checked_len(&self, arg: u64, min_item_bytes: usize) -> Result<usize, CodecError> {
        let n = usize::try_from(arg).map_err(|_| CodecError::LengthOverflow)?;
        let needed = n
            .checked_mul(min_item_bytes)
            .ok_or(CodecError::LengthOverflow)?;
        if needed > self.remaining() {
            return Err(CodecError::UnexpectedEof);
        }
        Ok(n)
    }

    /// Decode one value.
    ///
    /// # Errors
    /// Any [`CodecError`] except [`CodecError::NotCanonical`], which only
    /// [`decode_canonical`] raises.
    pub fn value(&mut self) -> Result<Value, CodecError> {
        self.read_value(0)
    }

    fn read_value(&mut self, depth: u32) -> Result<Value, CodecError> {
        if depth >= MAX_NESTING_DEPTH {
            return Err(CodecError::DepthExceeded);
        }
        let (major, arg) = self.head()?;
        match major {
            MT_UINT => Ok(Value::Uint(arg)),
            MT_NEGINT => Err(CodecError::NegativeInt),
            MT_BYTES => {
                let n = self.checked_len(arg, 1)?;
                Ok(Value::Bytes(self.take(n)?.to_vec()))
            }
            MT_TEXT => {
                let n = self.checked_len(arg, 1)?;
                let raw = self.take(n)?;
                let s = core::str::from_utf8(raw).map_err(|_| CodecError::InvalidUtf8)?;
                Ok(Value::Text(String::from(s)))
            }
            MT_ARRAY => {
                let n = self.checked_len(arg, 1)?;
                // No `Vec::with_capacity(n)`: `n` is attacker-declared and
                // `checked_len` bounds it only per nesting level, so reserving
                // on it amplifies a small input into a large live allocation.
                // Grow against elements actually consumed instead (M1 §A.1
                // rule 2, applied to this layer).
                let mut items = Vec::new();
                for _ in 0..n {
                    items.push(self.read_value(depth.saturating_add(1))?);
                }
                Ok(Value::Array(items))
            }
            MT_MAP => {
                let n = self.checked_len(arg, 2)?;
                let mut map = CanonicalMap::new();
                let mut prev: Option<String> = None;
                for _ in 0..n {
                    let (kmajor, karg) = self.head()?;
                    if kmajor != MT_TEXT {
                        return Err(CodecError::NonTextMapKey);
                    }
                    let klen = self.checked_len(karg, 1)?;
                    let kraw = self.take(klen)?;
                    let key = core::str::from_utf8(kraw).map_err(|_| CodecError::InvalidUtf8)?;
                    if let Some(p) = &prev {
                        match encoded_text_key_cmp(p, key) {
                            Ordering::Less => {}
                            Ordering::Equal => return Err(CodecError::DuplicateMapKey),
                            Ordering::Greater => return Err(CodecError::MapKeysOutOfOrder),
                        }
                    }
                    let val = self.read_value(depth.saturating_add(1))?;
                    map.insert(key, val)?;
                    prev = Some(String::from(key));
                }
                Ok(Value::Map(map))
            }
            MT_TAG => Err(CodecError::Tag),
            MT_SIMPLE => Err(CodecError::FloatOrSimple),
            // `major` is a `u8 >> 5`, so 0..=7 above is exhaustive. This arm
            // exists to keep the match total without a panicking `unreachable!`.
            _ => Err(CodecError::ReservedAdditionalInfo),
        }
    }

    /// Assert the input is fully consumed (parent §3.2 rule 5, audit L7).
    ///
    /// # Errors
    /// [`CodecError::TrailingBytes`] if anything is left.
    pub fn finish(self) -> Result<(), CodecError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

/// Decode canonical CBOR, with the round-trip check of spec M1 §B.4.
///
/// The value is decoded strictly, trailing bytes are refused, and then the
/// decoded value is re-encoded and required to equal the input byte for byte.
/// Non-canonical input is **rejected**, never normalized (parent §3.2 rule 5).
///
/// # Errors
/// Any [`CodecError`]; [`CodecError::NotCanonical`] if the re-encoding differs.
pub fn decode_canonical(input: &[u8]) -> Result<Value, CodecError> {
    let mut dec = Decoder::new(input);
    let value = dec.value()?;
    dec.finish()?;
    let re = encode_canonical(&value)?;
    if re.as_bytes() == input {
        Ok(value)
    } else {
        Err(CodecError::NotCanonical)
    }
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use std::format;
    use std::string::ToString as _;
    use std::vec;

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn unhex(s: &str) -> Vec<u8> {
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars.len() % 2, 0, "odd-length hex literal");
        chars
            .chunks(2)
            .map(|pair| {
                let hi = pair[0].to_digit(16).expect("hex digit");
                let lo = pair[1].to_digit(16).expect("hex digit");
                u8::try_from(hi * 16 + lo).expect("byte")
            })
            .collect()
    }

    fn enc_hex(v: &Value) -> String {
        hex(encode_canonical(v).expect("encodes").as_bytes())
    }

    fn map_of(pairs: &[(&str, Value)]) -> Value {
        let mut m = CanonicalMap::new();
        for (k, v) in pairs {
            m.insert(k, v.clone()).expect("no duplicate in fixture");
        }
        Value::Map(m)
    }

    // -- (a) the exact M1 §B.2 ordering case ------------------------------

    #[test]
    fn b2_shorter_keys_sort_first_not_plain_string_order() {
        // Plain string order would be "aa" < "b" < "z".
        // M1 §B.2 orders the *encoded* keys: 61 62 ("b"), 61 7a ("z"),
        // 62 61 61 ("aa") -- so the one-byte keys come first.
        let v = map_of(&[
            ("z", Value::uint(1)),
            ("aa", Value::uint(2)),
            ("b", Value::uint(3)),
        ]);
        assert_eq!(enc_hex(&v), "a3616203617a0162616102");

        let m = v.as_map().expect("map");
        let keys: Vec<&str> = m.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["b", "z", "aa"]);

        // the same bytes survive the strict decoder
        assert_eq!(decode_canonical(&unhex("a3616203617a0162616102")), Ok(v));
    }

    #[test]
    fn b2_ordering_is_bytewise_over_the_encoded_key_incl_head() {
        // Cross the 23/24-byte head boundary: a 23-byte key has a one-byte head
        // (0x77), a 24-byte key a two-byte head (0x78 0x18), so the 23-byte key
        // sorts first even though its content is lexically larger.
        let short = "z".repeat(23);
        let long = "a".repeat(24);
        assert_eq!(encoded_text_key_cmp(&short, &long), Ordering::Less);
        assert!(
            long.as_str() < short.as_str(),
            "plain order is the opposite"
        );

        let v = map_of(&[
            (long.as_str(), Value::uint(0)),
            (short.as_str(), Value::uint(1)),
        ]);
        let keys: Vec<&str> = v.as_map().expect("map").iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec![short.as_str(), long.as_str()]);

        let expected = format!(
            "a277{}017818{}00",
            hex(short.as_bytes()),
            hex(long.as_bytes())
        );
        assert_eq!(enc_hex(&v), expected);
    }

    #[test]
    fn b2_comparator_agrees_with_actually_encoded_keys() {
        // The comparator claims to be "bytewise over the fully encoded key".
        // Prove it by encoding the keys and comparing the real bytes.
        let k23 = "q".repeat(23);
        let k24 = "a".repeat(24);
        let k255 = "a".repeat(255);
        let k256 = "a".repeat(256);
        let keys: [&str; 13] = [
            "", "a", "b", "z", "aa", "ab", "zz", "key", "kex", &k23, &k24, &k255, &k256,
        ];
        for a in keys {
            for b in keys {
                let mut ea = Encoder::new();
                ea.text(a);
                let mut eb = Encoder::new();
                eb.text(b);
                assert_eq!(
                    encoded_text_key_cmp(a, b),
                    ea.finish().cmp(&eb.finish()),
                    "comparator disagreed with the encoded bytes for {a:?} vs {b:?}"
                );
            }
        }
    }

    // -- (b) shortest-form integer boundary vectors -----------------------

    #[test]
    fn b5_shortest_form_integer_vectors() {
        let vectors: [(u64, &str); 9] = [
            (0, "00"),
            (23, "17"),
            (24, "1818"),
            (255, "18ff"),
            (256, "190100"),
            (65_535, "19ffff"),
            (65_536, "1a00010000"),
            (4_294_967_296, "1b0000000100000000"),
            (u64::MAX, "1bffffffffffffffff"),
        ];
        for (v, expect) in vectors {
            assert_eq!(enc_hex(&Value::uint(v)), expect, "encoding {v}");
            assert_eq!(decode_canonical(&unhex(expect)), Ok(Value::uint(v)));
        }
    }

    #[test]
    fn b5_boundary_minus_one_uses_the_smaller_head() {
        assert_eq!(enc_hex(&Value::uint(255)), "18ff");
        assert_eq!(enc_hex(&Value::uint(65_535)), "19ffff");
        assert_eq!(enc_hex(&Value::uint(4_294_967_295)), "1affffffff");
    }

    #[test]
    fn shortest_form_applies_to_lengths_too() {
        assert_eq!(
            enc_hex(&Value::bytes(vec![0u8; 23])),
            format!("57{}", "00".repeat(23))
        );
        assert_eq!(
            enc_hex(&Value::bytes(vec![0u8; 24])),
            format!("5818{}", "00".repeat(24))
        );
        assert_eq!(
            enc_hex(&Value::bytes(vec![0u8; 256])),
            format!("590100{}", "00".repeat(256))
        );
    }

    // -- (e) byte strings are major type 2, not arrays of integers --------

    #[test]
    fn b1_byte_strings_use_major_type_2() {
        let v = Value::bytes(vec![1u8, 2, 3]);
        let bytes = encode_canonical(&v).expect("encodes");
        assert_eq!(hex(bytes.as_bytes()), "43010203");
        let first = *bytes.as_bytes().first().expect("non-empty");
        assert_eq!(first >> 5, 2, "byte string must be major type 2");

        // the array-of-integers form (what serde's Vec<u8> produces, M1 §B.1)
        // is a different value with a different encoding
        let as_array = Value::array(vec![Value::uint(1), Value::uint(2), Value::uint(3)]);
        assert_eq!(enc_hex(&as_array), "83010203");
        assert_ne!(enc_hex(&v), enc_hex(&as_array));

        // a 1568-byte ML-KEM field costs 3 head bytes, not ~1568 extra ones
        let ek = Value::bytes(vec![0xabu8; 1568]);
        assert_eq!(encode_canonical(&ek).expect("encodes").len(), 1568 + 3);
    }

    // -- (c) rejection tests ---------------------------------------------

    #[track_caller]
    fn reject(hex_input: &str, expect: CodecError) {
        let bytes = unhex(hex_input);
        assert_eq!(
            decode_canonical(&bytes),
            Err(expect),
            "input {hex_input} should be rejected with {expect:?}"
        );
    }

    #[test]
    fn reject_indefinite_lengths() {
        reject("9f010203ff", CodecError::IndefiniteLength); // array
        reject("bf616101ff", CodecError::IndefiniteLength); // map
        reject("5f41614161ff", CodecError::IndefiniteLength); // byte string
        reject("7f61614161ff", CodecError::IndefiniteLength); // text string
        reject("ff", CodecError::IndefiniteLength); // lone break
    }

    #[test]
    fn reject_non_shortest_integers() {
        reject("1817", CodecError::NonShortestInt); // 23 in a 1-byte tail
        reject("190017", CodecError::NonShortestInt); // 23 in 2 bytes
        reject("1a00000017", CodecError::NonShortestInt); // 23 in 4 bytes
        reject("1b0000000000000017", CodecError::NonShortestInt); // 23 in 8 bytes
        reject("1900ff", CodecError::NonShortestInt); // 255 in 2 bytes
        reject("1a0000ffff", CodecError::NonShortestInt); // 65535 in 4 bytes
        reject("1b00000000ffffffff", CodecError::NonShortestInt); // 2^32-1 in 8
        reject("5817", CodecError::NonShortestInt); // non-shortest byte-string length
        reject("9817", CodecError::NonShortestInt); // non-shortest array length
    }

    #[test]
    fn reject_floats_and_simple_values() {
        reject("f93c00", CodecError::FloatOrSimple); // half 1.0
        reject("fa3f800000", CodecError::FloatOrSimple); // single 1.0
        reject("fb3ff0000000000000", CodecError::FloatOrSimple); // double 1.0
        reject("f4", CodecError::FloatOrSimple); // false
        reject("f5", CodecError::FloatOrSimple); // true
        reject("f6", CodecError::FloatOrSimple); // null (M1 §B.3)
        reject("f7", CodecError::FloatOrSimple); // undefined
        reject("e0", CodecError::FloatOrSimple); // simple(0)
    }

    #[test]
    fn reject_null_nested_in_a_map() {
        // M1 §B.3: `null` is never a legitimate stand-in for an absent key.
        reject("a16161f6", CodecError::FloatOrSimple); // {"a": null}
        reject("81f6", CodecError::FloatOrSimple); // [null]
    }

    #[test]
    fn reject_negative_integers() {
        reject("20", CodecError::NegativeInt); // -1
        reject("3818", CodecError::NegativeInt); // -25
        reject("3bffffffffffffffff", CodecError::NegativeInt); // -2^64
        reject("a1616120", CodecError::NegativeInt); // {"a": -1}
        reject("8120", CodecError::NegativeInt); // [-1]
    }

    #[test]
    fn reject_tags() {
        reject("c100", CodecError::Tag); // tag 1 over 0
        reject(
            "c074323031332d30332d32315432303a30343a30305a",
            CodecError::Tag,
        );
        reject("d8ff00", CodecError::Tag); // tag 255
        reject("81c100", CodecError::Tag); // nested
    }

    #[test]
    fn reject_reserved_additional_info() {
        reject("1c", CodecError::ReservedAdditionalInfo);
        reject("1d", CodecError::ReservedAdditionalInfo);
        reject("1e", CodecError::ReservedAdditionalInfo);
    }

    #[test]
    fn reject_bad_map_keys() {
        reject("a2616101616102", CodecError::DuplicateMapKey); // {"a":1,"a":2}
        reject("a262616101616202", CodecError::MapKeysOutOfOrder); // {"aa":1,"b":2}
        reject("a10001", CodecError::NonTextMapKey); // {0: 1}
        reject("a1416101", CodecError::NonTextMapKey); // {h'61': 1}
        reject("a1806101", CodecError::NonTextMapKey); // {[]: ...}
    }

    #[test]
    fn reject_non_utf8_text() {
        reject("62ffff", CodecError::InvalidUtf8); // bare text
        reject("a162ffff01", CodecError::InvalidUtf8); // as a map key
    }

    #[test]
    fn reject_trailing_bytes() {
        reject("0000", CodecError::TrailingBytes);
        reject("810100", CodecError::TrailingBytes);
        reject("a1616101f6", CodecError::TrailingBytes);
    }

    #[test]
    fn reject_truncated_input() {
        reject("", CodecError::UnexpectedEof);
        reject("18", CodecError::UnexpectedEof);
        reject("430102", CodecError::UnexpectedEof); // bytes(3) with 2 bytes
        reject("8201", CodecError::UnexpectedEof); // array(2) with 1 item
        reject("a16161", CodecError::UnexpectedEof); // map(1) with no value
    }

    #[test]
    fn reject_absurd_declared_lengths_without_allocating() {
        reject("5bffffffffffffffff", CodecError::UnexpectedEof); // bytes(2^64-1)
        reject("9bffffffffffffffff", CodecError::UnexpectedEof); // array(2^64-1)
        reject("bb7fffffffffffffff", CodecError::UnexpectedEof); // map(2^63-1)

        // A map declares 2 bytes per pair, so `n * 2` is what overflows first:
        // these two reach `LengthOverflow` rather than `UnexpectedEof`.
        reject("bbffffffffffffffff", CodecError::LengthOverflow); // map(2^64-1)
        reject("bb8000000000000000", CodecError::LengthOverflow); // map(2^63)
    }

    /// A declared array length is not an allocation hint.
    ///
    /// This asserts the *shape* of the fix: a large declared length that the
    /// input cannot satisfy is refused, and a large declared length the input
    /// *can* satisfy still decodes. The memory cost is what actually
    /// distinguishes the fixed decoder from the broken one, and that is
    /// measured in `tests/alloc_amplification.rs`, which can install a counting
    /// allocator (this crate cannot: it is `#![forbid(unsafe_code)]`).
    #[test]
    fn a_declared_array_length_is_not_an_allocation_hint() {
        // array(65533) whose first element is a break byte: the declared length
        // passes the `<= remaining` check, but element 0 is already invalid.
        let mut unsatisfiable = vec![0x99, 0xff, 0xfd];
        unsatisfiable.resize(65_536, 0xff);
        assert_eq!(
            decode_canonical(&unsatisfiable),
            Err(CodecError::IndefiniteLength)
        );

        // the same head, satisfied: 65533 one-byte `Uint(0)` elements
        let mut satisfiable = vec![0x99, 0xff, 0xfd];
        satisfiable.resize(65_536, 0x00);
        let decoded = decode_canonical(&satisfiable).expect("a satisfiable array decodes");
        assert_eq!(decoded.as_array().expect("array").len(), 65_533);
    }

    #[test]
    fn reject_excessive_nesting() {
        let depth = usize::try_from(MAX_NESTING_DEPTH).expect("fits") + 1;
        let mut bytes = vec![0x81u8; depth];
        bytes.push(0x00);
        assert_eq!(decode_canonical(&bytes), Err(CodecError::DepthExceeded));

        let mut v = Value::uint(0);
        for _ in 0..depth {
            v = Value::array(vec![v]);
        }
        assert_eq!(encode_canonical(&v), Err(CodecError::DepthExceeded));
    }

    #[test]
    fn accept_nesting_just_below_the_limit() {
        let depth = usize::try_from(MAX_NESTING_DEPTH).expect("fits") - 1;
        let mut bytes = vec![0x81u8; depth];
        bytes.push(0x00);
        assert!(decode_canonical(&bytes).is_ok());
    }

    // -- the M1 §B.4 round-trip check ------------------------------------

    #[test]
    fn b4_round_trip_check_accepts_our_own_output() {
        let v = map_of(&[
            ("a", Value::uint(1)),
            ("bb", Value::bytes(vec![0xde, 0xad])),
            ("c", Value::array(vec![Value::text("x"), Value::uint(0)])),
        ]);
        let bytes = encode_canonical(&v).expect("encodes");
        assert_eq!(decode_canonical(bytes.as_bytes()), Ok(v));
    }

    #[test]
    fn b4_non_canonical_input_is_rejected_not_normalized() {
        // {"aa":1,"b":2} written out of order. A normalizing decoder would
        // return the map; ours must refuse and return no value at all.
        let bad = unhex("a262616101616202");
        assert!(decode_canonical(&bad).is_err());

        // the canonical form of that value is a different byte string
        let good = map_of(&[("aa", Value::uint(1)), ("b", Value::uint(2))]);
        assert_eq!(enc_hex(&good), "a261620262616101");
        assert_ne!(
            encode_canonical(&good).expect("encodes").as_bytes(),
            bad.as_slice()
        );
    }

    // -- M1 §B.3 absence --------------------------------------------------

    #[test]
    fn b3_absent_value_omits_the_key_entirely() {
        let mut m = CanonicalMap::new();
        m.insert_opt("opk_id", None).expect("ok");
        m.insert_opt("spk_id", Some(Value::uint(7))).expect("ok");
        let v = Value::Map(m);
        assert_eq!(v.as_map().expect("map").len(), 1);
        assert!(!v.as_map().expect("map").contains_key("opk_id"));
        assert_eq!(enc_hex(&v), "a16673706b5f696407");
        // no `null` byte anywhere in the output
        assert!(!encode_canonical(&v).expect("encodes").contains(&0xf6));
    }

    #[test]
    fn b3_without_confirm_is_the_map_with_the_key_removed() {
        // parent §4.2 `canonical(InitialMessageV2 without confirm)`.
        let mut narrow = CanonicalMap::new();
        narrow.insert("ek", Value::bytes(vec![1, 2])).expect("ok");
        narrow
            .insert("confirm", Value::bytes(vec![9; 4]))
            .expect("ok");
        let removed = narrow.remove("confirm").expect("was present");
        assert_eq!(removed, Value::bytes(vec![9; 4]));

        let mut wide = CanonicalMap::new();
        wide.insert("ek", Value::bytes(vec![1, 2])).expect("ok");
        wide.insert("confirm", Value::bytes(vec![9; 32]))
            .expect("ok");
        wide.remove("confirm");

        // the preimage does not depend on `confirm`'s own width
        assert_eq!(narrow, wide);
        assert_eq!(
            encode_canonical(&Value::Map(narrow)).expect("encodes"),
            encode_canonical(&Value::Map(wide)).expect("encodes")
        );
    }

    #[test]
    fn duplicate_key_on_insert_is_a_hard_reject() {
        let mut m = CanonicalMap::new();
        m.insert("k", Value::uint(1)).expect("first insert");
        assert_eq!(
            m.insert("k", Value::uint(2)),
            Err(CodecError::DuplicateMapKey)
        );
        // no silent overwrite
        assert_eq!(m.get("k"), Some(&Value::uint(1)));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn empty_containers() {
        assert_eq!(enc_hex(&Value::bytes(vec![])), "40");
        assert_eq!(enc_hex(&Value::text("")), "60");
        assert_eq!(enc_hex(&Value::array(vec![])), "80");
        assert_eq!(enc_hex(&Value::Map(CanonicalMap::new())), "a0");
        for h in ["40", "60", "80", "a0"] {
            assert!(decode_canonical(&unhex(h)).is_ok(), "{h}");
        }
    }

    /// Exercises the `CanonicalBytes` accessors.
    ///
    /// Deliberately **not** named for the M1 §G.3 "only `encode_canonical` can
    /// mint one" invariant: that is a negative claim about the set of
    /// constructors, which no unit test inside this crate can witness. It is
    /// stated as a type-level invariant on `CanonicalBytes` instead.
    #[test]
    fn canonical_bytes_accessors() {
        let cb = encode_canonical(&Value::uint(1)).expect("encodes");
        assert_eq!(cb.as_bytes(), &[0x01]);
        assert_eq!(cb.as_ref(), &[0x01]);
        assert_eq!(cb.len(), 1);
        assert!(!cb.is_empty());
        assert_eq!(format!("{cb:?}"), "CanonicalBytes(1 bytes)");
        assert_eq!(cb.into_vec(), vec![0x01]);
    }

    #[test]
    fn encoder_primitives_write_the_expected_heads() {
        let mut e = Encoder::new();
        e.array(2);
        e.map(1);
        e.text("k");
        e.bytes(&[0xff]);
        e.u64(24);
        assert_eq!(hex(&e.finish()), "82a1616b41ff1818");
    }

    #[test]
    fn map_accessors_and_iteration() {
        let v = map_of(&[("b", Value::uint(1)), ("aa", Value::text("x"))]);
        let m = v.as_map().expect("map");
        assert_eq!(m.get("b"), Some(&Value::uint(1)));
        assert_eq!(m.get("aa").and_then(Value::as_text), Some("x"));
        assert_eq!(m.get("nope"), None);
        assert!(!m.is_empty());
        let via_ref: Vec<&str> = m.into_iter().map(|(k, _)| k).collect();
        assert_eq!(via_ref, vec!["b", "aa"]);
        assert_eq!(Value::from(m.clone()), v);
        assert_eq!(Value::map(m.clone()), v);
        assert_eq!(v.as_uint(), None);
        assert_eq!(v.as_bytes(), None);
        assert_eq!(v.as_array(), None);
    }

    #[test]
    fn decoder_reports_position_and_trailing_bytes() {
        let input = unhex("01ff");
        let mut d = Decoder::new(&input);
        assert_eq!(d.value(), Ok(Value::uint(1)));
        assert_eq!(d.position(), 1);
        assert_eq!(d.remaining(), 1);
        assert_eq!(d.finish(), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn error_display_is_populated() {
        for err in [
            CodecError::UnexpectedEof,
            CodecError::NonShortestInt,
            CodecError::IndefiniteLength,
            CodecError::ReservedAdditionalInfo,
            CodecError::NegativeInt,
            CodecError::Tag,
            CodecError::FloatOrSimple,
            CodecError::InvalidUtf8,
            CodecError::NonTextMapKey,
            CodecError::DuplicateMapKey,
            CodecError::MapKeysOutOfOrder,
            CodecError::TrailingBytes,
            CodecError::DepthExceeded,
            CodecError::LengthOverflow,
            CodecError::NotCanonical,
        ] {
            assert!(!err.to_string().is_empty());
        }
    }

    // -- (d) property tests: injectivity and byte-identical round trip ----

    /// splitmix64 — deterministic, so a failure is reproducible, and no
    /// dev-dependency is needed.
    struct Rng(u64);

    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            if n == 0 { 0 } else { self.next_u64() % n }
        }
        fn usize_below(&mut self, n: u64) -> usize {
            usize::try_from(self.below(n)).unwrap_or(0)
        }
    }

    const KEY_POOL: [&str; 10] = [
        "a",
        "b",
        "z",
        "aa",
        "ab",
        "k",
        "key",
        "kex",
        "opk_id",
        "a_very_long_key_name_here",
    ];

    fn gen_value(rng: &mut Rng, depth: u32) -> Value {
        let choice = if depth >= 3 {
            rng.below(3)
        } else {
            rng.below(5)
        };
        match choice {
            0 => {
                // exercise every integer head width
                let v = match rng.below(5) {
                    0 => rng.below(24),
                    1 => 24 + rng.below(232),
                    2 => 256 + rng.below(65_280),
                    3 => 65_536 + rng.below(4_294_901_760),
                    _ => rng.next_u64(),
                };
                Value::Uint(v)
            }
            1 => {
                let n = rng.usize_below(6);
                let mut b = Vec::with_capacity(n);
                for _ in 0..n {
                    b.push(u8::try_from(rng.below(256)).unwrap_or(0));
                }
                Value::Bytes(b)
            }
            2 => {
                let n = rng.usize_below(4);
                let mut s = String::new();
                for _ in 0..n {
                    let c = u8::try_from(u64::from(b'a') + rng.below(4)).unwrap_or(b'a');
                    s.push(char::from(c));
                }
                Value::Text(s)
            }
            3 => {
                let n = rng.usize_below(4);
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(gen_value(rng, depth + 1));
                }
                Value::Array(items)
            }
            _ => {
                let n = rng.below(5);
                let mut m = CanonicalMap::new();
                for _ in 0..n {
                    let idx = rng.usize_below(KEY_POOL.len() as u64);
                    let key = KEY_POOL[idx];
                    let v = gen_value(rng, depth + 1);
                    // a repeated draw is simply skipped: the property under
                    // test is what a *valid* map does
                    let _ = m.insert(key, v);
                }
                Value::Map(m)
            }
        }
    }

    #[test]
    fn property_encode_decode_round_trips_byte_identically() {
        let mut rng = Rng(0x5eed_1234_abcd_0001);
        for i in 0..2000 {
            let v = gen_value(&mut rng, 0);
            let bytes = encode_canonical(&v).unwrap_or_else(|e| panic!("iter {i}: encode: {e}"));
            let back = decode_canonical(bytes.as_bytes())
                .unwrap_or_else(|e| panic!("iter {i}: decode {}: {e}", hex(bytes.as_bytes())));
            assert_eq!(back, v, "iter {i}: value changed across the round trip");
            let re = encode_canonical(&back).expect("re-encodes");
            assert_eq!(
                re.as_bytes(),
                bytes.as_bytes(),
                "iter {i}: re-encoding is not byte-identical"
            );
        }
    }

    #[test]
    fn property_encoding_is_injective() {
        let mut rng = Rng(0x5eed_1234_abcd_0002);
        let mut corpus: Vec<(Value, Vec<u8>)> = Vec::new();
        for _ in 0..600 {
            let v = gen_value(&mut rng, 0);
            let b = encode_canonical(&v).expect("encodes").into_vec();
            corpus.push((v, b));
        }
        // hand-picked adversarial pairs on top of the random corpus
        for v in [
            Value::bytes(vec![1, 2, 3]),
            Value::array(vec![Value::uint(1), Value::uint(2), Value::uint(3)]),
            Value::text("abc"),
            Value::uint(0),
            Value::array(vec![]),
            Value::Map(CanonicalMap::new()),
            Value::bytes(vec![]),
            Value::text(""),
            map_of(&[("a", Value::uint(1))]),
            map_of(&[("a", Value::text("1"))]),
            map_of(&[("a", Value::uint(1)), ("b", Value::uint(2))]),
            map_of(&[("b", Value::uint(1)), ("a", Value::uint(2))]),
        ] {
            let b = encode_canonical(&v).expect("encodes").into_vec();
            corpus.push((v, b));
        }

        let mut checked = 0usize;
        for (i, (va, ba)) in corpus.iter().enumerate() {
            for (vb, bb) in corpus.iter().skip(i + 1) {
                checked += 1;
                if ba == bb {
                    assert_eq!(va, vb, "distinct values share an encoding: {}", hex(ba));
                } else {
                    assert_ne!(va, vb, "one value produced two different encodings");
                }
            }
        }
        assert!(checked > 100_000, "the corpus was too small to mean much");
    }

    #[test]
    fn property_single_byte_mutation_never_re_decodes_to_the_same_value() {
        let mut rng = Rng(0x5eed_1234_abcd_0003);
        let mut collisions = 0usize;
        let mut mutations = 0usize;
        for _ in 0..300 {
            let v = gen_value(&mut rng, 0);
            let bytes = encode_canonical(&v).expect("encodes").into_vec();
            for idx in 0..bytes.len() {
                let mut m = bytes.clone();
                m[idx] ^= 0x01;
                mutations += 1;
                if decode_canonical(&m) == Ok(v.clone()) {
                    collisions += 1;
                }
            }
        }
        assert!(mutations > 1000, "not enough mutations to be meaningful");
        assert_eq!(
            collisions, 0,
            "a mutated byte string decoded to the same value -- encoding is not injective"
        );
    }
}
