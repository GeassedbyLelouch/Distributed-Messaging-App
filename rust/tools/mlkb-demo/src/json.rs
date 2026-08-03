//! A demo-grade JSON writer, and a form-body reader.
//!
//! # Why this exists at all
//!
//! `deny.toml` bans `serde` and every CBOR crate from the graph outright, and
//! the workspace deliberately has no JSON crate: the one serializer in this
//! project is `mlkb-codec`, and it produces deterministic CBOR for the *wire*,
//! not JSON for a browser. This module is therefore not a second codec in the
//! sense audit M8 is about — nothing here ever touches a protocol structure.
//! Its only job is to hand a `<script>` tag some numbers and hex strings.
//!
//! # It is a writer, not a parser
//!
//! There is no JSON *parser* here, because the demo does not need one: request
//! bodies are `application/x-www-form-urlencoded`, which [`parse_form`] reads.
//! A parser is the part with the interesting failure modes, so the design
//! avoids owning one.
//!
//! Demo-grade means demo-grade. This is not a shipping component.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Accumulates a JSON object.
///
/// Field order is insertion order; the browser does not care, and unlike
/// `mlkb-codec` this encoding has no determinism requirement to meet.
#[derive(Debug, Default)]
pub(crate) struct Obj {
    buf: String,
    first: bool,
}

impl Obj {
    /// An empty object.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            buf: String::from("{"),
            first: true,
        }
    }

    fn comma(&mut self) {
        if self.first {
            self.first = false;
        } else {
            self.buf.push(',');
        }
    }

    fn key(&mut self, k: &str) {
        self.comma();
        escape_into(&mut self.buf, k);
        self.buf.push(':');
    }

    /// A string field, escaped.
    pub(crate) fn str(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        escape_into(&mut self.buf, v);
        self
    }

    /// An unsigned field.
    pub(crate) fn num(&mut self, k: &str, v: u64) -> &mut Self {
        self.key(k);
        // `u64` has no representation JSON cannot hold literally, and values
        // above 2^53 would lose precision in the browser. None of the counters
        // here approach that; the epoch and index counters are small.
        let _ = write!(self.buf, "{v}");
        self
    }

    /// A boolean field.
    pub(crate) fn bool(&mut self, k: &str, v: bool) -> &mut Self {
        self.key(k);
        self.buf.push_str(if v { "true" } else { "false" });
        self
    }

    /// A field holding an already-rendered JSON fragment (an object or array).
    pub(crate) fn raw(&mut self, k: &str, v: &str) -> &mut Self {
        self.key(k);
        self.buf.push_str(v);
        self
    }

    /// Finishes the object.
    #[must_use]
    pub(crate) fn done(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

/// Renders a JSON array from already-rendered elements.
#[must_use]
pub(crate) fn array(items: &[String]) -> String {
    let mut s = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(item);
    }
    s.push(']');
    s
}

/// Renders a JSON array of strings.
#[must_use]
pub(crate) fn str_array(items: &[String]) -> String {
    let mut s = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        escape_into(&mut s, item);
    }
    s.push(']');
    s
}

/// Writes `v` as a quoted, escaped JSON string.
///
/// Escapes the two structural characters, the C0 range, and `<`/`&` — the last
/// two so that a value can never close the `<script>` context it is embedded
/// in. The demo does not embed JSON in HTML, but the cost of being safe is one
/// match arm.
fn escape_into(out: &mut String, v: &str) {
    out.push('"');
    for c in v.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Reads an `application/x-www-form-urlencoded` body into a map.
///
/// Unknown keys are kept; a duplicate key keeps the last value. A malformed
/// percent escape is left as-is rather than rejected: this is a local demo, and
/// a request that reaches here has already been length-bounded by the server.
#[must_use]
pub(crate) fn parse_form(body: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        out.insert(percent_decode(k), percent_decode(v));
    }
    out
}

/// `%XX` and `+` decoding, lossy on invalid UTF-8.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes.get(i) {
            Some(b'+') => {
                out.push(b' ');
                i = i.saturating_add(1);
            }
            Some(b'%') => {
                let hi = bytes.get(i.saturating_add(1)).copied().and_then(hex_val);
                let lo = bytes.get(i.saturating_add(2)).copied().and_then(hex_val);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi << 4) | lo);
                    i = i.saturating_add(3);
                } else {
                    out.push(b'%');
                    i = i.saturating_add(1);
                }
            }
            Some(b) => {
                out.push(*b);
                i = i.saturating_add(1);
            }
            None => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// Lowercase hex, for showing wire bytes.
#[must_use]
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
