//! The protocol error type and the progress type (spec parent §8.4).

use core::fmt;

/// Every way a protocol operation can fail (spec parent §8.4).
///
/// # The load-bearing property
///
/// [`ProtocolError::Unauthenticated`] carries **zero fields**, and every
/// integrity failure — bad MAC, bad signature, bad KEM decapsulation, wrong
/// key, wrong header binding — collapses into it. That is what stops an oracle
/// crossing the FFI boundary. Do not add a field, a source, a code, or a
/// `&'static str` reason to it, and do not add a variant that splits it.
///
/// The `Display` strings below are part of that property: no authentication
/// outcome renders as anything that distinguishes *which* check failed.
///
/// Deliberately **not** `#[non_exhaustive]`: spec parent §8.4 requires that
/// downstream matches be exhaustive so that adding a variant is a compile
/// error to be reviewed rather than a silently-taken fallback arm. (§8.4 also
/// records why the proposed `size_of` test for the zero-field property does not
/// work: an enum's size reflects its largest variant.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolError {
    /// Authentication failed. Carries nothing, on purpose (spec parent §8.4).
    Unauthenticated,
    /// The input is not a well-formed encoding (spec parent §8.4).
    Malformed,
    /// The message has already been accepted (spec parent §8.4).
    ReplayDetected,
    /// Local state is older than the peer's view of it (spec parent §5.2,
    /// §8.4).
    Rewound,
    /// Accepting this message would require skipping more keys than the
    /// bound allows (spec parent §6.3, §8.4).
    SkippedKeyLimit,
    /// The first-contact pool for Unknown peers is full (spec parent §6.6).
    ///
    /// Distinct and user-actionable by requirement: spec parent §6.6 point 4
    /// forbids surfacing this exhaustion as a silent drop.
    FirstContactCapacity,
    /// A local fault — a poisoned lock, a broken invariant (spec parent §8.5).
    ///
    /// Spec parent §8.5: a process fault must never be reported as an
    /// authentication failure.
    Internal,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every string here is a category, never a check. See the type docs.
        let s = match self {
            Self::Unauthenticated => "authentication failed",
            Self::Malformed => "malformed input",
            Self::ReplayDetected => "message already accepted",
            Self::Rewound => "local state is behind",
            Self::SkippedKeyLimit => "skipped-key bound exceeded",
            Self::FirstContactCapacity => "first-contact capacity reached",
            Self::Internal => "internal fault",
        };
        f.write_str(s)
    }
}

impl core::error::Error for ProtocolError {}

/// The result of a step that may simply not be finished yet
/// (spec parent §8.4).
///
/// Incompleteness is **not** an error. Keeping "need more data" out of
/// [`ProtocolError`] is what removes the Python conflation of a partial read
/// with an authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Progress<T> {
    /// The step finished and produced `T`.
    Complete(T),
    /// The step needs more input. Nothing is wrong.
    NeedMore,
}

impl<T> Progress<T> {
    /// The finished value, if there is one (spec parent §8.4).
    #[must_use]
    pub fn complete(self) -> Option<T> {
        match self {
            Self::Complete(v) => Some(v),
            Self::NeedMore => None,
        }
    }

    /// True when more input is required (spec parent §8.4).
    #[must_use]
    pub fn is_need_more(&self) -> bool {
        matches!(self, Self::NeedMore)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    const ALL: [ProtocolError; 7] = [
        ProtocolError::Unauthenticated,
        ProtocolError::Malformed,
        ProtocolError::ReplayDetected,
        ProtocolError::Rewound,
        ProtocolError::SkippedKeyLimit,
        ProtocolError::FirstContactCapacity,
        ProtocolError::Internal,
    ];

    #[test]
    fn unauthenticated_is_a_unit_variant() {
        // A field-carrying variant would not construct from the bare path,
        // would not be `Copy`, and would not compare by identity alone.
        let a = ProtocolError::Unauthenticated;
        let b: ProtocolError = ProtocolError::Unauthenticated;
        assert_eq!(a, b);
        let copied = a;
        assert_eq!(copied, a);
    }

    #[test]
    fn display_never_names_the_failing_check() {
        // Words that would betray *which* check failed.
        const FORBIDDEN: [&str; 12] = [
            "mac",
            "tag",
            "signature",
            "sign",
            "hmac",
            "poly1305",
            "decapsul",
            "kem",
            "hkdf",
            "header",
            "key mismatch",
            "aad",
        ];
        for e in ALL {
            let rendered = format!("{e}").to_ascii_lowercase();
            for word in FORBIDDEN {
                assert!(
                    !rendered.contains(word),
                    "{e:?} leaks {word:?} via Display: {rendered}"
                );
            }
        }
    }

    #[test]
    fn display_is_non_empty_and_distinct_per_variant() {
        let rendered: Vec<String> = ALL.iter().map(|e| format!("{e}")).collect();
        for r in &rendered {
            assert!(!r.is_empty());
        }
        // Variants are already distinguishable by identity; the strings just
        // must not collide and confuse a human reading a log.
        for (i, a) in rendered.iter().enumerate() {
            for b in rendered.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn is_a_core_error() {
        fn assert_error<E: core::error::Error>(e: E) -> String {
            format!("{e}")
        }
        assert!(!assert_error(ProtocolError::Unauthenticated).is_empty());
        // Spec parent §8.4: no payload, so no source to chase.
        let e: &dyn core::error::Error = &ProtocolError::Unauthenticated;
        assert!(e.source().is_none());
    }

    #[test]
    fn exhaustive_match_covers_every_variant() {
        // If a variant is added, this match stops compiling. That is the
        // review trigger spec parent §8.4 asks for in place of a `size_of`
        // test.
        for e in ALL {
            let seen = match e {
                ProtocolError::Unauthenticated => 0,
                ProtocolError::Malformed => 1,
                ProtocolError::ReplayDetected => 2,
                ProtocolError::Rewound => 3,
                ProtocolError::SkippedKeyLimit => 4,
                ProtocolError::FirstContactCapacity => 5,
                ProtocolError::Internal => 6,
            };
            assert!(seen < ALL.len());
        }
        // And the list above is the whole list.
        for (i, a) in ALL.iter().enumerate() {
            for b in ALL.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn progress_needmore_is_not_an_error() {
        let p: Progress<u8> = Progress::NeedMore;
        assert!(p.is_need_more());
        assert_eq!(p.complete(), None);

        let q = Progress::Complete(7u8);
        assert!(!q.is_need_more());
        assert_eq!(q.complete(), Some(7u8));
    }

    #[test]
    fn progress_is_not_convertible_from_protocol_error() {
        // Both are usable in the same signature without either absorbing the
        // other: `Result<Progress<T>, ProtocolError>` is the intended shape.
        fn step(input: &[u8]) -> Result<Progress<usize>, ProtocolError> {
            match input.len() {
                0 => Ok(Progress::NeedMore),
                1 => Err(ProtocolError::Malformed),
                n => Ok(Progress::Complete(n)),
            }
        }
        assert_eq!(step(&[]), Ok(Progress::NeedMore));
        assert_eq!(step(&[0]), Err(ProtocolError::Malformed));
        assert_eq!(step(&[0, 1, 2]), Ok(Progress::Complete(3)));
    }
}
