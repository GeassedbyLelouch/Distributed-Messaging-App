//! The complete domain-separation registry (spec parent §4.4, M1 §E.2,
//! M1 §J row 9).
//!
//! Every HKDF label and every signature context string in ML-KEM-Braid is
//! spelled here, once. Nothing else in the workspace may write one of these
//! byte strings as a literal; it must name the constant. Adding a label means
//! editing this file, which is what makes the closed-set claim of parent §4.4
//! and M1 §E.2 checkable by review.
//!
//! Encoding of a label, stated by M1 §E.2 for the whole project: the literal
//! ASCII bytes shown, with **no terminator and no length prefix**. The one
//! embedded NUL in [`XEDDSA_DOMAIN`] is part of that literal, not a
//! terminator.

/// Prefix of the PQXDH `SK` info string (spec parent §4.1, §4.4).
///
/// The full info is this label followed by the initiator's and then the
/// responder's `IdentityId`; see [`crate::SkInfo`].
pub const SK_INFO_PREFIX: &[u8] = b"MLKEMBraid/pqxdh/v2";

/// `K_frame_i2r`, the initiator→responder frame MAC key (spec parent §4.4).
pub const FRAME_I2R: &[u8] = b"MLKEMBraid/frame/i2r/v2";

/// `K_frame_r2i`, the responder→initiator frame MAC key (spec parent §4.4).
pub const FRAME_R2I: &[u8] = b"MLKEMBraid/frame/r2i/v2";

/// `k_cf`, the PQXDH confirmation MAC key (spec parent §4.2, §4.4).
pub const PQXDH_CONFIRM: &[u8] = b"MLKEMBraid/pqxdh/confirm/v2";

/// `session_id`, the replay-defence session identifier (spec parent §4.4,
/// §6.3).
pub const SESSION_ID: &[u8] = b"MLKEMBraid/sid/v2";

/// `K_chunk`, the per-erasure-share integrity key (spec parent §4.4).
///
/// M2+ only. The label is pinned now so that the M2 share layer cannot invent
/// a second spelling; this crate derives nothing from it.
pub const ERASURE_CHUNK: &[u8] = b"MLKEMBraid/erasure-chunk/v2";

/// The Double Ratchet root-step info string (spec M1 §D.2, §J row 9).
pub const RATCHET_ROOT: &[u8] = b"MLKEMBraid/ratchet/root/v2";

/// `K_store`, the at-rest value-sealing key (spec M1 §G.5, §J row 9).
///
/// M1 §J row 9 requires the label table to carry `K_store`, and §G.5 requires
/// every secret blob to be sealed under it before it reaches SQL. Neither
/// section spells the string, so it is fixed here — this crate is the one
/// definition, and `mlkb-store` derives the key with it rather than writing a
/// literal of its own.
pub const K_STORE: &[u8] = b"MLKEMBraid/store/v2";

/// The framed-signature domain tag (spec parent §3.6, M1 §E.2).
///
/// This is the literal including its trailing NUL, which is what keeps the
/// framed byte-space disjoint from the raw XEdDSA signing path.
pub const XEDDSA_DOMAIN: &[u8] = b"MLKEMBraid/xeddsa/v2\x00";

/// Context for the X25519 signed prekey in `PrekeyBundleV2` (spec M1 §E.2).
pub const CTX_SPK: &[u8] = b"MLKEMBraid/ctx/spk/v2";

/// Context for the ML-KEM-1024 signed prekey (spec M1 §E.2).
pub const CTX_PQSPK: &[u8] = b"MLKEMBraid/ctx/pqspk/v2";

/// Context for an `EnrolmentProof` (spec M1 §E.2, §F).
pub const CTX_ENROLMENT: &[u8] = b"MLKEMBraid/ctx/enrolment/v2";

/// The closed signature-context registry (spec M1 §E.2).
///
/// A signature is always made under exactly one of these. Because the context
/// is an enum rather than a caller-supplied slice, a signed prekey cannot be
/// lifted into a PQ-prekey slot: there is no way to spell a context that is
/// not in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigContext {
    /// The X25519 signed prekey (spec M1 §E.2).
    SignedPrekey,
    /// The ML-KEM-1024 signed prekey (spec M1 §E.2).
    PqSignedPrekey,
    /// An `EnrolmentProof` (spec M1 §E.2, §F).
    Enrolment,
}

impl SigContext {
    /// Every context in the registry, for exhaustive tests (spec M1 §E.2).
    pub const ALL: [Self; 3] = [Self::SignedPrekey, Self::PqSignedPrekey, Self::Enrolment];

    /// The exact ASCII bytes of this context (spec M1 §E.2).
    #[must_use]
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::SignedPrekey => CTX_SPK,
            Self::PqSignedPrekey => CTX_PQSPK,
            Self::Enrolment => CTX_ENROLMENT,
        }
    }
}

/// Every label in the registry, in one slice, for the registry tests.
///
/// The registry's closed-set claim (spec parent §4.4, M1 §E.2) is checked by
/// the tests below rather than used by the library, so this exists only under
/// `cfg(test)`.
#[cfg(test)]
const ALL_LABELS: [&[u8]; 12] = [
    SK_INFO_PREFIX,
    FRAME_I2R,
    FRAME_R2I,
    PQXDH_CONFIRM,
    SESSION_ID,
    ERASURE_CHUNK,
    RATCHET_ROOT,
    K_STORE,
    XEDDSA_DOMAIN,
    CTX_SPK,
    CTX_PQSPK,
    CTX_ENROLMENT,
];

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_label_is_distinct() {
        for (i, a) in ALL_LABELS.iter().enumerate() {
            for b in ALL_LABELS.iter().skip(i + 1) {
                assert_ne!(a, b, "duplicate label");
            }
        }
    }

    /// No label is a prefix of another.
    ///
    /// Labels are used with no length prefix (M1 §E.2), so prefix-freeness is
    /// what stops one derivation's info string from being the head of
    /// another's.
    #[test]
    fn the_registry_is_prefix_free() {
        for a in ALL_LABELS {
            for b in ALL_LABELS {
                if a == b {
                    // The same label; distinctness is the test above.
                    continue;
                }
                assert!(
                    !b.starts_with(a),
                    "{:?} is a prefix of {:?}",
                    core::str::from_utf8(a),
                    core::str::from_utf8(b)
                );
            }
        }
    }

    #[test]
    fn every_label_is_ascii_and_project_scoped() {
        for label in ALL_LABELS {
            assert!(label.is_ascii(), "label is not ASCII");
            assert!(label.starts_with(b"MLKEMBraid/"), "label is not scoped");
            assert!(label.len() > 11);
        }
    }

    /// The only NUL in the registry is the one M1 §E.2 keeps deliberately.
    #[test]
    #[allow(clippy::naive_bytecount)]
    fn only_the_xeddsa_domain_tag_carries_a_nul() {
        for label in ALL_LABELS {
            let nuls = label.iter().filter(|b| **b == 0).count();
            if label == XEDDSA_DOMAIN {
                assert_eq!(nuls, 1);
                assert_eq!(label.last(), Some(&0u8));
            } else {
                assert_eq!(nuls, 0, "unexpected NUL in a label");
            }
        }
    }

    #[test]
    fn sig_context_maps_onto_the_registry_injectively() {
        let bytes: [&[u8]; 3] = [
            SigContext::SignedPrekey.as_bytes(),
            SigContext::PqSignedPrekey.as_bytes(),
            SigContext::Enrolment.as_bytes(),
        ];
        assert_eq!(bytes[0], CTX_SPK);
        assert_eq!(bytes[1], CTX_PQSPK);
        assert_eq!(bytes[2], CTX_ENROLMENT);
        for (i, a) in bytes.iter().enumerate() {
            for b in bytes.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        assert_eq!(SigContext::ALL.len(), bytes.len());
    }

    /// Every context fits ML-DSA-65's 255-byte context bound (spec M1 §E.3).
    #[test]
    fn every_context_fits_the_ml_dsa_context_bound() {
        for ctx in SigContext::ALL {
            assert!(ctx.as_bytes().len() <= 255);
        }
    }
}
