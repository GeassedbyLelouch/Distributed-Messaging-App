//! The two domain tags this crate needs that `mlkb_crypto::labels` does not
//! carry (spec parent §3.3, §3.5, M1 §I.2).
//!
//! # Why they are here and not there
//!
//! M1 §I.2 is the closed label registry and says no crate may spell one of its
//! byte strings outside `mlkb-crypto`'s `labels` module. Two literals the
//! parent spec defines are nevertheless absent from that module as it stands:
//!
//! - `MLKEMBraid/frame/v2` (parent §3.3, M1 §I.2 row 9) — the frame MAC
//!   preimage prefix. `mlkb-crypto` writes it in a doc comment on
//!   `FrameKey::mac` and states there that the preimage is `mlkb-wire`'s to
//!   build, but exports no constant for it.
//! - `MLKEMBraid/identity/v2` (parent §3.5) — the `IdentityId` hash tag. It is
//!   in neither the parent's §4.4 table nor M1 §I.2, because it is a hash
//!   domain tag rather than an HKDF label; `mlkb-crypto` treats `IdentityId`s
//!   as opaque 32-byte strings and documents that this crate computes them.
//!
//! Since this crate cannot mint them by any other route, they are spelled once
//! here. **This is a divergence from M1 §I.2's "one home" rule, not a second
//! spelling**: neither string appears anywhere else in the workspace. The
//! right fix is to move both into `mlkb_crypto::labels` when that crate is
//! next edited and re-export them from here; until then this module is the one
//! definition, and adding a third literal of either string is the defect M1
//! §I.2 exists to prevent.
//!
//! Encoding of a label, as M1 §E.2 states for the whole project: the literal
//! ASCII bytes shown, with no terminator and no length prefix.

/// The frame MAC preimage prefix (spec parent §3.3, M1 §A.1, §I.2).
///
/// ```text
/// frame_mac = HMAC-SHA256(K_frame_dir, "MLKEMBraid/frame/v2" || wire[0 .. 15 + payload_len])
/// ```
pub const FRAME_MAC: &[u8] = b"MLKEMBraid/frame/v2";

/// The `IdentityId` hash domain tag (spec parent §3.5).
///
/// ```text
/// IdentityId = SHA-256("MLKEMBraid/identity/v2" || ik_x25519 || SHA-256(ik_mldsa65_pk))
/// ```
pub const IDENTITY: &[u8] = b"MLKEMBraid/identity/v2";
