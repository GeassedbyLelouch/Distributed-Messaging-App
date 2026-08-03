//! `EnrolmentProof` — the credential that makes scarcity checkable locally
//! (spec M1 §F, parent §4.3, §6.2).
//!
//! ```text
//! "e"   uint      issuer epoch
//! "k"   uint      issuer_key_id (u32)
//! "na"  uint      not_after_ms (u64)
//! "s"   bstr      HybridSignature
//! "sj"  bstr(32)  subject: IdentityId
//! "t"   uint      tier (u8)
//! "v"   uint      version == 0x0200
//! ```
//!
//! `"s"` signs `signed_msg` with `ctx = "MLKEMBraid/ctx/enrolment/v2"` and
//! `payload = canonical(EnrolmentProof without "s")` — the omission rule being
//! M1 §B.3, so the key is absent rather than null.
//!
//! Two things this module deliberately does **not** do, both from M1 §F:
//!
//! - it does not check expiry. `not_after_ms` is compared by the caller, which
//!   owns the clock; giving this crate one would breach parent §11 gate 6.
//! - it does not resolve `issuer_key_id` to a key. Issuer public keys ship as
//!   a pinned set in the client binary, so there is no fetch and no
//!   substitution surface; selection is `mlkb-policy`'s.

use alloc::boxed::Box;

use mlkb_codec::{CanonicalBytes, CanonicalMap, Value};
use mlkb_crypto::{HybridSignature, SigContext};
use mlkb_secrets::ProtocolError;

use crate::PROTOCOL_VERSION;
use crate::identity::IdentityId;
use crate::util;

const KEY_ISSUER_EPOCH: &str = "e";
const KEY_ISSUER_KEY_ID: &str = "k";
const KEY_NOT_AFTER_MS: &str = "na";
const KEY_SIGNATURE: &str = "s";
const KEY_SUBJECT: &str = "sj";
const KEY_TIER: &str = "t";

/// A signed statement that a subject was admitted (spec M1 §F).
///
/// `Voucher` at the FFI boundary (parent §10.3) **is** this structure,
/// serialized. It is explicitly not a bare enum: parent §10.3 warns that an
/// enum with no signature is not scarcity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnrolmentProof {
    /// The issuer's epoch.
    pub issuer_epoch: u64,
    /// Which pinned issuer key signed this (spec M1 §F).
    pub issuer_key_id: u32,
    /// Expiry, in milliseconds since the Unix epoch (M1 §B.5). Compared by the
    /// caller.
    pub not_after_ms: u64,
    /// The admitted identity.
    pub subject: IdentityId,
    /// Attestation-backed vs. rate-limit-backed enrolment (spec M1 §F).
    pub tier: u8,
    /// The hybrid signature over [`EnrolmentProof::signed_payload`].
    ///
    /// Boxed: a `HybridSignature` is ~3.4 KB, and a `PrekeyBundleV2` carries
    /// three of them (M1 §G.4 — this subtree is built for
    /// `thumbv7em-none-eabi`).
    pub signature: Box<HybridSignature>,
}

impl EnrolmentProof {
    /// The signature context this proof is signed under (spec M1 §E.2).
    ///
    /// Naming it here is what stops a signed prekey being lifted into an
    /// enrolment slot: the caller cannot spell a context of its own.
    pub const CONTEXT: SigContext = SigContext::Enrolment;

    /// The protocol version, a constant of the format (parent §3.1).
    #[must_use]
    pub fn version(&self) -> u16 {
        PROTOCOL_VERSION
    }

    /// The CBOR map of M1 §F, signature included.
    pub(crate) fn to_map(&self) -> Result<CanonicalMap, ProtocolError> {
        let mut m = CanonicalMap::new();
        util::put(&mut m, KEY_ISSUER_EPOCH, Value::Uint(self.issuer_epoch))?;
        util::put(
            &mut m,
            KEY_ISSUER_KEY_ID,
            Value::Uint(u64::from(self.issuer_key_id)),
        )?;
        util::put(&mut m, KEY_NOT_AFTER_MS, Value::Uint(self.not_after_ms))?;
        util::put(
            &mut m,
            KEY_SIGNATURE,
            Value::Bytes(self.signature.to_bytes()),
        )?;
        util::put(
            &mut m,
            KEY_SUBJECT,
            Value::Bytes(self.subject.as_bytes().to_vec()),
        )?;
        util::put(&mut m, KEY_TIER, Value::Uint(u64::from(self.tier)))?;
        util::put_version(&mut m)?;
        Ok(m)
    }

    /// `canonical(EnrolmentProof)`.
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only; see `util::encode`.
    pub fn encode(&self) -> Result<CanonicalBytes, ProtocolError> {
        util::encode(&Value::Map(self.to_map()?))
    }

    /// `canonical(EnrolmentProof without "s")` — the signed payload of
    /// M1 §F.
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only.
    pub fn signed_payload(&self) -> Result<CanonicalBytes, ProtocolError> {
        let mut m = self.to_map()?;
        m.remove(KEY_SIGNATURE);
        util::encode(&Value::Map(m))
    }

    /// Parses `canonical(EnrolmentProof)` (spec M1 §F).
    ///
    /// The `"s"` field is parsed as a `HybridSignature`, so M1 §E.1's checks —
    /// `version == 0x0200`, `suite == 0x0001`, both length prefixes equal to
    /// the suite's fixed sizes, no trailing bytes — all happen here, **before
    /// any cryptographic work**.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::from_map(util::decode_map(bytes)?)
    }

    /// Parses the map form, for the nested use inside a `PrekeyBundleV2`.
    pub(crate) fn from_map(mut m: CanonicalMap) -> Result<Self, ProtocolError> {
        util::take_version(&mut m)?;
        let issuer_epoch = util::as_uint(util::take(&mut m, KEY_ISSUER_EPOCH)?)?;
        let issuer_key_id = util::as_u32(util::take(&mut m, KEY_ISSUER_KEY_ID)?)?;
        let not_after_ms = util::as_uint(util::take(&mut m, KEY_NOT_AFTER_MS)?)?;
        let signature =
            HybridSignature::from_bytes(&util::as_vec(util::take(&mut m, KEY_SIGNATURE)?)?)?;
        let subject =
            IdentityId::from_bytes(util::as_array::<32>(util::take(&mut m, KEY_SUBJECT)?)?);
        let tier = util::as_u8(util::take(&mut m, KEY_TIER)?)?;
        util::finish(&m)?;

        Ok(Self {
            issuer_epoch,
            issuer_key_id,
            not_after_ms,
            subject,
            tier,
            signature: Box::new(signature),
        })
    }
}

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
    use crate::testkit::{corrupt_cases, sample_enrolment};
    use mlkb_codec::{decode_canonical, encode_canonical};
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn f_round_trips() {
        let proof = sample_enrolment();
        let bytes = proof.encode().unwrap();
        assert_eq!(EnrolmentProof::decode(bytes.as_bytes()).unwrap(), proof);
        assert_eq!(proof.version(), PROTOCOL_VERSION);
    }

    #[test]
    fn f_uses_exactly_the_specified_map_keys() {
        let proof = sample_enrolment();
        let value = decode_canonical(proof.encode().unwrap().as_bytes()).unwrap();
        let keys: Vec<&str> = value.as_map().unwrap().iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["e", "k", "s", "t", "v", "na", "sj"]);
    }

    #[test]
    fn f_signed_payload_is_the_map_without_the_signature() {
        let proof = sample_enrolment();
        let payload = proof.signed_payload().unwrap();
        let value = decode_canonical(payload.as_bytes()).unwrap();
        assert!(!value.as_map().unwrap().contains_key("s"));
        assert_eq!(value.as_map().unwrap().len(), 6);
        assert_eq!(EnrolmentProof::CONTEXT, SigContext::Enrolment);

        // Every signed field is inside the payload, so none of them can be
        // altered without invalidating the signature.
        let mut other = proof.clone();
        other.tier = 9;
        assert_ne!(other.signed_payload().unwrap(), payload);
        let mut other = proof.clone();
        other.subject = IdentityId::from_bytes([0xee; 32]);
        assert_ne!(other.signed_payload().unwrap(), payload);
        let mut other = proof.clone();
        other.not_after_ms = 1;
        assert_ne!(other.signed_payload().unwrap(), payload);
    }

    #[test]
    fn hostile_inputs_are_rejected() {
        let good = sample_enrolment().encode().unwrap().into_vec();
        for (name, bytes) in corrupt_cases(&good) {
            assert_eq!(
                EnrolmentProof::decode(&bytes),
                Err(ProtocolError::Malformed),
                "{name} must be refused"
            );
        }
    }

    #[test]
    fn e1_a_bad_hybrid_signature_is_refused_by_the_parser() {
        let proof = sample_enrolment();
        let good = proof.signature.to_bytes();
        for (name, mut sig) in [
            ("truncated", good[..good.len() - 1].to_vec()),
            ("extended", {
                let mut v = good.clone();
                v.push(0);
                v
            }),
            ("empty", Vec::new()),
        ] {
            if name == "truncated" {
                sig.truncate(good.len() - 1);
            }
            let mut m = proof.to_map().unwrap();
            m.remove("s");
            m.insert("s", Value::Bytes(sig)).unwrap();
            let bytes = encode_canonical(&Value::Map(m)).unwrap();
            assert_eq!(
                EnrolmentProof::decode(bytes.as_bytes()),
                Err(ProtocolError::Malformed),
                "{name} signature must be refused"
            );
        }

        // A wrong suite or version in the signature header, likewise. Each
        // pair below really does change the byte: `version` is `02 00` and
        // `suite` is `00 01`, so the substitutions are 0x0300, 0x0201, 0x0101
        // and 0x0002 — none of them the one registered value.
        for (offset, byte) in [(0usize, 0x03u8), (1, 0x01), (2, 0x01), (3, 0x02)] {
            let mut sig = good.clone();
            sig[offset] = byte;
            let mut m = proof.to_map().unwrap();
            m.remove("s");
            m.insert("s", Value::Bytes(sig)).unwrap();
            let bytes = encode_canonical(&Value::Map(m)).unwrap();
            assert_eq!(
                EnrolmentProof::decode(bytes.as_bytes()),
                Err(ProtocolError::Malformed),
                "signature byte {offset} = {byte:#04x} must be refused"
            );
        }
    }

    #[test]
    fn a_wrong_version_or_an_unknown_key_is_refused() {
        let proof = sample_enrolment();

        let mut m = proof.to_map().unwrap();
        m.remove("v");
        m.insert("v", Value::Uint(0x0100)).unwrap();
        let bytes = encode_canonical(&Value::Map(m)).unwrap();
        assert_eq!(
            EnrolmentProof::decode(bytes.as_bytes()),
            Err(ProtocolError::Malformed)
        );

        let mut m = proof.to_map().unwrap();
        m.insert("zz", Value::Uint(0)).unwrap();
        let bytes = encode_canonical(&Value::Map(m)).unwrap();
        assert_eq!(
            EnrolmentProof::decode(bytes.as_bytes()),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn out_of_range_scalars_are_refused() {
        let proof = sample_enrolment();
        for (key, value) in [
            ("t", Value::Uint(256)),
            ("k", Value::Uint(u64::from(u32::MAX) + 1)),
        ] {
            let mut m = proof.to_map().unwrap();
            m.remove(key);
            m.insert(key, value).unwrap();
            let bytes = encode_canonical(&Value::Map(m)).unwrap();
            assert_eq!(
                EnrolmentProof::decode(bytes.as_bytes()),
                Err(ProtocolError::Malformed),
                "{key} out of range must be refused"
            );
        }
    }
}
