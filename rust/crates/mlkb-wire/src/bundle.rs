//! `PrekeyBundleV2` and its parts (spec parent §4.3, M1 §C.3, §E.2, §F).
//!
//! ```text
//! PrekeyBundleV2
//!   "ea"  uint   expires_at_ms          "ot"  map   one_time      (optional)
//!   "en"  map    enrolment              "pq"  map   pq_prekey
//!   "id"  map    identity               "sp"  map   signed_prekey
//!   "v"   uint   version
//!
//! HybridIdentityPublic     SignedPrekey        SignedPqPrekey     OneTimePrekey
//!   "ik" bstr(32)            "id" uint           "ek" bstr(1568)    "id" uint
//!   "md" bstr(1952)          "p"  bstr(32)       "id" uint          "p"  bstr(32)
//!                            "s"  bstr           "s"  bstr
//! ```
//!
//! # A recorded gap, not a silent choice
//!
//! Parent §4.3 gives this structure's *fields*; unlike `InitialMessageV2`
//! (M1 §C.3) and `EnrolmentProof` (M1 §F), **no normative document assigns its
//! CBOR map keys**, and none assigns the signed payload of a prekey signature
//! either. The names above and the `canonical(<part> without "s")` payload
//! rule below are this crate's, chosen by analogy with the two structures that
//! *are* pinned, and they need ratifying before an interoperating
//! implementation exists. Until then they are normative by being the only
//! definition — which is the position M1 §I.2 takes for `K_store` and for the
//! same reason.
//!
//! Two things about them are not free choices:
//!
//! - each part's signature covers its own `id`. Leaving the id out would let
//!   a signed prekey be replayed into another slot, which is the substitution
//!   M1 §E.2's context registry exists to prevent — the context separates
//!   *kinds* of prekey, the id separates *instances*.
//! - `SignedPqPrekey` carries an `id`, per M1 §C.3: `InitialMessageV2.pqspk_id`
//!   selects it, and without the id a responder with rotating PQ prekeys
//!   cannot pick the decapsulation key.
//!
//! Every signature in a bundle is verified **before any key in it is used**
//! (parent §4.3). This crate parses; `mlkb-protocol` verifies.

use alloc::boxed::Box;

use mlkb_codec::{CanonicalBytes, CanonicalMap, Value};
use mlkb_crypto::{
    HybridSignature, KEM_ENCAPSULATION_KEY_LEN, MLDSA_VERIFYING_KEY_LEN, SigContext,
};
use mlkb_secrets::ProtocolError;

use crate::PROTOCOL_VERSION;
use crate::enrolment::EnrolmentProof;
use crate::identity::IdentityId;
use crate::util;

const KEY_EXPIRES_AT_MS: &str = "ea";
const KEY_ENROLMENT: &str = "en";
const KEY_IDENTITY: &str = "id";
const KEY_ONE_TIME: &str = "ot";
const KEY_PQ_PREKEY: &str = "pq";
const KEY_SIGNED_PREKEY: &str = "sp";

const KEY_IK_X25519: &str = "ik";
const KEY_IK_MLDSA: &str = "md";

const KEY_ID: &str = "id";
const KEY_PUBLIC: &str = "p";
const KEY_EK: &str = "ek";
const KEY_SIGNATURE: &str = "s";

/// A peer's long-term public identity (spec parent §3.5, §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridIdentityPublic {
    /// The X25519 identity key — also the XEdDSA verification key.
    pub ik_x25519: [u8; 32],
    /// The ML-DSA-65 public key — 1952 bytes, by type (M1 §H). Boxed to keep
    /// the aggregate off a `thumbv7em-none-eabi` stack (M1 §G.4).
    pub ik_mldsa: Box<[u8; MLDSA_VERIFYING_KEY_LEN]>,
}

impl HybridIdentityPublic {
    /// The identity this key pair denotes (spec parent §3.5).
    ///
    /// A responder compares this against `InitialMessageV2.ik_mldsa_hash`
    /// before using the ML-DSA key (parent §3.4); computing the id from the
    /// full key here and from the hash there is what makes the comparison
    /// meaningful.
    #[must_use]
    pub fn identity_id(&self) -> IdentityId {
        IdentityId::from_public_keys(&self.ik_x25519, self.ik_mldsa.as_slice())
    }

    fn to_map(&self) -> Result<CanonicalMap, ProtocolError> {
        let mut m = CanonicalMap::new();
        util::put(&mut m, KEY_IK_X25519, Value::Bytes(self.ik_x25519.to_vec()))?;
        util::put(
            &mut m,
            KEY_IK_MLDSA,
            Value::Bytes(self.ik_mldsa.as_slice().to_vec()),
        )?;
        Ok(m)
    }

    fn from_map(mut m: CanonicalMap) -> Result<Self, ProtocolError> {
        let ik_x25519 = util::as_array::<32>(util::take(&mut m, KEY_IK_X25519)?)?;
        let ik_mldsa =
            util::as_boxed_array::<MLDSA_VERIFYING_KEY_LEN>(util::take(&mut m, KEY_IK_MLDSA)?)?;
        util::finish(&m)?;
        Ok(Self {
            ik_x25519,
            ik_mldsa,
        })
    }
}

/// The signed X25519 prekey (spec parent §4.3, M1 §E.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPrekey {
    /// The id `InitialMessageV2.spk_id` selects.
    pub id: u32,
    /// The X25519 public key.
    pub public: [u8; 32],
    /// The hybrid signature over [`SignedPrekey::signed_payload`].
    pub signature: Box<HybridSignature>,
}

impl SignedPrekey {
    /// The signature context (spec M1 §E.2): `MLKEMBraid/ctx/spk/v2`.
    pub const CONTEXT: SigContext = SigContext::SignedPrekey;

    fn to_map(&self) -> Result<CanonicalMap, ProtocolError> {
        let mut m = CanonicalMap::new();
        util::put(&mut m, KEY_ID, Value::Uint(u64::from(self.id)))?;
        util::put(&mut m, KEY_PUBLIC, Value::Bytes(self.public.to_vec()))?;
        util::put(
            &mut m,
            KEY_SIGNATURE,
            Value::Bytes(self.signature.to_bytes()),
        )?;
        Ok(m)
    }

    /// `canonical(SignedPrekey without "s")` — what the signature covers.
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only.
    pub fn signed_payload(&self) -> Result<CanonicalBytes, ProtocolError> {
        let mut m = self.to_map()?;
        m.remove(KEY_SIGNATURE);
        util::encode(&Value::Map(m))
    }

    fn from_map(mut m: CanonicalMap) -> Result<Self, ProtocolError> {
        let id = util::as_u32(util::take(&mut m, KEY_ID)?)?;
        let public = util::as_array::<32>(util::take(&mut m, KEY_PUBLIC)?)?;
        let signature =
            HybridSignature::from_bytes(&util::as_vec(util::take(&mut m, KEY_SIGNATURE)?)?)?;
        util::finish(&m)?;
        Ok(Self {
            id,
            public,
            signature: Box::new(signature),
        })
    }
}

/// The signed ML-KEM-1024 prekey — the last-resort PQ contribution
/// (spec parent §4.3, M1 §C.3, §E.2).
///
/// This is why OPK exhaustion is a bounded forward-secrecy degradation and
/// **not** a PQ downgrade: the PQ leg is always present and always signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedPqPrekey {
    /// The id `InitialMessageV2.pqspk_id` selects (spec M1 §C.3).
    pub id: u32,
    /// The ML-KEM-1024 encapsulation key — 1568 bytes, by type.
    pub ek: Box<[u8; KEM_ENCAPSULATION_KEY_LEN]>,
    /// The hybrid signature over [`SignedPqPrekey::signed_payload`].
    pub signature: Box<HybridSignature>,
}

impl SignedPqPrekey {
    /// The signature context (spec M1 §E.2): `MLKEMBraid/ctx/pqspk/v2`.
    pub const CONTEXT: SigContext = SigContext::PqSignedPrekey;

    fn to_map(&self) -> Result<CanonicalMap, ProtocolError> {
        let mut m = CanonicalMap::new();
        util::put(&mut m, KEY_EK, Value::Bytes(self.ek.as_slice().to_vec()))?;
        util::put(&mut m, KEY_ID, Value::Uint(u64::from(self.id)))?;
        util::put(
            &mut m,
            KEY_SIGNATURE,
            Value::Bytes(self.signature.to_bytes()),
        )?;
        Ok(m)
    }

    /// `canonical(SignedPqPrekey without "s")` — what the signature covers.
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only.
    pub fn signed_payload(&self) -> Result<CanonicalBytes, ProtocolError> {
        let mut m = self.to_map()?;
        m.remove(KEY_SIGNATURE);
        util::encode(&Value::Map(m))
    }

    fn from_map(mut m: CanonicalMap) -> Result<Self, ProtocolError> {
        let ek = util::as_boxed_array::<KEM_ENCAPSULATION_KEY_LEN>(util::take(&mut m, KEY_EK)?)?;
        let id = util::as_u32(util::take(&mut m, KEY_ID)?)?;
        let signature =
            HybridSignature::from_bytes(&util::as_vec(util::take(&mut m, KEY_SIGNATURE)?)?)?;
        util::finish(&m)?;
        Ok(Self {
            id,
            ek,
            signature: Box::new(signature),
        })
    }
}

/// A one-time X25519 prekey — unsigned, as in standard X3DH
/// (spec parent §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneTimePrekey {
    /// The id `InitialMessageV2.opk_id` carries back.
    pub id: u32,
    /// The X25519 public key.
    pub public: [u8; 32],
}

impl OneTimePrekey {
    fn to_map(&self) -> Result<CanonicalMap, ProtocolError> {
        let mut m = CanonicalMap::new();
        util::put(&mut m, KEY_ID, Value::Uint(u64::from(self.id)))?;
        util::put(&mut m, KEY_PUBLIC, Value::Bytes(self.public.to_vec()))?;
        Ok(m)
    }

    fn from_map(mut m: CanonicalMap) -> Result<Self, ProtocolError> {
        let id = util::as_u32(util::take(&mut m, KEY_ID)?)?;
        let public = util::as_array::<32>(util::take(&mut m, KEY_PUBLIC)?)?;
        util::finish(&m)?;
        Ok(Self { id, public })
    }
}

/// Everything a peer needs to start a PQXDH handshake (spec parent §4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrekeyBundleV2 {
    /// The owner's hybrid public identity.
    pub identity: HybridIdentityPublic,
    /// The signed X25519 prekey.
    pub signed_prekey: SignedPrekey,
    /// The signed ML-KEM-1024 prekey (last-resort PQ contribution).
    pub pq_prekey: SignedPqPrekey,
    /// A one-time prekey, if the pool was not exhausted.
    ///
    /// Absent means the last-resort path, and M1 §B.3 means the key is simply
    /// not in the map — there is no `null` for a peer to misread as "present
    /// but empty".
    pub one_time: Option<OneTimePrekey>,
    /// The enrolment proof, so a peer can verify scarcity locally
    /// (parent §6.2).
    pub enrolment: EnrolmentProof,
    /// Expiry, in milliseconds since the Unix epoch. Compared by the caller,
    /// which owns the clock (`BUNDLE_MAX_AGE_MS`, M1 §I).
    pub expires_at_ms: u64,
}

impl PrekeyBundleV2 {
    /// The protocol version, a constant of the format (parent §3.1).
    #[must_use]
    pub fn version(&self) -> u16 {
        PROTOCOL_VERSION
    }

    /// The bundle owner's identity (spec parent §3.5).
    #[must_use]
    pub fn identity_id(&self) -> IdentityId {
        self.identity.identity_id()
    }

    fn to_map(&self) -> Result<CanonicalMap, ProtocolError> {
        let mut m = CanonicalMap::new();
        util::put(&mut m, KEY_EXPIRES_AT_MS, Value::Uint(self.expires_at_ms))?;
        util::put(&mut m, KEY_ENROLMENT, Value::Map(self.enrolment.to_map()?))?;
        util::put(&mut m, KEY_IDENTITY, Value::Map(self.identity.to_map()?))?;
        let one_time = match self.one_time.as_ref() {
            Some(opk) => Some(Value::Map(opk.to_map()?)),
            None => None,
        };
        util::put_opt(&mut m, KEY_ONE_TIME, one_time)?;
        util::put(&mut m, KEY_PQ_PREKEY, Value::Map(self.pq_prekey.to_map()?))?;
        util::put(
            &mut m,
            KEY_SIGNED_PREKEY,
            Value::Map(self.signed_prekey.to_map()?),
        )?;
        util::put_version(&mut m)?;
        Ok(m)
    }

    /// `canonical(PrekeyBundleV2)`.
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only; see `util::encode`.
    pub fn encode(&self) -> Result<CanonicalBytes, ProtocolError> {
        util::encode(&Value::Map(self.to_map()?))
    }

    /// Parses `canonical(PrekeyBundleV2)`.
    ///
    /// Every nested structure is parsed by the same rules as a top-level one:
    /// exact widths, no unknown keys, and each `HybridSignature` checked
    /// against M1 §E.1 before any cryptographic work.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut m = util::decode_map(bytes)?;
        util::take_version(&mut m)?;

        let expires_at_ms = util::as_uint(util::take(&mut m, KEY_EXPIRES_AT_MS)?)?;
        let enrolment =
            EnrolmentProof::from_map(util::into_map(util::take(&mut m, KEY_ENROLMENT)?)?)?;
        let identity =
            HybridIdentityPublic::from_map(util::into_map(util::take(&mut m, KEY_IDENTITY)?)?)?;
        let one_time = match util::take_opt(&mut m, KEY_ONE_TIME) {
            Some(v) => Some(OneTimePrekey::from_map(util::into_map(v)?)?),
            None => None,
        };
        let pq_prekey =
            SignedPqPrekey::from_map(util::into_map(util::take(&mut m, KEY_PQ_PREKEY)?)?)?;
        let signed_prekey =
            SignedPrekey::from_map(util::into_map(util::take(&mut m, KEY_SIGNED_PREKEY)?)?)?;
        util::finish(&m)?;

        Ok(Self {
            identity,
            signed_prekey,
            pq_prekey,
            one_time,
            enrolment,
            expires_at_ms,
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
    use crate::testkit::{corrupt_cases, sample_bundle};
    use mlkb_codec::{decode_canonical, encode_canonical};
    use std::vec;
    use std::vec::Vec;

    fn encoded(bundle: &PrekeyBundleV2) -> Vec<u8> {
        bundle.encode().unwrap().into_vec()
    }

    #[test]
    fn round_trips_with_and_without_a_one_time_prekey() {
        for with_opk in [true, false] {
            let bundle = sample_bundle(with_opk);
            let bytes = encoded(&bundle);
            assert_eq!(PrekeyBundleV2::decode(&bytes).unwrap(), bundle);
            assert_eq!(bundle.version(), PROTOCOL_VERSION);
        }
    }

    #[test]
    fn map_keys_and_nesting_are_the_documented_ones() {
        let bundle = sample_bundle(true);
        let value = decode_canonical(&encoded(&bundle)).unwrap();
        let map = value.as_map().unwrap();
        let keys: Vec<&str> = map.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["v", "ea", "en", "id", "ot", "pq", "sp"]);

        let ident: Vec<&str> = map
            .get("id")
            .unwrap()
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(ident, vec!["ik", "md"]);

        let sp: Vec<&str> = map
            .get("sp")
            .unwrap()
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(sp, vec!["p", "s", "id"]);

        let pq: Vec<&str> = map
            .get("pq")
            .unwrap()
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, _)| k)
            .collect();
        assert_eq!(pq, vec!["s", "ek", "id"]);
    }

    #[test]
    fn b3_an_absent_one_time_prekey_omits_the_key() {
        let bytes = encoded(&sample_bundle(false));
        let value = decode_canonical(&bytes).unwrap();
        assert!(!value.as_map().unwrap().contains_key("ot"));
        assert!(!bytes.contains(&0xf6), "a CBOR null was emitted");
    }

    #[test]
    fn signed_payloads_cover_the_id_and_the_key_but_not_the_signature() {
        let bundle = sample_bundle(true);

        let sp = bundle.signed_prekey.signed_payload().unwrap();
        let m = decode_canonical(sp.as_bytes()).unwrap();
        assert!(!m.as_map().unwrap().contains_key("s"));
        assert!(m.as_map().unwrap().contains_key("id"));
        assert!(m.as_map().unwrap().contains_key("p"));

        let pq = bundle.pq_prekey.signed_payload().unwrap();
        let m = decode_canonical(pq.as_bytes()).unwrap();
        assert!(!m.as_map().unwrap().contains_key("s"));
        assert!(m.as_map().unwrap().contains_key("id"));
        assert!(m.as_map().unwrap().contains_key("ek"));

        // Changing the id changes the signed bytes — that is what stops a
        // prekey being replayed into another slot.
        let mut other = bundle.signed_prekey.clone();
        other.id = other.id.wrapping_add(1);
        assert_ne!(other.signed_payload().unwrap(), sp);

        // The three contexts are distinct, so a prekey signature cannot be
        // lifted into another kind of slot either (M1 §E.2).
        assert_ne!(SignedPrekey::CONTEXT, SignedPqPrekey::CONTEXT);
        assert_ne!(SignedPrekey::CONTEXT, EnrolmentProof::CONTEXT);
    }

    #[test]
    fn identity_id_agrees_with_the_hash_form() {
        let bundle = sample_bundle(true);
        assert_eq!(
            bundle.identity_id(),
            IdentityId::from_public_keys(
                &bundle.identity.ik_x25519,
                bundle.identity.ik_mldsa.as_slice()
            )
        );
    }

    #[test]
    fn hostile_inputs_are_rejected() {
        let good = encoded(&sample_bundle(true));
        for (name, bytes) in corrupt_cases(&good) {
            assert_eq!(
                PrekeyBundleV2::decode(&bytes),
                Err(ProtocolError::Malformed),
                "{name} must be refused"
            );
        }
    }

    #[test]
    fn a_missing_or_unknown_nested_key_is_refused() {
        let bundle = sample_bundle(true);

        // a missing mandatory part
        for key in ["ea", "en", "id", "pq", "sp", "v"] {
            let mut m = bundle.to_map().unwrap();
            m.remove(key);
            let bytes = encode_canonical(&Value::Map(m)).unwrap();
            assert_eq!(
                PrekeyBundleV2::decode(bytes.as_bytes()),
                Err(ProtocolError::Malformed),
                "a bundle without {key} must be refused"
            );
        }

        // an unknown key, at the top level and one level down
        let mut m = bundle.to_map().unwrap();
        m.insert("zz", Value::Uint(0)).unwrap();
        let bytes = encode_canonical(&Value::Map(m)).unwrap();
        assert_eq!(
            PrekeyBundleV2::decode(bytes.as_bytes()),
            Err(ProtocolError::Malformed)
        );

        let mut m = bundle.to_map().unwrap();
        let mut inner = m.remove("id").unwrap().as_map().unwrap().clone();
        inner.insert("zz", Value::Uint(0)).unwrap();
        m.insert("id", Value::Map(inner)).unwrap();
        let bytes = encode_canonical(&Value::Map(m)).unwrap();
        assert_eq!(
            PrekeyBundleV2::decode(bytes.as_bytes()),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn a_nested_part_of_the_wrong_shape_is_refused() {
        let bundle = sample_bundle(true);
        for key in ["en", "id", "ot", "pq", "sp"] {
            let mut m = bundle.to_map().unwrap();
            m.remove(key);
            m.insert(key, Value::Uint(0)).unwrap();
            let bytes = encode_canonical(&Value::Map(m)).unwrap();
            assert_eq!(
                PrekeyBundleV2::decode(bytes.as_bytes()),
                Err(ProtocolError::Malformed),
                "{key} as a non-map must be refused"
            );
        }
    }

    #[test]
    fn a_wrong_key_width_anywhere_is_refused() {
        let bundle = sample_bundle(true);
        for (part, key, len) in [
            ("id", "ik", 31usize),
            ("id", "md", MLDSA_VERIFYING_KEY_LEN - 1),
            ("id", "md", MLDSA_VERIFYING_KEY_LEN + 1),
            ("sp", "p", 33),
            ("pq", "ek", KEM_ENCAPSULATION_KEY_LEN - 1),
            ("ot", "p", 0),
        ] {
            let mut m = bundle.to_map().unwrap();
            let mut inner = m.remove(part).unwrap().as_map().unwrap().clone();
            inner.remove(key);
            inner.insert(key, Value::Bytes(vec![0u8; len])).unwrap();
            m.insert(part, Value::Map(inner)).unwrap();
            let bytes = encode_canonical(&Value::Map(m)).unwrap();
            assert_eq!(
                PrekeyBundleV2::decode(bytes.as_bytes()),
                Err(ProtocolError::Malformed),
                "{part}.{key} at {len} bytes must be refused"
            );
        }
    }
}
