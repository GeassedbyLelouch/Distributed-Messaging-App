//! `InitialMessageV2` — the PQXDH handshake payload (spec M1 §C.3, parent
//! §3.4, §4.2).
//!
//! ```text
//! "c"    bstr(32)   confirm            "sid"  uint(u32)  spk_id
//! "ct"   bstr(1568) kem_ct             "sq"   uint(u64)  handshake_seq
//! "ek"   bstr(32)   ek_x25519          "td"   uint(u32)  to_device_id
//! "ih"   bstr(32)   ik_mldsa_hash      "v"    uint(u16)  version
//! "ik"   bstr(32)   ik_x25519
//! "oid"  uint(u32)  opk_id             (absent when no OPK was claimed)
//! "pid"  uint(u32)  pqspk_id
//! ```
//!
//! The keys are fixed forever by M1 §C.3's table. They are short on purpose:
//! this is a ~1.7 KB structure pushed to mobile devices.
//!
//! Two of the fields exist because the parent's §3.4 could not be implemented
//! without them, and neither is fixable later:
//!
//! - **`pqspk_id`** identifies the ML-KEM prekey `kem_ct` was encapsulated to.
//!   Without it a responder holding more than one PQ prekey — which it must,
//!   during any rotation — cannot select the decapsulation key.
//! - **`to_device_id`** (the parent's `device_id`, renamed) is the *responder*
//!   device the handshake is addressed to, because parent §6.3 keys the replay
//!   floor on it and the responder must be able to compute that key from the
//!   message alone. The initiator's own device is deliberately not on the
//!   wire: it is bound through `IdentityId` and the DH legs.

use alloc::boxed::Box;

use mlkb_codec::{CanonicalBytes, CanonicalMap, Value};
use mlkb_crypto::KEM_CIPHERTEXT_LEN;
use mlkb_secrets::ProtocolError;

use crate::PROTOCOL_VERSION;
use crate::identity::IdentityId;
use crate::util;

const KEY_CONFIRM: &str = "c";
const KEY_KEM_CT: &str = "ct";
const KEY_EK: &str = "ek";
const KEY_IK_MLDSA_HASH: &str = "ih";
const KEY_IK: &str = "ik";
const KEY_OPK_ID: &str = "oid";
const KEY_PQSPK_ID: &str = "pid";
const KEY_SPK_ID: &str = "sid";
const KEY_HANDSHAKE_SEQ: &str = "sq";
const KEY_TO_DEVICE_ID: &str = "td";

/// The PQXDH handshake message (spec M1 §C.3).
///
/// There is no `version` field: parent §3.1 fixes it, so it is a constant of
/// the format rather than something a caller can set or a decoder can carry
/// forward. Every other field is exact-width by type, so a decoded value
/// cannot be the wrong shape and no later code has to re-check one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialMessageV2 {
    /// The responder device this handshake is addressed to (spec M1 §C.3).
    pub to_device_id: u32,
    /// Monotonic per (initiator, responder device) — parent §6.3's replay
    /// floor.
    pub handshake_seq: u64,
    /// The initiator's long-term X25519 identity key. Also DH leg 1's input.
    pub ik_x25519: [u8; 32],
    /// `SHA-256` of the initiator's ML-DSA-65 public key (parent §3.4).
    pub ik_mldsa_hash: [u8; 32],
    /// The initiator's ephemeral X25519 key.
    pub ek_x25519: [u8; 32],
    /// The ML-KEM-1024 ciphertext — exactly 1568 bytes, by type (M1 §H).
    pub kem_ct: Box<[u8; KEM_CIPHERTEXT_LEN]>,
    /// Which signed prekey the initiator used.
    pub spk_id: u32,
    /// Which ML-KEM prekey `kem_ct` was encapsulated to (spec M1 §C.3).
    pub pqspk_id: u32,
    /// Which one-time prekey was claimed, if any.
    ///
    /// `None` is the last-resort path, and it is also what fixes the arity of
    /// `DhLegs`: M1 §C.1 omits `DH4` from the `ikm` entirely when this is
    /// `None` — it is never zero-filled. This field is inside the MAC preimage
    /// and inside the `confirm` preimage, so an attacker cannot flip it.
    pub opk_id: Option<u32>,
    /// `HMAC-SHA256(k_cf, canonical(InitialMessageV2 without confirm))`
    /// (parent §4.2).
    pub confirm: [u8; 32],
}

impl InitialMessageV2 {
    /// The protocol version, a constant of the format (parent §3.1).
    #[must_use]
    pub fn version(&self) -> u16 {
        PROTOCOL_VERSION
    }

    /// The initiator's identity, computed from this message alone
    /// (spec parent §3.5).
    ///
    /// This is why `IdentityId` hashes the ML-DSA key rather than embedding
    /// it: on first contact the responder has the message and nothing else.
    #[must_use]
    pub fn identity_id(&self) -> IdentityId {
        IdentityId::from_ik(&self.ik_x25519, &self.ik_mldsa_hash)
    }

    /// The CBOR map of M1 §C.3, `confirm` included.
    fn to_map(&self) -> Result<CanonicalMap, ProtocolError> {
        let mut m = CanonicalMap::new();
        util::put(&mut m, KEY_CONFIRM, Value::Bytes(self.confirm.to_vec()))?;
        util::put(
            &mut m,
            KEY_KEM_CT,
            Value::Bytes(self.kem_ct.as_slice().to_vec()),
        )?;
        util::put(&mut m, KEY_EK, Value::Bytes(self.ek_x25519.to_vec()))?;
        util::put(
            &mut m,
            KEY_IK_MLDSA_HASH,
            Value::Bytes(self.ik_mldsa_hash.to_vec()),
        )?;
        util::put(&mut m, KEY_IK, Value::Bytes(self.ik_x25519.to_vec()))?;
        // M1 §B.3: `None` omits the key entirely. There is no `null`.
        util::put_opt(
            &mut m,
            KEY_OPK_ID,
            self.opk_id.map(|id| Value::Uint(u64::from(id))),
        )?;
        util::put(&mut m, KEY_PQSPK_ID, Value::Uint(u64::from(self.pqspk_id)))?;
        util::put(&mut m, KEY_SPK_ID, Value::Uint(u64::from(self.spk_id)))?;
        util::put(&mut m, KEY_HANDSHAKE_SEQ, Value::Uint(self.handshake_seq))?;
        util::put(
            &mut m,
            KEY_TO_DEVICE_ID,
            Value::Uint(u64::from(self.to_device_id)),
        )?;
        util::put_version(&mut m)?;
        Ok(m)
    }

    /// `canonical(InitialMessageV2)` — the payload of a `0x01` frame
    /// (spec M1 §A.2, §C.3).
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only; see `util::encode`.
    pub fn encode(&self) -> Result<CanonicalBytes, ProtocolError> {
        util::encode(&Value::Map(self.to_map()?))
    }

    /// `canonical(InitialMessageV2 without confirm)` — the confirmation-tag
    /// preimage of parent §4.2.
    ///
    /// The omission rule is M1 §B.3: the `"c"` key is **absent**, never
    /// `null`, which keeps the preimage independent of `confirm`'s own width
    /// and leaves no encoding a verifier could mistake for "present but
    /// empty".
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only.
    pub fn confirm_preimage(&self) -> Result<CanonicalBytes, ProtocolError> {
        let mut m = self.to_map()?;
        m.remove(KEY_CONFIRM);
        util::encode(&Value::Map(m))
    }

    /// Parses `canonical(InitialMessageV2)` (spec M1 §C.3).
    ///
    /// Non-canonical CBOR is rejected rather than normalized (M1 §B.4), every
    /// width is checked by conversion, an unknown map key is a hard reject,
    /// and a `version` other than `0x0200` is refused before anything else is
    /// looked at.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] for every one of the above.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut m = util::decode_map(bytes)?;
        util::take_version(&mut m)?;

        let confirm = util::as_array::<32>(util::take(&mut m, KEY_CONFIRM)?)?;
        let kem_ct = util::as_boxed_array::<KEM_CIPHERTEXT_LEN>(util::take(&mut m, KEY_KEM_CT)?)?;
        let ek_x25519 = util::as_array::<32>(util::take(&mut m, KEY_EK)?)?;
        let ik_mldsa_hash = util::as_array::<32>(util::take(&mut m, KEY_IK_MLDSA_HASH)?)?;
        let ik_x25519 = util::as_array::<32>(util::take(&mut m, KEY_IK)?)?;
        let opk_id = match util::take_opt(&mut m, KEY_OPK_ID) {
            Some(v) => Some(util::as_u32(v)?),
            None => None,
        };
        let pqspk_id = util::as_u32(util::take(&mut m, KEY_PQSPK_ID)?)?;
        let spk_id = util::as_u32(util::take(&mut m, KEY_SPK_ID)?)?;
        let handshake_seq = util::as_uint(util::take(&mut m, KEY_HANDSHAKE_SEQ)?)?;
        let to_device_id = util::as_u32(util::take(&mut m, KEY_TO_DEVICE_ID)?)?;

        // Every key defined above has been removed, so anything left is a
        // field this structure does not define.
        util::finish(&m)?;

        Ok(Self {
            to_device_id,
            handshake_seq,
            ik_x25519,
            ik_mldsa_hash,
            ek_x25519,
            kem_ct,
            spk_id,
            pqspk_id,
            opk_id,
            confirm,
        })
    }
}

/// Every map key this structure defines, for the test that checks coverage.
#[cfg(test)]
const KEYS: [&str; 11] = [
    KEY_CONFIRM,
    KEY_KEM_CT,
    KEY_EK,
    KEY_IK_MLDSA_HASH,
    KEY_IK,
    KEY_OPK_ID,
    KEY_PQSPK_ID,
    KEY_SPK_ID,
    KEY_HANDSHAKE_SEQ,
    KEY_TO_DEVICE_ID,
    util::KEY_VERSION,
];

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
    use crate::testkit::{corrupt_cases, sample_initial};
    use mlkb_codec::decode_canonical;
    use std::vec::Vec;

    #[test]
    fn c3_round_trips_with_and_without_an_opk() {
        for opk in [None, Some(9u32)] {
            let msg = sample_initial(opk);
            let bytes = msg.encode().unwrap();
            let back = InitialMessageV2::decode(bytes.as_bytes()).unwrap();
            assert_eq!(back, msg);
            assert_eq!(back.version(), PROTOCOL_VERSION);
            assert_eq!(back.kem_ct.len(), KEM_CIPHERTEXT_LEN);
        }
    }

    #[test]
    fn c3_uses_exactly_the_specified_map_keys() {
        let msg = sample_initial(Some(3));
        let value = decode_canonical(msg.encode().unwrap().as_bytes()).unwrap();
        let map = value.as_map().unwrap();
        let keys: Vec<&str> = map.iter().map(|(k, _)| k).collect();
        // M1 §B.2 order: one-byte keys first, then two, then three.
        assert_eq!(
            keys,
            std::vec![
                "c", "v", "ct", "ek", "ih", "ik", "sq", "td", "oid", "pid", "sid"
            ]
        );
        for k in KEYS {
            assert!(map.contains_key(k), "missing {k}");
        }
    }

    #[test]
    fn b3_an_absent_opk_omits_the_key_and_never_emits_null() {
        let msg = sample_initial(None);
        let bytes = msg.encode().unwrap();
        let value = decode_canonical(bytes.as_bytes()).unwrap();
        assert!(!value.as_map().unwrap().contains_key("oid"));
        assert!(!bytes.as_bytes().contains(&0xf6), "a CBOR null was emitted");
        // and the map is one pair shorter than the OPK form
        assert_eq!(
            value.as_map().unwrap().len() + 1,
            decode_canonical(sample_initial(Some(1)).encode().unwrap().as_bytes())
                .unwrap()
                .as_map()
                .unwrap()
                .len()
        );
    }

    #[test]
    fn b3_confirm_preimage_is_the_map_with_the_key_removed() {
        let msg = sample_initial(Some(1));
        let preimage = msg.confirm_preimage().unwrap();
        let value = decode_canonical(preimage.as_bytes()).unwrap();
        assert!(!value.as_map().unwrap().contains_key("c"));
        assert_eq!(value.as_map().unwrap().len(), 10);

        // The preimage does not depend on `confirm`'s own value at all — that
        // is the property parent §4.2 needs, since the verifier recomputes it
        // before it has a tag to compare.
        let mut other = msg.clone();
        other.confirm = [0xff; 32];
        assert_eq!(other.confirm_preimage().unwrap(), preimage);
        assert_ne!(other.encode().unwrap(), msg.encode().unwrap());
    }

    #[test]
    fn hostile_inputs_are_rejected() {
        let msg = sample_initial(Some(4));
        let good = msg.encode().unwrap().into_vec();
        for (name, bytes) in corrupt_cases(&good) {
            assert_eq!(
                InitialMessageV2::decode(&bytes),
                Err(ProtocolError::Malformed),
                "{name} must be refused"
            );
        }
    }

    #[test]
    fn a_wrong_version_is_refused() {
        let msg = sample_initial(None);
        let mut map = msg.to_map().unwrap();
        map.remove("v");
        map.insert("v", Value::Uint(0x0201)).unwrap();
        let bytes = mlkb_codec::encode_canonical(&Value::Map(map)).unwrap();
        assert_eq!(
            InitialMessageV2::decode(bytes.as_bytes()),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let msg = sample_initial(None);
        let mut map = msg.to_map().unwrap();
        map.insert("zz", Value::Uint(1)).unwrap();
        let bytes = mlkb_codec::encode_canonical(&Value::Map(map)).unwrap();
        assert_eq!(
            InitialMessageV2::decode(bytes.as_bytes()),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn a_wrong_field_width_is_refused() {
        let msg = sample_initial(None);
        for (key, wrong) in [
            ("c", Value::Bytes(std::vec![0u8; 31])),
            ("c", Value::Bytes(std::vec![0u8; 33])),
            ("ct", Value::Bytes(std::vec![0u8; KEM_CIPHERTEXT_LEN - 1])),
            ("ct", Value::Bytes(std::vec![0u8; KEM_CIPHERTEXT_LEN + 1])),
            ("ik", Value::Bytes(std::vec![0u8; 0])),
            ("ek", Value::Uint(0)),
            ("sq", Value::Bytes(std::vec![0u8; 8])),
            ("td", Value::Uint(u64::from(u32::MAX) + 1)),
            ("oid", Value::Uint(u64::MAX)),
        ] {
            let mut map = msg.to_map().unwrap();
            map.remove(key);
            map.insert(key, wrong.clone()).unwrap();
            let bytes = mlkb_codec::encode_canonical(&Value::Map(map)).unwrap();
            assert_eq!(
                InitialMessageV2::decode(bytes.as_bytes()),
                Err(ProtocolError::Malformed),
                "{key} = {wrong:?} must be refused"
            );
        }
    }

    #[test]
    fn identity_is_computable_from_the_message_alone() {
        let msg = sample_initial(None);
        assert_eq!(
            msg.identity_id(),
            IdentityId::from_ik(&msg.ik_x25519, &msg.ik_mldsa_hash)
        );
    }
}
