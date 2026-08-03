//! `RatchetMessage` — the application message (spec M1 §D.3).
//!
//! ```text
//! "ct"  bstr        AEAD ciphertext with the 16-byte Poly1305 tag appended
//! "dh"  bstr(32)    sender's current X25519 ratchet public key
//! "ek"  bstr(1568)  sender's current ML-KEM-1024 encapsulation key   } present iff this
//! "kc"  bstr(1568)  ML-KEM ciphertext to the receiver's current ek   } message opens a
//!                                                                   } new sending chain
//! "n"   uint        message index within the current sending chain
//! "nc"  bstr(24)    XChaCha20-Poly1305 nonce (192-bit random)
//! "pn"  uint        number of messages in the sender's previous sending chain
//! ```
//!
//! # The pairing rule is a parser property, by requirement
//!
//! M1 §D.3: `"ek"` and `"kc"` are present **together or not at all**, and
//! exactly on the first message of each new sending chain — i.e. when
//! `n == 0`. Their presence is what tells the receiver to perform a root step
//! before the chain step, and §D.3 requires that this be a property of the
//! parser rather than of the state machine.
//!
//! Both halves of the rule are enforced twice over, on the way in and on the
//! way out:
//!
//! - the pair is a single `Option<`[`RatchetStep`]`>`, so "one without the
//!   other" is not a value this type can hold;
//! - the two constructors are [`RatchetMessage::chain_start`], which fixes
//!   `n = 0` and takes a step, and [`RatchetMessage::in_chain`], which takes a
//!   `NonZeroU64` and no step. There is no third one, so a caller cannot build
//!   a message the decoder would refuse.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::num::NonZeroU64;

use mlkb_codec::{CanonicalBytes, CanonicalMap, Value};
use mlkb_crypto::{KEM_CIPHERTEXT_LEN, KEM_ENCAPSULATION_KEY_LEN};
use mlkb_secrets::{Nonce192, ProtocolError, WireNonce};

use crate::PROTOCOL_VERSION;
use crate::identity::IdentityId;
use crate::util;

const KEY_CT: &str = "ct";
const KEY_DH: &str = "dh";
const KEY_EK: &str = "ek";
const KEY_KC: &str = "kc";
const KEY_N: &str = "n";
const KEY_NONCE: &str = "nc";
const KEY_PN: &str = "pn";

// The AAD map of M1 §D.3.
const AAD_KEY_EPOCH: &str = "e";
const AAD_KEY_HEADER: &str = "h";
const AAD_KEY_RECIPIENT: &str = "r";
const AAD_KEY_SENDER: &str = "s";
const AAD_KEY_VERSION: &str = "v";

/// The two fields that open a new sending chain (spec M1 §D.3).
///
/// They travel together because a root step needs both: the peer's fresh
/// ML-KEM encapsulation key for the *next* step, and the ciphertext to the
/// receiver's current one for *this* step. M1 §D.1 is why both exist at all —
/// each DH ratchet step contributes a fresh X25519 output *and* a fresh ML-KEM
/// encapsulation, so breaking the chain requires breaking X25519 **and**
/// ML-KEM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetStep {
    /// The sender's current ML-KEM-1024 encapsulation key — 1568 bytes, by
    /// type.
    pub ek: Box<[u8; KEM_ENCAPSULATION_KEY_LEN]>,
    /// An ML-KEM ciphertext to the receiver's current `ek` — 1568 bytes, by
    /// type.
    pub kc: Box<[u8; KEM_CIPHERTEXT_LEN]>,
}

/// An application message (spec M1 §D.3).
///
/// Fields are private because two of them — `n` and the presence of the step —
/// are not independent. See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetMessage {
    dh: [u8; 32],
    n: u64,
    pn: u64,
    nonce: WireNonce,
    step: Option<RatchetStep>,
    ct: Vec<u8>,
}

impl RatchetMessage {
    /// The first message of a new sending chain: `n == 0`, and the step is
    /// present (spec M1 §D.3).
    #[must_use]
    pub fn chain_start(
        dh: [u8; 32],
        pn: u64,
        nonce: WireNonce,
        step: RatchetStep,
        ct: Vec<u8>,
    ) -> Self {
        Self {
            dh,
            n: 0,
            pn,
            nonce,
            step: Some(step),
            ct,
        }
    }

    /// A subsequent message in the current sending chain: `n != 0`, and no
    /// step (spec M1 §D.3).
    ///
    /// `n` is a [`NonZeroU64`] so that the "no step" half of the rule cannot
    /// be paired with `n == 0` even by mistake.
    #[must_use]
    pub fn in_chain(dh: [u8; 32], n: NonZeroU64, pn: u64, nonce: WireNonce, ct: Vec<u8>) -> Self {
        Self {
            dh,
            n: n.get(),
            pn,
            nonce,
            step: None,
            ct,
        }
    }

    /// The sender's current X25519 ratchet public key.
    #[must_use]
    pub fn dh(&self) -> &[u8; 32] {
        &self.dh
    }

    /// The message index within the current sending chain.
    #[must_use]
    pub fn n(&self) -> u64 {
        self.n
    }

    /// The number of messages in the sender's previous sending chain.
    ///
    /// This is what lets a receiver derive the message keys it skipped in that
    /// chain before ratcheting forward, exactly as in Signal.
    #[must_use]
    pub fn pn(&self) -> u64 {
        self.pn
    }

    /// The received AEAD nonce (spec M1 §G.2).
    ///
    /// A [`WireNonce`], never a [`Nonce192`]: the two do not convert, so a
    /// received nonce cannot be fed to the sealing side.
    #[must_use]
    pub fn nonce(&self) -> &WireNonce {
        &self.nonce
    }

    /// The root-step fields, present exactly when `n == 0` (spec M1 §D.3).
    #[must_use]
    pub fn step(&self) -> Option<&RatchetStep> {
        self.step.as_ref()
    }

    /// Whether this message opens a new sending chain, i.e. whether the
    /// receiver must perform a root step before the chain step.
    #[must_use]
    pub fn opens_chain(&self) -> bool {
        self.step.is_some()
    }

    /// The ciphertext, with its 16-byte Poly1305 tag appended.
    #[must_use]
    pub fn ct(&self) -> &[u8] {
        &self.ct
    }

    /// The CBOR map of M1 §D.3.
    fn to_map(&self) -> Result<CanonicalMap, ProtocolError> {
        let mut m = CanonicalMap::new();
        util::put(&mut m, KEY_CT, Value::Bytes(self.ct.clone()))?;
        util::put(&mut m, KEY_DH, Value::Bytes(self.dh.to_vec()))?;
        // M1 §B.3: absent means the key is not there. Both or neither, and the
        // `Option<RatchetStep>` is what makes "both or neither" hold.
        util::put_opt(
            &mut m,
            KEY_EK,
            self.step
                .as_ref()
                .map(|s| Value::Bytes(s.ek.as_slice().to_vec())),
        )?;
        util::put_opt(
            &mut m,
            KEY_KC,
            self.step
                .as_ref()
                .map(|s| Value::Bytes(s.kc.as_slice().to_vec())),
        )?;
        util::put(&mut m, KEY_N, Value::Uint(self.n))?;
        util::put(
            &mut m,
            KEY_NONCE,
            Value::Bytes(self.nonce.as_bytes().to_vec()),
        )?;
        util::put(&mut m, KEY_PN, Value::Uint(self.pn))?;
        Ok(m)
    }

    /// `canonical(RatchetMessage)` — the payload of a `0x02` frame
    /// (spec M1 §A.2, §D.3).
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only; see `util::encode`.
    pub fn encode(&self) -> Result<CanonicalBytes, ProtocolError> {
        util::encode(&Value::Map(self.to_map()?))
    }

    /// `canonical(RatchetMessage without "ct")` — the `"h"` field of the AAD
    /// (spec M1 §D.3).
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only.
    pub fn header_preimage(&self) -> Result<CanonicalBytes, ProtocolError> {
        let mut m = self.to_map()?;
        m.remove(KEY_CT);
        util::encode(&Value::Map(m))
    }

    /// The AEAD associated data, and the only value it ever takes
    /// (spec M1 §D.3).
    ///
    /// ```text
    /// AAD = canonical({
    ///     "e":  uint      frame epoch,
    ///     "h":  bstr      canonical(RatchetMessage without "ct"),
    ///     "r":  bstr(32)  IdentityId of the recipient,
    ///     "s":  bstr(32)  IdentityId of the sender,
    ///     "v":  uint      PROTOCOL_VERSION,
    /// })
    /// ```
    ///
    /// This is strictly stronger than the Python binding, which bound only the
    /// `(epoch, index)` header and a caller-supplied opaque blob: binding both
    /// `IdentityId`s makes a ciphertext non-transplantable between sessions,
    /// and binding the whole header minus the ciphertext makes every ratchet
    /// field — `dh`, `ek`, `kc`, the nonce, `n`, `pn` — authenticated by the
    /// AEAD as well as by the frame MAC.
    ///
    /// The result is a `CanonicalBytes`, so `mlkb_crypto::Aad::new` accepts it
    /// by construction and the ad-hoc concatenation of audit L6 is
    /// unrepresentable (M1 §G.3).
    ///
    /// # Errors
    /// [`ProtocolError::Internal`] only.
    pub fn aad(
        &self,
        epoch: u64,
        sender: &IdentityId,
        recipient: &IdentityId,
    ) -> Result<CanonicalBytes, ProtocolError> {
        let header = self.header_preimage()?;
        let mut m = CanonicalMap::new();
        util::put(&mut m, AAD_KEY_EPOCH, Value::Uint(epoch))?;
        util::put(
            &mut m,
            AAD_KEY_HEADER,
            Value::Bytes(header.as_bytes().to_vec()),
        )?;
        util::put(
            &mut m,
            AAD_KEY_RECIPIENT,
            Value::Bytes(recipient.as_bytes().to_vec()),
        )?;
        util::put(
            &mut m,
            AAD_KEY_SENDER,
            Value::Bytes(sender.as_bytes().to_vec()),
        )?;
        util::put(
            &mut m,
            AAD_KEY_VERSION,
            Value::Uint(u64::from(PROTOCOL_VERSION)),
        )?;
        util::encode(&Value::Map(m))
    }

    /// Parses `canonical(RatchetMessage)` (spec M1 §D.3).
    ///
    /// The pairing rule is checked here and nowhere else:
    ///
    /// - `n != 0` carrying `"ek"` or `"kc"` → [`ProtocolError::Malformed`];
    /// - `n == 0` carrying neither → [`ProtocolError::Malformed`];
    /// - one of the pair without the other → [`ProtocolError::Malformed`].
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] for the above, for non-canonical CBOR, for
    /// a wrong field width, and for an unknown map key.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let mut m = util::decode_map(bytes)?;

        let ct = util::as_vec(util::take(&mut m, KEY_CT)?)?;
        let dh = util::as_array::<32>(util::take(&mut m, KEY_DH)?)?;
        let ek = util::take_opt(&mut m, KEY_EK);
        let kc = util::take_opt(&mut m, KEY_KC);
        let n = util::as_uint(util::take(&mut m, KEY_N)?)?;
        let nonce = util::as_array::<{ Nonce192::LEN }>(util::take(&mut m, KEY_NONCE)?)?;
        let pn = util::as_uint(util::take(&mut m, KEY_PN)?)?;
        util::finish(&m)?;

        // "present together or not at all, and exactly when n == 0".
        let step = match (ek, kc, n) {
            (Some(ek), Some(kc), 0) => Some(RatchetStep {
                ek: util::as_boxed_array::<KEM_ENCAPSULATION_KEY_LEN>(ek)?,
                kc: util::as_boxed_array::<KEM_CIPHERTEXT_LEN>(kc)?,
            }),
            (None, None, 0) => return Err(ProtocolError::Malformed),
            (None, None, _) => None,
            _ => return Err(ProtocolError::Malformed),
        };

        Ok(Self {
            dh,
            n,
            pn,
            nonce: WireNonce::from_bytes(nonce),
            step,
            ct,
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
    use crate::testkit::{corrupt_cases, sample_step, wire_nonce};
    use mlkb_codec::{decode_canonical, encode_canonical};
    use std::vec;

    fn start() -> RatchetMessage {
        RatchetMessage::chain_start(
            [0x11; 32],
            5,
            wire_nonce(0x22),
            sample_step(),
            vec![0xcc; 48],
        )
    }

    fn later() -> RatchetMessage {
        RatchetMessage::in_chain(
            [0x11; 32],
            NonZeroU64::new(3).unwrap(),
            5,
            wire_nonce(0x22),
            vec![0xcc; 48],
        )
    }

    fn map_of(msg: &RatchetMessage) -> CanonicalMap {
        decode_canonical(msg.encode().unwrap().as_bytes())
            .unwrap()
            .as_map()
            .unwrap()
            .clone()
    }

    fn encode_map(m: &CanonicalMap) -> Vec<u8> {
        encode_canonical(&Value::Map(m.clone())).unwrap().into_vec()
    }

    #[test]
    fn d3_round_trips_both_shapes() {
        for msg in [start(), later()] {
            let bytes = msg.encode().unwrap();
            let back = RatchetMessage::decode(bytes.as_bytes()).unwrap();
            assert_eq!(back, msg);
            assert_eq!(back.opens_chain(), msg.n() == 0);
        }
    }

    #[test]
    fn d3_uses_exactly_the_specified_map_keys() {
        let opening = map_of(&start());
        let keys: Vec<&str> = opening.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["n", "ct", "dh", "ek", "kc", "nc", "pn"]);
        let continuing = map_of(&later());
        let keys: Vec<&str> = continuing.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["n", "ct", "dh", "nc", "pn"]);
    }

    #[test]
    fn d3_n_nonzero_carrying_ek_or_kc_is_rejected() {
        let mut m = map_of(&later());
        let step = sample_step();
        m.insert("ek", Value::Bytes(step.ek.as_slice().to_vec()))
            .unwrap();
        m.insert("kc", Value::Bytes(step.kc.as_slice().to_vec()))
            .unwrap();
        assert_eq!(
            RatchetMessage::decode(&encode_map(&m)),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn d3_n_zero_carrying_neither_is_rejected() {
        let mut m = map_of(&start());
        m.remove("ek");
        m.remove("kc");
        assert_eq!(
            RatchetMessage::decode(&encode_map(&m)),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn d3_one_of_the_pair_without_the_other_is_rejected() {
        for drop_key in ["ek", "kc"] {
            let mut m = map_of(&start());
            m.remove(drop_key);
            assert_eq!(
                RatchetMessage::decode(&encode_map(&m)),
                Err(ProtocolError::Malformed),
                "dropping {drop_key} must be refused"
            );
        }
        // and the same, on a message that does not open a chain
        for add_key in ["ek", "kc"] {
            let mut m = map_of(&later());
            m.insert(add_key, Value::Bytes(vec![0u8; 1568])).unwrap();
            assert_eq!(
                RatchetMessage::decode(&encode_map(&m)),
                Err(ProtocolError::Malformed),
                "adding {add_key} alone must be refused"
            );
        }
    }

    #[test]
    fn d3_the_pair_is_refused_at_the_wrong_width_too() {
        for (key, len) in [("ek", 1567usize), ("ek", 1569), ("kc", 0), ("kc", 32)] {
            let mut m = map_of(&start());
            m.remove(key);
            m.insert(key, Value::Bytes(vec![0u8; len])).unwrap();
            assert_eq!(
                RatchetMessage::decode(&encode_map(&m)),
                Err(ProtocolError::Malformed),
                "{key} at {len} bytes must be refused"
            );
        }
    }

    #[test]
    fn d3_header_preimage_omits_only_the_ciphertext() {
        let msg = start();
        let header = msg.header_preimage().unwrap();
        let m = decode_canonical(header.as_bytes()).unwrap();
        let map = m.as_map().unwrap();
        assert!(!map.contains_key("ct"));
        assert_eq!(map.len(), 6);

        // Changing the ciphertext must not change the header preimage...
        let mut other = msg.clone();
        other.ct = vec![0x01; 9];
        assert_eq!(other.header_preimage().unwrap(), header);
        // ...but changing any header field must.
        let mut other = msg.clone();
        other.pn = 6;
        assert_ne!(other.header_preimage().unwrap(), header);
    }

    #[test]
    fn d3_aad_binds_epoch_header_both_identities_and_the_version() {
        let msg = start();
        let a = IdentityId::from_bytes([0xa1; 32]);
        let b = IdentityId::from_bytes([0xb2; 32]);
        let aad = msg.aad(7, &a, &b).unwrap();

        let value = decode_canonical(aad.as_bytes()).unwrap();
        let map = value.as_map().unwrap();
        let keys: Vec<&str> = map.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["e", "h", "r", "s", "v"]);
        assert_eq!(map.get("e").unwrap(), &Value::Uint(7));
        assert_eq!(map.get("v").unwrap(), &Value::Uint(0x0200));
        assert_eq!(
            map.get("h").unwrap().as_bytes().unwrap(),
            msg.header_preimage().unwrap().as_bytes()
        );
        assert_eq!(map.get("s").unwrap().as_bytes().unwrap(), a.as_bytes());
        assert_eq!(map.get("r").unwrap().as_bytes().unwrap(), b.as_bytes());

        // Every input changes it, and the direction is not symmetric — that is
        // what makes a ciphertext non-transplantable between sessions.
        assert_ne!(msg.aad(8, &a, &b).unwrap(), aad);
        assert_ne!(msg.aad(7, &b, &a).unwrap(), aad);
        assert_ne!(later().aad(7, &a, &b).unwrap(), aad);
    }

    #[test]
    fn hostile_inputs_are_rejected() {
        for msg in [start(), later()] {
            let good = msg.encode().unwrap().into_vec();
            for (name, bytes) in corrupt_cases(&good) {
                assert_eq!(
                    RatchetMessage::decode(&bytes),
                    Err(ProtocolError::Malformed),
                    "{name} must be refused"
                );
            }
        }
    }

    /// M1 §B.2 / §B.4: the same *value*, encoded two ways, and only one of
    /// them is a message.
    ///
    /// Both byte strings below decode — under a lenient reader — to exactly
    /// the same map. The canonical one is accepted; the other two are refused
    /// outright rather than normalized, which is the property parent §3.2
    /// rule 5 exists for. A normalizing decoder would accept all three and
    /// hand the caller a value whose bytes it can no longer reproduce, which
    /// is how a signature or a MAC preimage silently stops being injective.
    #[test]
    fn b4_non_canonical_orderings_and_lengths_are_rejected_not_normalized() {
        fn key(name: &str) -> Vec<u8> {
            let mut v = std::vec![0x60 | u8::try_from(name.len()).unwrap()];
            v.extend_from_slice(name.as_bytes());
            v
        }
        fn bstr(fill: u8, len: usize) -> Vec<u8> {
            let mut v = std::vec![0x58, u8::try_from(len).unwrap()];
            v.extend_from_slice(&std::vec![fill; len]);
            v
        }

        let ct = (key("ct"), std::vec![0x44, 0xcc, 0xcc, 0xcc, 0xcc]);
        let dh = (key("dh"), bstr(0x11, 32));
        let n_short = (key("n"), std::vec![0x03]);
        let nc = (key("nc"), bstr(0x22, 24));
        let pn = (key("pn"), std::vec![0x05]);

        let build = |pairs: &[&(Vec<u8>, Vec<u8>)]| {
            let mut out = std::vec![0xa0 | u8::try_from(pairs.len()).unwrap()];
            for (k, v) in pairs {
                out.extend_from_slice(k);
                out.extend_from_slice(v);
            }
            out
        };

        // M1 §B.2 order: the one-byte key first, then the two-byte ones.
        let canonical = build(&[&n_short, &ct, &dh, &nc, &pn]);
        let decoded = RatchetMessage::decode(&canonical).expect("the canonical form decodes");
        assert_eq!(decoded.n(), 3);
        assert_eq!(decoded.pn(), 5);
        assert_eq!(decoded.encode().unwrap().as_bytes(), canonical.as_slice());

        // Plain string order, which is what a serializer that sorts by `str`
        // would emit. Same value, different bytes.
        let plain_order = build(&[&ct, &dh, &n_short, &nc, &pn]);
        assert_ne!(plain_order, canonical);
        assert_eq!(
            RatchetMessage::decode(&plain_order),
            Err(ProtocolError::Malformed)
        );

        // `n = 3` written in the two-byte head. Same value, different bytes.
        let n_long = (key("n"), std::vec![0x18, 0x03]);
        let non_shortest = build(&[&n_long, &ct, &dh, &nc, &pn]);
        assert_ne!(non_shortest, canonical);
        assert_eq!(
            RatchetMessage::decode(&non_shortest),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let mut m = map_of(&later());
        m.insert("zz", Value::Uint(1)).unwrap();
        assert_eq!(
            RatchetMessage::decode(&encode_map(&m)),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn a_wrong_field_width_is_refused() {
        for (key, wrong) in [
            ("dh", Value::Bytes(vec![0u8; 31])),
            ("nc", Value::Bytes(vec![0u8; 23])),
            ("nc", Value::Bytes(vec![0u8; 25])),
            ("n", Value::Bytes(vec![0u8; 1])),
            ("pn", Value::Bytes(vec![0u8; 1])),
            ("ct", Value::Uint(0)),
        ] {
            let mut m = map_of(&later());
            m.remove(key);
            m.insert(key, wrong.clone()).unwrap();
            assert_eq!(
                RatchetMessage::decode(&encode_map(&m)),
                Err(ProtocolError::Malformed),
                "{key} = {wrong:?} must be refused"
            );
        }
    }

    #[test]
    fn an_empty_ciphertext_is_still_a_well_formed_message() {
        // The AEAD tag lives inside `"ct"`, so an empty one is not something
        // this layer can rule out — it is `MessageKey::open`'s to refuse. The
        // parser must not invent a bound the spec does not state.
        let msg = RatchetMessage::in_chain(
            [0; 32],
            NonZeroU64::new(1).unwrap(),
            0,
            wire_nonce(0),
            Vec::new(),
        );
        let bytes = msg.encode().unwrap();
        assert_eq!(RatchetMessage::decode(bytes.as_bytes()).unwrap(), msg);
    }

    #[test]
    fn accessors_report_what_was_built() {
        let msg = start();
        assert_eq!(msg.dh(), &[0x11; 32]);
        assert_eq!(msg.n(), 0);
        assert_eq!(msg.pn(), 5);
        assert_eq!(msg.nonce(), &wire_nonce(0x22));
        assert_eq!(msg.ct(), &[0xcc; 48]);
        assert!(msg.step().is_some());
        assert!(later().step().is_none());
    }
}
