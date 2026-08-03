//! The frame envelope — a fixed big-endian layout, not CBOR (spec M1 §A.1,
//! parent §3.3).
//!
//! ```text
//!   offset  size  field
//!        0     2  version      u16  == PROTOCOL_VERSION (0x0200)
//!        2     8  epoch        u64
//!       10     1  msg_type     u8
//!       11     4  payload_len  u32  <= MAX_FRAME_PAYLOAD
//!       15   var  payload
//!    15+n    32  frame_mac
//! ```
//!
//! Total length is exactly `FRAME_HEADER_LEN + payload_len + FRAME_MAC_LEN`,
//! and the MAC is one HMAC pass over
//! `b"MLKEMBraid/frame/v2" || wire[0 .. 15 + payload_len]` — no re-encode, no
//! reconstruction. That equality between the preimage and the transmitted
//! bytes is the whole reason M1 §A.1 exempts the frame from parent §3.2.

use alloc::vec::Vec;

use mlkb_crypto::{FrameKey, Mac256};
use mlkb_secrets::{Progress, ProtocolError};

use crate::labels;
use crate::util::{be_u32, be_u64};
use crate::{PROTOCOL_VERSION, util};

/// Bytes before the payload: `version || epoch || msg_type || payload_len`
/// (spec M1 §A.1, §I).
pub const FRAME_HEADER_LEN: usize = 15;

/// The trailing HMAC-SHA256 tag, in bytes (spec parent §3.3).
pub const FRAME_MAC_LEN: usize = 32;

/// The largest `payload_len` a frame may declare (spec M1 §A.1 rule 2, §I).
///
/// The bound is inclusive: `payload_len > MAX_FRAME_PAYLOAD` is the reject
/// condition, so a payload of exactly this length is legal.
pub const MAX_FRAME_PAYLOAD: usize = 65_536;

// Field offsets, so no decoder writes a bare number.
const OFF_VERSION: usize = 0;
const OFF_EPOCH: usize = 2;
const OFF_MSG_TYPE: usize = 10;
const OFF_PAYLOAD_LEN: usize = 11;

/// The closed `msg_type` registry (spec M1 §A.2).
///
/// Unknown values are a hard reject, so no future extension can become a
/// downgrade surface. The Python Braid types (`HDR`, `EK`, `CT1_ACK`,
/// `EK_CT1_ACK`) are deliberately **not** here: they belong to the deferred
/// SCKA layer and will be assigned from the reserved range when the Braid
/// lands. Assigning them now would freeze a layout that does not exist yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgType {
    /// `0x01` — PQXDH handshake, initiator → responder. Payload is
    /// `canonical(InitialMessageV2)` (spec M1 §C.3).
    Initial,
    /// `0x02` — application message. Payload is `canonical(RatchetMessage)`
    /// (spec M1 §D.3).
    Message,
    /// `0x03` — keepalive / delivery ack. **No payload**, and it carries no
    /// key material (spec M1 §A.2).
    Ack,
}

impl MsgType {
    /// Every value in the registry, in order (spec M1 §A.2).
    pub const ALL: [Self; 3] = [Self::Initial, Self::Message, Self::Ack];

    /// The wire byte (spec M1 §A.2).
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Initial => 0x01,
            Self::Message => 0x02,
            Self::Ack => 0x03,
        }
    }

    /// Parses a wire byte (spec M1 §A.2).
    ///
    /// `0x00` and `0x04..=0xFF` are reserved and rejected. Note where this is
    /// *called* from: [`Frame::decode`] reaches it only after the MAC has
    /// verified, because dispatching on an unauthenticated type byte would
    /// contradict parent §8.1.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] for any value outside the registry.
    pub fn from_u8(byte: u8) -> Result<Self, ProtocolError> {
        match byte {
            0x01 => Ok(Self::Initial),
            0x02 => Ok(Self::Message),
            0x03 => Ok(Self::Ack),
            _ => Err(ProtocolError::Malformed),
        }
    }

    /// Whether this type may carry a payload at all (spec M1 §A.2, §A.1
    /// rule 7).
    ///
    /// A payload-free type declaring `payload_len != 0` is a hard reject; this
    /// preserves `protocol/messages.py:203-207`.
    #[must_use]
    pub fn carries_payload(self) -> bool {
        match self {
            Self::Initial | Self::Message => true,
            Self::Ack => false,
        }
    }
}

/// An authenticated frame (spec M1 §A.1, parent §3.3).
///
/// A `Frame` only ever exists having been MAC'd: [`Frame::seal`] computes the
/// tag and [`Frame::decode`] verifies it before the value is constructed.
/// There is no constructor that takes a tag from a caller, so "an
/// unauthenticated frame" is not a state this type can be in.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame {
    epoch: u64,
    msg_type: MsgType,
    payload: Vec<u8>,
    mac: Mac256,
}

/// Prints the shape, never the payload bytes.
impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame")
            .field("version", &PROTOCOL_VERSION)
            .field("epoch", &self.epoch)
            .field("msg_type", &self.msg_type)
            .field("payload_len", &self.payload.len())
            // The payload and the tag are deliberately not printed: a frame
            // ends up in a log line, and the payload is a ciphertext nobody
            // needs there.
            .finish_non_exhaustive()
    }
}

impl Frame {
    /// The protocol version, which is a constant of the format
    /// (spec parent §3.1).
    #[must_use]
    pub fn version(&self) -> u16 {
        PROTOCOL_VERSION
    }

    /// The sending chain's DH-ratchet generation (spec M1 §A.3).
    ///
    /// It is constant across every message sent within one sending chain, and
    /// a receiver never advances its own state from a peer's `epoch` alone:
    /// parent §8.1 requires authentication first and M1 §D.3 defines the only
    /// state transitions.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The authenticated message type (spec M1 §A.2).
    #[must_use]
    pub fn msg_type(&self) -> MsgType {
        self.msg_type
    }

    /// The authenticated payload (spec M1 §A.1).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The frame tag (spec parent §3.3).
    #[must_use]
    pub fn mac(&self) -> &Mac256 {
        &self.mac
    }

    /// Builds and authenticates a frame (spec M1 §A.1, parent §3.3).
    ///
    /// `key` is directional (parent §4.4): a peer's own frame reflected back
    /// at it does not verify.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] if `payload` is longer than
    /// [`MAX_FRAME_PAYLOAD`] (M1 §A.1 rule 2), or if `msg_type` is
    /// payload-free and `payload` is not empty (rule 7). The second check is
    /// on the sending side as well as the receiving side so that this crate
    /// cannot emit a frame it would itself refuse.
    pub fn seal(
        epoch: u64,
        msg_type: MsgType,
        payload: Vec<u8>,
        key: &FrameKey,
    ) -> Result<Self, ProtocolError> {
        let payload_len = u32::try_from(payload.len()).map_err(|_| ProtocolError::Malformed)?;
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(ProtocolError::Malformed);
        }
        if !msg_type.carries_payload() && !payload.is_empty() {
            return Err(ProtocolError::Malformed);
        }

        let mut preimage = Vec::new();
        preimage.extend_from_slice(labels::FRAME_MAC);
        write_header(&mut preimage, epoch, msg_type, payload_len);
        preimage.extend_from_slice(&payload);
        let mac = key.mac(&preimage);

        Ok(Self {
            epoch,
            msg_type,
            payload,
            mac,
        })
    }

    /// The exact number of bytes [`Frame::to_wire`] will produce.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        FRAME_HEADER_LEN
            .saturating_add(self.payload.len())
            .saturating_add(FRAME_MAC_LEN)
    }

    /// The transmitted bytes (spec M1 §A.1).
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        // Total: the length was range-checked in `seal`, and `decode` only
        // ever constructs a `Frame` from a payload it has already measured.
        let payload_len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        write_header(&mut out, self.epoch, self.msg_type, payload_len);
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(self.mac.as_bytes());
        out
    }

    /// The total frame length a buffer's header declares (spec M1 §A.1
    /// rules 1–3).
    ///
    /// A transport that has to know how many bytes to read before it can call
    /// [`Frame::decode`] asks here. It enforces rules 1 and 2 — wrong version,
    /// oversized `payload_len` — **without allocating and without looking at
    /// `msg_type`**, so it is not a dispatch on unauthenticated input; it
    /// returns a length and nothing else.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] on a wrong version or an oversized
    /// `payload_len`.
    pub fn wire_len_of(buf: &[u8]) -> Result<Progress<usize>, ProtocolError> {
        check_version(buf)?;
        let Some(payload_len) = declared_payload_len(buf)? else {
            return Ok(Progress::NeedMore);
        };
        Ok(Progress::Complete(total_len(payload_len)?))
    }

    /// Parses and authenticates a frame (spec M1 §A.1, all seven rules).
    ///
    /// `buf` must hold exactly one frame. The order below is normative and is
    /// the point of this function:
    ///
    /// 1. `version != PROTOCOL_VERSION` → reject, as soon as two bytes exist.
    /// 2. `payload_len > MAX_FRAME_PAYLOAD` → reject **before allocating**.
    ///    The length prefix is never trusted as an allocation hint.
    /// 3. Buffer shorter than `15 + payload_len + 32` → [`Progress::NeedMore`],
    ///    which is not an error (parent §8.4).
    /// 4. Buffer longer → reject (parent §3.3, audit L7: no trailing bytes).
    /// 5. The tag is verified in constant time; failure is
    ///    [`ProtocolError::Unauthenticated`].
    /// 6. **`msg_type` is validated only after the MAC verifies.** Dispatching
    ///    on an unauthenticated type byte would contradict parent §8.1.
    /// 7. A payload-free `msg_type` declaring `payload_len != 0` → reject.
    ///
    /// A frame that fails a *length* check costs no allocation at all: the
    /// declared length is checked against `MAX_FRAME_PAYLOAD` before any buffer
    /// exists. A frame that reaches the MAC check does allocate the preimage,
    /// which contains a copy of the payload — bounded by bytes already in hand
    /// (ratio 1.0, no amplification), but not free. An earlier revision of this
    /// comment claimed a failing frame never allocates; that was false, and the
    /// contract on this function is not a good place to overstate a guarantee.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] for rules 1, 2, 4, 6 and 7;
    /// [`ProtocolError::Unauthenticated`] for rule 5.
    pub fn decode(buf: &[u8], key: &FrameKey) -> Result<Progress<Self>, ProtocolError> {
        // Rule 1.
        check_version(buf)?;

        // Rule 2, and rule 3 for the header itself.
        let Some(payload_len) = declared_payload_len(buf)? else {
            return Ok(Progress::NeedMore);
        };

        let mac_offset = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(ProtocolError::Malformed)?;
        let total = total_len(payload_len)?;

        // Rule 3.
        if buf.len() < total {
            return Ok(Progress::NeedMore);
        }
        // Rule 4.
        if buf.len() > total {
            return Err(ProtocolError::Malformed);
        }

        // Rule 5. The preimage is the label followed by the transmitted bytes
        // up to the tag — one contiguous buffer, bounded by the input that is
        // already in hand, and no reconstruction of any field.
        let macd = buf.get(..mac_offset).ok_or(ProtocolError::Malformed)?;
        let tag = buf
            .get(mac_offset..total)
            .and_then(|b| <[u8; FRAME_MAC_LEN]>::try_from(b).ok())
            .ok_or(ProtocolError::Malformed)?;

        let mut preimage = Vec::with_capacity(labels::FRAME_MAC.len().saturating_add(mac_offset));
        preimage.extend_from_slice(labels::FRAME_MAC);
        preimage.extend_from_slice(macd);
        key.verify(&preimage, &Mac256::from_bytes(tag))?;

        // Rule 6 — after, and only after, rule 5.
        let type_byte = *buf.get(OFF_MSG_TYPE).ok_or(ProtocolError::Malformed)?;
        let msg_type = MsgType::from_u8(type_byte)?;

        // Rule 7.
        if !msg_type.carries_payload() && payload_len != 0 {
            return Err(ProtocolError::Malformed);
        }

        let epoch = be_u64(buf, OFF_EPOCH).ok_or(ProtocolError::Malformed)?;
        let payload = buf
            .get(FRAME_HEADER_LEN..mac_offset)
            .ok_or(ProtocolError::Malformed)?
            .to_vec();

        Ok(Progress::Complete(Self {
            epoch,
            msg_type,
            payload,
            mac: Mac256::from_bytes(tag),
        }))
    }
}

/// Writes the 15-byte header (spec M1 §A.1).
fn write_header(out: &mut Vec<u8>, epoch: u64, msg_type: MsgType, payload_len: u32) {
    out.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(msg_type.to_u8());
    out.extend_from_slice(&payload_len.to_be_bytes());
}

/// Rule 1, applied as soon as the two version bytes are present.
///
/// A buffer too short to hold them is not yet wrong — it is
/// [`Progress::NeedMore`], which the callers return.
fn check_version(buf: &[u8]) -> Result<(), ProtocolError> {
    match util::be_u16(buf, OFF_VERSION) {
        Some(v) if v != PROTOCOL_VERSION => Err(ProtocolError::Malformed),
        _ => Ok(()),
    }
}

/// Rule 2: the declared payload length, refused if it exceeds the bound.
///
/// `Ok(None)` means the header is not yet complete. Nothing is allocated on
/// any path through this function, which is what makes rule 2 "reject before
/// allocating" rather than "reject after".
fn declared_payload_len(buf: &[u8]) -> Result<Option<usize>, ProtocolError> {
    let Some(declared) = be_u32(buf, OFF_PAYLOAD_LEN) else {
        return Ok(None);
    };
    let payload_len = usize::try_from(declared).map_err(|_| ProtocolError::Malformed)?;
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(ProtocolError::Malformed);
    }
    Ok(Some(payload_len))
}

/// `15 + payload_len + 32`, without an overflow anywhere.
fn total_len(payload_len: usize) -> Result<usize, ProtocolError> {
    FRAME_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|n| n.checked_add(FRAME_MAC_LEN))
        .ok_or(ProtocolError::Malformed)
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
    use crate::testkit::{other_frame_key, test_frame_key};
    use std::vec;

    fn sealed(payload: Vec<u8>) -> (Frame, Vec<u8>, FrameKey) {
        let key = test_frame_key();
        let frame = Frame::seal(7, MsgType::Message, payload, &key).expect("seals");
        let wire = frame.to_wire();
        (frame, wire, key)
    }

    // -- the layout ------------------------------------------------------

    #[test]
    fn a1_layout_is_the_fixed_big_endian_one() {
        let (frame, wire, _key) = sealed(vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(wire.len(), FRAME_HEADER_LEN + 3 + FRAME_MAC_LEN);
        assert_eq!(wire.len(), frame.wire_len());
        assert_eq!(&wire[0..2], &[0x02, 0x00]); // version 0x0200
        assert_eq!(&wire[2..10], &7u64.to_be_bytes()); // epoch
        assert_eq!(wire[10], 0x02); // MESSAGE
        assert_eq!(&wire[11..15], &3u32.to_be_bytes()); // payload_len
        assert_eq!(&wire[15..18], &[0xaa, 0xbb, 0xcc]);
        assert_eq!(&wire[18..], frame.mac().as_bytes());
    }

    #[test]
    fn a1_mac_preimage_is_the_label_plus_the_transmitted_bytes() {
        // The point of M1 §A.1: verification is one HMAC pass over the wire
        // bytes, with no re-encode and no reconstruction step.
        let (frame, wire, key) = sealed(vec![1, 2, 3, 4]);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"MLKEMBraid/frame/v2");
        preimage.extend_from_slice(&wire[..wire.len() - FRAME_MAC_LEN]);
        assert_eq!(&key.mac(&preimage), frame.mac());
    }

    #[test]
    fn round_trips_every_msg_type() {
        let key = test_frame_key();
        for ty in MsgType::ALL {
            let payload = if ty.carries_payload() {
                vec![9u8; 40]
            } else {
                Vec::new()
            };
            let frame = Frame::seal(1, ty, payload.clone(), &key).expect("seals");
            let wire = frame.to_wire();
            let back = Frame::decode(&wire, &key)
                .expect("decodes")
                .complete()
                .expect("complete");
            assert_eq!(back, frame);
            assert_eq!(back.epoch(), 1);
            assert_eq!(back.msg_type(), ty);
            assert_eq!(back.payload(), payload.as_slice());
            assert_eq!(back.version(), PROTOCOL_VERSION);
        }
    }

    #[test]
    fn round_trips_an_empty_and_a_maximum_payload() {
        let key = test_frame_key();
        for len in [0usize, 1, MAX_FRAME_PAYLOAD] {
            let frame = Frame::seal(0, MsgType::Initial, vec![0x5a; len], &key).expect("seals");
            let wire = frame.to_wire();
            let back = Frame::decode(&wire, &key).unwrap().complete().unwrap();
            assert_eq!(back.payload().len(), len);
        }
    }

    // -- rule 1: version --------------------------------------------------

    #[test]
    fn a1_rule1_wrong_version_is_rejected() {
        let (_frame, wire, key) = sealed(vec![1, 2, 3]);
        for bad in [0x0100u16, 0x0201, 0x0000, 0xffff] {
            let mut bad_wire = wire.clone();
            bad_wire[0..2].copy_from_slice(&bad.to_be_bytes());
            assert_eq!(
                Frame::decode(&bad_wire, &key),
                Err(ProtocolError::Malformed),
                "version {bad:#06x} must be refused"
            );
        }
    }

    #[test]
    fn a1_rule1_wrong_version_is_refused_from_two_bytes_on() {
        // Not "wait for more, then complain": a version that cannot become
        // right is wrong immediately.
        let key = test_frame_key();
        assert_eq!(
            Frame::decode(&[0x01, 0x00], &key),
            Err(ProtocolError::Malformed)
        );
        assert_eq!(
            Frame::wire_len_of(&[0x01, 0x00]),
            Err(ProtocolError::Malformed)
        );
        // One byte is genuinely not enough to know.
        assert_eq!(Frame::decode(&[0x02], &key), Ok(Progress::NeedMore));
    }

    // -- rule 2: the length prefix ---------------------------------------

    #[test]
    fn a1_rule2_oversized_payload_len_is_rejected() {
        let key = test_frame_key();
        for declared in [
            u32::try_from(MAX_FRAME_PAYLOAD).unwrap() + 1,
            0x00ff_ffff,
            u32::MAX,
        ] {
            let mut header = Vec::new();
            write_header(&mut header, 0, MsgType::Message, declared);
            // The buffer is 15 bytes; the declared length is enormous. The
            // rejection must not depend on the rest arriving.
            assert_eq!(
                Frame::decode(&header, &key),
                Err(ProtocolError::Malformed),
                "declared {declared} must be refused"
            );
            assert_eq!(Frame::wire_len_of(&header), Err(ProtocolError::Malformed));
        }
    }

    #[test]
    fn a1_rule2_the_bound_itself_is_accepted() {
        let key = test_frame_key();
        let mut header = Vec::new();
        write_header(
            &mut header,
            0,
            MsgType::Message,
            u32::try_from(MAX_FRAME_PAYLOAD).unwrap(),
        );
        // Legal, merely unfinished.
        assert_eq!(Frame::decode(&header, &key), Ok(Progress::NeedMore));
        assert_eq!(
            Frame::wire_len_of(&header),
            Ok(Progress::Complete(
                FRAME_HEADER_LEN + MAX_FRAME_PAYLOAD + FRAME_MAC_LEN
            ))
        );
    }

    // -- rules 3 and 4: short and long buffers ---------------------------

    #[test]
    fn a1_rule3_a_short_buffer_is_needmore_not_an_error() {
        let (_frame, wire, key) = sealed(vec![7u8; 30]);
        for cut in 0..wire.len() {
            assert_eq!(
                Frame::decode(&wire[..cut], &key),
                Ok(Progress::NeedMore),
                "a {cut}-byte prefix must be NeedMore"
            );
        }
        assert!(Frame::decode(&wire, &key).unwrap().complete().is_some());
    }

    #[test]
    fn a1_rule3_truncated_by_exactly_one_byte_is_needmore() {
        let (_frame, wire, key) = sealed(vec![7u8; 30]);
        assert_eq!(
            Frame::decode(&wire[..wire.len() - 1], &key),
            Ok(Progress::NeedMore)
        );
    }

    #[test]
    fn a1_rule4_a_trailing_byte_is_rejected() {
        let (_frame, wire, key) = sealed(vec![7u8; 30]);
        for extra in [0x00u8, 0xff] {
            let mut long = wire.clone();
            long.push(extra);
            assert_eq!(Frame::decode(&long, &key), Err(ProtocolError::Malformed));
        }
        // Two frames concatenated are not one frame either.
        let mut two = wire.clone();
        two.extend_from_slice(&wire);
        assert_eq!(Frame::decode(&two, &key), Err(ProtocolError::Malformed));
    }

    // -- rule 5: the MAC --------------------------------------------------

    #[test]
    fn a1_rule5_a_flipped_bit_anywhere_fails_the_mac() {
        let (_frame, wire, key) = sealed(vec![0x11, 0x22, 0x33, 0x44]);
        for idx in 0..wire.len() {
            let mut bad = wire.clone();
            bad[idx] ^= 0x01;
            let outcome = Frame::decode(&bad, &key);

            // Nothing anywhere in the frame may still decode.
            assert!(
                !matches!(outcome, Ok(Progress::Complete(_))),
                "bit flip at offset {idx} was accepted"
            );

            if (0..2).contains(&idx) {
                // Rule 1 catches the version before the MAC is reached.
                assert_eq!(outcome, Err(ProtocolError::Malformed), "offset {idx}");
            } else if (11..15).contains(&idx) {
                // A flipped length prefix either exceeds MAX_FRAME_PAYLOAD
                // (rule 2) or makes the buffer the wrong size for what it now
                // claims (rules 3 and 4). Which one depends on the bit, and
                // neither is an authentication outcome — the point is only
                // that a length can never be believed.
                assert!(
                    outcome == Err(ProtocolError::Malformed) || outcome == Ok(Progress::NeedMore),
                    "offset {idx} gave {outcome:?}"
                );
            } else {
                // Epoch, msg_type, payload and tag are all inside the MAC.
                assert_eq!(outcome, Err(ProtocolError::Unauthenticated), "offset {idx}");
            }
        }
    }

    #[test]
    fn a1_rule5_the_frame_key_is_directional() {
        // parent §4.4: a peer's own frame reflected back does not verify.
        let (_frame, wire, _key) = sealed(vec![1, 2, 3]);
        assert_eq!(
            Frame::decode(&wire, &other_frame_key()),
            Err(ProtocolError::Unauthenticated)
        );
    }

    // -- rules 6 and 7: msg_type, after the MAC --------------------------

    #[test]
    fn a1_rule6_unknown_msg_type_is_rejected_and_only_after_the_mac() {
        let key = test_frame_key();
        for byte in [0x00u8, 0x04, 0x7f, 0xff] {
            // (a) with the MAC recomputed over the tampered type byte, so the
            //     frame is authentic and only the type is unknown.
            let mut header = Vec::new();
            header.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            header.extend_from_slice(&3u64.to_be_bytes());
            header.push(byte);
            header.extend_from_slice(&0u32.to_be_bytes());
            let mut preimage = Vec::new();
            preimage.extend_from_slice(labels::FRAME_MAC);
            preimage.extend_from_slice(&header);
            let mut wire = header.clone();
            wire.extend_from_slice(key.mac(&preimage).as_bytes());
            assert_eq!(
                Frame::decode(&wire, &key),
                Err(ProtocolError::Malformed),
                "authenticated msg_type {byte:#04x} must still be refused"
            );

            // (b) without recomputing: the MAC must fail *first*, so the
            //     unknown type is never the thing that decided the outcome.
            let mut forged = wire.clone();
            forged[10] = byte.wrapping_add(1);
            assert_eq!(
                Frame::decode(&forged, &key),
                Err(ProtocolError::Unauthenticated)
            );
        }
    }

    #[test]
    fn a1_rule7_ack_with_a_payload_is_rejected() {
        let key = test_frame_key();

        // The sealing side refuses to build one at all.
        assert_eq!(
            Frame::seal(0, MsgType::Ack, vec![1], &key),
            Err(ProtocolError::Malformed)
        );

        // And a hand-built, correctly MAC'd one is refused on decode.
        let mut header = Vec::new();
        write_header(&mut header, 0, MsgType::Ack, 1);
        let mut body = header.clone();
        body.push(0x5a);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(labels::FRAME_MAC);
        preimage.extend_from_slice(&body);
        let mut wire = body;
        wire.extend_from_slice(key.mac(&preimage).as_bytes());
        assert_eq!(Frame::decode(&wire, &key), Err(ProtocolError::Malformed));
    }

    #[test]
    fn seal_refuses_an_oversized_payload() {
        let key = test_frame_key();
        assert_eq!(
            Frame::seal(0, MsgType::Message, vec![0u8; MAX_FRAME_PAYLOAD + 1], &key),
            Err(ProtocolError::Malformed)
        );
        assert!(Frame::seal(0, MsgType::Message, vec![0u8; MAX_FRAME_PAYLOAD], &key).is_ok());
    }

    // -- the registry -----------------------------------------------------

    #[test]
    fn a2_registry_is_closed_and_round_trips() {
        assert_eq!(MsgType::Initial.to_u8(), 0x01);
        assert_eq!(MsgType::Message.to_u8(), 0x02);
        assert_eq!(MsgType::Ack.to_u8(), 0x03);
        for ty in MsgType::ALL {
            assert_eq!(MsgType::from_u8(ty.to_u8()), Ok(ty));
        }
        let known: Vec<u8> = MsgType::ALL.iter().map(|t| t.to_u8()).collect();
        for byte in 0u8..=0xff {
            let parsed = MsgType::from_u8(byte);
            if known.contains(&byte) {
                assert!(parsed.is_ok(), "{byte:#04x} should parse");
            } else {
                assert_eq!(
                    parsed,
                    Err(ProtocolError::Malformed),
                    "{byte:#04x} is reserved"
                );
            }
        }
        assert!(MsgType::Initial.carries_payload());
        assert!(MsgType::Message.carries_payload());
        assert!(!MsgType::Ack.carries_payload());
    }

    #[test]
    fn debug_shows_the_shape_not_the_payload() {
        let (frame, _wire, _key) = sealed(vec![0xde, 0xad, 0xbe, 0xef]);
        let rendered = std::format!("{frame:?}");
        assert!(rendered.contains("payload_len: 4"), "{rendered}");
        assert!(!rendered.contains("222"), "payload byte leaked: {rendered}");
    }

    #[test]
    fn wire_len_of_matches_a_real_frame() {
        let (frame, wire, _key) = sealed(vec![3u8; 100]);
        assert_eq!(
            Frame::wire_len_of(&wire),
            Ok(Progress::Complete(frame.wire_len()))
        );
        assert_eq!(
            Frame::wire_len_of(&wire[..FRAME_HEADER_LEN - 1]),
            Ok(Progress::NeedMore)
        );
    }
}
