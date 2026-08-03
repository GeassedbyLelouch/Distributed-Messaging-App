//! SHA-256, SHA-512, HMAC-SHA256 and HKDF-SHA256 (spec parent §5.3).
//!
//! These are the only hash and KDF entry points in ML-KEM-Braid. Every
//! derivation in the crate is expressed in terms of them, and every one of
//! them is total: no path in this module can panic, so spec parent §11 gate 7
//! holds without an `unwrap` anywhere.

use mlkb_secrets::{ProtocolError, Secret32, SecretBytes};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::util::copy_prefix;

/// SHA-256 output length in bytes.
pub const SHA256_LEN: usize = 32;

/// SHA-256 block length in bytes (HMAC's key block, RFC 2104).
const SHA256_BLOCK_LEN: usize = 64;

/// SHA-512 output length in bytes.
pub const SHA512_LEN: usize = 64;

/// The RFC 5869 §2.3 bound on HKDF-Expand output: `255 * HashLen`.
pub const HKDF_MAX_OKM: usize = 255 * SHA256_LEN;

/// SHA-256 over the concatenation of `parts` (spec parent §5.3).
///
/// Multi-part so a caller never has to build a temporary concatenation
/// buffer, which is where audit finding L6's ad-hoc concatenations lived.
#[must_use]
pub fn sha256(parts: &[&[u8]]) -> [u8; SHA256_LEN] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SHA-512 over the concatenation of `parts` (spec parent §5.4).
///
/// Used only by XEdDSA, which is defined over SHA-512.
#[must_use]
pub fn sha512(parts: &[&[u8]]) -> [u8; SHA512_LEN] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A 256-bit authentication tag (spec parent §3.3, §4.2).
///
/// Equality is constant-time, and [`Mac256::verify`] is the only shape in
/// which a comparison result reaches a caller: it returns
/// [`ProtocolError::Unauthenticated`] rather than a `bool`, so a tag check
/// cannot be dropped with a stray `;`.
///
/// A tag is public data — it travels on the wire — so this type does not
/// zeroize and its `Debug` shows its bytes.
#[derive(Debug, Clone, Copy)]
pub struct Mac256([u8; SHA256_LEN]);

impl Mac256 {
    /// Wraps a tag read off the wire (spec parent §3.3).
    #[must_use]
    pub fn from_bytes(bytes: [u8; SHA256_LEN]) -> Self {
        Self(bytes)
    }

    /// The tag bytes, for encoding (spec parent §3.3).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHA256_LEN] {
        &self.0
    }

    /// Constant-time comparison against a received tag (spec parent §5.3).
    ///
    /// # Errors
    /// [`ProtocolError::Unauthenticated`] if the tags differ.
    pub fn verify(&self, received: &Self) -> Result<(), ProtocolError> {
        if bool::from(self.0.ct_eq(&received.0)) {
            Ok(())
        } else {
            Err(ProtocolError::Unauthenticated)
        }
    }
}

/// Constant-time (spec parent §5.3).
impl PartialEq for Mac256 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Mac256 {}

/// Builds the HMAC-SHA256 state for `key`, without a fallible constructor.
///
/// `Hmac::new` takes a full block and RFC 2104's key-preparation step (pad
/// short keys with zeros, hash long ones first) is performed here so that the
/// `Result`-returning `new_from_slice` — whose error case is unreachable for
/// every key this crate uses — never appears on a code path.
fn hmac_state(key: &[u8]) -> hmac::Hmac<Sha256> {
    use hmac::digest::KeyInit;
    use hmac::digest::array::Array;

    let mut block = Zeroizing::new([0u8; SHA256_BLOCK_LEN]);
    if key.len() > SHA256_BLOCK_LEN {
        let digest = Zeroizing::new(sha256(&[key]));
        copy_prefix(block.as_mut_slice(), digest.as_slice());
    } else {
        copy_prefix(block.as_mut_slice(), key);
    }
    let key_block = Array::from(*block);
    <hmac::Hmac<Sha256> as KeyInit>::new(&key_block)
}

/// HMAC-SHA256 over the concatenation of `parts` (spec parent §5.3, M1 §D.2).
///
/// Accepts a key of any length, exactly as RFC 2104 defines it.
#[must_use]
pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> Mac256 {
    use hmac::Mac;

    let mut mac = hmac_state(key);
    for p in parts {
        mac.update(p);
    }
    Mac256(mac.finalize().into_bytes().into())
}

/// An HKDF pseudo-random key (RFC 5869 §2.2, spec parent §5.3).
///
/// A `Prk` is either the output of [`Prk::extract`] or a secret that is
/// already uniformly random ([`Prk::from_secret`], RFC 5869 §3.3). It carries
/// no label of its own: the domain separation is entirely in the `info`
/// argument of [`Prk::expand`], which must come from [`crate::labels`].
#[derive(Clone)]
pub struct Prk(Secret32);

/// Redacting (spec M1 §G.1).
impl core::fmt::Debug for Prk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Prk([REDACTED])")
    }
}

impl Prk {
    /// HKDF-Extract over the concatenation of `ikm_parts` (RFC 5869 §2.2).
    ///
    /// Multi-part input so the PQXDH `ikm` of spec parent §4.1 — six 32-byte
    /// components — never has to be materialised as one buffer.
    #[must_use]
    pub fn extract(salt: Option<&[u8]>, ikm_parts: &[&[u8]]) -> Self {
        let mut ext = hkdf::HkdfExtract::<Sha256>::new(salt);
        for p in ikm_parts {
            ext.input_ikm(p);
        }
        let (prk, _) = ext.finalize();
        Self(Secret32::from_fill(|out| copy_prefix(out, &prk)))
    }

    /// Treats an already-uniform secret as a PRK (RFC 5869 §3.3).
    ///
    /// This is the "expand-from-PRK" entry point: it is what lets a key
    /// schedule that has already extracted once — the PQXDH `SK` of spec
    /// parent §4.4 — expand further labels without re-extracting.
    #[must_use]
    pub fn from_secret(secret: &Secret32) -> Self {
        Self(secret.clone())
    }

    /// The PRK bytes.
    ///
    /// Present because RFC 5869's test vectors pin the PRK as well as the OKM,
    /// and because `mlkb-store` needs the raw bytes to persist a derived key.
    #[must_use]
    pub fn as_secret(&self) -> &Secret32 {
        &self.0
    }

    /// HKDF-Expand into `out` (RFC 5869 §2.3).
    ///
    /// `info` is multi-part for the same reason `ikm` is; spec parent §4.1's
    /// info string is a label followed by two identities.
    ///
    /// # Errors
    /// [`ProtocolError::Malformed`] if `out` is longer than [`HKDF_MAX_OKM`],
    /// which RFC 5869 §2.3 does not define an output for.
    pub fn expand(&self, info: &[&[u8]], out: &mut [u8]) -> Result<(), ProtocolError> {
        if out.len() > HKDF_MAX_OKM {
            return Err(ProtocolError::Malformed);
        }
        self.expand_unchecked(info, out);
        Ok(())
    }

    /// HKDF-Expand into a fixed-size secret container (RFC 5869 §2.3).
    ///
    /// Total: the `const` assertion discharges the only precondition of
    /// [`Prk::expand`] at compile time, so no error can reach the caller and
    /// the derivations built on this — `derive_sk`, the root step, the §4.4
    /// label table — keep the infallible signatures spec parent §4.1 and §8.2
    /// give them.
    #[must_use]
    pub(crate) fn expand_secret<const N: usize>(&self, info: &[&[u8]]) -> SecretBytes<N> {
        const {
            assert!(N <= HKDF_MAX_OKM, "RFC 5869 §2.3 bounds OKM at 255*HashLen");
        }
        SecretBytes::<N>::from_fill(|out| self.expand_unchecked(info, out))
    }

    /// The RFC 5869 §2.3 expansion loop.
    ///
    /// `out.len() <= HKDF_MAX_OKM` is the caller's precondition; the loop
    /// stops after `T(255)` regardless, so violating it truncates rather than
    /// overflowing the block counter.
    fn expand_unchecked(&self, info: &[&[u8]], out: &mut [u8]) {
        use hmac::Mac;

        let key = self.0.expose_secret();
        let mut prev: Option<Zeroizing<[u8; SHA256_LEN]>> = None;
        let mut counter: u8 = 1;
        for block in out.chunks_mut(SHA256_LEN) {
            let mut mac = hmac_state(key);
            if let Some(p) = prev.as_ref() {
                mac.update(p.as_slice());
            }
            for i in info {
                mac.update(i);
            }
            mac.update(&[counter]);
            let t = Zeroizing::new(<[u8; SHA256_LEN]>::from(mac.finalize().into_bytes()));
            copy_prefix(block, t.as_slice());
            prev = Some(t);
            match counter.checked_add(1) {
                Some(next) => counter = next,
                None => break,
            }
        }
    }
}

/// One-shot HKDF-SHA256: extract then expand (RFC 5869 §2).
///
/// Provided for the RFC 5869 known-answer tests spec parent §5.3 requires be
/// kept, and for callers that have no reason to hold on to the PRK.
///
/// # Errors
/// [`ProtocolError::Malformed`] if `out` is longer than [`HKDF_MAX_OKM`].
pub fn hkdf_sha256(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[&[u8]],
    out: &mut [u8],
) -> Result<(), ProtocolError> {
    Prk::extract(salt, &[ikm]).expand(info, out)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn hex(bytes: &[u8]) -> alloc::string::String {
        use core::fmt::Write as _;
        let mut s = alloc::string::String::new();
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    // -----------------------------------------------------------------
    // RFC 5869 known-answer tests (spec parent §5.3: keep the KATs).
    // -----------------------------------------------------------------

    /// RFC 5869 test case 1 (SHA-256, basic).
    #[test]
    fn rfc5869_test_case_1() {
        let ikm = [0x0b_u8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let prk = Prk::extract(Some(&salt), &[&ikm]);
        assert_eq!(
            hex(prk.as_secret().expose_secret()),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let mut okm = [0u8; 42];
        prk.expand(&[&info], &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // The one-shot form agrees.
        let mut okm2 = [0u8; 42];
        hkdf_sha256(Some(&salt), &ikm, &[&info], &mut okm2).unwrap();
        assert_eq!(okm, okm2);

        // Splitting the info into pieces is the same as concatenating it.
        let mut okm3 = [0u8; 42];
        prk.expand(&[&info[..4], &info[4..]], &mut okm3).unwrap();
        assert_eq!(okm, okm3);

        // Splitting the ikm is the same as concatenating it.
        let prk2 = Prk::extract(Some(&salt), &[&ikm[..7], &ikm[7..]]);
        assert_eq!(prk2.as_secret(), prk.as_secret());

        // Expand-from-PRK reaches the same OKM (RFC 5869 §3.3).
        let mut okm4 = [0u8; 42];
        Prk::from_secret(prk.as_secret())
            .expand(&[&info], &mut okm4)
            .unwrap();
        assert_eq!(okm, okm4);
    }

    /// RFC 5869 test case 2 (SHA-256, longer inputs and output: 3 blocks).
    #[test]
    fn rfc5869_test_case_2() {
        let ikm: Vec<u8> = (0u8..=0x4f).collect();
        let salt: Vec<u8> = (0x60u8..=0xaf).collect();
        let info: Vec<u8> = (0xb0u8..=0xff).collect();

        let prk = Prk::extract(Some(&salt), &[&ikm]);
        assert_eq!(
            hex(prk.as_secret().expose_secret()),
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
        );

        let mut okm = [0u8; 82];
        prk.expand(&[&info], &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87"
                .replace(' ', "")
        );
    }

    /// RFC 5869 test case 3 (SHA-256, zero-length salt and info).
    #[test]
    fn rfc5869_test_case_3() {
        let ikm = [0x0b_u8; 22];
        let prk = Prk::extract(None, &[&ikm]);
        assert_eq!(
            hex(prk.as_secret().expose_secret()),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );

        let mut okm = [0u8; 42];
        prk.expand(&[], &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );

        // An empty salt is the same as no salt (RFC 5869 §2.2).
        let prk_empty = Prk::extract(Some(&[]), &[&ikm]);
        assert_eq!(prk_empty.as_secret(), prk.as_secret());
    }

    /// This crate's HKDF-Expand and the `hkdf` crate's agree everywhere.
    ///
    /// Spec parent §5.3 says to drop the hand-rolled HKDF. `Prk::extract` uses
    /// the crate; `Prk::expand` does not, because `hkdf`'s expander is
    /// fallible in a way that would force a panicking path into `derive_sk`
    /// (spec parent §4.1 pins its signature as infallible). This test is what
    /// makes that substitution safe: it is an equivalence proof over every
    /// output length from 0 to three blocks, and over multi-part info.
    #[test]
    fn expand_agrees_with_the_hkdf_crate() {
        let prk_bytes = Secret32::new([0x5a_u8; 32]);
        let ours = Prk::from_secret(&prk_bytes);
        let theirs = hkdf::Hkdf::<Sha256>::from_prk(prk_bytes.expose_secret()).unwrap();

        for len in 0..=96usize {
            let info = [0x11_u8, 0x22, 0x33];
            let mut a = vec![0u8; len];
            let mut b = vec![0u8; len];
            ours.expand(&[&info], &mut a).unwrap();
            theirs.expand(&info, &mut b).unwrap();
            assert_eq!(a, b, "length {len}");
        }

        // Multi-part info == concatenated info, on both sides.
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        ours.expand(&[b"one", b"two", b"three"], &mut a).unwrap();
        theirs.expand(b"onetwothree", &mut b).unwrap();
        assert_eq!(a, b);

        // And the full extract+expand pipeline agrees.
        let (_, hk) = hkdf::Hkdf::<Sha256>::extract(Some(b"salt"), b"ikm");
        let mut c = [0u8; 42];
        let mut d = [0u8; 42];
        Prk::extract(Some(b"salt"), &[b"ikm"])
            .expand(&[b"info"], &mut c)
            .unwrap();
        hk.expand(b"info", &mut d).unwrap();
        assert_eq!(c, d);
    }

    #[test]
    fn expand_rejects_an_output_past_the_rfc_bound() {
        let prk = Prk::from_secret(&Secret32::new([1u8; 32]));
        let mut ok = vec![0u8; HKDF_MAX_OKM];
        assert_eq!(prk.expand(&[b"i"], &mut ok), Ok(()));
        let mut too_long = vec![0u8; HKDF_MAX_OKM + 1];
        assert_eq!(
            prk.expand(&[b"i"], &mut too_long),
            Err(ProtocolError::Malformed)
        );
        // A rejected expansion writes nothing.
        assert!(too_long.iter().all(|b| *b == 0));
    }

    #[test]
    fn expand_is_domain_separated_by_info() {
        let prk = Prk::from_secret(&Secret32::new([7u8; 32]));
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        prk.expand(&[crate::labels::FRAME_I2R], &mut a).unwrap();
        prk.expand(&[crate::labels::FRAME_R2I], &mut b).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn expand_secret_matches_expand() {
        let prk = Prk::from_secret(&Secret32::new([3u8; 32]));
        let got: SecretBytes<64> = prk.expand_secret(&[b"label"]);
        let mut want = [0u8; 64];
        prk.expand(&[b"label"], &mut want).unwrap();
        assert_eq!(got.expose_secret(), &want);
    }

    // -----------------------------------------------------------------
    // HMAC / SHA
    // -----------------------------------------------------------------

    /// RFC 4231 test case 1.
    #[test]
    fn rfc4231_test_case_1() {
        let tag = hmac_sha256(&[0x0b_u8; 20], &[b"Hi There"]);
        assert_eq!(
            hex(tag.as_bytes()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 test case 2 — a key shorter than the block, ASCII.
    #[test]
    fn rfc4231_test_case_2() {
        let tag = hmac_sha256(b"Jefe", &[b"what do ya want ", b"for nothing?"]);
        assert_eq!(
            hex(tag.as_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// RFC 4231 test case 6 — a key **longer** than the 64-byte block, which
    /// is the branch of `hmac_state` that hashes the key first.
    #[test]
    fn rfc4231_test_case_6_long_key() {
        let key = [0xaa_u8; 131];
        let tag = hmac_sha256(
            &key,
            &[b"Test Using Larger Than Block-Size Key - Hash Key First"],
        );
        assert_eq!(
            hex(tag.as_bytes()),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn hmac_multi_part_equals_concatenated() {
        let key = [9u8; 32];
        let a = hmac_sha256(&key, &[b"abcdef"]);
        let b = hmac_sha256(&key, &[b"abc", b"def"]);
        let c = hmac_sha256(&key, &[b"", b"abcdef", b""]);
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, hmac_sha256(&key, &[b"abcdeg"]));
        assert_ne!(a, hmac_sha256(&[8u8; 32], &[b"abcdef"]));
    }

    #[test]
    fn mac_verify_accepts_equal_and_rejects_every_single_bit_flip() {
        let tag = hmac_sha256(&[1u8; 32], &[b"m"]);
        assert_eq!(tag.verify(&tag), Ok(()));
        assert_eq!(tag, Mac256::from_bytes(*tag.as_bytes()));

        for byte in 0..SHA256_LEN {
            for bit in 0..8u32 {
                let mut bad = *tag.as_bytes();
                bad[byte] ^= 1u8 << bit;
                let bad = Mac256::from_bytes(bad);
                assert_eq!(
                    tag.verify(&bad),
                    Err(ProtocolError::Unauthenticated),
                    "accepted a flip at {byte}:{bit}"
                );
                assert_ne!(tag, bad);
            }
        }
    }

    #[test]
    fn sha256_matches_the_fips_180_4_vector() {
        assert_eq!(
            hex(&sha256(&[b"abc"])),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Multi-part == concatenated.
        assert_eq!(sha256(&[b"ab", b"c"]), sha256(&[b"abc"]));
        assert_eq!(
            hex(&sha256(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha512_matches_the_fips_180_4_vector() {
        assert_eq!(
            hex(&sha512(&[b"abc"])),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                .replace(' ', "")
        );
        assert_eq!(sha512(&[b"a", b"bc"]), sha512(&[b"abc"]));
        assert_eq!(sha512(&[b"abc"]).len(), SHA512_LEN);
    }

    #[test]
    fn prk_debug_is_redacted() {
        let prk = Prk::from_secret(&Secret32::new([0xab_u8; 32]));
        let rendered = alloc::format!("{prk:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("ab"));
    }
}
