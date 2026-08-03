//! Panic-free byte plumbing (spec parent §11 gate 7).
//!
//! Nothing in this module is cryptographic. It exists so that no library path
//! in the crate reaches for `copy_from_slice`, `split_at` or `a[i..j]`, all of
//! which panic on a length mismatch.

/// Copies `min(dst.len(), src.len())` bytes of `src` over the head of `dst`.
///
/// Total for every pair of lengths. Where the two lengths are equal by
/// construction — a 32-byte digest into a 32-byte container — this is a
/// full copy; that equality is the caller's to establish and every caller in
/// this crate establishes it with a fixed-size type on both sides.
pub(crate) fn copy_prefix(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d = *s;
    }
}

/// Reads a big-endian `u16` from the front of `bytes`, returning the rest.
///
/// `None` if fewer than two bytes remain (spec M1 §A.1: big-endian is the
/// project's fixed-layout byte order).
pub(crate) fn take_u16_be(bytes: &[u8]) -> Option<(u16, &[u8])> {
    let (head, rest) = bytes.split_at_checked(2)?;
    let value = u16::from_be_bytes(*head.first_chunk::<2>()?);
    Some((value, rest))
}

/// Splits `n` bytes off the front of `bytes` (spec M1 §E.1 exact lengths).
pub(crate) fn take(bytes: &[u8], n: usize) -> Option<(&[u8], &[u8])> {
    bytes.split_at_checked(n)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn copy_prefix_never_panics_at_any_length_pair() {
        for dst_len in 0..8usize {
            for src_len in 0..8usize {
                let mut dst = vec![0xff_u8; dst_len];
                let src: alloc::vec::Vec<u8> = (0..src_len)
                    .map(|i| u8::try_from(i).unwrap_or(0) + 1)
                    .collect();
                copy_prefix(&mut dst, &src);
                let n = dst_len.min(src_len);
                assert_eq!(&dst[..n], &src[..n]);
                // The tail of `dst` is untouched.
                assert!(dst[n..].iter().all(|b| *b == 0xff));
            }
        }
    }

    #[test]
    fn take_u16_be_reads_network_order_and_bounds_check() {
        assert_eq!(
            take_u16_be(&[0x02, 0x00, 0x09]),
            Some((0x0200, &[0x09][..]))
        );
        assert_eq!(take_u16_be(&[0xff, 0xff]), Some((0xffff, &[][..])));
        assert_eq!(take_u16_be(&[0x01]), None);
        assert_eq!(take_u16_be(&[]), None);
    }

    #[test]
    fn take_bounds_check() {
        let b = [1u8, 2, 3];
        assert_eq!(take(&b, 0), Some((&[][..], &b[..])));
        assert_eq!(take(&b, 3), Some((&b[..], &[][..])));
        assert_eq!(take(&b, 4), None);
    }
}
