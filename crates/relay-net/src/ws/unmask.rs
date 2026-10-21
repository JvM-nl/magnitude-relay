//! Frame payload masking (RFC 6455 §5.3). Client-to-server payloads are XORed
//! with a repeating 4-byte key; the same operation masks and unmasks.
//!
//! This is the one loop in the protocol that touches every payload byte, so it is
//! kept in its own function with a plain signature: the production box has AVX2 and
//! a runtime-dispatched variant can replace the body without touching a caller.

/// XORs `buf` with the repeating `mask`. Byte `i` of `buf` is treated as byte
/// `offset + i` of the payload, i.e. it is XORed with `mask[(offset + i) % 4]`;
/// pass the payload offset of `buf[0]` when unmasking a payload piecewise.
///
/// Eight bytes per step: the mask, rotated to the starting phase, is repeated into
/// a `u64`. Eight is a multiple of four, so the phase is the same at the start of
/// every step and only the sub-8-byte tail needs per-byte indexing. Native-endian
/// loads are fine because the key's in-memory layout matches the data's.
#[inline]
pub fn unmask(buf: &mut [u8], mask: [u8; 4], offset: usize) {
    let r = offset & 3;
    let m = [mask[r], mask[(r + 1) & 3], mask[(r + 2) & 3], mask[(r + 3) & 3]];
    let key = u64::from_ne_bytes([m[0], m[1], m[2], m[3], m[0], m[1], m[2], m[3]]);
    let mut chunks = buf.chunks_exact_mut(8);
    for c in &mut chunks {
        let v = u64::from_ne_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) ^ key;
        c.copy_from_slice(&v.to_ne_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= m[i & 3];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The definition from the RFC, byte by byte.
    fn reference(buf: &mut [u8], mask: [u8; 4], offset: usize) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b ^= mask[(offset + i) % 4];
        }
    }

    #[test]
    fn matches_reference_for_every_length_and_phase() {
        let masks = [[0x37, 0xfa, 0x21, 0x3d], [0, 0, 0, 0], [0xff; 4], [1, 2, 3, 4], [0x80, 0x01, 0x7f, 0xfe]];
        for mask in masks {
            for offset in 0..9 {
                for len in 0..300 {
                    let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
                    let mut fast = data.clone();
                    let mut slow = data.clone();
                    unmask(&mut fast, mask, offset);
                    reference(&mut slow, mask, offset);
                    assert_eq!(fast, slow, "mask {mask:?} offset {offset} len {len}");
                }
            }
        }
    }

    #[test]
    fn is_an_involution() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 13) as u8).collect();
        let mut v = data.clone();
        unmask(&mut v, [9, 8, 7, 6], 0);
        assert_ne!(v, data);
        unmask(&mut v, [9, 8, 7, 6], 0);
        assert_eq!(v, data);
    }

    #[test]
    fn piecewise_equals_whole() {
        // Unmasking in arbitrary pieces with the right offsets must equal one pass.
        let mask = [0xde, 0xad, 0xbe, 0xef];
        let data: Vec<u8> = (0..257u32).map(|i| (i * 5) as u8).collect();
        let mut whole = data.clone();
        unmask(&mut whole, mask, 0);
        for cut in 0..=data.len() {
            let mut parts = data.clone();
            let (a, b) = parts.split_at_mut(cut);
            unmask(a, mask, 0);
            unmask(b, mask, cut);
            assert_eq!(parts, whole, "cut {cut}");
        }
    }
}
