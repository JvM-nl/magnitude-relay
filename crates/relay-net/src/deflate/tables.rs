//! Constants both halves of the codec agree on (RFC 1951 §3.2.5-3.2.7).

/// Shortest and longest match a DEFLATE stream can express.
pub const MIN_MATCH: usize = 3;
pub const MAX_MATCH: usize = 258;
/// Window sizes are `1 << bits` for 8..=15 (RFC 7692 allows the same range).
pub const MIN_WINDOW_BITS: u8 = 8;
pub const MAX_WINDOW_BITS: u8 = 15;
/// Longest Huffman codeword.
pub const MAX_CODE_BITS: usize = 15;
/// Literal/length alphabet size including the two codes (286, 287) that exist only
/// in the fixed table and are an error if they ever appear in data.
pub const LITLEN_SYMBOLS: usize = 288;
/// Distance alphabet size including the two codes (30, 31) that are never valid.
pub const DIST_SYMBOLS: usize = 32;
/// The end-of-block symbol.
pub const EOB: usize = 256;

/// The four bytes of an empty stored block (`LEN = 0`, `NLEN = 0xffff`) that a
/// sync flush ends with and that RFC 7692 §7.2.1 strips from every message.
pub const SYNC_TAIL: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

/// Base match length of length symbols 257..=285, and the extra bits that follow.
pub const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
pub const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];

/// Base distance of distance symbols 0..=29, and the extra bits that follow.
pub const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
pub const DIST_EXTRA: [u8; 30] =
    [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// The order the code-length code's own lengths are transmitted in (§3.2.7).
pub const CL_ORDER: [u8; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/// Length code (0..=28, i.e. symbol - 257) for a match length, indexed by
/// `length - MIN_MATCH`. Length 258 gets its own code (285) rather than the
/// 5-extra-bit form of 284 that could also express it: every decoder accepts the
/// short form and zlib never emits the other.
pub static LEN_CODE: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut l = 0;
    while l < 256 {
        let len = l + MIN_MATCH;
        let mut c = 28;
        if len != MAX_MATCH {
            c = 0;
            while c + 1 < 28 && LEN_BASE[c + 1] as usize <= len {
                c += 1;
            }
        }
        t[l] = c as u8;
        l += 1;
    }
    t
};

/// Extra-bit count for a match length, indexed by `length - MIN_MATCH`.
pub static LEN_EXTRA_BITS: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut l = 0;
    while l < 256 {
        t[l] = LEN_EXTRA[LEN_CODE[l] as usize];
        l += 1;
    }
    t
};

/// Distance code for `distance - 1` (0..=32767). The code is a function of the
/// position of the top bit and the bit under it: codes 2k and 2k+1 split each
/// power-of-two range in half, and every base-minus-one is a multiple of its
/// own extra-bit span, so the extra bits are just the low bits of `distance - 1`.
#[inline(always)]
pub fn dist_code(d: u32) -> usize {
    if d < 4 {
        d as usize
    } else {
        let n = 31 - d.leading_zeros();
        ((n << 1) | ((d >> (n - 1)) & 1)) as usize
    }
}

/// Fixed-Huffman literal/length code lengths (§3.2.6).
pub static FIXED_LITLEN_LENS: [u8; LITLEN_SYMBOLS] = {
    let mut t = [8u8; LITLEN_SYMBOLS];
    let mut i = 144;
    while i < 256 {
        t[i] = 9;
        i += 1;
    }
    while i < 280 {
        t[i] = 7;
        i += 1;
    }
    t
};

/// Fixed-Huffman distance code lengths: all 32 codes are five bits.
pub static FIXED_DIST_LENS: [u8; DIST_SYMBOLS] = [5; DIST_SYMBOLS];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_codes_invert_the_base_tables() {
        for len in MIN_MATCH..=MAX_MATCH {
            let c = LEN_CODE[len - MIN_MATCH] as usize;
            let (base, extra) = (LEN_BASE[c] as usize, LEN_EXTRA[c]);
            assert!(len >= base && len - base < (1 << extra).max(1), "len {len} code {c}");
            assert_eq!(LEN_EXTRA_BITS[len - MIN_MATCH], extra);
            // The extra bits are the low bits of (len - 3): bases are aligned to their span.
            if extra > 0 {
                assert_eq!((len - MIN_MATCH) & ((1 << extra) - 1), len - base, "len {len}");
            }
        }
        assert_eq!(LEN_CODE[MAX_MATCH - MIN_MATCH], 28);
        assert_eq!(LEN_CODE[257 - MIN_MATCH], 27, "257 uses the 5-extra-bit form of code 284");
    }

    #[test]
    fn distance_codes_invert_the_base_tables() {
        for dist in 1..=32768usize {
            let c = dist_code(dist as u32 - 1);
            let (base, extra) = (DIST_BASE[c] as usize, DIST_EXTRA[c]);
            assert!(dist >= base && dist - base < (1 << extra), "dist {dist} code {c}");
            assert_eq!((dist - 1) & ((1 << extra) - 1), dist - base, "dist {dist}");
        }
    }

    #[test]
    fn fixed_code_is_complete() {
        // Kraft sum of the fixed literal/length code is exactly 1.
        let sum: u64 = FIXED_LITLEN_LENS.iter().map(|&l| 1u64 << (15 - l)).sum();
        assert_eq!(sum, 1 << 15);
        let sum: u64 = FIXED_DIST_LENS.iter().map(|&l| 1u64 << (15 - l)).sum();
        assert_eq!(sum, 1 << 15);
    }
}
