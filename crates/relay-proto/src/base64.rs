//! Standard-alphabet base64 with padding (RFC 4648 §4), for gift-wrap content.
//!
//! A NIP-44 payload is base64 and is most of what the relay stores, so records
//! keep it decoded (a quarter smaller) when the text is exactly the canonical
//! encoding of its bytes, and every event sent encodes it again. Decoding is
//! therefore strict in a way RFC 4648 decoders usually are not: it succeeds only
//! when encoding the result gives back the same text (no whitespace, `=` only
//! as the last one or two characters, the unused bits of the last character
//! zero), so the round trip is byte-exact.
//!
//! Bulk work is SIMD: AVX2 on x86 (production's Skylake; 24 bytes <-> 32
//! characters a step, Muła and Lemire's method), NEON on ARM (48 <-> 64 with
//! interleaving loads and stores and a 64-entry table). Tails and other CPUs
//! use the scalar loops, which are also the tests' reference.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const INVALID: u8 = 0xFF;

/// Character -> its six bits, `INVALID` for anything outside the alphabet (`=` included).
static DECODE: [u8; 256] = {
    let mut t = [INVALID; 256];
    let mut i = 0;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
};

/// Length of the padded encoding of `n` bytes.
#[inline]
pub const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// The length `text` decodes to if it is canonical base64; `None` when its
/// length alone rules that out.
#[inline]
pub fn decoded_len(text: &[u8]) -> Option<usize> {
    let n = text.len();
    if n % 4 != 0 {
        return None;
    }
    let pad = match text {
        [.., b'=', b'='] => 2,
        [.., b'='] => 1,
        _ => 0,
    };
    Some(n / 4 * 3 - pad)
}

/// Appends the padded encoding of `src` to `out`.
#[inline]
pub fn encode_into(src: &[u8], out: &mut Vec<u8>) {
    let n = encoded_len(src.len());
    out.reserve(n);
    let start = out.len();
    // SAFETY: `reserve` made room for `n` bytes past `start`; the SIMD part and
    // the scalar tail together write every one of them (neither writes beyond).
    unsafe {
        let dst = out.as_mut_ptr().add(start);
        let done = simd_encode(src, dst);
        encode_scalar(&src[done..], dst.add(done / 3 * 4));
        out.set_len(start + n);
    }
}

/// Appends the bytes `src` encodes and returns true, if and only if `src` is
/// exactly the padded encoding of those bytes. Otherwise returns false and
/// leaves `out` as it was.
#[inline]
pub fn decode_canonical_into(src: &[u8], out: &mut Vec<u8>) -> bool {
    let Some(len) = decoded_len(src) else { return false };
    let n = src.len();
    if n == 0 {
        return true;
    }
    // AVX2 stores 32 bytes for every 24 it decodes.
    out.reserve(len + 32);
    let start = out.len();
    // SAFETY: room for `len + 32` bytes past `start`. The SIMD part decodes
    // whole blocks of the quads before the last (`body`), which are worth
    // `body / 4 * 3 <= len` bytes, and may store up to 8 bytes past them; the
    // scalar part writes exactly the remaining bytes up to `len`. The length is
    // set only when every byte up to `len` was written and the text was valid.
    unsafe {
        let dst = out.as_mut_ptr().add(start);
        let body = n - 4;
        let Some(done) = simd_decode(&src[..body], dst) else { return false };
        let o = done / 4 * 3;
        if !decode_scalar(&src[done..body], dst.add(o)) || !decode_last(&src[body..], dst.add(o + (body - done) / 4 * 3)) {
            return false;
        }
        out.set_len(start + len);
    }
    true
}

/// Encodes all of `src` (whole groups, then the padded rest) to `dst`.
#[inline]
unsafe fn encode_scalar(src: &[u8], dst: *mut u8) {
    let mut o = dst;
    let mut groups = src.chunks_exact(3);
    for g in &mut groups {
        let v = (u32::from(g[0]) << 16) | (u32::from(g[1]) << 8) | u32::from(g[2]);
        *o = ALPHABET[(v >> 18) as usize];
        *o.add(1) = ALPHABET[(v >> 12) as usize & 63];
        *o.add(2) = ALPHABET[(v >> 6) as usize & 63];
        *o.add(3) = ALPHABET[v as usize & 63];
        o = o.add(4);
    }
    let (v, chars) = match *groups.remainder() {
        [a] => (u32::from(a) << 16, 2),
        [a, b] => ((u32::from(a) << 16) | (u32::from(b) << 8), 3),
        _ => return,
    };
    for i in 0..4 {
        *o.add(i) = if i < chars { ALPHABET[(v >> (18 - 6 * i)) as usize & 63] } else { b'=' };
    }
}

/// Decodes whole quads with no padding; false on any character outside the alphabet.
#[inline]
unsafe fn decode_scalar(src: &[u8], dst: *mut u8) -> bool {
    let mut o = dst;
    let mut bad = 0u8;
    for q in src.chunks_exact(4) {
        let (a, b, c, d) = (DECODE[q[0] as usize], DECODE[q[1] as usize], DECODE[q[2] as usize], DECODE[q[3] as usize]);
        // One branch for the whole text: invalid characters set the high bit.
        bad |= a | b | c | d;
        let v = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        *o = (v >> 16) as u8;
        *o.add(1) = (v >> 8) as u8;
        *o.add(2) = v as u8;
        o = o.add(3);
    }
    bad & 0x80 == 0
}

/// The final quad, which may end in one or two `=`: the bits a shorter group
/// leaves unused must be zero, or the text is not the encoding of its bytes.
#[inline]
unsafe fn decode_last(q: &[u8], dst: *mut u8) -> bool {
    let (a, b) = (DECODE[q[0] as usize], DECODE[q[1] as usize]);
    if (a | b) & 0x80 != 0 {
        return false;
    }
    match (q[2], q[3]) {
        (b'=', b'=') => {
            if b & 0x0F != 0 {
                return false;
            }
            *dst = (a << 2) | (b >> 4);
        }
        (c, b'=') => {
            let c = DECODE[c as usize];
            if c & 0x80 != 0 || c & 0x03 != 0 {
                return false;
            }
            *dst = (a << 2) | (b >> 4);
            *dst.add(1) = (b << 4) | (c >> 2);
        }
        _ => return decode_scalar(q, dst),
    }
    true
}

/// Encodes a prefix of `src` into `dst` with SIMD; returns how many input
/// bytes it took (a multiple of three, so the rest starts on a group).
#[inline]
unsafe fn simd_encode(src: &[u8], dst: *mut u8) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if src.len() >= 32 && std::arch::is_x86_feature_detected!("avx2") {
            return encode_avx2(src, dst);
        }
        0
    }
    #[cfg(target_arch = "aarch64")]
    {
        encode_neon(src, dst)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (src, dst);
        0
    }
}

/// Decodes a prefix of `src` (whole quads, no padding) into `dst` with SIMD;
/// returns how many characters it took (a multiple of four), or `None` if one
/// of them is outside the alphabet.
#[inline]
unsafe fn simd_decode(src: &[u8], dst: *mut u8) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        if src.len() >= 32 && std::arch::is_x86_feature_detected!("avx2") {
            return decode_avx2(src, dst);
        }
        Some(0)
    }
    #[cfg(target_arch = "aarch64")]
    {
        decode_neon(src, dst)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (src, dst);
        Some(0)
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn encode_avx2(src: &[u8], dst: *mut u8) -> usize {
    use std::arch::x86_64::*;
    // Each group of three bytes a b c lands in a 32-bit lane as b a c b, so
    // that its four sextets can be masked and shifted into place.
    // Lane 0 reads its 12 bytes from offset 4, lane 1 from offset 0.
    let spread = _mm256_setr_epi8(
        5, 4, 6, 5, 8, 7, 9, 8, 11, 10, 12, 11, 14, 13, 15, 14, //
        1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10,
    );
    // Sextet -> character: the offset to add, indexed by which run of the
    // alphabet the sextet is in (A-Z, a-z, 0-9, +, /).
    let offsets = _mm256_setr_epi8(
        65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0, //
        65, 71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 0, 0,
    );
    let n = src.len();
    // The first block reads bytes 0-31 and moves lane 0's 12 bytes up by 4;
    // later ones read from 4 bytes before the block, which needs no move.
    let mut v = _mm256_permutevar8x32_epi32(_mm256_loadu_si256(src.as_ptr() as *const __m256i), _mm256_setr_epi32(0, 0, 1, 2, 3, 4, 5, 6));
    let (mut i, mut o) = (0, 0);
    loop {
        let g = _mm256_shuffle_epi8(v, spread);
        // Each sextet shifted to its own byte. (The published method uses
        // mulhi/mullo by powers of two, which LLVM turns into widening
        // variable shifts that cost twice as much on Skylake's port 5.)
        let a = _mm256_srli_epi32(_mm256_and_si256(g, _mm256_set1_epi32(0x0000_FC00)), 10);
        let b = _mm256_slli_epi32(_mm256_and_si256(g, _mm256_set1_epi32(0x0000_03F0)), 4);
        let c = _mm256_srli_epi32(_mm256_and_si256(g, _mm256_set1_epi32(0x0FC0_0000)), 6);
        let d = _mm256_slli_epi32(_mm256_and_si256(g, _mm256_set1_epi32(0x003F_0000)), 8);
        let sextets = _mm256_or_si256(_mm256_or_si256(a, b), _mm256_or_si256(c, d));
        let mut idx = _mm256_subs_epu8(sextets, _mm256_set1_epi8(51));
        idx = _mm256_sub_epi8(idx, _mm256_cmpgt_epi8(sextets, _mm256_set1_epi8(25)));
        _mm256_storeu_si256(dst.add(o) as *mut __m256i, _mm256_add_epi8(sextets, _mm256_shuffle_epi8(offsets, idx)));
        i += 24;
        o += 32;
        if i + 28 > n {
            break;
        }
        v = _mm256_loadu_si256(src.as_ptr().add(i - 4) as *const __m256i);
    }
    i
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn decode_avx2(src: &[u8], dst: *mut u8) -> Option<usize> {
    use std::arch::x86_64::*;
    // Validity by nibbles: a character is in the alphabet exactly when the
    // classes of its low and high nibble share no bit.
    let lo_class = _mm256_setr_epi8(
        0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A, //
        0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A,
    );
    let hi_class = _mm256_setr_epi8(
        0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, //
        0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
    );
    // Character -> sextet: the offset to add, by high nibble ('/' shares '+''s
    // nibble and is moved to slot 1).
    let offsets = _mm256_setr_epi8(
        0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0, //
        0, 16, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0,
    );
    // 0x2F masks the nibbles (shuffles ignore bits 4-6) and is also '/'.
    let mask = _mm256_set1_epi8(0x2F);
    // Sextets a b c d -> 24 bits -> three bytes, high first, packed to 12 bytes a lane.
    let pack = _mm256_setr_epi8(
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1, //
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
    );
    let lanes = _mm256_setr_epi32(0, 1, 2, 4, 5, 6, 0, 0);
    let n = src.len();
    let (mut i, mut o) = (0, 0);
    while i + 32 <= n {
        let v = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        let hi = _mm256_and_si256(_mm256_srli_epi32(v, 4), mask);
        let lo = _mm256_and_si256(v, mask);
        if _mm256_testz_si256(_mm256_shuffle_epi8(lo_class, lo), _mm256_shuffle_epi8(hi_class, hi)) == 0 {
            return None;
        }
        let slot = _mm256_add_epi8(_mm256_cmpeq_epi8(v, mask), hi);
        let sextets = _mm256_add_epi8(v, _mm256_shuffle_epi8(offsets, slot));
        let pairs = _mm256_maddubs_epi16(sextets, _mm256_set1_epi32(0x0140_0140));
        let words = _mm256_madd_epi16(pairs, _mm256_set1_epi32(0x0001_1000));
        let bytes = _mm256_permutevar8x32_epi32(_mm256_shuffle_epi8(words, pack), lanes);
        _mm256_storeu_si256(dst.add(o) as *mut __m256i, bytes);
        i += 32;
        o += 24;
    }
    Some(i)
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn encode_neon(src: &[u8], dst: *mut u8) -> usize {
    use std::arch::aarch64::*;
    let table = vld1q_u8_x4(ALPHABET.as_ptr());
    let low6 = vdupq_n_u8(0x3F);
    let mut i = 0;
    let mut o = dst;
    while i + 48 <= src.len() {
        // De-interleaved on load: the first, second and third byte of 16 groups.
        let g = vld3q_u8(src.as_ptr().add(i));
        let a = vshrq_n_u8(g.0, 2);
        let b = vandq_u8(vorrq_u8(vshlq_n_u8(g.0, 4), vshrq_n_u8(g.1, 4)), low6);
        let c = vandq_u8(vorrq_u8(vshlq_n_u8(g.1, 2), vshrq_n_u8(g.2, 6)), low6);
        let d = vandq_u8(g.2, low6);
        let chars = uint8x16x4_t(vqtbl4q_u8(table, a), vqtbl4q_u8(table, b), vqtbl4q_u8(table, c), vqtbl4q_u8(table, d));
        vst4q_u8(o, chars);
        i += 48;
        o = o.add(64);
    }
    i
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn decode_neon(src: &[u8], dst: *mut u8) -> Option<usize> {
    use std::arch::aarch64::*;
    // DECODE in two 64-entry tables: characters 0-63 and 64-127. A table
    // lookup out of range gives 0, so each character takes its value from
    // one table and 0 from the other; bytes of 128 and up get 0 from both and
    // are caught by their own high bit.
    let low = vld1q_u8_x4(DECODE.as_ptr());
    let high = vld1q_u8_x4(DECODE.as_ptr().add(64));
    let k64 = vdupq_n_u8(64);
    let sextets = |v: uint8x16_t, bad: &mut uint8x16_t| {
        let s = vorrq_u8(vqtbl4q_u8(low, v), vqtbl4q_u8(high, vsubq_u8(v, k64)));
        *bad = vorrq_u8(*bad, vorrq_u8(s, v));
        s
    };
    let mut i = 0;
    let mut o = dst;
    while i + 64 <= src.len() {
        let mut bad = vdupq_n_u8(0);
        // De-interleaved on load: the first, second, third and fourth character of 16 quads.
        let q = vld4q_u8(src.as_ptr().add(i));
        let (a, b, c, d) = (sextets(q.0, &mut bad), sextets(q.1, &mut bad), sextets(q.2, &mut bad), sextets(q.3, &mut bad));
        if vmaxvq_u8(bad) & 0x80 != 0 {
            return None;
        }
        let x = vorrq_u8(vshlq_n_u8(a, 2), vshrq_n_u8(b, 4));
        let y = vorrq_u8(vshlq_n_u8(b, 4), vshrq_n_u8(c, 2));
        let z = vorrq_u8(vshlq_n_u8(c, 6), d);
        vst3q_u8(o, uint8x16x3_t(x, y, z));
        i += 64;
        o = o.add(48);
    }
    Some(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The definition, bit by bit: the reference everything else is checked against.
    fn reference_encode(src: &[u8]) -> Vec<u8> {
        let mut bits = Vec::new();
        for &b in src {
            for k in (0..8).rev() {
                bits.push((b >> k) & 1);
            }
        }
        while bits.len() % 6 != 0 {
            bits.push(0);
        }
        let mut out: Vec<u8> = bits.chunks(6).map(|c| ALPHABET[c.iter().fold(0, |a, &b| (a << 1) | b as usize)]).collect();
        while out.len() % 4 != 0 {
            out.push(b'=');
        }
        out
    }

    fn encode(src: &[u8]) -> Vec<u8> {
        let mut out = b"prefix".to_vec();
        encode_into(src, &mut out);
        out.split_off(6)
    }

    fn decode(src: &[u8]) -> Option<Vec<u8>> {
        let mut out = b"prefix".to_vec();
        let ok = decode_canonical_into(src, &mut out);
        if !ok {
            assert_eq!(out, b"prefix", "a failed decode leaves the buffer as it was");
            return None;
        }
        Some(out.split_off(6))
    }

    fn scalar_encode(src: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; encoded_len(src.len())];
        unsafe { encode_scalar(src, out.as_mut_ptr()) };
        out
    }

    /// The scalar path alone, as a CPU without SIMD runs it.
    fn scalar_decode(src: &[u8]) -> Option<Vec<u8>> {
        if src.is_empty() {
            return Some(Vec::new());
        }
        if src.len() % 4 != 0 {
            return None;
        }
        let pad = src.iter().rev().take(2).filter(|&&c| c == b'=').count();
        let mut out = vec![0u8; src.len() / 4 * 3];
        let body = src.len() - 4;
        let ok = unsafe { decode_scalar(&src[..body], out.as_mut_ptr()) && decode_last(&src[body..], out.as_mut_ptr().add(body / 4 * 3)) };
        out.truncate(src.len() / 4 * 3 - pad);
        ok.then_some(out)
    }

    fn data(len: usize, seed: u32) -> Vec<u8> {
        (0..len as u32).map(|i| (i.wrapping_add(seed).wrapping_mul(2654435761) >> 13) as u8).collect()
    }

    #[test]
    fn every_length_round_trips_against_the_reference() {
        for len in 0..=200 {
            for seed in [0, 1, 77] {
                let bytes = data(len, seed);
                let text = reference_encode(&bytes);
                assert_eq!(encode(&bytes), text, "encode, len {len}");
                assert_eq!(scalar_encode(&bytes), text, "scalar encode, len {len}");
                assert_eq!(decode(&text).as_deref(), Some(&bytes[..]), "decode, len {len}");
                assert_eq!(scalar_decode(&text).as_deref(), Some(&bytes[..]), "scalar decode, len {len}");
            }
        }
        // Long ones, through many SIMD blocks, at every alignment of the tail.
        for len in 1000..1100 {
            let bytes = data(len, 3);
            let text = reference_encode(&bytes);
            assert_eq!(encode(&bytes), text, "encode, len {len}");
            assert_eq!(decode(&text).as_deref(), Some(&bytes[..]), "decode, len {len}");
        }
    }

    #[test]
    fn matches_the_base64_crate() {
        use ::base64::engine::general_purpose::STANDARD;
        use ::base64::Engine;
        for len in (0..300).chain([1024, 1400, 4095, 65536]) {
            let bytes = data(len, 9);
            let text = STANDARD.encode(&bytes);
            assert_eq!(encode(&bytes), text.as_bytes(), "len {len}");
            assert_eq!(decode(text.as_bytes()), Some(bytes), "len {len}");
        }
        // Every character in every position of a block: the crate (strict,
        // canonical padding) and we agree on what is valid.
        let base = reference_encode(&data(120, 5));
        for at in [0, 1, 2, 3, 31, 32, 63, 64, 100, 155, 156, 157, 158, 159] {
            for c in 0..=255u8 {
                let mut t = base.clone();
                t[at] = c;
                assert_eq!(decode(&t), STANDARD.decode(&t).ok(), "{c:#04x} at {at}");
            }
        }
    }

    #[test]
    fn padding_must_be_canonical() {
        for len in 0..40 {
            let bytes = data(len, 11);
            let text = reference_encode(&bytes);
            if len % 3 == 0 {
                continue;
            }
            // The last character before the padding carries bits the group
            // does not use: any of them set and the text is another encoding.
            let last = text.len() - 1 - (3 - len % 3);
            let unused = if len % 3 == 1 { 4 } else { 2 };
            for bit in 0..unused {
                let mut t = text.clone();
                t[last] = ALPHABET[DECODE[t[last] as usize] as usize ^ (1 << bit)];
                assert_eq!(decode(&t), None, "len {len}, unused bit {bit}");
                assert_eq!(scalar_decode(&t), None, "scalar, len {len}, unused bit {bit}");
            }
            // Missing padding, extra padding.
            let bare: Vec<u8> = text.iter().copied().filter(|&c| c != b'=').collect();
            assert_eq!(decode(&bare), None, "unpadded, len {len}");
            assert_eq!(decode(&[&text[..], b"===="].concat()), None, "extra quad of padding, len {len}");
        }
        for bad in [&b"===="[..], b"A===", b"AA=A", b"A=AA", b"=AAA", b"AAA", b"AAAAA", b"AA==AAAA", b"AAA=AAAA"] {
            assert_eq!(decode(bad), None, "{}", String::from_utf8_lossy(bad));
            assert_eq!(scalar_decode(bad), None, "scalar {}", String::from_utf8_lossy(bad));
        }
        assert_eq!(decode(b""), Some(Vec::new()));
        assert_eq!(decode(b"AA=="), Some(vec![0]));
        assert_eq!(decode(b"AAA="), Some(vec![0, 0]));
    }

    #[test]
    fn invalid_characters_anywhere_fail() {
        let text = reference_encode(&data(300, 13));
        for at in 0..text.len() - 2 {
            for bad in [b' ', b'\n', b'\r', b'\t', b'=', b'-', b'_', b'.', b'\\', b'"', b'@', b'[', b'`', b'{', 0, 0x7F, 0x80, 0xC3, 0xFF] {
                let mut t = text.clone();
                t[at] = bad;
                assert_eq!(decode(&t), None, "{bad:#04x} at {at}");
            }
        }
        // Whitespace inserted (a line-wrapped encoding) or appended.
        for at in [0, 10, 76, 200, text.len()] {
            for ws in [&b"\n"[..], b"\r\n", b" ", b"    "] {
                let t = [&text[..at], ws, &text[at..]].concat();
                assert_eq!(decode(&t), None, "{ws:?} at {at}");
            }
        }
    }

    #[test]
    fn simd_and_scalar_agree_on_noise() {
        // Base64 text with now and then one stray character, so that valid
        // and invalid blocks at every position come up.
        let extra = b"=- \n_.";
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 300) as usize & !3;
            let mut t: Vec<u8> = (0..len).map(|_| ALPHABET[(next() % 64) as usize]).collect();
            if len > 0 && next() % 8 == 0 {
                let at = (next() as usize) % len;
                t[at] = extra[(next() % 6) as usize];
            }
            assert_eq!(decode(&t), scalar_decode(&t), "{}", String::from_utf8_lossy(&t));
            if let Some(bytes) = decode(&t) {
                assert_eq!(encode(&bytes), t);
            }
        }
    }
}
