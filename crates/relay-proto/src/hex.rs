//! Lowercase hex, the only case Nostr allows for ids, keys and signatures.
//!
//! Decoding is strict: an uppercase digit is invalid, because the event would no
//! longer re-serialise to the bytes its id commits to.

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Byte → its two hex digits, packed as they sit in memory.
static ENCODE: [[u8; 2]; 256] = {
    let mut t = [[0u8; 2]; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = [DIGITS[i >> 4], DIGITS[i & 15]];
        i += 1;
    }
    t
};

/// Hex digit → nibble, 0xFF for anything that is not `0-9a-f`.
static DECODE: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 6 {
        t[b'a' as usize + i] = 10 + i as u8;
        i += 1;
    }
    t
};

/// Appends the lowercase hex of `src` to `out`.
///
/// Every event sent to a client hex-encodes its id, pubkey, signature and any
/// 32-byte tag values (~350 characters per event), so this is on the hottest
/// output path. SIMD table lookups do 32 bytes per step on AVX2 (production's
/// Skylake), 16 on SSSE3 and NEON; the tail uses a byte-pair table.
#[inline]
pub fn encode_into(src: &[u8], out: &mut Vec<u8>) {
    let n = src.len();
    out.reserve(n * 2);
    let start = out.len();
    // SAFETY: `reserve` made room for 2n bytes past `start`; every one of them
    // is written below before the length is set.
    unsafe {
        let dst = out.as_mut_ptr().add(start);
        let done = simd_encode(src, dst);
        for (i, &b) in src[done..].iter().enumerate() {
            let pair = ENCODE[b as usize];
            *dst.add((done + i) * 2) = pair[0];
            *dst.add((done + i) * 2 + 1) = pair[1];
        }
        out.set_len(start + n * 2);
    }
}

/// Encodes a prefix of `src` into `dst` with SIMD; returns how many input bytes
/// it handled (the rest is left to the scalar loop).
#[inline]
unsafe fn simd_encode(src: &[u8], dst: *mut u8) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        if src.len() >= 32 && std::arch::is_x86_feature_detected!("avx2") {
            return encode_avx2(src, dst);
        }
        if src.len() >= 16 && std::arch::is_x86_feature_detected!("ssse3") {
            return encode_ssse3(src, dst);
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

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn encode_avx2(src: &[u8], dst: *mut u8) -> usize {
    use std::arch::x86_64::*;
    let lut = _mm256_setr_epi8(
        b'0' as i8, b'1' as i8, b'2' as i8, b'3' as i8, b'4' as i8, b'5' as i8, b'6' as i8, b'7' as i8,
        b'8' as i8, b'9' as i8, b'a' as i8, b'b' as i8, b'c' as i8, b'd' as i8, b'e' as i8, b'f' as i8,
        b'0' as i8, b'1' as i8, b'2' as i8, b'3' as i8, b'4' as i8, b'5' as i8, b'6' as i8, b'7' as i8,
        b'8' as i8, b'9' as i8, b'a' as i8, b'b' as i8, b'c' as i8, b'd' as i8, b'e' as i8, b'f' as i8,
    );
    let mask = _mm256_set1_epi8(0x0F);
    let mut i = 0;
    while i + 32 <= src.len() {
        let v = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
        let hi = _mm256_shuffle_epi8(lut, _mm256_and_si256(_mm256_srli_epi16(v, 4), mask));
        let lo = _mm256_shuffle_epi8(lut, _mm256_and_si256(v, mask));
        // unpack works per 128-bit lane: a = bytes 0-7 | 16-23, b = 8-15 | 24-31.
        let a = _mm256_unpacklo_epi8(hi, lo);
        let b = _mm256_unpackhi_epi8(hi, lo);
        _mm256_storeu_si256(dst.add(i * 2) as *mut __m256i, _mm256_permute2x128_si256(a, b, 0x20));
        _mm256_storeu_si256(dst.add(i * 2 + 32) as *mut __m256i, _mm256_permute2x128_si256(a, b, 0x31));
        i += 32;
    }
    i
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "ssse3")]
unsafe fn encode_ssse3(src: &[u8], dst: *mut u8) -> usize {
    use std::arch::x86_64::*;
    let lut = _mm_loadu_si128(DIGITS.as_ptr() as *const __m128i);
    let mask = _mm_set1_epi8(0x0F);
    let mut i = 0;
    while i + 16 <= src.len() {
        let v = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
        let hi = _mm_shuffle_epi8(lut, _mm_and_si128(_mm_srli_epi16(v, 4), mask));
        let lo = _mm_shuffle_epi8(lut, _mm_and_si128(v, mask));
        _mm_storeu_si128(dst.add(i * 2) as *mut __m128i, _mm_unpacklo_epi8(hi, lo));
        _mm_storeu_si128(dst.add(i * 2 + 16) as *mut __m128i, _mm_unpackhi_epi8(hi, lo));
        i += 16;
    }
    i
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn encode_neon(src: &[u8], dst: *mut u8) -> usize {
    use std::arch::aarch64::*;
    let lut = vld1q_u8(DIGITS.as_ptr());
    let mask = vdupq_n_u8(0x0F);
    let mut i = 0;
    while i + 16 <= src.len() {
        let v = vld1q_u8(src.as_ptr().add(i));
        let hi = vqtbl1q_u8(lut, vshrq_n_u8(v, 4));
        let lo = vqtbl1q_u8(lut, vandq_u8(v, mask));
        vst2q_u8(dst.add(i * 2), uint8x16x2_t(hi, lo));
        i += 16;
    }
    i
}

/// Lowercase hex of a 32-byte value.
#[inline]
pub fn encode_32(src: &[u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, &b) in src.iter().enumerate() {
        out[i * 2..i * 2 + 2].copy_from_slice(&ENCODE[b as usize]);
    }
    out
}

pub fn encode_string(src: &[u8]) -> String {
    let mut out = Vec::with_capacity(src.len() * 2);
    encode_into(src, &mut out);
    // Every byte pushed came from DIGITS.
    String::from_utf8(out).expect("hex is ascii")
}

/// Decodes exactly `out.len() * 2` lowercase hex digits.
#[inline]
pub fn decode_into(src: &[u8], out: &mut [u8]) -> bool {
    if src.len() != out.len() * 2 {
        return false;
    }
    let mut bad = 0u8;
    for (i, o) in out.iter_mut().enumerate() {
        let hi = DECODE[src[i * 2] as usize];
        let lo = DECODE[src[i * 2 + 1] as usize];
        // One branch for the whole value: invalid digits set the high bit.
        bad |= hi | lo;
        *o = (hi << 4) | (lo & 0x0F);
    }
    bad & 0x80 == 0
}

#[inline]
pub fn decode_32(src: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    decode_into(src, &mut out).then_some(out)
}

#[inline]
pub fn decode_64(src: &[u8]) -> Option<[u8; 64]> {
    let mut out = [0u8; 64];
    decode_into(src, &mut out).then_some(out)
}

/// True when `src` is exactly 64 lowercase hex digits: the shape stored as 32 raw bytes.
#[inline]
pub fn is_hex64(src: &[u8]) -> bool {
    src.len() == 64 && src.iter().all(|&b| DECODE[b as usize] != 0xFF)
}

/// Hex digit of either case → nibble, 0xFF for anything else.
static DECODE_ANY: [u8; 256] = {
    let mut t = DECODE;
    let mut i = 0;
    while i < 6 {
        t[b'A' as usize + i] = 10 + i as u8;
        i += 1;
    }
    t
};

/// Decodes any even-length lowercase-or-uppercase hex (NIP-77 messages are not
/// case-restricted by the spec, so accept both there).
///
/// A heavy NIP-77 reconciliation sends hundreds of kilobytes of it per round,
/// so the bulk is decoded with SIMD (64 digits a step on AVX2, 32 on NEON).
pub fn decode_any_case(src: &[u8]) -> Option<Vec<u8>> {
    if src.len() % 2 != 0 {
        return None;
    }
    let mut out = vec![0u8; src.len() / 2];
    // SAFETY: `out` holds exactly half of `src`'s length, as the SIMD decoders require.
    let (done, ok) = unsafe { simd_decode_any(src, &mut out) };
    if !ok || !decode_any_scalar(&src[done * 2..], &mut out[done..]) {
        return None;
    }
    Some(out)
}

/// `out.len() * 2` digits of `src`, either case.
#[inline]
fn decode_any_scalar(src: &[u8], out: &mut [u8]) -> bool {
    let mut bad = 0u8;
    for (o, pair) in out.iter_mut().zip(src.chunks_exact(2)) {
        let (hi, lo) = (DECODE_ANY[pair[0] as usize], DECODE_ANY[pair[1] as usize]);
        bad |= hi | lo;
        *o = (hi << 4) | (lo & 0x0F);
    }
    bad & 0x80 == 0
}

/// Decodes a prefix of `src` into `out` with SIMD: (output bytes written, all
/// digits valid). `out.len()` must be `src.len() / 2`.
#[inline]
unsafe fn simd_decode_any(src: &[u8], out: &mut [u8]) -> (usize, bool) {
    #[cfg(target_arch = "x86_64")]
    {
        if src.len() >= 64 && std::arch::is_x86_feature_detected!("avx2") {
            return decode_any_avx2(src, out);
        }
        (0, true)
    }
    #[cfg(target_arch = "aarch64")]
    {
        decode_any_neon(src, out)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (src, out);
        (0, true)
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn decode_any_avx2(src: &[u8], out: &mut [u8]) -> (usize, bool) {
    use std::arch::x86_64::*;
    let (zero, nine, a, five, ten, case) = (
        _mm256_set1_epi8(b'0' as i8),
        _mm256_set1_epi8(9),
        _mm256_set1_epi8(b'a' as i8),
        _mm256_set1_epi8(5),
        _mm256_set1_epi8(10),
        _mm256_set1_epi8(0x20),
    );
    // Each pair of nibbles (high first) becomes hi * 16 + lo in a 16-bit lane.
    let weights = _mm256_set1_epi16(0x0110);
    let mut ok = _mm256_set1_epi8(-1);
    let nibbles = |v: __m256i, ok: &mut __m256i| {
        let d = _mm256_sub_epi8(v, zero);
        let is_digit = _mm256_cmpeq_epi8(_mm256_min_epu8(d, nine), d);
        // Folding case maps digits below 'a', where they fail this test.
        let l = _mm256_sub_epi8(_mm256_or_si256(v, case), a);
        let is_letter = _mm256_cmpeq_epi8(_mm256_min_epu8(l, five), l);
        *ok = _mm256_and_si256(*ok, _mm256_or_si256(is_digit, is_letter));
        _mm256_blendv_epi8(_mm256_add_epi8(l, ten), d, is_digit)
    };
    let mut i = 0;
    while i + 64 <= src.len() {
        let x = nibbles(_mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i), &mut ok);
        let y = nibbles(_mm256_loadu_si256(src.as_ptr().add(i + 32) as *const __m256i), &mut ok);
        let bytes = _mm256_packus_epi16(_mm256_maddubs_epi16(x, weights), _mm256_maddubs_epi16(y, weights));
        // packus works per 128-bit lane: x's halves are quads 0 and 2, y's 1 and 3.
        let ordered = _mm256_permute4x64_epi64(bytes, 0b11_01_10_00);
        _mm256_storeu_si256(out.as_mut_ptr().add(i / 2) as *mut __m256i, ordered);
        i += 64;
    }
    (i / 2, _mm256_movemask_epi8(ok) == -1)
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn decode_any_neon(src: &[u8], out: &mut [u8]) -> (usize, bool) {
    use std::arch::aarch64::*;
    let (zero, nine, a, five, ten, case) = (vdupq_n_u8(b'0'), vdupq_n_u8(9), vdupq_n_u8(b'a'), vdupq_n_u8(5), vdupq_n_u8(10), vdupq_n_u8(0x20));
    let mut ok = vdupq_n_u8(0xFF);
    let nibbles = |v: uint8x16_t, ok: &mut uint8x16_t| {
        let d = vsubq_u8(v, zero);
        let is_digit = vcleq_u8(d, nine);
        let l = vsubq_u8(vorrq_u8(v, case), a);
        let is_letter = vcleq_u8(l, five);
        *ok = vandq_u8(*ok, vorrq_u8(is_digit, is_letter));
        vbslq_u8(is_digit, d, vaddq_u8(l, ten))
    };
    let mut i = 0;
    while i + 32 <= src.len() {
        // De-interleaved on load: even digits (high nibbles) and odd ones.
        let pair = vld2q_u8(src.as_ptr().add(i));
        let hi = nibbles(pair.0, &mut ok);
        let lo = nibbles(pair.1, &mut ok);
        vst1q_u8(out.as_mut_ptr().add(i / 2), vorrq_u8(vshlq_n_u8(hi, 4), lo));
        i += 32;
    }
    (i / 2, vminvq_u8(ok) == 0xFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        let mut s = Vec::new();
        encode_into(&bytes, &mut s);
        let mut back = vec![0u8; 256];
        assert!(decode_into(&s, &mut back));
        assert_eq!(back, bytes);
    }

    #[test]
    fn simd_matches_scalar_at_every_length() {
        let data: Vec<u8> = (0..300u32).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
        for len in 0..data.len() {
            for off in [0usize, 1, 3] {
                if off + len > data.len() {
                    continue;
                }
                let src = &data[off..off + len];
                let mut fast = vec![b'x'; 5];
                encode_into(src, &mut fast);
                let mut slow = vec![b'x'; 5];
                for &b in src {
                    slow.extend_from_slice(&ENCODE[b as usize]);
                }
                assert_eq!(fast, slow, "len {len} off {off}");
            }
        }
    }

    #[test]
    fn any_case_decoding_matches_the_table_at_every_length() {
        let digits = b"0123456789abcdefABCDEF";
        let src: Vec<u8> = (0..600u32).map(|i| digits[(i.wrapping_mul(2654435761) >> 9) as usize % digits.len()]).collect();
        let reference = |s: &[u8]| -> Option<Vec<u8>> {
            let nib = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
            (s.len() % 2 == 0).then(|| s.chunks_exact(2).map(|p| Some((nib(p[0])? << 4) | nib(p[1])?)).collect::<Option<Vec<u8>>>())?
        };
        for len in 0..=src.len() {
            for off in [0usize, 1, 7] {
                if off + len > src.len() {
                    continue;
                }
                let s = &src[off..off + len];
                assert_eq!(decode_any_case(s), reference(s), "len {len} off {off}");
            }
        }
        // One bad character anywhere, in the SIMD part or the tail, fails the whole.
        for at in 0..300 {
            for bad in [b'g', b'G', b'/', b':', b'@', b'`', b' ', 0x80, 0xFF] {
                let mut s = src[..300].to_vec();
                s[at] = bad;
                assert_eq!(decode_any_case(&s), None, "bad {bad:#x} at {at}");
            }
        }
    }

    #[test]
    fn strict_lowercase() {
        let lower = [b'a'; 64];
        let mut upper = lower;
        upper[10] = b'A';
        assert!(decode_32(&lower).is_some());
        assert!(decode_32(&upper).is_none());
        assert!(!is_hex64(&upper));
        assert!(decode_32(&lower[..62]).is_none());
        let mut junk = lower;
        junk[0] = b'g';
        assert!(decode_32(&junk).is_none());
    }
}
