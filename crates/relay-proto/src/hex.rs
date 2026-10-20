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
#[inline]
pub fn encode_into(src: &[u8], out: &mut Vec<u8>) {
    out.reserve(src.len() * 2);
    for &b in src {
        out.extend_from_slice(&ENCODE[b as usize]);
    }
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

/// Decodes any even-length lowercase-or-uppercase hex (NIP-77 messages are not
/// case-restricted by the spec, so accept both there).
pub fn decode_any_case(src: &[u8]) -> Option<Vec<u8>> {
    if src.len() % 2 != 0 {
        return None;
    }
    let nib = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    src.chunks_exact(2).map(|p| Some((nib(p[0])? << 4) | nib(p[1])?)).collect()
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
