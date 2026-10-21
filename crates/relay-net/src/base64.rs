//! Standard-alphabet base64 with padding (RFC 4648 §4).
//!
//! The handshake needs it twice: to encode the 20-byte SHA-1 digest into
//! `Sec-WebSocket-Accept` and to check that `Sec-WebSocket-Key` is 16 bytes of
//! base64. Both are tiny and once per connection, so the code is the plain
//! three-bytes-to-four loop with a 256-entry decode table.
//!
//! The decoder is strict about structure (length a multiple of four, `=` only as
//! the final one or two characters, nothing outside the alphabet) and lenient about
//! the unused low bits of the last character, which RFC 4648 §3.5 lets a decoder
//! ignore. A handshake key that decodes to the right length is good enough.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const INVALID: u8 = 0xFF;

const DECODE: [u8; 256] = {
    let mut t = [INVALID; 256];
    let mut i = 0;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input length is not a multiple of four.
    Length,
    /// A byte outside the alphabet, or `=` somewhere but the end.
    InvalidByte,
    /// The destination slice is shorter than the decoded data.
    OutputTooSmall,
}

/// Length of the padded encoding of `n` input bytes.
#[inline]
pub const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Encodes `src` into `dst`, which must hold at least `encoded_len(src.len())`
/// bytes. Returns the number of bytes written.
pub fn encode_slice(src: &[u8], dst: &mut [u8]) -> usize {
    let mut o = 0;
    let mut chunks = src.chunks_exact(3);
    for c in &mut chunks {
        let v = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        dst[o] = ALPHABET[(v >> 18) as usize & 63];
        dst[o + 1] = ALPHABET[(v >> 12) as usize & 63];
        dst[o + 2] = ALPHABET[(v >> 6) as usize & 63];
        dst[o + 3] = ALPHABET[v as usize & 63];
        o += 4;
    }
    match *chunks.remainder() {
        [a] => {
            let v = u32::from(a) << 16;
            dst[o] = ALPHABET[(v >> 18) as usize & 63];
            dst[o + 1] = ALPHABET[(v >> 12) as usize & 63];
            dst[o + 2] = b'=';
            dst[o + 3] = b'=';
            o += 4;
        }
        [a, b] => {
            let v = (u32::from(a) << 16) | (u32::from(b) << 8);
            dst[o] = ALPHABET[(v >> 18) as usize & 63];
            dst[o + 1] = ALPHABET[(v >> 12) as usize & 63];
            dst[o + 2] = ALPHABET[(v >> 6) as usize & 63];
            dst[o + 3] = b'=';
            o += 4;
        }
        _ => {}
    }
    o
}

/// Appends the encoding of `src` to `out`.
pub fn encode(src: &[u8], out: &mut Vec<u8>) {
    let start = out.len();
    out.resize(start + encoded_len(src.len()), 0);
    encode_slice(src, &mut out[start..]);
}

/// The encoding of `src` as a `String`.
pub fn encode_string(src: &[u8]) -> String {
    let mut v = Vec::new();
    encode(src, &mut v);
    // The alphabet is ASCII.
    String::from_utf8(v).expect("base64 output is ASCII")
}

#[inline]
fn sextet(b: u8) -> Result<u8, DecodeError> {
    match DECODE[b as usize] {
        INVALID => Err(DecodeError::InvalidByte),
        v => Ok(v),
    }
}

/// Decodes `src` into `dst`, returning the number of bytes written. `dst` must be
/// able to hold the decoded data (at most `src.len() / 4 * 3` bytes).
pub fn decode_slice(src: &[u8], dst: &mut [u8]) -> Result<usize, DecodeError> {
    if src.len() % 4 != 0 {
        return Err(DecodeError::Length);
    }
    let pad = if src.ends_with(b"==") {
        2
    } else if src.ends_with(b"=") {
        1
    } else {
        0
    };
    let want = src.len() / 4 * 3 - pad;
    if dst.len() < want {
        return Err(DecodeError::OutputTooSmall);
    }
    // A padded final quad is handled separately; every other quad is four sextets.
    let full = if pad > 0 { src.len() - 4 } else { src.len() };
    let mut o = 0;
    for q in src[..full].chunks_exact(4) {
        let (a, b, c, d) = (sextet(q[0])?, sextet(q[1])?, sextet(q[2])?, sextet(q[3])?);
        dst[o] = (a << 2) | (b >> 4);
        dst[o + 1] = (b << 4) | (c >> 2);
        dst[o + 2] = (c << 6) | d;
        o += 3;
    }
    if pad > 0 {
        let q = &src[full..];
        let (a, b) = (sextet(q[0])?, sextet(q[1])?);
        dst[o] = (a << 2) | (b >> 4);
        o += 1;
        if pad == 1 {
            let c = sextet(q[2])?;
            dst[o] = (b << 4) | (c >> 2);
            o += 1;
        }
    }
    debug_assert_eq!(o, want);
    Ok(o)
}

/// Appends the decoded `src` to `out`. On error `out` is left unchanged.
pub fn decode(src: &[u8], out: &mut Vec<u8>) -> Result<(), DecodeError> {
    let start = out.len();
    out.resize(start + src.len() / 4 * 3, 0);
    match decode_slice(src, &mut out[start..]) {
        Ok(n) => {
            out.truncate(start + n);
            Ok(())
        }
        Err(e) => {
            out.truncate(start);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC4648: [(&str, &str); 7] = [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ];

    #[test]
    fn rfc4648_vectors() {
        for (plain, enc) in RFC4648 {
            assert_eq!(encode_string(plain.as_bytes()), enc);
            let mut out = Vec::new();
            decode(enc.as_bytes(), &mut out).unwrap();
            assert_eq!(out, plain.as_bytes());
        }
    }

    #[test]
    fn round_trip_all_small_lengths() {
        let mut x = 0x1234_5678u32;
        for n in 0..200 {
            let data: Vec<u8> = (0..n)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let enc = encode_string(&data);
            assert_eq!(enc.len(), encoded_len(n));
            let mut back = Vec::new();
            decode(enc.as_bytes(), &mut back).unwrap();
            assert_eq!(back, data, "length {n}");
        }
    }

    #[test]
    fn all_alphabet_characters() {
        // 0..=255 covers every sextet value in every position.
        let data: Vec<u8> = (0..=255u8).collect();
        let enc = encode_string(&data);
        let mut back = Vec::new();
        decode(enc.as_bytes(), &mut back).unwrap();
        assert_eq!(back, data);
        for c in ALPHABET {
            assert!(enc.as_bytes().contains(c), "sextet {} never produced", *c as char);
        }
    }

    #[test]
    fn rejects_malformed() {
        let mut out = Vec::new();
        for (bad, want) in [
            ("Zg=", DecodeError::Length),
            ("Zg", DecodeError::Length),
            ("Z===", DecodeError::InvalidByte),
            ("====", DecodeError::InvalidByte),
            ("Zg==Zg==", DecodeError::InvalidByte),
            ("Zm=v", DecodeError::InvalidByte),
            ("Zm9 ", DecodeError::InvalidByte),
            ("Zm9-", DecodeError::InvalidByte),
            ("Zm9_", DecodeError::InvalidByte),
            ("Zm9\n", DecodeError::InvalidByte),
        ] {
            assert_eq!(decode(bad.as_bytes(), &mut out), Err(want), "{bad:?}");
            assert!(out.is_empty(), "output must be untouched on error");
        }
    }

    #[test]
    fn decode_slice_checks_capacity() {
        let mut small = [0u8; 2];
        assert_eq!(decode_slice(b"Zm9v", &mut small), Err(DecodeError::OutputTooSmall));
        let mut exact = [0u8; 3];
        assert_eq!(decode_slice(b"Zm9v", &mut exact), Ok(3));
        assert_eq!(&exact, b"foo");
    }

    #[test]
    fn append_preserves_prefix() {
        let mut out = b"xy".to_vec();
        encode(b"foo", &mut out);
        assert_eq!(out, b"xyZm9v");
        decode(b"Zg==", &mut out).unwrap();
        assert_eq!(out, b"xyZm9vf");
    }
}
