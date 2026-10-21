//! base64url without padding (RFC 4648 §5): the encoding JWS and ACME use for every
//! binary value (keys, signatures, digests, the CSR).
//!
//! relay-net's base64 is the padded standard alphabet the WebSocket handshake needs;
//! this one is the other alphabet and never pads, so the two stay separate and small.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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

/// The unpadded encoding of `src`.
pub fn encode(src: &[u8]) -> String {
    let mut out = String::with_capacity(src.len().div_ceil(3) * 4);
    let mut chunks = src.chunks_exact(3);
    for c in &mut chunks {
        let v = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[(v >> shift) as usize & 63] as char);
        }
    }
    match *chunks.remainder() {
        [a] => {
            let v = u32::from(a) << 16;
            out.push(ALPHABET[(v >> 18) as usize & 63] as char);
            out.push(ALPHABET[(v >> 12) as usize & 63] as char);
        }
        [a, b] => {
            let v = (u32::from(a) << 16) | (u32::from(b) << 8);
            out.push(ALPHABET[(v >> 18) as usize & 63] as char);
            out.push(ALPHABET[(v >> 12) as usize & 63] as char);
            out.push(ALPHABET[(v >> 6) as usize & 63] as char);
        }
        _ => {}
    }
    out
}

/// Decodes unpadded base64url. Padding, whitespace, the standard alphabet's `+` and
/// `/`, and a length that leaves one stray character are all errors. The unused low
/// bits of the last character must be zero, so each value has exactly one encoding.
pub fn decode(src: &str) -> Option<Vec<u8>> {
    let b = src.as_bytes();
    if b.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3 + 2);
    let mut acc = 0u32;
    let mut bits = 0;
    for &c in b {
        let v = DECODE[c as usize];
        if v == INVALID {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (acc == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 with the padding removed.
    const VECTORS: [(&str, &str); 7] =
        [("", ""), ("f", "Zg"), ("fo", "Zm8"), ("foo", "Zm9v"), ("foob", "Zm9vYg"), ("fooba", "Zm9vYmE"), ("foobar", "Zm9vYmFy")];

    #[test]
    fn rfc4648_vectors() {
        for (plain, enc) in VECTORS {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn url_alphabet_not_standard() {
        // 0xfb 0xff 0xfe is "+//+" in the standard alphabet.
        assert_eq!(encode(&[0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(decode("-__-").unwrap(), [0xfb, 0xff, 0xfe]);
        assert!(decode("+//+").is_none());
    }

    #[test]
    fn every_byte_value_and_length_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        for n in 0..=all.len() {
            let enc = encode(&all[..n]);
            assert!(!enc.contains('='));
            assert_eq!(decode(&enc).unwrap(), &all[..n], "length {n}");
        }
    }

    #[test]
    fn rejects_what_is_not_canonical() {
        assert!(decode("Zg==").is_none(), "padding");
        assert!(decode("Zm9v\n").is_none(), "whitespace");
        assert!(decode("Z").is_none(), "one stray character");
        assert!(decode("Zh").is_none(), "non-zero trailing bits (Zg is canonical)");
        assert!(decode("Zm9vY").is_none());
        assert!(decode("a b").is_none());
        assert!(decode("\u{e9}\u{e9}\u{e9}\u{e9}").is_none());
    }
}
