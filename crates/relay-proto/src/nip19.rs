//! NIP-19: the `npub` form of a public key (bech32, BIP-173), read and written.

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const HRP: &[u8] = b"npub";
/// "npub1", 52 characters of key (256 bits in 5-bit groups) and a 6-character checksum.
const NPUB_LEN: usize = 63;

/// The key an `npub1...` names, or `None` if it is not a valid npub.
/// Upper case is accepted whole, as bech32 allows; mixed case is not.
pub fn decode_npub(s: &str) -> Option<[u8; 32]> {
    let s = s.as_bytes();
    if s.len() != NPUB_LEN || (s.iter().any(u8::is_ascii_uppercase) && s.iter().any(u8::is_ascii_lowercase)) {
        return None;
    }
    let lower: Vec<u8> = s.iter().map(u8::to_ascii_lowercase).collect();
    let (hrp, data) = lower.split_at(HRP.len());
    if hrp != HRP || data[0] != b'1' {
        return None;
    }
    let mut values = Vec::with_capacity(data.len() - 1);
    for c in &data[1..] {
        values.push(CHARSET.iter().position(|x| x == c)? as u8);
    }
    let expanded = HRP.iter().map(|c| c >> 5).chain([0]).chain(HRP.iter().map(|c| c & 31));
    if polymod(expanded.chain(values.iter().copied())) != 1 {
        return None;
    }
    // 5-bit groups to bytes; the 4 bits left over must be zero padding.
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for &v in &values[..values.len() - 6] {
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[n] = (acc >> bits) as u8;
            n += 1;
        }
    }
    (n == 32 && bits < 5 && acc & ((1 << bits) - 1) == 0).then_some(out)
}

/// The `npub1...` form of a key.
pub fn encode_npub(key: &[u8; 32]) -> String {
    // Bytes to 5-bit groups, the last padded with zeros.
    let mut values = Vec::with_capacity(52 + 6);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in key {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            values.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        values.push(((acc << (5 - bits)) & 31) as u8);
    }
    let expanded = HRP.iter().map(|c| c >> 5).chain([0]).chain(HRP.iter().map(|c| c & 31));
    let check = polymod(expanded.chain(values.iter().copied()).chain([0; 6])) ^ 1;
    values.extend((0..6).map(|i| ((check >> (5 * (5 - i))) & 31) as u8));
    let mut out = String::with_capacity(NPUB_LEN);
    out.push_str("npub1");
    out.extend(values.iter().map(|&v| char::from(CHARSET[usize::from(v)])));
    out
}

fn polymod(values: impl Iterator<Item = u8>) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(v);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    // NIP-19's own example.
    const NPUB: &str = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
    const HEX: &str = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

    #[test]
    fn decodes_nip19s_example_in_either_case() {
        assert_eq!(decode_npub(NPUB).map(|k| hex::encode_string(&k)).as_deref(), Some(HEX));
        assert_eq!(decode_npub(&NPUB.to_ascii_uppercase()).map(|k| hex::encode_string(&k)).as_deref(), Some(HEX));
    }

    #[test]
    fn encodes_nip19s_example_and_round_trips() {
        let key = hex::decode_32(HEX.as_bytes()).unwrap();
        assert_eq!(encode_npub(&key), NPUB);
        for seed in 0..=255u8 {
            let k = [seed; 32];
            let k2: [u8; 32] = std::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u8));
            assert_eq!(decode_npub(&encode_npub(&k)), Some(k));
            assert_eq!(decode_npub(&encode_npub(&k2)), Some(k2));
        }
    }

    #[test]
    fn refuses_anything_else() {
        let mut typo = NPUB.as_bytes().to_vec();
        typo[20] = if typo[20] == b'q' { b'p' } else { b'q' };
        let mixed = format!("{}{}", &NPUB[..10], NPUB[10..].to_ascii_uppercase());
        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        for bad in [std::str::from_utf8(&typo).unwrap(), &mixed, nsec, &NPUB[..62], HEX, "", "npub1"] {
            assert_eq!(decode_npub(bad), None, "{bad}");
        }
    }
}
