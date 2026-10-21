//! Byte-level mutation for the stable fuzz runner: the classic havoc set (bit
//! flips, interesting bytes, range deletes, duplicates, splices, dictionary
//! tokens) plus two the relay's parsers particularly deserve: repeating a chunk
//! many times (quadratic and nesting paths) and rewriting decimal numbers into
//! their edge cases (overflow, leading zeros, exponents).

use crate::rng::Rng;

/// Bytes that change the meaning of JSON, HTTP and frame headers.
const INTERESTING: &[u8] = &[
    0, 1, 0x7F, 0x80, 0xFF, 0xFE, 0xC0, 0xED, 0xF4, b'"', b'\\', b',', b':', b'[', b']', b'{', b'}', b'0', b'9', b'-', b'+', b'e',
    b'.', b' ', b'\n', b'\r', b'\t', b'u', b'/', b'#', b'=', b';',
];

/// Number spellings worth trying wherever a number appears.
const NUMBERS: &[&[u8]] = &[
    b"0",
    b"-0",
    b"00",
    b"01",
    b"1e3",
    b"1E+3",
    b"1.0",
    b"-1",
    b"4294967295",
    b"4294967296",
    b"9007199254740993",
    b"18446744073709551615",
    b"18446744073709551616",
    b"99999999999999999999999999999",
    b"1e309",
    b"-9223372036854775808",
    b"0x10",
    b"NaN",
    b"Infinity",
];

pub struct Mutator {
    pub max_len: usize,
    pub dict: Vec<Vec<u8>>,
}

impl Mutator {
    pub fn new(max_len: usize, dict: &[&[u8]]) -> Mutator {
        let mut d: Vec<Vec<u8>> = dict.iter().map(|t| t.to_vec()).collect();
        d.extend(NUMBERS.iter().map(|n| n.to_vec()));
        Mutator { max_len, dict: d }
    }

    /// One to eight stacked mutations of `base`, sometimes spliced with `other`.
    pub fn mutate(&self, rng: &mut Rng, base: &[u8], other: &[u8]) -> Vec<u8> {
        let mut v = base.to_vec();
        let rounds = 1 + rng.skewed(7);
        for _ in 0..rounds {
            self.once(rng, &mut v, other);
            if v.len() > self.max_len {
                v.truncate(self.max_len);
            }
        }
        v
    }

    fn once(&self, rng: &mut Rng, v: &mut Vec<u8>, other: &[u8]) {
        let len = v.len();
        let at = |rng: &mut Rng, n: usize| if n == 0 { 0 } else { rng.usize(n + 1) };
        match rng.below(15) {
            0 if len > 0 => {
                let i = rng.usize(len);
                v[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.usize(len);
                v[i] = *rng.pick(INTERESTING);
            }
            2 if len > 0 => {
                let i = rng.usize(len);
                let n = 1 + rng.skewed((len - i - 1) as u64) as usize;
                v.drain(i..(i + n).min(len));
            }
            3 if len > 0 => {
                // Duplicate a range in place.
                let i = rng.usize(len);
                let n = 1 + rng.skewed((len - i - 1) as u64) as usize;
                let chunk = v[i..(i + n).min(len)].to_vec();
                let to = at(rng, len);
                v.splice(to..to, chunk);
            }
            4 => {
                let n = 1 + rng.skewed(32) as usize;
                let mut b = vec![0u8; n];
                rng.fill(&mut b);
                let to = at(rng, len);
                v.splice(to..to, b);
            }
            5 if !self.dict.is_empty() => {
                let t = rng.pick(&self.dict).clone();
                let to = at(rng, len);
                v.splice(to..to, t);
            }
            6 if !self.dict.is_empty() && len > 0 => {
                let t = rng.pick(&self.dict).clone();
                let i = rng.usize(len);
                let end = (i + t.len()).min(len);
                v.splice(i..end, t);
            }
            7 if !other.is_empty() => {
                // Crossover: our head, their tail.
                let cut = at(rng, len);
                let from = rng.usize(other.len());
                v.truncate(cut);
                v.extend_from_slice(&other[from..]);
            }
            8 if len > 0 => {
                v.truncate(rng.usize(len));
            }
            9 if len > 0 => {
                // Repeat a short chunk many times: nesting, long lists, quadratic paths.
                let i = rng.usize(len);
                let n = 1 + rng.skewed(16) as usize;
                let chunk = v[i..(i + n).min(len)].to_vec();
                let times = 2 + rng.skewed(4000) as usize;
                let room = self.max_len.saturating_sub(len) / chunk.len().max(1);
                let mut rep = Vec::with_capacity(chunk.len() * times.min(room));
                for _ in 0..times.min(room) {
                    rep.extend_from_slice(&chunk);
                }
                v.splice(i..i, rep);
            }
            10 => self.renumber(rng, v),
            11 if len > 1 => {
                let a = rng.usize(len);
                let b = rng.usize(len);
                v.swap(a, b);
            }
            12 if len > 0 => {
                // A run of one byte: long strings, long whitespace.
                let c = if rng.chance(1, 2) { v[rng.usize(len)] } else { *rng.pick(INTERESTING) };
                let n = 1 + rng.skewed(2000) as usize;
                let to = at(rng, len);
                v.splice(to..to, std::iter::repeat_n(c, n.min(self.max_len.saturating_sub(len))));
            }
            13 if len > 0 => {
                // Arithmetic on one byte, as on a length or opcode field.
                let i = rng.usize(len);
                let d = rng.range(1, 35) as u8;
                v[i] = if rng.chance(1, 2) { v[i].wrapping_add(d) } else { v[i].wrapping_sub(d) };
            }
            _ => {
                if len > 0 {
                    let i = rng.usize(len);
                    v[i] = rng.next_u64() as u8;
                } else {
                    v.push(rng.next_u64() as u8);
                }
            }
        }
    }

    /// Replaces one decimal number in `v` with an edge-case spelling.
    fn renumber(&self, rng: &mut Rng, v: &mut Vec<u8>) {
        let starts: Vec<usize> = (0..v.len()).filter(|&i| v[i].is_ascii_digit() && (i == 0 || !v[i - 1].is_ascii_digit())).collect();
        if starts.is_empty() {
            return;
        }
        let s = *rng.pick(&starts);
        let mut e = s;
        while e < v.len() && v[e].is_ascii_digit() {
            e += 1;
        }
        let n = rng.pick(NUMBERS).to_vec();
        v.splice(s..e, n);
    }
}
