//! SHA-1 (FIPS 180-4), for exactly one job: the WebSocket handshake hashes a
//! 60-byte string once per connection (RFC 6455 §4.2.2).
//!
//! SHA-1 is broken as a collision-resistant hash and is used here only because the
//! protocol demands it; nothing in the relay trusts it for integrity. That also
//! settles the design: correctness and a short, auditable body beat speed, so there
//! is no SIMD and no unrolling, just the textbook 80-round schedule.

const H0: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];

/// Streaming SHA-1. `update` as many times as needed, then `finalize`.
#[derive(Clone)]
pub struct Sha1 {
    h: [u32; 5],
    /// Bytes of an incomplete trailing block.
    buf: [u8; 64],
    buf_len: usize,
    /// Total message length in bytes.
    total: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub const fn new() -> Self {
        Sha1 { h: H0, buf: [0; 64], buf_len: 0, total: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len < 64 {
                return;
            }
            let block = self.buf;
            compress(&mut self.h, &block);
            self.buf_len = 0;
        }
        let mut blocks = data.chunks_exact(64);
        for block in &mut blocks {
            compress(&mut self.h, block.try_into().unwrap());
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buf_len = rest.len();
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total.wrapping_mul(8);
        // 0x80, zeros up to 56 mod 64, then the 64-bit big-endian bit length.
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let zeros = (119 - self.buf_len) % 64; // pad bytes after 0x80
        let n = 1 + zeros;
        pad[n..n + 8].copy_from_slice(&bit_len.to_be_bytes());
        // `update` would add to `total`, but it is already captured in `bit_len`.
        self.update(&pad[..n + 8]);
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; 20];
        for (o, h) in out.chunks_exact_mut(4).zip(self.h) {
            o.copy_from_slice(&h.to_be_bytes());
        }
        out
    }
}

/// One-shot digest.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut s = Sha1::new();
    s.update(data);
    s.finalize()
}

fn compress(h: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for (wi, c) in w.iter_mut().zip(block.chunks_exact(4)) {
        *wi = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *h;
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
            _ => (b ^ c ^ d, 0xCA62_C1D6u32),
        };
        let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: [u8; 20]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn fips_vectors() {
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        // 448-bit message: padding spills into a second block.
        assert_eq!(
            hex(sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // 896-bit message.
        assert_eq!(
            hex(sha1(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "a49b2446a02c645bf419f995b67091253a04a259"
        );
    }

    #[test]
    fn million_a() {
        let mut s = Sha1::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            s.update(&chunk);
        }
        assert_eq!(hex(s.finalize()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    }

    #[test]
    fn padding_boundaries() {
        // Lengths around the 55/56/63/64 padding edges; digests from Python hashlib.
        let cases = [
            (55, "c1c8bbdc22796e28c0e15163d20899b65621d65a"),
            (56, "c2db330f6083854c99d4b5bfb6e8f29f201be699"),
            (63, "03f09f5b158a7a8cdad920bddc29b81c18a551f5"),
            (64, "0098ba824b5c16427bd7a1122a5a442a25ec644d"),
            (65, "11655326c708d70319be2610e8a57d9a5b959d3b"),
        ];
        for (n, want) in cases {
            assert_eq!(hex(sha1(&vec![b'a'; n])), want, "length {n}");
        }
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let want = sha1(&data);
        for step in [1, 2, 3, 7, 31, 63, 64, 65, 100, 999] {
            let mut s = Sha1::new();
            for c in data.chunks(step) {
                s.update(c);
            }
            assert_eq!(s.finalize(), want, "step {step}");
        }
    }
}
