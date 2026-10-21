//! A small, fast, seedable generator (splitmix64 seeding a xorshift*): every
//! campaign is reproducible from its seed, on any machine.

#[derive(Clone)]
pub struct Rng(u64);

pub fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(mix(seed) | 1)
    }

    /// An independent stream for item `n` of a campaign seeded `seed`.
    pub fn derive(seed: u64, n: u64) -> Rng {
        Rng::new(mix(seed ^ mix(n.wrapping_add(0x51A5_5EED))))
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `0..n` (n > 0).
    #[inline]
    pub fn below(&mut self, n: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(n)) >> 64) as u64
    }

    #[inline]
    pub fn usize(&mut self, n: usize) -> usize {
        self.below(n as u64) as usize
    }

    /// True with probability `num/den`.
    #[inline]
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for c in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
    }

    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }

    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.usize(v.len())]
    }

    /// Small numbers far more often than large ones: lengths, counts, depths.
    pub fn skewed(&mut self, max: u64) -> u64 {
        let bits = self.below(64 - max.leading_zeros() as u64 + 1);
        if bits == 0 {
            return 0;
        }
        self.below(1u64 << bits.min(63)).min(max)
    }
}
