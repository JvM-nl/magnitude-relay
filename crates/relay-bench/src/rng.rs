//! Deterministic randomness: SplitMix64 and a Zipf-like sampler.
//!
//! The dataset must be byte-identical for a given seed on any machine and any
//! thread count, so nothing here touches the clock, the OS, `HashMap` order or
//! floating-point functions whose last bit varies between libm implementations.
//! Every event derives its own stream from `(seed, n)`, which is what lets the
//! generator sign chunks on all cores and still write the same file.

/// SplitMix64: one add and three xorshift-multiplies per word. Passes BigCrush,
/// and its state is one `u64`, so a fresh independent stream costs nothing.
#[derive(Clone)]
pub struct Rng(u64);

/// The SplitMix64 output function, also used as a standalone 64-bit mixer.
#[inline]
pub fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(mix(seed ^ GOLDEN))
    }

    /// An independent stream for item `n` of purpose `stream` under `seed`. The three
    /// inputs are mixed in sequence so neighbouring `n` share nothing.
    pub fn for_item(seed: u64, n: u64, stream: u64) -> Rng {
        Rng(mix(mix(seed ^ stream.wrapping_mul(GOLDEN)) ^ n.wrapping_mul(0xD6E8_FEB8_6659_FD93)))
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(GOLDEN);
        mix(self.0)
    }

    /// Uniform in `0..n` (`n > 0`). Multiply-shift: for `n` below 2^32 the bias is
    /// under 2^-32, far below anything a benchmark can see, and it needs no retry
    /// loop, so the number of words consumed is fixed (which keeps streams in step).
    #[inline]
    pub fn below(&mut self, n: u64) -> u64 {
        ((u128::from(self.next_u64()) * u128::from(n)) >> 64) as u64
    }

    /// True with probability `num / den`.
    #[inline]
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let w = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&w[..chunk.len()]);
        }
    }

    pub fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }

    /// Fisher-Yates.
    pub fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i as u64 + 1) as usize;
            v.swap(i, j);
        }
    }
}

/// Rank sampler with P(rank k) proportional to 1/(k+1)^0.75 over `0..n`.
///
/// Exponent 0.75 over 10,000 recipients and 3.5M wraps gives the heaviest mailbox
/// about 95k events, the second about 57k and the tenth about 17k, with the long
/// tail still holding ~100 each: "a few heavy mailboxes of 50k+" without making one
/// of them most of the dataset (exponent 1 would give the top mailbox 10%).
///
/// Weights are built from `sqrt` only (k^0.75 = sqrt(k) * sqrt(sqrt(k))), which
/// IEEE 754 requires to be correctly rounded, so the table is identical on every
/// platform; the cumulative sums are integers.
pub struct Zipf {
    cdf: Vec<u64>,
}

impl Zipf {
    pub fn new(n: usize) -> Zipf {
        assert!(n > 0, "empty Zipf population");
        let mut cdf = Vec::with_capacity(n);
        let mut acc = 0u64;
        for k in 1..=n {
            let r = (k as f64).sqrt();
            let w = (1u64 << 40) as f64 / (r * r.sqrt());
            acc += w as u64;
            cdf.push(acc);
        }
        Zipf { cdf }
    }

    #[inline]
    pub fn sample(&self, rng: &mut Rng) -> usize {
        let total = *self.cdf.last().unwrap();
        let x = rng.below(total);
        self.cdf.partition_point(|&c| c <= x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream_and_streams_differ() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(1);
        let mut c = Rng::new(2);
        let va: Vec<u64> = (0..16).map(|_| a.next_u64()).collect();
        let vb: Vec<u64> = (0..16).map(|_| b.next_u64()).collect();
        let vc: Vec<u64> = (0..16).map(|_| c.next_u64()).collect();
        assert_eq!(va, vb);
        assert_ne!(va, vc);
        let x = Rng::for_item(5, 10, 1).next_u64();
        assert_eq!(x, Rng::for_item(5, 10, 1).next_u64());
        assert_ne!(x, Rng::for_item(5, 11, 1).next_u64());
        assert_ne!(x, Rng::for_item(5, 10, 2).next_u64());
        assert_ne!(x, Rng::for_item(6, 10, 1).next_u64());
    }

    #[test]
    fn splitmix_known_vector() {
        // Reference values for SplitMix64 seeded with 0 (state starts at 0, add then mix).
        let mut s = 0u64;
        let mut next = || {
            s = s.wrapping_add(GOLDEN);
            mix(s)
        };
        assert_eq!(next(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(next(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(next(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn below_stays_in_range_and_is_roughly_uniform() {
        let mut r = Rng::new(3);
        let mut buckets = [0u32; 10];
        for _ in 0..100_000 {
            buckets[r.below(10) as usize] += 1;
        }
        for b in buckets {
            assert!((9_000..11_000).contains(&b), "{b}");
        }
        assert_eq!(Rng::new(1).below(1), 0);
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut v: Vec<u32> = (0..100).collect();
        Rng::new(8).shuffle(&mut v);
        let mut s = v.clone();
        s.sort_unstable();
        assert_eq!(s, (0..100).collect::<Vec<_>>());
        assert_ne!(v, s);
    }

    #[test]
    fn zipf_is_skewed_as_documented() {
        // 10,000 ranks, 3.5M draws would be slow in a unit test: check the shares instead.
        let z = Zipf::new(10_000);
        let total = *z.cdf.last().unwrap() as f64;
        let share = |k: usize| (z.cdf[k] - if k == 0 { 0 } else { z.cdf[k - 1] }) as f64 / total;
        let wraps = 3_500_000.0;
        assert!((85_000.0..105_000.0).contains(&(share(0) * wraps)), "top {}", share(0) * wraps);
        assert!((50_000.0..65_000.0).contains(&(share(1) * wraps)), "second {}", share(1) * wraps);
        assert!(share(9) * wraps > 15_000.0);
        assert!(share(9_999) * wraps > 50.0);
        // Sampling matches the table.
        let mut r = Rng::new(11);
        let mut hits0 = 0;
        for _ in 0..200_000 {
            let k = z.sample(&mut r);
            assert!(k < 10_000);
            if k == 0 {
                hits0 += 1;
            }
        }
        let expect = share(0) * 200_000.0;
        assert!((f64::from(hits0) - expect).abs() < expect * 0.1, "{hits0} vs {expect}");
    }
}
