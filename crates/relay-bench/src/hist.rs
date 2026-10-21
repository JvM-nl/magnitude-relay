//! Log-linear latency histogram, in nanoseconds.
//!
//! A benchmark that reports only a mean hides exactly what a relay operator needs
//! (the tail), and a sorted `Vec` of every sample costs gigabytes over a long
//! run. This keeps a fixed 3,776 counters (30 KiB) per recorder and answers any
//! quantile in one pass over them.
//!
//! Layout, the same idea as HDR histograms: values below 128 each get their own
//! bucket; above that every power of two is split into 64 equal-width buckets, so
//! the relative error of a reported quantile is at most 1/64 (1.6%, two
//! significant digits) at any magnitude from 1 ns to 584 years, with no
//! configuration and no overflow. Each task records into its own histogram and
//! the results are merged at the end, so recording never touches shared state.

/// Values below this have one exact bucket each.
const LINEAR: u64 = 128;
/// Buckets per power of two above [`LINEAR`].
const PER_OCTAVE: u64 = 64;
/// 128 linear buckets, then 57 octaves (2^7 ..= 2^63) of 64.
const BUCKETS: usize = (LINEAR + 57 * PER_OCTAVE) as usize;

#[derive(Clone)]
pub struct Histogram {
    counts: Vec<u64>,
    n: u64,
    sum: u128,
    min: u64,
    max: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram::new()
    }
}

/// Bucket holding `v`.
#[inline]
fn index(v: u64) -> usize {
    if v < LINEAR {
        return v as usize;
    }
    let msb = 63 - v.leading_zeros() as u64;
    // Keep the top 7 bits (the leading 1 and 6 more): 64..=127.
    let shift = msb - 6;
    let top = v >> shift;
    (LINEAR + (shift - 1) * PER_OCTAVE + (top - 64)) as usize
}

/// Smallest and largest value that land in bucket `i`.
#[inline]
fn bounds(i: usize) -> (u64, u64) {
    let i = i as u64;
    if i < LINEAR {
        return (i, i);
    }
    let k = i - LINEAR;
    let shift = k / PER_OCTAVE + 1;
    let top = 64 + k % PER_OCTAVE;
    let lo = top << shift;
    (lo, lo + ((1u64 << shift) - 1))
}

impl Histogram {
    pub fn new() -> Histogram {
        Histogram { counts: vec![0; BUCKETS], n: 0, sum: 0, min: u64::MAX, max: 0 }
    }

    #[inline]
    pub fn record(&mut self, v: u64) {
        self.counts[index(v)] += 1;
        self.n += 1;
        self.sum += u128::from(v);
        self.min = self.min.min(v);
        self.max = self.max.max(v);
    }

    pub fn merge(&mut self, other: &Histogram) {
        for (a, b) in self.counts.iter_mut().zip(&other.counts) {
            *a += b;
        }
        self.n += other.n;
        self.sum += other.sum;
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
    }

    pub fn count(&self) -> u64 {
        self.n
    }

    /// Largest recorded value (exact), 0 when empty.
    pub fn max(&self) -> u64 {
        self.max
    }

    /// Smallest recorded value (exact), 0 when empty.
    pub fn min(&self) -> u64 {
        if self.n == 0 {
            0
        } else {
            self.min
        }
    }

    pub fn mean(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.sum as f64 / self.n as f64
        }
    }

    /// The value below which a fraction `q` (0..=1) of the samples fall: the top of
    /// the bucket holding the `ceil(q * n)`-th smallest sample, clamped to the exact
    /// observed min and max. Rounding up, never down, so a reported p99 is never
    /// better than the truth by more than the bucket width.
    pub fn quantile(&self, q: f64) -> u64 {
        if self.n == 0 {
            return 0;
        }
        let rank = ((q.clamp(0.0, 1.0) * self.n as f64).ceil() as u64).clamp(1, self.n);
        let mut seen = 0u64;
        for (i, &c) in self.counts.iter().enumerate() {
            seen += c;
            if seen >= rank {
                return bounds(i).1.clamp(self.min, self.max);
            }
        }
        self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::Rng;

    #[test]
    fn small_values_are_exact() {
        let mut h = Histogram::new();
        for v in 0..LINEAR {
            h.record(v);
        }
        assert_eq!(h.count(), 128);
        assert_eq!(h.min(), 0);
        assert_eq!(h.max(), 127);
        assert_eq!(h.quantile(0.5), 63);
        assert_eq!(h.quantile(1.0), 127);
    }

    #[test]
    fn bucket_layout_is_contiguous_and_self_consistent() {
        let mut prev_hi = None::<u64>;
        for i in 0..BUCKETS {
            let (lo, hi) = bounds(i);
            assert!(lo <= hi);
            assert_eq!(index(lo), i, "lo of bucket {i}");
            assert_eq!(index(hi), i, "hi of bucket {i}");
            if let Some(p) = prev_hi {
                assert_eq!(lo, p + 1, "gap before bucket {i}");
            }
            prev_hi = Some(hi);
        }
        assert_eq!(prev_hi, Some(u64::MAX));
        assert_eq!(index(u64::MAX), BUCKETS - 1);
    }

    #[test]
    fn relative_error_is_bounded() {
        // Log-uniform samples from 1 ns to ~100 s, compared with the exact sorted answer.
        let mut rng = Rng::new(42);
        let mut h = Histogram::new();
        let mut all = Vec::new();
        for _ in 0..200_000 {
            let exp = rng.below(37) as u32;
            let v = (1u64 << exp) + rng.below(1u64 << exp);
            h.record(v);
            all.push(v);
        }
        all.sort_unstable();
        for q in [0.01, 0.1, 0.5, 0.9, 0.99, 0.999, 0.9999] {
            let exact = all[((q * all.len() as f64).ceil() as usize).clamp(1, all.len()) - 1];
            let got = h.quantile(q);
            assert!(got >= exact, "q={q}: {got} < exact {exact}");
            let err = (got - exact) as f64 / exact as f64;
            assert!(err <= 1.0 / 64.0 + 1e-9, "q={q}: relative error {err}");
        }
        assert_eq!(h.max(), *all.last().unwrap());
        assert_eq!(h.min(), all[0]);
        assert_eq!(h.quantile(1.0), h.max());
    }

    #[test]
    fn merge_equals_recording_everything_in_one() {
        let mut rng = Rng::new(7);
        let (mut a, mut b, mut both) = (Histogram::new(), Histogram::new(), Histogram::new());
        for i in 0..50_000u64 {
            let v = rng.below(5_000_000);
            both.record(v);
            let side = if i % 3 == 0 { &mut a } else { &mut b };
            side.record(v);
        }
        a.merge(&b);
        assert_eq!(a.count(), both.count());
        assert_eq!(a.max(), both.max());
        assert_eq!(a.min(), both.min());
        assert!((a.mean() - both.mean()).abs() < 1e-6);
        for q in [0.5, 0.9, 0.99, 0.999] {
            assert_eq!(a.quantile(q), both.quantile(q));
        }
    }

    #[test]
    fn empty_and_extremes_do_not_panic() {
        let h = Histogram::new();
        assert_eq!((h.count(), h.min(), h.max(), h.quantile(0.99)), (0, 0, 0, 0));
        assert_eq!(h.mean(), 0.0);
        let mut h = Histogram::new();
        h.record(0);
        h.record(u64::MAX);
        assert_eq!(h.quantile(0.0), 0);
        assert_eq!(h.quantile(0.5), 0);
        assert_eq!(h.quantile(1.0), u64::MAX);
    }

    #[test]
    fn quantiles_never_decrease() {
        let mut rng = Rng::new(9);
        let mut h = Histogram::new();
        for _ in 0..10_000 {
            h.record(rng.below(1 << 30));
        }
        let mut last = 0;
        for i in 0..=1000 {
            let v = h.quantile(f64::from(i) / 1000.0);
            assert!(v >= last);
            last = v;
        }
    }
}
