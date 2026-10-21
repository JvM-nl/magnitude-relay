//! Bloom filters over index key prefixes (see `keys::bloom_prefix`), for segment
//! files (persisted after their blocks) and memory runs (built with the run).
//! Blocked: a prefix's `K` bits all fall in one 512-bit block, so a probe for an
//! absent prefix costs one cache line.

pub(crate) const BITS_PER_PREFIX: usize = 10;
pub(crate) const K: u32 = 7;

/// 64-bit hash for bloom probes: multiply-xorshift over 8-byte words. Fast,
/// well mixed, and stable across platforms (it is persisted in segment files).
pub fn hash64(b: &[u8]) -> u64 {
    const M: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut h = (b.len() as u64).wrapping_mul(M) ^ 0x2545_F491_4F6C_DD1D;
    let mut chunks = b.chunks_exact(8);
    for c in &mut chunks {
        let w = u64::from_le_bytes(c.try_into().unwrap());
        h = (h ^ w.wrapping_mul(M)).rotate_left(29).wrapping_mul(M);
    }
    let mut tail = [0u8; 8];
    tail[..chunks.remainder().len()].copy_from_slice(chunks.remainder());
    h = (h ^ u64::from_le_bytes(tail).wrapping_mul(M)).rotate_left(29).wrapping_mul(M);
    h ^= h >> 32;
    h = h.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    h ^ (h >> 32)
}

/// Calls `f(block, bit)` for each of the hash's `K` bits until it returns false;
/// true if it never did.
#[inline]
pub(crate) fn probe(h: u64, nblocks: u64, mut f: impl FnMut(usize, u32) -> bool) -> bool {
    let block = (((h >> 32) * nblocks) >> 32) as usize;
    let h1 = h as u32;
    let h2 = ((h >> 32) as u32).rotate_left(16) | 1;
    for i in 0..K {
        if !f(block, h1.wrapping_add(i.wrapping_mul(h2)) & 511) {
            return false;
        }
    }
    true
}

/// Blocks for a filter of `prefixes` distinct prefixes.
pub(crate) fn blocks_for(prefixes: usize) -> u64 {
    (prefixes * BITS_PER_PREFIX).div_ceil(512).max(1) as u64
}

/// One 512-bit block, aligned so that it is one cache line.
#[derive(Clone, Copy, Default)]
#[repr(C, align(64))]
pub(crate) struct Line(pub [u64; 8]);

/// The filter's blocks for these prefix hashes.
pub(crate) fn lines(hashes: &[u64]) -> Box<[Line]> {
    let nblocks = blocks_for(hashes.len());
    let mut lines = vec![Line::default(); nblocks as usize].into_boxed_slice();
    for &h in hashes {
        probe(h, nblocks, |blk, bit| {
            lines[blk].0[(bit / 64) as usize] |= 1 << (bit % 64);
            true
        });
    }
    lines
}

/// A filter held in memory.
pub struct Bloom {
    lines: Box<[Line]>,
}

impl Bloom {
    pub fn new(hashes: &[u64]) -> Bloom {
        Bloom { lines: lines(hashes) }
    }

    /// False means no key with bloom prefix `p` was added.
    #[inline]
    pub fn may_contain(&self, p: &[u8]) -> bool {
        let lines = &self.lines;
        probe(hash64(p), lines.len() as u64, |blk, bit| lines[blk].0[(bit / 64) as usize] & (1 << (bit % 64)) != 0)
    }

    pub fn bytes(&self) -> usize {
        self.lines.len() * 64
    }
}

/// One filter over every memory run between two flushes: a lookup it rules
/// out skips them all on one probe (a dozen or more runs each have their own
/// filter too). Bits are only ever set, before the version holding their run
/// is published, so an older version's reader sees at most extra bits, which
/// costs a false positive and nothing else. A flush starts a new one.
pub struct SharedBloom {
    lines: Box<[AtomicLine]>,
}

#[repr(C, align(64))]
struct AtomicLine([std::sync::atomic::AtomicU64; 8]);

impl SharedBloom {
    /// Sized for about `prefixes` distinct prefixes.
    pub fn with_capacity(prefixes: usize) -> SharedBloom {
        let n = blocks_for(prefixes) as usize;
        SharedBloom { lines: (0..n).map(|_| AtomicLine(Default::default())).collect() }
    }

    pub fn add(&self, hashes: &[u64]) {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.lines.len() as u64;
        for &h in hashes {
            probe(h, n, |blk, bit| {
                self.lines[blk].0[(bit / 64) as usize].fetch_or(1 << (bit % 64), Relaxed);
                true
            });
        }
    }

    /// False means no key with bloom prefix `p` was added.
    #[inline]
    pub fn may_contain(&self, p: &[u8]) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        let lines = &self.lines;
        probe(hash64(p), lines.len() as u64, |blk, bit| lines[blk].0[(bit / 64) as usize].load(Relaxed) & (1 << (bit % 64)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shared_filter_knows_what_was_added() {
        let keys: Vec<Vec<u8>> = (0..5_000u32).map(|i| [&b"s"[..], &i.to_be_bytes()].concat()).collect();
        let s = SharedBloom::with_capacity(10_000);
        assert!(!keys.iter().any(|k| s.may_contain(k)));
        let hashes: Vec<u64> = keys.iter().map(|k| hash64(k)).collect();
        s.add(&hashes[..2_500]);
        assert!(keys[..2_500].iter().all(|k| s.may_contain(k)));
        s.add(&hashes[2_500..]);
        assert!(keys.iter().all(|k| s.may_contain(k)));
    }

    #[test]
    fn no_false_negatives_and_few_false_positives() {
        let keys: Vec<Vec<u8>> = (0..20_000u32).map(|i| [&b"k"[..], &i.to_be_bytes()].concat()).collect();
        let hashes: Vec<u64> = keys.iter().map(|k| hash64(k)).collect();
        let b = Bloom::new(&hashes);
        assert!(keys.iter().all(|k| b.may_contain(k)));
        let fp = (20_000..120_000u32).filter(|i| b.may_contain(&[&b"k"[..], &i.to_be_bytes()].concat())).count();
        // 10 bits and 7 probes per prefix: about 1%, a little more for blocking.
        assert!(fp < 2_500, "{fp} false positives in 100000");
        assert!(!Bloom::new(&[]).may_contain(b"anything"));
    }
}
