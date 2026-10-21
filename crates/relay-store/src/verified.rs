//! Which records have had their checksum checked since the store was opened.
//!
//! Replay and log compaction check every frame's CRC; reads did not, so a bit
//! flipped inside a record on disk was served as it was. Checking on every
//! read costs about 0.1 µs per KiB of record, every time it is read (and for
//! every candidate a scan reads); one bit per seq makes it once per record per
//! process. A record is checked where it is read, in the frame `locs` points
//! at; a compaction that moves it checks it as it copies.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// Bits per page: 2^20 records in 128 KiB, allocated as seqs reach them.
const PAGE_BITS: u64 = 1 << 20;
const PAGE_WORDS: usize = (PAGE_BITS / 64) as usize;
/// Pages: 2^32 records. Seqs beyond are checked on every read.
const PAGES: usize = 1 << 12;

pub struct Verified {
    pages: Box<[OnceLock<Box<[AtomicU64]>>]>,
}

impl Default for Verified {
    fn default() -> Self {
        Verified { pages: (0..PAGES).map(|_| OnceLock::new()).collect() }
    }
}

impl Verified {
    #[inline]
    fn at(seq: u64) -> Option<(usize, usize, u64)> {
        let page = (seq / PAGE_BITS) as usize;
        (page < PAGES).then(|| (page, ((seq % PAGE_BITS) / 64) as usize, 1u64 << (seq % 64)))
    }

    /// Whether `seq`'s record has been checked.
    #[inline]
    pub fn contains(&self, seq: u64) -> bool {
        let Some((page, word, bit)) = Self::at(seq) else { return false };
        self.pages[page].get().is_some_and(|p| p[word].load(Ordering::Relaxed) & bit != 0)
    }

    pub fn insert(&self, seq: u64) {
        let Some((page, word, bit)) = Self::at(seq) else { return };
        let p = self.pages[page].get_or_init(|| (0..PAGE_WORDS).map(|_| AtomicU64::new(0)).collect());
        p[word].fetch_or(bit, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_each_seq_alone() {
        let v = Verified::default();
        for s in [0, 1, 63, 64, PAGE_BITS - 1, PAGE_BITS, 3 * PAGE_BITS + 7] {
            assert!(!v.contains(s));
            v.insert(s);
            assert!(v.contains(s));
        }
        assert!(!v.contains(2) && !v.contains(PAGE_BITS + 1));
        // Past the last page: never remembered, so always checked.
        let far = PAGES as u64 * PAGE_BITS;
        v.insert(far);
        assert!(!v.contains(far));
    }
}
