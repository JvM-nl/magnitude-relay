//! An immutable sorted run of keys in memory: the LSM tree's memtable tier.
//!
//! Each write batch becomes one small run; runs of similar size merge, so there
//! are O(log n) of them. Keys live back to back in one buffer with a u32 offset
//! table: a lookup is a binary search over a flat array, no pointer chasing.

use crate::keys::{self, KeyBuf};

pub struct MemRun {
    data: Vec<u8>,
    /// `offs[i]..offs[i + 1]` is key `i`; one extra entry at the end.
    offs: Vec<u32>,
}

impl MemRun {
    /// Sorts and deduplicates a batch of keys into a run.
    pub fn build(kb: &KeyBuf) -> MemRun {
        let mut idx: Vec<u32> = (0..kb.len() as u32).collect();
        idx.sort_unstable_by(|&a, &b| keys::key_cmp(kb.key(a as usize), kb.key(b as usize)));
        idx.dedup_by(|a, b| kb.key(*a as usize) == kb.key(*b as usize));
        let mut data = Vec::with_capacity(kb.data.len());
        let mut offs = Vec::with_capacity(idx.len() + 1);
        for &i in &idx {
            offs.push(data.len() as u32);
            data.extend_from_slice(kb.key(i as usize));
        }
        offs.push(data.len() as u32);
        MemRun { data, offs }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.offs.len() - 1
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Memory held, for flush and merge decisions.
    pub fn bytes(&self) -> usize {
        self.data.len() + self.offs.len() * 4
    }

    #[inline]
    pub fn key(&self, i: usize) -> &[u8] {
        &self.data[self.offs[i] as usize..self.offs[i + 1] as usize]
    }

    /// Index of the first key `>= k`.
    #[inline]
    pub fn lower_bound(&self, k: &[u8]) -> usize {
        let (mut lo, mut hi) = (0usize, self.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if keys::key_lt(self.key(mid), k) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }

    /// Merges two runs, dropping keys for which `drop` says so (keys of dead
    /// events). Tombstone keys carry no seq and are always kept.
    pub fn merge(a: &MemRun, b: &MemRun, drop: impl Fn(u64) -> bool) -> MemRun {
        let mut data = Vec::with_capacity(a.data.len() + b.data.len());
        let mut offs = Vec::with_capacity(a.len() + b.len() + 1);
        let keep = |k: &[u8]| !(keys::has_seq(k) && drop(keys::seq_of(k)));
        let (mut i, mut j) = (0, 0);
        let push = |k: &[u8], data: &mut Vec<u8>, offs: &mut Vec<u32>| {
            if keep(k) {
                offs.push(data.len() as u32);
                data.extend_from_slice(k);
            }
        };
        while i < a.len() && j < b.len() {
            let (ka, kb) = (a.key(i), b.key(j));
            match keys::key_cmp(ka, kb) {
                std::cmp::Ordering::Less => {
                    push(ka, &mut data, &mut offs);
                    i += 1;
                }
                std::cmp::Ordering::Greater => {
                    push(kb, &mut data, &mut offs);
                    j += 1;
                }
                std::cmp::Ordering::Equal => {
                    push(ka, &mut data, &mut offs);
                    i += 1;
                    j += 1;
                }
            }
        }
        for k in i..a.len() {
            push(a.key(k), &mut data, &mut offs);
        }
        for k in j..b.len() {
            push(b.key(k), &mut data, &mut offs);
        }
        offs.push(data.len() as u32);
        MemRun { data, offs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(keys: &[&[u8]]) -> MemRun {
        let mut kb = KeyBuf::default();
        for k in keys {
            kb.push(k);
        }
        MemRun::build(&kb)
    }

    #[test]
    fn sorted_dedup_search_merge() {
        let r = run(&[b"c", b"a", b"b", b"a"]);
        assert_eq!(r.len(), 3);
        assert_eq!(r.key(0), b"a");
        assert_eq!(r.lower_bound(b"b"), 1);
        assert_eq!(r.lower_bound(b"bb"), 2);
        assert_eq!(r.lower_bound(b"z"), 3);
        let s = run(&[b"b", b"d"]);
        let m = MemRun::merge(&r, &s, |_| false);
        let all: Vec<&[u8]> = (0..m.len()).map(|i| m.key(i)).collect();
        assert_eq!(all, vec![&b"a"[..], b"b", b"c", b"d"]);
    }
}
