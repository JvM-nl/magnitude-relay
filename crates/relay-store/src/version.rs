//! A published, immutable view of the store, and every read that runs on it.
//!
//! Readers hold an `Arc<Version>`. Nothing a version points at changes in a way
//! the version can see: runs are immutable, the log only grows past `count`, and
//! the writer zeroes a dead record only after every version that could still
//! read it has been dropped (see `Writer::reclaim`).

use crate::dead::DeadSet;
use crate::keys::{self, *};
use crate::log::{self, Segs};
use crate::locs;
use crate::memrun::MemRun;
use crate::mmap::MappedFile;
use relay_proto::filter::Filter;
use relay_proto::Record;
use std::collections::BinaryHeap;
use std::sync::Arc;

pub struct Version {
    pub gen: u64,
    /// Seqs `< count` are published.
    pub count: u64,
    pub(crate) seg_size: u64,
    pub(crate) segs: Segs,
    pub(crate) locs: Arc<MappedFile>,
    pub(crate) dead: DeadSet,
    /// Oldest first.
    pub(crate) runs: Arc<Vec<Arc<MemRun>>>,
}

/// One query result, enough to order it and fetch it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    pub created_at: u64,
    pub seq: u64,
    pub id: [u8; 32],
}

/// How a filter will be answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    Nothing,
    Ids,
    /// Range scans over these prefixes. `exact`: every key in range matches the
    /// filter, so no record has to be checked (it is still read to be sent).
    Scan { prefixes: Vec<Vec<u8>>, exact: bool },
}

/// Over this many prefixes, cardinality is estimated from a sample.
const ESTIMATE_SAMPLE: usize = 16;
/// Cartesian products (authors × kinds, values × kinds) above this fall back to
/// the single-dimension index.
const MAX_PRODUCT: usize = 4096;

impl Version {
    #[inline]
    pub fn is_live(&self, seq: u64) -> bool {
        seq < self.count && !self.dead.is_dead(seq)
    }

    /// The record stored at `seq`, unless it is unpublished or dead.
    #[inline]
    pub fn record(&self, seq: u64) -> Option<Record<'_>> {
        if !self.is_live(seq) {
            return None;
        }
        Some(self.record_unchecked(seq))
    }

    #[inline]
    pub(crate) fn record_unchecked(&self, seq: u64) -> Record<'_> {
        let off = locs::get(&self.locs, seq);
        Record(log::record_at(&self.segs, self.seg_size, off))
    }

    pub fn dead_count(&self) -> u64 {
        self.dead.count()
    }

    pub fn index_keys(&self) -> usize {
        self.runs.iter().map(|r| r.len()).sum()
    }

    pub fn index_bytes(&self) -> usize {
        self.runs.iter().map(|r| r.bytes()).sum()
    }

    /// The live seq holding event `id`, if any.
    pub fn lookup_id(&self, id: &[u8; 32]) -> Option<u64> {
        let p = prefix(T_ID, &[id]);
        for run in self.runs.iter().rev() {
            let mut i = run.lower_bound(&p);
            while i < run.len() && run.key(i).starts_with(&p) {
                let seq = seq_of(run.key(i));
                if self.is_live(seq) {
                    return Some(seq);
                }
                i += 1;
            }
        }
        None
    }

    /// True if exactly `key` exists in some run (tombstone lookups).
    pub fn has_key(&self, key: &[u8]) -> bool {
        self.runs.iter().any(|r| {
            let i = r.lower_bound(key);
            i < r.len() && r.key(i) == key
        })
    }

    /// Visits every key starting with `p`, all runs, unordered across runs.
    pub fn for_prefix(&self, p: &[u8], mut f: impl FnMut(&[u8])) {
        for run in self.runs.iter() {
            let mut i = run.lower_bound(p);
            while i < run.len() && run.key(i).starts_with(p) {
                f(run.key(i));
                i += 1;
            }
        }
    }

    /// Number of index entries under `p` with created_at in `[since, until]`.
    fn estimate(&self, p: &[u8], since: u64, until: u64) -> u64 {
        let (lo, hi) = bounds(p, since, until);
        self.runs.iter().map(|r| (r.lower_bound(&hi) - r.lower_bound(&lo)) as u64).sum()
    }

    fn estimate_all(&self, prefixes: &[Vec<u8>], since: u64, until: u64) -> u64 {
        if prefixes.len() <= ESTIMATE_SAMPLE {
            return prefixes.iter().map(|p| self.estimate(p, since, until)).sum();
        }
        let step = prefixes.len() / ESTIMATE_SAMPLE;
        let sampled: u64 = prefixes.iter().step_by(step).take(ESTIMATE_SAMPLE).map(|p| self.estimate(p, since, until)).sum();
        sampled * prefixes.len() as u64 / ESTIMATE_SAMPLE as u64
    }

    /// Chooses the index whose ranges hold the fewest entries.
    pub fn plan(&self, f: &Filter) -> Plan {
        if f.never_matches() {
            return Plan::Nothing;
        }
        if f.ids.is_some() {
            return Plan::Ids;
        }
        let since = f.since.unwrap_or(0);
        let until = f.until.unwrap_or(u64::MAX);
        let n_tags = f.tags.len();
        let mut candidates: Vec<(Vec<Vec<u8>>, bool)> = Vec::new();

        let kinds = f.kinds.as_deref();
        if let Some(authors) = &f.authors {
            match kinds {
                Some(ks) if authors.len() * ks.len() <= MAX_PRODUCT => {
                    let ps = authors
                        .iter()
                        .flat_map(|a| ks.iter().map(move |k| prefix(T_AUTHOR_KIND, &[a, &k.to_be_bytes()])))
                        .collect();
                    candidates.push((ps, n_tags == 0));
                }
                _ => {
                    let ps = authors.iter().map(|a| prefix(T_AUTHOR, &[a])).collect();
                    candidates.push((ps, kinds.is_none() && n_tags == 0));
                }
            }
        }
        for t in &f.tags {
            let alone = n_tags == 1 && f.authors.is_none();
            match kinds {
                Some(ks) if t.values.len() * ks.len() <= MAX_PRODUCT => {
                    let ps = t
                        .values
                        .iter()
                        .flat_map(|v| ks.iter().map(move |k| prefix(T_TAG_KIND, &[&[t.name], v, &k.to_be_bytes()])))
                        .collect();
                    candidates.push((ps, alone));
                }
                _ => {
                    let ps = t.values.iter().map(|v| prefix(T_TAG, &[&[t.name], v])).collect();
                    candidates.push((ps, alone && kinds.is_none()));
                }
            }
        }
        if let Some(ks) = kinds {
            let ps = ks.iter().map(|k| prefix(T_KIND, &[&k.to_be_bytes()])).collect();
            candidates.push((ps, f.authors.is_none() && n_tags == 0));
        }
        if candidates.is_empty() {
            return Plan::Scan { prefixes: vec![vec![T_CREATED]], exact: true };
        }
        if candidates.len() == 1 {
            let (prefixes, exact) = candidates.pop().unwrap();
            return Plan::Scan { prefixes, exact };
        }
        let best = candidates
            .into_iter()
            .map(|(ps, exact)| {
                let est = self.estimate_all(&ps, since, until);
                (est, !exact, ps, exact)
            })
            .min_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)))
            .unwrap();
        Plan::Scan { prefixes: best.2, exact: best.3 }
    }

    /// Up to `limit` matching events, `created_at` descending, ties lowest id
    /// first (NIP-01). Expired events (`expiration <= now`) are never returned.
    pub fn query(&self, f: &Filter, limit: usize, now: u64) -> Vec<Hit> {
        if limit == 0 {
            return Vec::new();
        }
        let mut hits = Vec::new();
        match self.plan(f) {
            Plan::Nothing => {}
            Plan::Ids => {
                for id in f.ids.as_deref().unwrap_or(&[]) {
                    let Some(seq) = self.lookup_id(id) else { continue };
                    let rec = self.record_unchecked(seq);
                    if !expired(rec, now) && f.matches(rec) {
                        hits.push(Hit { created_at: rec.created_at(), seq, id: *rec.id() });
                    }
                }
            }
            Plan::Scan { prefixes, exact } => {
                let since = f.since.unwrap_or(0);
                let until = f.until.unwrap_or(u64::MAX);
                let mut m = Merge::new(self, &prefixes, since, until);
                let mut last = u64::MAX;
                let mut boundary: Option<u64> = None;
                while let Some((ca, seq)) = m.next() {
                    if seq == last {
                        continue;
                    }
                    last = seq;
                    if boundary.is_some_and(|b| ca < b) {
                        break;
                    }
                    if !self.is_live(seq) {
                        continue;
                    }
                    let rec = self.record_unchecked(seq);
                    if expired(rec, now) || (!exact && !f.matches(rec)) {
                        continue;
                    }
                    hits.push(Hit { created_at: ca, seq, id: *rec.id() });
                    // Keep reading the rest of the last second: which of its
                    // events make the cut depends on their ids.
                    if boundary.is_none() && hits.len() >= limit {
                        boundary = Some(ca);
                    }
                }
            }
        }
        hits.sort_unstable_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));
        hits.truncate(limit);
        hits
    }

    /// Number of matching events (NIP-45). Exact plans never read a record.
    pub fn count(&self, f: &Filter, now: u64) -> u64 {
        match self.plan(f) {
            Plan::Nothing => 0,
            Plan::Ids => self.query(f, usize::MAX, now).len() as u64,
            Plan::Scan { prefixes, exact } => {
                let since = f.since.unwrap_or(0);
                let until = f.until.unwrap_or(u64::MAX);
                let mut m = Merge::new(self, &prefixes, since, until);
                let mut last = u64::MAX;
                let mut n = 0;
                while let Some((_, seq)) = m.next() {
                    if seq == last {
                        continue;
                    }
                    last = seq;
                    if !self.is_live(seq) {
                        continue;
                    }
                    if exact {
                        n += 1;
                        continue;
                    }
                    let rec = self.record_unchecked(seq);
                    if !expired(rec, now) && f.matches(rec) {
                        n += 1;
                    }
                }
                n
            }
        }
    }
}

#[inline]
fn expired(rec: Record<'_>, now: u64) -> bool {
    rec.expiration().is_some_and(|e| e <= now)
}

/// The key range `[lo, hi)` holding prefix `p` with created_at in `[since, until]`.
fn bounds(p: &[u8], since: u64, until: u64) -> (Vec<u8>, Vec<u8>) {
    let mut lo = Vec::with_capacity(p.len() + 16);
    lo.extend_from_slice(p);
    lo.extend_from_slice(&since.to_be_bytes());
    lo.extend_from_slice(&[0; 8]);
    let mut hi = Vec::with_capacity(p.len() + 17);
    hi.extend_from_slice(p);
    hi.extend_from_slice(&until.to_be_bytes());
    hi.extend_from_slice(&[0xFF; 8]);
    // One byte past every key with this created_at (seq is at most 8 bytes of 0xFF).
    hi.push(0);
    (lo, hi)
}

/// A backwards cursor over one prefix range of one run.
struct Cursor<'a> {
    run: &'a MemRun,
    lo: usize,
    /// One past the next key to yield.
    at: usize,
}

/// Newest-first merge of many cursors, by `(created_at, seq)`.
struct Merge<'a> {
    cursors: Vec<Cursor<'a>>,
    heap: BinaryHeap<(u128, usize)>,
}

impl<'a> Merge<'a> {
    fn new(v: &'a Version, prefixes: &[Vec<u8>], since: u64, until: u64) -> Merge<'a> {
        let mut cursors = Vec::new();
        let mut heap = BinaryHeap::new();
        for p in prefixes {
            let (lo_key, hi_key) = bounds(p, since, until);
            for run in v.runs.iter() {
                let lo = run.lower_bound(&lo_key);
                let hi = run.lower_bound(&hi_key);
                if lo < hi {
                    let c = Cursor { run, lo, at: hi };
                    heap.push((suffix(c.run.key(hi - 1)), cursors.len()));
                    cursors.push(c);
                }
            }
        }
        Merge { cursors, heap }
    }

    #[inline]
    fn next(&mut self) -> Option<(u64, u64)> {
        let (s, ci) = self.heap.pop()?;
        let c = &mut self.cursors[ci];
        c.at -= 1;
        if c.at > c.lo {
            self.heap.push((suffix(c.run.key(c.at - 1)), ci));
        }
        Some(((s >> 64) as u64, s as u64))
    }
}

#[inline]
fn suffix(key: &[u8]) -> u128 {
    (u128::from(keys::created_at_of(key)) << 64) | u128::from(keys::seq_of(key))
}
