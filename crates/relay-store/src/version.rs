//! A published, immutable view of the store, and every read that runs on it.
//!
//! Readers hold an `Arc<Version>`. Nothing a version points at changes in a way
//! the version can see: runs and segments are immutable, the log only grows past
//! `count`, and the writer zeroes a dead record only after every version that
//! could still read it has been dropped (see `Writer::reclaim`).

use crate::dead::DeadSet;
use crate::keys::{self, *};
use crate::log::{self, Segs};
use crate::locs;
use crate::memrun::MemRun;
use crate::mmap::MappedFile;
use crate::segment::{SegCursor, Segment};
use relay_proto::filter::Filter;
use relay_proto::Record;
use std::collections::BinaryHeap;
use std::sync::Arc;

/// One sorted run of index keys: in memory (recent writes) or a segment file.
#[derive(Clone)]
pub enum Run {
    Mem(Arc<MemRun>),
    Disk(Arc<Segment>),
}

impl Run {
    pub fn keys(&self) -> u64 {
        match self {
            Run::Mem(m) => m.len() as u64,
            Run::Disk(s) => s.keys(),
        }
    }

    /// Bytes held: memory for a memory run, file size for a segment.
    pub fn bytes(&self) -> u64 {
        match self {
            Run::Mem(m) => m.bytes() as u64,
            Run::Disk(s) => s.bytes(),
        }
    }

    /// False only when the run certainly holds no key with bloom prefix `p`.
    #[inline]
    fn may_contain(&self, p: Option<&[u8]>) -> bool {
        match (self, p) {
            (Run::Disk(s), Some(p)) => s.may_contain(p),
            _ => true,
        }
    }

    /// Visits keys in `[lo, hi)` in ascending order until `f` returns false.
    pub fn scan(&self, lo: &[u8], hi: &[u8], bloom: Option<&[u8]>, f: &mut dyn FnMut(&[u8]) -> bool) {
        if !self.may_contain(bloom) {
            return;
        }
        match self {
            Run::Mem(m) => {
                let mut i = m.lower_bound(lo);
                let end = m.lower_bound(hi);
                while i < end {
                    if !f(m.key(i)) {
                        return;
                    }
                    i += 1;
                }
            }
            Run::Disk(s) => {
                let mut c = s.range(lo, hi);
                while let Some(k) = c.next_front() {
                    if !f(k) {
                        return;
                    }
                }
            }
        }
    }

    /// Keys in `[lo, hi)`: exact for memory runs, from the block index for
    /// segments (within two blocks, no decoding).
    fn estimate(&self, lo: &[u8], hi: &[u8], bloom: Option<&[u8]>) -> u64 {
        if !self.may_contain(bloom) {
            return 0;
        }
        match self {
            Run::Mem(m) => (m.lower_bound(hi) - m.lower_bound(lo)) as u64,
            Run::Disk(s) => s.estimate_range(lo, hi),
        }
    }

    fn contains(&self, key: &[u8]) -> bool {
        match self {
            Run::Mem(m) => {
                let i = m.lower_bound(key);
                i < m.len() && m.key(i) == key
            }
            Run::Disk(s) => s.contains(key),
        }
    }

    fn cursor(&self, lo: &[u8], hi: &[u8]) -> Option<RunCursor<'_>> {
        match self {
            Run::Mem(m) => {
                let lo = m.lower_bound(lo);
                let at = m.lower_bound(hi);
                (lo < at).then_some(RunCursor::Mem { run: m, lo, at })
            }
            Run::Disk(s) => {
                let c = s.range(lo, hi);
                (c.remaining() > 0).then_some(RunCursor::Disk(c))
            }
        }
    }
}

/// The exclusive upper bound of every key starting with `p`.
pub fn prefix_end(p: &[u8]) -> Vec<u8> {
    let mut e = p.to_vec();
    while let Some(last) = e.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return e;
        }
        e.pop();
    }
    vec![0xFF; p.len() + 1]
}

pub struct Version {
    pub gen: u64,
    /// Seqs `< count` are published.
    pub count: u64,
    pub(crate) seg_size: u64,
    pub(crate) segs: Segs,
    pub(crate) locs: Arc<MappedFile>,
    pub(crate) dead: DeadSet,
    /// Segments first (oldest first), then memory runs (oldest first).
    pub(crate) runs: Arc<Vec<Run>>,
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
/// A plan touching at most this many index entries is taken without looking further.
const GOOD_ENOUGH: u64 = 256;
/// COUNTs over more entries than this are answered from the block index
/// (NIP-45 `approximate`) instead of walking every key.
pub const COUNT_EXACT_LIMIT: u64 = 20_000;

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

    pub fn index_keys(&self) -> u64 {
        self.runs.iter().map(|r| r.keys()).sum()
    }

    /// Index bytes held in memory (memory runs only; segments live in files).
    pub fn index_bytes(&self) -> u64 {
        self.runs.iter().filter(|r| matches!(r, Run::Mem(_))).map(|r| r.bytes()).sum()
    }

    /// Index bytes in segment files.
    pub fn segment_bytes(&self) -> u64 {
        self.runs.iter().filter(|r| matches!(r, Run::Disk(_))).map(|r| r.bytes()).sum()
    }

    pub fn runs(&self) -> &[Run] {
        &self.runs
    }

    /// Visits every key in `[lo, hi)`, run by run (not merged across runs).
    pub fn for_range(&self, lo: &[u8], hi: &[u8], mut f: impl FnMut(&[u8])) {
        for r in self.runs.iter() {
            r.scan(lo, hi, None, &mut |k| {
                f(k);
                true
            });
        }
    }

    /// Visits every key starting with `p`, which must be a whole bloom prefix
    /// (so segments that lack it are skipped with one bloom probe).
    pub fn for_prefix(&self, p: &[u8], mut f: impl FnMut(&[u8])) {
        let end = prefix_end(p);
        for r in self.runs.iter() {
            r.scan(p, &end, Some(p), &mut |k| {
                f(k);
                true
            });
        }
    }

    /// The live seq holding event `id`, if any.
    pub fn lookup_id(&self, id: &[u8; 32]) -> Option<u64> {
        let p = prefix(T_ID, &[id]);
        let end = prefix_end(&p);
        let mut found = None;
        for r in self.runs.iter().rev() {
            r.scan(&p, &end, Some(&p), &mut |k| {
                let seq = seq_of(k);
                if self.is_live(seq) {
                    found = Some(seq);
                    return false;
                }
                true
            });
            if found.is_some() {
                break;
            }
        }
        found
    }

    /// True if exactly `key` exists in some run (tombstone lookups).
    pub fn has_key(&self, key: &[u8]) -> bool {
        self.runs.iter().any(|r| r.contains(key))
    }

    /// Number of index entries under `p` with created_at in `[since, until]`.
    fn estimate(&self, p: &[u8], since: u64, until: u64) -> u64 {
        let (lo, hi) = bounds(p, since, until);
        self.runs.iter().map(|r| r.estimate(&lo, &hi, Some(p))).sum()
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
        // Candidates are in rough order of selectivity (author+kind, tags,
        // authors, kinds). Estimate in that order and stop as soon as one is
        // clearly small: estimating the rest would cost more than it could save.
        let mut best: Option<(u64, bool, Vec<Vec<u8>>, bool)> = None;
        for (ps, exact) in candidates {
            let est = self.estimate_all(&ps, since, until);
            if best.as_ref().is_none_or(|b| (est, !exact) < (b.0, b.1)) {
                best = Some((est, !exact, ps, exact));
            }
            if best.as_ref().is_some_and(|b| b.0 <= GOOD_ENOUGH) {
                break;
            }
        }
        let best = best.unwrap();
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

    /// The NIP-77 set for `kinds:[k...] #name:[values...]` within `[since, until]`,
    /// read from covering NEG keys alone. `None` when the shape is not covered
    /// (the caller falls back to a query). Live, unexpired events only: the set
    /// must match exactly what a REQ by id would return, or Vector's client
    /// treats the sync as failed.
    pub fn neg_items(&self, f: &Filter, now: u64) -> Option<Vec<(u64, [u8; 32])>> {
        let kinds = f.kinds.as_deref()?;
        if f.ids.is_some() || f.authors.is_some() || f.tags.len() != 1 || f.tags[0].name != b'p' {
            return None;
        }
        if !kinds.iter().all(|k| keys::NEG_KINDS.contains(k)) {
            return None;
        }
        let since = f.since.unwrap_or(0);
        let until = f.until.unwrap_or(u64::MAX);
        let mut items = Vec::new();
        for v in &f.tags[0].values {
            for k in kinds {
                let p = prefix(T_NEG, &[b"p", v, &k.to_be_bytes()]);
                let lo = prefix(T_NEG, &[b"p", v, &k.to_be_bytes(), &since.to_be_bytes()]);
                let hi = prefix(T_NEG, &[b"p", v, &k.to_be_bytes(), &until.to_be_bytes(), &[0xFF; 49]]);
                for r in self.runs.iter() {
                    r.scan(&lo, &hi, Some(&p), &mut |key| {
                        let n = key.len();
                        let seq = seq_of(key);
                        let exp = u64::from_be_bytes(key[n - 16..n - 8].try_into().unwrap());
                        if self.is_live(seq) && (exp == 0 || exp > now) {
                            let ca = u64::from_be_bytes(key[n - 56..n - 48].try_into().unwrap());
                            items.push((ca, key[n - 48..n - 16].try_into().unwrap()));
                        }
                        true
                    });
                }
            }
        }
        Some(items)
    }

    /// Number of matching events (NIP-45). Exact plans never read a record.
    pub fn count(&self, f: &Filter, now: u64) -> u64 {
        self.count_approx(f, now).0
    }

    /// NIP-45 COUNT with its `approximate` flag. An exact plan over a very large
    /// range is answered from block counts in O(log n), never walking the keys:
    /// Vector uses COUNT to size a sync, where "about 255 000" is the answer
    /// that matters, and it comes back in microseconds.
    pub fn count_approx(&self, f: &Filter, now: u64) -> (u64, bool) {
        match self.plan(f) {
            Plan::Nothing => (0, false),
            Plan::Ids => (self.query(f, usize::MAX, now).len() as u64, false),
            Plan::Scan { prefixes, exact } => {
                let since = f.since.unwrap_or(0);
                let until = f.until.unwrap_or(u64::MAX);
                if exact {
                    let est = self.estimate_all(&prefixes, since, until);
                    if est > COUNT_EXACT_LIMIT {
                        return (est, true);
                    }
                }
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
                (n, false)
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
enum RunCursor<'a> {
    Mem { run: &'a MemRun, lo: usize, at: usize },
    Disk(SegCursor<'a>),
}

impl RunCursor<'_> {
    /// Suffix of the next key (walking backwards), not consumed.
    #[inline]
    fn peek(&mut self) -> Option<u128> {
        match self {
            RunCursor::Mem { run, lo, at } => (*at > *lo).then(|| suffix(run.key(*at - 1))),
            RunCursor::Disk(c) => c.peek_back().map(suffix),
        }
    }

    #[inline]
    fn advance(&mut self) {
        match self {
            RunCursor::Mem { at, .. } => *at -= 1,
            RunCursor::Disk(c) => {
                c.next_back();
            }
        }
    }
}

/// Newest-first merge of many cursors, by `(created_at, seq)`.
struct Merge<'a> {
    cursors: Vec<RunCursor<'a>>,
    heap: BinaryHeap<(u128, usize)>,
}

impl<'a> Merge<'a> {
    fn new(v: &'a Version, prefixes: &[Vec<u8>], since: u64, until: u64) -> Merge<'a> {
        let mut cursors = Vec::new();
        let mut heap = BinaryHeap::new();
        for p in prefixes {
            let (lo_key, hi_key) = bounds(p, since, until);
            for run in v.runs.iter() {
                if !run.may_contain(Some(p)) {
                    continue;
                }
                if let Some(mut c) = run.cursor(&lo_key, &hi_key) {
                    if let Some(s) = c.peek() {
                        heap.push((s, cursors.len()));
                        cursors.push(c);
                    }
                }
            }
        }
        Merge { cursors, heap }
    }

    #[inline]
    fn next(&mut self) -> Option<(u64, u64)> {
        let (s, ci) = self.heap.pop()?;
        let c = &mut self.cursors[ci];
        c.advance();
        if let Some(n) = c.peek() {
            self.heap.push((n, ci));
        }
        Some(((s >> 64) as u64, s as u64))
    }
}

#[inline]
fn suffix(key: &[u8]) -> u128 {
    (u128::from(keys::created_at_of(key)) << 64) | u128::from(keys::seq_of(key))
}
