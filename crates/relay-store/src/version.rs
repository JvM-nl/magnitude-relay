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
            (Run::Mem(m), Some(p)) => m.may_contain(p),
            (_, None) => true,
        }
    }

    /// Visits keys in `[lo, hi)` in ascending order until `f` returns false.
    pub fn scan(&self, lo: &[u8], hi: &[u8], bloom: Option<&[u8]>, f: &mut dyn FnMut(&[u8]) -> bool) {
        if !self.may_contain(bloom) {
            return;
        }
        match self {
            Run::Mem(m) => {
                // Ranges are mostly a few keys: walk to the end rather than
                // search for it.
                let mut i = m.lower_bound(lo);
                while i < m.len() && keys::key_lt(m.key(i), hi) {
                    if !f(m.key(i)) {
                        return;
                    }
                    i += 1;
                }
            }
            Run::Disk(s) => s.scan(lo, hi, f),
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
                if !m.may_contain(keys::bloom_prefix(key)) {
                    return false;
                }
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
    /// Where the memory runs start in `runs`.
    pub(crate) mem_start: usize,
    /// A filter over every memory run's prefixes (see `bloom::SharedBloom`).
    pub(crate) mem_bloom: Arc<crate::bloom::SharedBloom>,
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

    /// Whether a live event's stored bytes still match their checksum.
    pub fn intact(&self, seq: u64) -> bool {
        self.is_live(seq) && log::frame_intact(&self.segs, self.seg_size, locs::get(&self.locs, seq))
    }

    /// First step of reading event `seq` soon: starts loading where its offset
    /// is kept. A hint only.
    #[inline]
    pub fn prefetch_loc(&self, seq: u64) {
        let at = (seq * 8) as usize;
        self.locs.prefetch(at, at + 8);
    }

    /// Second step: starts loading the event's frame and fixed header (what
    /// filters, ids and expirations are read from). Reads the offset, so it is
    /// best a few steps after [`prefetch_loc`](Self::prefetch_loc). A hint only.
    #[inline]
    pub fn prefetch_record(&self, seq: u64) {
        let off = locs::get(&self.locs, seq);
        if let Some(seg) = self.segs.file(off / self.seg_size) {
            let o = (off % self.seg_size) as usize;
            seg.prefetch(o, o + log::FRAME_HEADER + relay_proto::record::HEADER_LEN + 8);
        }
    }

    #[inline]
    pub(crate) fn record_unchecked(&self, seq: u64) -> Record<'_> {
        let off = locs::get(&self.locs, seq);
        Record(log::record_at(&self.segs, self.seg_size, off))
    }

    /// Whether `seq`'s log frame is flagged dead. A kill's flag reaches the disk
    /// before the record may be zeroed, so after a crash this tells a killed
    /// (perhaps zeroed) record from a live one even when the dead set, loaded
    /// from the last checkpoint, has not heard of the kill.
    pub(crate) fn frame_dead(&self, seq: u64) -> bool {
        log::frame_dead(&self.segs, self.seg_size, locs::get(&self.locs, seq))
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

    /// The runs that may hold keys with bloom prefix `p`, oldest first: the
    /// memory runs are left out together when their shared filter rules `p`
    /// out (each run's own filter is still asked by the callers' scans).
    #[inline]
    fn runs_for(&self, p: &[u8]) -> &[Run] {
        if self.mem_start < self.runs.len() && !self.mem_bloom.may_contain(p) {
            &self.runs[..self.mem_start]
        } else {
            &self.runs
        }
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
        for r in self.runs_for(p) {
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
        for r in self.runs_for(&p).iter().rev() {
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

    /// True if at least `n` keys start with bloom prefix `p` (live or not).
    pub fn prefix_has(&self, p: &[u8], n: usize) -> bool {
        let end = prefix_end(p);
        let mut seen = 0;
        for r in self.runs_for(p) {
            r.scan(p, &end, Some(p), &mut |_| {
                seen += 1;
                seen < n
            });
            if seen >= n {
                return true;
            }
        }
        false
    }

    /// True if exactly `key` exists in some run (tombstone lookups).
    pub fn has_key(&self, key: &[u8]) -> bool {
        self.runs_for(keys::bloom_prefix(key)).iter().any(|r| r.contains(key))
    }

    /// Number of index entries under `p` with created_at in `[since, until]`.
    fn estimate(&self, p: &[u8], since: u64, until: u64) -> u64 {
        let (lo, hi) = bounds(p, since, until);
        self.runs_for(p).iter().map(|r| r.estimate(&lo, &hi, Some(p))).sum()
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
        // An author+kind or tag+kind index reads a subset of what the kind
        // index would, and is at least as exact: with one of them, kinds alone
        // is never the better plan and is not worth estimating.
        let mut kinds_combined = false;

        let kinds = f.kinds.as_deref();
        if let Some(authors) = &f.authors {
            match kinds {
                Some(ks) if authors.len() * ks.len() <= MAX_PRODUCT => {
                    let ps = authors
                        .iter()
                        .flat_map(|a| ks.iter().map(move |k| prefix(T_AUTHOR_KIND, &[a, &k.to_be_bytes()])))
                        .collect();
                    candidates.push((ps, n_tags == 0));
                    kinds_combined = true;
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
                    kinds_combined = true;
                }
                _ => {
                    let ps = t.values.iter().map(|v| prefix(T_TAG, &[&[t.name], v])).collect();
                    candidates.push((ps, alone && kinds.is_none()));
                }
            }
        }
        if let Some(ks) = kinds.filter(|_| !kinds_combined) {
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

    /// Up to `limit` matching events, each once, `created_at` descending, ties
    /// lowest id first (NIP-01). Expired events (`expiration <= now`) are never returned.
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
                let mut boundary: Option<u64> = None;
                for (ca, seq) in Ahead::new(self, Merge::new(self, &prefixes, since, until)) {
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
        // Each event once: an id a filter lists twice is looked up twice.
        hits.dedup_by_key(|h| h.seq);
        hits.truncate(limit);
        hits
    }

    /// Every live, unexpired event matching any of `filters`, newest first
    /// (`created_at` descending, ties latest stored first), each once however
    /// many filters match it. With `older_than`, only events created strictly
    /// before it. A filter's `limit` is not applied.
    ///
    /// Lazy, unlike [`query`](Self::query): memory is bounded by the number of
    /// filters, not of matches, so an operator can walk millions of events.
    pub fn matching(&self, filters: &[Filter], older_than: Option<u64>, now: u64) -> Matching<'_> {
        self.walk(filters, older_than, now, None)
    }

    /// [`matching`](Self::matching) without the records: hits carry no id (it is
    /// zeroed), and a filter the index answers whole reads no record at all,
    /// because the only expired events still live are the few the next sweep
    /// will take, found up front in the expiry index. For counting and removal,
    /// where reading millions of records would be the whole cost.
    pub fn matching_seqs(&self, filters: &[Filter], older_than: Option<u64>, now: u64) -> Matching<'_> {
        self.walk(filters, older_than, now, Some(self.expired_live(now)))
    }

    /// Live events whose expiration has passed (not yet swept), from the expiry
    /// index: what a keys-only walk must leave out.
    fn expired_live(&self, now: u64) -> std::collections::HashSet<u64> {
        let mut expired = std::collections::HashSet::new();
        let hi = prefix(T_EXPIRY, &[&now.saturating_add(1).to_be_bytes()]);
        self.for_range(&[T_EXPIRY], &hi, |k| {
            let seq = seq_of(k);
            if self.is_live(seq) {
                expired.insert(seq);
            }
        });
        expired
    }

    fn walk(&self, filters: &[Filter], older_than: Option<u64>, now: u64, keys_only: Option<std::collections::HashSet<u64>>) -> Matching<'_> {
        let mut filters = filters.to_vec();
        if let Some(cutoff) = older_than {
            for f in &mut filters {
                match cutoff.checked_sub(1) {
                    Some(last) => f.until = Some(f.until.map_or(last, |u| u.min(last))),
                    // Nothing is older than the epoch: an inverted window matches nothing.
                    None => (f.since, f.until) = (Some(1), Some(0)),
                }
            }
        }
        let mut sources = Vec::with_capacity(filters.len());
        for f in &filters {
            let (feed, exact) = match self.plan(f) {
                Plan::Nothing => (Feed::List(Vec::new().into_iter()), true),
                Plan::Ids => {
                    let mut found = Vec::new();
                    for id in f.ids.as_deref().unwrap_or(&[]) {
                        let Some(seq) = self.lookup_id(id) else { continue };
                        let rec = self.record_unchecked(seq);
                        if f.matches(rec) {
                            found.push((rec.created_at(), seq));
                        }
                    }
                    found.sort_unstable_by(|a, b| b.cmp(a));
                    (Feed::List(found.into_iter()), true)
                }
                Plan::Scan { prefixes, exact } => {
                    (Feed::Scan(Merge::new(self, &prefixes, f.since.unwrap_or(0), f.until.unwrap_or(u64::MAX))), exact)
                }
            };
            let mut s = Source { feed, exact, last: u64::MAX, head: None };
            s.advance(self, f, now, keys_only.as_ref());
            sources.push(s);
        }
        Matching { v: self, now, filters, sources, keys_only }
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
                for r in self.runs_for(&p) {
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

    /// Number of matching events (NIP-45), exact.
    pub fn count(&self, f: &Filter, now: u64) -> u64 {
        self.count_all(std::slice::from_ref(f), now)
    }

    /// Exact NIP-45 COUNT of a union of filters: each event once, expired ones
    /// left out. A filter the index answers whole reads no record (about 50 ns
    /// a key: a million-wrap mailbox in ~50 ms); see [`count_cost`](Self::count_cost)
    /// to decide where to run a big one.
    pub fn count_all(&self, filters: &[Filter], now: u64) -> u64 {
        if let [f] = filters {
            if let Some(n) = self.count_by_keys(f, now) {
                return n;
            }
        }
        self.matching_seqs(filters, None, now).count() as u64
    }

    /// One filter the index answers whole, whose keys name each event at most
    /// once (one author, kind or author and kind per event; or a single prefix):
    /// counted run by run, range by range. The walk would merge every run's
    /// keys into order and drop repeats, which a count needs neither of.
    fn count_by_keys(&self, f: &Filter, now: u64) -> Option<u64> {
        let Plan::Scan { prefixes, exact: true } = self.plan(f) else { return None };
        let distinct = prefixes.len() == 1 || prefixes.iter().all(|p| matches!(p.first(), Some(&(T_AUTHOR | T_AUTHOR_KIND | T_KIND | T_CREATED))));
        if !distinct {
            return None;
        }
        let expired = self.expired_live(now);
        let (since, until) = (f.since.unwrap_or(0), f.until.unwrap_or(u64::MAX));
        let mut n = 0u64;
        for p in &prefixes {
            let (lo, hi) = bounds(p, since, until);
            for r in self.runs_for(p) {
                r.scan(&lo, &hi, Some(p), &mut |k| {
                    let seq = seq_of(k);
                    n += u64::from(self.is_live(seq) && !expired.contains(&seq));
                    true
                });
            }
        }
        Some(n)
    }

    /// Roughly how many index keys counting `filters` walks, from the block
    /// index alone (no block decoded).
    pub fn count_cost(&self, filters: &[Filter]) -> u64 {
        filters
            .iter()
            .map(|f| match self.plan(f) {
                Plan::Nothing => 0,
                Plan::Ids => f.ids.as_ref().map_or(0, |i| i.len() as u64),
                Plan::Scan { prefixes, .. } => self.estimate_all(&prefixes, f.since.unwrap_or(0), f.until.unwrap_or(u64::MAX)),
            })
            .sum()
    }
}

/// The walk [`Version::matching`] returns.
pub struct Matching<'a> {
    v: &'a Version,
    now: u64,
    filters: Vec<Filter>,
    sources: Vec<Source<'a>>,
    /// Set for a keys-only walk: the live events already expired.
    keys_only: Option<std::collections::HashSet<u64>>,
}

/// One filter's share of a [`Matching`] walk.
struct Source<'a> {
    feed: Feed<'a>,
    /// Every key in range matches the filter, so a record is read only to check expiry.
    exact: bool,
    /// The last seq taken from the feed: an event listed under several prefixes
    /// comes up once per prefix, side by side.
    last: u64,
    /// What this filter yields next, read ahead so the filters can be merged.
    head: Option<Hit>,
}

enum Feed<'a> {
    Scan(Merge<'a>),
    /// Already matched and ordered (an `ids` filter names a handful of events).
    List(std::vec::IntoIter<(u64, u64)>),
}

impl Source<'_> {
    /// Moves `head` to the next live, unexpired event the filter matches.
    fn advance(&mut self, v: &Version, f: &Filter, now: u64, keys_only: Option<&std::collections::HashSet<u64>>) {
        self.head = None;
        loop {
            let next = match &mut self.feed {
                Feed::Scan(m) => m.next(),
                Feed::List(l) => l.next(),
            };
            let Some((created_at, seq)) = next else { return };
            if seq == self.last {
                continue;
            }
            self.last = seq;
            if !v.is_live(seq) {
                continue;
            }
            if let Some(expired_now) = keys_only.filter(|_| self.exact) {
                if expired_now.contains(&seq) {
                    continue;
                }
                self.head = Some(Hit { created_at, seq, id: [0; 32] });
                return;
            }
            let rec = v.record_unchecked(seq);
            if expired(rec, now) || (!self.exact && !f.matches(rec)) {
                continue;
            }
            self.head = Some(Hit { created_at, seq, id: if keys_only.is_some() { [0; 32] } else { *rec.id() } });
            return;
        }
    }
}

impl Iterator for Matching<'_> {
    type Item = Hit;

    fn next(&mut self) -> Option<Hit> {
        let hit = self.sources.iter().filter_map(|s| s.head).max_by_key(|h| (h.created_at, h.seq))?;
        // Every filter that matched this event moves past it.
        for (s, f) in self.sources.iter_mut().zip(&self.filters) {
            if s.head.is_some_and(|h| h.seq == hit.seq) {
                s.advance(self.v, f, self.now, self.keys_only.as_ref());
            }
        }
        Some(hit)
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
            for run in v.runs_for(p) {
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

/// Merge output read a few entries ahead, for callers that read each entry's
/// record in turn. A record is two dependent cache misses away (its offset in
/// `locs`, then its bytes in the log), so one at a time the CPU mostly waits;
/// here an entry's offset is prefetched as it is pulled from the merge and its
/// record half a window later, so several are on their way at once. Repeats of
/// a seq in a row (an event under two of the merged prefixes) are dropped.
struct Ahead<'a> {
    v: &'a Version,
    merge: Merge<'a>,
    ring: [(u64, u64); AHEAD],
    head: usize,
    len: usize,
    last: u64,
    done: bool,
}

/// Entries in flight: offsets for the newer half, records for the older.
const AHEAD: usize = 8;

impl<'a> Ahead<'a> {
    fn new(v: &'a Version, merge: Merge<'a>) -> Ahead<'a> {
        Ahead { v, merge, ring: [(0, 0); AHEAD], head: 0, len: 0, last: u64::MAX, done: false }
    }

    #[inline]
    fn at(&self, i: usize) -> (u64, u64) {
        self.ring[(self.head + i) % AHEAD]
    }
}

impl Iterator for Ahead<'_> {
    type Item = (u64, u64);

    /// `(created_at, seq)`, in the merge's order. An entry at position `p` of
    /// the window has had its record prefetched exactly when
    /// `p < len - AHEAD / 2`.
    #[inline]
    fn next(&mut self) -> Option<(u64, u64)> {
        while !self.done && self.len < AHEAD {
            match self.merge.next() {
                Some((ca, seq)) => {
                    if seq == self.last {
                        continue;
                    }
                    self.last = seq;
                    self.v.prefetch_loc(seq);
                    self.ring[(self.head + self.len) % AHEAD] = (ca, seq);
                    self.len += 1;
                    if self.len > AHEAD / 2 {
                        self.v.prefetch_record(self.at(self.len - 1 - AHEAD / 2).1);
                    }
                }
                None => {
                    self.done = true;
                    // The newer half will not reach the record step on its own.
                    for i in self.len.saturating_sub(AHEAD / 2)..self.len {
                        self.v.prefetch_record(self.at(i).1);
                    }
                }
            }
        }
        if self.len == 0 {
            return None;
        }
        let e = self.at(0);
        self.head = (self.head + 1) % AHEAD;
        self.len -= 1;
        Some(e)
    }
}

#[inline]
fn suffix(key: &[u8]) -> u128 {
    (u128::from(keys::created_at_of(key)) << 64) | u128::from(keys::seq_of(key))
}
