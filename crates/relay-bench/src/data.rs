//! The reference answers: the dataset file scanned into memory once, plus the
//! indexes needed to compute what any filter *must* return.
//!
//! Only what the checks need is kept per event (id, pubkey, kind, `created_at`;
//! the 1-2 KB contents are skipped), 72 bytes per event, so 5M events fit in well
//! under a gigabyte with their indexes. The answer to a filter is computed here, by
//! plain code that shares nothing with any relay, following NIP-01 literally:
//! match, sort `created_at` descending with ties **lowest id first**, truncate to
//! `limit`.
//!
//! Replaceable (0, 3, 10000-19999) and addressable (30000-39999, by `d` tag) kinds
//! are resolved at scan time: only the winning version of each key is live, because
//! that is what a relay holding the whole file serves afterwards. A newer
//! `created_at` wins; on a tie the lowest id does (NIP-01).

use crate::jsonw::Json;
use crate::wire::parse_event_line;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Instant;

pub const GIFT_WRAP: u32 = 1059;

/// What the checks keep of a live event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub id: [u8; 32],
    pub pk: [u8; 32],
    pub ts: u32,
    pub kind: u32,
}

/// A REQ/COUNT filter, built by workloads, rendered to JSON for the relay and
/// evaluated against the dataset for the expected answer: one definition of "what
/// this filter means", used on both sides of the comparison.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FilterSpec {
    pub ids: Vec<[u8; 32]>,
    pub authors: Vec<[u8; 32]>,
    pub kinds: Vec<u32>,
    /// `#p` values.
    pub p: Vec<[u8; 32]>,
    /// `#t` values.
    pub t: Vec<String>,
    /// Inclusive.
    pub since: Option<u32>,
    /// Inclusive.
    pub until: Option<u32>,
    pub limit: Option<usize>,
}

impl FilterSpec {
    pub fn to_json(&self) -> String {
        let hexes = |v: &[[u8; 32]]| Json::Arr(v.iter().map(|b| Json::Str(relay_proto::hex::encode_string(b))).collect());
        let mut o = Json::obj();
        if !self.ids.is_empty() {
            o = o.with("ids", hexes(&self.ids));
        }
        if !self.authors.is_empty() {
            o = o.with("authors", hexes(&self.authors));
        }
        if !self.kinds.is_empty() {
            o = o.with("kinds", self.kinds.clone());
        }
        if !self.p.is_empty() {
            o = o.with("#p", hexes(&self.p));
        }
        if !self.t.is_empty() {
            o = o.with("#t", self.t.clone());
        }
        if let Some(s) = self.since {
            o = o.with("since", s);
        }
        if let Some(u) = self.until {
            o = o.with("until", u);
        }
        if let Some(l) = self.limit {
            o = o.with("limit", l);
        }
        o.render()
    }
}

/// FNV-1a, 64-bit: the `d`-tag identity of an addressable event while scanning.
pub fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[inline]
fn id8(id: &[u8; 32]) -> u64 {
    u64::from_be_bytes(id[..8].try_into().unwrap())
}

/// `v` is sorted by `.0`: the run with key `k`.
fn run_u64(v: &[(u64, u32)], k: u64) -> &[(u64, u32)] {
    let lo = v.partition_point(|e| e.0 < k);
    let hi = v[lo..].partition_point(|e| e.0 == k);
    &v[lo..lo + hi]
}

fn run_u32(v: &[(u32, u32)], k: u32) -> &[(u32, u32)] {
    let lo = v.partition_point(|e| e.0 < k);
    let hi = v[lo..].partition_point(|e| e.0 == k);
    &v[lo..lo + hi]
}

pub struct Dataset {
    /// Live events, in file order.
    pub events: Vec<Meta>,
    /// Lines read from the file.
    pub lines: u64,
    /// Replaceable/addressable versions that lost to a newer one.
    pub superseded: u64,
    pub min_ts: u32,
    pub max_ts: u32,
    /// Wrapping sum of every live event id's first 8 bytes: a cheap identity for "the
    /// same dataset", recorded in every result so runs against different relays can be
    /// checked to have used the same data.
    pub fingerprint: u64,
    recips: Vec<[u8; 32]>,
    recip_ix: HashMap<[u8; 32], u32>,
    words: Vec<String>,
    word_ix: HashMap<String, u32>,
    by_id: Vec<(u64, u32)>,
    by_pk: Vec<(u64, u32)>,
    /// (interned `p` value, event) for every distinct `p` tag.
    by_p: Vec<(u32, u32)>,
    by_t: Vec<(u32, u32)>,
    by_kind: Vec<(u32, u32)>,
}

impl Dataset {
    pub fn load(path: &Path, progress: bool) -> Result<Dataset, String> {
        let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Dataset::from_reader(BufReader::with_capacity(1 << 20, f), progress).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn from_reader<R: BufRead>(mut r: R, progress: bool) -> Result<Dataset, String> {
        let started = Instant::now();
        let mut metas: Vec<Meta> = Vec::new();
        let mut pairs_p: Vec<(u32, u32)> = Vec::new();
        let mut pairs_t: Vec<(u32, u32)> = Vec::new();
        let mut recips: Vec<[u8; 32]> = Vec::new();
        let mut recip_ix: HashMap<[u8; 32], u32> = HashMap::new();
        let mut words: Vec<String> = Vec::new();
        let mut word_ix: HashMap<String, u32> = HashMap::new();
        // (pubkey, kind, d-hash) -> current winner.
        let mut winners: HashMap<([u8; 32], u32, u64), u32> = HashMap::new();
        let mut dead: HashSet<u32> = HashSet::new();
        let mut buf = Vec::new();
        let mut lines = 0u64;
        let mut last_report = Instant::now();
        loop {
            buf.clear();
            if r.read_until(b'\n', &mut buf).map_err(|e| e.to_string())? == 0 {
                break;
            }
            lines += 1;
            while matches!(buf.last(), Some(b'\n' | b'\r')) {
                buf.pop();
            }
            if buf.is_empty() {
                continue;
            }
            let text = std::str::from_utf8(&buf).map_err(|_| format!("line {lines}: not UTF-8"))?;
            let e = parse_event_line(text).map_err(|m| format!("line {lines}: {m}"))?;
            let (Ok(ts), Ok(kind)) = (u32::try_from(e.created_at), u32::try_from(e.kind)) else {
                return Err(format!("line {lines}: created_at or kind out of range"));
            };
            let idx = u32::try_from(metas.len()).map_err(|_| "more than 4 billion events".to_string())?;
            for p in &e.p {
                let ix = *recip_ix.entry(*p).or_insert_with(|| {
                    recips.push(*p);
                    (recips.len() - 1) as u32
                });
                pairs_p.push((ix, idx));
            }
            for t in &e.t {
                let ix = match word_ix.get(t.as_ref()) {
                    Some(&ix) => ix,
                    None => {
                        words.push(t.to_string());
                        word_ix.insert(t.to_string(), (words.len() - 1) as u32);
                        (words.len() - 1) as u32
                    }
                };
                pairs_t.push((ix, idx));
            }
            let class = if kind == 0 || kind == 3 || (10_000..20_000).contains(&kind) {
                Some(0)
            } else if (30_000..40_000).contains(&kind) {
                Some(fnv64(e.d.as_deref().unwrap_or("")))
            } else {
                None
            };
            let meta = Meta { id: e.id, pk: e.pubkey, ts, kind };
            if let Some(d) = class {
                match winners.entry((e.pubkey, kind, d)) {
                    Entry::Vacant(v) => {
                        v.insert(idx);
                    }
                    Entry::Occupied(mut o) => {
                        let cur = &metas[*o.get() as usize];
                        // Newer wins; the same second, the lower id.
                        if (ts, std::cmp::Reverse(e.id)) > (cur.ts, std::cmp::Reverse(cur.id)) {
                            dead.insert(*o.get());
                            o.insert(idx);
                        } else {
                            dead.insert(idx);
                        }
                    }
                }
            }
            metas.push(meta);
            if progress && last_report.elapsed().as_secs() >= 5 {
                last_report = Instant::now();
                eprintln!("  scanned {lines} events...");
            }
        }
        if metas.is_empty() {
            return Err("no events".into());
        }
        let superseded = dead.len() as u64;
        // Drop the losers, and remap event numbers in the tag pairs.
        let mut remap = vec![u32::MAX; metas.len()];
        let mut live = 0u32;
        for (i, slot) in remap.iter_mut().enumerate() {
            if !dead.contains(&(i as u32)) {
                *slot = live;
                live += 1;
            }
        }
        if superseded > 0 {
            let mut i = 0usize;
            metas.retain(|_| {
                let keep = remap[i] != u32::MAX;
                i += 1;
                keep
            });
            for pairs in [&mut pairs_p, &mut pairs_t] {
                pairs.retain(|e| remap[e.1 as usize] != u32::MAX);
                for e in pairs.iter_mut() {
                    e.1 = remap[e.1 as usize];
                }
            }
        }
        drop(remap);

        let mut by_id: Vec<(u64, u32)> = metas.iter().enumerate().map(|(i, m)| (id8(&m.id), i as u32)).collect();
        by_id.sort_unstable();
        // Two events with one id would make every answer ambiguous.
        for w in by_id.windows(2) {
            if w[0].0 == w[1].0 && metas[w[0].1 as usize].id == metas[w[1].1 as usize].id {
                return Err(format!("duplicate event id {}", relay_proto::hex::encode_string(&metas[w[0].1 as usize].id)));
            }
        }
        let mut by_pk: Vec<(u64, u32)> = metas.iter().enumerate().map(|(i, m)| (id8(&m.pk), i as u32)).collect();
        by_pk.sort_unstable();
        let mut by_kind: Vec<(u32, u32)> = metas.iter().enumerate().map(|(i, m)| (m.kind, i as u32)).collect();
        by_kind.sort_unstable();
        pairs_p.sort_unstable();
        pairs_p.dedup();
        pairs_t.sort_unstable();
        pairs_t.dedup();
        let (min_ts, max_ts) = metas.iter().fold((u32::MAX, 0), |(lo, hi), m| (lo.min(m.ts), hi.max(m.ts)));
        let fingerprint = metas.iter().fold(0u64, |a, m| a.wrapping_add(id8(&m.id)));
        if progress {
            eprintln!(
                "  scanned {lines} lines, {} live events ({superseded} superseded versions dropped) in {:.1}s",
                metas.len(),
                started.elapsed().as_secs_f64()
            );
        }
        Ok(Dataset { events: metas, lines, superseded, min_ts, max_ts, fingerprint, recips, recip_ix, words, word_ix, by_id, by_pk, by_p: pairs_p, by_t: pairs_t, by_kind })
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn lookup_id(&self, id: &[u8; 32]) -> Option<u32> {
        run_u64(&self.by_id, id8(id)).iter().map(|e| e.1).find(|&i| &self.events[i as usize].id == id)
    }

    /// Mailboxes (distinct `p` values) of gift wraps with their sizes, biggest first;
    /// ties by value so the order is stable.
    pub fn wrap_mailboxes(&self) -> Vec<([u8; 32], u32)> {
        let mut out: Vec<([u8; 32], u32)> = Vec::new();
        let mut i = 0;
        while i < self.by_p.len() {
            let r = self.by_p[i].0;
            let mut n = 0;
            while i < self.by_p.len() && self.by_p[i].0 == r {
                if self.events[self.by_p[i].1 as usize].kind == GIFT_WRAP {
                    n += 1;
                }
                i += 1;
            }
            if n > 0 {
                out.push((self.recips[r as usize], n));
            }
        }
        out.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }

    /// Authors all of whose live events are of `kind`, with at least `min` of them,
    /// biggest first. Plane keys for `kind` 1059: single-use wrap authors have one
    /// event each and generic authors never publish wraps, so neither shows up.
    pub fn pure_authors(&self, kind: u32, min: u32) -> Vec<([u8; 32], u32)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.by_pk.len() {
            let k = self.by_pk[i].0;
            let start = i;
            while i < self.by_pk.len() && self.by_pk[i].0 == k {
                i += 1;
            }
            let group = &self.by_pk[start..i];
            let pk = self.events[group[0].1 as usize].pk;
            let n = group.iter().filter(|e| self.events[e.1 as usize].pk == pk && self.events[e.1 as usize].kind == kind).count();
            if n as u32 >= min && n == group.len() {
                out.push((pk, n as u32));
            }
        }
        out.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }

    /// Up to `n` distinct `t` tag values, drawn at random in proportion to how often
    /// they occur (so popular tags are queried more, as in real use).
    pub fn sample_words(&self, rng: &mut crate::rng::Rng, n: usize) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if self.by_t.is_empty() {
            return out;
        }
        for _ in 0..n.saturating_mul(20) {
            let w = &self.words[self.by_t[rng.below(self.by_t.len() as u64) as usize].0 as usize];
            if !out.contains(w) {
                out.push(w.clone());
                if out.len() == n {
                    break;
                }
            }
        }
        out
    }

    /// (kind, live events) pairs, most common first.
    pub fn kind_counts(&self) -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> = Vec::new();
        for e in &self.by_kind {
            match out.last_mut() {
                Some(last) if last.0 == e.0 => last.1 += 1,
                _ => out.push((e.0, 1)),
            }
        }
        out.sort_unstable_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }

    fn accepts(&self, i: u32, f: &FilterSpec, recips: &[u32], words: &[u32]) -> bool {
        let m = &self.events[i as usize];
        if f.since.is_some_and(|s| m.ts < s) || f.until.is_some_and(|u| m.ts > u) {
            return false;
        }
        (f.kinds.is_empty() || f.kinds.contains(&m.kind))
            && (f.authors.is_empty() || f.authors.contains(&m.pk))
            && (f.ids.is_empty() || f.ids.contains(&m.id))
            && (f.p.is_empty() || recips.iter().any(|&r| self.by_p.binary_search(&(r, i)).is_ok()))
            && (f.t.is_empty() || words.iter().any(|&w| self.by_t.binary_search(&(w, i)).is_ok()))
    }

    /// Every live event the filter matches (its `limit` ignored), `created_at`
    /// descending, ties lowest id first.
    pub fn matching(&self, f: &FilterSpec) -> Vec<u32> {
        let recips: Vec<u32> = f.p.iter().filter_map(|p| self.recip_ix.get(p).copied()).collect();
        let words: Vec<u32> = f.t.iter().filter_map(|w| self.word_ix.get(w).copied()).collect();
        if (!f.p.is_empty() && recips.is_empty()) || (!f.t.is_empty() && words.is_empty()) {
            return Vec::new();
        }
        // The narrowest index the filter can use; the rest is checked per candidate.
        let mut best: (usize, u8) = (self.events.len(), 0);
        let mut consider = |size: usize, source: u8| {
            if size < best.0 || (size == best.0 && best.1 == 0) {
                best = (size, source);
            }
        };
        if !f.ids.is_empty() {
            consider(f.ids.len(), 1);
        }
        if !f.p.is_empty() {
            consider(recips.iter().map(|&r| run_u32(&self.by_p, r).len()).sum(), 2);
        }
        if !f.authors.is_empty() {
            consider(f.authors.iter().map(|a| run_u64(&self.by_pk, id8(a)).len()).sum(), 3);
        }
        if !f.t.is_empty() {
            consider(words.iter().map(|&w| run_u32(&self.by_t, w).len()).sum(), 4);
        }
        if !f.kinds.is_empty() {
            consider(f.kinds.iter().map(|&k| run_u32(&self.by_kind, k).len()).sum(), 5);
        }
        let mut cand: Vec<u32> = match best.1 {
            1 => f.ids.iter().filter_map(|id| self.lookup_id(id)).collect(),
            2 => recips.iter().flat_map(|&r| run_u32(&self.by_p, r).iter().map(|e| e.1)).collect(),
            3 => f.authors.iter().flat_map(|a| run_u64(&self.by_pk, id8(a)).iter().map(|e| e.1)).collect(),
            4 => words.iter().flat_map(|&w| run_u32(&self.by_t, w).iter().map(|e| e.1)).collect(),
            5 => f.kinds.iter().flat_map(|&k| run_u32(&self.by_kind, k).iter().map(|e| e.1)).collect(),
            _ => (0..self.events.len() as u32).collect(),
        };
        // Union sources (several recipients, ids listed twice) can repeat an event.
        cand.sort_unstable();
        cand.dedup();
        cand.retain(|&i| self.accepts(i, f, &recips, &words));
        cand.sort_unstable_by(|&a, &b| {
            let (ma, mb) = (&self.events[a as usize], &self.events[b as usize]);
            mb.ts.cmp(&ma.ts).then_with(|| ma.id.cmp(&mb.id))
        });
        cand
    }

    /// What a correct relay must answer for a REQ with these filters.
    pub fn expected(&self, filters: &[FilterSpec]) -> Expected {
        let mut ex = Expected { single: filters.len() == 1, ..Expected::default() };
        for f in filters {
            let all = self.matching(f);
            let take = f.limit.map_or(all.len(), |l| l.min(all.len()));
            for &i in &all[..take] {
                let m = &self.events[i as usize];
                if ex.want.insert(m.id, m.ts).is_none() && ex.single {
                    ex.order.push(m.id);
                }
            }
            // A limit that cuts through a same-second group leaves several equally valid
            // answers (NIP-01 says lowest id first, strfry serves insertion order). Record the
            // whole group at the cut so only genuinely wrong answers are failures.
            if take > 0 && take < all.len() {
                let cut = self.events[all[take - 1] as usize].ts;
                let mut tied = false;
                for &i in &all[take..] {
                    let m = &self.events[i as usize];
                    if m.ts != cut {
                        break;
                    }
                    tied = true;
                    if !ex.want.contains_key(&m.id) {
                        ex.extra.insert(m.id);
                    }
                }
                if tied && !ex.subst_secs.contains(&cut) {
                    ex.subst_secs.push(cut);
                }
            }
        }
        ex.total = ex.want.len() as u64;
        ex
    }

    /// What a correct relay must answer for a COUNT: every match, `limit` ignored.
    pub fn count(&self, f: &FilterSpec) -> u64 {
        self.matching(f).len() as u64
    }

    /// One-paragraph summary for the report header.
    pub fn describe(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "{} live events ({} lines, {} superseded), created_at {}..{}, fingerprint {:016x}",
            self.len(),
            self.lines,
            self.superseded,
            self.min_ts,
            self.max_ts,
            self.fingerprint
        );
        let kinds = self.kind_counts();
        let _ = write!(s, "; kinds:");
        for (k, n) in kinds.iter().take(6) {
            let _ = write!(s, " {k}x{n}");
        }
        s
    }
}

/// The correct answer to a REQ, as a checker needs it.
#[derive(Default, Debug)]
pub struct Expected {
    /// One filter: results must also be in NIP-01 order.
    pub single: bool,
    /// The exact NIP-01 answer in order (single filter only).
    pub order: Vec<[u8; 32]>,
    /// The answer as id -> `created_at`.
    pub want: HashMap<[u8; 32], u32>,
    /// Events that may legitimately replace members of `want` because a `limit` cut
    /// through their second.
    pub extra: HashSet<[u8; 32]>,
    /// The seconds at which such a cut happened.
    pub subst_secs: Vec<u32>,
    /// The number of distinct events in `want`.
    pub total: u64,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Cursor;

    pub fn hx(n: u16) -> String {
        format!("{n:04x}{}", "0".repeat(60))
    }

    pub fn id(n: u16) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..2].copy_from_slice(&n.to_be_bytes());
        b
    }

    /// An event line with the given identity; ids are `hx(n)`, authors `hx(1000 + a)`.
    pub fn line(n: u16, author: u16, ts: u64, kind: u64, tags: &[&[&str]]) -> String {
        let mut t = String::from("[");
        for tag in tags {
            crate::sign::push_tag(&mut t, tag);
        }
        t.push(']');
        format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":{ts},"kind":{kind},"tags":{t},"content":"x","sig":"{}"}}"#,
            hx(n),
            hx(1000 + author),
            "0".repeat(128)
        )
    }

    pub fn dataset(lines: &[String]) -> Dataset {
        Dataset::from_reader(Cursor::new(lines.join("\n")), false).unwrap()
    }

    fn ids(ds: &Dataset, idx: &[u32]) -> Vec<u16> {
        idx.iter().map(|&i| u16::from_be_bytes([ds.events[i as usize].id[0], ds.events[i as usize].id[1]])).collect()
    }

    #[test]
    fn order_is_newest_first_and_ties_lowest_id_first() {
        let ds = dataset(&[
            line(5, 1, 100, 1, &[]),
            line(3, 1, 200, 1, &[]),
            line(9, 1, 200, 1, &[]),
            line(1, 1, 200, 1, &[]),
            line(2, 1, 50, 1, &[]),
        ]);
        let f = FilterSpec { kinds: vec![1], ..Default::default() };
        assert_eq!(ids(&ds, &ds.matching(&f)), vec![1, 3, 9, 5, 2]);
    }

    #[test]
    fn limit_truncates_and_records_the_tied_group_at_the_cut() {
        let ds = dataset(&[
            line(4, 1, 300, 1, &[]),
            line(1, 1, 200, 1, &[]),
            line(2, 1, 200, 1, &[]),
            line(3, 1, 200, 1, &[]),
            line(7, 1, 100, 1, &[]),
        ]);
        let ex = ds.expected(&[FilterSpec { kinds: vec![1], limit: Some(2), ..Default::default() }]);
        assert_eq!(ex.order, vec![id(4), id(1)]);
        assert_eq!(ex.want.len(), 2);
        assert_eq!(ex.extra, HashSet::from([id(2), id(3)]));
        assert_eq!(ex.subst_secs, vec![200]);
        // A cut between seconds leaves no ambiguity.
        let ex = ds.expected(&[FilterSpec { kinds: vec![1], limit: Some(4), ..Default::default() }]);
        assert_eq!(ex.order, vec![id(4), id(1), id(2), id(3)]);
        assert!(ex.extra.is_empty() && ex.subst_secs.is_empty());
        // Nothing cut: nothing ambiguous.
        let ex = ds.expected(&[FilterSpec { kinds: vec![1], limit: Some(50), ..Default::default() }]);
        assert_eq!(ex.want.len(), 5);
        assert!(ex.extra.is_empty());
    }

    #[test]
    fn since_and_until_are_inclusive() {
        let ds = dataset(&[line(1, 1, 99, 1, &[]), line(2, 1, 100, 1, &[]), line(3, 1, 150, 1, &[]), line(4, 1, 200, 1, &[]), line(5, 1, 201, 1, &[])]);
        let f = FilterSpec { since: Some(100), until: Some(200), ..Default::default() };
        assert_eq!(ids(&ds, &ds.matching(&f)), vec![4, 3, 2]);
    }

    #[test]
    fn tag_filters_match_any_tag_of_the_name() {
        let r1 = hx(0xa1);
        let r2 = hx(0xa2);
        let ds = dataset(&[
            line(1, 1, 10, 1059, &[&["p", &r1]]),
            line(2, 2, 20, 1059, &[&["p", &r2], &["p", &r1]]),
            line(3, 3, 30, 1, &[&["t", "rust"], &["t", "nostr"]]),
            line(4, 3, 40, 1, &[&["t", "nostr"]]),
        ]);
        let mut a1 = [0u8; 32];
        a1[..2].copy_from_slice(&0xa1u16.to_be_bytes());
        let f = FilterSpec { kinds: vec![1059], p: vec![a1], ..Default::default() };
        assert_eq!(ids(&ds, &ds.matching(&f)), vec![2, 1]);
        let f = FilterSpec { t: vec!["rust".into()], ..Default::default() };
        assert_eq!(ids(&ds, &ds.matching(&f)), vec![3]);
        let f = FilterSpec { t: vec!["nostr".into()], ..Default::default() };
        assert_eq!(ids(&ds, &ds.matching(&f)), vec![4, 3]);
        let f = FilterSpec { t: vec!["unknown".into()], ..Default::default() };
        assert!(ds.matching(&f).is_empty());
        // Combined: author and tag together use one index and check the other.
        let f = FilterSpec { authors: vec![id(1003)], t: vec!["rust".into()], ..Default::default() };
        assert_eq!(ids(&ds, &ds.matching(&f)), vec![3]);
        let f = FilterSpec { authors: vec![id(1001)], t: vec!["rust".into()], ..Default::default() };
        assert!(ds.matching(&f).is_empty());
    }

    #[test]
    fn replaceable_and_addressable_keep_only_the_winner() {
        let ds = dataset(&[
            line(1, 1, 100, 0, &[]),
            line(2, 1, 300, 0, &[]),
            line(3, 1, 200, 0, &[]),
            // Same second: the lower id wins whatever the arrival order.
            line(9, 2, 500, 10050, &[]),
            line(8, 2, 500, 10050, &[]),
            // Addressable: one winner per d.
            line(10, 3, 100, 30078, &[&["d", "a"]]),
            line(11, 3, 200, 30078, &[&["d", "a"]]),
            line(12, 3, 150, 30078, &[&["d", "b"]]),
            // Regular events are never replaced.
            line(20, 1, 100, 1, &[]),
            line(21, 1, 100, 1, &[]),
        ]);
        assert_eq!(ds.superseded, 4);
        let live: HashSet<u16> = ids(&ds, &(0..ds.len() as u32).collect::<Vec<_>>()).into_iter().collect();
        assert_eq!(live, HashSet::from([2, 8, 11, 12, 20, 21]));
        assert_eq!(ds.len(), 6);
        // Queries never see a superseded event, by id either.
        assert!(ds.lookup_id(&id(1)).is_none());
        assert!(ds.lookup_id(&id(2)).is_some());
        // Tag pairs follow the remapped numbers.
        let ds = dataset(&[line(1, 1, 100, 0, &[&["t", "x"]]), line(2, 1, 200, 0, &[&["t", "y"]]), line(3, 2, 50, 1, &[&["t", "x"]])]);
        let f = FilterSpec { t: vec!["x".into()], ..Default::default() };
        assert_eq!(ids(&ds, &ds.matching(&f)), vec![3]);
    }

    #[test]
    fn ids_and_multi_filter_union() {
        let ds = dataset(&[line(1, 1, 10, 1, &[]), line(2, 2, 20, 1, &[]), line(3, 2, 30, 7, &[]), line(4, 3, 40, 7, &[])]);
        let f = FilterSpec { ids: vec![id(2), id(2), id(99)], ..Default::default() };
        assert_eq!(ids(&ds, &ds.matching(&f)), vec![2]);
        let fs = [
            FilterSpec { authors: vec![id(1002)], ..Default::default() },
            FilterSpec { kinds: vec![7], limit: Some(1), ..Default::default() },
        ];
        let ex = ds.expected(&fs);
        assert!(!ex.single);
        assert_eq!(ex.want.len(), 3, "events 3 and 2 from the author, 4 from the kind filter; 3 is in both");
        assert!(ex.want.contains_key(&id(4)) && ex.want.contains_key(&id(3)) && ex.want.contains_key(&id(2)));
        assert_eq!(ex.total, 3);
        // An id filter combined with a kind it does not have matches nothing.
        let f = FilterSpec { ids: vec![id(1)], kinds: vec![7], ..Default::default() };
        assert!(ds.matching(&f).is_empty());
    }

    #[test]
    fn mailbox_and_plane_discovery() {
        let r = hx(0xb1);
        let mut lines = Vec::new();
        for i in 0..5u16 {
            lines.push(line(i + 1, 50 + i, 100 + u64::from(i), 1059, &[&["p", &r]]));
        }
        for i in 0..4u16 {
            lines.push(line(20 + i, 7, 200 + u64::from(i), 1059, &[&["p", &hx(0xc0 + i)]]));
        }
        lines.push(line(40, 8, 300, 1, &[]));
        lines.push(line(41, 8, 301, 1059, &[]));
        let ds = dataset(&lines);
        let boxes = ds.wrap_mailboxes();
        assert_eq!((boxes[0].1, boxes.len()), (5, 5));
        let planes = ds.pure_authors(1059, 2);
        assert_eq!(planes.len(), 1, "author 7 only: single-use authors and the mixed-kind author 8 are excluded");
        assert_eq!(planes[0].1, 4);
        assert_eq!(ds.kind_counts()[0], (1059, 10));
    }

    #[test]
    fn filter_json_is_valid_and_complete() {
        let f = FilterSpec {
            ids: vec![id(1)],
            authors: vec![id(2)],
            kinds: vec![1059, 21059],
            p: vec![id(3)],
            t: vec!["a\"b".into()],
            since: Some(5),
            until: Some(9),
            limit: Some(500),
        };
        let j = f.to_json();
        assert_eq!(
            j,
            format!(
                r##"{{"ids":["{}"],"authors":["{}"],"kinds":[1059,21059],"#p":["{}"],"#t":["a\"b"],"since":5,"until":9,"limit":500}}"##,
                hx(1),
                hx(2),
                hx(3)
            )
        );
        assert_eq!(FilterSpec::default().to_json(), "{}");
    }

    #[test]
    fn fingerprint_identifies_the_live_set() {
        let a = dataset(&[line(1, 1, 10, 1, &[]), line(2, 1, 11, 1, &[])]);
        let b = dataset(&[line(2, 1, 11, 1, &[]), line(1, 1, 10, 1, &[])]);
        let c = dataset(&[line(1, 1, 10, 1, &[]), line(3, 1, 11, 1, &[])]);
        assert_eq!(a.fingerprint, b.fingerprint, "order does not matter");
        assert_ne!(a.fingerprint, c.fingerprint);
        // A superseded version is not live, so it does not count.
        let d = dataset(&[line(1, 1, 10, 0, &[]), line(2, 1, 11, 0, &[])]);
        let e = dataset(&[line(2, 1, 11, 0, &[])]);
        assert_eq!(d.fingerprint, e.fingerprint);
    }

    #[test]
    fn rejects_damaged_files() {
        let e = |text: &str| Dataset::from_reader(Cursor::new(text.to_owned()), false).err().expect("should fail");
        assert!(e("").contains("no events"));
        assert!(e("not json\n").contains("line 1"));
        let dup = [line(1, 1, 10, 1, &[]), line(1, 2, 11, 1, &[])].join("\n");
        assert!(e(&dup).contains("duplicate event id"));
    }
}
