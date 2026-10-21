//! Live subscriptions: which open REQs a new event must go to.
//!
//! Each filter is filed under exactly one of its most selective keys (its ids,
//! else its authors, else its smallest tag list, else its kinds, else "all").
//! An event looks up only its own id, pubkey, tags and kind, then fully matches
//! the handful of filters found there. A Concord live REQ with hundreds of plane
//! authors therefore costs one hash probe per event, not a scan of every filter.
//!
//! One index per reactor; nothing here is shared or locked.

use relay_proto::{Filter, Record};
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::Arc;

pub type ConnId = u64;

/// A fast non-cryptographic hasher (FxHash). Keys are pubkeys, ids and tag
/// values chosen by clients; flooding one bucket only slows that client's own
/// filters, and every list is bounded by the subscription limits.
#[derive(Default)]
pub struct FxHasher(u64);

impl Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const K: u64 = 0x51_7c_c1_b7_27_22_0a_95;
        let mut h = self.0;
        let mut chunks = bytes.chunks_exact(8);
        for c in &mut chunks {
            h = (h.rotate_left(5) ^ u64::from_le_bytes(c.try_into().unwrap())).wrapping_mul(K);
        }
        for &b in chunks.remainder() {
            h = (h.rotate_left(5) ^ u64::from(b)).wrapping_mul(K);
        }
        self.0 = h;
    }

    #[inline]
    fn write_u64(&mut self, v: u64) {
        self.0 = (self.0.rotate_left(5) ^ v).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
}

pub type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<FxHasher>>;

#[derive(Clone, PartialEq, Eq, Hash)]
enum Slot {
    Id([u8; 32]),
    Author([u8; 32]),
    /// Tag name followed by the encoded value.
    Tag(Box<[u8]>),
    Kind(u64),
    All,
}

struct Entry {
    conn: ConnId,
    sub: Arc<str>,
    filter: Filter,
    slots: Vec<Slot>,
    /// Store generation the REQ's stored results were read at: batches up to
    /// it are already answered, so live delivery starts after it.
    gen: u64,
}

#[derive(Default)]
pub struct SubIndex {
    entries: Vec<Option<Entry>>,
    free: Vec<u32>,
    by_id: FxMap<[u8; 32], Vec<u32>>,
    by_author: FxMap<[u8; 32], Vec<u32>>,
    by_tag: FxMap<Box<[u8]>, Vec<u32>>,
    by_kind: FxMap<u64, Vec<u32>>,
    all: Vec<u32>,
    /// Filter entries per (connection, subscription id).
    subs: FxMap<ConnId, FxMap<Arc<str>, Vec<u32>>>,
    scratch: Vec<u32>,
}

impl SubIndex {
    /// Number of open subscriptions on `conn`.
    pub fn count(&self, conn: ConnId) -> usize {
        self.subs.get(&conn).map_or(0, |m| m.len())
    }

    /// Total filters registered.
    #[allow(dead_code)] // for metrics
    pub fn filters(&self) -> usize {
        self.entries.len() - self.free.len()
    }

    /// Opens (or replaces) subscription `sub` on `conn`, live from after store
    /// generation `gen`.
    pub fn add(&mut self, conn: ConnId, sub: &str, filters: Vec<Filter>, gen: u64) {
        self.remove(conn, sub);
        let sub: Arc<str> = Arc::from(sub);
        let mut ids = Vec::with_capacity(filters.len());
        for f in filters {
            if f.never_matches() {
                continue;
            }
            let slots = slots_for(&f);
            let e = Entry { conn, sub: sub.clone(), filter: f, slots, gen };
            let i = match self.free.pop() {
                Some(i) => {
                    self.entries[i as usize] = Some(e);
                    i
                }
                None => {
                    self.entries.push(Some(e));
                    (self.entries.len() - 1) as u32
                }
            };
            for s in self.entries[i as usize].as_ref().unwrap().slots.clone() {
                self.list(&s).push(i);
            }
            ids.push(i);
        }
        // Registered even with no live filters, so it counts against the limit
        // and CLOSE finds it.
        self.subs.entry(conn).or_default().insert(sub, ids);
    }

    pub fn remove(&mut self, conn: ConnId, sub: &str) -> bool {
        let Some(m) = self.subs.get_mut(&conn) else { return false };
        let Some(ids) = m.remove(sub) else { return false };
        if m.is_empty() {
            self.subs.remove(&conn);
        }
        for i in ids {
            self.drop_entry(i);
        }
        true
    }

    pub fn remove_conn(&mut self, conn: ConnId) {
        let Some(m) = self.subs.remove(&conn) else { return };
        for (_, ids) in m {
            for i in ids {
                self.drop_entry(i);
            }
        }
    }

    fn drop_entry(&mut self, i: u32) {
        let Some(e) = self.entries[i as usize].take() else { return };
        for s in &e.slots {
            let empty = {
                let l = self.list(s);
                if let Some(p) = l.iter().position(|&x| x == i) {
                    l.swap_remove(p);
                }
                l.is_empty()
            };
            if empty {
                match s {
                    Slot::Id(k) => {
                        self.by_id.remove(k);
                    }
                    Slot::Author(k) => {
                        self.by_author.remove(k);
                    }
                    Slot::Tag(k) => {
                        self.by_tag.remove(k);
                    }
                    Slot::Kind(k) => {
                        self.by_kind.remove(k);
                    }
                    Slot::All => {}
                }
            }
        }
        self.free.push(i);
    }

    fn list(&mut self, s: &Slot) -> &mut Vec<u32> {
        match s {
            Slot::Id(k) => self.by_id.entry(*k).or_default(),
            Slot::Author(k) => self.by_author.entry(*k).or_default(),
            Slot::Tag(k) => self.by_tag.entry(k.clone()).or_default(),
            Slot::Kind(k) => self.by_kind.entry(*k).or_default(),
            Slot::All => &mut self.all,
        }
    }

    /// Every (connection, subscription) the event must be sent to, each once.
    /// `gen` is the generation that published the event (`u64::MAX` for
    /// ephemeral events, which no stored query can have returned).
    pub fn matches(&mut self, rec: Record<'_>, gen: u64, out: &mut Vec<(ConnId, Arc<str>)>) {
        let cand = &mut self.scratch;
        cand.clear();
        if let Some(l) = self.by_id.get(rec.id()) {
            cand.extend_from_slice(l);
        }
        if let Some(l) = self.by_author.get(rec.pubkey()) {
            cand.extend_from_slice(l);
        }
        if !self.by_tag.is_empty() {
            let mut key = Vec::with_capacity(48);
            for t in rec.tags() {
                if let Some((name, value)) = t.indexable() {
                    key.clear();
                    key.push(name);
                    key.extend_from_slice(value);
                    if let Some(l) = self.by_tag.get(key.as_slice()) {
                        cand.extend_from_slice(l);
                    }
                }
            }
        }
        if let Some(l) = self.by_kind.get(&rec.kind()) {
            cand.extend_from_slice(l);
        }
        cand.extend_from_slice(&self.all);
        if cand.is_empty() {
            return;
        }
        cand.sort_unstable();
        cand.dedup();
        let start = out.len();
        for &i in cand.iter() {
            let e = self.entries[i as usize].as_ref().expect("indexed entry exists");
            let wrap_to_broad = rec.kind() == relay_proto::kind::GIFT_WRAP && crate::session::broad(&e.filter);
            if e.gen < gen && !wrap_to_broad && e.filter.matches(rec) {
                out.push((e.conn, e.sub.clone()));
            }
        }
        // Several filters of one REQ may match; the event goes out once.
        let tail = &mut out[start..];
        tail.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let mut w = start;
        for r in start..out.len() {
            if r == start || out[r] != out[w - 1] {
                out.swap(w, r);
                w += 1;
            }
        }
        out.truncate(w);
    }
}

/// Where a filter is filed: every value of its most selective list.
fn slots_for(f: &Filter) -> Vec<Slot> {
    if let Some(ids) = &f.ids {
        return ids.iter().map(|i| Slot::Id(*i)).collect();
    }
    if let Some(a) = &f.authors {
        return a.iter().map(|k| Slot::Author(*k)).collect();
    }
    if let Some(t) = f.tags.iter().min_by_key(|t| t.values.len()) {
        return t
            .values
            .iter()
            .map(|v| {
                let mut k = Vec::with_capacity(v.len() + 1);
                k.push(t.name);
                k.extend_from_slice(v);
                Slot::Tag(k.into_boxed_slice())
            })
            .collect();
    }
    if let Some(k) = &f.kinds {
        return k.iter().map(|k| Slot::Kind(*k)).collect();
    }
    vec![Slot::All]
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_proto::event::parse_event_json;
    use relay_proto::json::Scanner;
    use relay_proto::{hex, EventParser};

    fn hx(b: u8) -> String {
        hex::encode_string(&[b; 32])
    }

    fn rec(id: u8, author: u8, kind: u64, tags: &str) -> Vec<u8> {
        let j = format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":100,"kind":{kind},"tags":{tags},"content":"","sig":"{}"}}"#,
            hx(id),
            hx(author),
            "00".repeat(64)
        );
        let mut out = Vec::new();
        parse_event_json(&j, &mut EventParser::new(), &mut out, false).unwrap();
        out
    }

    fn f(j: &str) -> Filter {
        Filter::parse(&mut Scanner::new(j)).unwrap()
    }

    fn hits(ix: &mut SubIndex, r: &[u8]) -> Vec<(ConnId, String)> {
        let mut out = Vec::new();
        ix.matches(Record(r), u64::MAX, &mut out);
        out.into_iter().map(|(c, s)| (c, s.to_string())).collect()
    }

    #[test]
    fn routes_by_most_selective_key() {
        let mut ix = SubIndex::default();
        let me = hx(9);
        ix.add(1, "dm", vec![f(&format!(r##"{{"kinds":[1059],"#p":["{me}"]}}"##))], 0);
        let authors: Vec<String> = (10..200).map(|b| format!("\"{}\"", hx(b))).collect();
        ix.add(2, "concord", vec![f(&format!(r#"{{"kinds":[1059,21059],"authors":[{}]}}"#, authors.join(",")))], 0);
        ix.add(3, "all", vec![f("{}")], 0);
        ix.add(3, "kinds", vec![f(r#"{"kinds":[0]}"#), f(r#"{"kinds":[0,1059]}"#)], 0);

        let dm = rec(1, 50, 1059, &format!(r#"[["p","{me}"]]"#));
        // The broad "all" filter does not get gift wraps.
        assert_eq!(hits(&mut ix, &dm), vec![(1, "dm".into()), (2, "concord".into()), (3, "kinds".into())]);

        let stream = rec(2, 150, 21059, r#"[["p","00"]]"#);
        assert_eq!(hits(&mut ix, &stream), vec![(2, "concord".into()), (3, "all".into())]);

        // A profile matches both filters of "kinds" but is delivered once.
        let profile = rec(3, 7, 0, "[]");
        assert_eq!(hits(&mut ix, &profile), vec![(3, "all".into()), (3, "kinds".into())]);

        assert!(ix.remove(2, "concord"));
        assert_eq!(hits(&mut ix, &stream), vec![(3, "all".into())]);
        ix.remove_conn(3);
        assert!(hits(&mut ix, &stream).is_empty());
        assert_eq!(ix.filters(), 1);
        assert!(ix.by_author.is_empty(), "empty lists are dropped");

        // Replacing a subscription id drops its old filters.
        ix.add(1, "dm", vec![f(r#"{"kinds":[7]}"#)], 0);
        assert!(hits(&mut ix, &dm).is_empty());
        assert_eq!(ix.count(1), 1);
    }

    #[test]
    fn slots_are_reused() {
        let mut ix = SubIndex::default();
        for round in 0..3 {
            for c in 0..50u64 {
                ix.add(c, "s", vec![f(r#"{"kinds":[1]}"#)], 0);
            }
            for c in 0..50u64 {
                ix.remove_conn(c);
            }
            assert_eq!(ix.filters(), 0, "round {round}");
        }
        assert!(ix.entries.len() <= 50);
    }
}
