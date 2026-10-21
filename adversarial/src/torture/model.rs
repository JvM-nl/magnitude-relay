//! A reference model of the store: what every acknowledged operation must
//! have done, written as plainly as possible and sharing no code with the
//! store's rules. The torture parent replays acknowledgements into it and
//! compares the store with it after every crash.
//!
//! Rules (PLAN.md, writer.rs): duplicates by id; kind-5 `e` tombstones (a gift
//! wrap answers only to its p-tagged recipients); NIP-62 vanish tombstones;
//! replaceable and addressable slots (newest wins, same second lowest id); `a`
//! tombstones; vanish refused for a key that authored live gift wraps; operator
//! removal (no tombstone); expiry sweeps.

use super::work::{self, Ev, Op};
use relay_proto::json::Scanner;
use relay_proto::{hex, kind, Filter, Record};
use relay_store::Outcome;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone)]
pub struct Slot {
    pub ev: Arc<Ev>,
    pub rec: Arc<Vec<u8>>,
    pub seq: u64,
    pub alive: bool,
    /// Why the model killed it, and by which seq (u64::MAX: no event).
    pub why: (&'static str, u64),
}

/// The outcome classes the store reports (a stored event's seq is checked too).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    Stored(u64),
    Duplicate,
    Superseded,
    Deleted,
    Rejected,
}

impl Out {
    pub fn of(o: &Outcome) -> Out {
        match o {
            Outcome::Stored(s) => Out::Stored(*s),
            Outcome::Duplicate => Out::Duplicate,
            Outcome::Superseded => Out::Superseded,
            Outcome::Deleted | Outcome::Vanished => Out::Deleted,
            Outcome::Rejected(_) => Out::Rejected,
        }
    }

    pub fn token(&self) -> String {
        match self {
            Out::Stored(s) => format!("S{s}"),
            Out::Duplicate => "D".into(),
            Out::Superseded => "U".into(),
            Out::Deleted => "X".into(),
            Out::Rejected => "R".into(),
        }
    }

    pub fn parse(t: &str) -> Option<Out> {
        Some(match t {
            "D" => Out::Duplicate,
            "U" => Out::Superseded,
            "X" => Out::Deleted,
            "R" => Out::Rejected,
            s => Out::Stored(s.strip_prefix('S')?.parse().ok()?),
        })
    }
}

#[derive(Clone)]
pub struct Model {
    pub seed: u64,
    /// Every stored copy of every event, in store order (index = seq).
    pub slots: Vec<Slot>,
    /// id -> the seq of its live copy.
    live: HashMap<[u8; 32], u64>,
    deleted_e: HashSet<([u8; 32], [u8; 32])>,
    addr_deleted: HashMap<([u8; 32], u64, Vec<u8>), u64>,
    vanished: HashMap<[u8; 32], u64>,
}

/// The encoded `d` of an event's address, as the store keys it.
pub fn address_d(ev: &Ev) -> Vec<u8> {
    let mut out = Vec::new();
    if kind::is_addressable(ev.kind) {
        match ev.tags.iter().find(|t| t.first().is_some_and(|x| x == "d")) {
            Some(t) => relay_proto::record::encode_field_str(t.get(1).map_or("", String::as_str).as_bytes(), &mut out),
            None => out.push(0),
        }
    } else {
        out.push(0);
    }
    out
}

fn p_tags(ev: &Ev) -> Vec<[u8; 32]> {
    ev.tags
        .iter()
        .filter(|t| t.len() >= 2 && t[0] == "p")
        .filter_map(|t| hex::decode_32(t[1].as_bytes()))
        .collect()
}

pub fn deletable_by(target: &Ev, deleter: &[u8; 32]) -> bool {
    match target.kind {
        kind::GIFT_WRAP => p_tags(target).iter().any(|p| p == deleter),
        kind::DELETION => false,
        _ => &target.pubkey == deleter,
    }
}

fn vanish_targets(ev: &Ev) -> bool {
    ev.kind == kind::VANISH
        && ev.tags.iter().any(|t| t.len() >= 2 && t[0] == "relay" && (t[1] == "ALL_RELAYS" || t[1].trim().trim_end_matches('/').eq_ignore_ascii_case(work::URL)))
}

/// `kind:pubkey:d` as the store reads an `a` tag.
fn parse_address(a: &str) -> Option<(u64, [u8; 32], &str)> {
    let (k, rest) = a.split_once(':')?;
    let (pk, d) = rest.split_once(':')?;
    if k.is_empty() || !k.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((k.parse().ok()?, hex::decode_32(pk.as_bytes())?, d))
}

pub fn parse_filter(json: &str) -> Filter {
    Filter::parse(&mut Scanner::new(json)).expect("workload filter parses")
}

impl Model {
    pub fn new(seed: u64) -> Model {
        Model { seed, slots: Vec::new(), live: HashMap::new(), deleted_e: HashSet::new(), addr_deleted: HashMap::new(), vanished: HashMap::new() }
    }

    pub fn next_seq(&self) -> u64 {
        self.slots.len() as u64
    }

    pub fn live_seqs(&self) -> impl Iterator<Item = &Slot> {
        self.slots.iter().filter(|s| s.alive)
    }

    pub fn is_live_id(&self, id: &[u8; 32]) -> bool {
        self.live.contains_key(id)
    }

    fn kill(&mut self, seq: u64, why: &'static str, by: u64) {
        let s = &mut self.slots[seq as usize];
        if s.alive {
            s.alive = false;
            s.why = (why, by);
            self.live.remove(&s.ev.id);
        }
    }

    pub fn kill_seq(&mut self, seq: u64) {
        self.kill(seq, "operator", u64::MAX);
    }

    /// Brings back a copy whose removal a crash undid (an unacknowledged
    /// operator removal). Two live copies of one id cannot be modelled: the
    /// caller's state check then fails, which is what such a store deserves.
    pub fn revive_seq(&mut self, seq: u64) {
        let s = &mut self.slots[seq as usize];
        if !s.alive && !self.live.contains_key(&s.ev.id) {
            s.alive = true;
            self.live.insert(s.ev.id, seq);
        }
    }

    /// What a restart's repair does with events a crash brought back (see
    /// `revive_seq`): one that a later event's rule would have removed had it
    /// been alive (a deletion's tombstone, a vanish) dies again, and a
    /// replaceable or addressable slot left with two live events keeps the
    /// newest (ties: the lowest id).
    pub fn settle_revived(&mut self, revived: &[u64]) {
        for &r in revived {
            let s = &self.slots[r as usize];
            if !s.alive {
                continue;
            }
            let ev = s.ev.clone();
            let (id, pk, k, ca) = (ev.id, ev.pubkey, ev.kind, ev.created_at);
            let tombstoned = if k == kind::GIFT_WRAP {
                p_tags(&ev).iter().any(|p| self.deleted_e.contains(&(id, *p)) || self.vanished.get(p).is_some_and(|&t| t >= ca))
            } else {
                self.deleted_e.contains(&(id, pk)) && deletable_by(&ev, &pk)
            };
            let vanished = k != kind::VANISH && self.vanished.get(&pk).is_some_and(|&t| t >= ca);
            let slotted = kind::is_replaceable(k) || kind::is_addressable(k);
            let d = address_d(&ev);
            let addr_deleted = slotted && self.addr_deleted.get(&(pk, k, d.clone())).is_some_and(|&t| t >= ca);
            if tombstoned || vanished || addr_deleted {
                self.kill(r, "repaired", u64::MAX);
                continue;
            }
            if slotted {
                let members = self.at_address(&pk, k, &d);
                let best = members.iter().copied().max_by(|&a, &b| {
                    let (ea, eb) = (&self.slots[a as usize].ev, &self.slots[b as usize].ev);
                    ea.created_at.cmp(&eb.created_at).then(eb.id.cmp(&ea.id))
                });
                if let Some(best) = best {
                    for m in members.into_iter().filter(|&m| m != best) {
                        self.kill(m, "replaced", best);
                    }
                }
            }
        }
    }

    /// Kills the live copy of `id`, if any (an observation after a crash).
    pub fn kill_id(&mut self, id: &[u8; 32]) {
        if let Some(&s) = self.live.get(id) {
            self.kill(s, "observed", u64::MAX);
        }
    }

    fn at_address(&self, pk: &[u8; 32], k: u64, d: &[u8]) -> Vec<u64> {
        self.live
            .values()
            .copied()
            .filter(|&s| {
                let e = &self.slots[s as usize].ev;
                (kind::is_replaceable(e.kind) || kind::is_addressable(e.kind)) && &e.pubkey == pk && e.kind == k && address_d(e) == d
            })
            .collect()
    }

    /// Applies one event as the writer does; returns the outcome it must report.
    pub fn apply_event(&mut self, ev: &Ev) -> Out {
        let (id, pk, k, ca) = (ev.id, ev.pubkey, ev.kind, ev.created_at);
        if self.live.contains_key(&id) {
            return Out::Duplicate;
        }
        if k == kind::GIFT_WRAP {
            for p in p_tags(ev) {
                if self.deleted_e.contains(&(id, p)) || self.vanished.get(&p).is_some_and(|&t| t >= ca) {
                    return Out::Deleted;
                }
            }
        } else if self.deleted_e.contains(&(id, pk)) {
            return Out::Deleted;
        }
        if self.vanished.get(&pk).is_some_and(|&t| t >= ca) {
            return Out::Deleted;
        }
        if kind::is_replaceable(k) || kind::is_addressable(k) {
            let d = address_d(ev);
            if self.addr_deleted.get(&(pk, k, d.clone())).is_some_and(|&t| t >= ca) {
                return Out::Deleted;
            }
            let existing = self.at_address(&pk, k, &d);
            let beats = existing.iter().any(|&s| {
                let e = &self.slots[s as usize].ev;
                e.created_at > ca || (e.created_at == ca && e.id < id)
            });
            if beats {
                return Out::Superseded;
            }
            let me = self.slots.len() as u64;
            for s in existing {
                self.kill(s, "replaced", me);
            }
        }
        if k == kind::DELETION {
            for t in &ev.tags {
                if t.len() < 2 {
                    continue;
                }
                if t[0] == "e" {
                    let Some(target) = hex::decode_32(t[1].as_bytes()) else { continue };
                    if let Some(&s) = self.live.get(&target) {
                        if deletable_by(&self.slots[s as usize].ev.clone(), &pk) {
                            let me = self.slots.len() as u64;
                            self.kill(s, "kind-5 e", me);
                        }
                    }
                } else if t[0] == "a" {
                    let Some((ak, apk, d)) = parse_address(&t[1]) else { continue };
                    if apk != pk {
                        continue;
                    }
                    let mut dfield = Vec::new();
                    relay_proto::record::encode_field_str(d.as_bytes(), &mut dfield);
                    for s in self.at_address(&pk, ak, &dfield) {
                        if self.slots[s as usize].ev.created_at <= ca {
                            let me = self.slots.len() as u64;
                            self.kill(s, "kind-5 a", me);
                        }
                    }
                }
            }
        }
        if vanish_targets(ev) {
            let wraps = self.live.values().any(|&s| {
                let e = &self.slots[s as usize].ev;
                e.pubkey == pk && e.kind == kind::GIFT_WRAP
            });
            if wraps {
                return Out::Rejected;
            }
            let kills: Vec<u64> = self
                .live
                .values()
                .copied()
                .filter(|&s| {
                    let e = &self.slots[s as usize].ev;
                    e.created_at <= ca && ((e.pubkey == pk && e.kind != kind::VANISH) || (e.kind == kind::GIFT_WRAP && p_tags(e).contains(&pk)))
                })
                .collect();
            let me = self.slots.len() as u64;
            for s in kills {
                self.kill(s, "vanish", me);
            }
        }
        // Stored: its tombstones take effect for everything after it.
        let seq = self.slots.len() as u64;
        if k == kind::DELETION {
            for t in &ev.tags {
                if t.len() >= 2 && t[0] == "e" {
                    if let Some(target) = hex::decode_32(t[1].as_bytes()) {
                        self.deleted_e.insert((target, pk));
                    }
                } else if t.len() >= 2 && t[0] == "a" {
                    if let Some((ak, apk, d)) = parse_address(&t[1]) {
                        if apk == pk {
                            let mut dfield = Vec::new();
                            relay_proto::record::encode_field_str(d.as_bytes(), &mut dfield);
                            let e = self.addr_deleted.entry((pk, ak, dfield)).or_insert(0);
                            *e = (*e).max(ca);
                        }
                    }
                }
            }
        }
        if vanish_targets(ev) {
            let e = self.vanished.entry(pk).or_insert(0);
            *e = (*e).max(ca);
        }
        self.slots.push(Slot { ev: Arc::new(ev.clone()), rec: Arc::new(ev.record()), seq, alive: true, why: ("", u64::MAX) });
        self.live.insert(id, seq);
        Out::Stored(seq)
    }

    /// Live, unexpired events matching any filter (and created before
    /// `older_than`), newest first, ties latest stored first: the operator walk.
    pub fn matching(&self, filters: &[Filter], older_than: Option<u64>, now: u64) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .live
            .values()
            .copied()
            .filter(|&s| {
                let sl = &self.slots[s as usize];
                let r = Record(&sl.rec);
                r.expiration().is_none_or(|e| e > now) && older_than.is_none_or(|c| r.created_at() < c) && filters.iter().any(|f| f.matches(r))
            })
            .collect();
        v.sort_unstable_by(|a, b| {
            let (x, y) = (&self.slots[*a as usize], &self.slots[*b as usize]);
            y.ev.created_at.cmp(&x.ev.created_at).then(b.cmp(a))
        });
        v
    }

    /// What a NIP-01 query must return: matching, unexpired, newest first, ties
    /// lowest id first, at most `limit`.
    pub fn query(&self, f: &Filter, limit: usize, now: u64) -> Vec<[u8; 32]> {
        let mut v: Vec<&Slot> = self
            .live
            .values()
            .map(|&s| &self.slots[s as usize])
            .filter(|sl| {
                let r = Record(&sl.rec);
                r.expiration().is_none_or(|e| e > now) && f.matches(r)
            })
            .collect();
        v.sort_unstable_by(|a, b| b.ev.created_at.cmp(&a.ev.created_at).then(a.ev.id.cmp(&b.ev.id)));
        v.truncate(limit);
        v.iter().map(|s| s.ev.id).collect()
    }

    /// Kills live events expiring at or before `now`.
    pub fn sweep(&mut self, now: u64) -> usize {
        let kills: Vec<u64> = self.live.values().copied().filter(|&s| Record(&self.slots[s as usize].rec).expiration().is_some_and(|e| e <= now)).collect();
        for &s in &kills {
            self.kill(s, "expired", u64::MAX);
        }
        kills.len()
    }

    /// The operator removal of `Op::Delete`. Returns how many it removed.
    pub fn delete(&mut self, filters: &[String], older_than: Option<u64>, now: u64) -> usize {
        let fs: Vec<Filter> = filters.iter().map(|f| parse_filter(f)).collect();
        let targets = self.matching(&fs, older_than, now);
        for &s in &targets {
            self.kill(s, "operator", u64::MAX);
        }
        targets.len()
    }

    /// Applies one acknowledged operation; returns the outcomes it must have
    /// reported (one token per event, or the removal count).
    pub fn apply_op(&mut self, op: &Op, now: u64) -> Vec<Out> {
        match op {
            Op::Batch(evs) => evs.iter().map(|e| self.apply_event(e)).collect(),
            Op::Delete { filters, older_than } => {
                let n = self.delete(filters, *older_than, now);
                vec![Out::Stored(n as u64)]
            }
            Op::AdminDelete { filters, between } => {
                let fs: Vec<Filter> = filters.iter().map(|f| parse_filter(f)).collect();
                let targets = self.matching(&fs, None, now);
                let mut out = Vec::new();
                let mut killed = 0;
                let chunks: Vec<&[u64]> = targets.chunks(ADMIN_CHUNK).collect();
                let steps = chunks.len().max(between.len());
                for i in 0..steps {
                    if let Some(c) = chunks.get(i) {
                        for &s in *c {
                            if self.slots[s as usize].alive {
                                killed += 1;
                                self.kill(s, "admin", u64::MAX);
                            }
                        }
                    }
                    if let Some(b) = between.get(i) {
                        out.extend(b.iter().map(|e| self.apply_event(e)));
                    }
                }
                out.push(Out::Stored(killed));
                out
            }
            Op::Sweep(t) => {
                self.sweep(*t);
                Vec::new()
            }
            Op::Restart => {
                self.sweep(work::PAST);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// A digest of the observable state, to drop duplicate candidates.
    pub fn digest(&self) -> u64 {
        let mut ids: Vec<(u64, [u8; 32])> = self.live.iter().map(|(id, &s)| (s, *id)).collect();
        ids.sort_unstable();
        ids.iter().fold(self.slots.len() as u64, |h, (s, id)| crate::rng::mix(h ^ s ^ u64::from_le_bytes(id[..8].try_into().unwrap())))
    }
}

/// Kills per `kill_live` call in an admin delete (the server uses 4096; small
/// here so the interleaving with client batches is exercised).
pub const ADMIN_CHUNK: usize = 3;
