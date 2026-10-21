//! The single writer: applies NIP-01 storage rules to a batch, appends it to the
//! log, makes it durable with one sync, then publishes a new version.

use crate::dead::DeadSet;
use crate::keys::{self, *};
use crate::locs::{self, LocsWriter};
use crate::log::{LogWriter, Segs};
use crate::memrun::MemRun;
use crate::version::Version;
use crate::{Options, Shared};
use relay_proto::record::{Field, Record};
use relay_proto::kind;
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};

/// What happened to one event of a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Stored(u64),
    /// Already have it.
    Duplicate,
    /// A newer event holds this replaceable/addressable slot.
    Superseded,
    /// Its author (or, for a gift wrap, its recipient) asked for it to be deleted.
    Deleted,
}

pub struct Writer {
    pub(crate) shared: Arc<Shared>,
    pub(crate) log: LogWriter,
    pub(crate) locs: LocsWriter,
    pub(crate) dead: DeadSet,
    pub(crate) runs: Vec<Arc<MemRun>>,
    pub(crate) next_seq: u64,
    pub(crate) opts: Options,
    segs: (usize, Segs),
    /// Per published version, the dead records to zero once it (and every
    /// older version) has no readers left.
    pending_zero: VecDeque<(Weak<Version>, Vec<u64>)>,
    scratch: Vec<u8>,
}

/// Events accepted so far in the batch being applied, visible to the rules for
/// the rest of the batch.
struct Batch {
    base: Arc<Version>,
    keys: KeyBuf,
    key_set: BTreeSet<Vec<u8>>,
    new: Vec<Vec<u8>>,
    kills: Vec<u64>,
    killed: HashSet<u64>,
}

impl Batch {
    fn is_live(&self, seq: u64) -> bool {
        if self.killed.contains(&seq) {
            return false;
        }
        if seq >= self.base.count {
            ((seq - self.base.count) as usize) < self.new.len()
        } else {
            self.base.is_live(seq)
        }
    }

    fn record(&self, seq: u64) -> Record<'_> {
        if seq >= self.base.count {
            Record(&self.new[(seq - self.base.count) as usize])
        } else {
            self.base.record_unchecked(seq)
        }
    }

    fn has_key(&self, key: &[u8]) -> bool {
        self.key_set.contains(key) || self.base.has_key(key)
    }

    fn for_prefix(&self, p: &[u8], mut f: impl FnMut(&[u8])) {
        self.base.for_prefix(p, &mut f);
        for k in self.key_set.range(p.to_vec()..) {
            if !k.starts_with(p) {
                break;
            }
            f(k);
        }
    }

    fn lookup_id(&self, id: &[u8; 32]) -> Option<u64> {
        let p = prefix(T_ID, &[id]);
        let mut found = None;
        self.for_prefix(&p, |k| {
            let s = seq_of(k);
            if found.is_none() && self.is_live(s) {
                found = Some(s);
            }
        });
        found
    }

    fn kill(&mut self, seq: u64) {
        if self.killed.insert(seq) {
            self.kills.push(seq);
        }
    }

    /// Live `(created_at, seq)` entries under a scan prefix.
    fn live_under(&self, p: &[u8]) -> Vec<(u64, u64)> {
        let mut v = Vec::new();
        self.for_prefix(p, |k| {
            let s = seq_of(k);
            if self.is_live(s) {
                v.push((created_at_of(k), s));
            }
        });
        v
    }
}

impl Writer {
    pub(crate) fn new(shared: Arc<Shared>, log: LogWriter, locs: LocsWriter, dead: DeadSet, runs: Vec<Arc<MemRun>>, next_seq: u64, opts: Options) -> Writer {
        let segs = log.segments();
        Writer {
            shared,
            log,
            locs,
            dead,
            runs,
            next_seq,
            opts,
            segs: (segs.len(), segs),
            pending_zero: VecDeque::new(),
            scratch: Vec::new(),
        }
    }

    pub fn current(&self) -> Arc<Version> {
        self.shared.current.read().unwrap().clone()
    }

    /// Applies, persists and publishes a batch of verified records. Outcomes are
    /// in input order. Nothing is visible to readers until it is durable.
    pub fn write(&mut self, records: &[&[u8]]) -> io::Result<Vec<Outcome>> {
        let mut b = Batch {
            base: self.current(),
            keys: KeyBuf::default(),
            key_set: BTreeSet::new(),
            new: Vec::new(),
            kills: Vec::new(),
            killed: HashSet::new(),
        };
        let outcomes = records.iter().map(|rec| self.apply(&mut b, rec)).collect();
        self.commit(b)?;
        Ok(outcomes)
    }

    fn apply(&mut self, b: &mut Batch, raw: &[u8]) -> Outcome {
        let r = Record(raw);
        let (id, pk, k, ca) = (r.id(), r.pubkey(), r.kind(), r.created_at());

        if b.lookup_id(id).is_some() {
            return Outcome::Duplicate;
        }

        // Tombstones. A gift wrap answers only to its recipients: its author is a
        // throwaway (DM) or shared (Concord plane) key, so author deletes are
        // refused for it (Concord CORD-01; see PLAN.md decisions).
        if k == kind::GIFT_WRAP {
            let blocked = r.tags().any(|t| {
                let mut f = t.fields();
                match (f.next(), f.next()) {
                    (Some(n), Some(Field::Hex32(p))) if n.is_str(b"p") => b.has_key(&prefix(T_DELETED, &[id, p])),
                    _ => false,
                }
            });
            if blocked {
                return Outcome::Deleted;
            }
        } else if b.has_key(&prefix(T_DELETED, &[id, pk])) {
            return Outcome::Deleted;
        }

        if kind::is_replaceable(k) || kind::is_addressable(k) {
            address_d(r, &mut self.scratch);
            let kb = k.to_be_bytes();
            let mut deleted_until = None;
            b.for_prefix(&prefix(T_ADDR_DELETED, &[pk, &kb, &self.scratch]), |key| {
                let t = u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap());
                deleted_until = deleted_until.max(Some(t));
            });
            if deleted_until.is_some_and(|t| t >= ca) {
                return Outcome::Deleted;
            }
            let existing = b.live_under(&prefix(T_ADDR, &[pk, &kb, &self.scratch]));
            // Newest wins; same second, lowest id wins (NIP-01).
            let beats_new = |&(eca, seq): &(u64, u64)| eca > ca || (eca == ca && b.record(seq).id() < id);
            if existing.iter().any(beats_new) {
                return Outcome::Superseded;
            }
            for (_, seq) in existing {
                b.kill(seq);
            }
        }

        if k == kind::DELETION {
            for tag in r.tags() {
                let mut f = tag.fields();
                match (f.next(), f.next()) {
                    (Some(n), Some(Field::Hex32(target))) if n.is_str(b"e") => {
                        let Some(t) = b.lookup_id(target) else { continue };
                        let tr = b.record(t);
                        let allowed = match tr.kind() {
                            kind::GIFT_WRAP => tr.tags().any(|tt| {
                                let mut ff = tt.fields();
                                matches!((ff.next(), ff.next()), (Some(n), Some(Field::Hex32(p))) if n.is_str(b"p") && p == pk)
                            }),
                            kind::DELETION => false,
                            _ => tr.pubkey() == pk,
                        };
                        if allowed {
                            b.kill(t);
                        }
                    }
                    (Some(n), Some(Field::Str(a))) if n.is_str(b"a") => {
                        let Some((ak, apk, d)) = keys::parse_address(a) else { continue };
                        if &apk != pk {
                            continue;
                        }
                        let mut dfield = Vec::new();
                        relay_proto::record::encode_field_str(d, &mut dfield);
                        for (eca, seq) in b.live_under(&prefix(T_ADDR, &[pk, &ak.to_be_bytes(), &dfield])) {
                            if eca <= ca {
                                b.kill(seq);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        let seq = self.next_seq + b.new.len() as u64;
        b.new.push(raw.to_vec());
        let first = b.keys.len();
        index_keys(r, seq, &mut b.keys, &mut self.scratch);
        for i in first..b.keys.len() {
            b.key_set.insert(b.keys.key(i).to_vec());
        }
        Outcome::Stored(seq)
    }

    fn commit(&mut self, b: Batch) -> io::Result<()> {
        if b.new.is_empty() && b.kills.is_empty() {
            return Ok(());
        }
        let base_count = self.next_seq;
        let mut offs = Vec::with_capacity(b.new.len());
        for (i, rec) in b.new.iter().enumerate() {
            offs.push(self.log.append(base_count + i as u64, rec)?);
        }
        self.log.flush()?;
        for (i, &off) in offs.iter().enumerate() {
            self.locs.set(base_count + i as u64, off)?;
        }
        self.next_seq += b.new.len() as u64;

        let mut zero = Vec::with_capacity(b.kills.len());
        for &seq in &b.kills {
            let off = if seq >= base_count { offs[(seq - base_count) as usize] } else { locs::get(&b.base.locs, seq) };
            self.log.mark_dead(off)?;
            zero.push(off);
        }
        if self.opts.sync {
            self.log.sync()?;
        } else {
            self.log.flush()?;
        }

        self.dead.grow_to(self.next_seq);
        for &seq in &b.kills {
            self.dead.set(seq);
        }
        if !b.keys.is_empty() {
            self.runs.push(Arc::new(MemRun::build(&b.keys)));
            self.merge_runs();
        }
        let old = self.publish();
        self.pending_zero.push_back((Arc::downgrade(&old), zero));
        drop(old);
        self.reclaim()
    }

    /// Kills seqs outside of a client batch (replay repair, expiry sweeps).
    pub(crate) fn kill_seqs(&mut self, seqs: &[u64]) -> io::Result<()> {
        if seqs.is_empty() {
            return Ok(());
        }
        let base = self.current();
        let b = Batch {
            base,
            keys: KeyBuf::default(),
            key_set: BTreeSet::new(),
            new: Vec::new(),
            kills: seqs.to_vec(),
            killed: seqs.iter().copied().collect(),
        };
        self.commit(b)
    }

    /// Marks events whose NIP-40 expiration is `<= now` dead. Returns how many.
    pub fn sweep_expired(&mut self, now: u64) -> io::Result<usize> {
        let v = self.current();
        let mut kills = Vec::new();
        v.for_prefix(&[T_EXPIRY], |k| {
            let exp = u64::from_be_bytes(k[1..9].try_into().unwrap());
            let seq = seq_of(k);
            if exp <= now && v.is_live(seq) {
                kills.push(seq);
            }
        });
        kills.sort_unstable();
        kills.dedup();
        self.kill_seqs(&kills)?;
        Ok(kills.len())
    }

    /// Geometric merging: the newest run merges into the one before it while it
    /// is at least half its size, so run sizes stay roughly powers of two.
    fn merge_runs(&mut self) {
        while self.runs.len() >= 2 {
            let n = self.runs.len();
            if self.runs[n - 1].len() * 2 < self.runs[n - 2].len() && n <= 24 {
                break;
            }
            let b = self.runs.pop().unwrap();
            let a = self.runs.pop().unwrap();
            let dead = &self.dead;
            self.runs.push(Arc::new(MemRun::merge(&a, &b, |s| dead.is_dead(s))));
        }
    }

    fn publish(&mut self) -> Arc<Version> {
        let segs = self.log.segments();
        if segs.len() != self.segs.0 {
            self.segs = (segs.len(), segs);
        }
        let gen = self.shared.gen.load(Ordering::Relaxed) + 1;
        let v = Arc::new(Version {
            gen,
            count: self.next_seq,
            seg_size: self.log.seg_size(),
            segs: self.segs.1.clone(),
            locs: self.locs.map(),
            dead: self.dead.clone(),
            runs: Arc::new(self.runs.clone()),
        });
        let old = std::mem::replace(&mut *self.shared.current.write().unwrap(), v);
        self.shared.gen.store(gen, Ordering::Release);
        old
    }

    /// Zeroes dead records that no live snapshot can reach any more.
    fn reclaim(&mut self) -> io::Result<()> {
        while let Some((w, _)) = self.pending_zero.front() {
            if w.strong_count() > 0 {
                break;
            }
            let (_, offs) = self.pending_zero.pop_front().unwrap();
            for off in offs {
                self.log.zero_record(off)?;
            }
        }
        Ok(())
    }

    /// Restores the storage invariants a crash between syncs could leave broken:
    /// one live event per address, deletions applied.
    pub(crate) fn repair(&mut self) -> io::Result<usize> {
        let v = self.current();
        let mut kills: Vec<u64> = Vec::new();

        // Addresses: group T_ADDR keys by prefix (everything but created_at ‖ seq).
        let mut group: Vec<u8> = Vec::new();
        let mut members: Vec<(u64, u64)> = Vec::new();
        let flush = |members: &mut Vec<(u64, u64)>, kills: &mut Vec<u64>| {
            if members.len() > 1 {
                let best = *members
                    .iter()
                    .min_by(|a, b| b.0.cmp(&a.0).then_with(|| v.record_unchecked(a.1).id().cmp(v.record_unchecked(b.1).id())))
                    .unwrap();
                kills.extend(members.iter().filter(|m| m.1 != best.1).map(|m| m.1));
            }
            members.clear();
        };
        let mut all = Vec::new();
        v.for_prefix(&[T_ADDR], |k| all.push(k.to_vec()));
        all.sort_unstable();
        for k in &all {
            let p = &k[..k.len() - 16];
            if p != group.as_slice() {
                flush(&mut members, &mut kills);
                group.clear();
                group.extend_from_slice(p);
            }
            let s = seq_of(k);
            if v.is_live(s) {
                members.push((created_at_of(k), s));
            }
        }
        flush(&mut members, &mut kills);

        // `e` tombstones whose target is still live and was deletable.
        v.for_prefix(&[T_DELETED], |k| {
            let target: [u8; 32] = k[1..33].try_into().unwrap();
            let deleter = &k[33..65];
            let Some(t) = v.lookup_id(&target) else { return };
            let tr = v.record_unchecked(t);
            let allowed = match tr.kind() {
                kind::GIFT_WRAP => tr.tags().any(|tt| {
                    let mut ff = tt.fields();
                    matches!((ff.next(), ff.next()), (Some(n), Some(Field::Hex32(p))) if n.is_str(b"p") && &p[..] == deleter)
                }),
                kind::DELETION => false,
                _ => &tr.pubkey()[..] == deleter,
            };
            if allowed {
                kills.push(t);
            }
        });

        // `a` tombstones: everything at the address up to the deletion's time.
        v.for_prefix(&[T_ADDR_DELETED], |k| {
            let upto = u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap());
            let mut p = Vec::with_capacity(k.len());
            p.push(T_ADDR);
            p.extend_from_slice(&k[1..k.len() - 8]);
            v.for_prefix(&p, |ak| {
                let s = seq_of(ak);
                if created_at_of(ak) <= upto && v.is_live(s) {
                    kills.push(s);
                }
            });
        });

        kills.sort_unstable();
        kills.dedup();
        let n = kills.len();
        drop(v);
        self.kill_seqs(&kills)?;
        Ok(n)
    }

    /// Forces durability of everything written (for relaxed mode and shutdown).
    pub fn sync(&mut self) -> io::Result<()> {
        self.log.sync()?;
        self.locs.sync()
    }

    #[inline]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}
