//! The single writer: applies NIP-01 storage rules to a batch, appends it to the
//! log, makes it durable with one sync, then publishes a new version. It also
//! owns the index's shape: memory runs, the flushes that turn them into
//! segments, compactions, and the checkpoints that let a restart skip replay.

use crate::bg::{self, Done, Job};
use crate::dead::DeadSet;
use crate::keys::{self, *};
use crate::locs::{self, LocsWriter};
use crate::log::{LogWriter, Segs};
use crate::memrun::MemRun;
use crate::segment::Segment;
use crate::version::{Run, Version};
use crate::{Options, Shared, VanishCfg};
use relay_proto::kind;
use relay_proto::record::{Field, Record};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, Sender};
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
    /// Refused by a storage rule; the message is for the client.
    Rejected(&'static str),
}

/// A batch written to the log but not yet synced or published (see `Writer::stage`).
pub struct Staged {
    b: Batch,
    offs: Vec<u64>,
    base_count: u64,
}

/// A segment tier: segments within a factor of 4 in size share a level, and a
/// level holding this many is merged into one.
const COMPACT_FANIN: usize = 4;
const LEVEL_BASE: u64 = 4 << 20;

pub struct Writer {
    pub(crate) shared: Arc<Shared>,
    pub(crate) log: LogWriter,
    pub(crate) locs: LocsWriter,
    pub(crate) dead: DeadSet,
    pub(crate) segments: Vec<Arc<Segment>>,
    pub(crate) mem: Vec<Arc<MemRun>>,
    pub(crate) next_seq: u64,
    pub(crate) opts: Options,
    pub(crate) dir: PathBuf,
    pub(crate) vanish: VanishCfg,
    /// `mem[..frozen]` are being flushed into a segment.
    frozen: usize,
    flushing: bool,
    compacting: bool,
    pub(crate) next_seg_id: u64,
    /// From the last checkpoint: every key of seqs below `covered` is in a segment,
    /// and replay starts at log offset `replay_from`.
    pub(crate) covered: u64,
    pub(crate) replay_from: u64,
    jobs: Sender<Job>,
    done: Receiver<Done>,
    segs: (usize, Segs),
    /// Per published version, the dead records to zero once it (and every
    /// older version) has no readers left.
    pending_zero: VecDeque<(Weak<Version>, Vec<u64>)>,
    scratch: Vec<u8>,
}

/// Events accepted so far in the batch being applied, visible to the rules for
/// the rest of the batch. Only what the rules look up is tracked per event (its
/// id, and the address/tombstone keys); the full index keys go straight into
/// the batch's memory run. A vanish request, which needs everything about an
/// author, scans the batch's records instead.
struct Batch {
    base: Arc<Version>,
    keys: KeyBuf,
    ids: HashMap<[u8; 32], u64>,
    rules: BTreeSet<Vec<u8>>,
    new: Vec<Vec<u8>>,
    kills: Vec<u64>,
    killed: HashSet<u64>,
}

impl Batch {
    fn new(base: Arc<Version>) -> Batch {
        Batch {
            base,
            keys: KeyBuf::default(),
            ids: HashMap::new(),
            rules: BTreeSet::new(),
            new: Vec::new(),
            kills: Vec::new(),
            killed: HashSet::new(),
        }
    }

    /// The seqs and records added by this batch so far.
    fn added(&self) -> impl Iterator<Item = (u64, Record<'_>)> {
        self.new.iter().enumerate().map(|(i, r)| (self.base.count + i as u64, Record(r)))
    }

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
        self.rules.contains(key) || self.base.has_key(key)
    }

    /// Keys under a whole bloom prefix, from the store and this batch's
    /// rule-bearing keys (ADDR, DELETED, ADDR_DELETED, VANISH).
    fn for_prefix(&self, p: &[u8], mut f: impl FnMut(&[u8])) {
        self.base.for_prefix(p, &mut f);
        for k in self.rules.range(p.to_vec()..) {
            if !k.starts_with(p) {
                break;
            }
            f(k);
        }
    }

    fn lookup_id(&self, id: &[u8; 32]) -> Option<u64> {
        if let Some(&s) = self.ids.get(id) {
            if self.is_live(s) {
                return Some(s);
            }
        }
        let mut found = None;
        self.base.for_prefix(&prefix(T_ID, &[id]), |k| {
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

    /// The latest time recorded under a tombstone prefix whose keys end in a
    /// created_at (ADDR_DELETED, VANISH).
    fn latest_tombstone(&self, p: &[u8]) -> Option<u64> {
        let mut t = None;
        self.for_prefix(p, |k| t = t.max(Some(u64::from_be_bytes(k[k.len() - 8..].try_into().unwrap()))));
        t
    }
}

/// The p-tag values (as raw keys) of a record.
fn p_tags(r: Record<'_>) -> Vec<[u8; 32]> {
    r.tags()
        .filter_map(|t| {
            let mut f = t.fields();
            match (f.next(), f.next()) {
                (Some(n), Some(Field::Hex32(p))) if n.is_str(b"p") => Some(*p),
                _ => None,
            }
        })
        .collect()
}

impl Writer {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        shared: Arc<Shared>,
        log: LogWriter,
        locs: LocsWriter,
        dead: DeadSet,
        segments: Vec<Arc<Segment>>,
        mem: Vec<Arc<MemRun>>,
        next_seq: u64,
        opts: Options,
        dir: PathBuf,
        next_seg_id: u64,
        covered: u64,
        replay_from: u64,
    ) -> io::Result<Writer> {
        let (job_tx, job_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let idx = dir.join("idx");
        std::thread::Builder::new().name("store-bg".into()).spawn(move || bg::worker(idx, job_rx, done_tx))?;
        let segs = log.segments();
        let vanish = VanishCfg::new(&opts.vanish_urls);
        Ok(Writer {
            shared,
            log,
            locs,
            dead,
            segments,
            mem,
            next_seq,
            opts,
            dir,
            vanish,
            frozen: 0,
            flushing: false,
            compacting: false,
            next_seg_id,
            covered,
            replay_from,
            jobs: job_tx,
            done: done_rx,
            segs: (segs.len(), segs),
            pending_zero: VecDeque::new(),
            scratch: Vec::new(),
        })
    }

    pub fn current(&self) -> Arc<Version> {
        self.shared.current.read().unwrap().clone()
    }

    /// Applies, persists and publishes a batch of verified records. Outcomes are
    /// in input order. Nothing is visible to readers until it is durable.
    pub fn write(&mut self, records: &[&[u8]]) -> io::Result<Vec<Outcome>> {
        let (outcomes, staged) = self.stage(records)?;
        self.finish(staged)?;
        Ok(outcomes)
    }

    /// First half of a write: applies the rules and writes the batch to the log,
    /// but does not sync or publish it. The caller may already relay the stored
    /// events live (they passed every rule and are in the log), then calls
    /// [`finish`](Self::finish), which makes them durable and publishes version
    /// [`next_gen`](Self::next_gen). Acknowledgements must wait for `finish`.
    pub fn stage(&mut self, records: &[&[u8]]) -> io::Result<(Vec<Outcome>, Staged)> {
        self.maintain()?;
        let mut b = Batch::new(self.current());
        let outcomes = records.iter().map(|rec| self.apply(&mut b, rec)).collect();
        let staged = self.append(b)?;
        Ok((outcomes, staged))
    }

    /// The generation `finish` will publish for the batch staged last.
    pub fn next_gen(&self) -> u64 {
        self.shared.gen.load(Ordering::Relaxed) + 1
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
            for p in p_tags(r) {
                if b.has_key(&prefix(T_DELETED, &[id, &p])) || b.latest_tombstone(&prefix(T_VANISH, &[&p])).is_some_and(|t| t >= ca) {
                    return Outcome::Deleted;
                }
            }
        } else if b.has_key(&prefix(T_DELETED, &[id, pk])) {
            return Outcome::Deleted;
        }
        if b.latest_tombstone(&prefix(T_VANISH, &[pk])).is_some_and(|t| t >= ca) {
            return Outcome::Deleted;
        }

        if kind::is_replaceable(k) || kind::is_addressable(k) {
            address_d(r, &mut self.scratch);
            let kb = k.to_be_bytes();
            if b.latest_tombstone(&prefix(T_ADDR_DELETED, &[pk, &kb, &self.scratch])).is_some_and(|t| t >= ca) {
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
                        if deletable_by(b.record(t), pk) {
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

        if k == kind::VANISH && self.vanish.targets(r) {
            // A key that authored gift wraps is a Concord plane key (or a DM
            // throwaway): vanishing it would wipe a shared plane for everyone.
            let wraps = !b.live_under(&prefix(T_AUTHOR_KIND, &[pk, &kind::GIFT_WRAP.to_be_bytes()])).is_empty()
                || b.added().any(|(s, a)| a.pubkey() == pk && a.kind() == kind::GIFT_WRAP && b.is_live(s));
            if wraps {
                return Outcome::Rejected("blocked: a key that authored gift wraps cannot vanish");
            }
            vanish_kills(b, pk, ca);
        }

        let seq = self.next_seq + b.new.len() as u64;
        b.new.push(raw.to_vec());
        b.ids.insert(*id, seq);
        let first = b.keys.len();
        index_keys(r, seq, &mut b.keys, &mut self.scratch, &self.vanish);
        for i in first..b.keys.len() {
            let key = b.keys.key(i);
            if matches!(key[0], T_ADDR | T_DELETED | T_ADDR_DELETED | T_VANISH) {
                b.rules.insert(key.to_vec());
            }
        }
        Outcome::Stored(seq)
    }

    fn commit(&mut self, b: Batch) -> io::Result<()> {
        let staged = self.append(b)?;
        self.finish(staged)
    }

    /// Writes a batch's new records to the log (not yet synced).
    fn append(&mut self, b: Batch) -> io::Result<Staged> {
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
        Ok(Staged { b, offs, base_count })
    }

    /// Second half of a write: applies kills, syncs, and publishes.
    pub fn finish(&mut self, s: Staged) -> io::Result<()> {
        let Staged { b, offs, base_count } = s;
        if b.new.is_empty() && b.kills.is_empty() {
            return Ok(());
        }
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
            self.mem.push(Arc::new(MemRun::build(&b.keys)));
            self.merge_mem();
        }
        let old = self.publish();
        self.pending_zero.push_back((Arc::downgrade(&old), zero));
        drop(old);
        self.reclaim()?;
        self.maybe_flush();
        Ok(())
    }

    /// Kills seqs outside of a client batch (repair, expiry sweeps).
    pub(crate) fn kill_seqs(&mut self, seqs: &[u64]) -> io::Result<()> {
        if seqs.is_empty() {
            return Ok(());
        }
        let mut b = Batch::new(self.current());
        for &s in seqs {
            b.kill(s);
        }
        self.commit(b)
    }

    /// Marks events whose NIP-40 expiration is `<= now` dead. Returns how many.
    pub fn sweep_expired(&mut self, now: u64) -> io::Result<usize> {
        let v = self.current();
        let mut kills = Vec::new();
        let hi = prefix(T_EXPIRY, &[&now.saturating_add(1).to_be_bytes()]);
        v.for_range(&[T_EXPIRY], &hi, |k| {
            let seq = seq_of(k);
            if v.is_live(seq) {
                kills.push(seq);
            }
        });
        kills.sort_unstable();
        kills.dedup();
        self.kill_seqs(&kills)?;
        Ok(kills.len())
    }

    /// Geometric merging of the memory runs not being flushed: the newest run
    /// merges into the one before it while it is at least half its size.
    fn merge_mem(&mut self) {
        while self.mem.len() >= self.frozen + 2 {
            let n = self.mem.len();
            if self.mem[n - 1].len() * 2 < self.mem[n - 2].len() && n - self.frozen <= 24 {
                break;
            }
            let b = self.mem.pop().unwrap();
            let a = self.mem.pop().unwrap();
            let dead = &self.dead;
            self.mem.push(Arc::new(MemRun::merge(&a, &b, |s| dead.is_dead(s))));
        }
    }

    fn mem_bytes(&self) -> usize {
        self.mem[self.frozen..].iter().map(|m| m.bytes()).sum()
    }

    /// Hands the memory runs to the background worker once they are big enough.
    fn maybe_flush(&mut self) {
        if !self.flushing && self.mem_bytes() >= self.opts.flush_bytes {
            self.start_flush();
        }
    }

    fn start_flush(&mut self) {
        if self.mem.is_empty() {
            return;
        }
        self.frozen = self.mem.len();
        self.flushing = true;
        let id = self.next_seg_id;
        self.next_seg_id += 1;
        let job = Job::Flush { id, runs: self.mem.clone(), dead: self.dead.clone(), covered: self.next_seq, replay_from: self.log.head() };
        if self.jobs.send(job).is_err() {
            self.flushing = false;
            self.frozen = 0;
        }
    }

    fn maybe_compact(&mut self) {
        if self.compacting || self.segments.len() < COMPACT_FANIN {
            return;
        }
        let level = |s: &Segment| (s.bytes() / LEVEL_BASE).max(1).ilog(4);
        let mut by_level: Vec<(u32, Vec<Arc<Segment>>)> = Vec::new();
        for s in &self.segments {
            let l = level(s);
            match by_level.iter_mut().find(|(lv, _)| *lv == l) {
                Some((_, v)) => v.push(s.clone()),
                None => by_level.push((l, vec![s.clone()])),
            }
        }
        if let Some((_, group)) = by_level.into_iter().find(|(_, v)| v.len() >= COMPACT_FANIN) {
            self.start_compaction(group);
        }
    }

    fn start_compaction(&mut self, segs: Vec<Arc<Segment>>) {
        if segs.len() < 2 {
            return;
        }
        self.compacting = true;
        let id = self.next_seg_id;
        self.next_seg_id += 1;
        if self.jobs.send(Job::Compact { id, segs, dead: self.dead.clone() }).is_err() {
            self.compacting = false;
        }
    }

    /// Takes in finished background work. Called before every batch and on idle ticks.
    pub fn maintain(&mut self) -> io::Result<()> {
        while let Ok(d) = self.done.try_recv() {
            self.finish_job(d)?;
        }
        Ok(())
    }

    fn finish_job(&mut self, d: Done) -> io::Result<()> {
        match d {
            Done::Flushed { seg, frozen, covered, replay_from } => {
                self.mem.drain(..frozen);
                self.frozen = 0;
                self.flushing = false;
                self.segments.push(seg);
                self.covered = covered;
                self.replay_from = replay_from;
                drop(self.publish());
                self.write_checkpoint()?;
                self.maybe_compact();
                self.maybe_flush();
            }
            Done::Compacted { seg, replaced } => {
                let (gone, keep): (Vec<_>, Vec<_>) = self.segments.drain(..).partition(|s| replaced.contains(&s.id));
                self.segments = keep;
                self.segments.push(seg);
                self.compacting = false;
                drop(self.publish());
                // The checkpoint must stop naming the old segments before their
                // files can be removed (they go when the last snapshot drops them).
                self.write_checkpoint()?;
                for s in gone {
                    s.mark_obsolete();
                }
                self.maybe_compact();
            }
            Done::Failed(msg) => {
                eprintln!("store: background job failed: {msg}");
                self.flushing = false;
                self.frozen = 0;
                self.compacting = false;
            }
        }
        Ok(())
    }

    /// Flushes every memory run to a segment and waits for it (shutdown, end of import).
    pub fn flush_all(&mut self) -> io::Result<()> {
        while self.flushing {
            let d = self.done.recv().map_err(|_| io::Error::other("store worker stopped"))?;
            self.finish_job(d)?;
        }
        if self.mem.is_empty() {
            return Ok(());
        }
        self.start_flush();
        while self.flushing {
            let d = self.done.recv().map_err(|_| io::Error::other("store worker stopped"))?;
            self.finish_job(d)?;
        }
        Ok(())
    }

    /// Merges every segment into one and waits (after a bulk import: one
    /// segment means one probe per lookup).
    pub fn compact_all(&mut self) -> io::Result<()> {
        self.flush_all()?;
        while self.compacting {
            let d = self.done.recv().map_err(|_| io::Error::other("store worker stopped"))?;
            self.finish_job(d)?;
        }
        if self.segments.len() < 2 {
            return Ok(());
        }
        self.start_compaction(self.segments.clone());
        while self.compacting {
            let d = self.done.recv().map_err(|_| io::Error::other("store worker stopped"))?;
            self.finish_job(d)?;
        }
        Ok(())
    }

    /// Records that every key below `covered` is in the listed segments, so a
    /// restart replays only the log after `replay_from`. Order matters: `locs`
    /// and the dead set are made durable before the checkpoint that relies on them.
    fn write_checkpoint(&mut self) -> io::Result<()> {
        self.locs.sync()?;
        let dead_tmp = self.dir.join("dead.bits.tmp");
        std::fs::write(&dead_tmp, self.dead.to_bytes(self.next_seq))?;
        std::fs::File::open(&dead_tmp)?.sync_all()?;
        std::fs::rename(&dead_tmp, self.dir.join("dead.bits"))?;
        let ids: Vec<u64> = self.segments.iter().map(|s| s.id).collect();
        crate::checkpoint::write(&self.dir, &crate::checkpoint::Checkpoint { covered: self.covered, replay_from: self.replay_from, next_seg_id: self.next_seg_id, segments: ids })
    }

    fn publish(&mut self) -> Arc<Version> {
        let segs = self.log.segments();
        if segs.len() != self.segs.0 {
            self.segs = (segs.len(), segs);
        }
        let mut runs: Vec<Run> = self.segments.iter().map(|s| Run::Disk(s.clone())).collect();
        runs.extend(self.mem.iter().map(|m| Run::Mem(m.clone())));
        let gen = self.shared.gen.load(Ordering::Relaxed) + 1;
        let v = Arc::new(Version {
            gen,
            count: self.next_seq,
            seg_size: self.log.seg_size(),
            segs: self.segs.1.clone(),
            locs: self.locs.map(),
            dead: self.dead.clone(),
            runs: Arc::new(runs),
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

    /// Re-applies the storage rules implied by `keys` (the index keys of the log
    /// tail just replayed): a crash between syncs can leave a replaced event live,
    /// or a deletion unapplied. Old seqs killed by tail events are found this way
    /// too, since only the tail is replayed.
    pub(crate) fn repair(&mut self, tail: &[Vec<u8>]) -> io::Result<usize> {
        let v = self.current();
        let mut kills: Vec<u64> = Vec::new();
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for key in tail {
            match key[0] {
                T_ADDR => {
                    let p = &key[..key.len() - 16];
                    if !seen.insert(p.to_vec()) {
                        continue;
                    }
                    let mut members = Vec::new();
                    v.for_prefix(p, |k| {
                        let s = seq_of(k);
                        if v.is_live(s) {
                            members.push((created_at_of(k), s));
                        }
                    });
                    if members.len() > 1 {
                        let best = *members
                            .iter()
                            .min_by(|a, b| b.0.cmp(&a.0).then_with(|| v.record_unchecked(a.1).id().cmp(v.record_unchecked(b.1).id())))
                            .unwrap();
                        kills.extend(members.iter().filter(|m| m.1 != best.1).map(|m| m.1));
                    }
                }
                T_DELETED => {
                    let target: [u8; 32] = key[1..33].try_into().unwrap();
                    let deleter: [u8; 32] = key[33..65].try_into().unwrap();
                    if let Some(t) = v.lookup_id(&target) {
                        if deletable_by(v.record_unchecked(t), &deleter) {
                            kills.push(t);
                        }
                    }
                }
                T_ADDR_DELETED => {
                    let upto = u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap());
                    let mut p = Vec::with_capacity(key.len());
                    p.push(T_ADDR);
                    p.extend_from_slice(&key[1..key.len() - 8]);
                    v.for_prefix(&p, |ak| {
                        let s = seq_of(ak);
                        if created_at_of(ak) <= upto && v.is_live(s) {
                            kills.push(s);
                        }
                    });
                }
                T_VANISH => {
                    let pk: [u8; 32] = key[1..33].try_into().unwrap();
                    let upto = u64::from_be_bytes(key[33..41].try_into().unwrap());
                    let mut b = Batch::new(v.clone());
                    vanish_kills(&mut b, &pk, upto);
                    kills.extend(b.kills);
                }
                _ => {}
            }
        }
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

    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }
}

/// May `deleter` delete `target` with a kind-5 `e` tag? A gift wrap only by a
/// p-tagged recipient (Concord), a deletion never, anything else by its author.
fn deletable_by(target: Record<'_>, deleter: &[u8; 32]) -> bool {
    match target.kind() {
        kind::GIFT_WRAP => p_tags(target).iter().any(|p| p == deleter),
        kind::DELETION => false,
        _ => target.pubkey() == deleter,
    }
}

/// NIP-62: everything `pk` published up to `upto` (but its vanish requests), and
/// every gift wrap addressed to it up to `upto`.
fn vanish_kills(b: &mut Batch, pk: &[u8; 32], upto: u64) {
    let mut kills = Vec::new();
    for (ca, seq) in b.live_under(&prefix(T_AUTHOR, &[pk])) {
        if ca <= upto && b.record(seq).kind() != kind::VANISH {
            kills.push(seq);
        }
    }
    let mut field = vec![relay_proto::record::FIELD_HEX32 as u8];
    field.extend_from_slice(pk);
    for (ca, seq) in b.live_under(&prefix(T_TAG_KIND, &[b"p", &field, &kind::GIFT_WRAP.to_be_bytes()])) {
        if ca <= upto {
            kills.push(seq);
        }
    }
    // Earlier events of this same batch are not in the store yet.
    for (seq, r) in b.added() {
        if r.created_at() > upto || !b.is_live(seq) {
            continue;
        }
        let by_them = r.pubkey() == pk && r.kind() != kind::VANISH;
        let to_them = r.kind() == kind::GIFT_WRAP && p_tags(r).iter().any(|p| p == pk);
        if by_them || to_them {
            kills.push(seq);
        }
    }
    for s in kills {
        b.kill(s);
    }
}
