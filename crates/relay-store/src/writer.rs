//! The single writer: applies NIP-01 storage rules to a batch, appends it to the
//! log, makes it durable with one sync, then publishes a new version. It also
//! owns the index's shape: memory runs, the flushes that turn them into
//! segments, compactions, and the checkpoints that let a restart skip replay.

use crate::bg::{self, Done, Job};
use crate::dead::DeadSet;
use crate::keys::{self, *};
use crate::locs::{self, LocsWriter};
use crate::log::{LogWriter, Segs, COLD_BASE};
use crate::memrun::MemRun;
use crate::segment::Segment;
use crate::version::{Run, Version};
use crate::{Options, Shared, VanishCfg};
use relay_proto::kind;
use relay_proto::record::{Field, Record};
use relay_proto::Filter;
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
    /// Its author (or, for a gift wrap, its recipient) asked this relay to
    /// forget them (NIP-62) after it was created. Told apart from `Deleted` so
    /// a sync or an import can say which rule refused what.
    Vanished,
    /// Refused by a storage rule; the message is for the client.
    Rejected(&'static str),
}

/// Nanoseconds spent in each phase of `finish` (sync, build run, merge runs,
/// publish + reclaim), for the writer's debug breakdown.
pub static FINISH_NS: [std::sync::atomic::AtomicU64; 4] =
    [std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0)];

#[inline]
fn lap(slot: usize, t: &mut std::time::Instant) {
    let now = std::time::Instant::now();
    FINISH_NS[slot].fetch_add((now - *t).as_nanos() as u64, Ordering::Relaxed);
    *t = now;
}

/// The sync a published batch still owes (see `Writer::publish_staged`).
pub struct SyncTicket {
    files: Vec<Arc<crate::mmap::MappedFile>>,
    seq_end: u64,
    durable: Arc<std::sync::atomic::AtomicU64>,
    /// The batch's number: once synced, its dead flags are on disk.
    epoch: u64,
    synced: Arc<std::sync::atomic::AtomicU64>,
}

impl SyncTicket {
    /// Folds a later ticket into this one, so one sync covers both.
    pub fn absorb(&mut self, later: SyncTicket) {
        for f in later.files {
            if !self.files.iter().any(|g| Arc::ptr_eq(g, &f)) {
                self.files.push(f);
            }
        }
        self.seq_end = self.seq_end.max(later.seq_end);
        self.epoch = self.epoch.max(later.epoch);
    }

    /// Syncs, then advances the durability horizon.
    pub fn sync(self) -> io::Result<()> {
        for f in &self.files {
            f.sync()?;
        }
        self.durable.fetch_max(self.seq_end, Ordering::AcqRel);
        self.synced.fetch_max(self.epoch, Ordering::AcqRel);
        Ok(())
    }
}

/// A batch written to the log but not yet synced or published (see `Writer::stage`).
pub struct Staged {
    b: Batch,
    offs: Vec<u64>,
    base_count: u64,
}

/// Where a log compaction stands.
enum LogState {
    Idle,
    /// The background worker is writing cold segments.
    Writing,
    /// Cold segments registered (checkpointed as an intent); waiting until no
    /// reader can hold a version without them before `locs` points at them.
    Waiting { reg_gen: u64, moves: Vec<(u64, u64)>, retire: Vec<u64> },
    /// The background worker is relinking `locs`.
    Relinking { retire: Vec<u64> },
}

/// Cold segments as sorted runs (segment numbers, frame bytes), oldest first.
pub(crate) type ColdRuns = Vec<(Vec<u64>, u64)>;

/// Cold runs merged at once, and how far apart in size they may be.
const MERGE_FANIN: usize = 4;
const MERGE_RATIO: u64 = 4;

/// Events an operator removal kills per commit: enough to amortise the sync,
/// few enough that the writer is never away from client batches for long.
pub const DELETE_BATCH: usize = 4096;

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
    /// The background worker, stopped and waited for when the writer goes.
    bg: Option<std::thread::JoinHandle<()>>,
    stop: bg::Stop,
    segs: ((usize, usize, usize, usize), Segs),
    /// Every replaced version (gen, handle) with the dead records to zero once
    /// it, and every older version, has no readers left.
    /// The fourth field is the batch whose sync must land first: a record's
    /// bytes may only go once the flag marking it dead is on disk, or a crash
    /// could leave zeros where a live event is expected.
    pending_zero: VecDeque<(u64, Weak<Version>, Vec<u64>, u64)>,
    /// Batches published so far, and the latest whose sync has completed.
    epoch: u64,
    synced: Arc<std::sync::atomic::AtomicU64>,
    pub(crate) next_cold: u64,
    pub(crate) cold_runs: ColdRuns,
    pub(crate) retired: Vec<u64>,
    log_state: LogState,
    /// A log compaction's cold segments and the hot segments they replace,
    /// from registration until the relink is done: every checkpoint in between
    /// records it, so a restart finishes the exchange.
    intent: (Vec<u64>, Vec<u64>),
    /// A backup is copying files: no log compaction starts, and one that
    /// finishes writing is not registered (its relink would point `locs` at
    /// files the backup lacks) until the backup ends.
    backup_hold: bool,
    held_done: Vec<Done>,
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

impl Drop for Writer {
    /// Nothing of a closed store may still write into its directory once its
    /// lock can be released (a new opener's cleanup would race it): the job in
    /// progress is stopped and the worker waited for, before the writer's share
    /// of the lock goes.
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Hanging up ends the worker's loop once its job returns.
        let (hung_up, _) = std::sync::mpsc::channel();
        drop(std::mem::replace(&mut self.jobs, hung_up));
        if let Some(t) = self.bg.take() {
            let _ = t.join();
        }
    }
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
        log_lists: (u64, ColdRuns, Vec<u64>),
    ) -> io::Result<Writer> {
        let (job_tx, job_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let idx = dir.join("idx");
        let stop = bg::Stop::default();
        let bg = {
            let stop = stop.clone();
            std::thread::Builder::new().name("store-bg".into()).spawn(move || bg::worker(idx, job_rx, done_tx, stop))?
        };
        let segs = log.segments();
        let shape = log.shape();
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
            bg: Some(bg),
            stop,
            segs: (shape, segs),
            pending_zero: VecDeque::new(),
            epoch: 0,
            synced: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            next_cold: log_lists.0,
            cold_runs: log_lists.1,
            retired: log_lists.2,
            log_state: LogState::Idle,
            intent: (Vec::new(), Vec::new()),
            backup_hold: false,
            held_done: Vec::new(),
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
                if b.has_key(&prefix(T_DELETED, &[id, &p])) {
                    return Outcome::Deleted;
                }
                if b.latest_tombstone(&prefix(T_VANISH, &[&p])).is_some_and(|t| t >= ca) {
                    return Outcome::Vanished;
                }
            }
        } else if b.has_key(&prefix(T_DELETED, &[id, pk])) {
            return Outcome::Deleted;
        }
        if b.latest_tombstone(&prefix(T_VANISH, &[pk])).is_some_and(|t| t >= ca) {
            return Outcome::Vanished;
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
        self.publish_staged(s)?.sync()
    }

    /// Publishes a staged batch without waiting for its sync, and returns the
    /// sync still owed. Readers and the rules of the next batch see it at once;
    /// it is durable (and may be acknowledged) only once the ticket's `sync`
    /// returns, which another thread can do while this one stages more.
    pub fn publish_staged(&mut self, s: Staged) -> io::Result<SyncTicket> {
        let Staged { b, offs, base_count } = s;
        if b.new.is_empty() && b.kills.is_empty() {
            return Ok(self.ticket(Vec::new()));
        }
        self.epoch += 1;
        let mut zero = Vec::with_capacity(b.kills.len());
        for &seq in &b.kills {
            let off = if seq >= base_count { offs[(seq - base_count) as usize] } else { locs::get(&b.base.locs, seq) };
            self.log.mark_dead(off)?;
            zero.push(off);
        }
        let mut t = std::time::Instant::now();
        let files = if self.opts.sync { self.log.take_touched()? } else { self.log.flush().map(|_| Vec::new())? };
        lap(0, &mut t);

        self.dead.grow_to(self.next_seq);
        for &seq in &b.kills {
            self.dead.set(seq);
        }
        if !b.keys.is_empty() {
            self.mem.push(Arc::new(MemRun::build(&b.keys)));
            lap(1, &mut t);
            self.merge_mem();
            lap(2, &mut t);
        }
        drop(self.publish());
        self.defer_zero(zero);
        self.reclaim()?;
        self.maybe_flush()?;
        lap(3, &mut t);
        Ok(self.ticket(files))
    }

    fn ticket(&self, files: Vec<Arc<crate::mmap::MappedFile>>) -> SyncTicket {
        SyncTicket { files, seq_end: self.next_seq, durable: self.shared.durable.clone(), epoch: self.epoch, synced: self.synced.clone() }
    }

    /// Makes everything written durable now, whatever tickets are outstanding:
    /// required before anything persistent (a segment flush, a checkpoint) may
    /// rely on it.
    fn barrier(&mut self) -> io::Result<()> {
        if self.shared.durable.load(Ordering::Acquire) >= self.next_seq && self.synced.load(Ordering::Acquire) >= self.epoch {
            return Ok(());
        }
        self.log.sync_all()?;
        self.shared.durable.fetch_max(self.next_seq, Ordering::AcqRel);
        self.synced.fetch_max(self.epoch, Ordering::AcqRel);
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

    /// Kills whichever of `seqs` are still live, in one commit. Returns how many were.
    /// The kills reach disk as dead flags in the log but not yet in a checkpoint:
    /// call [`write_checkpoint`](Self::write_checkpoint) once the last batch is in.
    pub fn kill_live(&mut self, seqs: &[u64]) -> io::Result<usize> {
        let v = self.current();
        let mut live: Vec<u64> = seqs.iter().copied().filter(|&s| v.is_live(s)).collect();
        drop(v);
        live.sort_unstable();
        live.dedup();
        self.kill_seqs(&live)?;
        Ok(live.len())
    }

    /// Operator removal: kills every live event matching any of `filters` (and,
    /// with `older_than`, created strictly before it). Returns how many.
    ///
    /// Not a NIP-09 deletion: no tombstone is kept, so a deleted event can be
    /// published again. The kills go in batches of [`DELETE_BATCH`], each its own
    /// commit. A server that must keep serving writes feeds batches to
    /// `kill_live` between its own instead.
    pub fn delete_matching(&mut self, filters: &[Filter], older_than: Option<u64>, now: u64) -> io::Result<usize> {
        let v = self.current();
        let mut deleted = 0;
        let killed = self.kill_batches(&v, filters, older_than, now, &mut deleted);
        // Until the snapshot is gone the killed records cannot be zeroed. What
        // was killed is made permanent before anything may zero it, even when a
        // batch failed part-way.
        drop(v);
        if deleted > 0 {
            self.write_checkpoint()?;
            self.reclaim()?;
        }
        killed.map(|()| deleted)
    }

    fn kill_batches(&mut self, v: &Version, filters: &[Filter], older_than: Option<u64>, now: u64, deleted: &mut usize) -> io::Result<()> {
        let mut batch = Vec::with_capacity(DELETE_BATCH);
        for hit in v.matching_seqs(filters, older_than, now) {
            batch.push(hit.seq);
            if batch.len() == DELETE_BATCH {
                *deleted += self.kill_live(&batch)?;
                batch.clear();
            }
        }
        *deleted += self.kill_live(&batch)?;
        Ok(())
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
    fn maybe_flush(&mut self) -> io::Result<()> {
        if !self.flushing && self.mem_bytes() >= self.opts.flush_bytes {
            self.start_flush()?;
        }
        Ok(())
    }

    fn start_flush(&mut self) -> io::Result<()> {
        if self.mem.is_empty() {
            return Ok(());
        }
        // The segment will cover every seq below next_seq: they must be durable.
        self.barrier()?;
        self.frozen = self.mem.len();
        self.flushing = true;
        let id = self.next_seg_id;
        self.next_seg_id += 1;
        let job = Job::Flush { id, runs: self.mem.clone(), dead: self.dead.clone(), covered: self.next_seq, replay_from: self.log.head() };
        if self.jobs.send(job).is_err() {
            self.flushing = false;
            self.frozen = 0;
        }
        Ok(())
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
        self.reclaim()?;
        self.step_log_compaction();
        Ok(())
    }

    /// Log compaction, one step at a time: start it when enough sealed hot
    /// segments have built up; relink once no reader can hold a version that
    /// lacks the new cold segments.
    fn step_log_compaction(&mut self) {
        match &self.log_state {
            LogState::Idle => {
                let min = self.opts.log_compact_segments;
                if min == 0 || self.backup_hold {
                    return;
                }
                let sealed = self.log.sealed(self.replay_from);
                if sealed.len() >= min {
                    self.start_log_compaction(sealed);
                } else if let Some(pick) = self.pick_merge() {
                    self.start_merge(pick);
                }
            }
            LogState::Waiting { reg_gen, .. } => {
                let reg_gen = *reg_gen;
                if self.pending_zero.front().is_none_or(|f| f.0 >= reg_gen) {
                    let LogState::Waiting { moves, retire, .. } = std::mem::replace(&mut self.log_state, LogState::Idle) else { unreachable!() };
                    let job = Job::LogRelink { moves, dead: self.dead.clone(), locs: self.locs.map() };
                    if self.jobs.send(job).is_ok() {
                        self.log_state = LogState::Relinking { retire };
                    }
                }
            }
            LogState::Writing | LogState::Relinking { .. } => {}
        }
    }

    fn start_log_compaction(&mut self, hot: Vec<(u64, Arc<crate::mmap::MappedFile>)>) {
        if hot.is_empty() {
            return;
        }
        let job = Job::LogCompact {
            hot,
            first_cold: self.next_cold,
            seg_size: self.log.seg_size(),
            log_dir: self.log.dir().to_path_buf(),
            dead: self.dead.clone(),
            version: self.current(),
            chunk: self.opts.log_chunk_bytes,
        };
        if self.jobs.send(job).is_ok() {
            self.log_state = LogState::Writing;
        }
    }

    /// The runs a merge should combine: the smallest `MERGE_FANIN` whose sizes
    /// are within `MERGE_RATIO` of each other (size tiers, so a record is
    /// rewritten a few times over its life), if the disk has room for the copy.
    fn pick_merge(&self) -> Option<Vec<usize>> {
        if self.cold_runs.len() < MERGE_FANIN {
            return None;
        }
        let mut order: Vec<usize> = (0..self.cold_runs.len()).collect();
        order.sort_by_key(|&i| self.cold_runs[i].1);
        let pick = order.windows(MERGE_FANIN).find(|w| self.cold_runs[w[MERGE_FANIN - 1]].1 <= self.cold_runs[w[0]].1.max(1) * MERGE_RATIO)?;
        self.room_for(pick).then(|| pick.to_vec())
    }

    /// Whether the log's filesystem can hold a copy of these runs (with a margin).
    fn room_for(&self, runs: &[usize]) -> bool {
        let need: u64 = runs.iter().map(|&i| self.cold_runs[i].1).sum();
        crate::mmap::free_bytes(self.log.dir()).is_none_or(|free| free >= need + need / 8 + (64 << 20))
    }

    fn start_merge(&mut self, runs: Vec<usize>) {
        let segs: Vec<Vec<(u64, Arc<crate::mmap::MappedFile>)>> = runs
            .iter()
            .map(|&i| self.cold_runs[i].0.iter().filter_map(|&n| Some((n, self.log.cold_file(n)?))).collect())
            .collect();
        let job = Job::LogMerge {
            runs: segs,
            first_cold: self.next_cold,
            seg_size: self.log.seg_size(),
            log_dir: self.log.dir().to_path_buf(),
            dead: self.dead.clone(),
            version: self.current(),
        };
        if self.jobs.send(job).is_ok() {
            self.log_state = LogState::Writing;
        }
    }

    /// Rewrites every sealed hot segment into clustered cold ones, then merges
    /// all cold runs into one, and waits for both (after a bulk import: one run
    /// means every history is contiguous).
    pub fn compact_log_all(&mut self) -> io::Result<()> {
        self.compact_log_hot()?;
        self.merge_log_runs()
    }

    /// The first half of `compact_log_all`: sealed hot segments into cold runs.
    pub fn compact_log_hot(&mut self) -> io::Result<()> {
        // The rewrite may only take segments a restart would not replay, so the
        // replay point must first move past them: flush_all checkpoints it.
        self.flush_all()?;
        self.settle_log_compaction()?;
        let sealed = self.log.sealed(self.replay_from);
        if !sealed.is_empty() {
            self.start_log_compaction(sealed);
            self.settle_log_compaction()?;
        }
        Ok(())
    }

    /// The second half: every cold run merged into one, if the disk has room.
    pub fn merge_log_runs(&mut self) -> io::Result<()> {
        self.settle_log_compaction()?;
        let all: Vec<usize> = (0..self.cold_runs.len()).collect();
        if all.len() > 1 && self.room_for(&all) {
            self.start_merge(all);
            self.settle_log_compaction()?;
        }
        Ok(())
    }

    /// Starts an online backup (see [`crate::backup`]): a fresh checkpoint, and
    /// a snapshot that pins every file it names until the plan is dropped. Log
    /// compaction holds still until [`end_backup`](Self::end_backup). Cheap: a
    /// flush of queued frames and one checkpoint.
    pub fn begin_backup(&mut self) -> io::Result<crate::backup::Plan> {
        if self.backup_hold {
            return Err(io::Error::new(io::ErrorKind::ResourceBusy, "a backup is already running"));
        }
        self.maintain()?;
        self.log.flush()?;
        self.backup_hold = true;
        if let Err(e) = self.write_checkpoint() {
            self.backup_hold = false;
            return Err(e);
        }
        let checkpoint = match crate::checkpoint::read(&self.dir) {
            Ok(Some(c)) => c,
            Ok(None) => {
                self.backup_hold = false;
                return Err(io::Error::other("no checkpoint after writing one"));
            }
            Err(e) => {
                self.backup_hold = false;
                return Err(e);
            }
        };
        Ok(crate::backup::Plan::new(self.current(), checkpoint, self.log.head(), self.next_seq, self.log.seg_size(), self.dir.clone()))
    }

    /// Ends a backup: log compaction resumes, and a compaction that finished
    /// meanwhile is registered now.
    pub fn end_backup(&mut self) -> io::Result<()> {
        self.backup_hold = false;
        for d in std::mem::take(&mut self.held_done) {
            self.finish_job(d)?;
        }
        self.step_log_compaction();
        Ok(())
    }

    /// Cold runs, as the checkpoint records them.
    pub fn cold_runs(&self) -> usize {
        self.cold_runs.len()
    }

    /// Drives the log compaction in flight to its end without starting another.
    /// Polls: while waiting for old readers to go there is no job to hear from.
    fn settle_log_compaction(&mut self) -> io::Result<()> {
        while !matches!(self.log_state, LogState::Idle) {
            match self.done.recv_timeout(std::time::Duration::from_millis(5)) {
                Ok(d) => self.finish_job(d)?,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return Err(io::Error::other("store worker stopped")),
            }
            self.reclaim()?;
            if !matches!(self.log_state, LogState::Idle) {
                self.step_log_compaction();
            }
        }
        Ok(())
    }

    /// Queues dead records for zeroing once no reader of an older version is left.
    fn defer_zero(&mut self, offs: Vec<u64>) {
        if offs.is_empty() {
            return;
        }
        let epoch = self.epoch;
        match self.pending_zero.back_mut() {
            Some(b) => {
                b.2.extend(offs);
                b.3 = b.3.max(epoch);
            }
            None => {
                let cur = self.current();
                self.pending_zero.push_back((cur.gen, Arc::downgrade(&cur), offs, epoch));
            }
        }
    }

    fn finish_job(&mut self, d: Done) -> io::Result<()> {
        if self.backup_hold && matches!(d, Done::LogCompacted { .. }) {
            self.held_done.push(d);
            return Ok(());
        }
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
                self.maybe_flush()?;
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
            Done::LogCompacted { runs, moves, retire } => {
                // 1. The cold segments join the table; every version from here on can read them.
                let mut intent_cold = Vec::new();
                for run in runs {
                    let mut nums = Vec::with_capacity(run.segs.len());
                    for (n, f) in run.segs {
                        self.log.register_cold(n, f);
                        nums.push(n);
                        intent_cold.push(n);
                        self.next_cold = self.next_cold.max(n + 1);
                    }
                    if !nums.is_empty() {
                        self.cold_runs.push((nums, run.bytes));
                    }
                }
                drop(self.publish());
                let reg_gen = self.current().gen;
                // 2. Record the intent: a crash from here on finishes the exchange at open.
                self.intent = (intent_cold, retire.clone());
                self.write_checkpoint()?;
                // 3. Relink once no reader can hold a version without them.
                self.log_state = LogState::Waiting { reg_gen, moves, retire };
                self.step_log_compaction();
            }
            Done::LogRelinked { moves } => {
                let LogState::Relinking { retire } = std::mem::replace(&mut self.log_state, LogState::Idle) else {
                    return Ok(());
                };
                // Events that died while their copy was being written: the cold
                // copy dies too, and its bytes go like any other dead record's.
                let mut zero = Vec::new();
                for (seq, off) in moves {
                    if self.dead.is_dead(seq) {
                        self.log.mark_dead(off)?;
                        zero.push(off);
                    }
                }
                for &n in &retire {
                    if n >= COLD_BASE {
                        // A merge's input: its whole run goes.
                        self.log.retire_cold(n - COLD_BASE);
                        self.cold_runs.retain(|r| !r.0.contains(&(n - COLD_BASE)));
                    } else {
                        self.log.retire_hot(n);
                        self.retired.push(n);
                    }
                }
                self.intent = (Vec::new(), Vec::new());
                drop(self.publish());
                self.defer_zero(zero);
                self.write_checkpoint()?;
            }
            Done::Failed(msg) => {
                eprintln!("store: background job failed: {msg}");
                self.flushing = false;
                self.frozen = 0;
                self.compacting = false;
            }
            Done::LogFailed(msg) => {
                eprintln!("store: background job failed: {msg}");
                // An unfinished exchange is finished at the next open from its
                // recorded intent (kept in every checkpoint until then), or never
                // happened if it failed before registering. No retries until then.
                self.log_state = LogState::Idle;
                self.opts.log_compact_segments = 0;
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
        self.start_flush()?;
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
    ///
    /// This is also what makes `kill_live` kills survive a restart: unlike a
    /// deletion event or an expiry, they leave no key behind for a restart to
    /// re-derive them from, and the log is replayed only from `replay_from`.
    pub fn write_checkpoint(&mut self) -> io::Result<()> {
        // The dead set may hold kills by batches whose sync is still in flight.
        self.barrier()?;
        self.locs.sync()?;
        let dead_tmp = self.dir.join("dead.bits.tmp");
        std::fs::write(&dead_tmp, self.dead.to_bytes(self.next_seq))?;
        std::fs::File::open(&dead_tmp)?.sync_all()?;
        std::fs::rename(&dead_tmp, self.dir.join("dead.bits"))?;
        let ids: Vec<u64> = self.segments.iter().map(|s| s.id).collect();
        crate::checkpoint::write(
            &self.dir,
            &crate::checkpoint::Checkpoint {
                covered: self.covered,
                replay_from: self.replay_from,
                next_seg_id: self.next_seg_id,
                segments: ids,
                next_cold: self.next_cold,
                cold: self.cold_runs.iter().flat_map(|r| r.0.iter().copied()).collect(),
                run_lens: self.cold_runs.iter().map(|r| r.0.len() as u64).collect(),
                run_bytes: self.cold_runs.iter().map(|r| r.1).collect(),
                retired: self.retired.clone(),
                intent_cold: self.intent.0.clone(),
                intent_retire: self.intent.1.clone(),
            },
        )
    }

    fn publish(&mut self) -> Arc<Version> {
        let shape = self.log.shape();
        if shape != self.segs.0 {
            self.segs = (shape, self.log.segments());
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
        // Tracked until no reader holds it: dead records are zeroed, and old log
        // segments relinked, only once every older version is gone.
        self.pending_zero.push_back((old.gen, Arc::downgrade(&old), Vec::new(), 0));
        old
    }

    /// Zeroes dead records that no live snapshot can reach any more.
    fn reclaim(&mut self) -> io::Result<()> {
        let synced = self.synced.load(Ordering::Acquire);
        while let Some((_, w, _, epoch)) = self.pending_zero.front() {
            if w.strong_count() > 0 || *epoch > synced {
                break;
            }
            let (_, _, offs, _) = self.pending_zero.pop_front().unwrap();
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

    /// Idle-time upkeep that must stay off the latency path: keeps the log's
    /// next region pre-written so syncs overwrite rather than allocate.
    pub fn prepare(&mut self) -> io::Result<()> {
        self.log.prepare()
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
