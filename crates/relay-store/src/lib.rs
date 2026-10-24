//! The storage engine.
//!
//! - An append-only **event log** is the source of truth and the write-ahead log.
//! - **`locs`** maps each event's seq to its place in the log.
//! - An LSM-style **index** of sorted key runs answers every query shape.
//! - A **dead set** marks deleted, replaced and expired events.
//!
//! Everything but the log is derivable from it. One [`Writer`] applies batches;
//! any number of readers take [`Version`] snapshots and never block it. Memory
//! runs flush to segment files in the background, and a checkpoint records which
//! segments cover which part of the log, so a restart replays only the tail.

/// A moment worth crashing at, for the crash tests (see [`fault`]). Expands to
/// nothing in a normal build.
macro_rules! crash_point {
    ($name:literal) => {
        #[cfg(any(test, feature = "fault-injection"))]
        $crate::fault::crash_point($name);
    };
}

pub mod backup;
pub mod bloom;
pub mod bg;
pub mod checkpoint;
pub mod crc32c;
pub mod dead;
#[cfg(any(test, feature = "fault-injection"))]
pub mod fault;
pub mod keys;
pub mod locs;
pub mod log;
pub mod memrun;
pub mod mmap;
pub mod segment;
pub mod verified;
pub mod version;
pub mod writer;

#[cfg(test)]
mod fault_tests;

pub use version::{Hit, Matching, Plan, Version};
pub use writer::{Outcome, Staged, SyncTicket, Writer};

use crate::dead::DeadSet;
use crate::keys::KeyBuf;
use crate::locs::LocsWriter;
use crate::log::LogWriter;
use crate::memrun::MemRun;
use crate::segment::Segment;
use crate::version::Run;
use relay_proto::record::Field;
use relay_proto::Record;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock};

#[derive(Debug, Clone)]
pub struct Options {
    /// Size of each log segment file (sparse until written).
    pub segment_size: u64,
    /// Sync every batch before acknowledging it. Off only for benchmarks that
    /// compare against relays that never sync.
    pub sync: bool,
    /// Memory runs are flushed to a segment once they hold this many bytes.
    /// Smaller uses less RAM; larger means fewer, bigger segments.
    pub flush_bytes: usize,
    /// This relay's own URLs (`wss://host/path`). A NIP-62 request to vanish is
    /// honoured when it names one of them or `ALL_RELAYS`.
    pub vanish_urls: Vec<String>,
    /// Sealed hot log segments that trigger a log compaction (clustering and
    /// space reclaim); 0 never compacts automatically.
    pub log_compact_segments: usize,
    /// Log bytes clustered together in one sort (0: sized from available memory).
    pub log_chunk_bytes: u64,
    /// Check every index block's checksum when opening, and refuse a damaged
    /// index (see `Store::open`). Off only for reading events without the
    /// index, which is how a damaged one is rebuilt (export, then import).
    pub verify_index: bool,
    /// With `verify_index`: open at once and check the blocks on a thread of
    /// their own (see `Store::index_check`), instead of before returning. A
    /// cold 1.5 GB index on a slow disk took 12 s to check, all of it time the
    /// relay could not serve. Reads stay safe meanwhile: every block is checked
    /// the first time a query uses it. A damage found leaves `index-damaged`
    /// in the data directory, and the next open checks before returning.
    pub check_index_in_background: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { segment_size: 1 << 30, sync: true, flush_bytes: 64 << 20, vanish_urls: Vec::new(), log_compact_segments: 2, log_chunk_bytes: 0, verify_index: true, check_index_in_background: false }
    }
}

/// Which NIP-62 requests target this relay.
#[derive(Debug, Clone, Default)]
pub struct VanishCfg {
    urls: Vec<String>,
}

impl VanishCfg {
    pub fn new(urls: &[String]) -> VanishCfg {
        VanishCfg { urls: urls.iter().map(|u| normalize_url(u.as_bytes())).collect() }
    }

    /// True when a `relay` tag says `ALL_RELAYS` or names one of our URLs.
    pub fn targets(&self, rec: Record<'_>) -> bool {
        rec.tags().any(|t| {
            let mut f = t.fields();
            match (f.next(), f.next()) {
                (Some(n), Some(Field::Str(v))) if n.is_str(b"relay") => v == b"ALL_RELAYS" || self.urls.contains(&normalize_url(v)),
                _ => false,
            }
        })
    }
}

/// `wss://Host/path/` and `ws://host/path` compare equal.
fn normalize_url(u: &[u8]) -> String {
    let s = String::from_utf8_lossy(u).trim().to_ascii_lowercase();
    let s = s.strip_prefix("wss://").or_else(|| s.strip_prefix("ws://")).unwrap_or(&s).to_string();
    s.trim_end_matches('/').to_string()
}

pub(crate) struct Shared {
    pub(crate) current: RwLock<Arc<Version>>,
    pub(crate) gen: AtomicU64,
    /// Every seq below this is on disk. Published events above it are visible
    /// (and relayed live) but their sync is still in flight.
    pub(crate) durable: Arc<AtomicU64>,
    /// Records whose checksum has been checked (see `verified`).
    pub(crate) verified: Arc<verified::Verified>,
    /// The background index check, when one was asked for.
    index_check: Arc<(Mutex<IndexCheck>, Condvar)>,
    /// Held for as long as the store is open: one process per directory.
    _lock: std::fs::File,
}

/// Where the check of every index block stands (`Options::check_index_in_background`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexCheck {
    /// Done before the store opened, or not asked for.
    BeforeOpen,
    /// Still reading blocks.
    Running,
    /// Every block's checksum matched.
    Passed { blocks: usize, took: std::time::Duration },
    /// A block did not: the message says which, and how to rebuild.
    Damaged(String),
}

/// Left in the data directory when a damaged index block is found (by the
/// background check, or by a read meeting it first), so the next open checks
/// every block before it returns, and refuses, as it always did.
pub(crate) const INDEX_DAMAGED: &str = "index-damaged";

/// Checks every block of `segments` on `threads` threads; the first damaged
/// one (its segment's path and block number), if any. Each segment's blocks
/// are split across the threads, each reading its share in large pieces
/// (see `Segment::verify_blocks`).
fn check_blocks(segments: &[Arc<Segment>], threads: usize) -> Option<(PathBuf, usize)> {
    std::thread::scope(|s| {
        let mut handles = Vec::new();
        for seg in segments {
            let n = seg.blocks();
            let per = n.div_ceil(threads).max(1);
            for lo in (0..n).step_by(per) {
                let range = lo..(lo + per).min(n);
                handles.push(s.spawn(move || seg.verify_blocks(range).err().map(|b| (seg.path().to_path_buf(), b))));
            }
        }
        handles.into_iter().find_map(|h| h.join().expect("index check"))
    })
}

fn damaged_index(path: &Path, block: usize) -> String {
    format!(
        "index segment {} block {block} is damaged on disk, and a damaged index cannot answer correctly. Every event is still in the log: rebuild with `export` (it reads events without the index) and `import` into an empty data directory, or restore a backup",
        path.display()
    )
}

/// Takes the directory's lock, or says which process holds it. Two writers on
/// one log would corrupt it, and even a read-only command opens the writer
/// (opening repairs and sweeps).
fn lock_dir(dir: &Path) -> io::Result<std::fs::File> {
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsRawFd;
    let mut f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(dir.join("LOCK"))?;
    // SAFETY: plain flock on a descriptor we own.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let mut who = String::new();
        let _ = f.read_to_string(&mut who);
        let who = who.trim();
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("{} is in use by another process{}", dir.display(), if who.is_empty() { String::new() } else { format!(" (pid {who})") }),
        ));
    }
    f.set_len(0)?;
    f.seek(io::SeekFrom::Start(0))?;
    write!(f, "{}", std::process::id())?;
    Ok(f)
}

/// Format version of the data directory.
const FORMAT: u32 = 3;

/// The store's fixed parameters, recorded when it is created. The log addresses
/// records by `offset / segment_size`, so opening it with another segment size
/// would misread every record: refuse instead.
fn check_meta(dir: &Path, opts: &Options) -> io::Result<()> {
    let path = dir.join("meta");
    let want = format!("format {FORMAT}\nsegment_size {}\n", opts.segment_size);
    // Replaced whole or not at all: a crash while creating the store must not
    // leave a file that refuses every later start.
    let create = || -> io::Result<()> {
        let tmp = dir.join("meta.tmp");
        std::fs::write(&tmp, &want)?;
        std::fs::File::open(&tmp)?.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        bg::sync_dir(dir)
    };
    match std::fs::read_to_string(&path) {
        // Empty: written by an earlier version that crashed while creating the
        // store. It is written before anything else, so the store is still new.
        Ok(have) if have.is_empty() => create(),
        Ok(have) => {
            let get = |k: &str| have.lines().find_map(|l| l.strip_prefix(k)?.trim().parse::<u64>().ok());
            if get("format ") != Some(u64::from(FORMAT)) {
                return Err(io::Error::other(format!("{}: unsupported data format (expected format {FORMAT})", path.display())));
            }
            if get("segment_size ") != Some(opts.segment_size) {
                return Err(io::Error::other(format!(
                    "this data folder was created with a segment size of {} MiB; segment_mb cannot change after creation (configured: {} MiB)",
                    get("segment_size ").unwrap_or(0) >> 20,
                    opts.segment_size >> 20
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => create(),
        Err(e) => Err(e),
    }
}

/// A cloneable handle readers use to get snapshots.
#[derive(Clone)]
pub struct Store {
    shared: Arc<Shared>,
}

/// How long each step of `Store::open` took, so a slow start can say why.
#[derive(Clone, Debug, Default)]
pub struct OpenPhases {
    pub steps: Vec<(&'static str, std::time::Duration)>,
    at: Option<std::time::Instant>,
}

impl OpenPhases {
    fn start() -> OpenPhases {
        OpenPhases { steps: Vec::new(), at: Some(std::time::Instant::now()) }
    }

    /// Ends the step `name` here; the next starts.
    fn mark(&mut self, name: &'static str) {
        let now = std::time::Instant::now();
        let at = self.at.replace(now).unwrap_or(now);
        self.steps.push((name, now - at));
    }
}

impl Store {
    /// Opens (or creates) a store in `dir`: maps the checkpointed segments and
    /// replays only the log after the checkpoint. Returns the reader handle and
    /// the one writer.
    pub fn open(dir: &Path, opts: Options) -> io::Result<(Store, Writer)> {
        std::fs::create_dir_all(dir)?;
        let lock = lock_dir(dir)?;
        check_meta(dir, &opts)?;
        let verify_index = opts.verify_index;
        let idx = dir.join("idx");
        std::fs::create_dir_all(&idx)?;
        // Which step of opening failed, for an error an operator can act on.
        let step = |what: &'static str| move |e: io::Error| io::Error::new(e.kind(), format!("{what}: {e}"));
        let mut phases = OpenPhases::start();
        let ck = checkpoint::read(dir)?;
        let have_ck = ck.is_some();
        let ck = ck.unwrap_or_default();

        let mut segments = Vec::with_capacity(ck.segments.len());
        for &id in &ck.segments {
            segments.push(Arc::new(Segment::open(id, &bg::seg_path(&idx, id))?));
        }
        phases.mark("index segments opened");
        // Every block's checksum: a damaged block met by a query later could
        // only stop the relay (and the same query would stop it again after a
        // restart). Before returning, unless asked to do it in the background
        // and no earlier background check found damage.
        let marker = dir.join(INDEX_DAMAGED);
        let in_background = opts.verify_index && opts.check_index_in_background && !marker.exists();
        if opts.verify_index && !in_background {
            let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(2, 8);
            if let Some((path, block)) = check_blocks(&segments, threads) {
                return Err(io::Error::other(damaged_index(&path, block)));
            }
            if marker.exists() {
                std::fs::remove_file(&marker).map_err(step("clearing the damaged-index marker"))?;
            }
            phases.mark("index checked");
        }
        let check_segments = in_background.then(|| segments.clone());
        // Leftovers of a flush or compaction that never reached a checkpoint.
        for e in std::fs::read_dir(&idx).map_err(step("listing the index"))?.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let listed = name.strip_suffix(".seg").and_then(|n| n.parse::<u64>().ok()).is_some_and(|id| ck.segments.contains(&id));
            if !listed && (name.ends_with(".seg") || name.ends_with(".tmp")) {
                std::fs::remove_file(e.path()).map_err(step("removing an unfinished index segment"))?;
            }
        }

        let mut dead = DeadSet::default();
        // Words of a dead.bits without a checksum (written before it had one).
        let mut unchecked_words = None;
        if have_ck {
            // Every checkpoint is written after its dead.bits: without it, or
            // with it damaged, every removal since the store began would be
            // undone. That is a refusal, not a guess.
            let img = std::fs::read(dir.join("dead.bits")).map_err(step("reading dead.bits"))?;
            let words = match img.len() % 8 {
                0 => {
                    unchecked_words = Some(img.len() / 8);
                    &img[..]
                }
                4 => {
                    let (words, crc) = img.split_at(img.len() - 4);
                    if crate::crc32c::crc32c(words) != u32::from_le_bytes(crc.try_into().unwrap()) {
                        return Err(io::Error::other("dead.bits is corrupt (its checksum does not match)"));
                    }
                    words
                }
                _ => return Err(io::Error::other("dead.bits is corrupt (its length is not whole words)")),
            };
            dead.load(words);
        }

        let vanish = VanishCfg::new(&opts.vanish_urls);
        let mut locs = LocsWriter::open(&dir.join("locs")).map_err(step("opening locs"))?;
        let mut kb = KeyBuf::default();
        let mut scratch = Vec::new();
        let mut dead_seqs = Vec::new();
        let mut next_seq = ck.covered;
        let mut loc_err: Option<io::Error> = None;
        // A log compaction or merge the last run did not finish: the segments it
        // replaces go (every live record has a copy in its output), and `locs`
        // is re-derived from that output below.
        let mut retired = ck.retired.clone();
        retired.extend(ck.intent_retire.iter().filter(|&&n| n < log::COLD_BASE));
        let gone_cold: Vec<u64> = ck.intent_retire.iter().filter(|&&n| n >= log::COLD_BASE).map(|n| n - log::COLD_BASE).collect();
        let mut cold_runs: Vec<(Vec<u64>, u64)> = Vec::with_capacity(ck.run_lens.len());
        let mut at = 0;
        for (&len, &bytes) in ck.run_lens.iter().zip(&ck.run_bytes) {
            let nums = ck.cold[at..at + len as usize].to_vec();
            at += len as usize;
            if !nums.iter().any(|n| gone_cold.contains(n)) {
                cold_runs.push((nums, bytes));
            }
        }
        // Runs from before sizes were recorded: what their files hold on disk.
        for run in cold_runs.iter_mut().filter(|r| r.1 == 0) {
            use std::os::unix::fs::MetadataExt;
            run.1 = run.0.iter().filter_map(|&n| std::fs::metadata(log::cold_path(&dir.join("log"), n)).ok()).map(|m| m.blocks() * 512).sum();
        }
        let cold_keep: Vec<u64> = cold_runs.iter().flat_map(|r| r.0.iter().copied()).collect();
        // The segments an unfinished exchange replaces go below, and a kill made
        // after their copies were taken is recorded only in their frames' dead
        // flags (the copies were written first): carry those kills over.
        for &n in &ck.intent_retire {
            let path = if n >= log::COLD_BASE { log::cold_path(&dir.join("log"), n - log::COLD_BASE) } else { log::hot_path(&dir.join("log"), n) };
            if path.exists() {
                dead_seqs.extend(log::flagged_dead(&path, opts.segment_size)?);
            }
        }
        phases.mark("dead set and locations loaded");
        let log = LogWriter::open(&dir.join("log"), opts.segment_size, ck.replay_from, ck.covered, &retired, &cold_keep, |fr: log::Frame<'_>| {
            if loc_err.is_none() {
                if let Err(e) = locs.set(fr.seq, fr.off) {
                    loc_err = Some(e);
                }
            }
            next_seq = next_seq.max(fr.seq + 1);
            if fr.dead {
                dead_seqs.push(fr.seq);
                // An event of the tail that died still decided things before it
                // did: the slot it took from an older event, its tombstones, a
                // vanish. Its keys bring those back for `repair` (its bytes are
                // kept until a segment covers it, see `zero_when_covered`).
                if fr.seq >= ck.covered && fr.intact {
                    keys::index_keys(Record(fr.record), fr.seq, &mut kb, &mut scratch, &vanish);
                }
            } else if fr.seq >= ck.covered {
                keys::index_keys(Record(fr.record), fr.seq, &mut kb, &mut scratch, &vanish);
            }
        })
        .map_err(step("replaying the log"))?;
        if let Some(e) = loc_err {
            return Err(e);
        }
        crash_point!("open.replayed");
        phases.mark("log tail replayed");
        if !ck.intent_cold.is_empty() {
            let segs = log.segments();
            for &n in &ck.intent_cold {
                let Some(f) = segs.file(log::COLD_BASE + n) else { continue };
                let mut err = None;
                log::scan_cold(f, opts.segment_size, n, |fr| {
                    if fr.dead {
                        // Its hot copy is gone: whatever killed it must hold.
                        dead_seqs.push(fr.seq);
                    } else if err.is_none() && !dead.is_dead(fr.seq) {
                        if let Err(e) = locs.set(fr.seq, fr.off) {
                            err = Some(e);
                        }
                    }
                });
                if let Some(e) = err {
                    return Err(e);
                }
            }
            locs.sync().map_err(step("finishing an interrupted log compaction"))?;
        }

        // One without a checksum is at least as long as the checkpoint's
        // indexed part of the log, and never longer than the log: one that is
        // not was damaged (cut, or padded out to whole words).
        if unchecked_words.is_some_and(|w| (w as u64) < ck.covered.div_ceil(64) || w as u64 > next_seq.div_ceil(64)) {
            return Err(io::Error::other("dead.bits is corrupt (its length does not match the log)"));
        }
        dead.grow_to(next_seq);
        // A dead frame naming a seq past the end names no record (a damaged
        // frame whose checksum could not be checked): nothing to kill.
        for s in dead_seqs.into_iter().filter(|&s| s < next_seq) {
            dead.set(s);
        }
        // The tail's rule-bearing keys: replaying them re-derives any kill a
        // crash between syncs could have lost.
        let tail: Vec<Vec<u8>> = (0..kb.len())
            .map(|i| kb.key(i))
            .filter(|k| matches!(k[0], keys::T_ID | keys::T_ADDR | keys::T_DELETED | keys::T_ADDR_DELETED | keys::T_VANISH))
            .map(|k| k.to_vec())
            .collect();
        let mem = if kb.is_empty() { Vec::new() } else { vec![Arc::new(MemRun::build(&kb))] };
        drop(kb);

        let mem_bloom = writer::mem_bloom(&opts, &mem);
        let verified = Arc::new(verified::Verified::default());
        let mut runs: Vec<Run> = segments.iter().map(|s| Run::Disk(s.clone())).collect();
        runs.extend(mem.iter().map(|m| Run::Mem(m.clone())));
        let v = Arc::new(Version {
            gen: 0,
            count: next_seq,
            seg_size: opts.segment_size,
            segs: log.segments(),
            locs: locs.map(),
            dead: dead.clone(),
            runs: Arc::new(runs),
            mem_start: segments.len(),
            mem_bloom: mem_bloom.clone(),
            verified: verified.clone(),
        });
        let index_check = Arc::new((Mutex::new(if in_background { IndexCheck::Running } else { IndexCheck::BeforeOpen }), Condvar::new()));
        let shared = Arc::new(Shared {
            current: RwLock::new(v),
            gen: AtomicU64::new(0),
            durable: Arc::new(AtomicU64::new(next_seq)),
            verified,
            index_check: index_check.clone(),
            _lock: lock,
        });
        let finish_intent = !ck.intent_cold.is_empty();
        let mut w = Writer::new(
            shared.clone(),
            log,
            locs,
            dead,
            segments,
            mem,
            mem_bloom,
            next_seq,
            opts,
            dir.to_path_buf(),
            ck.next_seg_id,
            ck.covered,
            ck.replay_from,
            (ck.next_cold, cold_runs, retired),
        )?;
        if finish_intent {
            w.write_checkpoint().map_err(step("recording a finished log compaction"))?;
            crash_point!("open.intent_finished");
        }
        phases.mark("in-memory index built");
        let repaired = w.repair(&tail).map_err(step("re-applying the replayed tail's rules"))?;
        // Kills re-derived just now rest on tail events that may themselves die
        // before the next checkpoint, taking the evidence with them: record them.
        if repaired > 0 {
            w.write_checkpoint().map_err(step("recording the re-applied rules"))?;
        }
        crash_point!("open.repaired");
        phases.mark("tail rules re-applied");
        // Expiry kills are not re-derived from the tail like rule kills are:
        // one that was not checkpointed is redone before anything is served.
        // (Not when opened without trusting the index: the sweep reads it, and
        // such an open is for an export, whose import sweeps them anyway.)
        if verify_index {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            w.sweep_expired(now).map_err(step("removing expired events"))?;
            phases.mark("expired events removed");
        }
        w.open_phases = phases;
        if let Some(segments) = check_segments {
            // Two threads: the relay is serving, and this is a background job.
            std::thread::Builder::new()
                .name("index-check".into())
                .spawn(move || {
                    let t = std::time::Instant::now();
                    let state = match check_blocks(&segments, 2) {
                        None => IndexCheck::Passed { blocks: segments.iter().map(|s| s.blocks()).sum(), took: t.elapsed() },
                        Some((path, block)) => {
                            let msg = damaged_index(&path, block);
                            // Best effort: without it the next open checks in the background again.
                            let _ = std::fs::write(&marker, &msg);
                            IndexCheck::Damaged(msg)
                        }
                    };
                    let (lock, ready) = &*index_check;
                    *lock.lock().unwrap() = state;
                    ready.notify_all();
                })
                .map_err(step("starting the index check"))?;
        }
        Ok((Store { shared }, w))
    }

    /// Where the check of every index block stands.
    pub fn index_check(&self) -> IndexCheck {
        self.shared.index_check.0.lock().unwrap().clone()
    }

    /// Waits for a background index check to finish, and says how it ended.
    pub fn wait_index_check(&self) -> IndexCheck {
        let (lock, ready) = &*self.shared.index_check;
        let mut g = lock.lock().unwrap();
        while *g == IndexCheck::Running {
            g = ready.wait(g).unwrap();
        }
        g.clone()
    }

    /// The latest published version.
    #[inline]
    pub fn snapshot(&self) -> Arc<Version> {
        self.shared.current.read().unwrap().clone()
    }

    /// Bumped on every publish; compare with `Version::gen` to refresh a cached
    /// snapshot without touching the lock.
    #[inline]
    pub fn generation(&self) -> u64 {
        self.shared.gen.load(Ordering::Acquire)
    }

    /// Seqs below this are durable. A published event at or above it must not
    /// be acknowledged (even as a duplicate) until its sync completes.
    #[inline]
    pub fn durable_seq(&self) -> u64 {
        self.shared.durable.load(Ordering::Acquire)
    }

    /// Replaces `v` with the latest version if a newer one was published.
    #[inline]
    pub fn refresh(&self, v: &mut Arc<Version>) {
        if v.gen != self.generation() {
            *v = self.snapshot();
        }
    }
}
