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

pub mod bg;
pub mod checkpoint;
pub mod crc32c;
pub mod dead;
pub mod keys;
pub mod locs;
pub mod log;
pub mod memrun;
pub mod mmap;
pub mod segment;
pub mod version;
pub mod writer;

pub use version::{Hit, Plan, Version};
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
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

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
}

impl Default for Options {
    fn default() -> Self {
        Options { segment_size: 1 << 30, sync: true, flush_bytes: 64 << 20, vanish_urls: Vec::new(), log_compact_segments: 2, log_chunk_bytes: 0 }
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
    /// Held for as long as the store is open: one process per directory.
    _lock: std::fs::File,
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
    match std::fs::read_to_string(&path) {
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
        Err(e) if e.kind() == io::ErrorKind::NotFound => std::fs::write(&path, want),
        Err(e) => Err(e),
    }
}

/// A cloneable handle readers use to get snapshots.
#[derive(Clone)]
pub struct Store {
    shared: Arc<Shared>,
}

impl Store {
    /// Opens (or creates) a store in `dir`: maps the checkpointed segments and
    /// replays only the log after the checkpoint. Returns the reader handle and
    /// the one writer.
    pub fn open(dir: &Path, opts: Options) -> io::Result<(Store, Writer)> {
        std::fs::create_dir_all(dir)?;
        let lock = lock_dir(dir)?;
        check_meta(dir, &opts)?;
        let idx = dir.join("idx");
        std::fs::create_dir_all(&idx)?;
        let ck = checkpoint::read(dir)?;
        let have_ck = ck.is_some();
        let ck = ck.unwrap_or_default();

        let mut segments = Vec::with_capacity(ck.segments.len());
        for &id in &ck.segments {
            segments.push(Arc::new(Segment::open(id, &bg::seg_path(&idx, id))?));
        }
        // Leftovers of a flush or compaction that never reached a checkpoint.
        for e in std::fs::read_dir(&idx)?.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let listed = name.strip_suffix(".seg").and_then(|n| n.parse::<u64>().ok()).is_some_and(|id| ck.segments.contains(&id));
            if !listed && (name.ends_with(".seg") || name.ends_with(".tmp")) {
                std::fs::remove_file(e.path())?;
            }
        }

        let mut dead = DeadSet::default();
        if have_ck {
            if let Ok(img) = std::fs::read(dir.join("dead.bits")) {
                dead.load(&img);
            }
        }

        let vanish = VanishCfg::new(&opts.vanish_urls);
        let mut locs = LocsWriter::open(&dir.join("locs"))?;
        let mut kb = KeyBuf::default();
        let mut scratch = Vec::new();
        let mut dead_seqs = Vec::new();
        let mut next_seq = ck.covered;
        let mut loc_err: Option<io::Error> = None;
        // A log compaction the last run did not finish: its old hot segments go
        // (their records all have cold copies), and `locs` is re-derived below.
        let mut retired = ck.retired.clone();
        retired.extend(&ck.intent_retire);
        let log = LogWriter::open(&dir.join("log"), opts.segment_size, ck.replay_from, &retired, &ck.cold, |fr: log::Frame<'_>| {
            if loc_err.is_none() {
                if let Err(e) = locs.set(fr.seq, fr.off) {
                    loc_err = Some(e);
                }
            }
            next_seq = next_seq.max(fr.seq + 1);
            if fr.dead {
                dead_seqs.push(fr.seq);
            } else if fr.seq >= ck.covered {
                keys::index_keys(Record(fr.record), fr.seq, &mut kb, &mut scratch, &vanish);
            }
        })?;
        if let Some(e) = loc_err {
            return Err(e);
        }
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
            locs.sync()?;
        }

        dead.grow_to(next_seq);
        for s in dead_seqs {
            dead.set(s);
        }
        // The tail's rule-bearing keys: replaying them re-derives any kill a
        // crash between syncs could have lost.
        let tail: Vec<Vec<u8>> = (0..kb.len())
            .map(|i| kb.key(i))
            .filter(|k| matches!(k[0], keys::T_ADDR | keys::T_DELETED | keys::T_ADDR_DELETED | keys::T_VANISH))
            .map(|k| k.to_vec())
            .collect();
        let mem = if kb.is_empty() { Vec::new() } else { vec![Arc::new(MemRun::build(&kb))] };
        drop(kb);

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
        });
        let shared = Arc::new(Shared { current: RwLock::new(v), gen: AtomicU64::new(0), durable: Arc::new(AtomicU64::new(next_seq)), _lock: lock });
        let finish_intent = !ck.intent_cold.is_empty();
        let mut w = Writer::new(
            shared.clone(),
            log,
            locs,
            dead,
            segments,
            mem,
            next_seq,
            opts,
            dir.to_path_buf(),
            ck.next_seg_id,
            ck.covered,
            ck.replay_from,
            (ck.next_cold, ck.cold.clone(), retired),
        )?;
        if finish_intent {
            w.write_checkpoint()?;
        }
        w.repair(&tail)?;
        // Expiry kills are not re-derived from the tail like rule kills are:
        // one that was not checkpointed is redone before anything is served.
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        w.sweep_expired(now)?;
        Ok((Store { shared }, w))
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
