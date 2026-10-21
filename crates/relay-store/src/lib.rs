//! The storage engine.
//!
//! - An append-only **event log** is the source of truth and the write-ahead log.
//! - **`locs`** maps each event's seq to its place in the log.
//! - An LSM-style **index** of sorted key runs answers every query shape.
//! - A **dead set** marks deleted, replaced and expired events.
//!
//! Everything but the log is derivable from it. One [`Writer`] applies batches;
//! any number of readers take [`Version`] snapshots and never block it.

pub mod crc32c;
pub mod dead;
pub mod keys;
pub mod locs;
pub mod log;
pub mod memrun;
pub mod mmap;
pub mod version;
pub mod writer;

pub use version::{Hit, Plan, Version};
pub use writer::{Outcome, Writer};

use crate::dead::DeadSet;
use crate::keys::KeyBuf;
use crate::locs::LocsWriter;
use crate::log::LogWriter;
use crate::memrun::MemRun;
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
}

impl Default for Options {
    fn default() -> Self {
        Options { segment_size: 1 << 30, sync: true }
    }
}

pub(crate) struct Shared {
    pub(crate) current: RwLock<Arc<Version>>,
    pub(crate) gen: AtomicU64,
}

/// Format version of the data directory.
const FORMAT: u32 = 1;

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
    /// Opens (or creates) a store in `dir`, replaying the log. Returns the reader
    /// handle and the one writer.
    pub fn open(dir: &Path, opts: Options) -> io::Result<(Store, Writer)> {
        std::fs::create_dir_all(dir)?;
        check_meta(dir, &opts)?;
        let mut locs = LocsWriter::open(&dir.join("locs"))?;
        let mut kb = KeyBuf::default();
        let mut scratch = Vec::new();
        let mut dead_seqs = Vec::new();
        let mut next_seq = 0u64;
        let mut loc_err: Option<io::Error> = None;
        let log = LogWriter::open(&dir.join("log"), opts.segment_size, |fr| {
            if loc_err.is_none() {
                if let Err(e) = locs.set(fr.seq, fr.off) {
                    loc_err = Some(e);
                }
            }
            next_seq = next_seq.max(fr.seq + 1);
            if fr.dead {
                dead_seqs.push(fr.seq);
            } else {
                keys::index_keys(Record(fr.record), fr.seq, &mut kb, &mut scratch);
            }
        })?;
        if let Some(e) = loc_err {
            return Err(e);
        }

        let mut dead = DeadSet::default();
        dead.grow_to(next_seq);
        for s in dead_seqs {
            dead.set(s);
        }
        let runs = if kb.is_empty() { Vec::new() } else { vec![Arc::new(MemRun::build(&kb))] };
        drop(kb);

        let v = Arc::new(Version {
            gen: 0,
            count: next_seq,
            seg_size: opts.segment_size,
            segs: log.segments(),
            locs: locs.map(),
            dead: dead.clone(),
            runs: Arc::new(runs.clone()),
        });
        let shared = Arc::new(Shared { current: RwLock::new(v), gen: AtomicU64::new(0) });
        let mut w = Writer::new(shared.clone(), log, locs, dead, runs, next_seq, opts);
        w.repair()?;
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

    /// Replaces `v` with the latest version if a newer one was published.
    #[inline]
    pub fn refresh(&self, v: &mut Arc<Version>) {
        if v.gen != self.generation() {
            *v = self.snapshot();
        }
    }
}
