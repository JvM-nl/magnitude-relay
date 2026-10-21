//! `locs`: seq → global log offset, a dense array of u64 in a mapped file.
//!
//! The indirection is what lets compaction move records (clustering cold data
//! by reader) without touching a single index key. It is derivable from the
//! log, so it is never fsynced on the write path; a crash just means replaying
//! the log tail into it.

use crate::mmap::MappedFile;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Initial capacity: 16M events (128 MiB of sparse file).
const INITIAL_CAP: u64 = 1 << 24;

pub struct LocsWriter {
    path: PathBuf,
    map: Arc<MappedFile>,
    cap: u64,
}

impl LocsWriter {
    pub fn open(path: &Path) -> io::Result<LocsWriter> {
        let existing = std::fs::metadata(path).map(|m| m.len() / 8).unwrap_or(0);
        let cap = existing.max(INITIAL_CAP).next_power_of_two();
        let map = Arc::new(MappedFile::open(path, (cap * 8) as usize)?);
        Ok(LocsWriter { path: path.to_path_buf(), map, cap })
    }

    /// The current mapping, for snapshots. Grows by remapping: old snapshots keep
    /// the old (still valid, smaller) mapping alive through their `Arc`.
    pub fn map(&self) -> Arc<MappedFile> {
        self.map.clone()
    }

    pub fn set(&mut self, seq: u64, off: u64) -> io::Result<()> {
        if seq >= self.cap {
            let cap = (seq + 1).next_power_of_two();
            self.map = Arc::new(MappedFile::open(&self.path, (cap * 8) as usize)?);
            self.cap = cap;
        }
        self.map.write_at(seq * 8, &off.to_le_bytes())
    }

    pub fn sync(&self) -> io::Result<()> {
        self.map.sync()
    }
}

#[inline]
pub fn get(map: &MappedFile, seq: u64) -> u64 {
    map.read_u64((seq * 8) as usize)
}
