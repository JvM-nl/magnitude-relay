//! The event log: append-only segment files, the store's source of truth.
//!
//! ```text
//! frame = len u32 | flags u32 | seq u64 | crc32c u32 | record[len]
//! ```
//!
//! Every frame carries its own seq, so the log can be replayed into `locs` even
//! after compaction has reordered records. A frame never spans segments; the
//! unused tail of a segment is zeros, and a zero `len` means "continue in the
//! next segment". A dead frame keeps its length (so scans can step over it) and
//! has its record bytes zeroed once no reader can still be looking at them.

use crate::crc32c::crc32c;
use crate::mmap::{Advice, MappedFile};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const FRAME_HEADER: usize = 20;
pub const FLAG_DEAD: u32 = 1;
/// Records are at most an event plus overhead; anything larger is corruption.
pub const MAX_RECORD: usize = 4 << 20;

pub type Segs = Arc<[Arc<MappedFile>]>;

fn seg_path(dir: &Path, n: usize) -> PathBuf {
    dir.join(format!("{n:08}.log"))
}

/// Reads the record at global offset `off`. The caller guarantees `off` is a
/// published, live frame.
#[inline]
pub fn record_at(segs: &[Arc<MappedFile>], seg_size: u64, off: u64) -> &[u8] {
    let seg = &segs[(off / seg_size) as usize];
    let o = (off % seg_size) as usize;
    let len = seg.read_u32(o) as usize;
    seg.slice(o + FRAME_HEADER, len)
}

/// One frame found while replaying.
pub struct Frame<'a> {
    pub off: u64,
    pub seq: u64,
    pub dead: bool,
    pub record: &'a [u8],
}

/// Bytes kept written (zeroed) ahead of the head, and the step they are added in.
const ZERO_MARGIN: u64 = 16 << 20;
const ZERO_STEP: u64 = 8 << 20;

pub struct LogWriter {
    dir: PathBuf,
    seg_size: u64,
    files: Vec<Arc<MappedFile>>,
    /// Global offset where the next frame goes.
    head: u64,
    /// Everything below this global offset has been written (frames or zeros),
    /// so a sync of new frames there overwrites blocks instead of filling holes:
    /// on ext4 that skips the journal commit, 5.8 ms -> 1.4 ms per fdatasync on
    /// the production box.
    zeroed_to: u64,
    buf: Vec<u8>,
    buf_start: u64,
    touched: BTreeSet<usize>,
}

impl LogWriter {
    /// Opens the log in `dir`, replaying every frame from global offset `from`
    /// (a checkpoint's replay point; 0 for all) through `f` in log order. A torn
    /// tail (crc mismatch at the end of the last segment) is cut off.
    pub fn open(dir: &Path, seg_size: u64, from: u64, mut f: impl FnMut(Frame<'_>)) -> io::Result<LogWriter> {
        std::fs::create_dir_all(dir)?;
        let mut names: Vec<usize> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.strip_suffix(".log")?.parse().ok())
            .collect();
        names.sort_unstable();
        for (i, &n) in names.iter().enumerate() {
            if n != i {
                return Err(io::Error::other(format!("log segment {i:08}.log is missing")));
            }
        }
        let mut files = Vec::with_capacity(names.len().max(1));
        for &n in &names {
            files.push(Arc::new(MappedFile::open(&seg_path(dir, n), seg_size as usize)?));
        }
        if files.is_empty() {
            files.push(Arc::new(MappedFile::open(&seg_path(dir, 0), seg_size as usize)?));
        }

        let from_seg = (from / seg_size) as usize;
        if from_seg >= files.len() {
            return Err(io::Error::other(format!("checkpoint replay point {from} is past the end of the log")));
        }
        let mut head = 0u64;
        // Segments past the head may exist already, pre-created and zeroed by
        // `prepare`. The real last segment is the last one holding any frame.
        let mut last = files.len() - 1;
        while last > from_seg && files[last].read_u32(0) == 0 {
            last -= 1;
        }
        for (si, seg) in files.iter().enumerate() {
            if si < from_seg || si > last {
                continue;
            }
            seg.advise(Advice::Sequential);
            let base = si as u64 * seg_size;
            let mut o = if si == from_seg { (from % seg_size) as usize } else { 0 };
            // (where the good frames end, whether they ended cleanly)
            let (end, clean) = loop {
                if o + FRAME_HEADER > seg_size as usize {
                    break (o, true);
                }
                let len = seg.read_u32(o) as usize;
                if len == 0 {
                    break (o, true);
                }
                let flags = seg.read_u32(o + 4);
                let seq = seg.read_u64(o + 8);
                let crc = seg.read_u32(o + 16);
                if len > MAX_RECORD || o + FRAME_HEADER + len > seg_size as usize {
                    break (o, false);
                }
                let record = seg.slice(o + FRAME_HEADER, len);
                let dead = flags & FLAG_DEAD != 0;
                if !dead && crc32c(record) != crc {
                    break (o, false);
                }
                f(Frame { off: base + o as u64, seq, dead, record });
                o += FRAME_HEADER + len;
            };
            if si == last {
                head = base + end as u64;
                // Whatever follows the last good frame was never acknowledged.
                if !clean || end < seg_size as usize {
                    seg.zero_from(end as u64)?;
                }
            } else if !clean {
                return Err(io::Error::other(format!("corrupt frame inside sealed segment {si:08}.log at byte {end}")));
            }
            seg.advise(Advice::Random);
        }
        Ok(LogWriter { dir: dir.to_path_buf(), seg_size, files, head, zeroed_to: head, buf: Vec::new(), buf_start: head, touched: BTreeSet::new() })
    }

    pub fn segments(&self) -> Segs {
        self.files.iter().cloned().collect()
    }

    #[inline]
    pub fn seg_size(&self) -> u64 {
        self.seg_size
    }

    /// Queues a frame; returns its global offset. Nothing is on disk until
    /// [`flush`](Self::flush) and [`sync`](Self::sync).
    pub fn append(&mut self, seq: u64, record: &[u8]) -> io::Result<u64> {
        let frame = FRAME_HEADER + record.len();
        assert!(record.len() <= MAX_RECORD && frame as u64 <= self.seg_size, "record too large for a segment");
        if self.head % self.seg_size + frame as u64 > self.seg_size {
            self.flush()?;
            let next = self.head / self.seg_size + 1;
            self.head = next * self.seg_size;
            self.buf_start = self.head;
            let n = next as usize;
            if n == self.files.len() {
                self.files.push(Arc::new(MappedFile::open(&seg_path(&self.dir, n), self.seg_size as usize)?));
            }
        }
        let off = self.head;
        self.buf.extend_from_slice(&(record.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(&0u32.to_le_bytes());
        self.buf.extend_from_slice(&seq.to_le_bytes());
        self.buf.extend_from_slice(&crc32c(record).to_le_bytes());
        self.buf.extend_from_slice(record);
        self.head += frame as u64;
        Ok(off)
    }

    /// Writes queued frames to their segment (one `pwrite`).
    pub fn flush(&mut self) -> io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let si = (self.buf_start / self.seg_size) as usize;
        self.files[si].write_at(self.buf_start % self.seg_size, &self.buf)?;
        self.touched.insert(si);
        self.buf.clear();
        self.buf_start = self.head;
        Ok(())
    }

    /// Flags the frame at `off` dead. Readers never look at flags, so this is
    /// safe to do immediately; the record bytes are zeroed later (`zero_record`).
    pub fn mark_dead(&mut self, off: u64) -> io::Result<()> {
        let si = (off / self.seg_size) as usize;
        self.files[si].write_at(off % self.seg_size + 4, &FLAG_DEAD.to_le_bytes())?;
        self.touched.insert(si);
        Ok(())
    }

    /// Overwrites a dead record's bytes with zeros, so deleted content does not
    /// linger on disk. Only once no snapshot that could read it is alive.
    pub fn zero_record(&mut self, off: u64) -> io::Result<()> {
        let si = (off / self.seg_size) as usize;
        let seg = &self.files[si];
        let o = off % self.seg_size;
        let len = seg.read_u32(o as usize) as usize;
        const ZEROS: [u8; 4096] = [0; 4096];
        let mut done = 0;
        while done < len {
            let n = (len - done).min(ZEROS.len());
            seg.write_at(o + FRAME_HEADER as u64 + done as u64, &ZEROS[..n])?;
            done += n;
        }
        self.touched.insert(si);
        Ok(())
    }

    /// Writes queued frames and hands over the segments written since the last
    /// call, for a sync on another thread.
    pub fn take_touched(&mut self) -> io::Result<Vec<Arc<MappedFile>>> {
        self.flush()?;
        let files = self.touched.iter().map(|&si| self.files[si].clone()).collect();
        self.touched.clear();
        Ok(files)
    }

    /// Syncs every segment file: a barrier after which everything ever written
    /// is durable, whoever was due to sync it. A sync of a clean file costs
    /// next to nothing, and this runs only before checkpoints.
    pub fn sync_all(&mut self) -> io::Result<()> {
        self.flush()?;
        for f in &self.files {
            f.sync()?;
        }
        self.touched.clear();
        Ok(())
    }

    /// Makes everything written so far durable.
    pub fn sync(&mut self) -> io::Result<()> {
        self.flush()?;
        for &si in &self.touched {
            self.files[si].sync()?;
        }
        self.touched.clear();
        Ok(())
    }

    #[inline]
    pub fn head(&self) -> u64 {
        self.head
    }

    /// Keeps the region ahead of the head written with zeros (call when idle,
    /// off the latency path). Never touches `[buf_start, head)`, which holds
    /// queued frames, or anything below the head.
    pub fn prepare(&mut self) -> io::Result<()> {
        self.zeroed_to = self.zeroed_to.max(self.head);
        if self.zeroed_to >= self.head + ZERO_MARGIN {
            return Ok(());
        }
        let mut from = self.zeroed_to;
        let si = (from / self.seg_size) as usize;
        if si >= self.files.len() {
            if si != self.files.len() {
                return Ok(());
            }
            self.files.push(Arc::new(MappedFile::open(&seg_path(&self.dir, si), self.seg_size as usize)?));
        }
        let seg_end = (si as u64 + 1) * self.seg_size;
        let to = (from + ZERO_STEP).min(seg_end);
        static ZEROS: [u8; 256 * 1024] = [0; 256 * 1024];
        let seg = &self.files[si];
        while from < to {
            let n = ((to - from) as usize).min(ZEROS.len());
            seg.write_at(from % self.seg_size, &ZEROS[..n])?;
            from += n as u64;
        }
        seg.start_writeback(self.zeroed_to % self.seg_size, to - self.zeroed_to);
        self.zeroed_to = if to == seg_end { seg_end } else { to };
        Ok(())
    }
}
