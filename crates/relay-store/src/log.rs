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
//!
//! Two kinds of segment share one offset space. **Hot** segments (`log/N.log`)
//! receive appends in arrival order. **Cold** segments (`log/cold/N.log`) are
//! written by log compaction: the live records of sealed hot segments, sorted
//! by how they are read (a recipient's gift wraps together, an author's events
//! together), so a mailbox or a channel history is a few sequential reads even
//! when the log is far larger than RAM. Retired hot segments leave gaps.

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
/// Segment indexes at or above this address cold segments (offsets stay below
/// 2^56 even with 4 GiB segments).
pub const COLD_BASE: u64 = 1 << 24;

/// The segment files a version can read, hot and cold.
#[derive(Clone)]
pub struct Segs {
    pub hot: Arc<[Option<Arc<MappedFile>>]>,
    pub cold: Arc<[Option<Arc<MappedFile>>]>,
}

impl Segs {
    #[inline]
    pub fn file(&self, idx: u64) -> Option<&Arc<MappedFile>> {
        if idx >= COLD_BASE {
            self.cold.get((idx - COLD_BASE) as usize)?.as_ref()
        } else {
            self.hot.get(idx as usize)?.as_ref()
        }
    }
}

pub fn hot_path(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("{n:08}.log"))
}

pub fn cold_path(dir: &Path, n: u64) -> PathBuf {
    dir.join("cold").join(format!("{n:08}.log"))
}

/// The record at global offset `off`, if the frame there is `seq`'s and whole
/// by its header. After damage on disk, what `locs` points at may be another
/// frame, a zeroed or cut one, or a segment that is gone: such a record is
/// missing, never another event's.
#[inline]
pub fn record_of(segs: &Segs, seg_size: u64, off: u64, seq: u64) -> Option<&[u8]> {
    let seg = segs.file(off / seg_size)?;
    let o = (off % seg_size) as usize;
    if o + FRAME_HEADER > seg_size as usize {
        return None;
    }
    let len = seg.read_u32(o) as usize;
    if seg.read_u64(o + 8) != seq || len < relay_proto::record::HEADER_LEN || o + FRAME_HEADER + len > seg_size as usize {
        return None;
    }
    Some(seg.slice(o + FRAME_HEADER, len))
}

/// Whether `rec`, read by [`record_of`] at `off`, matches its frame's checksum.
#[inline]
pub fn record_crc_ok(segs: &Segs, seg_size: u64, off: u64, rec: &[u8]) -> bool {
    segs.file(off / seg_size).is_some_and(|seg| crc32c(rec) == seg.read_u32((off % seg_size) as usize + 16))
}

/// Records found damaged on read (they are skipped), since the process started.
pub static DAMAGED_READS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Counts a record that failed its checksum on read, and says so for the first few.
#[cold]
pub fn report_damaged(seq: u64) {
    let n = DAMAGED_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n < 16 {
        eprintln!("store: record {seq} fails its checksum: it is damaged on disk and is skipped (a backup or a re-import restores it)");
    }
}

/// Whether the frame at `off` still matches the checksum it was written with.
pub fn frame_intact(segs: &Segs, seg_size: u64, off: u64) -> bool {
    let Some(seg) = segs.file(off / seg_size) else { return false };
    let o = (off % seg_size) as usize;
    let len = seg.read_u32(o) as usize;
    len <= MAX_RECORD && o + FRAME_HEADER + len <= seg_size as usize && crc32c(seg.slice(o + FRAME_HEADER, len)) == seg.read_u32(o + 16)
}

/// Whether the frame at global offset `off` is flagged dead (false when its
/// segment is gone).
pub fn frame_dead(segs: &Segs, seg_size: u64, off: u64) -> bool {
    segs.file(off / seg_size).is_some_and(|seg| seg.read_u32((off % seg_size) as usize + 4) & FLAG_DEAD != 0)
}

/// One frame found while replaying.
pub struct Frame<'a> {
    pub off: u64,
    pub seq: u64,
    pub dead: bool,
    /// The record's bytes match its checksum (a dead record may be zeroed).
    pub intact: bool,
    pub record: &'a [u8],
}

/// Bytes kept written (zeroed) ahead of the head, and the step they are added in.
const ZERO_MARGIN: u64 = 16 << 20;
const ZERO_STEP: u64 = 8 << 20;

pub struct LogWriter {
    dir: PathBuf,
    seg_size: u64,
    hot: Vec<Option<Arc<MappedFile>>>,
    cold: Vec<Option<Arc<MappedFile>>>,
    /// Global offset where the next frame goes.
    head: u64,
    /// Everything below this global offset has been written (frames or zeros),
    /// so a sync of new frames there overwrites blocks instead of filling holes:
    /// on ext4 that skips the journal commit, 5.8 ms -> 1.4 ms per fdatasync on
    /// the production box.
    zeroed_to: u64,
    buf: Vec<u8>,
    buf_start: u64,
    /// Global segment indexes written since the last sync.
    touched: BTreeSet<u64>,
    /// What an append that failed may have left on disk from the head on
    /// (global offsets), still to be zeroed: see `abandon`.
    junk: Option<(u64, u64)>,
}

/// Scans the frames of one segment from byte `o`, calling `f` for each good one.
/// Returns where the good frames end and whether they ended cleanly. With
/// `trust_len` (a segment written whole and synced before use), a crc mismatch
/// is a record zeroed after its copy was taken: reported dead, not an end.
///
/// With `expect`, frames must carry consecutive seqs from it on: one that
/// does not ends the scan as not clean.
fn scan(seg: &MappedFile, seg_size: u64, base: u64, mut o: usize, trust_len: bool, mut expect: Option<&mut u64>, f: &mut impl FnMut(Frame<'_>)) -> (usize, bool) {
    loop {
        if o + FRAME_HEADER > seg_size as usize {
            return (o, true);
        }
        let len = seg.read_u32(o) as usize;
        if len == 0 {
            return (o, true);
        }
        let flags = seg.read_u32(o + 4);
        let seq = seg.read_u64(o + 8);
        let crc = seg.read_u32(o + 16);
        if len > MAX_RECORD || o + FRAME_HEADER + len > seg_size as usize {
            return (o, false);
        }
        let record = seg.slice(o + FRAME_HEADER, len);
        let intact = crc32c(record) == crc;
        let mut dead = flags & FLAG_DEAD != 0;
        if !dead && !intact {
            if !trust_len {
                return (o, false);
            }
            dead = true;
        }
        if let Some(e) = expect.as_deref_mut() {
            if seq != *e {
                return (o, false);
            }
            *e += 1;
        }
        f(Frame { off: base + o as u64, seq, dead, intact, record });
        o += FRAME_HEADER + len;
    }
}

/// The seqs of every frame flagged dead in the segment file at `path`. For
/// segments an interrupted exchange replaces: a kill made after their copy
/// was taken is recorded only in their flags.
pub fn flagged_dead(path: &Path, seg_size: u64) -> io::Result<Vec<u64>> {
    let seg = MappedFile::open(path, seg_size as usize)?;
    let mut out = Vec::new();
    let mut o = 0usize;
    while o + FRAME_HEADER <= seg_size as usize {
        let len = seg.read_u32(o) as usize;
        if len == 0 || len > MAX_RECORD || o + FRAME_HEADER + len > seg_size as usize {
            break;
        }
        if seg.read_u32(o + 4) & FLAG_DEAD != 0 {
            out.push(seg.read_u64(o + 8));
        }
        o += FRAME_HEADER + len;
    }
    Ok(out)
}

/// Every frame of a cold segment (used when finishing an interrupted compaction).
pub fn scan_cold(seg: &MappedFile, seg_size: u64, n: u64, mut f: impl FnMut(Frame<'_>)) {
    scan(seg, seg_size, (COLD_BASE + n) * seg_size, 0, true, None, &mut f);
}

/// Every frame of a sealed hot segment, in order (log compaction's input).
/// Sealed segments were synced whole, so a crc mismatch is a record being
/// zeroed under the scan (reported dead). False if the frames did not end
/// cleanly: the segment is damaged and must not be retired.
pub fn scan_hot(seg: &MappedFile, seg_size: u64, n: u64, mut f: impl FnMut(Frame<'_>)) -> bool {
    scan(seg, seg_size, n * seg_size, 0, true, None, &mut f).1
}

impl LogWriter {
    /// Opens the log in `dir`, replaying every hot frame from global offset
    /// `from` (a checkpoint's replay point; 0 for all) through `f` in log order.
    /// A torn tail (crc mismatch at the end of the last segment) is cut off.
    /// `retired` hot segments may be missing (and are removed if present);
    /// `cold` lists the cold segments in use (unlisted ones are leftovers of a
    /// compaction that never finished, and are removed).
    /// Replays the log from `from`, whose first frame is seq `first_seq`.
    pub fn open(dir: &Path, seg_size: u64, from: u64, first_seq: u64, retired: &[u64], cold: &[u64], mut f: impl FnMut(Frame<'_>)) -> io::Result<LogWriter> {
        std::fs::create_dir_all(dir.join("cold"))?;
        let mut names: Vec<u64> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str()?.strip_suffix(".log")?.parse().ok())
            .collect();
        names.sort_unstable();
        let mut hot: Vec<Option<Arc<MappedFile>>> = Vec::new();
        let top = names.last().copied().unwrap_or(0);
        for i in 0..=top {
            if retired.contains(&i) {
                let _ = std::fs::remove_file(hot_path(dir, i));
                hot.push(None);
            } else if names.binary_search(&i).is_ok() || (names.is_empty() && i == 0) {
                hot.push(Some(Arc::new(MappedFile::open(&hot_path(dir, i), seg_size as usize)?)));
            } else {
                return Err(io::Error::other(format!("log segment {i:08}.log is missing")));
            }
        }
        for e in std::fs::read_dir(dir.join("cold"))?.flatten() {
            let n: Option<u64> = e.file_name().to_str().and_then(|s| s.strip_suffix(".log")?.parse().ok());
            if n.is_none_or(|n| !cold.contains(&n)) {
                std::fs::remove_file(e.path())?;
            }
        }
        let mut cold_files: Vec<Option<Arc<MappedFile>>> = Vec::new();
        for &n in cold {
            let i = n as usize;
            if cold_files.len() <= i {
                cold_files.resize(i + 1, None);
            }
            cold_files[i] = Some(Arc::new(MappedFile::open(&cold_path(dir, n), seg_size as usize)?));
        }

        let from_seg = (from / seg_size) as usize;
        if from_seg >= hot.len() || hot[from_seg].is_none() {
            return Err(io::Error::other(format!("checkpoint replay point {from} is not in the log")));
        }
        // Segments past the head may exist already, pre-created and zeroed by
        // `prepare`. The real last segment is the last one holding any frame.
        let mut last = hot.len() - 1;
        while last > from_seg && hot[last].as_ref().is_none_or(|s| s.read_u32(0) == 0) {
            last -= 1;
        }
        // The log ends at the first frame that is torn or out of sequence,
        // whatever segment it is in. A power cut can keep a later page and lose
        // an earlier one, both unsynced: a batch spanning two segments may be
        // torn in the first and whole in the second. Nothing from the first
        // lost frame on was acknowledged (a batch is acknowledged only once it
        // and every batch before it are synced), so it all goes; replaying the
        // rest would give seqs whose frames are gone.
        let mut head = 0u64;
        let mut expect = first_seq;
        let mut ended = false;
        for (si, slot) in hot.iter().enumerate().take(last + 1).skip(from_seg) {
            let Some(seg) = slot.clone() else { continue };
            let base = si as u64 * seg_size;
            if ended {
                seg.zero_from(0)?;
                continue;
            }
            seg.advise(Advice::Sequential);
            let start = if si == from_seg { (from % seg_size) as usize } else { 0 };
            let (end, clean) = scan(&seg, seg_size, base, start, false, Some(&mut expect), &mut f);
            seg.advise(Advice::Random);
            if si == last || !clean {
                head = base + end as u64;
                // Whatever follows the last good frame was never acknowledged.
                if !clean || end < seg_size as usize {
                    seg.zero_from(end as u64)?;
                }
                if si != last {
                    eprintln!("store: the log ends at byte {end} of {si:08}.log (a torn or out-of-sequence frame); what follows was never acknowledged and is dropped");
                }
                ended = true;
            }
        }
        Ok(LogWriter {
            dir: dir.to_path_buf(),
            seg_size,
            hot,
            cold: cold_files,
            head,
            zeroed_to: head,
            buf: Vec::new(),
            buf_start: head,
            touched: BTreeSet::new(),
            junk: None,
        })
    }

    pub fn segments(&self) -> Segs {
        Segs { hot: self.hot.iter().cloned().collect(), cold: self.cold.iter().cloned().collect() }
    }

    /// A fingerprint of the segment table, to know when `segments` changed.
    pub fn shape(&self) -> (usize, usize, usize, usize) {
        (self.hot.len(), self.hot.iter().filter(|s| s.is_some()).count(), self.cold.len(), self.cold.iter().filter(|s| s.is_some()).count())
    }

    #[inline]
    pub fn seg_size(&self) -> u64 {
        self.seg_size
    }

    #[inline]
    fn file(&self, idx: u64) -> Option<&Arc<MappedFile>> {
        if idx >= COLD_BASE {
            self.cold.get((idx - COLD_BASE) as usize)?.as_ref()
        } else {
            self.hot.get(idx as usize)?.as_ref()
        }
    }

    fn ensure_hot(&mut self, n: usize) -> io::Result<()> {
        if n >= self.hot.len() {
            self.hot.resize(n + 1, None);
        }
        if self.hot[n].is_none() {
            self.hot[n] = Some(Arc::new(MappedFile::open(&hot_path(&self.dir, n as u64), self.seg_size as usize)?));
        }
        Ok(())
    }

    /// Queues a frame; returns its global offset. Nothing is on disk until
    /// [`flush`](Self::flush) and [`sync`](Self::sync).
    pub fn append(&mut self, seq: u64, record: &[u8]) -> io::Result<u64> {
        if self.junk.is_some() {
            self.clear_junk()?;
        }
        let frame = FRAME_HEADER + record.len();
        assert!(record.len() <= MAX_RECORD && frame as u64 <= self.seg_size, "record too large for a segment");
        if self.head % self.seg_size + frame as u64 > self.seg_size {
            self.flush()?;
            let next = self.head / self.seg_size + 1;
            self.head = next * self.seg_size;
            self.buf_start = self.head;
            self.ensure_hot(next as usize)?;
        } else if self.head % self.seg_size == 0 {
            // The last frame filled its segment exactly (or the log reopened
            // there): what is buffered belongs to that segment, this frame to
            // the next one.
            self.flush()?;
            self.ensure_hot((self.head / self.seg_size) as usize)?;
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
        let si = self.buf_start / self.seg_size;
        crash_point!("log.flushing");
        self.file(si).expect("head segment").write_at(self.buf_start % self.seg_size, &self.buf)?;
        self.touched.insert(si);
        self.buf.clear();
        self.buf_start = self.head;
        Ok(())
    }

    /// Forgets the frames queued or written from `start` on by an append that
    /// failed: the next frame goes to `start` again, under the same seq. What
    /// the failed append put on disk is zeroed first (now if it can be, else
    /// before the next append), and synced with the next frames: a restart
    /// must never replay a frame whose seq was given out again, which would
    /// point one event's index entries at another's record.
    pub fn abandon(&mut self, start: u64) {
        let end = self.head.max(self.junk.map_or(0, |j| j.1));
        let from = self.junk.map_or(start, |j| j.0.min(start));
        self.buf.clear();
        self.head = start;
        self.buf_start = start;
        if end > from {
            self.junk = Some((from, end));
            let _ = self.clear_junk();
        }
    }

    /// Zeroes `junk` from its end back: if that is cut short, what is left is
    /// still a run of frames straight after the head, which a restart may
    /// replay as a prefix of the failed batch. Zeroed from the front instead,
    /// a restart could find frames past a gap, under seqs never given out.
    fn clear_junk(&mut self) -> io::Result<()> {
        static ZEROS: [u8; 64 * 1024] = [0; 64 * 1024];
        while let Some((from, end)) = self.junk {
            if from >= end {
                self.junk = None;
                break;
            }
            let si = (end - 1) / self.seg_size;
            let start = from.max(si * self.seg_size).max(end.saturating_sub(ZEROS.len() as u64));
            if let Some(seg) = self.file(si).cloned() {
                let o = start % self.seg_size;
                if !seg.punch_hole(o, o + (end - start)) {
                    seg.write_at(o, &ZEROS[..(end - start) as usize])?;
                }
                self.touched.insert(si);
            }
            self.junk = Some((from, start));
        }
        Ok(())
    }

    /// Flags the frame at `off` dead. Readers never look at flags, so this is
    /// safe to do immediately; the record bytes are zeroed later (`zero_record`).
    /// A frame in a retired segment needs nothing.
    pub fn mark_dead(&mut self, off: u64) -> io::Result<()> {
        let si = off / self.seg_size;
        if let Some(seg) = self.file(si) {
            seg.write_at(off % self.seg_size + 4, &FLAG_DEAD.to_le_bytes())?;
            self.touched.insert(si);
        }
        Ok(())
    }

    /// Overwrites a dead record's bytes with zeros, so deleted content does not
    /// linger on disk. Only once no snapshot that could read it is alive.
    pub fn zero_record(&mut self, off: u64) -> io::Result<()> {
        let si = off / self.seg_size;
        let Some(seg) = self.file(si).cloned() else { return Ok(()) };
        let o = off % self.seg_size;
        let len = seg.read_u32(o as usize) as usize;
        if o as usize + FRAME_HEADER + len > self.seg_size as usize {
            // A damaged header: there is no knowing what to zero.
            return Ok(());
        }
        self.touched.insert(si);
        // The header stays (its flag says dead). Whole blocks inside the record
        // are given back; the partial ones at its ends are overwritten. Most
        // records are smaller than a block and are only overwritten: a hole
        // punch there frees nothing, and costs the writer a filesystem
        // transaction and an unmap of the range from every reader's mapping
        // (ingest ran 20% slower punching every dead record).
        const BLOCK: u64 = 4096;
        let (body, end) = (o + FRAME_HEADER as u64, o + FRAME_HEADER as u64 + len as u64);
        let (a, b) = (body.next_multiple_of(BLOCK), end / BLOCK * BLOCK);
        crash_point!("log.zeroing");
        if b > a && seg.punch_hole(a, b) {
            write_zeros(&seg, body, a)?;
            return write_zeros(&seg, b, end);
        }
        write_zeros(&seg, body, end)
    }

    /// Zeroes a dead record's content but keeps the rest of it (its checksum
    /// rewritten to match): for a record whose index keys a restart may still
    /// have to rebuild from the log (see `Writer::zero_when_covered`), while
    /// what it said leaves the disk at once. One write, checksum and record
    /// together.
    pub fn scrub_content(&mut self, off: u64) -> io::Result<()> {
        let si = off / self.seg_size;
        let Some(seg) = self.file(si).cloned() else { return Ok(()) };
        let o = (off % self.seg_size) as usize;
        let len = seg.read_u32(o) as usize;
        if o + FRAME_HEADER + len > self.seg_size as usize {
            return Ok(());
        }
        let mut rec = seg.slice(o + FRAME_HEADER, len).to_vec();
        if crc32c(&rec) != seg.read_u32(o + 16) {
            // Already zeroed (or damaged): nothing left to keep.
            return Ok(());
        }
        let content = relay_proto::Record(&rec).stored_content();
        let start = content.as_ptr() as usize - rec.as_ptr() as usize;
        let end = start + content.len();
        if start == end {
            return Ok(());
        }
        rec[start..end].fill(0);
        let mut buf = Vec::with_capacity(4 + len);
        buf.extend_from_slice(&crc32c(&rec).to_le_bytes());
        buf.extend_from_slice(&rec);
        self.touched.insert(si);
        crash_point!("log.scrubbing");
        seg.write_at((o + 16) as u64, &buf)
    }

    /// Writes queued frames and hands over the segments written since the last
    /// call, for a sync on another thread.
    pub fn take_touched(&mut self) -> io::Result<Vec<Arc<MappedFile>>> {
        self.flush()?;
        let files = self.touched.iter().filter_map(|&si| self.file(si).cloned()).collect();
        self.touched.clear();
        Ok(files)
    }

    /// Syncs every segment file: a barrier after which everything ever written
    /// is durable, whoever was due to sync it. A sync of a clean file costs
    /// next to nothing, and this runs only before checkpoints.
    pub fn sync_all(&mut self) -> io::Result<()> {
        self.flush()?;
        for f in self.hot.iter().chain(self.cold.iter()).flatten() {
            f.sync()?;
        }
        self.touched.clear();
        Ok(())
    }

    /// Makes everything written so far durable.
    pub fn sync(&mut self) -> io::Result<()> {
        self.flush()?;
        for &si in &self.touched {
            if let Some(f) = self.file(si) {
                f.sync()?;
            }
        }
        self.touched.clear();
        Ok(())
    }

    #[inline]
    pub fn head(&self) -> u64 {
        self.head
    }

    /// Hot segments that log compaction may rewrite: present, wholly before
    /// both the head and `replay_from` (a restart never replays them).
    pub fn sealed(&self, replay_from: u64) -> Vec<(u64, Arc<MappedFile>)> {
        let limit = (self.head / self.seg_size).min(replay_from / self.seg_size);
        self.hot.iter().enumerate().take(limit as usize).filter_map(|(i, s)| Some((i as u64, s.clone()?))).collect()
    }

    /// Adds a cold segment written by compaction.
    pub fn register_cold(&mut self, n: u64, f: Arc<MappedFile>) {
        let i = n as usize;
        if self.cold.len() <= i {
            self.cold.resize(i + 1, None);
        }
        self.cold[i] = Some(f);
    }

    /// Drops a compacted hot segment from the table; its file goes once no
    /// published version holds it.
    pub fn retire_hot(&mut self, n: u64) {
        if let Some(slot) = self.hot.get_mut(n as usize) {
            if let Some(f) = slot.take() {
                f.mark_obsolete();
            }
        }
    }

    /// Drops a merged cold segment from the table; its file goes once no
    /// published version holds it.
    pub fn retire_cold(&mut self, n: u64) {
        if let Some(slot) = self.cold.get_mut(n as usize) {
            if let Some(f) = slot.take() {
                f.mark_obsolete();
            }
        }
    }

    pub fn cold_file(&self, n: u64) -> Option<Arc<MappedFile>> {
        self.cold.get(n as usize)?.clone()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
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
        if si > self.hot.len() {
            return Ok(());
        }
        self.ensure_hot(si)?;
        let seg_end = (si as u64 + 1) * self.seg_size;
        let to = (from + ZERO_STEP).min(seg_end);
        static ZEROS: [u8; 256 * 1024] = [0; 256 * 1024];
        let seg = self.hot[si].clone().expect("just ensured");
        while from < to {
            let n = ((to - from) as usize).min(ZEROS.len());
            crash_point!("log.preparing");
            seg.write_at(from % self.seg_size, &ZEROS[..n])?;
            from += n as u64;
        }
        seg.start_writeback(self.zeroed_to % self.seg_size, to - self.zeroed_to);
        self.zeroed_to = if to == seg_end { seg_end } else { to };
        Ok(())
    }
}

/// Overwrites `[from, to)` of a segment (offsets within it) with zeros.
fn write_zeros(seg: &MappedFile, from: u64, to: u64) -> io::Result<()> {
    const ZEROS: [u8; 4096] = [0; 4096];
    let mut at = from;
    while at < to {
        let n = ((to - at) as usize).min(ZEROS.len());
        seg.write_at(at, &ZEROS[..n])?;
        at += n as u64;
    }
    Ok(())
}
