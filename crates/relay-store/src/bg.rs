//! The background worker: turns memory runs into segments (flush) and merges
//! segments (compaction), off the writer's thread so writes never wait on it.
//!
//! Both jobs are the same operation, a k-way merge of sorted runs into a new
//! segment, dropping keys of events that are already dead (tombstones carry no
//! seq and always survive). The writer swaps the result in when it next looks.

use crate::dead::DeadSet;
use crate::keys;
use crate::log::{self, COLD_BASE, FRAME_HEADER};
use crate::memrun::MemRun;
use crate::mmap::MappedFile;
use crate::segment::{SegCursor, Segment, SegmentWriter};
use crate::version::Version;
use relay_proto::record::{Field, Record};
use relay_proto::kind;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

/// Set when the writer is dropped: a job in progress gives up at its next
/// check (what it leaves is a crash's leftovers, removed at the next open), so
/// that nothing of a closed store still writes into its directory.
pub type Stop = Arc<AtomicBool>;

fn stopping(stop: &AtomicBool) -> io::Result<()> {
    if stop.load(Ordering::Relaxed) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "the store is closing"));
    }
    Ok(())
}

pub enum Job {
    Flush { id: u64, runs: Vec<Arc<MemRun>>, dead: DeadSet, covered: u64, replay_from: u64 },
    Compact { id: u64, segs: Vec<Arc<Segment>>, dead: DeadSet },
    /// Rewrite sealed hot log segments into clustered cold ones.
    LogCompact { hot: Vec<(u64, Arc<MappedFile>)>, first_cold: u64, seg_size: u64, log_dir: PathBuf, dead: DeadSet, version: Arc<Version>, chunk: u64 },
    /// Merge sorted cold runs into one, leaving dead records behind.
    LogMerge { runs: Vec<Vec<(u64, Arc<MappedFile>)>>, first_cold: u64, seg_size: u64, log_dir: PathBuf, dead: DeadSet, version: Arc<Version> },
    /// Point `locs` at the cold copies (once no reader can hold a version without them).
    LogRelink { moves: Vec<(u64, u64)>, dead: DeadSet, locs: Arc<MappedFile> },
}

pub enum Done {
    Flushed { seg: Arc<Segment>, frozen: usize, covered: u64, replay_from: u64 },
    Compacted { seg: Arc<Segment>, replaced: Vec<u64> },
    /// New cold runs, every record's new place, and the segments they replace
    /// (hot numbers, or `COLD_BASE + n` for cold ones).
    LogCompacted { runs: Vec<ColdRun>, moves: Vec<(u64, u64)>, retire: Vec<u64> },
    LogRelinked { moves: Vec<(u64, u64)> },
    /// A flush failed: its memory runs stay, to be flushed again.
    FlushFailed(String),
    /// A compaction failed: its input segments stay.
    CompactFailed(String),
    /// A log compaction or relink failed.
    LogFailed(String),
}

/// Cold segments holding one sorted sequence of records.
pub struct ColdRun {
    pub segs: Vec<(u64, Arc<MappedFile>)>,
    /// Frame bytes in it.
    pub bytes: u64,
}

pub fn seg_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:016}.seg"))
}

/// Runs jobs until the writer hangs up or `stop` is set.
pub fn worker(dir: PathBuf, rx: Receiver<Job>, tx: Sender<Done>, stop: Stop) {
    for job in rx {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let stop = &*stop;
        let done = match job {
            Job::Flush { id, runs, dead, covered, replay_from } => {
                let frozen = runs.len();
                let srcs = runs.iter().map(|r| Src::Mem { run: r, i: 0 }).collect();
                match write(&dir, id, srcs, &dead, stop) {
                    Ok(seg) => Done::Flushed { seg, frozen, covered, replay_from },
                    Err(e) => Done::FlushFailed(format!("flush to segment {id}: {e}")),
                }
            }
            Job::Compact { id, segs, dead } => {
                let srcs = segs.iter().map(|s| Src::Seg(s.range(&[], &[0xFF; 2]))).collect();
                match write(&dir, id, srcs, &dead, stop) {
                    Ok(seg) => Done::Compacted { seg, replaced: segs.iter().map(|s| s.id).collect() },
                    Err(e) => Done::CompactFailed(format!("compaction into segment {id}: {e}")),
                }
            }
            Job::LogCompact { hot, first_cold, seg_size, log_dir, dead, version, chunk } => match compact_log(&hot, first_cold, seg_size, &log_dir, &dead, &version, chunk, stop) {
                Ok((runs, moves)) => Done::LogCompacted { runs, moves, retire: hot.iter().map(|h| h.0).collect() },
                Err(e) => Done::LogFailed(format!("log compaction: {e}")),
            },
            Job::LogMerge { runs, first_cold, seg_size, log_dir, dead, version } => match merge_runs(&runs, first_cold, seg_size, &log_dir, &dead, &version, stop) {
                Ok((run, moves)) => {
                    Done::LogCompacted { runs: vec![run], moves, retire: runs.iter().flatten().map(|s| COLD_BASE + s.0).collect() }
                }
                Err(e) => Done::LogFailed(format!("log merge: {e}")),
            },
            Job::LogRelink { moves, dead, locs } => match relink(&moves, &dead, &locs, stop) {
                Ok(()) => Done::LogRelinked { moves },
                Err(e) => Done::LogFailed(format!("log relink: {e}")),
            },
        };
        if tx.send(done).is_err() {
            return;
        }
    }
}

/// One sorted input of a merge.
enum Src<'a> {
    Mem { run: &'a MemRun, i: usize },
    Seg(SegCursor<'a>),
}

impl Src<'_> {
    #[inline]
    fn peek(&mut self) -> Option<&[u8]> {
        match self {
            Src::Mem { run, i } => (*i < run.len()).then(|| run.key(*i)),
            Src::Seg(c) => c.peek_front(),
        }
    }

    #[inline]
    fn advance(&mut self) {
        match self {
            Src::Mem { i, .. } => *i += 1,
            Src::Seg(c) => {
                c.next_front();
            }
        }
    }
}

/// Merges `srcs` into segment `id`: written to a temporary name, synced, then
/// renamed, so a crash never leaves a half-written file under a real name.
fn write(dir: &Path, id: u64, mut srcs: Vec<Src<'_>>, dead: &DeadSet, stop: &AtomicBool) -> io::Result<Arc<Segment>> {
    let path = seg_path(dir, id);
    let tmp = path.with_extension("seg.tmp");
    let mut w = SegmentWriter::create(&tmp)?;
    let mut cur: Vec<u8> = Vec::new();
    let mut last: Vec<u8> = Vec::new();
    let mut have_last = false;
    let mut n = 0u32;
    loop {
        n = n.wrapping_add(1);
        if n % 4096 == 0 {
            stopping(stop)?;
        }
        // Few inputs (a handful of runs or segments): a linear minimum beats a
        // heap. The minimum is copied into a reused buffer, not allocated.
        let mut best = false;
        for s in srcs.iter_mut() {
            if let Some(k) = s.peek() {
                if !best || k < cur.as_slice() {
                    cur.clear();
                    cur.extend_from_slice(k);
                    best = true;
                }
            }
        }
        if !best {
            break;
        }
        // The same key can sit in two inputs (a merge of overlapping runs).
        for s in srcs.iter_mut() {
            if s.peek() == Some(cur.as_slice()) {
                s.advance();
            }
        }
        if have_last && cur == last {
            continue;
        }
        if keys::has_seq(&cur) && dead.is_dead(keys::seq_of(&cur)) {
            continue;
        }
        w.add(&cur)?;
        std::mem::swap(&mut last, &mut cur);
        have_last = true;
    }
    w.finish()?;
    crash_point!("bg.segment_written");
    std::fs::rename(&tmp, &path)?;
    crash_point!("bg.segment_renamed");
    sync_dir(dir)?;
    Ok(Arc::new(Segment::open(id, &path)?))
}

/// Makes a rename durable.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Log bytes clustered together: the copy reads them in cluster order, which is
/// random within the span, so the span must fit in memory or the copy thrashes.
/// An eighth of the memory available to the process, within these bounds.
fn chunk_bytes() -> u64 {
    (crate::mmap::memory_budget() / 8).clamp(64 << 20, 2 << 30)
}

/// Where a record belongs in a cold segment: who reads it. Concord plane traffic
/// (a gift-wrap author with more than one wrap) by author; a DM gift wrap by its
/// recipient; anything else by author. Then by time.
fn cluster_key(r: Record<'_>, v: &Version, planes: &mut HashSet<[u8; 32]>) -> [u8; 41] {
    let mut k = [0u8; 41];
    let ca = r.created_at().to_be_bytes();
    k[33..].copy_from_slice(&ca);
    if r.kind() == kind::GIFT_WRAP {
        let pk = *r.pubkey();
        // Only plane keys are remembered: a DM wrap's one-off key is seen once.
        let plane = planes.contains(&pk) || v.prefix_has(&keys::prefix(keys::T_AUTHOR_KIND, &[&pk, &kind::GIFT_WRAP.to_be_bytes()]), 2);
        if plane {
            planes.insert(pk);
        }
        if plane {
            k[0] = 0;
            k[1..33].copy_from_slice(&pk);
        } else {
            k[0] = 1;
            let p = r.tags().find_map(|t| {
                let mut f = t.fields();
                match (f.next(), f.next()) {
                    (Some(n), Some(Field::Hex32(p))) if n.is_str(b"p") => Some(*p),
                    _ => None,
                }
            });
            k[1..33].copy_from_slice(&p.unwrap_or([0; 32]));
        }
    } else {
        k[0] = 2;
        k[1..33].copy_from_slice(r.pubkey());
    }
    k
}

/// Cold segments being written, frame by frame, in 1 MiB writes.
struct ColdOut<'a> {
    log_dir: &'a Path,
    seg_size: u64,
    next: u64,
    /// (number, file, bytes in it so far)
    cur: Option<(u64, Arc<MappedFile>, u64)>,
    buf: Vec<u8>,
    buf_at: u64,
    done: Vec<(u64, Arc<MappedFile>)>,
    moves: Vec<(u64, u64)>,
    /// Finished runs, and the bytes of the one being written.
    runs: Vec<ColdRun>,
    run_bytes: u64,
}

impl<'a> ColdOut<'a> {
    fn new(log_dir: &'a Path, seg_size: u64, first: u64) -> ColdOut<'a> {
        ColdOut {
            log_dir,
            seg_size,
            next: first,
            cur: None,
            buf: Vec::with_capacity(1 << 20),
            buf_at: 0,
            done: Vec::new(),
            moves: Vec::new(),
            runs: Vec::new(),
            run_bytes: 0,
        }
    }

    /// Ends the sorted run being written: the next record starts a new segment,
    /// so a run is always whole segments (the rest of the last one stays a hole).
    fn end_run(&mut self) -> io::Result<()> {
        self.seal()?;
        if !self.done.is_empty() {
            self.runs.push(ColdRun { segs: std::mem::take(&mut self.done), bytes: self.run_bytes });
        }
        self.run_bytes = 0;
        Ok(())
    }

    /// The runs and every record's new place, once the last run has ended.
    #[allow(clippy::type_complexity)]
    fn finish(mut self) -> io::Result<(Vec<ColdRun>, Vec<(u64, u64)>)> {
        self.end_run()?;
        sync_dir(&self.log_dir.join("cold"))?;
        Ok((self.runs, self.moves))
    }

    fn put(&mut self, seq: u64, frame: &[u8]) -> io::Result<()> {
        let len = frame.len() as u64;
        if self.cur.as_ref().is_none_or(|c| c.2 + len > self.seg_size) {
            self.seal()?;
            let f = Arc::new(MappedFile::open(&log::cold_path(self.log_dir, self.next), self.seg_size as usize)?);
            // A job that failed may have left a file of this number behind (its
            // numbers are taken again): what it wrote must not show past the end
            // of what this one writes.
            f.zero_from(0)?;
            self.cur = Some((self.next, f, 0));
            self.next += 1;
        }
        let c = self.cur.as_mut().unwrap();
        self.moves.push((seq, (COLD_BASE + c.0) * self.seg_size + c.2));
        self.buf.extend_from_slice(frame);
        c.2 += len;
        self.run_bytes += len;
        if self.buf.len() >= 1 << 20 {
            crash_point!("cold.writing");
            c.1.write_at(self.buf_at, &self.buf)?;
            self.buf_at += self.buf.len() as u64;
            self.buf.clear();
        }
        Ok(())
    }

    /// Writes out and syncs the segment being filled.
    fn seal(&mut self) -> io::Result<()> {
        if let Some((n, f, _)) = self.cur.take() {
            crash_point!("cold.sealing");
            f.write_at(self.buf_at, &self.buf)?;
            f.sync()?;
            crash_point!("cold.sealed");
            self.buf.clear();
            self.buf_at = 0;
            self.done.push((n, f));
        }
        Ok(())
    }
}

/// (cluster key, index in `hot`, offset in that segment, frame length, seq)
type Pending = ([u8; 41], u32, u32, u32, u64);

/// Copies one chunk's records in cluster order, then lets the kernel drop the
/// chunk's input pages: they are read once, and on a small machine they would
/// otherwise push the index out of memory.
fn copy_chunk(recs: &mut Vec<Pending>, hot: &[(u64, Arc<MappedFile>)], from: (usize, u64), to: (usize, u64), out: &mut ColdOut<'_>) -> io::Result<()> {
    recs.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.4.cmp(&b.4)));
    for &(_, gi, o, len, seq) in recs.iter() {
        out.put(seq, hot[gi as usize].1.slice(o as usize, len as usize))?;
    }
    recs.clear();
    // Each chunk is one sorted run: later merges rely on runs being sorted.
    out.end_run()?;
    for (gi, (_, seg)) in hot.iter().enumerate().take(to.0 + 1).skip(from.0) {
        let a = if gi == from.0 { from.1 } else { 0 };
        let b = if gi == to.0 { to.1 } else { seg.len() as u64 };
        seg.drop_cache(a as usize, (b - a) as usize);
    }
    Ok(())
}

/// Writes the live records of `hot` into new cold segments numbered from
/// `first_cold`, clustered, each synced. Returns the segments and every move
/// as (seq, new global offset). Streams: records are clustered within chunks
/// of `chunk_bytes` of log, so memory stays bounded whatever the log's size.
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
fn compact_log(
    hot: &[(u64, Arc<MappedFile>)],
    first_cold: u64,
    seg_size: u64,
    log_dir: &Path,
    dead: &DeadSet,
    v: &Version,
    chunk: u64,
    stop: &AtomicBool,
) -> io::Result<(Vec<ColdRun>, Vec<(u64, u64)>)> {
    let limit = if chunk > 0 { chunk } else { chunk_bytes() };
    let mut planes = HashSet::new();
    let mut out = ColdOut::new(log_dir, seg_size, first_cold);
    let mut recs: Vec<Pending> = Vec::new();
    let mut span = 0u64;
    let mut from = (0usize, 0u64);
    let mut err: Option<io::Error> = None;
    for (gi, (n, seg)) in hot.iter().enumerate() {
        seg.advise(crate::mmap::Advice::Sequential);
        let clean = log::scan_hot(seg, seg_size, *n, |fr| {
            if err.is_some() {
                return;
            }
            if let Err(e) = stopping(stop) {
                err = Some(e);
                return;
            }
            let o = fr.off % seg_size;
            let len = (FRAME_HEADER + fr.record.len()) as u64;
            span += len;
            if !(fr.dead || dead.is_dead(fr.seq)) {
                let k = cluster_key(Record(fr.record), v, &mut planes);
                recs.push((k, gi as u32, o as u32, len as u32, fr.seq));
            }
            if span >= limit {
                let to = (gi, o + len);
                if let Err(e) = copy_chunk(&mut recs, hot, from, to, &mut out) {
                    err = Some(e);
                }
                (from, span) = (to, 0);
            }
        });
        seg.advise(crate::mmap::Advice::Random);
        if let Some(e) = err {
            return Err(e);
        }
        if !clean {
            return Err(io::Error::other(format!("log segment {n:08}.log has a damaged frame; not compacting it")));
        }
    }
    if let Some((_, seg)) = hot.last() {
        copy_chunk(&mut recs, hot, from, (hot.len() - 1, seg.len() as u64), &mut out)?;
    }
    out.finish()
}

/// Walks one cold run's frames in order, letting the kernel drop the pages it
/// has passed (a merge reads each byte once).
struct RunReader<'a> {
    segs: &'a [(u64, Arc<MappedFile>)],
    seg_size: usize,
    si: usize,
    o: usize,
    dropped_to: usize,
}

/// Read this far past the last drop, the pages behind are let go.
const DROP_EVERY: usize = 64 << 20;

impl<'a> RunReader<'a> {
    /// The next frame: (seq, dead, whole frame, record). A crc mismatch counts
    /// as dead: cold segments are written whole, so it is a record zeroed under us.
    #[allow(clippy::type_complexity)]
    fn next(&mut self) -> io::Result<Option<(u64, bool, &'a [u8], &'a [u8])>> {
        loop {
            let Some((n, seg)) = self.segs.get(self.si) else { return Ok(None) };
            let len = if self.o + FRAME_HEADER <= self.seg_size { seg.read_u32(self.o) as usize } else { 0 };
            if len == 0 {
                seg.drop_cache(self.dropped_to, self.o.saturating_sub(self.dropped_to));
                (self.si, self.o, self.dropped_to) = (self.si + 1, 0, 0);
                continue;
            }
            if len > log::MAX_RECORD || self.o + FRAME_HEADER + len > self.seg_size {
                return Err(io::Error::other(format!("cold segment {n:08}.log has a damaged frame at byte {}", self.o)));
            }
            let flags = seg.read_u32(self.o + 4);
            let seq = seg.read_u64(self.o + 8);
            let crc = seg.read_u32(self.o + 16);
            let frame = seg.slice(self.o, FRAME_HEADER + len);
            let record = &frame[FRAME_HEADER..];
            let dead = flags & log::FLAG_DEAD != 0 || crate::crc32c::crc32c(record) != crc;
            self.o += FRAME_HEADER + len;
            if self.o - self.dropped_to >= DROP_EVERY {
                seg.drop_cache(self.dropped_to, self.o - self.dropped_to);
                self.dropped_to = self.o;
            }
            return Ok(Some((seq, dead, frame, record)));
        }
    }

    /// The next frame worth keeping, with its cluster key.
    #[allow(clippy::type_complexity)]
    fn next_live(&mut self, dead: &DeadSet, v: &Version, planes: &mut HashSet<[u8; 32]>) -> io::Result<Option<([u8; 41], u64, &'a [u8])>> {
        while let Some((seq, is_dead, frame, record)) = self.next()? {
            if !is_dead && !dead.is_dead(seq) {
                return Ok(Some((cluster_key(Record(record), v, planes), seq, frame)));
            }
        }
        Ok(None)
    }
}

/// Merges sorted cold runs into one sorted run in new segments numbered from
/// `first_cold`: a streaming k-way merge, so memory is a few buffers whatever
/// the runs' size, and each input is read front to back. Dead records stay
/// behind, which is how their space comes back. Returns the run and every move.
fn merge_runs(
    runs: &[Vec<(u64, Arc<MappedFile>)>],
    first_cold: u64,
    seg_size: u64,
    log_dir: &Path,
    dead: &DeadSet,
    v: &Version,
    stop: &AtomicBool,
) -> io::Result<(ColdRun, Vec<(u64, u64)>)> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;
    let mut planes = HashSet::new();
    let mut out = ColdOut::new(log_dir, seg_size, first_cold);
    let mut readers: Vec<RunReader<'_>> = runs.iter().map(|segs| RunReader { segs, seg_size: seg_size as usize, si: 0, o: 0, dropped_to: 0 }).collect();
    for r in &readers {
        for (_, seg) in r.segs {
            seg.advise(crate::mmap::Advice::Sequential);
        }
    }
    let mut heads: Vec<Option<&[u8]>> = vec![None; readers.len()];
    let mut heap = BinaryHeap::with_capacity(readers.len());
    for (i, r) in readers.iter_mut().enumerate() {
        if let Some((k, seq, frame)) = r.next_live(dead, v, &mut planes)? {
            heads[i] = Some(frame);
            heap.push(Reverse((k, seq, i)));
        }
    }
    while let Some(Reverse((_, seq, i))) = heap.pop() {
        stopping(stop)?;
        out.put(seq, heads[i].take().expect("a head for every heap entry"))?;
        if let Some((k, seq, frame)) = readers[i].next_live(dead, v, &mut planes)? {
            heads[i] = Some(frame);
            heap.push(Reverse((k, seq, i)));
        }
    }
    let (mut runs_out, moves) = out.finish()?;
    let run = match runs_out.pop() {
        Some(r) => r,
        None => ColdRun { segs: Vec::new(), bytes: 0 },
    };
    Ok((run, moves))
}

/// Points `locs` at the cold copies of every move whose event is still live,
/// coalescing runs of consecutive seqs into one write, then syncs it.
fn relink(moves: &[(u64, u64)], dead: &DeadSet, locs: &MappedFile, stop: &AtomicBool) -> io::Result<()> {
    let mut live: Vec<(u64, u64)> = moves.iter().copied().filter(|m| !dead.is_dead(m.0)).collect();
    live.sort_unstable();
    let mut i = 0;
    let mut chunk = Vec::new();
    while i < live.len() {
        // Stopped part way, the exchange is finished at the next open, as after a crash.
        stopping(stop)?;
        let start = live[i].0;
        chunk.clear();
        while i < live.len() && live[i].0 == start + (chunk.len() / 8) as u64 {
            chunk.extend_from_slice(&live[i].1.to_le_bytes());
            i += 1;
        }
        locs.write_at(start * 8, &chunk)?;
        crash_point!("relink.writing");
    }
    locs.sync()
}
