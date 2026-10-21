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
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

pub enum Job {
    Flush { id: u64, runs: Vec<Arc<MemRun>>, dead: DeadSet, covered: u64, replay_from: u64 },
    Compact { id: u64, segs: Vec<Arc<Segment>>, dead: DeadSet },
    /// Rewrite sealed hot log segments into clustered cold ones.
    LogCompact { hot: Vec<(u64, Arc<MappedFile>)>, first_cold: u64, seg_size: u64, log_dir: PathBuf, dead: DeadSet, version: Arc<Version> },
    /// Point `locs` at the cold copies (once no reader can hold a version without them).
    LogRelink { moves: Vec<(u64, u64)>, dead: DeadSet, locs: Arc<MappedFile> },
}

pub enum Done {
    Flushed { seg: Arc<Segment>, frozen: usize, covered: u64, replay_from: u64 },
    Compacted { seg: Arc<Segment>, replaced: Vec<u64> },
    LogCompacted { cold: Vec<(u64, Arc<MappedFile>)>, moves: Vec<(u64, u64)>, retire: Vec<u64> },
    LogRelinked { moves: Vec<(u64, u64)> },
    Failed(String),
    /// A log compaction or relink failed.
    LogFailed(String),
}

pub fn seg_path(dir: &Path, id: u64) -> PathBuf {
    dir.join(format!("{id:016}.seg"))
}

/// Runs jobs until the writer hangs up.
pub fn worker(dir: PathBuf, rx: Receiver<Job>, tx: Sender<Done>) {
    for job in rx {
        let done = match job {
            Job::Flush { id, runs, dead, covered, replay_from } => {
                let frozen = runs.len();
                let srcs = runs.iter().map(|r| Src::Mem { run: r, i: 0 }).collect();
                match write(&dir, id, srcs, &dead) {
                    Ok(seg) => Done::Flushed { seg, frozen, covered, replay_from },
                    Err(e) => Done::Failed(format!("flush to segment {id}: {e}")),
                }
            }
            Job::Compact { id, segs, dead } => {
                let srcs = segs.iter().map(|s| Src::Seg(s.range(&[], &[0xFF; 2]))).collect();
                match write(&dir, id, srcs, &dead) {
                    Ok(seg) => Done::Compacted { seg, replaced: segs.iter().map(|s| s.id).collect() },
                    Err(e) => Done::Failed(format!("compaction into segment {id}: {e}")),
                }
            }
            Job::LogCompact { hot, first_cold, seg_size, log_dir, dead, version } => match compact_log(&hot, first_cold, seg_size, &log_dir, &dead, &version) {
                Ok((cold, moves)) => Done::LogCompacted { cold, moves, retire: hot.iter().map(|h| h.0).collect() },
                Err(e) => Done::LogFailed(format!("log compaction: {e}")),
            },
            Job::LogRelink { moves, dead, locs } => match relink(&moves, &dead, &locs) {
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
fn write(dir: &Path, id: u64, mut srcs: Vec<Src<'_>>, dead: &DeadSet) -> io::Result<Arc<Segment>> {
    let path = seg_path(dir, id);
    let tmp = path.with_extension("seg.tmp");
    let mut w = SegmentWriter::create(&tmp)?;
    let mut cur: Vec<u8> = Vec::new();
    let mut last: Vec<u8> = Vec::new();
    let mut have_last = false;
    loop {
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
    std::fs::rename(&tmp, &path)?;
    sync_dir(dir)?;
    Ok(Arc::new(Segment::open(id, &path)?))
}

/// Makes a rename durable.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Input bytes sorted together in one pass: bounds memory (~70 bytes per live
/// record in flight) on small machines; clustering is within each group.
const LOG_GROUP_BYTES: u64 = 2 << 30;

/// Where a record belongs in a cold segment: who reads it. Concord plane traffic
/// (a gift-wrap author with more than one wrap) by author; a DM gift wrap by its
/// recipient; anything else by author. Then by time.
fn cluster_key(r: Record<'_>, v: &Version, planes: &mut HashMap<[u8; 32], bool>) -> [u8; 41] {
    let mut k = [0u8; 41];
    let ca = r.created_at().to_be_bytes();
    k[33..].copy_from_slice(&ca);
    if r.kind() == kind::GIFT_WRAP {
        let pk = *r.pubkey();
        let plane = *planes.entry(pk).or_insert_with(|| v.prefix_has(&keys::prefix(keys::T_AUTHOR_KIND, &[&pk, &kind::GIFT_WRAP.to_be_bytes()]), 2));
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

/// Writes the live records of `hot` into new cold segments numbered from
/// `first_cold`, clustered, each synced. Returns the segments and every move
/// as (seq, new global offset).
#[allow(clippy::type_complexity)]
fn compact_log(hot: &[(u64, Arc<MappedFile>)], first_cold: u64, seg_size: u64, log_dir: &Path, dead: &DeadSet, v: &Version) -> io::Result<(Vec<(u64, Arc<MappedFile>)>, Vec<(u64, u64)>)> {
    let mut planes = HashMap::new();
    let mut out: Vec<(u64, Arc<MappedFile>)> = Vec::new();
    let mut moves = Vec::new();
    let mut next_cold = first_cold;
    let mut cur: Option<(u64, Arc<MappedFile>, u64)> = None; // (number, file, write position)
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 20);
    let mut buf_at = 0u64;

    let mut groups: Vec<&[(u64, Arc<MappedFile>)]> = Vec::new();
    let per_group = (LOG_GROUP_BYTES / seg_size).max(1) as usize;
    for g in hot.chunks(per_group) {
        groups.push(g);
    }
    for group in groups {
        // (cluster key, segment index in `hot`, offset in segment, frame length, seq)
        let mut recs: Vec<([u8; 41], u32, u32, u32, u64)> = Vec::new();
        for (gi, (n, seg)) in group.iter().enumerate() {
            let clean = log::scan_hot(seg, seg_size, *n, |fr| {
                if fr.dead || dead.is_dead(fr.seq) {
                    return;
                }
                let k = cluster_key(Record(fr.record), v, &mut planes);
                let o = (fr.off % seg_size) as u32;
                recs.push((k, gi as u32, o, (FRAME_HEADER + fr.record.len()) as u32, fr.seq));
            });
            if !clean {
                return Err(io::Error::other(format!("log segment {n:08}.log has a damaged frame; not compacting it")));
            }
        }
        recs.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.4.cmp(&b.4)));
        for (_, gi, o, len, seq) in recs {
            let seg = &group[gi as usize].1;
            let frame = seg.slice(o as usize, len as usize);
            // Opening a new cold segment when the frame does not fit.
            let fits = cur.as_ref().is_some_and(|c| c.2 + len as u64 <= seg_size);
            if !fits {
                if let Some((_, f, _)) = cur.take() {
                    f.write_at(buf_at, &buf)?;
                    buf.clear();
                    f.sync()?;
                    out.push((next_cold - 1, f));
                }
                let f = Arc::new(MappedFile::open(&log::cold_path(log_dir, next_cold), seg_size as usize)?);
                cur = Some((next_cold, f, 0));
                next_cold += 1;
                buf_at = 0;
            }
            let c = cur.as_mut().unwrap();
            moves.push((seq, (COLD_BASE + c.0) * seg_size + c.2));
            buf.extend_from_slice(frame);
            c.2 += len as u64;
            if buf.len() >= 1 << 20 {
                c.1.write_at(buf_at, &buf)?;
                buf_at += buf.len() as u64;
                buf.clear();
            }
        }
    }
    if let Some((n, f, _)) = cur.take() {
        f.write_at(buf_at, &buf)?;
        f.sync()?;
        out.push((n, f));
    }
    sync_dir(&log_dir.join("cold"))?;
    Ok((out, moves))
}

/// Points `locs` at the cold copies of every move whose event is still live,
/// coalescing runs of consecutive seqs into one write, then syncs it.
fn relink(moves: &[(u64, u64)], dead: &DeadSet, locs: &MappedFile) -> io::Result<()> {
    let mut live: Vec<(u64, u64)> = moves.iter().copied().filter(|m| !dead.is_dead(m.0)).collect();
    live.sort_unstable();
    let mut i = 0;
    let mut chunk = Vec::new();
    while i < live.len() {
        let start = live[i].0;
        chunk.clear();
        while i < live.len() && live[i].0 == start + (chunk.len() / 8) as u64 {
            chunk.extend_from_slice(&live[i].1.to_le_bytes());
            i += 1;
        }
        locs.write_at(start * 8, &chunk)?;
    }
    locs.sync()
}
