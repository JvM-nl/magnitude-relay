//! The background worker: turns memory runs into segments (flush) and merges
//! segments (compaction), off the writer's thread so writes never wait on it.
//!
//! Both jobs are the same operation, a k-way merge of sorted runs into a new
//! segment, dropping keys of events that are already dead (tombstones carry no
//! seq and always survive). The writer swaps the result in when it next looks.

use crate::dead::DeadSet;
use crate::keys;
use crate::memrun::MemRun;
use crate::segment::{SegCursor, Segment, SegmentWriter};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

pub enum Job {
    Flush { id: u64, runs: Vec<Arc<MemRun>>, dead: DeadSet, covered: u64, replay_from: u64 },
    Compact { id: u64, segs: Vec<Arc<Segment>>, dead: DeadSet },
}

pub enum Done {
    Flushed { seg: Arc<Segment>, frozen: usize, covered: u64, replay_from: u64 },
    Compacted { seg: Arc<Segment>, replaced: Vec<u64> },
    Failed(String),
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
