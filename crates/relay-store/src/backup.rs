//! Online backup: a consistent copy of a store, taken while it keeps serving.
//!
//! [`Writer::begin_backup`](crate::Writer::begin_backup) writes a fresh
//! checkpoint and takes a snapshot; that is all the writer does (milliseconds).
//! The snapshot pins every file the checkpoint names: index segments a
//! compaction replaces, and log segments a log compaction retires, stay on disk
//! until the plan is dropped, and no dead record is zeroed under the copy (the
//! zeroing waits for readers of older versions, and the plan is one). Log
//! compaction holds still meanwhile, so `locs` does not move under the copy;
//! an exchange already registered is in the checkpoint as an intent, which a
//! restore finishes.
//!
//! The dead set is copied as it stands at the start too. A death during the
//! copy is the work of an event the copy does not have (a deletion, a newer
//! replaceable), so the copy keeps its victim alive, as it was; dead flags that
//! reach a log frame meanwhile are set back to the start's while copying.
//!
//! [`copy`] then reads the files off the writer's thread: the log up to the
//! head at the start (later frames are cut off, so the copy is exactly the
//! store at that moment), index segments, `locs` for the events that existed,
//! the dead set of the start, and the checkpoint last. It writes into
//! `<dest>.partial`, renamed to `<dest>` once everything is synced: a backup
//! either exists whole or not at all. The result is a data directory: start a
//! relay on it, or copy it to another machine.

use crate::checkpoint::Checkpoint;
use crate::{bg, log, Version};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// What a backup copies, fixed at its start.
pub struct Plan {
    pub(crate) version: Arc<Version>,
    pub(crate) checkpoint: Checkpoint,
    /// Global log offset of the end of the last frame at the start.
    pub(crate) head: u64,
    /// Events (seqs) in the copy.
    pub(crate) count: u64,
    pub(crate) seg_size: u64,
    pub(crate) dir: PathBuf,
    /// The dead set at the start, as `dead.bits` holds it, for the events in
    /// the copy only.
    dead: Vec<u8>,
}

impl Plan {
    /// Fixes a backup's content. Called on the writer's thread, so the dead set
    /// read here is exactly the start's.
    pub(crate) fn new(version: Arc<Version>, checkpoint: Checkpoint, head: u64, count: u64, seg_size: u64, dir: PathBuf) -> Plan {
        // A bit past `count` would belong to an event the copy does not have, and
        // after a restore its seq goes to a new event, which would be born dead.
        let mut dead = version.dead.to_bytes(count);
        dead.resize(count.div_ceil(64) as usize * 8, 0);
        let rem = count % 64;
        if rem != 0 {
            let at = dead.len() - 8;
            let w = u64::from_le_bytes(dead[at..].try_into().unwrap()) & ((1u64 << rem) - 1);
            dead[at..].copy_from_slice(&w.to_le_bytes());
        }
        Plan { version, checkpoint, head, count, seg_size, dir, dead }
    }

    /// Events the copy holds (live or not).
    pub fn events(&self) -> u64 {
        self.count
    }

    #[inline]
    fn was_dead(&self, seq: u64) -> bool {
        self.dead.get((seq / 8) as usize).is_some_and(|b| b & (1 << (seq % 8)) != 0)
    }
}

/// What [`copy`] did.
#[derive(Debug, Clone, Copy, Default)]
pub struct Copied {
    pub files: usize,
    /// Bytes read from the store.
    pub bytes: u64,
    /// Bytes written (holes are not written).
    pub written: u64,
}

/// One file to copy: where from, where to, how much of it, and what length the
/// copy ends with.
struct Job {
    src: PathBuf,
    dst: PathBuf,
    len: u64,
    final_len: u64,
    sparse: bool,
    private: bool,
    /// A log segment: its frames' dead flags are set to the start's as they
    /// are copied.
    log: bool,
}

/// Bytes moved per read.
const BLOCK: usize = 1 << 20;
/// Pages read or written this far behind are let go from the cache: a backup of
/// a big store must not push the relay's working set out of memory.
const DROP_EVERY: u64 = 64 << 20;

/// Copies the store as `plan` fixed it into `dest`, which must not exist.
/// `progress` hears (bytes done, bytes in all) now and then; returning false
/// abandons the copy (the partial directory is removed).
pub fn copy(plan: &Plan, dest: &Path, progress: &mut dyn FnMut(u64, u64) -> bool) -> io::Result<Copied> {
    if within(dest, &plan.dir) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is inside the data directory {}", dest.display(), plan.dir.display())));
    }
    if dest.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", dest.display())));
    }
    let partial = partial_path(dest);
    if partial.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} is left from an earlier backup that did not finish; remove it first", partial.display()),
        ));
    }
    let result = copy_into(plan, &partial, progress);
    match result {
        Ok(c) => {
            std::fs::rename(&partial, dest)?;
            bg::sync_dir(dest.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")))?;
            Ok(c)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&partial);
            Err(e)
        }
    }
}

/// Whether `path` (which need not exist yet) is `dir` or lies inside it, links
/// resolved.
fn within(path: &Path, dir: &Path) -> bool {
    let Ok(dir) = dir.canonicalize() else { return false };
    let mut rest = PathBuf::new();
    for a in path.ancestors() {
        if let Ok(real) = a.canonicalize() {
            return real.join(rest).starts_with(&dir);
        }
        if let Some(name) = a.file_name() {
            rest = Path::new(name).join(rest);
        }
    }
    false
}

fn partial_path(dest: &Path) -> PathBuf {
    let mut p = dest.as_os_str().to_owned();
    p.push(".partial");
    PathBuf::from(p)
}

fn copy_into(plan: &Plan, out: &Path, progress: &mut dyn FnMut(u64, u64) -> bool) -> io::Result<Copied> {
    let (src, ck) = (&plan.dir, &plan.checkpoint);
    for d in [out.to_path_buf(), out.join("idx"), out.join("log"), out.join("log").join("cold")] {
        std::fs::create_dir_all(&d)?;
    }
    let mut jobs = Vec::new();
    let file = |p: &Path| -> io::Result<u64> { Ok(std::fs::metadata(p)?.len()) };
    let mut add = |src: PathBuf, dst: PathBuf, len: Option<u64>, final_len: Option<u64>, log: bool, private: bool| -> io::Result<()> {
        let full = file(&src)?;
        let len = len.unwrap_or(full).min(full);
        jobs.push(Job { src, dst, len, final_len: final_len.unwrap_or(len), sparse: log, private, log });
        Ok(())
    };
    add(src.join("meta"), out.join("meta"), None, None, false, false)?;
    for &id in &ck.segments {
        add(bg::seg_path(&src.join("idx"), id), bg::seg_path(&out.join("idx"), id), None, None, false, false)?;
    }
    // Hot segments up to the head's; the head's only up to the head.
    let head_seg = plan.head / plan.seg_size;
    for (i, slot) in plan.version.segs.hot.iter().enumerate().take(head_seg as usize + 1) {
        if slot.is_none() {
            continue;
        }
        let n = i as u64;
        let len = if n == head_seg { plan.head % plan.seg_size } else { plan.seg_size };
        add(log::hot_path(&src.join("log"), n), log::hot_path(&out.join("log"), n), Some(len), Some(plan.seg_size), true, false)?;
    }
    for &n in &ck.cold {
        add(log::cold_path(&src.join("log"), n), log::cold_path(&out.join("log"), n), None, Some(plan.seg_size), true, false)?;
    }
    // Certificates and the ACME account, for a move to another machine.
    if let Ok(entries) = std::fs::read_dir(src.join("tls")) {
        std::fs::create_dir_all(out.join("tls"))?;
        for e in entries.flatten() {
            if e.file_type().is_ok_and(|t| t.is_file()) {
                add(e.path(), out.join("tls").join(e.file_name()), None, None, false, true)?;
            }
        }
    }

    let total: u64 = jobs.iter().map(|j| j.len).sum::<u64>() + plan.count * 8;
    // What the copy will take on disk: what the files take now (holes stay holes).
    let need: u64 = jobs
        .iter()
        .map(|j| std::fs::metadata(&j.src).map_or(j.len, |m| (m.blocks() * 512).min(j.len)))
        .sum::<u64>()
        + plan.count * 8
        + plan.dead.len() as u64;
    if let Some(free) = crate::mmap::free_bytes(out) {
        if free < need {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!("the backup needs about {:.2} GB and {} has {:.2} GB free", need as f64 / 1e9, out.display(), free as f64 / 1e9),
            ));
        }
    }
    let mut c = Copied::default();
    let mut buf = vec![0u8; BLOCK];
    for j in &jobs {
        copy_file(plan, j, &mut buf, &mut c, total, progress)?;
    }

    // `locs` for the events in the copy, read through the snapshot's mapping.
    let locs_len = (plan.count * 8) as usize;
    let locs = plan.version.locs.slice(0, locs_len.min(plan.version.locs.len()));
    write_new(&out.join("locs"), locs, false)?;
    c.files += 1;
    c.bytes += locs.len() as u64;
    c.written += locs.len() as u64;
    if !progress(c.bytes, total) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "backup abandoned"));
    }

    write_new(&out.join("dead.bits"), &plan.dead, false)?;
    c.files += 1;

    // The checkpoint last: until it is there the directory is not a store.
    crate::checkpoint::write(out, ck)?;
    c.files += 1;
    for d in [out.join("idx"), out.join("log").join("cold"), out.join("log"), out.to_path_buf()] {
        bg::sync_dir(&d)?;
    }
    if out.join("tls").exists() {
        bg::sync_dir(&out.join("tls"))?;
    }
    Ok(c)
}

/// Copies `j.len` bytes, skipping all-zero blocks when sparse (they stay holes),
/// then sets the final length and syncs.
fn copy_file(plan: &Plan, j: &Job, buf: &mut [u8], c: &mut Copied, total: u64, progress: &mut dyn FnMut(u64, u64) -> bool) -> io::Result<()> {
    let mut frames = j.log.then_some(Frames { at: 0, end: j.len });
    let src = File::open(&j.src)?;
    let dst = create_new(&j.dst, j.private)?;
    let (mut off, mut dropped) = (0u64, 0u64);
    while off < j.len {
        let n = (j.len - off).min(buf.len() as u64) as usize;
        src.read_exact_at(&mut buf[..n], off)?;
        if let Some(f) = &mut frames {
            f.patch(&src, &|seq| plan.was_dead(seq), &mut buf[..n], off)?;
        }
        if !(j.sparse && all_zero(&buf[..n])) {
            dst.write_all_at(&buf[..n], off)?;
            c.written += n as u64;
        }
        off += n as u64;
        c.bytes += n as u64;
        if off - dropped >= DROP_EVERY {
            dst.sync_data()?;
            drop_cache(&src, dropped, off - dropped);
            drop_cache(&dst, dropped, off - dropped);
            dropped = off;
            if !progress(c.bytes, total) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "backup abandoned"));
            }
        }
    }
    dst.set_len(j.final_len)?;
    dst.sync_all()?;
    drop_cache(&src, dropped, off - dropped);
    drop_cache(&dst, dropped, off - dropped);
    c.files += 1;
    Ok(())
}

/// Walks a log segment's frames alongside its copy. Headers are read from the
/// bytes just read (the few that straddle two blocks, from the file again),
/// never through the relay's own mapping: a page touched there stays mapped,
/// and a mapped page is never let go from the cache, so a backup would leave
/// the whole log resident.
struct Frames {
    /// The next frame whose flags are not yet (all) set.
    at: u64,
    end: u64,
}

impl Frames {
    /// Sets the dead flag of every frame whose flags word overlaps `buf` (the
    /// bytes of `src` at `off`) to the start's.
    fn patch(&mut self, src: &File, was_dead: &dyn Fn(u64) -> bool, buf: &mut [u8], off: u64) -> io::Result<()> {
        let (lo, hi) = (off, off + buf.len() as u64);
        // Length, flags and seq: the first 16 bytes of a header.
        let mut head = [0u8; 16];
        while self.at + log::FRAME_HEADER as u64 <= self.end && self.at + 4 < hi {
            let o = self.at;
            if o >= lo && o + 16 <= hi {
                let p = (o - lo) as usize;
                head.copy_from_slice(&buf[p..p + 16]);
            } else {
                src.read_exact_at(&mut head, o)?;
            }
            let word = |at: usize| u32::from_le_bytes(head[at..at + 4].try_into().unwrap());
            let len = word(0) as u64;
            if len == 0 || len > log::MAX_RECORD as u64 {
                // The end of the frames.
                self.end = o;
                return Ok(());
            }
            let seq = u64::from_le_bytes(head[8..16].try_into().unwrap());
            let flags = (word(4) & !log::FLAG_DEAD) | if was_dead(seq) { log::FLAG_DEAD } else { 0 };
            for (i, b) in flags.to_le_bytes().into_iter().enumerate() {
                let p = o + 4 + i as u64;
                if (lo..hi).contains(&p) {
                    buf[(p - lo) as usize] = b;
                }
            }
            if o + 8 > hi {
                // The rest of the word is in the next block.
                return Ok(());
            }
            self.at = o + log::FRAME_HEADER as u64 + len;
        }
        Ok(())
    }
}

fn create_new(path: &Path, private: bool) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).mode(if private { 0o600 } else { 0o644 }).open(path)
}

fn write_new(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    let f = create_new(path, private)?;
    f.write_all_at(data, 0)?;
    f.sync_all()
}

#[inline]
fn all_zero(b: &[u8]) -> bool {
    let (words, tail) = b.split_at(b.len() / 8 * 8);
    words.chunks_exact(8).all(|w| u64::from_ne_bytes(w.try_into().unwrap()) == 0) && tail.iter().all(|&x| x == 0)
}

/// Lets the kernel drop a range of a file from its cache (Linux; advisory).
fn drop_cache(f: &File, off: u64, len: u64) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: valid descriptor; advisory.
        unsafe {
            libc::posix_fadvise(f.as_raw_fd(), off as i64, len as i64, libc::POSIX_FADV_DONTNEED);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (f, off, len);
}

/// What [`verify`] found.
#[derive(Debug, Clone, Copy)]
pub struct Verified {
    pub events: u64,
    /// Live events read back and checked against their checksums.
    pub checked: u64,
}

/// Opens a finished backup as a store and reads a spread of its events back,
/// checking each against the checksum it was written with. `events` is what
/// the backup's plan said it holds.
pub fn verify(dest: &Path, opts: crate::Options, events: u64) -> io::Result<Verified> {
    let opts = crate::Options { log_compact_segments: 0, ..opts };
    let (store, w) = crate::Store::open(dest, opts)?;
    let n = w.next_seq();
    if n != events {
        return Err(io::Error::other(format!("the backup holds {n} events, the plan said {events}")));
    }
    let v = store.snapshot();
    let mut checked = 0;
    let step = (n / 2000).max(1);
    let mut seq = 0;
    while seq < n {
        if v.is_live(seq) {
            if !v.intact(seq) {
                return Err(io::Error::other(format!("event {seq} in the backup does not match its checksum")));
            }
            checked += 1;
        }
        seq += step;
    }
    Ok(Verified { events: n, checked })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames of every length class, some flagged dead, in a file; then copied
    /// in blocks of many sizes, so that headers straddle blocks at every offset.
    #[test]
    fn dead_flags_are_set_whatever_the_blocks() {
        let mut file = Vec::new();
        let mut frames = Vec::new();
        for seq in 0..60u64 {
            let len = 1 + (seq * 37 % 300) as usize;
            let flags = if seq % 2 == 0 { log::FLAG_DEAD } else { 0 } | 0x10;
            frames.push((file.len(), seq));
            file.extend_from_slice(&(len as u32).to_le_bytes());
            file.extend_from_slice(&flags.to_le_bytes());
            file.extend_from_slice(&seq.to_le_bytes());
            file.extend_from_slice(&0xC0FFEEu32.to_le_bytes());
            file.extend((0..len).map(|i| (i as u8) ^ (seq as u8)));
        }
        let end = file.len() as u64;
        file.extend_from_slice(&[0u8; 64]);
        let path = std::env::temp_dir().join(format!("relay-backup-frames-{}", std::process::id()));
        std::fs::write(&path, &file).unwrap();
        let src = File::open(&path).unwrap();
        let was_dead = |seq: u64| seq % 3 == 0;
        for block in [1usize, 2, 3, 5, 7, 13, 16, 19, 20, 21, 64, 333, 4096, file.len()] {
            let mut out = Vec::with_capacity(file.len());
            let mut f = Frames { at: 0, end: file.len() as u64 };
            for (i, chunk) in file.chunks(block).enumerate() {
                let mut buf = chunk.to_vec();
                f.patch(&src, &was_dead, &mut buf, (i * block) as u64).unwrap();
                out.extend_from_slice(&buf);
            }
            assert_eq!(f.end, end, "block {block}: the frames end where they do");
            for &(o, seq) in &frames {
                let flags = u32::from_le_bytes(out[o + 4..o + 8].try_into().unwrap());
                assert_eq!(flags & log::FLAG_DEAD != 0, was_dead(seq), "block {block}, seq {seq}");
                assert_eq!(flags & !log::FLAG_DEAD, 0x10, "block {block}, seq {seq}: other flags kept");
            }
            // Nothing but flags words changed.
            let mut a = file.clone();
            let mut b = out.clone();
            for &(o, _) in &frames {
                a[o + 4..o + 8].fill(0);
                b[o + 4..o + 8].fill(0);
            }
            assert!(a == b, "block {block}: only flags changed");
        }
        let _ = std::fs::remove_file(&path);
    }
}
