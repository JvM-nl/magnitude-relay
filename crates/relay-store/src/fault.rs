//! Fault injection for the crash and disk-fault tests. Compiled only into the
//! crate's own unit tests and builds with the `fault-injection` feature: a
//! normal build has none of it, and every hook below expands to nothing.
//!
//! **Crash points.** `crash_point!("name")` marks a moment worth dying at: in
//! the middle of a flush, a compaction, a log exchange, a checkpoint. With
//! `RELAY_CRASH_AT=name:N` in the environment (`*:N` for whichever point comes
//! N-th), the process sends itself SIGKILL the N-th time it gets there. That is
//! exactly what a crash looks like to the files: whatever was written stays in
//! the page cache, nothing after it happens. `RELAY_CRASH_LOG=path` names a file
//! the point is appended to first, so a test knows where its child died.
//!
//! **Write faults.** [`fail_writes`] makes writes to files under a directory
//! fail with ENOSPC once a byte budget is spent, the way a full disk does: the
//! write that crosses the budget lands partly, then fails.
//!
//! **Power cuts.** With `RELAY_POWER_CUT=<seed>` as well, a crash point is a
//! power cut rather than a process crash: before dying, every page written
//! through a [`MappedFile`](crate::mmap::MappedFile) (the log, `locs`) since
//! that file was last synced is set back to one of the states it went through
//! since, chosen at random, as a page cache writing pages back at arbitrary
//! moments would leave it. What was synced stays. Files written whole, synced
//! and renamed into place (segments, checkpoints, `dead.bits`) are left as
//! they are. Writes and syncs are serialised in this mode.

use std::collections::HashMap;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// The crash point named by `RELAY_CRASH_AT`, and how many hits it waits for.
fn target() -> &'static Option<(String, u64)> {
    static T: OnceLock<Option<(String, u64)>> = OnceLock::new();
    T.get_or_init(|| {
        let v = std::env::var("RELAY_CRASH_AT").ok()?;
        let (name, n) = v.rsplit_once(':')?;
        Some((name.to_string(), n.parse().ok()?))
    })
}

static HITS: AtomicU64 = AtomicU64::new(0);

/// Called by `crash_point!`. Dies by SIGKILL on the configured hit.
pub fn crash_point(name: &'static str) {
    let Some((want, n)) = target() else { return };
    if want != "*" && want != name {
        return;
    }
    if HITS.fetch_add(1, Ordering::AcqRel) + 1 != *n {
        return;
    }
    if let Ok(log) = std::env::var("RELAY_CRASH_LOG") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log) {
            let _ = writeln!(f, "{name}");
            let _ = f.sync_all();
        }
    }
    if let Some(p) = power() {
        cut(p);
    }
    // SAFETY: signalling our own process.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
    // SIGKILL cannot be caught; this is never reached.
    std::process::abort();
}

const PAGE: u64 = 4096;

/// Pages written since their file's last sync: (file, page offset) -> the
/// page's contents before each of those writes.
pub struct Unsynced {
    pages: HashMap<(PathBuf, u64), Vec<Vec<u8>>>,
    rng: u64,
}

fn power() -> Option<&'static Mutex<Unsynced>> {
    static P: OnceLock<Option<Mutex<Unsynced>>> = OnceLock::new();
    P.get_or_init(|| {
        let seed: u64 = std::env::var("RELAY_POWER_CUT").ok()?.parse().ok()?;
        Some(Mutex::new(Unsynced { pages: HashMap::new(), rng: seed | 1 }))
    })
    .as_ref()
}

/// Called before `len` bytes at `off` of `file` (at `path`) change: in
/// power-cut mode, remembers the pages as they were. The write must happen
/// while the returned guard is held.
pub fn before_write(path: &Path, file: &std::fs::File, off: u64, len: u64) -> Option<MutexGuard<'static, Unsynced>> {
    let mut u = power()?.lock().unwrap_or_else(|e| e.into_inner());
    let mut page = off / PAGE * PAGE;
    while page < off + len {
        let mut buf = vec![0u8; PAGE as usize];
        let n = file.read_at(&mut buf, page).unwrap_or(0);
        buf.truncate(n);
        u.pages.entry((path.to_path_buf(), page)).or_default().push(buf);
        page += PAGE;
    }
    Some(u)
}

/// Runs `sync` for the file at `path`; in power-cut mode, once it succeeds,
/// the file's writes so far survive any cut.
pub fn sync(path: &Path, sync: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    let Some(p) = power() else { return sync() };
    let mut u = p.lock().unwrap_or_else(|e| e.into_inner());
    sync()?;
    u.pages.retain(|(f, _), _| f != path);
    Ok(())
}

/// Set once a power cut has begun: the process is dead to the files from
/// then on, and what its other threads see (pages going back) means nothing.
static CUTTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether a power cut is under way (a test's panic hook ignores panics then).
pub fn cutting() -> bool {
    CUTTING.load(Ordering::Acquire)
}

/// The cut: every unsynced page back to a random one of its states. The lock
/// stays held, so nothing is written after it.
fn cut(p: &'static Mutex<Unsynced>) {
    CUTTING.store(true, Ordering::Release);
    let mut u = p.lock().unwrap_or_else(|e| e.into_inner());
    let mut rng = u.rng;
    let mut pages: Vec<_> = u.pages.drain().collect();
    pages.sort_by(|a, b| a.0.cmp(&b.0));
    for ((path, page), versions) in pages {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let pick = (rng % (versions.len() as u64 + 1)) as usize;
        if pick == versions.len() {
            continue;
        }
        if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&path) {
            let _ = f.write_all_at(&versions[pick], page);
        }
    }
    std::mem::forget(u);
}

/// Directories whose files fail writes, with the bytes each may still take.
fn budgets() -> &'static Mutex<Vec<(PathBuf, u64)>> {
    static B: OnceLock<Mutex<Vec<(PathBuf, u64)>>> = OnceLock::new();
    B.get_or_init(|| Mutex::new(Vec::new()))
}

/// From now on, writes to files under `dir` take `budget` more bytes, then fail
/// with ENOSPC. Replaces any earlier budget for `dir`.
pub fn fail_writes(dir: &Path, budget: u64) {
    let mut b = budgets().lock().unwrap();
    b.retain(|(d, _)| d != dir);
    b.push((dir.to_path_buf(), budget));
}

/// What is left of the budget on `dir`, if it has one: with a large budget,
/// measures what an operation writes.
pub fn remaining(dir: &Path) -> Option<u64> {
    budgets().lock().unwrap().iter().find(|(d, _)| d == dir).map(|b| b.1)
}

/// Lifts the budget on `dir`: the disk has room again.
pub fn clear(dir: &Path) {
    budgets().lock().unwrap().retain(|(d, _)| d != dir);
}

/// How many of `len` bytes may be written to `path`; fewer than `len` means
/// the write must stop there and fail.
pub fn allowance(path: &Path, len: usize) -> usize {
    let mut b = budgets().lock().unwrap();
    match b.iter_mut().find(|(d, _)| path.starts_with(d)) {
        Some((_, left)) => {
            let n = (*left).min(len as u64);
            *left -= n;
            n as usize
        }
        None => len,
    }
}

/// The error a full disk gives.
pub fn enospc() -> io::Error {
    io::Error::from_raw_os_error(libc::ENOSPC)
}

/// For writes that are all or nothing (a whole small file): fails when the
/// budget cannot take `len` more bytes.
pub fn check(path: &Path, len: usize) -> io::Result<()> {
    if allowance(path, len) < len {
        Err(enospc())
    } else {
        Ok(())
    }
}
