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

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

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
    // SAFETY: signalling our own process.
    unsafe {
        libc::kill(libc::getpid(), libc::SIGKILL);
    }
    // SIGKILL cannot be caught; this is never reached.
    std::process::abort();
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
