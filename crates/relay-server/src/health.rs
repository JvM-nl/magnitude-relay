//! The machine the relay runs on, and the relay's own signs of trouble: what
//! `/stats`, `/metrics` and the dashboard warn about. Read when asked (a few
//! small files and two system calls), never on a timer.
//!
//! Pressure is Linux's PSI (`/proc/pressure`): the share of the last 10 or 60
//! seconds in which some (or all) runnable tasks waited for CPU, memory or IO.
//! It says "this machine is overloaded" where load averages and free memory
//! only hint at it. Other systems report what they can; the rest is unknown and
//! raises no warning.

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Syncs, their total time (µs), and how many failed.
pub static SYNCS: AtomicU64 = AtomicU64::new(0);
pub static SYNC_MICROS: AtomicU64 = AtomicU64::new(0);
pub static SYNCS_FAILED: AtomicU64 = AtomicU64::new(0);
/// Syncs slower than `SLOW_SYNC`, and the slowest of them (µs).
pub static SYNCS_SLOW: AtomicU64 = AtomicU64::new(0);
pub static SYNC_SLOWEST_MICROS: AtomicU64 = AtomicU64::new(0);
/// Batches the store could not write, and how many of those for want of space.
pub static WRITES_FAILED: AtomicU64 = AtomicU64::new(0);
pub static WRITES_NO_SPACE: AtomicU64 = AtomicU64::new(0);
/// Set by the first failed sync, for the rest of the process: on Linux a
/// failed fsync may already have dropped the pages it could not write, so a
/// later sync that succeeds proves nothing about them. Writes stop (reads go
/// on) until a restart replays the log from what is really on disk.
static WRITES_STOPPED: AtomicBool = AtomicBool::new(false);

pub fn writes_stopped() -> bool {
    WRITES_STOPPED.load(Ordering::Relaxed)
}

/// When each kind of incident last happened (unix seconds, 0: never).
static LAST_SLOW_SYNC: AtomicU64 = AtomicU64::new(0);
static LAST_WRITE_FAILURE: AtomicU64 = AtomicU64::new(0);
static LAST_NO_SPACE: AtomicU64 = AtomicU64::new(0);

/// A sync is a few ms on an NVMe drive, and tens when a busy disk's cache
/// flushes; a quarter of a second means OKs are waiting on the disk.
pub const SLOW_SYNC: Duration = Duration::from_millis(250);
/// How long an incident keeps its warning up.
const RECENT_SECS: u64 = 300;

fn now() -> u64 {
    crate::ingest::now()
}

/// Counts one sync: how long it took, and whether it worked.
pub fn note_sync(took: Duration, ok: bool) {
    let us = took.as_micros() as u64;
    SYNCS.fetch_add(1, Ordering::Relaxed);
    SYNC_MICROS.fetch_add(us, Ordering::Relaxed);
    if took >= SLOW_SYNC {
        SYNCS_SLOW.fetch_add(1, Ordering::Relaxed);
        SYNC_SLOWEST_MICROS.fetch_max(us, Ordering::Relaxed);
        LAST_SLOW_SYNC.store(now(), Ordering::Relaxed);
    }
    if !ok {
        SYNCS_FAILED.fetch_add(1, Ordering::Relaxed);
        if !WRITES_STOPPED.swap(true, Ordering::Relaxed) {
            eprintln!("a sync failed: new events are refused from now on; restart the relay once the disk is healthy");
        }
    }
}

/// Counts a batch the store could not write.
pub fn note_write_failure(e: &io::Error) {
    WRITES_FAILED.fetch_add(1, Ordering::Relaxed);
    LAST_WRITE_FAILURE.store(now(), Ordering::Relaxed);
    if e.kind() == io::ErrorKind::StorageFull || e.raw_os_error() == Some(libc::ENOSPC) {
        WRITES_NO_SPACE.fetch_add(1, Ordering::Relaxed);
        LAST_NO_SPACE.store(now(), Ordering::Relaxed);
    }
}

/// One PSI resource: the share (percent) of the last 10 and 60 seconds in
/// which some task, and in which every task, was stalled on it.
#[derive(Clone, Copy, Default, Debug)]
pub struct Pressure {
    pub some10: f64,
    pub some60: f64,
    pub full10: f64,
    pub full60: f64,
}

/// What the host looks like now; `None` where this system does not say.
#[derive(Default, Debug)]
pub struct Host {
    pub disk_total: Option<u64>,
    pub disk_available: Option<u64>,
    pub memory_total: Option<u64>,
    pub memory_available: Option<u64>,
    pub cpu: Option<Pressure>,
    pub memory: Option<Pressure>,
    pub io: Option<Pressure>,
    pub open_files: Option<u64>,
    pub open_files_limit: Option<u64>,
}

/// Reads the host's state, with `data` naming the store's volume.
pub fn host(data: &Path) -> Host {
    let (disk_total, disk_available) = disk(data).map_or((None, None), |(t, a)| (Some(t), Some(a)));
    let (memory_total, memory_available) = meminfo().map_or((None, None), |(t, a)| (Some(t), Some(a)));
    Host {
        disk_total,
        disk_available,
        memory_total,
        memory_available,
        cpu: pressure("cpu"),
        memory: pressure("memory"),
        io: pressure("io"),
        open_files: open_files(),
        open_files_limit: open_files_limit(),
    }
}

// statvfs and rlimit field types differ between systems: casts that are no-ops
// on one are needed on another.
#[allow(clippy::unnecessary_cast)]
fn disk(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid C string and a statvfs to fill.
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    let unit = s.f_frsize as u64;
    Some((s.f_blocks as u64 * unit, s.f_bavail as u64 * unit))
}

fn meminfo() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let kb = |key: &str| text.lines().find_map(|l| l.strip_prefix(key)?.trim().strip_suffix("kB")?.trim().parse::<u64>().ok());
    Some((kb("MemTotal:")? * 1024, kb("MemAvailable:")? * 1024))
}

fn pressure(resource: &str) -> Option<Pressure> {
    parse_pressure(&std::fs::read_to_string(format!("/proc/pressure/{resource}")).ok()?)
}

/// `some avg10=1.23 avg60=… avg300=… total=…` and the same for `full`.
fn parse_pressure(text: &str) -> Option<Pressure> {
    let mut p = Pressure::default();
    let mut seen = false;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let which = parts.next()?;
        let field = |name: &str| line.split_whitespace().find_map(|f| f.strip_prefix(name)?.parse::<f64>().ok());
        let (a10, a60) = (field("avg10=")?, field("avg60=")?);
        match which {
            "some" => (p.some10, p.some60, seen) = (a10, a60, true),
            "full" => (p.full10, p.full60) = (a10, a60),
            _ => {}
        }
    }
    seen.then_some(p)
}

fn open_files() -> Option<u64> {
    let dir = if cfg!(target_os = "linux") { "/proc/self/fd" } else { "/dev/fd" };
    std::fs::read_dir(dir).ok().map(|d| d.count() as u64)
}

#[allow(clippy::unnecessary_cast)]
fn open_files_limit() -> Option<u64> {
    let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit fills the struct.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) } == 0 && r.rlim_cur != libc::RLIM_INFINITY).then_some(r.rlim_cur as u64)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Warning,
    Critical,
}

impl Level {
    pub fn name(self) -> &'static str {
        match self {
            Level::Warning => "warning",
            Level::Critical => "critical",
        }
    }
}

#[derive(Debug)]
pub struct Warning {
    pub level: Level,
    /// What it is about: disk, memory, cpu, io, files, sync, writes, damage.
    pub what: &'static str,
    pub message: String,
}

fn gb(b: u64) -> String {
    format!("{:.1} GB", b as f64 / 1e9)
}

/// What deserves an operator's attention now, worst first.
pub fn warnings(h: &Host, damaged_reads: u64) -> Vec<Warning> {
    let mut out = Vec::new();
    let mut warn = |level, what, message: String| out.push(Warning { level, what, message });
    let now = now();
    let recent = |at: &AtomicU64| {
        let t = at.load(Ordering::Relaxed);
        t != 0 && now.saturating_sub(t) < RECENT_SECS
    };

    if damaged_reads > 0 {
        warn(
            Level::Critical,
            "damage",
            format!("{damaged_reads} stored events failed their checksum and are skipped: the disk damaged them. Restore from a backup, or re-import an export"),
        );
    }
    if recent(&LAST_NO_SPACE) {
        warn(Level::Critical, "writes", "the disk is full: new events are refused until space is freed (no restart needed)".into());
    } else if recent(&LAST_WRITE_FAILURE) {
        warn(Level::Critical, "writes", "events could not be written to disk in the last 5 minutes (see the log)".into());
    }
    if writes_stopped() {
        warn(
            Level::Critical,
            "sync",
            "a sync failed, so new events are refused: restart the relay once the disk is healthy (it then reads back what really reached the disk)".into(),
        );
    }
    if let (Some(total), Some(avail)) = (h.disk_total, h.disk_available) {
        let share = avail as f64 / total.max(1) as f64;
        let msg = format!("{} free of {} on the data volume ({:.0}%)", gb(avail), gb(total), share * 100.0);
        // A share alone would cry wolf on a big disk (6% of 2 TB is 120 GB).
        if avail < 1 << 30 || (share < 0.03 && avail < 10 << 30) {
            warn(Level::Critical, "disk", format!("{msg}: nearly full; writes stop when it is"));
        } else if avail < 5 << 30 || (share < 0.10 && avail < 50 << 30) {
            warn(Level::Warning, "disk", msg);
        }
    }
    if let (Some(total), Some(avail)) = (h.memory_total, h.memory_available) {
        let share = avail as f64 / total.max(1) as f64;
        let msg = format!("{} of {} memory available ({:.0}%)", gb(avail), gb(total), share * 100.0);
        if share < 0.05 {
            warn(Level::Critical, "memory", msg);
        } else if share < 0.10 {
            warn(Level::Warning, "memory", msg);
        }
    }
    if let Some(p) = h.memory {
        if p.full60 > 5.0 {
            warn(Level::Critical, "memory", format!("every task stalled on memory {:.0}% of the last minute: the machine is swapping or reclaiming hard", p.full60));
        } else if p.some60 > 10.0 {
            warn(Level::Warning, "memory", format!("tasks waited for memory {:.0}% of the last minute", p.some60));
        }
    }
    if let Some(p) = h.cpu {
        if p.some60 > 75.0 {
            warn(Level::Critical, "cpu", format!("tasks waited for a CPU {:.0}% of the last minute: the machine is overloaded", p.some60));
        } else if p.some60 > 40.0 {
            warn(Level::Warning, "cpu", format!("tasks waited for a CPU {:.0}% of the last minute", p.some60));
        }
    }
    if let Some(p) = h.io {
        if p.full60 > 40.0 {
            warn(Level::Critical, "io", format!("every task stalled on the disk {:.0}% of the last minute", p.full60));
        } else if p.full60 > 10.0 {
            warn(Level::Warning, "io", format!("every task stalled on the disk {:.0}% of the last minute", p.full60));
        }
    }
    if let (Some(open), Some(limit)) = (h.open_files, h.open_files_limit) {
        let share = open as f64 / limit.max(1) as f64;
        let msg = format!("{open} of {limit} open files ({:.0}%): each connection takes one", share * 100.0);
        if share > 0.95 {
            warn(Level::Critical, "files", format!("{msg}; new connections fail at the limit"));
        } else if share > 0.80 {
            warn(Level::Warning, "files", msg);
        }
    }
    if recent(&LAST_SLOW_SYNC) {
        warn(
            Level::Warning,
            "sync",
            format!(
                "{} syncs took over {} ms (the slowest {} ms): OKs waited on the disk",
                SYNCS_SLOW.load(Ordering::Relaxed),
                SLOW_SYNC.as_millis(),
                SYNC_SLOWEST_MICROS.load(Ordering::Relaxed) / 1000
            ),
        );
    }
    out.sort_by_key(|w| w.level != Level::Critical);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pressure_lines() {
        let p = parse_pressure("some avg10=1.50 avg60=42.00 avg300=3.00 total=123\nfull avg10=0.25 avg60=12.50 avg300=0.10 total=9\n").unwrap();
        assert_eq!((p.some10, p.some60, p.full10, p.full60), (1.5, 42.0, 0.25, 12.5));
        // cpu has no `full` line on older kernels.
        let p = parse_pressure("some avg10=0.00 avg60=80.10 avg300=0.00 total=0\n").unwrap();
        assert_eq!((p.some60, p.full60), (80.1, 0.0));
        assert!(parse_pressure("").is_none());
    }

    #[test]
    fn warns_by_threshold_worst_first() {
        let calm = Host {
            disk_total: Some(500 << 30),
            disk_available: Some(100 << 30),
            memory_total: Some(64 << 30),
            memory_available: Some(40 << 30),
            cpu: Some(Pressure { some60: 5.0, ..Default::default() }),
            memory: Some(Pressure::default()),
            io: Some(Pressure { full60: 1.0, ..Default::default() }),
            open_files: Some(5_000),
            open_files_limit: Some(524_288),
        };
        assert!(warnings(&calm, 0).is_empty(), "{:?}", warnings(&calm, 0));
        // 6% free of a big disk is still room.
        let big = Host { disk_total: Some(2000 << 30), disk_available: Some(120 << 30), ..Default::default() };
        assert!(warnings(&big, 0).is_empty());
        let busy = Host {
            disk_available: Some(20 << 30),
            cpu: Some(Pressure { some60: 50.0, ..Default::default() }),
            open_files: Some(520_000),
            ..calm
        };
        let w = warnings(&busy, 3);
        let got: Vec<(&str, Level)> = w.iter().map(|w| (w.what, w.level)).collect();
        assert_eq!(got, [("damage", Level::Critical), ("files", Level::Critical), ("disk", Level::Warning), ("cpu", Level::Warning)]);
    }

    #[test]
    fn reads_this_host() {
        let h = host(Path::new("."));
        assert!(h.disk_total.is_some_and(|t| t > 0) && h.disk_available.is_some());
        assert!(h.open_files.is_some_and(|n| n > 0) && h.open_files_limit.is_some_and(|l| l > 0));
        if cfg!(target_os = "linux") {
            assert!(h.memory_total.is_some() && h.memory_available.is_some());
        }
    }
}
