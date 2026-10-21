//! A file written with `pwrite` and read through a shared read-only mapping.
//!
//! Writes never go through the mapping, so a reader can never observe a torn
//! page from a half-applied store. The file is extended to the mapping's full
//! length up front; on Linux and macOS that is a sparse extension, so a 1 GiB
//! segment costs nothing until bytes are written into it.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::ptr::NonNull;

pub struct MappedFile {
    file: File,
    ptr: NonNull<u8>,
    len: usize,
    path: std::path::PathBuf,
    /// Set when the file has been retired: it is deleted when the last holder
    /// (a published version) lets go of it.
    obsolete: std::sync::atomic::AtomicBool,
}

// SAFETY: the mapping is read-only and lives as long as the struct; all
// mutation goes through `pwrite` on the file descriptor.
unsafe impl Send for MappedFile {}
unsafe impl Sync for MappedFile {}

impl MappedFile {
    /// Opens (creating if needed) `path`, extends it to at least `len` bytes,
    /// and maps the first `len` bytes.
    pub fn open(path: &Path, len: usize) -> io::Result<MappedFile> {
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        if file.metadata()?.len() < len as u64 {
            file.set_len(len as u64)?;
        }
        Self::map(file, len, path)
    }

    fn map(file: File, len: usize, path: &Path) -> io::Result<MappedFile> {
        assert!(len > 0, "cannot map an empty range");
        // SAFETY: a fresh shared read-only mapping of a file we keep open.
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(p.cast::<u8>()).ok_or_else(|| io::Error::other("mmap returned null"))?;
        Ok(MappedFile { file, ptr, len, path: path.to_path_buf(), obsolete: std::sync::atomic::AtomicBool::new(false) })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The bytes at `[off, off + len)`. The caller only asks for ranges that are
    /// fully written and will not be rewritten while the slice is alive (the
    /// version/epoch rules in `version.rs` guarantee it).
    #[inline]
    pub fn slice(&self, off: usize, len: usize) -> &[u8] {
        assert!(off.checked_add(len).is_some_and(|e| e <= self.len), "read past mapping");
        // SAFETY: in bounds of a live mapping (checked above).
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().add(off), len) }
    }

    #[inline]
    pub fn read_u64(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.slice(off, 8).try_into().unwrap())
    }

    #[inline]
    pub fn read_u32(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.slice(off, 4).try_into().unwrap())
    }

    pub fn write_at(&self, off: u64, data: &[u8]) -> io::Result<()> {
        debug_assert!(off as usize + data.len() <= self.len);
        self.file.write_all_at(data, off)
    }

    /// Makes written data durable. `fdatasync` on Linux; plain `fsync` elsewhere
    /// (macOS is a development platform here, not a durability target).
    pub fn sync(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        // SAFETY: valid descriptor.
        let r = unsafe { libc::fdatasync(self.file.as_raw_fd()) };
        #[cfg(not(target_os = "linux"))]
        // SAFETY: valid descriptor.
        let r = unsafe { libc::fsync(self.file.as_raw_fd()) };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Starts writing a range back to disk without waiting (Linux), so a later
    /// sync finds it already clean.
    pub fn start_writeback(&self, off: u64, len: u64) {
        #[cfg(target_os = "linux")]
        // SAFETY: valid descriptor; advisory.
        unsafe {
            libc::sync_file_range(self.file.as_raw_fd(), off as i64, len as i64, libc::SYNC_FILE_RANGE_WRITE);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (off, len);
    }

    /// Makes `[off, end)` read as zeros and gives whole filesystem blocks in it
    /// back (Linux, `fallocate(PUNCH_HOLE)`; partial blocks are zeroed by the
    /// filesystem). False where that is not available: the caller writes zeros.
    pub fn punch_hole(&self, off: u64, end: u64) -> bool {
        #[cfg(target_os = "linux")]
        {
            if end <= off {
                return true;
            }
            // SAFETY: valid descriptor; the range lies within the file.
            let r = unsafe {
                libc::fallocate(self.file.as_raw_fd(), libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, off as i64, (end - off) as i64)
            };
            r == 0
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (off, end);
            false
        }
    }

    /// Discards everything from `off` to the end, leaving zeros (a hole) behind.
    pub fn zero_from(&self, off: u64) -> io::Result<()> {
        self.file.set_len(off)?;
        self.file.set_len(self.len as u64)
    }

    /// Tells the kernel how the range will be read.
    pub fn advise(&self, advice: Advice) {
        let a = match advice {
            Advice::Random => libc::MADV_RANDOM,
            Advice::Sequential => libc::MADV_SEQUENTIAL,
            Advice::WillNeed => libc::MADV_WILLNEED,
        };
        // SAFETY: advisory only, on our own live mapping.
        unsafe {
            libc::madvise(self.ptr.as_ptr().cast(), self.len, a);
        }
    }
}

impl MappedFile {
    /// Lets the kernel drop `[off, off + len)` from this mapping and from the page
    /// cache: for bytes read once that should not crowd out what is read often.
    /// Only whole pages inside the range go. Readers that touch them again just
    /// fault them back in.
    pub fn drop_cache(&self, off: usize, len: usize) {
        // SAFETY: plain sysconf query.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(4096) as usize;
        let a = off.div_ceil(page) * page;
        let b = (off + len).min(self.len) / page * page;
        if b <= a {
            return;
        }
        // SAFETY: a page-aligned subrange of our own live mapping; advisory.
        unsafe {
            libc::madvise(self.ptr.as_ptr().add(a).cast(), b - a, libc::MADV_DONTNEED);
        }
        #[cfg(target_os = "linux")]
        // SAFETY: valid descriptor; advisory.
        unsafe {
            libc::posix_fadvise(self.file.as_raw_fd(), a as i64, (b - a) as i64, libc::POSIX_FADV_DONTNEED);
        }
    }
}

/// Free bytes on the filesystem holding `path`, for unprivileged writers.
pub fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: a valid C string and a zeroed out-parameter.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    Some((st.f_bavail as u64).saturating_mul(st.f_frsize as u64))
}

/// Memory this process may use: physical memory, or less if its cgroup (v2) is
/// capped. Sizes work that must fit in memory to run at disk speed.
pub fn memory_budget() -> u64 {
    // SAFETY: plain sysconf queries.
    let phys = unsafe { (libc::sysconf(libc::_SC_PHYS_PAGES).max(0) as u64).saturating_mul(libc::sysconf(libc::_SC_PAGESIZE).max(0) as u64) };
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|c| c.lines().find_map(|l| l.strip_prefix("0::").map(|p| p.trim().to_string())))
        .and_then(|p| std::fs::read_to_string(format!("/sys/fs/cgroup{p}/memory.max")).ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    match cgroup {
        Some(c) if phys > 0 => phys.min(c),
        Some(c) => c,
        None if phys > 0 => phys,
        None => 1 << 30,
    }
}

#[derive(Clone, Copy)]
pub enum Advice {
    Random,
    Sequential,
    WillNeed,
}

impl MappedFile {
    /// The file goes once nothing holds this mapping any more.
    pub fn mark_obsolete(&self) {
        self.obsolete.store(true, std::sync::atomic::Ordering::Release);
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        // SAFETY: unmapping the exact range we mapped; no slices outlive `self`.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
        if self.obsolete.load(std::sync::atomic::Ordering::Acquire) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
