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
        Self::map(file, len)
    }

    fn map(file: File, len: usize) -> io::Result<MappedFile> {
        assert!(len > 0, "cannot map an empty range");
        // SAFETY: a fresh shared read-only mapping of a file we keep open.
        let p = unsafe {
            libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, file.as_raw_fd(), 0)
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = NonNull::new(p.cast::<u8>()).ok_or_else(|| io::Error::other("mmap returned null"))?;
        Ok(MappedFile { file, ptr, len })
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

#[derive(Clone, Copy)]
pub enum Advice {
    Random,
    Sequential,
    WillNeed,
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        // SAFETY: unmapping the exact range we mapped; no slices outlive `self`.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
        }
    }
}
