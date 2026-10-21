//! A counting allocator: the fuzz runner installs it so every target is held to
//! a memory budget per input, not just to "no panic". A parser that allocates a
//! gigabyte because a length field said so fails here even when the machine
//! could have afforded it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
/// The largest single request seen since the last reset.
static LARGEST: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn grew(n: usize) {
    let now = LIVE.fetch_add(n, Ordering::Relaxed) + n;
    PEAK.fetch_max(now, Ordering::Relaxed);
    LARGEST.fetch_max(n, Ordering::Relaxed);
}

// SAFETY: every call forwards to the system allocator unchanged; the counters
// are bookkeeping only.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        System.alloc(l)
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        grew(l.size());
        System.alloc_zeroed(l)
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        System.dealloc(p, l)
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if new > l.size() {
            grew(new - l.size());
        } else {
            LIVE.fetch_sub(l.size() - new, Ordering::Relaxed);
        }
        System.realloc(p, l, new)
    }
}

/// Starts a measurement: the peak becomes what is live now.
pub fn reset() {
    PEAK.store(LIVE.load(Ordering::Relaxed), Ordering::Relaxed);
    LARGEST.store(0, Ordering::Relaxed);
}

/// Bytes live right now (only meaningful when this allocator is installed).
pub fn live() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// Highest live bytes since `reset`, above what was live at the reset.
pub fn peak_since(base: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(base)
}

/// The largest single allocation since `reset`.
pub fn largest() -> usize {
    LARGEST.load(Ordering::Relaxed)
}
