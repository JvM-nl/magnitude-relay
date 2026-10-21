//! A tiny fork-join map over `std::thread`, for the one-off CPU-bound setup work
//! (deriving thousands of keys, pre-signing events) that must not run on the
//! async workers.

use std::thread;

/// Hardware threads, at least 1.
pub fn cpus() -> usize {
    thread::available_parallelism().map_or(1, |n| n.get())
}

/// `(0..n).map(f).collect()` on up to `threads` threads. The output order is the
/// input order whatever the thread count, so results never depend on it.
pub fn par_map<T: Send>(n: usize, threads: usize, f: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let threads = threads.clamp(1, n.max(1));
    if threads == 1 {
        return (0..n).map(f).collect();
    }
    let per = n.div_ceil(threads);
    let f = &f;
    thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let (lo, hi) = (t * per, ((t + 1) * per).min(n));
                s.spawn(move || (lo..hi).map(f).collect::<Vec<T>>())
            })
            .collect();
        let mut out = Vec::with_capacity(n);
        for h in handles {
            out.extend(h.join().expect("worker thread panicked"));
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_is_independent_of_thread_count() {
        let want: Vec<usize> = (0..1000).map(|i| i * i).collect();
        for threads in [1, 2, 3, 7, 64, 5000] {
            assert_eq!(par_map(1000, threads, |i| i * i), want, "threads={threads}");
        }
        assert!(par_map(0, 4, |i| i).is_empty());
    }
}
