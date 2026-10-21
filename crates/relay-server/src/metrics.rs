//! Counters, kept per reactor and summed when read.
//!
//! A shared counter bumped by every core on every message bounces its cache
//! line between cores; Magnitude measured 142 ns → 81 ns for four counter
//! updates just from padding them apart. Here each reactor owns a block of
//! counters aligned to 128 bytes (two lines: Intel's adjacent-line prefetcher
//! pairs them) and writes only its own, with relaxed ordering. `/stats` and
//! `/metrics` add the blocks up.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

macro_rules! counters {
    ($( $(#[$doc:meta])* $name:ident ),* $(,)?) => {
        /// One reactor's counters.
        #[repr(align(128))]
        #[derive(Default)]
        pub struct Block {
            $( $(#[$doc])* pub $name: AtomicU64, )*
        }

        /// A summed snapshot.
        #[derive(Default, Debug, Clone, Copy)]
        pub struct Totals {
            $( pub $name: u64, )*
        }

        impl Totals {
            fn add(&mut self, b: &Block) {
                $( self.$name += b.$name.load(Ordering::Relaxed); )*
            }

            /// `(name, value)` pairs, for the text formats.
            pub fn fields(&self) -> Vec<(&'static str, u64)> {
                vec![ $( (stringify!($name), self.$name), )* ]
            }
        }
    };
}

counters! {
    /// WebSocket connections accepted.
    connections_total,
    /// Connections refused at the per-IP limit.
    connections_refused,
    /// Connections that negotiated permessage-deflate.
    connections_deflate,
    /// Text messages received.
    messages_in,
    /// EVENT messages received.
    events_in,
    /// Events stored (OK true, new).
    events_stored,
    /// Events already stored (OK true, duplicate).
    events_duplicate,
    /// Events refused (policy, invalid, deleted, superseded, rate limit).
    events_refused,
    /// Ephemeral events relayed.
    events_ephemeral,
    /// Signatures accepted by a batch check (a read that brought several EVENTs).
    sigs_batched,
    /// Batch checks that passed (`sigs_batched` / this is the mean batch size;
    /// a batch can hold the EVENTs of many connections).
    sig_batches,
    /// Batch checks that failed, so each signature in them was checked alone.
    sig_batches_failed,
    /// EVENT messages sent to subscribers (stored replies and live delivery).
    events_out,
    /// Live deliveries (subset of events_out).
    events_live,
    /// Live deliveries whose bytes were shared with other subscribers, not copied.
    events_shared,
    /// REQ messages.
    reqs,
    /// COUNT messages.
    counts,
    /// COUNTs large enough to be handed to the counting workers.
    counts_offloaded,
    /// NEG-OPEN messages.
    neg_opens,
    /// Sum of REQ time to EOSE, microseconds (with reqs: the mean).
    req_micros,
    /// Bytes written to sockets.
    bytes_out,
    /// Bytes read from sockets.
    bytes_in,
    /// Connections dropped for falling behind.
    slow_drops,
}

pub struct Metrics {
    blocks: Box<[Block]>,
    started: Instant,
    /// Gauge: open connections.
    pub open: AtomicU64,
}

impl Metrics {
    pub fn new(reactors: usize) -> Metrics {
        Metrics { blocks: (0..reactors).map(|_| Block::default()).collect(), started: Instant::now(), open: AtomicU64::new(0) }
    }

    /// The block reactor `i` writes to.
    #[inline]
    pub fn of(&self, i: usize) -> &Block {
        &self.blocks[i]
    }

    pub fn totals(&self) -> Totals {
        let mut t = Totals::default();
        for b in self.blocks.iter() {
            t.add(b);
        }
        t
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }
}

#[inline]
pub fn inc(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn add(c: &AtomicU64, n: u64) {
    c.fetch_add(n, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    #[test]
    fn blocks_are_padded_and_summed() {
        assert_eq!(std::mem::align_of::<super::Block>(), 128);
        let m = super::Metrics::new(3);
        super::inc(&m.of(0).reqs);
        super::add(&m.of(2).reqs, 4);
        assert_eq!(m.totals().reqs, 5);
        assert!(m.totals().fields().iter().any(|(n, v)| *n == "reqs" && *v == 5));
    }
}
