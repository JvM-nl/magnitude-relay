//! The torture child: opens the store and runs the workload from a given
//! operation on, acknowledging each one on stdout only once it is durable,
//! until it is killed. Lines:
//!
//! ```text
//! O <next_seq>                 opened
//! A <op> <tokens...>           operation done and durable (outcomes, or a removal count)
//! P <op> <step> <tokens...>    an admin delete's client batch done and durable
//! E <op> <error>               the operation failed (write faults)
//! R <message>                  a panic (in the writer or a reader thread)
//! F <message>                  the store refused to open
//! ```

use super::model::{parse_filter, Out, ADMIN_CHUNK};
use super::work::{self, Op};
use relay_store::{Options, Store, Writer};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, RwLock};

/// "now" for operator walks and queries: past every PAST expiration, before every FUTURE one.
pub const NOW: u64 = 1_800_000_000;

#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub segment_size: u64,
    pub flush_bytes: usize,
    pub log_compact_segments: usize,
    pub log_chunk_bytes: u64,
}

impl Shape {
    pub fn options(&self) -> Options {
        Options {
            segment_size: self.segment_size,
            sync: true,
            flush_bytes: self.flush_bytes,
            vanish_urls: vec![work::URL.to_string()],
            log_compact_segments: self.log_compact_segments,
            log_chunk_bytes: self.log_chunk_bytes,
        }
    }

    pub fn encode(&self) -> String {
        format!("{}:{}:{}:{}", self.segment_size, self.flush_bytes, self.log_compact_segments, self.log_chunk_bytes)
    }

    pub fn decode(s: &str) -> Option<Shape> {
        let v: Vec<u64> = s.split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
        Some(Shape { segment_size: *v.first()?, flush_bytes: *v.get(1)? as usize, log_compact_segments: *v.get(2)? as usize, log_chunk_bytes: *v.get(3)? })
    }
}

pub fn say(line: &str) {
    let mut o = std::io::stdout().lock();
    let _ = o.write_all(line.as_bytes());
    let _ = o.write_all(b"\n");
    let _ = o.flush();
}

fn tokens(outs: &[Out]) -> String {
    outs.iter().map(Out::token).collect::<Vec<_>>().join(" ")
}

fn batch(w: &mut Writer, evs: &[work::Ev]) -> std::io::Result<Vec<Out>> {
    let recs: Vec<Vec<u8>> = evs.iter().map(|e| e.record()).collect();
    let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
    let outs = w.write(&refs)?;
    w.prepare()?;
    Ok(outs.iter().map(Out::of).collect())
}

/// Runs one operation (all but `Restart`, which the loop does). Acknowledgements
/// of an admin delete's client batches are said as they happen.
fn run_op(i: u64, op: &Op, store: &Store, w: &mut Writer) -> std::io::Result<Vec<Out>> {
    match op {
        Op::Batch(evs) => batch(w, evs),
        Op::Delete { filters, older_than } => {
            let fs: Vec<_> = filters.iter().map(|f| parse_filter(f)).collect();
            let n = w.delete_matching(&fs, *older_than, NOW)?;
            Ok(vec![Out::Stored(n as u64)])
        }
        Op::AdminDelete { filters, between } => {
            // As the admin socket does: find on a snapshot held until the
            // checkpoint, kill a few at a time between client batches.
            let fs: Vec<_> = filters.iter().map(|f| parse_filter(f)).collect();
            let v = store.snapshot();
            let seqs: Vec<u64> = v.matching_seqs(&fs, None, NOW).map(|h| h.seq).collect();
            let chunks: Vec<&[u64]> = seqs.chunks(ADMIN_CHUNK).collect();
            let mut killed = 0u64;
            for s in 0..chunks.len().max(between.len()) {
                if let Some(c) = chunks.get(s) {
                    killed += w.kill_live(c)? as u64;
                }
                if let Some(b) = between.get(s) {
                    let outs = batch(w, b)?;
                    say(&format!("P {i} {s} {}", tokens(&outs)));
                }
            }
            w.write_checkpoint()?;
            drop(v);
            Ok(vec![Out::Stored(killed)])
        }
        Op::Sweep(t) => w.sweep_expired(*t).map(|_| Vec::new()),
        Op::FlushAll => w.flush_all().map(|_| Vec::new()),
        Op::CompactAll => w.compact_all().map(|_| Vec::new()),
        Op::CompactLog => w.compact_log_hot().map(|_| Vec::new()),
        Op::MergeLog => w.merge_log_runs().map(|_| Vec::new()),
        Op::Checkpoint => w.write_checkpoint().map(|_| Vec::new()),
        Op::Restart => unreachable!("the loop restarts"),
    }
}

pub fn run(dir: &Path, seed: u64, start: u64, shape: Shape, fault_budget: Option<u64>, readers: bool) -> ! {
    std::panic::set_hook(Box::new(|info| {
        let msg = info.to_string().replace('\n', " | ");
        // The store's frames of the stack, innermost first: enough to place it.
        let bt = std::backtrace::Backtrace::force_capture().to_string();
        let frames: Vec<&str> = bt.lines().map(str::trim).filter(|l| l.contains("relay_store::") || l.contains("relay_adversarial::torture")).take(8).collect();
        say(&format!("R {msg} | at {}", frames.join(" < ")));
        std::process::exit(6);
    }));
    let open = || match Store::open(dir, shape.options()) {
        Ok(x) => x,
        Err(e) => {
            say(&format!("F open: {e}"));
            std::process::exit(4);
        }
    };
    let (store, w) = open();
    say(&format!("O {}", w.next_seq()));
    let slot: Arc<RwLock<Option<Store>>> = Arc::new(RwLock::new(Some(store)));
    if readers {
        super::readers::spawn(slot.clone(), seed);
    }
    let mut w = Some(w);
    if let Some(b) = fault_budget {
        relay_store::fault::fail_writes(dir, b);
    }
    let mut i = start;
    loop {
        let op = work::op(seed, i);
        let r = if let Op::Restart = op {
            // Clean shutdown, as on SIGTERM: flush and sync, then exit; the
            // parent starts the next process, as a restart would.
            let wr = w.as_mut().expect("writer");
            match wr.flush_all().and_then(|()| wr.sync()) {
                Ok(()) => {
                    say(&format!("A {i} "));
                    std::process::exit(0);
                }
                Err(e) => Err(e),
            }
        } else {
            let store = slot.read().unwrap().clone().expect("store");
            run_op(i, &op, &store, w.as_mut().expect("writer"))
        };
        match r {
            Ok(outs) => say(&format!("A {i} {}", tokens(&outs))),
            Err(e) => {
                say(&format!("E {i} {e}"));
                // A failed write leaves the operation's effect unknown: stop here
                // and let the parent decide what the store holds.
                std::process::exit(5);
            }
        }
        i += 1;
    }
}
