//! The torture child: opens the store and runs the workload from a given
//! operation on, acknowledging each one on stdout only once it is durable,
//! until it is killed. Lines:
//!
//! ```text
//! O <next_seq>                 opened
//! A <op> <tokens...>           operation done and durable (outcomes, or a removal count)
//! P <op> <step> <tokens...>    an admin delete's client batch done and durable
//! E <op> <error>               the operation failed (write faults)
//! V <op> <next_seq> <published> <live seqs>
//!                              after a failure: what the store holds now
//! N <message>                  the store could not open on a full disk
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
            verify_index: true,
            check_index_in_background: false,
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

/// Write faults for one child: the disk fills up after `budget` more bytes
/// (counted from the open, or from before it with `at_open`), and stays full
/// for `hold` more failed operations after the first, then has room again.
#[derive(Clone, Copy, Debug)]
pub struct Faults {
    pub budget: u64,
    pub hold: u64,
    pub at_open: bool,
}

impl Faults {
    pub fn encode(&self) -> String {
        format!("{}:{}:{}", self.budget, self.hold, u8::from(self.at_open))
    }

    pub fn decode(s: &str) -> Option<Faults> {
        let v: Vec<u64> = s.split(':').map(|x| x.parse().ok()).collect::<Option<_>>()?;
        Some(Faults { budget: *v.first()?, hold: *v.get(1)?, at_open: *v.get(2)? != 0 })
    }
}

/// Live seqs as ranges: `a-b` (inclusive) or `a`.
fn ranges(v: &relay_store::Version) -> String {
    let mut out = Vec::new();
    let mut run: Option<(u64, u64)> = None;
    let close = |a: u64, b: u64, out: &mut Vec<String>| out.push(if a == b { a.to_string() } else { format!("{a}-{b}") });
    for s in 0..v.count {
        if v.is_live(s) {
            run = match run {
                Some((a, b)) if b + 1 == s => Some((a, s)),
                Some((a, b)) => {
                    close(a, b, &mut out);
                    Some((s, s))
                }
                None => Some((s, s)),
            };
        }
    }
    if let Some((a, b)) = run {
        close(a, b, &mut out);
    }
    out.join(" ")
}

/// Parses `ranges` back.
pub fn parse_ranges(t: &str) -> Option<Vec<u64>> {
    let mut v = Vec::new();
    for r in t.split_whitespace() {
        match r.split_once('-') {
            Some((a, b)) => v.extend(a.parse::<u64>().ok()?..=b.parse::<u64>().ok()?),
            None => v.push(r.parse().ok()?),
        }
    }
    Some(v)
}

pub fn run(dir: &Path, seed: u64, start: u64, shape: Shape, faults: Option<Faults>, readers: bool) -> ! {
    std::panic::set_hook(Box::new(|info| {
        // A reader that sees a power cut's pages go back is reading a dead
        // process's memory: wait for the SIGKILL that follows.
        if relay_store::fault::cutting() {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        let msg = info.to_string().replace('\n', " | ");
        // The store's frames of the stack, innermost first: enough to place it.
        let bt = std::backtrace::Backtrace::force_capture().to_string();
        let frames: Vec<&str> = bt.lines().map(str::trim).filter(|l| l.contains("relay_store::") || l.contains("relay-store/src/") || l.contains("relay_adversarial::torture")).take(12).collect();
        say(&format!("R {msg} | at {}", frames.join(" < ")));
        std::process::exit(6);
    }));
    if let Some(f) = faults.filter(|f| f.at_open) {
        relay_store::fault::fail_writes(dir, f.budget);
    }
    let open = || match Store::open(dir, shape.options()) {
        Ok(x) => x,
        Err(e) => {
            // With the disk full from the start, an open that cannot write is
            // expected; what it left behind is checked by the parent's open.
            if faults.is_some_and(|f| f.at_open) {
                say(&format!("N open: {e}"));
                std::process::exit(4);
            }
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
    if let Some(f) = faults.filter(|f| !f.at_open) {
        relay_store::fault::fail_writes(dir, f.budget);
    }
    let mut failures = 0u64;
    let mut i = start;
    loop {
        // For replaying one child by hand: stop before this op, and say which
        // live records cannot be read after each one.
        if std::env::var("ADV_CHILD_STOP_AT").ok().and_then(|v| v.parse::<u64>().ok()).is_some_and(|n| i >= n) {
            std::process::exit(0);
        }
        if crate::env_flag("ADV_CHILD_CHECK") {
            let store = slot.read().unwrap().clone().expect("store");
            let v = store.snapshot();
            let bad: Vec<u64> = (0..v.count).filter(|&s| std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| v.record(s).map(|r| r.id()[0]))).is_err()).collect();
            if !bad.is_empty() {
                say(&format!("U before op {i}: {bad:?}"));
            }
        }
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
                let Some(f) = faults else {
                    // Without injected faults nothing should fail: the parent stops here.
                    std::process::exit(5);
                };
                // As the relay does after a failed write: carry on. Say what the
                // store now holds, so the parent can tell which outcome it was.
                let store = slot.read().unwrap().clone().expect("store");
                let v = store.snapshot();
                say(&format!("V {i} {} {} {}", w.as_ref().expect("writer").next_seq(), v.count, ranges(&v)));
                drop(v);
                failures += 1;
                if failures > f.hold {
                    relay_store::fault::clear(dir);
                }
            }
        }
        i += 1;
    }
}
