//! The writer thread: group commit and the hand-off to every reactor.
//!
//! Reactors parse and verify events on their own cores and queue them here.
//! The writer takes everything queued (one batch), commits it with a single
//! sync, then sends each reactor one message holding both the OK replies for
//! its connections and every newly stored event for its live subscriptions.
//! A reactor therefore always sees an event's OK and its fan-out together, and
//! learns about new events the moment they are durable: no polling, no inotify.

use crate::subs::ConnId;
use relay_store::{Outcome, Store, Writer};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Upper bounds on one batch. Large enough to amortise the sync under load,
/// small enough that the first event in a full batch is not kept waiting.
const MAX_BATCH_EVENTS: usize = 8192;
const MAX_BATCH_BYTES: usize = 32 << 20;
/// How often expired events are swept from the store.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// How long the writer waits for work before checking for shutdown.
const IDLE_TICK: Duration = Duration::from_millis(200);

/// Set on SIGTERM: the writer finishes the batch in flight, syncs, and returns.
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub struct WriteReq {
    pub reactor: usize,
    pub conn: ConnId,
    pub rec: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    pub conn: ConnId,
    pub id: [u8; 32],
    /// `None` when the batch could not be written (an IO error).
    pub outcome: Option<Outcome>,
}

/// Events that passed every rule and are in the log, relayed live while their
/// sync is still in flight (live delivery does not wait for the disk; only the
/// OK does). `gen` is the version that will publish them.
pub struct LiveBatch {
    pub gen: u64,
    /// Newly stored records, in seq order.
    pub events: Vec<Arc<[u8]>>,
}

/// The OKs for a batch that is now durable and published as version `gen`.
pub struct Replies {
    pub gen: u64,
    /// Indexed by reactor.
    pub replies: Vec<Vec<Reply>>,
}

#[derive(Clone)]
pub enum ReactorMsg {
    Live(Arc<LiveBatch>),
    Replies(Arc<Replies>),
    /// An ephemeral event: delivered live, never stored.
    Ephemeral(Arc<[u8]>),
}

pub type Sink = Box<dyn Fn(ReactorMsg) + Send>;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Runs the writer until every sender is gone.
pub fn run(mut w: Writer, store: Store, rx: Receiver<WriteReq>, sinks: Vec<Sink>) {
    let mut last_sweep = Instant::now();
    let mut reqs: Vec<WriteReq> = Vec::new();
    loop {
        if SHUTDOWN.load(Ordering::Acquire) {
            break;
        }
        let first = match rx.recv_timeout(IDLE_TICK) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => {
                if let Err(e) = w.prepare() {
                    eprintln!("log preparation failed: {e}");
                }
                if let Err(e) = w.maintain() {
                    eprintln!("index maintenance failed: {e}");
                }
                if last_sweep.elapsed() >= SWEEP_EVERY {
                    sweep(&mut w, &mut last_sweep);
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };
        reqs.clear();
        let mut bytes = first.rec.len();
        reqs.push(first);
        while reqs.len() < MAX_BATCH_EVENTS && bytes < MAX_BATCH_BYTES {
            match rx.try_recv() {
                Ok(r) => {
                    bytes += r.rec.len();
                    reqs.push(r);
                }
                Err(_) => break,
            }
        }

        let refs: Vec<&[u8]> = reqs.iter().map(|r| r.rec.as_slice()).collect();
        let staged = w.stage(&refs);
        let gen = w.next_gen();
        let outcomes: Vec<Option<Outcome>> = match staged {
            Ok((outcomes, staged)) => {
                // Relay what was stored now; the sync below only gates the OKs.
                let events: Vec<Arc<[u8]>> =
                    reqs.iter().zip(&outcomes).filter(|(_, o)| matches!(o, Outcome::Stored(_))).map(|(r, _)| Arc::<[u8]>::from(r.rec.as_slice())).collect();
                if !events.is_empty() {
                    let live = Arc::new(LiveBatch { gen, events });
                    for s in &sinks {
                        s(ReactorMsg::Live(live.clone()));
                    }
                }
                match w.finish(staged) {
                    Ok(()) => outcomes.into_iter().map(Some).collect(),
                    Err(e) => {
                        eprintln!("write failed: {e}");
                        vec![None; reqs.len()]
                    }
                }
            }
            Err(e) => {
                eprintln!("write failed: {e}");
                vec![None; reqs.len()]
            }
        };
        let mut replies: Vec<Vec<Reply>> = (0..sinks.len()).map(|_| Vec::new()).collect();
        for (r, outcome) in reqs.drain(..).zip(outcomes) {
            let id: [u8; 32] = r.rec[..32].try_into().unwrap();
            replies[r.reactor].push(Reply { conn: r.conn, id, outcome });
        }
        let msg = Arc::new(Replies { gen: store.generation(), replies });
        for s in &sinks {
            s(ReactorMsg::Replies(msg.clone()));
        }
        // With the OKs out, keep the log's next stretch pre-written.
        if let Err(e) = w.prepare() {
            eprintln!("log preparation failed: {e}");
        }
        if last_sweep.elapsed() >= SWEEP_EVERY {
            sweep(&mut w, &mut last_sweep);
        }
    }
    // Flush the index on the way out so the next start replays nothing.
    if let Err(e) = w.flush_all().and_then(|_| w.sync()) {
        eprintln!("final flush failed: {e}");
    }
}

fn sweep(w: &mut Writer, last: &mut Instant) {
    *last = Instant::now();
    if let Err(e) = w.sweep_expired(now()) {
        eprintln!("expiry sweep failed: {e}");
    }
}
