//! The writer thread: group commit and the hand-off to every reactor.
//!
//! Reactors parse and verify events on their own cores and queue them here.
//! The writer takes everything queued (one batch), commits it with a single
//! sync, then sends each reactor one message holding both the OK replies for
//! its connections and every newly stored event for its live subscriptions.
//! A reactor therefore always sees an event's OK and its fan-out together, and
//! learns about new events the moment they are durable: no polling, no inotify.

use crate::subs::ConnId;
use relay_store::{Outcome, Store, SyncTicket, Writer};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
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
/// The same while an operator's request is being worked through: its next
/// piece is usually already on its way.
const CONTROL_TICK: Duration = Duration::from_millis(2);

/// Set on SIGTERM: the writer finishes the batch in flight, syncs, and returns.
pub static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// What the admin socket asks of the writer, which alone may change the store.
/// The writer takes one between batches, so live writes wait for at most one.
pub enum Control {
    /// Kill whichever of these events are still live; the reply is how many were.
    Kill { seqs: Vec<u64>, reply: Sender<io::Result<usize>> },
    /// Record the kills so far in a checkpoint, so they survive a restart.
    Checkpoint { reply: Sender<io::Result<()>> },
}

fn control(w: &mut Writer, c: Control) {
    match c {
        Control::Kill { seqs, reply } => {
            let _ = reply.send(w.kill_live(&seqs));
        }
        Control::Checkpoint { reply } => {
            let _ = reply.send(w.write_checkpoint());
        }
    }
}

pub struct WriteReq {
    pub reactor: usize,
    pub conn: ConnId,
    pub rec: Vec<u8>,
    /// When the EVENT was read (for the RELAY_DEBUG_WRITER timings).
    pub at: Instant,
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
    /// When the batch's first EVENT was read, and when the batch was handed to
    /// the reactors (for the RELAY_DEBUG_WRITER timings).
    pub received: Instant,
    pub sent: Instant,
}

/// RELAY_DEBUG_WRITER=1: per-second timings of the writer and of live delivery.
pub fn debug() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("RELAY_DEBUG_WRITER").is_some())
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
    /// A COUNT answered by a counting worker, for one connection.
    Count { conn: ConnId, sub: String, n: u64 },
}

/// A COUNT too big to run on a reactor: the snapshot it is counted on, and
/// where the answer goes.
pub struct CountJob {
    pub snap: Arc<relay_store::Version>,
    pub filters: Vec<relay_proto::Filter>,
    pub now: u64,
    pub reactor: usize,
    pub conn: ConnId,
    pub sub: String,
}

pub type Sink = Box<dyn Fn(ReactorMsg) + Send>;

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Runs the writer until every sender is gone.
/// A published batch whose OKs wait for its sync.
struct SyncJob {
    ticket: Option<SyncTicket>,
    replies: Vec<Vec<Reply>>,
    gen: u64,
}

/// Syncs published batches in order, coalescing whatever has queued into one
/// sync, then sends their OKs. Runs beside the writer, so staging the next batch
/// never waits for the disk.
fn syncer(rx: Receiver<SyncJob>, sinks: Vec<Sink>) {
    while let Ok(first) = rx.recv() {
        let mut jobs = vec![first];
        while let Ok(j) = rx.try_recv() {
            jobs.push(j);
        }
        let mut ticket: Option<SyncTicket> = None;
        for j in &mut jobs {
            if let Some(t) = j.ticket.take() {
                match &mut ticket {
                    Some(a) => a.absorb(t),
                    None => ticket = Some(t),
                }
            }
        }
        let failed = match ticket.map_or(Ok(()), |t| t.sync()) {
            Ok(()) => false,
            Err(e) => {
                eprintln!("sync failed: {e}");
                true
            }
        };
        for mut j in jobs {
            if failed {
                for r in j.replies.iter_mut().flatten() {
                    r.outcome = None;
                }
            }
            let msg = Arc::new(Replies { gen: j.gen, replies: j.replies });
            for s in &sinks {
                s(ReactorMsg::Replies(msg.clone()));
            }
        }
    }
}

pub fn run(mut w: Writer, store: Store, rx: Receiver<WriteReq>, ctl: Receiver<Control>, sinks: Vec<Sink>, reply_sinks: Vec<Sink>) {
    let (sync_tx, sync_rx) = std::sync::mpsc::channel::<SyncJob>();
    let sync_thread = std::thread::Builder::new().name("syncer".into()).spawn(move || syncer(sync_rx, reply_sinks)).expect("syncer thread");
    let mut last_sweep = Instant::now();
    let mut reqs: Vec<WriteReq> = Vec::new();
    // RELAY_DEBUG_WRITER=1 prints a per-second breakdown of the writer's cycle.
    let debug = debug();
    let (mut d_batches, mut d_events, mut d_stage, mut d_finish, mut d_idle, mut d_queue) = (0u64, 0u64, 0f64, 0f64, 0f64, 0f64);
    let mut d_last = Instant::now();
    loop {
        // Operator work gets a turn between batches, one piece at a time.
        let wait = match ctl.try_recv() {
            Ok(c) => {
                control(&mut w, c);
                CONTROL_TICK
            }
            Err(_) => IDLE_TICK,
        };
        let wait_started = Instant::now();
        if SHUTDOWN.load(Ordering::Acquire) {
            break;
        }
        let first = match rx.recv_timeout(wait) {
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
        let received = first.at;
        if debug {
            d_queue += received.elapsed().as_secs_f64();
        }
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

        d_idle += wait_started.elapsed().as_secs_f64();
        let t_stage = Instant::now();
        let refs: Vec<&[u8]> = reqs.iter().map(|r| r.rec.as_slice()).collect();
        let staged = w.stage(&refs);
        let stage_secs = t_stage.elapsed().as_secs_f64();
        let mut finish_secs = 0f64;
        let gen = w.next_gen();
        let n = reqs.len();
        let (outcomes, ticket): (Vec<Option<Outcome>>, Option<SyncTicket>) = match staged {
            Ok((outcomes, staged)) => {
                let t_finish = Instant::now();
                match w.publish_staged(staged) {
                    Ok(ticket) => {
                        finish_secs = t_finish.elapsed().as_secs_f64();
                        // Published as `gen`: relay what was stored right away. The
                        // sync runs on the syncer thread and gates only the OKs.
                        let events: Vec<Arc<[u8]>> = reqs
                            .iter()
                            .zip(&outcomes)
                            .filter(|(_, o)| matches!(o, Outcome::Stored(_)))
                            .map(|(r, _)| Arc::<[u8]>::from(r.rec.as_slice()))
                            .collect();
                        if !events.is_empty() {
                            let live = Arc::new(LiveBatch { gen, events, received, sent: Instant::now() });
                            for s in &sinks {
                                s(ReactorMsg::Live(live.clone()));
                            }
                        }
                        (outcomes.into_iter().map(Some).collect(), Some(ticket))
                    }
                    Err(e) => {
                        eprintln!("write failed: {e}");
                        (vec![None; n], None)
                    }
                }
            }
            Err(e) => {
                eprintln!("write failed: {e}");
                (vec![None; n], None)
            }
        };
        let outcomes_len = outcomes.len() as u64;
        let mut replies: Vec<Vec<Reply>> = (0..sinks.len()).map(|_| Vec::new()).collect();
        for (r, outcome) in reqs.drain(..).zip(outcomes) {
            let id: [u8; 32] = r.rec[..32].try_into().unwrap();
            replies[r.reactor].push(Reply { conn: r.conn, id, outcome });
        }
        // OKs, duplicates included, wait for the sync of this batch (and so of
        // every batch before it).
        let _ = sync_tx.send(SyncJob { ticket, replies, gen: store.generation() });
        if debug {
            d_batches += 1;
            d_events += outcomes_len;
            d_stage += stage_secs;
            d_finish += finish_secs;
            if d_last.elapsed().as_secs() >= 1 {
                let ph: Vec<f64> = relay_store::writer::FINISH_NS
                    .iter()
                    .map(|a| a.swap(0, std::sync::atomic::Ordering::Relaxed) as f64 / 1e6 / d_batches.max(1) as f64)
                    .collect();
                eprintln!(
                    "writer: {d_batches} batches, {d_events} events ({:.0}/batch), queue {:.0} us, stage {:.2} ms/batch, finish {:.2} ms/batch (sync {:.2}, build {:.2}, merge {:.2}, publish {:.2}), idle {:.0}%",
                    d_events as f64 / d_batches.max(1) as f64,
                    d_queue * 1e6 / d_batches.max(1) as f64,
                    d_stage * 1e3 / d_batches.max(1) as f64,
                    d_finish * 1e3 / d_batches.max(1) as f64,
                    ph[0],
                    ph[1],
                    ph[2],
                    ph[3],
                    d_idle * 100.0 / d_last.elapsed().as_secs_f64()
                );
                (d_batches, d_events, d_stage, d_finish, d_idle, d_queue) = (0, 0, 0.0, 0.0, 0.0, 0.0);
                d_last = Instant::now();
            }
        }
        // With the OKs out, keep the log's next stretch pre-written.
        if let Err(e) = w.prepare() {
            eprintln!("log preparation failed: {e}");
        }
        if last_sweep.elapsed() >= SWEEP_EVERY {
            sweep(&mut w, &mut last_sweep);
        }
    }
    // Let the syncer finish acknowledging what is in flight.
    drop(sync_tx);
    let _ = sync_thread.join();
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
