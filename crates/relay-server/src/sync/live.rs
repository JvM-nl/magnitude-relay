//! Continuous sync inside a running relay, one `[[sync]]` entry at a time.
//!
//! Each entry runs two loops on the relay's sync thread, each with its own
//! connection to the other relay:
//!
//! - **reconcile**: on start, every `reconcile_seconds`, and whenever the live
//!   connection comes back after a gap, a full negentropy pass (`sync_filter`).
//! - **live**: between passes, a REQ for new events only (`limit: 0`) streams
//!   theirs in (down), and our new events are published as they become durable
//!   (up), found by walking the store's seqs from where the last walk stopped.
//!
//! Nothing here can stall the relay. Events go to the writer the way an
//! operator's delete does (`Control`, one batch between client batches), and
//! this thread waits for the answer; the reactors never see a sync. Memory is
//! bounded by constants, not by the other relay: a window of the set at a
//! time, a few batches, a few hundred unanswered EVENTs, and a cursor (not a
//! queue) for what is still to be published, so a slow relay means we fall
//! behind in the store, not in RAM. A dropped connection is retried with
//! backoff, and the reconcile that follows a reconnect catches up whatever
//! the stream missed.

use super::local::{carries, Inbound, InServer, Local, Refused};
use super::remote::Remote;
use super::{filter_text, slow_down, sync_filter, verdict_of_ok, Backoff, Opts, Report, PUSH_WINDOW};
use crate::config::SyncCfg;
use crate::inbound::{Tally, Verdict};
use crate::ingest::{self, Control};
use crate::session::{self, SessionCfg};
use relay_net::connector::{Connector, RelayUrl};
use relay_proto::json::Scanner;
use relay_proto::message::RelayMsg;
use relay_proto::{EventParser, Filter, Record};
use relay_store::Store;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

/// How often the live loop looks for new events of ours and flushes what it has.
const TICK: Duration = Duration::from_millis(200);
/// Store seqs one tick may walk, so a large backlog never holds up the loop.
const WALK_PER_TICK: u64 = 20_000;
/// Live events stored together.
const LIVE_BATCH: usize = 500;
/// An EVENT unanswered this long is given up on (the next reconcile retries it).
const OK_WAIT: Duration = Duration::from_secs(60);
/// Reconnect backoff: from the first, doubling to the last.
const RECONNECT_FIRST: Duration = Duration::from_secs(1);
const RECONNECT_MAX: Duration = Duration::from_secs(300);
/// A failed reconcile is retried after this, doubling, but never later than
/// the next scheduled one.
const RETRY_FIRST: Duration = Duration::from_secs(10);

/// One entry's counters, for `/stats` and `/metrics`.
#[derive(Debug, Default)]
pub struct Stats {
    pub url: String,
    pub direction: &'static str,
    pub filter: String,
    /// 1 while the live connection is up.
    pub connected: AtomicU64,
    pub reconciles: AtomicU64,
    pub reconcile_failures: AtomicU64,
    /// Unix time the last reconcile finished, and how long it took.
    pub last_reconcile_at: AtomicU64,
    pub last_reconcile_ms: AtomicU64,
    /// What the last reconcile found missing on each side.
    pub last_need: AtomicU64,
    pub last_have: AtomicU64,
    /// Events of theirs stored here, and turned away here (deleted, vanished,
    /// refused by policy, invalid; not counting ones already here).
    pub events_in: AtomicU64,
    pub events_in_refused: AtomicU64,
    /// Theirs not fetched again because an earlier pass turned them away.
    pub events_in_skipped: AtomicU64,
    /// Events of ours they stored, and turned away.
    pub events_out: AtomicU64,
    pub events_out_refused: AtomicU64,
    pub reconnects: AtomicU64,
}

impl Stats {
    fn count_in(&self, t: &Tally) {
        self.events_in.fetch_add(t.stored, Ordering::Relaxed);
        self.events_in_refused.fetch_add(t.turned_away(), Ordering::Relaxed);
    }

    fn count_out(&self, v: &Verdict) {
        let mut t = Tally::default();
        t.add(v);
        self.count_out_all(&t);
    }

    fn count_out_all(&self, t: &Tally) {
        self.events_out.fetch_add(t.stored, Ordering::Relaxed);
        self.events_out_refused.fetch_add(t.turned_away(), Ordering::Relaxed);
    }

    /// `(name, value)` pairs, for the text formats.
    pub fn fields(&self) -> Vec<(&'static str, u64)> {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        vec![
            ("connected", g(&self.connected)),
            ("reconciles", g(&self.reconciles)),
            ("reconcile_failures", g(&self.reconcile_failures)),
            ("last_reconcile_at", g(&self.last_reconcile_at)),
            ("last_reconcile_ms", g(&self.last_reconcile_ms)),
            ("last_need", g(&self.last_need)),
            ("last_have", g(&self.last_have)),
            ("events_in", g(&self.events_in)),
            ("events_in_refused", g(&self.events_in_refused)),
            ("events_in_skipped", g(&self.events_in_skipped)),
            ("events_out", g(&self.events_out)),
            ("events_out_refused", g(&self.events_out_refused)),
            ("reconnects", g(&self.reconnects)),
        ]
    }
}

/// Counters for each entry, made before the relay's shared state is.
pub fn stats_for(entries: &[SyncCfg]) -> Vec<Arc<Stats>> {
    entries
        .iter()
        .map(|c| {
            let filters: Vec<String> = c.filters.iter().map(filter_text).collect();
            let filter = if filters.len() == 1 { filters[0].clone() } else { format!("[{}]", filters.join(",")) };
            Arc::new(Stats { url: c.url.clone(), direction: c.direction.name(), filter, ..Stats::default() })
        })
        .collect()
}

/// Seqs this entry stored itself: its pushes leave them out, since they came
/// from the very relay it pushes to. Ranges, because a batch's events get
/// consecutive seqs; pruned as the push cursor passes them.
#[derive(Default)]
struct Mine {
    ranges: VecDeque<(u64, u64)>,
}

impl Mine {
    fn insert(&mut self, seq: u64) {
        match self.ranges.back_mut() {
            Some((_, end)) if *end == seq => *end = seq + 1,
            Some(&mut (_, end)) if seq < end => {
                // Out of order (two batches crossed): rare, so a plain insert.
                if !self.contains(seq) {
                    let at = self.ranges.partition_point(|&(s, _)| s < seq);
                    self.ranges.insert(at, (seq, seq + 1));
                }
            }
            _ => self.ranges.push_back((seq, seq + 1)),
        }
    }

    fn contains(&self, seq: u64) -> bool {
        let at = self.ranges.partition_point(|&(s, _)| s <= seq);
        at > 0 && seq < self.ranges[at - 1].1
    }

    fn prune_below(&mut self, cursor: u64) {
        while self.ranges.front().is_some_and(|&(_, end)| end <= cursor) {
            self.ranges.pop_front();
        }
    }
}

struct Entry {
    cfg: SyncCfg,
    url: RelayUrl,
    connector: Connector,
    store: Store,
    ctl: Sender<Control>,
    policy: Arc<SessionCfg>,
    stats: Arc<Stats>,
    mine: RefCell<Mine>,
    /// What this entry turned away, so later passes do not fetch it again.
    refused: Rc<RefCell<Refused>>,
    /// The live loop asks for a reconcile after a gap.
    wake: Notify,
}

impl Entry {
    fn local(self: &Rc<Self>) -> InServer {
        let mut l = InServer::new(self.store.clone(), self.ctl.clone(), self.policy.clone());
        let me = self.clone();
        l.on_stored = Box::new(move |seq| me.mine.borrow_mut().insert(seq));
        l.refused = self.refused.clone();
        l
    }

    fn broad(&self) -> bool {
        self.cfg.filters.iter().any(session::broad)
    }
}

/// Starts the sync thread for `entries` (nothing when there are none).
pub fn start(entries: Vec<SyncCfg>, stats: Vec<Arc<Stats>>, store: Store, ctl: Sender<Control>, policy: Arc<SessionCfg>) -> io::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let connector = Connector::new()?;
    std::thread::Builder::new().name("sync".into()).spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("sync runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&rt, async move {
            for (cfg, stats) in entries.into_iter().zip(stats) {
                // Checked when the settings were read.
                let url = RelayUrl::parse(&cfg.url).expect("valid sync url");
                let e = Rc::new(Entry {
                    cfg,
                    url,
                    connector: connector.clone(),
                    store: store.clone(),
                    ctl: ctl.clone(),
                    policy: policy.clone(),
                    stats,
                    mine: RefCell::new(Mine::default()),
                    refused: Rc::new(RefCell::new(Refused::new(Refused::CAP))),
                    wake: Notify::new(),
                });
                tokio::task::spawn_local(reconciler(e.clone()));
                tokio::task::spawn_local(live(e));
            }
            std::future::pending::<()>().await
        });
    })?;
    Ok(())
}

async fn reconciler(e: Rc<Entry>) {
    let every = Duration::from_secs(e.cfg.reconcile_seconds);
    let mut next = Instant::now();
    let mut retry = RETRY_FIRST;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(next.into()) => {}
            _ = e.wake.notified() => {}
        }
        let started = Instant::now();
        match reconcile_once(&e).await {
            Ok(r) => {
                let s = &e.stats;
                s.reconciles.fetch_add(1, Ordering::Relaxed);
                s.last_reconcile_at.store(ingest::now(), Ordering::Relaxed);
                s.last_reconcile_ms.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                s.last_need.store(r.need, Ordering::Relaxed);
                s.last_have.store(r.have, Ordering::Relaxed);
                next = Instant::now() + every;
                retry = RETRY_FIRST;
            }
            Err(why) => {
                eprintln!("sync with {}: reconcile failed: {why}", e.url);
                e.stats.reconcile_failures.fetch_add(1, Ordering::Relaxed);
                next = Instant::now() + retry.min(every);
                retry = (retry * 2).min(Duration::from_secs(600));
            }
        }
    }
}

async fn reconcile_once(e: &Rc<Entry>) -> Result<Report, String> {
    let mut remote = Remote::connect(&e.connector, &e.url).await?;
    let hide_wraps = if e.broad() { remote.hides_wraps().await? } else { false };
    let mut local = e.local();
    let opts = Opts { hide_wraps, ..Opts::new(e.cfg.direction) };
    let mut total = Report::default();
    for f in &e.cfg.filters {
        let mut r = Report::default();
        let result = sync_filter(&mut remote, &mut local, f, &opts, &mut r).await;
        e.stats.count_in(&r.down);
        e.stats.events_in_skipped.fetch_add(r.refused_before, Ordering::Relaxed);
        e.stats.count_out_all(&r.up);
        total.merge(&r);
        result?;
    }
    remote.close().await;
    Ok(total)
}

async fn live(e: Rc<Entry>) {
    // Our events from now on; the first reconcile covers everything before.
    let mut cursor = e.store.snapshot().count;
    let mut backoff = RECONNECT_FIRST;
    let mut first = true;
    loop {
        let started = Instant::now();
        let result = live_once(&e, &mut cursor, !first).await;
        e.stats.connected.store(0, Ordering::Relaxed);
        if let Err(why) = result {
            eprintln!("sync with {}: {why}; reconnecting in {} s", e.url, backoff.as_secs());
        }
        first = false;
        // A connection that lasted was not part of a failing streak.
        if started.elapsed() > RECONNECT_MAX {
            backoff = RECONNECT_FIRST;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_MAX);
        e.stats.reconnects.fetch_add(1, Ordering::Relaxed);
    }
}

/// Events of ours sent and not yet answered, and those to send again.
#[derive(Default)]
struct Outbox {
    waiting: HashMap<[u8; 32], (String, Instant)>,
    again: VecDeque<([u8; 32], String)>,
    backoff: Backoff,
}

async fn live_once(e: &Rc<Entry>, cursor: &mut u64, reconnected: bool) -> Result<(), String> {
    let dir = e.cfg.direction;
    let mut remote = Remote::connect(&e.connector, &e.url).await?;
    let hide_wraps = if dir.up() && e.broad() { remote.hides_wraps().await? } else { false };
    if dir.down() {
        let mut req = String::from("[\"REQ\",\"live\"");
        for f in &e.cfg.filters {
            // New events only: what is already stored is the reconcile's job.
            let f = Filter { limit: Some(0), ..f.clone() };
            req.push(',');
            req.push_str(&filter_text(&f));
        }
        req.push(']');
        remote.send(&req).await?;
    }
    e.stats.connected.store(1, Ordering::Relaxed);
    if reconnected {
        // Whatever happened while we were away.
        e.wake.notify_one();
    }
    let mut local = e.local();
    let mut parser = EventParser::new();
    let mut rec = Vec::new();
    let mut batch: Vec<Inbound> = Vec::new();
    let mut out = Outbox::default();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let ticked = tokio::select! {
            text = remote.next() => {
                let text = text?;
                match RelayMsg::parse(&text) {
                    Ok(RelayMsg::Event { sub_id: "live", at }) if !already_here(&mut parser, &mut rec, &e.store, &text, at) => batch.push(Inbound { text, at }),
                    Ok(RelayMsg::Ok { id, accepted, message }) => answered(e, &mut out, id, accepted, &message),
                    Ok(RelayMsg::Closed { sub_id: "live", message }) => return Err(format!("{} ended the live subscription: {message}", e.url)),
                    _ => {}
                }
                false
            }
            _ = tick.tick() => true,
        };
        if batch.len() >= LIVE_BATCH || (ticked && !batch.is_empty()) {
            let mut t = Tally::default();
            for v in local.ingest(&std::mem::take(&mut batch)).await? {
                t.add(&v);
            }
            e.stats.count_in(&t);
        }
        if ticked && dir.up() {
            publish_new(e, &mut remote, &mut out, cursor, hide_wraps).await?;
        }
    }
}

/// A live event we hold already (we published it, or a reconcile fetched it)
/// is skipped before any checking. One that does not even parse is left for
/// the check to count.
fn already_here(parser: &mut EventParser, rec: &mut Vec<u8>, store: &Store, text: &str, at: usize) -> bool {
    parser.parse_unchecked(&mut Scanner::new_at(text, at), rec).is_ok() && store.snapshot().lookup_id(Record(rec).id()).is_some()
}

/// One OK for something we published live.
fn answered(e: &Entry, out: &mut Outbox, id: [u8; 32], accepted: bool, message: &str) {
    let Some((json, _)) = out.waiting.remove(&id) else { return };
    if slow_down(accepted, message) {
        out.backoff.slowed(Instant::now());
        out.again.push_back((id, json));
    } else {
        out.backoff.accepted();
        e.stats.count_out(&verdict_of_ok(accepted, message));
    }
}

/// Publishes our events that became durable since the last walk, plus any the
/// other relay asked us to send again, keeping at most `PUSH_WINDOW` unanswered.
async fn publish_new(e: &Entry, remote: &mut Remote, out: &mut Outbox, cursor: &mut u64, hide_wraps: bool) -> Result<(), String> {
    let now = Instant::now();
    // Unanswered for too long: the next reconcile will find it if it is missing.
    out.waiting.retain(|_, (_, sent)| now.duration_since(*sent) < OK_WAIT);
    if out.backoff.waiting(now).is_some() {
        return Ok(());
    }
    while out.waiting.len() < PUSH_WINDOW {
        let Some((id, json)) = out.again.pop_front() else { break };
        remote.queue(&format!("[\"EVENT\",{json}]"));
        out.waiting.insert(id, (json, now));
    }
    let v = e.store.snapshot();
    let end = v.count.min(e.store.durable_seq());
    let stop = cursor.saturating_add(WALK_PER_TICK).min(end);
    while *cursor < stop && out.waiting.len() < PUSH_WINDOW {
        let seq = *cursor;
        *cursor += 1;
        if e.mine.borrow().contains(seq) {
            continue;
        }
        let Some(rec) = v.record(seq) else { continue };
        if !carries(&e.cfg.filters, rec, hide_wraps) {
            continue;
        }
        let json = rec.to_json();
        remote.queue(&format!("[\"EVENT\",{json}]"));
        out.waiting.insert(*rec.id(), (json, now));
    }
    e.mine.borrow_mut().prune_below(*cursor);
    remote.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Direction;

    #[test]
    fn mine_tracks_ranges() {
        let mut m = Mine::default();
        for s in [5, 6, 7, 10, 11, 20] {
            m.insert(s);
        }
        assert_eq!(m.ranges.iter().copied().collect::<Vec<_>>(), [(5, 8), (10, 12), (20, 21)]);
        // Two batches that crossed.
        m.insert(8);
        m.insert(15);
        m.insert(6);
        for s in [5, 6, 7, 8, 10, 11, 15, 20] {
            assert!(m.contains(s), "{s}");
        }
        for s in [0, 4, 9, 12, 14, 16, 19, 21] {
            assert!(!m.contains(s), "{s}");
        }
        m.prune_below(12);
        assert_eq!(m.ranges.iter().copied().collect::<Vec<_>>(), [(15, 16), (20, 21)]);
        assert!(!m.contains(5) && m.contains(20));
    }

    #[test]
    fn stats_name_their_entry() {
        let c = SyncCfg { url: "ws://h".into(), direction: Direction::Both, ..SyncCfg::default() };
        let s = &stats_for(&[c])[0];
        assert_eq!((s.url.as_str(), s.direction, s.filter.as_str()), ("ws://h", "both", "{}"));
        s.count_out(&Verdict::Stored);
        s.count_out(&Verdict::Duplicate);
        s.count_out(&Verdict::Refused("no".into()));
        assert_eq!((s.events_out.load(Ordering::Relaxed), s.events_out_refused.load(Ordering::Relaxed)), (1, 1));
    }
}
