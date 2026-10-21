//! Our side of a sync: the set a filter matches here, the events to send, and
//! a way to store what arrives. The store is reached one of three ways,
//! depending on where the sync runs:
//!
//! - [`Direct`]: the `sync` command with the relay stopped holds the store
//!   and its writer, as `import` does.
//! - [`ViaSocket`]: the `sync` command with the relay running asks it over the
//!   admin socket; the relay checks and stores the events.
//! - [`InServer`]: continuous sync inside the running relay hands events to
//!   the writer thread like a reactor does, without blocking anything.

use crate::admin::{self, Op, Request};
use crate::inbound::{self, Verdict};
use crate::ingest::{self, Control, IngestReply};
use crate::session::{self, SessionCfg};
use relay_proto::json::Scanner;
use relay_proto::{kind, Filter, Record};
use relay_store::{Outcome, Store, Version, Writer};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Arc;

/// One event as another relay sent it: the whole message, and where in it the
/// event object starts. Kept whole so nothing is copied on the way to the check.
pub struct Inbound {
    pub text: String,
    pub at: usize,
}

impl Inbound {
    /// The event object alone.
    pub fn object(&self) -> &str {
        let mut s = Scanner::new_at(&self.text, self.at);
        match s.skip() {
            Ok(()) => &self.text[self.at..s.pos()],
            // Located by RelayMsg::parse, which has skipped it once already.
            Err(_) => &self.text[self.at..],
        }
    }
}

/// `(created_at, id)` of every live event `f` matches here, newest first:
/// a negentropy set. At most `cap` + 1 items, so a caller can tell "more than
/// `cap`" without reading the rest. With `hide_wraps`, gift wraps are left out
/// of a filter that does not name their author, recipient or id, as this relay
/// does for its own clients.
///
/// Vector's DM shape is read from covering index keys alone. Anything else
/// walks the matching events and reads each one's header (its id).
pub fn items_of(v: &Version, f: &Filter, hide_wraps: bool, cap: usize, now: u64) -> Vec<(u64, [u8; 32])> {
    let hide = hide_wraps && session::broad(f);
    if !hide {
        if let Some(mut items) = v.neg_items(f, now) {
            if items.len() > cap {
                items.sort_unstable_by(|a, b| b.cmp(a));
                items.truncate(cap.saturating_add(1));
            }
            return items;
        }
    }
    let mut items = Vec::new();
    for h in v.matching(std::slice::from_ref(f), None, now) {
        if hide && v.record(h.seq).is_some_and(|r| r.kind() == kind::GIFT_WRAP) {
            continue;
        }
        items.push((h.created_at, h.id));
        if items.len() > cap {
            break;
        }
    }
    items
}

/// The JSON of whichever of `ids` are stored here.
pub fn events_of(v: &Version, ids: &[[u8; 32]]) -> Vec<String> {
    ids.iter().filter_map(|id| v.lookup_id(id).and_then(|seq| v.record(seq))).map(|r| r.to_json()).collect()
}

/// What a sync needs from our store.
pub trait Local {
    /// See [`items_of`].
    fn items(&mut self, f: &Filter, hide_wraps: bool, cap: usize) -> Result<Vec<(u64, [u8; 32])>, String>;
    /// See [`events_of`].
    fn events(&mut self, ids: &[[u8; 32]]) -> Result<Vec<String>, String>;
    /// Checks and stores events another relay sent; a verdict for each.
    async fn ingest(&mut self, batch: &[Inbound]) -> Result<Vec<Verdict>, String>;
}

/// Checks `batch` and returns the verdicts so far (`None` where an event
/// passed) and the records to store, in order.
fn check_batch(batch: &[Inbound], policy: &SessionCfg, v: &Version, threads: usize) -> (Vec<Option<Verdict>>, Vec<Vec<u8>>) {
    let texts: Vec<(&str, usize)> = batch.iter().map(|e| (e.text.as_str(), e.at)).collect();
    let mut verdicts = Vec::with_capacity(batch.len());
    let mut recs = Vec::new();
    for c in inbound::check_all(&texts, policy, v, ingest::now(), threads) {
        match c {
            Ok(rec) => {
                recs.push(rec);
                verdicts.push(None);
            }
            Err(v) => verdicts.push(Some(v)),
        }
    }
    (verdicts, recs)
}

/// Fills the gaps `check_batch` left with what the store did.
fn merge(verdicts: Vec<Option<Verdict>>, stored: Vec<Verdict>) -> Vec<Verdict> {
    let mut stored = stored.into_iter();
    verdicts.into_iter().map(|v| v.unwrap_or_else(|| stored.next().unwrap_or(Verdict::Failed))).collect()
}

/// The relay is stopped and the store is ours.
pub struct Direct {
    store: Store,
    w: Writer,
    policy: SessionCfg,
    threads: usize,
}

impl Direct {
    pub fn new(store: Store, w: Writer, policy: SessionCfg) -> Direct {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        Direct { store, w, policy, threads }
    }

    /// Leaves the store as a clean shutdown does: index flushed, nothing to replay.
    pub fn finish(mut self) -> Result<(), String> {
        self.w.flush_all().and_then(|_| self.w.sync()).map_err(|e| e.to_string())
    }
}

impl Local for Direct {
    fn items(&mut self, f: &Filter, hide_wraps: bool, cap: usize) -> Result<Vec<(u64, [u8; 32])>, String> {
        Ok(items_of(&self.store.snapshot(), f, hide_wraps, cap, ingest::now()))
    }

    fn events(&mut self, ids: &[[u8; 32]]) -> Result<Vec<String>, String> {
        Ok(events_of(&self.store.snapshot(), ids))
    }

    async fn ingest(&mut self, batch: &[Inbound]) -> Result<Vec<Verdict>, String> {
        let (verdicts, recs) = check_batch(batch, &self.policy, &self.store.snapshot(), self.threads);
        let refs: Vec<&[u8]> = recs.iter().map(Vec::as_slice).collect();
        let outcomes = if refs.is_empty() { Vec::new() } else { self.w.write(&refs).map_err(|e| format!("cannot store events: {e}"))? };
        Ok(merge(verdicts, outcomes.into_iter().map(|o| Verdict::of(Some(o))).collect()))
    }
}

/// The relay is running: everything goes through its admin socket, and the
/// relay checks what it is handed.
pub struct ViaSocket {
    sock: PathBuf,
    /// Why the store could not be opened directly, for error messages.
    held: String,
}

impl ViaSocket {
    pub fn new(sock: PathBuf, held: String) -> ViaSocket {
        ViaSocket { sock, held }
    }

    fn client(&self) -> Result<admin::Client, String> {
        admin::Client::connect(&self.sock).map_err(|e| format!("{}, and its admin socket {} did not answer: {e}", self.held, self.sock.display()))
    }
}

impl Local for ViaSocket {
    fn items(&mut self, f: &Filter, hide_wraps: bool, cap: usize) -> Result<Vec<(u64, [u8; 32])>, String> {
        let req = Request { limit: Some(cap.min(u64::MAX as usize) as u64), hide_wraps, ..Request::new(Op::Items, vec![f.clone()]) };
        self.client()?.items(&req).map_err(|e| e.to_string())
    }

    fn events(&mut self, ids: &[[u8; 32]]) -> Result<Vec<String>, String> {
        let f = Filter { ids: Some(ids.to_vec()), ..Filter::default() };
        let mut out = Vec::new();
        self.client()?
            .query(&Request::new(Op::Query, vec![f]), &mut |json| {
                out.push(json.to_string());
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        Ok(out)
    }

    async fn ingest(&mut self, batch: &[Inbound]) -> Result<Vec<Verdict>, String> {
        let req = Request { events: batch.iter().map(|e| e.object().to_string()).collect(), ..Request::new(Op::Ingest, Vec::new()) };
        self.client()?.ingest(&req).map_err(|e| e.to_string())
    }
}

/// Inside the running relay: reads from snapshots, writes through the writer
/// thread (between client batches), checks signatures on the sync's own thread.
pub struct InServer {
    store: Store,
    ctl: Sender<Control>,
    policy: Arc<SessionCfg>,
    /// Called with the seq of every event this sync stores, so its own pushes
    /// can leave them out.
    pub on_stored: Box<dyn FnMut(u64)>,
}

impl InServer {
    pub fn new(store: Store, ctl: Sender<Control>, policy: Arc<SessionCfg>) -> InServer {
        InServer { store, ctl, policy, on_stored: Box::new(|_| {}) }
    }
}

impl Local for InServer {
    fn items(&mut self, f: &Filter, hide_wraps: bool, cap: usize) -> Result<Vec<(u64, [u8; 32])>, String> {
        Ok(items_of(&self.store.snapshot(), f, hide_wraps, cap, ingest::now()))
    }

    fn events(&mut self, ids: &[[u8; 32]]) -> Result<Vec<String>, String> {
        Ok(events_of(&self.store.snapshot(), ids))
    }

    async fn ingest(&mut self, batch: &[Inbound]) -> Result<Vec<Verdict>, String> {
        // One thread: this runs beside the relay's own work.
        let (verdicts, recs) = check_batch(batch, &self.policy, &self.store.snapshot(), 1);
        if recs.is_empty() {
            return Ok(merge(verdicts, Vec::new()));
        }
        let n = recs.len();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let reply: IngestReply = Box::new(move |o| {
            let _ = tx.send(o);
        });
        self.ctl.send(Control::Ingest { recs, reply }).map_err(|_| "the relay is shutting down".to_string())?;
        let stored = match rx.await.map_err(|_| "the relay is shutting down".to_string())? {
            Some(outcomes) => outcomes
                .into_iter()
                .map(|o| {
                    if let Outcome::Stored(seq) = o {
                        (self.on_stored)(seq);
                    }
                    Verdict::of(Some(o))
                })
                .collect(),
            None => vec![Verdict::Failed; n],
        };
        Ok(merge(verdicts, stored))
    }
}

/// True when `rec` is one of the events a sync of `filters` carries, given
/// whether gift wraps are left out of broad filters.
pub fn carries(filters: &[Filter], rec: Record<'_>, hide_wraps: bool) -> bool {
    filters.iter().any(|f| f.matches(rec) && !(hide_wraps && rec.kind() == kind::GIFT_WRAP && session::broad(f)))
}
