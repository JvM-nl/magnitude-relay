//! The protocol, one connection at a time: what each client message does and
//! what goes back. No sockets here; replies are written into an [`Outbox`]
//! (the WebSocket layer frames them in place), so all of it is testable alone.

use crate::ingest::{ReactorMsg, Reply, WriteReq};
use crate::metrics::{self, Block};
use crate::subs::{ConnId, SubIndex};
use relay_proto::event::EventInfo;
use relay_proto::json::{escape_str, Scanner};
use relay_proto::message::{ClientMsg, MsgError};
use relay_proto::negentropy::{self, VecStorage};
use crate::verify::{Checked, Checker, Job, Verdict};
use relay_proto::{hex, kind, EventParser, Filter, Record};
use relay_store::{Outcome, Store, Version};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;

/// Where replies go: one call per protocol message.
pub trait Outbox {
    fn text(&mut self, f: &mut dyn FnMut(&mut Vec<u8>));
}

/// The limits and policy a session enforces (built once from the config).
pub struct SessionCfg {
    pub max_subscriptions: usize,
    pub max_filters: usize,
    pub max_filter_values: usize,
    pub default_limit: usize,
    pub max_limit: usize,
    pub max_event_bytes: usize,
    pub max_future_seconds: u64,
    pub max_tags: usize,
    pub kind_allowed: Box<dyn Fn(u64) -> bool + Send + Sync>,
}

impl SessionCfg {
    pub fn from_config(cfg: &crate::config::Config) -> SessionCfg {
        let kinds = cfg.policy.kind_policy();
        SessionCfg {
            max_subscriptions: cfg.limits.max_subscriptions,
            max_filters: cfg.limits.max_filters,
            max_filter_values: cfg.limits.max_filter_values,
            default_limit: cfg.limits.default_limit,
            max_limit: cfg.limits.max_limit,
            max_event_bytes: cfg.policy.max_event_bytes,
            max_future_seconds: cfg.policy.max_future_seconds,
            max_tags: cfg.policy.max_tags,
            kind_allowed: Box::new(move |k| kinds.allows(k)),
        }
    }

    /// Why an event is refused on policy alone, before anything is hashed:
    /// the same answer for a client's EVENT and for an event synced in.
    pub fn refusal(&self, info: &EventInfo, rec: Record<'_>, now: u64) -> Option<String> {
        if !(self.kind_allowed)(info.kind) {
            Some(format!("blocked: kind {} is not accepted by this relay", info.kind))
        } else if info.tag_count as usize > self.max_tags {
            Some(String::from("invalid: too many tags"))
        } else if info.created_at > now + self.max_future_seconds {
            Some(String::from("invalid: created_at is too far in the future"))
        } else if info.expiration.is_some_and(|e| e <= now) {
            Some(String::from("invalid: event has already expired"))
        } else if info.protected {
            // NIP-70 needs AUTH to prove authorship, and this relay never uses AUTH.
            Some(String::from("blocked: protected events are not accepted here"))
        } else if rec.json_len() > self.max_event_bytes {
            Some(format!("invalid: event is larger than {} bytes", self.max_event_bytes))
        } else {
            None
        }
    }
}

/// Everything a session needs from its reactor.
pub struct Ctx<'a> {
    pub cfg: &'a SessionCfg,
    pub store: &'a Store,
    pub snap: &'a mut Arc<Version>,
    pub subs: &'a mut SubIndex,
    pub writer: &'a SyncSender<WriteReq>,
    pub reactor: usize,
    /// Delivers an ephemeral event to every reactor, this one included.
    pub broadcast: &'a dyn Fn(ReactorMsg),
    /// Takes one EVENT from the client IP's allowance; false when it is spent.
    pub allow_event: &'a dyn Fn() -> bool,
    pub parser: &'a mut EventParser,
    pub rec: &'a mut Vec<u8>,
    /// Events from this read waiting for their signature check.
    pub sigs: &'a mut SigQueue,
    pub now: u64,
    /// This reactor's counters.
    pub m: &'a Block,
    /// Live batches this reactor relayed that are not yet published.
    pub pending: &'a std::collections::VecDeque<Arc<crate::ingest::LiveBatch>>,
    /// Hands a large COUNT to the counting workers; false when they are full.
    pub offload: &'a dyn Fn(crate::ingest::CountJob) -> bool,
    pub conn: ConnId,
}

/// COUNTs expected to walk more index keys than this (about 2.5 ms of work)
/// go to the counting workers, so one big count never stalls a reactor's other
/// connections. Smaller ones are answered on the spot.
const INLINE_COUNT_KEYS: u64 = 50_000;

/// Open negentropy sessions per connection (Vector runs one per relay at a time).
const MAX_NEG_SESSIONS: usize = 8;
/// Largest set a NEG-OPEN may reconcile, as strfry's `maxSyncEvents`.
const MAX_NEG_ITEMS: usize = 2_000_000;
/// Response cap in bytes before hex: ~100 KB on the wire, inside the 128 KB
/// frame Vector's negentropy client assumes.
const NEG_FRAME_LIMIT: usize = 50_000;

/// Most EVENTs a read queues before their signatures are checked: plenty
/// for a batch, since the verifier threads combine reads (`crate::verify`).
const MAX_QUEUED: usize = 64;
/// The same for a connection whose signatures are checked one at a time on
/// its reactor: about 0.6 ms of verification, so a burst still yields to the
/// reactor's other connections.
const MAX_QUEUED_ALONE: usize = 16;

/// EVENTs that passed every check but the signature, held until the frames of
/// the current read are all parsed: then the reactor checks them on the spot,
/// or hands the job to the verifier threads. One per reactor.
#[derive(Default)]
pub struct SigQueue {
    pub checker: Checker,
    pub job: Job,
}

impl SigQueue {
    pub fn len(&self) -> usize {
        self.job.len()
    }

    pub fn is_empty(&self) -> bool {
        self.job.is_empty()
    }
}

pub struct Session {
    pub conn: ConnId,
    /// Events queued to the writer and not yet answered.
    pub pending: usize,
    neg: Vec<(Box<str>, VecStorage)>,
    /// One of our own relays (a `[[peer]]`): gift wraps are listed to it like
    /// any other event, and events this relay took from clients are marked so.
    trusted: bool,
    /// A batch of this connection's signatures failed once: check the rest
    /// one at a time (a client mixing bad signatures into bursts would
    /// otherwise make every batch pay twice).
    no_batch: bool,
}

impl Session {
    pub fn new(conn: ConnId, trusted: bool) -> Session {
        Session { conn, pending: 0, neg: Vec::new(), trusted, no_batch: false }
    }

    pub fn on_text(&mut self, text: &str, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        let msg = ClientMsg::parse(text, cx.parser, cx.rec);
        if !matches!(msg, Ok(ClientMsg::Event { .. })) {
            // Replies keep the order the messages came in.
            self.flush_events(cx, out);
        }
        match msg {
            Ok(ClientMsg::Event { info, at }) => self.on_event(text, info, at, cx, out),
            Ok(ClientMsg::Req { sub_id, filters }) => self.on_req(sub_id, filters, cx, out),
            Ok(ClientMsg::Count { sub_id, filters }) => self.on_count(sub_id, filters, cx, out),
            Ok(ClientMsg::Close { sub_id }) => {
                cx.subs.remove(self.conn, sub_id);
            }
            Ok(ClientMsg::Auth { .. }) => {
                let id = *Record(cx.rec).id();
                ok(out, &id, false, "restricted: this relay does not use AUTH");
            }
            Ok(ClientMsg::NegOpen { sub_id, filter, msg }) => self.on_neg_open(sub_id, filter, &msg, cx, out),
            Ok(ClientMsg::NegMsg { sub_id, msg }) => self.on_neg_msg(sub_id, &msg, out),
            Ok(ClientMsg::NegClose { sub_id }) => self.neg.retain(|(s, _)| &**s != sub_id),
            Err(MsgError::Filter { sub_id, err }) => closed(out, &sub_id, &format!("error: {err}")),
            Err(e) => notice(out, &e.to_string()),
        }
    }

    fn on_event(&mut self, text: &str, info: EventInfo, at: usize, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        metrics::inc(&cx.m.events_in);
        let id = *Record(cx.rec).id();
        // Cheap checks first: nothing below costs a hash until these pass.
        if let Some(msg) = cx.cfg.refusal(&info, Record(cx.rec), cx.now) {
            metrics::inc(&cx.m.events_refused);
            return ok(out, &id, false, &msg);
        }
        if !(cx.allow_event)() {
            metrics::inc(&cx.m.events_refused);
            return ok(out, &id, false, "rate-limited: slow down, too many events from your address");
        }
        // A resend is answered from the index, before any hashing.
        cx.store.refresh(cx.snap);
        // A resend is answered from the index, unless the copy we hold is still
        // syncing: then the writer answers, after the sync, so an OK never
        // promises something a crash could take back.
        if cx.snap.lookup_id(&id).is_some_and(|seq| seq < cx.store.durable_seq()) {
            metrics::inc(&cx.m.events_duplicate);
            return ok(out, &id, true, "duplicate: already have this event");
        }
        // An id is hashed here only when the event had escapes: if their
        // canonical form does not match, the id is retried on the text as
        // received, which only this reactor still has. Every other id is
        // hashed with the signature check, eight at a time.
        if info.any_escaped && cx.parser.confirm_id(Scanner::new_at(text, at), cx.rec, info).is_err() {
            metrics::inc(&cx.m.events_refused);
            return ok(out, &id, false, "invalid: bad event id");
        }
        // Taken from a client and checked here. What a peer sends was taken by
        // some other relay first, so it is not.
        if !self.trusted {
            relay_proto::record::mark_first_hand(cx.rec);
        }
        // The signature last, together with any other EVENTs from this read.
        cx.sigs.job.push(cx.rec, info.kind, !info.any_escaped);
    }

    /// Whether this connection's signatures may be checked in batches.
    pub fn batches(&self) -> bool {
        !self.no_batch
    }

    /// How many EVENTs a read may queue before they must be checked.
    pub fn queue_cap(&self) -> usize {
        if self.no_batch {
            MAX_QUEUED_ALONE
        } else {
            MAX_QUEUED
        }
    }

    /// Verifies the queued signatures here and finishes each event in arrival
    /// order: for a read whose EVENTs do not go to the verifier threads, and
    /// before anything in a read that is not an EVENT.
    pub fn flush_events(&mut self, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        if cx.sigs.is_empty() {
            return;
        }
        // The job comes out of the queue while its events finish (finishing
        // needs the whole context), and goes back empty for the next read.
        let mut job = std::mem::take(&mut cx.sigs.job);
        cx.sigs.checker.check(&mut [&mut job], !self.no_batch);
        self.finish_job(&job, cx, out);
        job.clear();
        cx.sigs.job = job;
    }

    /// Finishes a job's events in arrival order, with the verdicts it carries.
    pub fn finish_job(&mut self, job: &Job, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        match job.checked {
            Checked::OneByOne => {}
            Checked::Batch => {
                metrics::add(&cx.m.sigs_batched, job.len() as u64);
                if job.head {
                    metrics::inc(&cx.m.sig_batches);
                }
            }
            Checked::BatchFailed => {
                metrics::inc(&cx.m.sig_batches_failed);
                self.no_batch = true;
            }
        }
        for ((rec, &kind), &verdict) in job.records().zip(&job.kinds).zip(&job.verdicts) {
            self.finish_event(rec, kind, verdict, cx, out);
        }
    }

    fn finish_event(&mut self, rec: &[u8], kind: u64, verdict: Verdict, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        let id = *Record(rec).id();
        match verdict {
            Verdict::Valid => {}
            Verdict::BadId => {
                metrics::inc(&cx.m.events_refused);
                return ok(out, &id, false, "invalid: bad event id");
            }
            Verdict::BadSig => {
                metrics::inc(&cx.m.events_refused);
                return ok(out, &id, false, "invalid: bad signature");
            }
        }
        if kind::is_ephemeral(kind) {
            metrics::inc(&cx.m.events_ephemeral);
            (cx.broadcast)(ReactorMsg::Ephemeral(Arc::from(rec)));
            // Even with nobody listening: Vector's relay check treats a refusal as fatal.
            return ok(out, &id, true, "");
        }
        match cx.writer.try_send(WriteReq { reactor: cx.reactor, conn: self.conn, rec: rec.to_vec(), at: std::time::Instant::now() }) {
            Ok(()) => self.pending += 1,
            Err(TrySendError::Full(_)) => ok(out, &id, false, "rate-limited: the relay is busy, try again shortly"),
            Err(TrySendError::Disconnected(_)) => ok(out, &id, false, "error: the relay is shutting down"),
        }
    }

    /// Validates filters against the limits and the gift-wrap rule.
    fn check_filters(&self, filters: &mut [Filter], cx: &Ctx<'_>) -> Result<(), String> {
        if filters.len() > cx.cfg.max_filters {
            return Err(format!("error: at most {} filters per request", cx.cfg.max_filters));
        }
        for f in filters.iter_mut() {
            let max = cx.cfg.max_filter_values;
            let too_many = f.ids.as_ref().is_some_and(|v| v.len() > max)
                || f.authors.as_ref().is_some_and(|v| v.len() > max)
                || f.kinds.as_ref().is_some_and(|v| v.len() > max)
                || f.tags.iter().any(|t| t.values.len() > max);
            if too_many {
                return Err(format!("error: at most {max} values per filter list"));
            }
            // No bulk scraping of gift wraps: they are found by author (Concord),
            // recipient (#p) or id, never listed wholesale.
            let addressed = f.ids.is_some() || f.authors.is_some() || f.tags.iter().any(|t| t.name == b'p');
            let wants_wraps = f.kinds.as_ref().is_some_and(|k| k.contains(&kind::GIFT_WRAP));
            if wants_wraps && !addressed && !self.trusted {
                return Err(String::from("restricted: gift wraps are requested by author, recipient or id"));
            }
        }
        Ok(())
    }

    fn on_req(&mut self, sub_id: &str, mut filters: Vec<Filter>, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        metrics::inc(&cx.m.reqs);
        let started = std::time::Instant::now();
        if let Err(msg) = self.check_filters(&mut filters, cx) {
            return closed(out, sub_id, &msg);
        }
        let replacing = cx.subs.count(self.conn) > 0 && cx.subs.remove(self.conn, sub_id);
        if !replacing && cx.subs.count(self.conn) >= cx.cfg.max_subscriptions {
            return closed(out, sub_id, &format!("error: at most {} open subscriptions", cx.cfg.max_subscriptions));
        }
        cx.store.refresh(cx.snap);
        let snap = cx.snap.clone();
        // Live from the snapshot the stored results come from: nothing is missed
        // and nothing is sent twice.
        cx.subs.add_with(self.conn, sub_id, filters.clone(), snap.gen, self.trusted);

        let mut hits = Vec::new();
        for f in &filters {
            let limit = f.limit.map_or(cx.cfg.default_limit, |l| (l as usize).min(cx.cfg.max_limit));
            hits.extend(snap.query(f, limit, cx.now));
        }
        // One filter's results are distinct and in order already. An event two
        // filters match is two equal hits, side by side once sorted.
        if filters.len() > 1 {
            hits.sort_unstable_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));
            hits.dedup_by_key(|h| h.seq);
        }
        // A gift wrap only broad filters matched is left out; with no broad
        // filter (Vector's are never broad) every hit came from one that is not.
        let any_broad = !self.trusted && filters.iter().any(broad);
        for (i, h) in hits.iter().enumerate() {
            // A later event's bytes load while this one is written out.
            if let Some(next) = hits.get(i + 3) {
                snap.prefetch_record(next.seq);
            }
            if let Some(rec) = snap.record(h.seq) {
                if any_broad && hides_wrap(&filters, rec) {
                    continue;
                }
                event_msg(out, sub_id, rec, self.trusted);
                metrics::inc(&cx.m.events_out);
            }
        }
        eose(out, sub_id);
        // Batches relayed live before this subscription existed but published
        // after the snapshot above: in neither the results nor the live stream
        // so far, so they go out now (exactly once).
        for batch in cx.pending.iter().filter(|b| b.gen > snap.gen) {
            for rec in &batch.events {
                let rec = Record(rec);
                if filters.iter().any(|f| f.matches(rec)) && !(any_broad && hides_wrap(&filters, rec)) {
                    event_msg(out, sub_id, rec, self.trusted);
                    metrics::inc(&cx.m.events_live);
                }
            }
        }
        metrics::add(&cx.m.req_micros, started.elapsed().as_micros() as u64);
    }

    fn on_neg_open(&mut self, sub_id: &str, filter: Filter, msg: &[u8], cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        metrics::inc(&cx.m.neg_opens);
        self.neg.retain(|(s, _)| &**s != sub_id);
        let mut fs = [filter];
        if let Err(m) = self.check_filters(&mut fs, cx) {
            return neg_err(out, sub_id, &m);
        }
        let [filter] = fs;
        if self.neg.len() >= MAX_NEG_SESSIONS {
            return neg_err(out, sub_id, "blocked: too many open negentropy sessions");
        }
        cx.store.refresh(cx.snap);
        // `limit` does not apply to a set reconciliation: the whole matching set is the set.
        let mut f = filter;
        f.limit = None;
        // Vector's DM shape is answered from covering index keys alone.
        let items = match cx.snap.neg_items(&f, cx.now) {
            Some(items) => items,
            None => {
                let hits = cx.snap.query(&f, MAX_NEG_ITEMS + 1, cx.now);
                hits.iter().filter(|h| self.trusted || !broad_wrap(&f, cx.snap, h.seq)).map(|h| (h.created_at, h.id)).collect()
            }
        };
        if items.len() > MAX_NEG_ITEMS {
            return neg_err(out, sub_id, "blocked: too many records to reconcile, narrow the filter");
        }
        let storage = VecStorage::new(items);
        match negentropy::reconcile(&storage, msg, NEG_FRAME_LIMIT) {
            Ok(resp) => {
                neg_msg(out, sub_id, &resp);
                self.neg.push((sub_id.into(), storage));
            }
            Err(e) => neg_err(out, sub_id, &format!("error: {e}")),
        }
    }

    fn on_neg_msg(&mut self, sub_id: &str, msg: &[u8], out: &mut dyn Outbox) {
        let Some((_, storage)) = self.neg.iter().find(|(s, _)| &**s == sub_id) else {
            return neg_err(out, sub_id, "closed: no open negentropy session with this id");
        };
        match negentropy::reconcile(storage, msg, NEG_FRAME_LIMIT) {
            Ok(resp) => neg_msg(out, sub_id, &resp),
            Err(e) => {
                neg_err(out, sub_id, &format!("error: {e}"));
                self.neg.retain(|(s, _)| &**s != sub_id);
            }
        }
    }

    fn on_count(&mut self, sub_id: &str, mut filters: Vec<Filter>, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        metrics::inc(&cx.m.counts);
        if let Err(msg) = self.check_filters(&mut filters, cx) {
            return closed(out, sub_id, &msg);
        }
        cx.store.refresh(cx.snap);
        // Exact, always: Vector sizes its syncs with it.
        if cx.snap.count_cost(&filters) > INLINE_COUNT_KEYS {
            let job = crate::ingest::CountJob { snap: cx.snap.clone(), filters, now: cx.now, reactor: cx.reactor, conn: cx.conn, sub: sub_id.to_string() };
            if (cx.offload)(job) {
                metrics::inc(&cx.m.counts_offloaded);
            } else {
                closed(out, sub_id, "rate-limited: too many large counts in progress, try again shortly");
            }
            return;
        }
        count_msg(out, sub_id, cx.snap.count_all(&filters, cx.now));
    }
}

/// `["COUNT", sub, {"count": n}]`.
pub fn count_msg(out: &mut dyn Outbox, sub_id: &str, n: u64) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"COUNT\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",{\"count\":");
        relay_proto::record::push_u64(b, n);
        b.extend_from_slice(b"}]");
    });
}

/// A filter that names no kinds, authors, recipients or ids is a broad scan.
/// Gift wraps are left out of broad scans (stored and live) rather than
/// refusing the whole request: they are found by author, recipient or id only.
#[inline]
pub fn broad(f: &Filter) -> bool {
    f.kinds.is_none() && f.ids.is_none() && f.authors.is_none() && !f.tags.iter().any(|t| t.name == b'p')
}

/// True when `rec` is a gift wrap that only broad filters matched.
pub fn hides_wrap(filters: &[Filter], rec: Record<'_>) -> bool {
    rec.kind() == kind::GIFT_WRAP && !filters.iter().any(|f| !broad(f) && f.matches(rec))
}

/// `["EVENT","sub",{...}]`. To a trusted peer, an event this relay took from
/// a client itself ends `,"first-hand"]`: the peer need not check its signature.
pub fn event_msg(out: &mut dyn Outbox, sub_id: &str, rec: Record<'_>, to_peer: bool) {
    let mark = to_peer && rec.is_first_hand();
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"EVENT\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",");
        rec.write_json(b);
        end_event(b, mark);
    });
}

/// [`event_msg`] with the event's JSON already encoded, for fan-out where it is
/// built once and shared by every subscriber.
pub fn event_msg_json(out: &mut dyn Outbox, sub_id: &str, json: &[u8], first_hand: bool) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"EVENT\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",");
        b.extend_from_slice(json);
        end_event(b, first_hand);
    });
}

#[inline]
fn end_event(b: &mut Vec<u8>, first_hand: bool) {
    if first_hand {
        b.extend_from_slice(b",\"");
        b.extend_from_slice(relay_proto::message::FIRST_HAND);
        b.push(b'"');
    }
    b.push(b']');
}

pub fn eose(out: &mut dyn Outbox, sub_id: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"EOSE\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\"]");
    });
}

pub fn ok(out: &mut dyn Outbox, id: &[u8; 32], accepted: bool, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"OK\",\"");
        hex::encode_into(id, b);
        b.extend_from_slice(if accepted { b"\",true,\"" } else { b"\",false,\"" });
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

/// The OK for an event the writer has finished with.
pub fn ok_reply(out: &mut dyn Outbox, r: &Reply) {
    let (accepted, msg) = match r.outcome {
        Some(Outcome::Stored(_)) => (true, ""),
        Some(Outcome::Duplicate) => (true, "duplicate: already have this event"),
        Some(Outcome::Superseded) => (false, "duplicate: a newer version of this event is already stored"),
        Some(Outcome::Deleted | Outcome::Vanished) => (false, "blocked: this event was deleted"),
        Some(Outcome::Rejected(m)) => (false, m),
        None => (false, "error: could not store the event, try again"),
    };
    ok(out, &r.id, accepted, msg);
}

pub fn closed(out: &mut dyn Outbox, sub_id: &str, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"CLOSED\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",\"");
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

pub fn notice(out: &mut dyn Outbox, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"NOTICE\",\"");
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

pub fn neg_msg(out: &mut dyn Outbox, sub_id: &str, msg: &[u8]) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"NEG-MSG\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",\"");
        hex::encode_into(msg, b);
        b.extend_from_slice(b"\"]");
    });
}

/// A gift wrap that a broad filter would match: left out of reconciliation too.
fn broad_wrap(f: &Filter, snap: &Version, seq: u64) -> bool {
    broad(f) && snap.record(seq).is_some_and(|r| r.kind() == kind::GIFT_WRAP)
}

pub fn neg_err(out: &mut dyn Outbox, sub_id: &str, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"NEG-ERR\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",\"");
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}
