//! The protocol, one connection at a time: what each client message does and
//! what goes back. No sockets here; replies are written into an [`Outbox`]
//! (the WebSocket layer frames them in place), so all of it is testable alone.

use crate::ingest::{ReactorMsg, Reply, WriteReq};
use crate::subs::{ConnId, SubIndex};
use relay_proto::event::{verify_sig, EventInfo};
use relay_proto::json::{escape_str, Scanner};
use relay_proto::message::{ClientMsg, MsgError};
use relay_proto::{hex, kind, EventParser, Filter, Record};
use relay_store::{Outcome, Store, Version};
use std::collections::HashSet;
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
    pub now: u64,
}

pub struct Session {
    pub conn: ConnId,
    /// Events queued to the writer and not yet answered.
    pub pending: usize,
}

impl Session {
    pub fn new(conn: ConnId) -> Session {
        Session { conn, pending: 0 }
    }

    pub fn on_text(&mut self, text: &str, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        match ClientMsg::parse(text, cx.parser, cx.rec) {
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
            Ok(ClientMsg::NegOpen { sub_id, .. } | ClientMsg::NegMsg { sub_id, .. }) => {
                neg_err(out, sub_id, "error: negentropy is not available yet");
            }
            Ok(ClientMsg::NegClose { .. }) => {}
            Err(MsgError::Filter { sub_id, err }) => closed(out, &sub_id, &format!("error: {err}")),
            Err(e) => notice(out, &e.to_string()),
        }
    }

    fn on_event(&mut self, text: &str, info: EventInfo, at: usize, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        let id = *Record(cx.rec).id();
        // Cheap checks first: nothing below costs a hash until these pass.
        let rejection = if !(cx.cfg.kind_allowed)(info.kind) {
            Some(format!("blocked: kind {} is not accepted by this relay", info.kind))
        } else if info.tag_count as usize > cx.cfg.max_tags {
            Some(String::from("invalid: too many tags"))
        } else if info.created_at > cx.now + cx.cfg.max_future_seconds {
            Some(String::from("invalid: created_at is too far in the future"))
        } else if info.expiration.is_some_and(|e| e <= cx.now) {
            Some(String::from("invalid: event has already expired"))
        } else if info.protected {
            // NIP-70 needs AUTH to prove authorship, and this relay never uses AUTH.
            Some(String::from("blocked: protected events are not accepted here"))
        } else if Record(cx.rec).json_len() > cx.cfg.max_event_bytes {
            Some(format!("invalid: event is larger than {} bytes", cx.cfg.max_event_bytes))
        } else {
            None
        };
        if let Some(msg) = rejection {
            return ok(out, &id, false, &msg);
        }
        if !(cx.allow_event)() {
            return ok(out, &id, false, "rate-limited: slow down, too many events from your address");
        }
        // A resend is answered from the index, before any hashing.
        cx.store.refresh(cx.snap);
        if cx.snap.lookup_id(&id).is_some() {
            return ok(out, &id, true, "duplicate: already have this event");
        }
        if cx.parser.confirm_id(Scanner::new_at(text, at), cx.rec, info).is_err() {
            return ok(out, &id, false, "invalid: bad event id");
        }
        if !verify_sig(Record(cx.rec)) {
            return ok(out, &id, false, "invalid: bad signature");
        }
        if kind::is_ephemeral(info.kind) {
            (cx.broadcast)(ReactorMsg::Ephemeral(Arc::from(cx.rec.as_slice())));
            // Even with nobody listening: Vector's relay check treats a refusal as fatal.
            return ok(out, &id, true, "");
        }
        match cx.writer.try_send(WriteReq { reactor: cx.reactor, conn: self.conn, rec: cx.rec.clone() }) {
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
            if wants_wraps && !addressed {
                return Err(String::from("restricted: gift wraps are requested by author, recipient or id"));
            }
        }
        Ok(())
    }

    fn on_req(&mut self, sub_id: &str, mut filters: Vec<Filter>, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
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
        cx.subs.add(self.conn, sub_id, filters.clone(), snap.gen);

        let mut hits = Vec::new();
        let mut seen = HashSet::new();
        for f in &filters {
            let limit = f.limit.map_or(cx.cfg.default_limit, |l| (l as usize).min(cx.cfg.max_limit));
            for h in snap.query(f, limit, cx.now) {
                if seen.insert(h.seq) {
                    hits.push(h);
                }
            }
        }
        if filters.len() > 1 {
            hits.sort_unstable_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));
        }
        for h in hits {
            if let Some(rec) = snap.record(h.seq) {
                if hides_wrap(&filters, rec) {
                    continue;
                }
                event_msg(out, sub_id, rec);
            }
        }
        eose(out, sub_id);
    }

    fn on_count(&mut self, sub_id: &str, mut filters: Vec<Filter>, cx: &mut Ctx<'_>, out: &mut dyn Outbox) {
        if let Err(msg) = self.check_filters(&mut filters, cx) {
            return closed(out, sub_id, &msg);
        }
        cx.store.refresh(cx.snap);
        let n = if filters.len() == 1 {
            cx.snap.count(&filters[0], cx.now)
        } else {
            // A union: events matched by several filters count once.
            let mut seen = HashSet::new();
            for f in &filters {
                for h in cx.snap.query(f, usize::MAX, cx.now) {
                    seen.insert(h.seq);
                }
            }
            seen.len() as u64
        };
        out.text(&mut |b| {
            b.extend_from_slice(b"[\"COUNT\",\"");
            b.extend_from_slice(sub_id.as_bytes());
            b.extend_from_slice(b"\",{\"count\":");
            relay_proto::record::push_u64(b, n);
            b.extend_from_slice(b"}]");
        });
    }
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

pub fn event_msg(out: &mut dyn Outbox, sub_id: &str, rec: Record<'_>) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"EVENT\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",");
        rec.write_json(b);
        b.push(b']');
    });
}

/// `["EVENT","sub",` + pre-encoded event JSON + `]`, for fan-out where the JSON
/// is built once and shared by every subscriber.
pub fn event_msg_json(out: &mut dyn Outbox, sub_id: &str, json: &[u8]) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"EVENT\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",");
        b.extend_from_slice(json);
        b.push(b']');
    });
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
        Some(Outcome::Deleted) => (false, "blocked: this event was deleted"),
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

pub fn neg_err(out: &mut dyn Outbox, sub_id: &str, msg: &str) {
    out.text(&mut |b| {
        b.extend_from_slice(b"[\"NEG-ERR\",\"");
        b.extend_from_slice(sub_id.as_bytes());
        b.extend_from_slice(b"\",\"");
        escape_str(msg, b);
        b.extend_from_slice(b"\"]");
    });
}
