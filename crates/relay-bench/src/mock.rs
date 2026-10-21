//! A scripted relay for testing the tester.
//!
//! The tool's whole value is that it catches a relay that answers wrongly, and the
//! only way to know it does is to feed it wrong answers on purpose. This in-process
//! server plays a *perfect* relay for the requests of a workload (the answers are
//! the dataset-derived expectations themselves), then breaks it in one chosen way:
//! an event dropped, repeated, reordered, with the wrong timestamp or an extra one,
//! a wrong COUNT, an unsupported COUNT or NIP-77, a refused subscription, a hung-up
//! connection. Tests assert each break is reported and each healthy run passes.
//!
//! Test-only: it is compiled only for `cargo test`.

use crate::wire::{event_id, Cur};
use crate::workload::{Pool, Step};
use relay_net::conn::{server_handshake, Handshake};
use relay_net::http::DEFAULT_MAX_HEAD;
use relay_net::ws::{write_close_empty, write_pong, write_text, Decoder, Event, Role};
use relay_proto::hex;
use relay_proto::negentropy::{reconcile, VecStorage};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    None,
    /// Leaves out the last event of every answer.
    DropOne,
    /// Sends answers oldest first.
    Reverse,
    /// Reports the first event with a created_at one second off.
    BadTimestamp,
    /// Appends an event nobody asked for.
    Extra,
    /// Sends the first event twice.
    Repeat,
    /// Answers COUNT with one too many.
    WrongCount,
    /// Answers COUNT with a NOTICE (a relay without NIP-45).
    CountNotice,
    /// Never answers COUNT.
    CountSilent,
    /// Answers every REQ with CLOSED.
    ReqClosed,
    /// Closes the connection on the first REQ.
    HangUp,
    /// Answers NEG-OPEN with NEG-ERR.
    NegErr,
    /// Never answers NEG-OPEN.
    NegSilent,
    /// Reconciles against a set missing one id it holds.
    NegForget,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Accept {
    /// OK true for everything.
    All,
    /// OK true "duplicate:" for everything (the relay already has it).
    Duplicates,
    /// OK false "blocked:".
    Reject,
    /// No reply.
    Silent,
}

#[derive(Default)]
pub struct Answers {
    /// Filters JSON (as sent after the subscription id) -> events, newest first.
    pub reqs: HashMap<String, Vec<([u8; 32], u32)>>,
    pub counts: HashMap<String, u64>,
    /// Filter JSON -> the relay's NIP-77 set.
    pub neg: HashMap<String, Vec<(u64, [u8; 32])>>,
}

impl Answers {
    /// The answers a perfect relay gives to every request of `pool`.
    pub fn from_pool(pool: &Pool) -> Answers {
        let mut a = Answers::default();
        for op in &pool.ops {
            for step in &op.steps {
                match step {
                    Step::Req { json, exp } => {
                        let mut evs: Vec<([u8; 32], u32)> = exp.want.iter().map(|(id, ts)| (*id, *ts)).collect();
                        evs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                        a.reqs.insert(json.clone(), evs);
                    }
                    Step::Count { json, expect } => {
                        a.counts.insert(json.clone(), *expect);
                    }
                }
            }
        }
        a
    }
}

pub struct Mock {
    pub addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Mock {
    pub async fn start(answers: Answers, fault: Fault, accept: Accept) -> Mock {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let answers = Arc::new(answers);
        let task = tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else { return };
                let answers = answers.clone();
                tokio::spawn(async move {
                    let _ = serve(s, answers, fault, accept).await;
                });
            }
        });
        Mock { addr, task }
    }

    pub fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }
}

impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn event_json(id: &[u8; 32], ts: u64) -> String {
    format!(
        "{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":{ts},\"kind\":1,\"tags\":[],\"content\":\"mock\",\"sig\":\"{}\"}}",
        hex::encode_string(id),
        "ab".repeat(32),
        "00".repeat(64)
    )
}

async fn serve(mut s: TcpStream, answers: Arc<Answers>, fault: Fault, accept: Accept) -> std::io::Result<()> {
    s.set_nodelay(true)?;
    let mut buf = Vec::new();
    if !matches!(server_handshake(&mut s, &mut buf, DEFAULT_MAX_HEAD).await?, Handshake::Upgraded(_)) {
        return Ok(());
    }
    let mut dec = Decoder::new(Role::Server, 1 << 22, 1 << 22);
    let mut neg_sessions: HashMap<String, VecStorage> = HashMap::new();
    let mut out = Vec::new();
    loop {
        let mut off = 0;
        let mut hang_up = false;
        loop {
            let d = match dec.decode(&mut buf[off..]) {
                Ok(d) => d,
                Err(_) => return Ok(()),
            };
            off += d.consumed;
            match d.event {
                Some(Event::Text(t)) => {
                    let text = t.to_owned();
                    hang_up |= respond(&text, &answers, fault, accept, &mut neg_sessions, &mut out);
                }
                Some(Event::Ping(p)) => write_pong(&mut out, p),
                Some(Event::Close(_)) => {
                    write_close_empty(&mut out);
                    hang_up = true;
                }
                Some(_) => {}
                None => break,
            }
            if hang_up {
                break;
            }
        }
        buf.drain(..off);
        if !out.is_empty() {
            s.write_all(&out).await?;
            out.clear();
        }
        if hang_up {
            return Ok(());
        }
        let missing = dec.needed().saturating_sub(buf.len()).max(4096);
        let old = buf.len();
        buf.resize(old + missing, 0);
        let n = s.read(&mut buf[old..]).await?;
        buf.truncate(old + n);
        if n == 0 {
            return Ok(());
        }
    }
}

fn send(out: &mut Vec<u8>, msg: &str) {
    write_text(out, msg.as_bytes());
}

/// Handles one client message; true means hang up after flushing.
fn respond(text: &str, answers: &Answers, fault: Fault, accept: Accept, neg: &mut HashMap<String, VecStorage>, out: &mut Vec<u8>) -> bool {
    let mut c = Cur::new(text);
    if c.expect(b'[').is_none() {
        return false;
    }
    let Some((label, _)) = c.string() else { return false };
    let sub = |c: &mut Cur<'_>| -> Option<String> {
        c.expect(b',')?;
        Some(c.string()?.0.to_owned())
    };
    match label {
        "REQ" => {
            let Some(sub) = sub(&mut c) else { return false };
            if fault == Fault::HangUp {
                return true;
            }
            if fault == Fault::ReqClosed {
                send(out, &format!("[\"CLOSED\",\"{sub}\",\"restricted: scripted refusal\"]"));
                return false;
            }
            let filters = text.strip_prefix(&format!("[\"REQ\",\"{sub}\",")).and_then(|r| r.strip_suffix(']')).unwrap_or("");
            let mut evs: Vec<([u8; 32], u64)> = answers.reqs.get(filters).map(|v| v.iter().map(|(i, t)| (*i, u64::from(*t))).collect()).unwrap_or_default();
            match fault {
                Fault::DropOne => {
                    evs.pop();
                }
                Fault::Reverse => evs.reverse(),
                Fault::BadTimestamp => {
                    if let Some(e) = evs.first_mut() {
                        e.1 += 1;
                    }
                }
                Fault::Extra => evs.push(([0xee; 32], 1)),
                Fault::Repeat => {
                    if let Some(e) = evs.first().copied() {
                        evs.insert(0, e);
                    }
                }
                _ => {}
            }
            for (id, ts) in &evs {
                send(out, &format!("[\"EVENT\",\"{sub}\",{}]", event_json(id, *ts)));
            }
            send(out, &format!("[\"EOSE\",\"{sub}\"]"));
        }
        "COUNT" => {
            let Some(sub) = sub(&mut c) else { return false };
            match fault {
                Fault::CountNotice => send(out, "[\"NOTICE\",\"ERROR: unknown command COUNT\"]"),
                Fault::CountSilent => {}
                _ => {
                    let filters = text.strip_prefix(&format!("[\"COUNT\",\"{sub}\",")).and_then(|r| r.strip_suffix(']')).unwrap_or("");
                    let n = answers.counts.get(filters).copied().unwrap_or(0) + u64::from(fault == Fault::WrongCount);
                    send(out, &format!("[\"COUNT\",\"{sub}\",{{\"count\":{n}}}]"));
                }
            }
        }
        "EVENT" => {
            let Some(id) = text.strip_prefix("[\"EVENT\",").and_then(|r| r.strip_suffix(']')).and_then(event_id) else { return false };
            let id = hex::encode_string(&id);
            match accept {
                Accept::All => send(out, &format!("[\"OK\",\"{id}\",true,\"\"]")),
                Accept::Duplicates => send(out, &format!("[\"OK\",\"{id}\",true,\"duplicate: already have this event\"]")),
                Accept::Reject => send(out, &format!("[\"OK\",\"{id}\",false,\"blocked: scripted refusal\"]")),
                Accept::Silent => {}
            }
        }
        "NEG-OPEN" => {
            let Some(sub) = sub(&mut c) else { return false };
            match fault {
                Fault::NegSilent => return false,
                Fault::NegErr => {
                    send(out, &format!("[\"NEG-ERR\",\"{sub}\",\"error: negentropy is not supported\"]"));
                    return false;
                }
                _ => {}
            }
            let rest = text.strip_prefix(&format!("[\"NEG-OPEN\",\"{sub}\",")).unwrap_or("");
            let Some(cut) = rest.rfind(",\"") else { return false };
            let (filter, msg) = (&rest[..cut], rest[cut + 2..].trim_end_matches(']').trim_end_matches('"'));
            let mut items = answers.neg.get(filter).cloned().unwrap_or_default();
            if fault == Fault::NegForget {
                items.pop();
            }
            let storage = VecStorage::new(items);
            let Some(bytes) = hex::decode_any_case(msg.as_bytes()) else { return false };
            match reconcile(&storage, &bytes, 50_000) {
                Ok(resp) => {
                    send(out, &format!("[\"NEG-MSG\",\"{sub}\",\"{}\"]", hex::encode_string(&resp)));
                    neg.insert(sub, storage);
                }
                Err(e) => send(out, &format!("[\"NEG-ERR\",\"{sub}\",\"error: {e}\"]")),
            }
        }
        "NEG-MSG" => {
            let Some(sub) = sub(&mut c) else { return false };
            let Some(storage) = neg.get(&sub) else { return false };
            let msg = text.rsplit(',').next().unwrap_or("").trim_end_matches(']').trim_matches('"');
            let Some(bytes) = hex::decode_any_case(msg.as_bytes()) else { return false };
            if let Ok(resp) = reconcile(storage, &bytes, 50_000) {
                send(out, &format!("[\"NEG-MSG\",\"{sub}\",\"{}\"]", hex::encode_string(&resp)));
            }
        }
        _ => {}
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{Dataset, FilterSpec, GIFT_WRAP};
    use crate::load::{self, LoadOpts};
    use crate::neg::{self, Mode, NegOpts};
    use crate::query::{self, QueryOpts};
    use crate::report::RunResult;
    use crate::workload::{build, tests_synthetic, PoolOpts};
    use std::time::Duration;

    fn qopts(url: String, workloads: &[&str]) -> QueryOpts {
        QueryOpts {
            url,
            file: std::path::PathBuf::new(),
            workloads: workloads.iter().map(|s| (*s).to_owned()).collect(),
            conns: 3,
            queries: 60,
            limit: Some(8),
            distinct: 10,
            seed: 2,
            strict_ties: true,
            timeout: Duration::from_millis(1500),
            warmup: 0,
            label: "mock".into(),
            src_ips: 1,
            json: None,
        }
    }

    fn popts() -> PoolOpts {
        PoolOpts { limit: Some(8), distinct: 10, seed: 2 }
    }

    /// Runs `workload` against a mock that is broken in `fault` (or not at all).
    async fn run_one(ds: &Dataset, workload: &str, fault: Fault) -> RunResult {
        let pool = build(workload, ds, &popts()).unwrap();
        let mock = Mock::start(Answers::from_pool(&pool), fault, Accept::All).await;
        let mut runs = query::run(&qopts(mock.url(), &[workload]), ds).await.unwrap();
        assert_eq!(runs.len(), 1);
        runs.remove(0)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_perfect_relay_passes_every_request_workload() {
        let ds = tests_synthetic(2500);
        for w in ["latest_100", "author", "kind", "tag", "time_window", "exact_ids_100", "multi_filter", "dm_inbox", "dm_catchup", "concord_page", "concord_paging", "dm_ids", "miss", "count"] {
            let r = run_one(&ds, w, Fault::None).await;
            assert!(!r.failed() && r.supported, "{w}: {:?} errors {} wrong {}", r.notes, r.errors, r.mismatches);
            assert!(r.ops >= 60, "{w}: {} ops", r.ops);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn every_kind_of_wrong_answer_fails_the_run() {
        let ds = tests_synthetic(2500);
        let cases = [
            (Fault::DropOne, "a missing event"),
            (Fault::Reverse, "oldest first"),
            (Fault::BadTimestamp, "a wrong created_at"),
            (Fault::Extra, "an unrequested event"),
            (Fault::Repeat, "a repeated event"),
        ];
        for (fault, what) in cases {
            for w in ["dm_inbox", "author", "concord_page"] {
                let r = run_one(&ds, w, fault).await;
                assert!(r.failed(), "{w} with {what} passed");
                assert!(r.mismatches > 0, "{w} with {what}: counted as {} errors, {} wrong", r.errors, r.mismatches);
                assert!(r.notes.iter().any(|n| n.contains("WRONG ANSWER")), "{w}/{what}: {:?}", r.notes);
            }
        }
        // The single-event workloads too: a dropped event is a miss even when the answer is one id.
        assert!(run_one(&ds, "exact_id", Fault::DropOne).await.failed());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn wrong_counts_fail_and_missing_features_are_reported_not_failed() {
        let ds = tests_synthetic(2500);
        let r = run_one(&ds, "count", Fault::WrongCount).await;
        assert!(r.failed() && r.mismatches > 0, "{:?}", r.notes);
        let r = run_one(&ds, "count", Fault::CountNotice).await;
        assert!(!r.supported && !r.failed(), "{}", r.row());
        assert!(r.unsupported_reason.contains("NOTICE"), "{}", r.unsupported_reason);
        let r = run_one(&ds, "count", Fault::CountSilent).await;
        assert!(!r.supported && !r.failed(), "{}", r.row());
        assert!(r.unsupported_reason.contains("no reply to COUNT"), "{}", r.unsupported_reason);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refusals_and_dropped_connections_are_errors_and_never_hang() {
        let ds = tests_synthetic(2500);
        let r = run_one(&ds, "dm_inbox", Fault::ReqClosed).await;
        assert!(r.failed() && r.errors > 0 && r.ops == 0, "{:?}", r.notes);
        assert!(r.notes.iter().any(|n| n.contains("restricted")), "{:?}", r.notes);
        let started = std::time::Instant::now();
        let r = run_one(&ds, "dm_inbox", Fault::HangUp).await;
        assert!(r.failed() && r.errors > 0, "{:?}", r.notes);
        assert!(started.elapsed() < Duration::from_secs(20), "a hang-up must not stall the run");
        // A relay that has none of the data: every non-empty expectation is a mismatch.
        let pool = build("author", &ds, &popts()).unwrap();
        let empty = Mock::start(Answers::default(), Fault::None, Accept::All).await;
        let _ = pool;
        let r = query::run(&qopts(empty.url(), &["author"]), &ds).await.unwrap().remove(0);
        assert!(r.failed() && r.mismatches > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ingest_counts_replies_by_kind() {
        let dir = std::env::temp_dir().join(format!("relay-bench-mock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("events.jsonl");
        let p = crate::generate::GenParams { recipients: 10, planes: 4, authors: 10, threads: 2, ..crate::generate::GenParams::new(300, 4) };
        crate::generate::generate(&p, &file).unwrap();
        let opts = |url: String, dup: bool| LoadOpts {
            url,
            file: file.clone(),
            conns: 3,
            window: 16,
            batch_ack: dup,
            duplicates: dup,
            count: None,
            skip: 0,
            timeout: Duration::from_millis(800),
            label: "mock".into(),
            src_ips: 1,
            json: None,
        };
        let go = |accept: Accept, dup: bool| async move {
            let mock = Mock::start(Answers::default(), Fault::None, accept).await;
            load::run(&opts(mock.url(), dup)).await.unwrap()
        };
        let r = go(Accept::All, false).await;
        assert!(!r.failed() && r.ops == 300, "{:?}", r.notes);
        let r = go(Accept::Duplicates, true).await;
        assert!(!r.failed() && r.ops == 300, "{:?}", r.notes);
        let r = go(Accept::Reject, false).await;
        assert!(r.failed() && r.errors == 300, "refusals are errors: {} errors", r.errors);
        let r = go(Accept::Silent, false).await;
        assert!(r.failed() && r.errors > 0 && r.ops == 0, "unanswered events are errors: {:?}", r.notes);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn neg_answers(ds: &Dataset) -> Answers {
        let mut a = Answers::default();
        for (r, _) in ds.wrap_mailboxes() {
            let f = FilterSpec { kinds: vec![GIFT_WRAP], p: vec![r], ..Default::default() };
            let items = ds.matching(&f).into_iter().map(|i| (u64::from(ds.events[i as usize].ts), ds.events[i as usize].id)).collect();
            a.neg.insert(f.to_json(), items);
        }
        a
    }

    fn nopts(url: String, have_pct: u32) -> NegOpts {
        NegOpts {
            url,
            mode: Mode::Heavy,
            have_pct,
            sessions: 6,
            conns: 2,
            seed: 9,
            timeout: Duration::from_millis(1200),
            frame_limit: 60_000,
            label: "mock".into(),
            src_ips: 1,
            json: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn negentropy_is_judged_by_the_reference_client() {
        let ds = tests_synthetic(2500);
        for pct in [0, 50, 100] {
            let mock = Mock::start(neg_answers(&ds), Fault::None, Accept::All).await;
            let r = neg::run(nopts(mock.url(), pct), &ds).await.unwrap();
            assert!(!r.failed() && r.supported && r.ops == 6, "pct {pct}: {:?} {}", r.notes, r.row());
        }
        // A relay that forgets one of its own ids leaves the client with an incomplete `need`.
        let mock = Mock::start(neg_answers(&ds), Fault::NegForget, Accept::All).await;
        let r = neg::run(nopts(mock.url(), 0), &ds).await.unwrap();
        assert!(r.failed() && r.mismatches > 0, "{:?}", r.notes);
        // No NIP-77: reported, not failed; and so is silence.
        for fault in [Fault::NegErr, Fault::NegSilent] {
            let mock = Mock::start(neg_answers(&ds), fault, Accept::All).await;
            let r = neg::run(nopts(mock.url(), 50), &ds).await.unwrap();
            assert!(!r.supported && !r.failed(), "{fault:?}: {}", r.row());
        }
    }
}
