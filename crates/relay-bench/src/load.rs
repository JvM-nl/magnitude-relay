//! `load`: ingest benchmark, and the way to fill a relay before the query workloads.
//!
//! `C` connections publish the dataset file concurrently. Each is a closed loop with
//! up to `W` EVENTs in flight (default 64), matching every `OK` to its event by id,
//! so the latency of an event is send-to-OK. Connections pull lines from one shared
//! reader in small batches, so the file is read once, in order, and never held in
//! memory (a 5M-event file is ~10 GB).
//!
//! `--batch-ack` changes the window from sliding to lock-step: send `W` events, wait
//! for all `W` OKs, send the next `W`. That is how a client behaves that publishes a
//! backlog in bursts, and it removes the relay's chance to overlap one burst's disk
//! sync with the next burst's parsing, so the two modes bracket a relay's behaviour.
//!
//! What counts as an error: an event that gets no OK (timeout or dropped
//! connection), or `OK false` with anything other than a `duplicate:`/`replaced:`
//! reason. A superseded replaceable version is *expected* to be answered that way
//! (the dataset publishes many versions per key, in a racing order), so it is
//! counted separately and is not a failure. `--duplicates` re-sends events the relay
//! already holds, to time the duplicate fast path; `OK true` without a duplicate
//! marker there is reported (`stored_again`) but not failed, since relays word it
//! differently.

use crate::hist::Histogram;
use crate::net::{connect, recv_text, resolve, source_ip, Target};
use crate::report::RunResult;
use crate::wire::{event_id, parse_relay_msg, RelayMsg};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct LoadOpts {
    pub url: String,
    pub file: PathBuf,
    pub conns: usize,
    pub window: usize,
    pub batch_ack: bool,
    pub duplicates: bool,
    /// Publish only the first N events of the file (after `skip`).
    pub count: Option<u64>,
    pub skip: u64,
    pub timeout: Duration,
    pub label: String,
    pub src_ips: usize,
    pub json: Option<String>,
}

/// Lines are handed out in batches of this many, under one lock.
const BATCH: usize = 128;

struct Source {
    rd: BufReader<File>,
    to_skip: u64,
    left: Option<u64>,
}

struct Shared {
    target: Target,
    src: Mutex<Source>,
    window: usize,
    batch_ack: bool,
    duplicates: bool,
    timeout: Duration,
    src_ips: usize,
    notes: Mutex<Vec<String>>,
}

impl Shared {
    fn note(&self, text: String) {
        let mut n = self.notes.lock().unwrap();
        if n.len() < 5 {
            n.push(text);
        }
    }

    /// The next batch of event lines; empty at the end.
    fn next_batch(&self) -> Vec<String> {
        let mut s = self.src.lock().unwrap();
        let mut out = Vec::with_capacity(BATCH);
        let mut line = String::new();
        while out.len() < BATCH && s.left != Some(0) {
            line.clear();
            match s.rd.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let l = line.trim_end_matches(['\n', '\r']);
            if l.is_empty() {
                continue;
            }
            if s.to_skip > 0 {
                s.to_skip -= 1;
                continue;
            }
            if let Some(n) = s.left.as_mut() {
                *n -= 1;
            }
            out.push(l.to_owned());
        }
        out
    }
}

#[derive(Default)]
struct Stats {
    sent: u64,
    acked: u64,
    ok_true: u64,
    /// `OK false` with a duplicate/replaced reason: expected for superseded versions.
    ok_false_benign: u64,
    ok_false_error: u64,
    /// `OK true` in `--duplicates` mode without a duplicate marker.
    stored_again: u64,
    unacked: u64,
    bad_lines: u64,
    stray_oks: u64,
    notices: u64,
    by_reply: BTreeMap<String, u64>,
}

impl Stats {
    fn add(&mut self, o: Stats) {
        self.sent += o.sent;
        self.acked += o.acked;
        self.ok_true += o.ok_true;
        self.ok_false_benign += o.ok_false_benign;
        self.ok_false_error += o.ok_false_error;
        self.stored_again += o.stored_again;
        self.unacked += o.unacked;
        self.bad_lines += o.bad_lines;
        self.stray_oks += o.stray_oks;
        self.notices += o.notices;
        for (k, v) in o.by_reply {
            *self.by_reply.entry(k).or_default() += v;
        }
    }
}

/// The word before the first colon of an OK message (`duplicate`, `blocked`, ...), if
/// it looks like a machine-readable prefix.
pub fn reply_prefix(msg: &str) -> &str {
    match msg.split_once(':') {
        Some((p, _)) if !p.is_empty() && p.len() <= 20 && p.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') => p,
        _ => "",
    }
}

async fn worker(id: usize, sh: Arc<Shared>) -> (Histogram, Stats) {
    let mut hist = Histogram::new();
    let mut st = Stats::default();
    let mut queue: VecDeque<([u8; 32], String)> = VecDeque::new();
    let mut inflight: HashMap<[u8; 32], Instant> = HashMap::new();
    let mut drained = false;
    let mut conn = match connect(&sh.target, source_ip(id, sh.src_ips)).await {
        Ok(c) => c,
        Err(e) => {
            sh.note(format!("connection {id}: {e}"));
            return (hist, st);
        }
    };
    loop {
        if queue.len() < sh.window && !drained {
            let batch = sh.next_batch();
            drained = batch.is_empty();
            for line in batch {
                match event_id(&line) {
                    Some(id) => queue.push_back((id, line)),
                    None => {
                        st.bad_lines += 1;
                        sh.note("a line of the file has no event id".into());
                    }
                }
            }
        }
        // Sliding: top the window up. Lock-step: send a full window only when it is empty.
        let room = if sh.batch_ack {
            if inflight.is_empty() {
                sh.window
            } else {
                0
            }
        } else {
            sh.window.saturating_sub(inflight.len())
        };
        let mut sent_now = false;
        let now = Instant::now();
        for _ in 0..room {
            let Some((eid, line)) = queue.pop_front() else { break };
            let mut msg = String::with_capacity(line.len() + 12);
            msg.push_str("[\"EVENT\",");
            msg.push_str(&line);
            msg.push(']');
            conn.queue_text(&msg);
            inflight.insert(eid, now);
            st.sent += 1;
            sent_now = true;
        }
        if sent_now {
            if let Err(e) = conn.flush().await {
                sh.note(format!("connection {id}: write failed: {e}"));
                break;
            }
        }
        if inflight.is_empty() {
            if drained && queue.is_empty() {
                break;
            }
            continue;
        }
        let text = match recv_text(&mut conn, sh.timeout).await {
            Ok(t) => t,
            Err(e) => {
                sh.note(format!("connection {id}: {e} with {} events unacknowledged", inflight.len()));
                break;
            }
        };
        match parse_relay_msg(&text) {
            RelayMsg::Ok { id: oid, accepted, msg } => {
                let Some(t0) = inflight.remove(&oid) else {
                    st.stray_oks += 1;
                    continue;
                };
                hist.record(t0.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64);
                st.acked += 1;
                let prefix = reply_prefix(&msg);
                *st.by_reply.entry(format!("{accepted}:{}", if prefix.is_empty() { "(none)" } else { prefix })).or_default() += 1;
                if accepted {
                    st.ok_true += 1;
                    if sh.duplicates && prefix != "duplicate" && !msg.contains("duplicate") {
                        st.stored_again += 1;
                    }
                } else if prefix == "duplicate" || prefix == "replaced" {
                    st.ok_false_benign += 1;
                } else {
                    st.ok_false_error += 1;
                    sh.note(format!("refused: {}", crate::report::clip(&msg, 160)));
                }
            }
            RelayMsg::Notice(m) => {
                st.notices += 1;
                sh.note(format!("NOTICE: {}", crate::report::clip(&m, 160)));
            }
            _ => {}
        }
    }
    st.unacked = inflight.len() as u64;
    (hist, st)
}

pub async fn run(o: &LoadOpts) -> Result<RunResult, String> {
    let target = resolve(&o.url).await?;
    let f = File::open(&o.file).map_err(|e| format!("{}: {e}", o.file.display()))?;
    let sh = Arc::new(Shared {
        target,
        src: Mutex::new(Source { rd: BufReader::with_capacity(1 << 20, f), to_skip: o.skip, left: o.count }),
        window: o.window.max(1),
        batch_ack: o.batch_ack,
        duplicates: o.duplicates,
        timeout: o.timeout,
        src_ips: o.src_ips,
        notes: Mutex::new(Vec::new()),
    });
    let workload = if o.duplicates { "ingest_dup" } else { "ingest" };
    let started = Instant::now();
    let tasks: Vec<_> = (0..o.conns.max(1)).map(|i| tokio::spawn(worker(i, sh.clone()))).collect();
    let mut hist = Histogram::new();
    let mut st = Stats::default();
    for t in tasks {
        let (h, s) = t.await.map_err(|e| format!("worker panicked: {e}"))?;
        hist.merge(&h);
        st.add(s);
    }
    let elapsed = started.elapsed();

    let mut r = RunResult::new(&o.label, "load", workload);
    r.conns = o.conns;
    r.ops = st.acked;
    r.secs = elapsed.as_secs_f64();
    r.hist = hist;
    // An event the relay never answered, a hard refusal, or a line we could not send.
    r.errors = st.ok_false_error + st.unacked + st.bad_lines;
    // A connection that failed before sending anything leaves events unread, not unacked:
    // the run published fewer events than the file holds.
    if st.sent == 0 {
        r.errors += 1;
    }
    r.notes = std::mem::take(&mut *sh.notes.lock().unwrap());
    r.param("url", o.url.as_str());
    r.param("file", o.file.display().to_string());
    r.param("window", o.window);
    r.param("batch_ack", o.batch_ack);
    r.param("duplicates", o.duplicates);
    r.param("count", o.count);
    r.param("skip", o.skip);
    r.detail("sent", st.sent);
    r.detail("acked", st.acked);
    r.detail("ok_true", st.ok_true);
    r.detail("ok_false_duplicate_or_replaced", st.ok_false_benign);
    r.detail("ok_false_refused", st.ok_false_error);
    r.detail("stored_again", st.stored_again);
    r.detail("unacked", st.unacked);
    r.detail("stray_oks", st.stray_oks);
    r.detail("notices", st.notices);
    r.info.push(format!(
        "replies: {}",
        st.by_reply.iter().map(|(k, v)| format!("{k} x{v}")).collect::<Vec<_>>().join(", ")
    ));
    r.detail("replies", crate::jsonw::Json::Obj(st.by_reply.into_iter().map(|(k, v)| (k, crate::jsonw::Json::U64(v))).collect()));
    r.print();
    if let Some(path) = &o.json {
        r.append_json(path).map_err(|e| format!("cannot append to {path}: {e}"))?;
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_prefixes() {
        assert_eq!(reply_prefix("duplicate: already have this event"), "duplicate");
        assert_eq!(reply_prefix("rate-limited: slow down"), "rate-limited");
        assert_eq!(reply_prefix(""), "");
        assert_eq!(reply_prefix("no prefix here"), "");
        assert_eq!(reply_prefix("Some Sentence: with a colon"), "");
        assert_eq!(reply_prefix(": leading"), "");
    }

    #[test]
    fn batches_respect_skip_count_and_blank_lines() {
        let dir = std::env::temp_dir().join(format!("relay-bench-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lines.jsonl");
        let body: String = (0..300).map(|i| format!("{{\"n\":{i}}}\n\n")).collect();
        std::fs::write(&path, body).unwrap();
        let mk = |skip, count| Shared {
            target: Target { addr: "127.0.0.1:1".parse().unwrap(), unix: None, host: String::new(), path: "/".into(), url: String::new() },
            src: Mutex::new(Source { rd: BufReader::new(File::open(&path).unwrap()), to_skip: skip, left: count }),
            window: 1,
            batch_ack: false,
            duplicates: false,
            timeout: Duration::from_secs(1),
            src_ips: 1,
            notes: Mutex::new(Vec::new()),
        };
        let sh = mk(0, None);
        let mut all = Vec::new();
        loop {
            let b = sh.next_batch();
            if b.is_empty() {
                break;
            }
            assert!(b.len() <= BATCH);
            all.extend(b);
        }
        assert_eq!(all.len(), 300);
        assert_eq!(all[0], "{\"n\":0}");
        assert_eq!(all[299], "{\"n\":299}");
        let sh = mk(10, Some(5));
        let got = sh.next_batch();
        assert_eq!(got, (10..15).map(|i| format!("{{\"n\":{i}}}")).collect::<Vec<_>>());
        assert!(sh.next_batch().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
