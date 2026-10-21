//! `idle`: how many quiet WebSocket connections a relay holds, and what each costs.
//!
//! Opens `--conns` connections, each with one live subscription (a DM-style
//! `{kinds:[1059], "#p":[unique key]}`, so the relay's subscription index grows
//! with the connection count as it would in production), holds them for `--hold`
//! seconds and reports how many came up, how many were dropped while idle, and, with
//! `--pid`, the relay's resident memory before, after setup and at the end. RSS per
//! connection is `(after - before) / connections`.
//!
//! Limits to know about on the machine running the bench:
//! * File descriptors: the tool raises its own soft limit to what it needs where the
//!   hard limit allows (and says so); beyond that run `ulimit -n 200000` (as root or
//!   after raising the hard limit) in the shell first.
//! * Ephemeral ports: one source address offers ~28,000 ports to a single
//!   destination, so past that pass `--src-ips 4` (or more) to spread connections over
//!   127.0.0.2, 127.0.0.3, ... (Linux treats all of 127.0.0.0/8 as local).
//!
//! The relay's own limits (per-IP connection caps, descriptor limit) apply as well, and
//! a refusal there is exactly what this command exists to show.

use crate::hist::Histogram;
use crate::net::{connect, raise_nofile, recv_text, resolve, rss_kb, source_ip, Target};
use crate::report::{clip, RunResult};
use crate::wire::{parse_relay_msg, RelayMsg};
use relay_net::conn::Message;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Semaphore};

pub struct IdleOpts {
    pub url: String,
    pub conns: usize,
    pub hold: Duration,
    pub pid: Option<u32>,
    /// Connections being established at once.
    pub parallel: usize,
    pub seed: u64,
    pub timeout: Duration,
    pub label: String,
    pub src_ips: usize,
    pub json: Option<String>,
}

struct Shared {
    target: Target,
    timeout: Duration,
    src_ips: usize,
    seed: u64,
    up: AtomicUsize,
    failed: AtomicUsize,
    dropped: AtomicUsize,
    notes: Mutex<Vec<String>>,
}

impl Shared {
    fn note(&self, t: String) {
        let mut n = self.notes.lock().unwrap();
        if n.len() < 5 {
            n.push(t);
        }
    }
}

async fn idle_conn(i: usize, sh: Arc<Shared>, gate: Arc<Semaphore>, hold_until: watch::Receiver<Option<Instant>>) -> Option<Duration> {
    let permit = gate.acquire().await.unwrap();
    let t0 = Instant::now();
    let mut conn = match connect(&sh.target, source_ip(i, sh.src_ips)).await {
        Ok(c) => c,
        Err(e) => {
            sh.failed.fetch_add(1, Relaxed);
            sh.note(format!("connection {i}: {e}"));
            return None;
        }
    };
    let mut h = Sha256::new();
    h.update(b"idle");
    h.update(sh.seed.to_le_bytes());
    h.update((i as u64).to_le_bytes());
    let key = relay_proto::hex::encode_string(&h.finalize());
    let req = format!("[\"REQ\",\"i\",{{\"kinds\":[1059],\"#p\":[\"{key}\"]}}]");
    let live = async {
        conn.send_text(&req).await.map_err(|e| e.to_string())?;
        loop {
            let t = recv_text(&mut conn, sh.timeout).await.map_err(|e| e.to_string())?;
            match parse_relay_msg(&t) {
                RelayMsg::Eose { sub: "i" } => return Ok::<(), String>(()),
                RelayMsg::Closed { msg, .. } | RelayMsg::Notice(msg) => return Err(format!("subscription refused: {}", clip(&msg, 120))),
                _ => {}
            }
        }
    }
    .await;
    drop(permit);
    if let Err(e) = live {
        sh.failed.fetch_add(1, Relaxed);
        sh.note(format!("connection {i}: {e}"));
        return None;
    }
    let setup = t0.elapsed();
    sh.up.fetch_add(1, Relaxed);

    // Hold, reading so that the relay's pings are answered and a drop is noticed.
    let mut rx = hold_until;
    let mut end = None;
    loop {
        let wait = match end {
            Some(e) => {
                let left = Instant::now();
                if left >= e {
                    break;
                }
                e - left
            }
            None => Duration::from_secs(3600),
        };
        tokio::select! {
            r = rx.changed(), if end.is_none() => {
                if r.is_err() { break; }
                end = *rx.borrow();
            }
            m = tokio::time::timeout(wait, conn.recv()) => match m {
                Err(_) => break,
                Ok(Err(e)) => {
                    sh.dropped.fetch_add(1, Relaxed);
                    sh.note(format!("connection {i} dropped while idle: {e}"));
                    break;
                }
                Ok(Ok(Message::Close(_))) => {
                    sh.dropped.fetch_add(1, Relaxed);
                    sh.note(format!("connection {i} closed by the relay while idle"));
                    break;
                }
                Ok(Ok(_)) => {}
            },
        }
    }
    Some(setup)
}

pub async fn run(o: IdleOpts) -> Result<RunResult, String> {
    let need = (o.conns + 256) as u64;
    match raise_nofile(need) {
        Some(n) if n >= need => {}
        Some(n) => eprintln!("warning: file descriptor limit is {n} but {need} are needed; run `ulimit -n {need}` first (hard limit permitting)"),
        None => eprintln!("warning: could not read the file descriptor limit; set `ulimit -n {need}` if connections fail"),
    }
    if o.conns > 28_000 && o.src_ips <= 1 {
        eprintln!("warning: more than ~28k connections from one source address will run out of ephemeral ports; pass --src-ips 4 or more");
    }
    let target = resolve(&o.url).await?;
    let rss_before = o.pid.and_then(rss_kb);
    if let (Some(pid), None) = (o.pid, rss_before) {
        eprintln!("warning: cannot read /proc/{pid}/status; RSS will not be reported");
    }
    let sh = Arc::new(Shared {
        target,
        timeout: o.timeout,
        src_ips: o.src_ips,
        seed: o.seed,
        up: AtomicUsize::new(0),
        failed: AtomicUsize::new(0),
        dropped: AtomicUsize::new(0),
        notes: Mutex::new(Vec::new()),
    });
    let gate = Arc::new(Semaphore::new(o.parallel.max(1)));
    let (tx, rx) = watch::channel::<Option<Instant>>(None);
    let started = Instant::now();
    let tasks: Vec<_> = (0..o.conns).map(|i| tokio::spawn(idle_conn(i, sh.clone(), gate.clone(), rx.clone()))).collect();
    let mut last = Instant::now();
    loop {
        let done = sh.up.load(Relaxed) + sh.failed.load(Relaxed);
        if done >= o.conns {
            break;
        }
        if last.elapsed() >= Duration::from_secs(5) {
            last = Instant::now();
            eprintln!("  {done}/{} connections", o.conns);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let setup_secs = started.elapsed().as_secs_f64();
    let up = sh.up.load(Relaxed);
    let rss_after = o.pid.and_then(rss_kb);
    eprintln!("idle: {up} connections up, {} failed, holding for {}s", sh.failed.load(Relaxed), o.hold.as_secs());
    let _ = tx.send(Some(Instant::now() + o.hold));
    let mut hist = Histogram::new();
    for t in tasks {
        if let Some(d) = t.await.map_err(|e| format!("connection task panicked: {e}"))? {
            hist.record(d.as_nanos().min(u128::from(u64::MAX)) as u64);
        }
    }
    let rss_end = o.pid.and_then(rss_kb);

    let failed = sh.failed.load(Relaxed);
    let dropped = sh.dropped.load(Relaxed);
    let mut r = RunResult::new(&o.label, "idle", "idle");
    r.conns = o.conns;
    r.ops = up as u64;
    r.secs = setup_secs;
    r.hist = hist;
    r.errors = (failed + dropped) as u64;
    r.notes = std::mem::take(&mut *sh.notes.lock().unwrap());
    r.param("url", o.url.as_str());
    r.param("hold_s", o.hold.as_secs());
    r.param("parallel", o.parallel);
    r.param("src_ips", o.src_ips);
    r.param("pid", o.pid.map(u64::from));
    r.detail("connections_up", up);
    r.detail("connections_failed", failed);
    r.detail("dropped_while_idle", dropped);
    r.detail("rss_before_kb", rss_before);
    r.detail("rss_after_setup_kb", rss_after);
    r.detail("rss_end_kb", rss_end);
    let per_conn = match (rss_before, rss_after) {
        (Some(b), Some(a)) if up > 0 => Some(a.saturating_sub(b) as f64 * 1024.0 / up as f64),
        _ => None,
    };
    r.detail("rss_per_conn_bytes", per_conn);
    if let Some(p) = per_conn {
        r.notes.push(format!("relay RSS {} -> {} KiB, {:.0} bytes per connection", rss_before.unwrap(), rss_after.unwrap(), p));
    }
    r.print();
    if let Some(path) = &o.json {
        r.append_json(path).map_err(|e| format!("cannot append to {path}: {e}"))?;
    }
    Ok(r)
}
