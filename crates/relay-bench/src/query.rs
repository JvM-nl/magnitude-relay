//! `query`: closed-loop read benchmark with every answer checked.
//!
//! Each connection holds exactly one request in flight: send REQ, read until EOSE,
//! then validate, then the next. The clock runs from the moment the request is
//! written to the moment its EOSE is *received*; the events are only parsed and
//! compared afterwards, so the client's own checking never inflates a latency (it
//! only lowers throughput slightly, which the closed loop makes visible honestly).
//! `CLOSE` goes out between requests, outside the timed window.
//!
//! What counts as wrong is defined in [`crate::check`]. A run with any wrong
//! answer or error exits non-zero: a fast relay that returns the wrong events must
//! not look like a winner.

use crate::check::{validate, Verdict};
use crate::data::Dataset;
use crate::hist::Histogram;
use crate::net::{connect, recv_text, resolve, source_ip, RecvError, Target};
use crate::report::{clip, RunResult};
use crate::rng::Rng;
use crate::workload::{build, Pool, PoolOpts, Step};
use crate::wire::{parse_relay_msg, RelayMsg};
use relay_net::conn::ClientConn;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

pub struct QueryOpts {
    pub url: String,
    pub file: PathBuf,
    pub workloads: Vec<String>,
    pub conns: usize,
    pub queries: u64,
    pub limit: Option<usize>,
    pub distinct: usize,
    pub seed: u64,
    pub strict_ties: bool,
    pub timeout: Duration,
    pub warmup: u64,
    pub label: String,
    pub src_ips: usize,
    pub json: Option<String>,
}

/// Failures of one step. `Net` means the connection is no longer usable.
enum StepErr {
    /// No answer within the timeout.
    Timeout,
    Net(String),
    /// The relay answered the request with CLOSED or a NOTICE.
    Refused(String),
    /// A COUNT the relay does not implement.
    Unsupported(String),
}

struct StepDone {
    dt: Duration,
    events: usize,
    verdict: Verdict,
}

#[derive(Default, Clone)]
struct Stats {
    ops: u64,
    errors: u64,
    set_mismatch: u64,
    order_mismatch: u64,
    tie_order: u64,
    tie_pick: u64,
    events: u64,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.ops += o.ops;
        self.errors += o.errors;
        self.set_mismatch += o.set_mismatch;
        self.order_mismatch += o.order_mismatch;
        self.tie_order += o.tie_order;
        self.tie_pick += o.tie_pick;
        self.events += o.events;
    }
}

struct Shared {
    target: Target,
    pool: Pool,
    name: String,
    seed: u64,
    salt: u64,
    next_op: AtomicU64,
    /// Steps finished with an answer; zero means the relay has never answered.
    completed: AtomicU64,
    steps_claimed: AtomicU64,
    step_budget: u64,
    strict: bool,
    timeout: Duration,
    src_ips: usize,
    notes: Mutex<Vec<String>>,
    unsupported: Mutex<Option<String>>,
    stop: AtomicBool,
}

impl Shared {
    fn note(&self, text: String) {
        let mut n = self.notes.lock().unwrap();
        if n.len() < 5 {
            n.push(text);
        }
    }
}

/// EVENT messages are the bulk of every answer: recognise them without a full parse.
fn is_event_msg(s: &str) -> bool {
    s.strip_prefix('[').is_some_and(|r| r.trim_start().starts_with("\"EVENT\""))
}

async fn do_step(c: &mut ClientConn<TcpStream>, sub: &str, step: &Step, sh: &Shared) -> Result<StepDone, StepErr> {
    let is_req = matches!(step, Step::Req { .. });
    let msg = format!("[\"{}\",\"{sub}\",{}]", if is_req { "REQ" } else { "COUNT" }, step.json());
    let net = |e: &dyn std::fmt::Display| StepErr::Net(e.to_string());
    let t0 = Instant::now();
    c.send_text(&msg).await.map_err(|e| net(&e))?;
    let mut raw: Vec<String> = Vec::new();
    let mut count_got = None;
    loop {
        let text = match recv_text(c, sh.timeout).await {
            Ok(t) => t,
            Err(RecvError::Timeout) => return Err(StepErr::Timeout),
            Err(e) => return Err(net(&e)),
        };
        if is_event_msg(&text) {
            raw.push(text);
            continue;
        }
        match parse_relay_msg(&text) {
            RelayMsg::Eose { sub: s } if s == sub && is_req => break,
            RelayMsg::Count { sub: s, count } if s == sub => {
                count_got = Some(count);
                break;
            }
            RelayMsg::Closed { sub: s, msg } if s == sub => {
                return Err(if is_req { StepErr::Refused(format!("CLOSED {msg}")) } else { StepErr::Unsupported(format!("CLOSED {msg}")) })
            }
            RelayMsg::Notice(m) => {
                return Err(if is_req { StepErr::Refused(format!("NOTICE {m}")) } else { StepErr::Unsupported(format!("NOTICE {m}")) })
            }
            // Stale messages of an earlier subscription, OKs, pings' echoes: not ours.
            _ => {}
        }
    }
    let dt = t0.elapsed();
    if is_req {
        c.send_text(&format!("[\"CLOSE\",\"{sub}\"]")).await.map_err(|e| net(&e))?;
    }

    // Validation happens after the clock stopped.
    let (events, verdict) = match step {
        Step::Req { exp, .. } => {
            let mut got = Vec::with_capacity(raw.len());
            let mut unparseable = 0;
            for t in &raw {
                match parse_relay_msg(t) {
                    RelayMsg::Event { sub: s, id, created_at, .. } => {
                        if s == sub {
                            got.push((id, created_at));
                        }
                    }
                    _ => unparseable += 1,
                }
            }
            let mut v = validate(exp, &got);
            if unparseable > 0 {
                v.set_mismatch = true;
                v.detail = format!("{unparseable} EVENT messages could not be parsed; {}", v.detail);
            }
            (got.len(), v)
        }
        Step::Count { expect, .. } => {
            let mut v = Verdict::default();
            if count_got != Some(*expect) {
                v.set_mismatch = true;
                v.detail = format!("COUNT returned {}, expected {expect}", count_got.map_or("nothing".into(), |n| n.to_string()));
            }
            (0, v)
        }
    };
    Ok(StepDone { dt, events, verdict })
}

async fn worker(id: usize, sh: Arc<Shared>) -> (Histogram, Stats) {
    let mut hist = Histogram::new();
    let mut st = Stats::default();
    let mut conn: Option<ClientConn<TcpStream>> = None;
    let mut fails = 0u32;
    let mut seq = 0u64;
    'ops: while !sh.stop.load(Relaxed) {
        let n = sh.next_op.fetch_add(1, Relaxed);
        let op = &sh.pool.ops[Rng::for_item(sh.seed, n, sh.salt).below(sh.pool.ops.len() as u64) as usize];
        if sh.steps_claimed.fetch_add(op.steps.len() as u64, Relaxed) >= sh.step_budget {
            break;
        }
        for step in &op.steps {
            if conn.is_none() {
                match connect(&sh.target, source_ip(id, sh.src_ips)).await {
                    Ok(c) => conn = Some(c),
                    Err(e) => {
                        st.errors += 1;
                        sh.note(format!("{}: connect failed: {e}", sh.name));
                        fails += 1;
                        if fails >= 3 {
                            break 'ops;
                        }
                        continue 'ops;
                    }
                }
            }
            seq += 1;
            let sub = format!("b{id}-{seq}");
            match do_step(conn.as_mut().unwrap(), &sub, step, &sh).await {
                Ok(done) => {
                    fails = 0;
                    sh.completed.fetch_add(1, Relaxed);
                    st.ops += 1;
                    st.events += done.events as u64;
                    hist.record(done.dt.as_nanos().min(u128::from(u64::MAX)) as u64);
                    let v = &done.verdict;
                    st.set_mismatch += u64::from(v.set_mismatch);
                    st.order_mismatch += u64::from(v.order_mismatch);
                    st.tie_order += u64::from(v.tie_order);
                    st.tie_pick += u64::from(v.tie_pick);
                    if !v.ok(sh.strict) {
                        sh.note(format!("{}: WRONG ANSWER, {}; request {}", sh.name, v.detail, clip(step.json(), 240)));
                    }
                }
                // A COUNT the relay never answers, when it has answered nothing at all: it
                // does not implement COUNT (strfry-style silence), not a failure.
                Err(StepErr::Timeout) if matches!(step, Step::Count { .. }) && sh.completed.load(Relaxed) == 0 => {
                    *sh.unsupported.lock().unwrap() = Some(format!("no reply to COUNT within {}s", sh.timeout.as_secs()));
                    sh.stop.store(true, Relaxed);
                    break 'ops;
                }
                Err(e @ (StepErr::Net(_) | StepErr::Timeout)) => {
                    let m = match e {
                        StepErr::Net(m) => m,
                        _ => format!("no reply within {}s", sh.timeout.as_secs()),
                    };
                    st.errors += 1;
                    sh.note(format!("{}: {m}; request {}", sh.name, clip(step.json(), 160)));
                    conn = None;
                    fails += 1;
                    if fails >= 3 {
                        break 'ops;
                    }
                    continue 'ops;
                }
                Err(StepErr::Refused(m)) => {
                    st.errors += 1;
                    sh.note(format!("{}: {m}; request {}", sh.name, clip(step.json(), 160)));
                    continue 'ops;
                }
                Err(StepErr::Unsupported(m)) => {
                    *sh.unsupported.lock().unwrap() = Some(m);
                    sh.stop.store(true, Relaxed);
                    break 'ops;
                }
            }
        }
    }
    (hist, st)
}

async fn run_phase(sh: &Arc<Shared>, conns: usize) -> (Histogram, Stats, Duration) {
    let started = Instant::now();
    let tasks: Vec<_> = (0..conns).map(|i| tokio::spawn(worker(i, sh.clone()))).collect();
    let mut hist = Histogram::new();
    let mut st = Stats::default();
    for t in tasks {
        let (h, s) = t.await.expect("query worker panicked");
        hist.merge(&h);
        st.add(&s);
    }
    (hist, st, started.elapsed())
}

fn shared(o: &QueryOpts, target: &Target, name: &str, pool: Pool, budget: u64) -> Arc<Shared> {
    Arc::new(Shared {
        target: target.clone(),
        pool,
        name: name.to_owned(),
        seed: o.seed,
        salt: crate::data::fnv64(name) ^ 0xA5,
        next_op: AtomicU64::new(0),
        completed: AtomicU64::new(0),
        steps_claimed: AtomicU64::new(0),
        step_budget: budget,
        strict: o.strict_ties,
        timeout: o.timeout,
        src_ips: o.src_ips,
        notes: Mutex::new(Vec::new()),
        unsupported: Mutex::new(None),
        stop: AtomicBool::new(false),
    })
}

/// Runs every requested workload in order against the relay and returns one result
/// each (also printed, and appended to `o.json` if set).
pub async fn run(o: &QueryOpts, ds: &Dataset) -> Result<Vec<RunResult>, String> {
    let target = resolve(&o.url).await?;
    let pool_opts = PoolOpts { limit: o.limit, distinct: o.distinct, seed: o.seed };
    let mut results = Vec::new();
    for name in &o.workloads {
        let mut r = RunResult::new(&o.label, "query", name);
        r.conns = o.conns;
        r.param("url", o.url.as_str());
        r.param("file", o.file.display().to_string());
        r.param("queries", o.queries);
        r.param("conns", o.conns);
        r.param("distinct", o.distinct);
        r.param("seed", o.seed);
        r.param("limit", o.limit);
        r.param("strict_ties", o.strict_ties);
        r.param("warmup", o.warmup);
        r.param("dataset_events", ds.len());
        r.param("dataset_fingerprint", format!("{:016x}", ds.fingerprint));
        let pool = match build(name, ds, &pool_opts) {
            Ok(p) => p,
            Err(e) => {
                r.supported = false;
                r.unsupported_reason = format!("skipped: {e}");
                r.print();
                finish(&mut r, o, &mut results);
                continue;
            }
        };
        let queries_in_pool = pool.ops.len();
        r.param("pool_ops", queries_in_pool);

        if o.warmup > 0 {
            let sh = shared(o, &target, name, build(name, ds, &pool_opts)?, o.warmup);
            let (_, st, _) = run_phase(&sh, o.conns.min(o.warmup as usize).max(1)).await;
            // Warm-up answers are discarded, but a wrong one is still wrong.
            r.mismatches += st.set_mismatch + st.order_mismatch;
            r.errors += st.errors;
        }

        let sh = shared(o, &target, name, pool, o.queries);
        let (hist, st, elapsed) = run_phase(&sh, o.conns.min(o.queries as usize).max(1)).await;
        if let Some(why) = sh.unsupported.lock().unwrap().clone() {
            r.supported = false;
            r.unsupported_reason = format!("unsupported by the relay: {}", clip(&why, 160));
            r.print();
            finish(&mut r, o, &mut results);
            continue;
        }
        r.hist = hist;
        r.ops = st.ops;
        r.secs = elapsed.as_secs_f64();
        r.errors += st.errors;
        r.mismatches += st.set_mismatch + st.order_mismatch;
        if o.strict_ties {
            r.mismatches += st.tie_order + st.tie_pick;
        }
        r.notes = std::mem::take(&mut *sh.notes.lock().unwrap());
        r.detail("events_returned", st.events);
        r.detail("set_mismatch", st.set_mismatch);
        r.detail("order_mismatch", st.order_mismatch);
        r.detail("tie_order", st.tie_order);
        r.detail("tie_pick", st.tie_pick);
        if (st.tie_order > 0 || st.tie_pick > 0) && !o.strict_ties {
            r.notes.push(format!(
                "tie handling differs from NIP-01 in {} answers (same-second order {}, boundary-second picks {}); allowed, use --strict-ties to fail on it",
                st.tie_order.max(st.tie_pick),
                st.tie_order,
                st.tie_pick
            ));
        }
        r.print();
        finish(&mut r, o, &mut results);
    }
    Ok(results)
}

fn finish(r: &mut RunResult, o: &QueryOpts, results: &mut Vec<RunResult>) {
    if let Some(path) = &o.json {
        if let Err(e) = r.append_json(path) {
            eprintln!("cannot append to {path}: {e}");
        }
    }
    results.push(std::mem::replace(r, RunResult::new("", "query", "")));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_messages_are_recognised_cheaply() {
        assert!(is_event_msg(r#"["EVENT","s",{}]"#));
        assert!(is_event_msg(r#"[ "EVENT" ,"s",{}]"#));
        assert!(!is_event_msg(r#"["EOSE","s"]"#));
        assert!(!is_event_msg(r#"["NOTICE","EVENT"]"#));
        assert!(!is_event_msg("EVENT"));
    }
}
