//! `fanout`: live delivery latency and loss, with Vector's two subscription shapes.
//!
//! * Half the subscribers hold a DM subscription, `{kinds:[1059], "#p":[own key]}`.
//! * Half hold a Concord one, `{kinds:[1059,21059], authors:[200 plane keys]}`.
//!   Concord subscribers are grouped into communities of `--community` members
//!   that share one set of 200 planes, so one plane event fans out to a whole
//!   community, as it does in a real Concord.
//!
//! Publishers send events that match known subscribers at a fixed total rate: DM
//! wraps to a random DM subscriber, plane events (half of them the ephemeral kind
//! 21059) from a random plane. Every delivery is checked off, so the run reports
//! **missed** and **duplicate** deliveries as well as latency; a relay that drops live
//! events under load fails, however fast it is.
//!
//! # Measuring without fooling ourselves
//!
//! * Events are **signed before the run**. Signing costs ~50 µs; at 5,000 events/s
//!   doing it inline would take a quarter of a core and delay sends.
//! * The sending schedule is fixed in advance (event `i` at `i / rate`). Latency is
//!   measured from the instant the publisher actually wrote the event (recorded in a
//!   shared table indexed by event number, which each event also carries in its
//!   content as `i:<n> ts:<scheduled ns>`) to the instant the subscriber's read
//!   returned. Publisher lateness (actual minus scheduled send) is reported
//!   separately, so a client that fell behind its own schedule is visible instead of
//!   silently flattering the relay.
//! * Publishers pace with a sleep until 3 ms before the slot and a yield loop for the
//!   rest, each on a dedicated thread: the async timer wheel ticks at 1 ms, coarser
//!   than a relay's fan-out time, and a shared work-stealing runtime wakes a yielding
//!   task 100-800 us late.
//! * Publisher and subscribers share one process and clock, so no clock skew exists.

use crate::hist::Histogram;
use crate::jsonw::Json;
use crate::net::{connect, now_or_never, raise_nofile, recv_text, resolve, source_ip, Target};
use crate::par::{cpus, par_map};
use crate::report::{clip, RunResult};
use crate::rng::Rng;
use crate::sign::{push_tag, Signer};
use crate::wire::{parse_relay_msg, RelayMsg};
use relay_net::conn::Message;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{watch, Semaphore};

pub struct FanoutOpts {
    pub url: String,
    pub subscribers: usize,
    pub publishers: usize,
    /// Events per second, all publishers together.
    pub rate: f64,
    pub duration: f64,
    /// Concord subscribers per community.
    pub community: usize,
    /// Percent of published events that are DM wraps.
    pub dm_share: u32,
    pub seed: u64,
    /// How long to keep listening after the last send before counting the rest as missed.
    pub drain: Duration,
    pub timeout: Duration,
    pub label: String,
    pub src_ips: usize,
    pub json: Option<String>,
}

/// Plane keys per Concord subscription.
const PLANES: usize = 200;

#[derive(Clone, Copy)]
enum Target1 {
    /// Delivered to DM subscriber `j`.
    Dm(usize),
    /// Delivered to every Concord subscriber of community `g`.
    Concord(usize),
}

struct Plan {
    /// `["EVENT", {...}]`, ready to send.
    msgs: Vec<String>,
    /// Scheduled send offset from the start of the run.
    sched_ns: Vec<u64>,
    targets: Vec<Target1>,
}

fn build_plan(o: &FanoutOpts, dm_subs: usize, communities: usize, created_at: u64) -> Plan {
    let total = (o.rate * o.duration).round() as usize;
    let seed = o.seed;
    let signed: Vec<(String, u64, Target1)> = par_map(total, cpus(), |i| {
        let mut rng = Rng::for_item(seed, i as u64, 0xFA);
        let sched_ns = (i as f64 * 1e9 / o.rate) as u64;
        let dm = dm_subs > 0 && (communities == 0 || rng.below(100) < u64::from(o.dm_share));
        let content = format!("i:{i} ts:{sched_ns}");
        let mut tags = String::from("[");
        let (ev, target) = if dm {
            let j = rng.below(dm_subs as u64) as usize;
            push_tag(&mut tags, &["p", &dm_recipient(seed, j)]);
            tags.push(']');
            // A fresh single-use author per wrap, as NIP-59 does.
            (Signer::derive(seed, "fan-author", i as u64).sign(created_at, 1059, &tags, &content), Target1::Dm(j))
        } else {
            let g = rng.below(communities as u64) as usize;
            let plane = g * PLANES + rng.below(PLANES as u64) as usize;
            push_tag(&mut tags, &["p", &hex32(&rng.bytes32())]);
            tags.push(']');
            // Alternate stored and ephemeral wraps from the plane.
            let kind = if i % 2 == 0 { 1059 } else { 21059 };
            (Signer::derive(seed, "fan-plane", plane as u64).sign(created_at, kind, &tags, &content), Target1::Concord(g))
        };
        (format!("[\"EVENT\",{}]", ev.json), sched_ns, target)
    });
    let mut plan = Plan { msgs: Vec::with_capacity(total), sched_ns: Vec::with_capacity(total), targets: Vec::with_capacity(total) };
    for (m, s, t) in signed {
        plan.msgs.push(m);
        plan.sched_ns.push(s);
        plan.targets.push(t);
    }
    plan
}

fn hex32(b: &[u8; 32]) -> String {
    relay_proto::hex::encode_string(b)
}

/// The recipient key of DM subscriber `j`: any 32 bytes do for a `p` tag.
fn dm_recipient(seed: u64, j: usize) -> String {
    let mut h = Sha256::new();
    h.update(b"fan-dm");
    h.update(seed.to_le_bytes());
    h.update((j as u64).to_le_bytes());
    hex32(&h.finalize().into())
}

struct SubShared {
    target: Target,
    timeout: Duration,
    src_ips: usize,
    ready: Vec<AtomicBool>,
    ready_count: AtomicUsize,
    failed: AtomicUsize,
    /// When each event was actually written, in ns after the run start, plus 1
    /// (0 = not sent yet).
    sent_at: Vec<AtomicU64>,
    notes: Mutex<Vec<String>>,
}

impl SubShared {
    fn note(&self, t: String) {
        let mut n = self.notes.lock().unwrap();
        if n.len() < 5 {
            n.push(t);
        }
    }
}

#[derive(Default)]
struct SubOut {
    deliveries: u64,
    duplicates: u64,
    lost: u64,
    stray: u64,
}

/// The index `n` from a content of the form `i:<n> ts:...`.
pub fn event_index(content: &str) -> Option<u32> {
    let rest = content.strip_prefix("i:")?;
    let end = rest.find(' ').unwrap_or(rest.len());
    rest[..end].parse().ok()
}

async fn subscriber(
    j: usize,
    filter: String,
    start: watch::Receiver<Option<Instant>>,
    stop_at: Arc<Mutex<Option<Instant>>>,
    sh: Arc<SubShared>,
    gate: Arc<Semaphore>,
) -> (Histogram, SubOut) {
    let mut hist = Histogram::new();
    let mut out = SubOut::default();
    let permit = gate.acquire().await.unwrap();
    let mut conn = match connect(&sh.target, source_ip(j, sh.src_ips)).await {
        Ok(c) => c,
        Err(e) => {
            sh.failed.fetch_add(1, Relaxed);
            sh.note(format!("subscriber {j}: connect failed: {e}"));
            return (hist, out);
        }
    };
    let sub = "f";
    let ok = async {
        conn.send_text(&format!("[\"REQ\",\"{sub}\",{filter}]")).await.map_err(|e| e.to_string())?;
        loop {
            match recv_text(&mut conn, sh.timeout).await.map_err(|e| e.to_string())?.as_str() {
                t if matches!(parse_relay_msg(t), RelayMsg::Eose { sub: s } if s == sub) => return Ok::<(), String>(()),
                t => {
                    if let RelayMsg::Closed { msg, .. } | RelayMsg::Notice(msg) = parse_relay_msg(t) {
                        return Err(format!("refused the subscription: {msg}"));
                    }
                }
            }
        }
    }
    .await;
    drop(permit);
    if let Err(e) = ok {
        sh.failed.fetch_add(1, Relaxed);
        sh.note(format!("subscriber {j}: {e}"));
        return (hist, out);
    }
    sh.ready[j].store(true, Relaxed);
    sh.ready_count.fetch_add(1, Relaxed);

    // Keep reading while waiting for the start: pings must be answered.
    let mut rx = start;
    let t0 = loop {
        tokio::select! {
            biased;
            r = rx.wait_for(|v| v.is_some()) => match r {
                Ok(v) => break v.unwrap(),
                Err(_) => return (hist, out),
            },
            m = conn.recv() => if m.is_err() { out.lost += 1; return (hist, out); },
        }
    };
    let mut seen: HashSet<u32> = HashSet::new();
    loop {
        // Set before the start signal, so it is always there by now.
        let end = stop_at.lock().unwrap().unwrap_or(t0 + Duration::from_secs(3600));
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, conn.recv()).await {
            Err(_) => break,
            Ok(Err(_)) => {
                out.lost += 1;
                break;
            }
            Ok(Ok(Message::Text(t))) => {
                let now = Instant::now();
                if let RelayMsg::Event { sub: s, content, .. } = parse_relay_msg(&t) {
                    let Some(i) = (s == sub).then(|| event_index(content)).flatten() else {
                        out.stray += 1;
                        continue;
                    };
                    let sent = sh.sent_at.get(i as usize).map_or(0, |a| a.load(Relaxed));
                    if sent == 0 {
                        // Delivered before it was sent cannot happen; count it as a stray.
                        out.stray += 1;
                        continue;
                    }
                    if !seen.insert(i) {
                        out.duplicates += 1;
                        continue;
                    }
                    out.deliveries += 1;
                    let at = now.saturating_duration_since(t0).as_nanos() as u64;
                    hist.record(at.saturating_sub(sent - 1));
                }
            }
            Ok(Ok(Message::Close(_))) => {
                out.lost += 1;
                break;
            }
            Ok(Ok(_)) => {}
        }
    }
    (hist, out)
}

#[derive(Default)]
struct PubOut {
    sent: u64,
    ok_true: u64,
    ok_false: u64,
    unanswered: u64,
}

async fn publisher(
    p: usize,
    plan: Arc<Plan>,
    publishers: usize,
    mut start: watch::Receiver<Option<Instant>>,
    sh: Arc<SubShared>,
    drain: Duration,
) -> (Histogram, PubOut) {
    let mut lag = Histogram::new();
    let mut out = PubOut::default();
    let mine: Vec<usize> = (p..plan.msgs.len()).step_by(publishers).collect();
    let mut conn = match connect(&sh.target, source_ip(p, sh.src_ips)).await {
        Ok(c) => c,
        Err(e) => {
            sh.failed.fetch_add(1, Relaxed);
            sh.note(format!("publisher {p}: connect failed: {e}"));
            out.unanswered = mine.len() as u64;
            return (lag, out);
        }
    };
    let t0 = match start.wait_for(|v| v.is_some()).await {
        Ok(v) => v.unwrap(),
        Err(_) => return (lag, out),
    };
    // True if the message was the OK for one of our events.
    let handle = |text: &str, out: &mut PubOut, sh: &SubShared| match parse_relay_msg(text) {
        RelayMsg::Ok { accepted, msg, .. } => {
            if accepted {
                out.ok_true += 1;
            } else {
                out.ok_false += 1;
                sh.note(format!("publish refused: {}", clip(&msg, 160)));
            }
            true
        }
        _ => false,
    };
    let mut answered = 0u64;
    let mut dead = false;
    'send: for &i in &mine {
        let slot = t0 + Duration::from_nanos(plan.sched_ns[i]);
        loop {
            let now = Instant::now();
            if now >= slot {
                break;
            }
            let wait = slot - now;
            // Far from the slot: sleep (reading OKs meanwhile) until 3 ms before it; the
            // timer wheel rounds both the deadline and the wake-up up to a millisecond tick,
            // so less margin would overshoot. Close to it: poll once and yield, so the slot is hit to microseconds.
            // (Not `timeout(ZERO, ..)`: that waits for the next millisecond tick too.)
            let read = if wait > Duration::from_millis(5) {
                tokio::time::timeout(wait - Duration::from_millis(3), conn.recv()).await.ok()
            } else {
                let r = now_or_never(conn.recv()).await;
                tokio::task::yield_now().await;
                r
            };
            match read {
                Some(Ok(Message::Text(t))) => answered += u64::from(handle(&t, &mut out, &sh)),
                Some(Ok(_)) | None => {}
                Some(Err(e)) => {
                    sh.note(format!("publisher {p}: connection lost: {e}"));
                    dead = true;
                    break 'send;
                }
            }
        }
        let at = Instant::now().saturating_duration_since(t0).as_nanos() as u64;
        sh.sent_at[i].store(at + 1, Relaxed);
        lag.record(at.saturating_sub(plan.sched_ns[i]));
        if conn.send_text(&plan.msgs[i]).await.is_err() {
            sh.note(format!("publisher {p}: write failed after {} events", out.sent));
            dead = true;
            break;
        }
        out.sent += 1;
    }
    // Collect the outstanding OKs.
    let give_up = Instant::now() + drain;
    while !dead && answered < out.sent {
        let left = give_up.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, conn.recv()).await {
            Ok(Ok(Message::Text(t))) => answered += u64::from(handle(&t, &mut out, &sh)),
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    out.unanswered = mine.len() as u64 - answered.min(mine.len() as u64);
    (lag, out)
}

pub async fn run(o: FanoutOpts) -> Result<RunResult, String> {
    if o.subscribers == 0 || o.publishers == 0 || o.rate <= 0.0 || o.duration <= 0.0 || o.community == 0 || o.dm_share > 100 {
        return Err("fanout needs subscribers, publishers, rate, duration and community above zero, and dm-share at most 100".into());
    }
    let need = (o.subscribers + o.publishers + 256) as u64;
    match raise_nofile(need) {
        Some(n) if n < need => eprintln!("warning: file descriptor limit is {n}, {need} wanted; raise it with `ulimit -n {need}` before running"),
        _ => {}
    }
    let target = resolve(&o.url).await?;
    let dm_subs = o.subscribers.div_ceil(2);
    let concord_subs = o.subscribers - dm_subs;
    let communities = concord_subs.div_ceil(o.community);
    eprintln!(
        "fanout: {} DM + {} Concord subscribers in {communities} communities, {} publishers, {:.0} events/s for {}s",
        dm_subs, concord_subs, o.publishers, o.rate, o.duration
    );

    // Subscriptions: every community shares one set of plane keys.
    let seed = o.seed;
    let plane_pks: Vec<String> = par_map(communities * PLANES, cpus(), |k| Signer::derive(seed, "fan-plane", k as u64).pk_hex());
    let community_filter: Vec<String> = (0..communities)
        .map(|g| {
            let authors = plane_pks[g * PLANES..(g + 1) * PLANES].iter().map(|a| Json::Str(a.clone())).collect();
            Json::obj().with("kinds", vec![1059u64, 21059]).with("authors", Json::Arr(authors)).render()
        })
        .collect();
    let created_at = crate::net::unix_time();
    let t = Instant::now();
    let plan = Arc::new(build_plan(&o, dm_subs, communities, created_at));
    eprintln!("fanout: signed {} events in {:.1}s", plan.msgs.len(), t.elapsed().as_secs_f64());
    if plan.msgs.is_empty() {
        return Err("rate x duration is less than one event".into());
    }

    let sh = Arc::new(SubShared {
        target,
        timeout: o.timeout,
        src_ips: o.src_ips,
        ready: (0..o.subscribers).map(|_| AtomicBool::new(false)).collect(),
        ready_count: AtomicUsize::new(0),
        failed: AtomicUsize::new(0),
        sent_at: (0..plan.msgs.len()).map(|_| AtomicU64::new(0)).collect(),
        notes: Mutex::new(Vec::new()),
    });
    let (start_tx, start_rx) = watch::channel::<Option<Instant>>(None);
    let stop_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let gate = Arc::new(Semaphore::new(256));

    // Subscriber j: even j is a DM subscriber, odd j a Concord one.
    let mut subs = Vec::with_capacity(o.subscribers);
    let (mut dm_i, mut concord_i) = (0usize, 0usize);
    let mut sub_kinds = Vec::with_capacity(o.subscribers);
    for j in 0..o.subscribers {
        let (target, filter) = if j % 2 == 0 && dm_i < dm_subs {
            let k = dm_i;
            dm_i += 1;
            (Target1::Dm(k), Json::obj().with("kinds", vec![1059u64]).with("#p", vec![dm_recipient(seed, k)]).render())
        } else {
            let k = concord_i;
            concord_i += 1;
            (Target1::Concord(k / o.community), community_filter[k / o.community].clone())
        };
        sub_kinds.push(target);
        subs.push(tokio::spawn(subscriber(j, filter, start_rx.clone(), stop_at.clone(), sh.clone(), gate.clone())));
    }
    // Wait for every subscription to be live (or to have failed).
    let setup_started = Instant::now();
    loop {
        let done = sh.ready_count.load(Relaxed) + sh.failed.load(Relaxed);
        if done >= o.subscribers {
            break;
        }
        if setup_started.elapsed() > o.timeout + Duration::from_secs(60 + o.subscribers as u64 / 200) {
            return Err(format!("only {done} of {} subscribers finished setting up", o.subscribers));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let ready_subs = sh.ready_count.load(Relaxed);
    let setup_failed = sh.failed.load(Relaxed);
    eprintln!("fanout: {ready_subs} subscriptions live, {setup_failed} failed to set up");

    // What each event must reach, given who actually subscribed.
    let mut ready_dm = vec![false; dm_subs];
    let mut ready_in_community = vec![0usize; communities];
    for (j, t) in sub_kinds.iter().enumerate() {
        if sh.ready[j].load(Relaxed) {
            match *t {
                Target1::Dm(k) => ready_dm[k] = true,
                Target1::Concord(g) => ready_in_community[g] += 1,
            }
        }
    }
    let expected: u64 = plan
        .targets
        .iter()
        .map(|t| match *t {
            Target1::Dm(k) => u64::from(ready_dm[k]),
            Target1::Concord(g) => ready_in_community[g] as u64,
        })
        .sum();

    // Publishers connect, then everything starts together. Each runs on its own OS thread
    // with a private single-threaded runtime: pacing to microseconds needs a thread that
    // nothing else can delay (on the shared work-stealing runtime, a yield loop wakes up
    // 100-800 us late; here 5-35 us).
    let drain = o.drain.max(Duration::from_secs(2));
    let pubs: Vec<_> = (0..o.publishers)
        .map(|p| {
            let (plan, start, sh, publishers) = (plan.clone(), start_rx.clone(), sh.clone(), o.publishers);
            tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("publisher runtime");
                rt.block_on(publisher(p, plan, publishers, start, sh, drain))
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let t0 = Instant::now() + Duration::from_millis(200);
    let run_for = Duration::from_secs_f64(o.duration);
    // Listeners stop a drain period after the schedule's last slot. Set before the start
    // signal: a subscriber that read it too early would listen for an hour.
    *stop_at.lock().unwrap() = Some(t0 + run_for + o.drain);
    let _ = start_tx.send(Some(t0));

    let mut lag = Histogram::new();
    let mut pub_out = PubOut::default();
    for p in pubs {
        let (l, po) = p.await.map_err(|e| format!("publisher panicked: {e}"))?;
        lag.merge(&l);
        pub_out.sent += po.sent;
        pub_out.ok_true += po.ok_true;
        pub_out.ok_false += po.ok_false;
        pub_out.unanswered += po.unanswered;
    }
    let mut hist = Histogram::new();
    let mut agg = SubOut::default();
    for s in subs {
        let (h, so) = s.await.map_err(|e| format!("subscriber panicked: {e}"))?;
        hist.merge(&h);
        agg.deliveries += so.deliveries;
        agg.duplicates += so.duplicates;
        agg.lost += so.lost;
        agg.stray += so.stray;
    }

    let missed = expected.saturating_sub(agg.deliveries);
    let mut r = RunResult::new(&o.label, "fanout", "fanout");
    r.conns = o.subscribers + o.publishers;
    r.ops = agg.deliveries;
    r.secs = o.duration;
    r.hist = hist;
    r.errors = setup_failed as u64 + pub_out.ok_false + pub_out.unanswered + agg.lost + (plan.msgs.len() as u64 - pub_out.sent.min(plan.msgs.len() as u64));
    r.mismatches = missed + agg.duplicates;
    r.notes = std::mem::take(&mut *sh.notes.lock().unwrap());
    r.param("url", o.url.as_str());
    r.param("subscribers", o.subscribers);
    r.param("publishers", o.publishers);
    r.param("rate", o.rate);
    r.param("duration_s", o.duration);
    r.param("community", o.community);
    r.param("dm_share", o.dm_share);
    r.param("seed", o.seed);
    r.detail("events_published", pub_out.sent);
    r.detail("publish_ok_true", pub_out.ok_true);
    r.detail("publish_ok_false", pub_out.ok_false);
    r.detail("publish_unanswered", pub_out.unanswered);
    r.detail("subscribers_live", ready_subs);
    r.detail("subscribers_failed", setup_failed);
    r.detail("subscribers_lost", agg.lost);
    r.detail("expected_deliveries", expected);
    r.detail("deliveries", agg.deliveries);
    r.detail("missed", missed);
    r.detail("duplicates", agg.duplicates);
    r.detail("stray_messages", agg.stray);
    r.detail("sender_lag_p50_us", lag.quantile(0.5) as f64 / 1000.0);
    r.detail("sender_lag_p99_us", lag.quantile(0.99) as f64 / 1000.0);
    r.detail("sender_lag_max_us", lag.max() as f64 / 1000.0);
    r.info.push(format!(
        "{} of {} expected deliveries ({} missed, {} duplicate); {} publishes OK, {} refused; sender lag p50 {} p99 {} max {}",
        agg.deliveries,
        expected,
        missed,
        agg.duplicates,
        pub_out.ok_true,
        pub_out.ok_false,
        crate::report::fmt_ns(lag.quantile(0.5)),
        crate::report::fmt_ns(lag.quantile(0.99)),
        crate::report::fmt_ns(lag.max())
    ));
    if missed > 0 {
        r.notes.push(format!(
            "{missed} deliveries never arrived within {}s of the last send (a relay that only queues them late counts as missing; raise --drain to tell the two apart)",
            o.drain.as_secs()
        ));
    }
    if lag.quantile(0.99) > 2_000_000 {
        r.notes.push(format!("the publishers ran up to {:.0} ms behind their own schedule: the client, not the relay, was the bottleneck", lag.max() as f64 / 1e6));
    }
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
    fn event_index_parses_the_content_marker() {
        assert_eq!(event_index("i:42 ts:1000"), Some(42));
        assert_eq!(event_index("i:7"), Some(7));
        assert_eq!(event_index("ts:1000 i:7"), None);
        assert_eq!(event_index("i:x ts:1"), None);
        assert_eq!(event_index(""), None);
    }

    #[test]
    fn plan_targets_match_the_subscription_shapes() {
        let o = FanoutOpts {
            url: String::new(),
            subscribers: 10,
            publishers: 2,
            rate: 50.0,
            duration: 1.0,
            community: 2,
            dm_share: 50,
            seed: 3,
            drain: Duration::from_secs(1),
            timeout: Duration::from_secs(1),
            label: String::new(),
            src_ips: 1,
            json: None,
        };
        let plan = build_plan(&o, 5, 3, 1_700_000_000);
        assert_eq!(plan.msgs.len(), 50);
        let dms = plan.targets.iter().filter(|t| matches!(t, Target1::Dm(_))).count();
        assert!((10..=40).contains(&dms), "{dms}");
        for (i, m) in plan.msgs.iter().enumerate() {
            assert!(m.starts_with("[\"EVENT\",{"));
            assert!(m.contains(&format!("\"content\":\"i:{i} ts:{}\"", plan.sched_ns[i])), "{m}");
            match plan.targets[i] {
                Target1::Dm(j) => {
                    assert!(j < 5);
                    assert!(m.contains(&dm_recipient(3, j)));
                    assert!(m.contains("\"kind\":1059"));
                }
                Target1::Concord(g) => {
                    assert!(g < 3);
                    let ephemeral = i % 2 == 1;
                    assert!(m.contains(if ephemeral { "\"kind\":21059" } else { "\"kind\":1059" }));
                    // Signed by one of the community's planes.
                    let line = &m[9..m.len() - 1];
                    let author = crate::wire::parse_event_line(line).unwrap().pubkey;
                    let ok = (g * PLANES..(g + 1) * PLANES).any(|k| Signer::derive(3, "fan-plane", k as u64).pk == author);
                    assert!(ok, "event {i} is not from a plane of community {g}");
                }
            }
        }
        // The schedule is evenly spaced.
        assert_eq!(plan.sched_ns[0], 0);
        assert_eq!(plan.sched_ns[1], 20_000_000);
        assert_eq!(plan.sched_ns[49], 980_000_000);
        // And every message is a validly signed event.
        for m in plan.msgs.iter().take(10) {
            crate::sign::verify_event_line(&m[9..m.len() - 1]).unwrap();
        }
    }
}
