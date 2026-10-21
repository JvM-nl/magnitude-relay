//! `neg`: NIP-77 reconciliation as Vector does it, judged by the reference client.
//!
//! Each session reconciles `{kinds:[1059], "#p":[r]}` for one recipient. The client
//! holds a chosen percentage of the relay's set for that mailbox plus a few ids the
//! relay does not have; when the exchange ends, the ids the reference client says it
//! must fetch (`need`) and can offer (`have`) have to equal, exactly, the ones the
//! dataset says. Frame limit 60,000, Vector's setting.
//!
//! Timing runs from the NEG-OPEN being written to the reconciliation finishing,
//! client work per round included (it is part of what a user waits for). Building
//! the client's own set and its first message happen before the clock starts: that
//! is the same for every relay and would only add noise.
//!
//! A relay that answers NEG-ERR or a NOTICE does not implement NIP-77 (or refuses
//! the shape): the run is reported as unsupported, not failed.

use crate::data::{Dataset, FilterSpec, GIFT_WRAP};
use crate::hist::Histogram;
use crate::jsonw::Json;
use crate::net::{connect, recv_text, resolve, source_ip, RecvError, Target};
use crate::report::{clip, RunResult};
use crate::rng::Rng;
use crate::wire::{parse_relay_msg, RelayMsg};
use negentropy::{Id, Negentropy, NegentropyStorageVector};
use relay_proto::hex;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Heavy,
    Light,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode, String> {
        match s {
            "heavy" => Ok(Mode::Heavy),
            "light" => Ok(Mode::Light),
            other => Err(format!("--recipient-mode must be heavy or light, not '{other}'")),
        }
    }
}

pub struct NegOpts {
    pub url: String,
    pub mode: Mode,
    pub have_pct: u32,
    pub sessions: u64,
    pub conns: usize,
    pub seed: u64,
    pub timeout: Duration,
    pub frame_limit: u64,
    pub label: String,
    pub src_ips: usize,
    pub json: Option<String>,
}

/// Recipients cycled through by the sessions.
const MAILBOXES: usize = 8;
/// Ids the relay lacks that the client holds, per session.
const EXTRAS: usize = 5;

struct Mailbox {
    filter_json: String,
    /// (created_at, id) of every live wrap for the recipient.
    members: Vec<(u64, [u8; 32])>,
}

/// Heavy: the biggest mailboxes. Light: mid-sized ones from the lower half of those
/// holding at least a few wraps, so a session is a handful of round trips.
fn pick_mailboxes(ds: &Dataset, mode: Mode, seed: u64) -> Result<Vec<Mailbox>, String> {
    let boxes: Vec<_> = ds.wrap_mailboxes().into_iter().filter(|b| b.1 >= 2).collect();
    if boxes.is_empty() {
        return Err("the dataset has no gift-wrap mailbox with two or more events".into());
    }
    let chosen: Vec<_> = match mode {
        Mode::Heavy => boxes.iter().take(MAILBOXES).collect(),
        Mode::Light => {
            let lower = &boxes[boxes.len() / 2..];
            let mut rng = Rng::for_item(seed, 0x6c, 1);
            let mut idx: Vec<usize> = (0..lower.len()).collect();
            rng.shuffle(&mut idx);
            idx.into_iter().take(MAILBOXES).map(|i| &lower[i]).collect()
        }
    };
    Ok(chosen
        .into_iter()
        .map(|(r, _)| {
            let f = FilterSpec { kinds: vec![GIFT_WRAP], p: vec![*r], ..Default::default() };
            let members = ds.matching(&f).into_iter().map(|i| (u64::from(ds.events[i as usize].ts), ds.events[i as usize].id)).collect();
            Mailbox { filter_json: f.to_json(), members }
        })
        .collect())
}

enum SessionErr {
    /// The relay never answered the NEG-OPEN: silence, as a relay without NIP-77 may do.
    NoReply,
    /// NEG-ERR, CLOSED or NOTICE in answer to the opening message.
    Unsupported(String),
    Net(String),
    /// The reference client rejected the relay's message.
    Protocol(String),
}

struct SessionDone {
    dt: Duration,
    rounds: u64,
    up: u64,
    down: u64,
    need: usize,
    have: usize,
    wrong: Option<String>,
}

async fn session(
    c: &mut crate::net::Conn,
    sub: &str,
    mb: &Mailbox,
    s: u64,
    o: &NegOpts,
) -> Result<SessionDone, SessionErr> {
    // The client's set: a fixed share of the relay's, picked at random, plus extras.
    let mut rng = Rng::for_item(o.seed, s, 0x4e);
    let n = mb.members.len();
    let mut order: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut order);
    let keep = ((n as u64 * u64::from(o.have_pct) + 50) / 100) as usize;
    let mut held: Vec<(u64, [u8; 32])> = order[..keep].iter().map(|&i| mb.members[i]).collect();
    let mut want_need: Vec<[u8; 32]> = order[keep..].iter().map(|&i| mb.members[i].1).collect();
    let (lo, hi) = mb.members.iter().fold((u64::MAX, 0), |(l, h), m| (l.min(m.0), h.max(m.0)));
    let mut want_have: Vec<[u8; 32]> = Vec::new();
    for j in 0..EXTRAS as u64 {
        let mut h = Sha256::new();
        h.update(b"neg-extra");
        h.update(o.seed.to_le_bytes());
        h.update(s.to_le_bytes());
        h.update(j.to_le_bytes());
        let id: [u8; 32] = h.finalize().into();
        held.push((lo + rng.below(hi - lo + 1), id));
        want_have.push(id);
    }
    want_need.sort_unstable();
    want_have.sort_unstable();

    let mut storage = NegentropyStorageVector::with_capacity(held.len());
    for (ts, id) in &held {
        storage.insert(*ts, Id::from_byte_array(*id)).map_err(|e| SessionErr::Protocol(e.to_string()))?;
    }
    storage.seal().map_err(|e| SessionErr::Protocol(e.to_string()))?;
    let mut neg = Negentropy::owned(storage, o.frame_limit).map_err(|e| SessionErr::Protocol(e.to_string()))?;
    let init = neg.initiate().map_err(|e| SessionErr::Protocol(e.to_string()))?;

    let net = |e: &dyn std::fmt::Display| SessionErr::Net(e.to_string());
    let (mut have, mut need): (Vec<Id>, Vec<Id>) = (Vec::new(), Vec::new());
    let (mut rounds, mut up, mut down) = (1u64, init.len() as u64, 0u64);
    let t0 = Instant::now();
    c.send_text(&format!("[\"NEG-OPEN\",\"{sub}\",{},\"{}\"]", mb.filter_json, hex::encode_string(&init))).await.map_err(|e| net(&e))?;
    let mut heard = false;
    loop {
        let text = match recv_text(c, o.timeout).await {
            Ok(t) => t,
            Err(RecvError::Timeout) if !heard => return Err(SessionErr::NoReply),
            Err(e) => return Err(net(&e)),
        };
        heard = true;
        match parse_relay_msg(&text) {
            RelayMsg::NegMsg { sub: s, hex: h } if s == sub => {
                let bytes = hex::decode_any_case(h.as_bytes()).ok_or_else(|| SessionErr::Protocol("relay sent non-hex NEG-MSG".into()))?;
                down += bytes.len() as u64;
                match neg.reconcile_with_ids(&bytes, &mut have, &mut need) {
                    Ok(Some(next)) => {
                        up += next.len() as u64;
                        rounds += 1;
                        c.send_text(&format!("[\"NEG-MSG\",\"{sub}\",\"{}\"]", hex::encode_string(&next))).await.map_err(|e| net(&e))?;
                    }
                    Ok(None) => break,
                    Err(e) => return Err(SessionErr::Protocol(format!("the reference client rejected a relay message: {e}"))),
                }
            }
            RelayMsg::NegErr { sub: s, msg } if s == sub => return Err(SessionErr::Unsupported(format!("NEG-ERR {msg}"))),
            RelayMsg::Closed { sub: s, msg } if s == sub => return Err(SessionErr::Unsupported(format!("CLOSED {msg}"))),
            RelayMsg::Notice(m) => return Err(SessionErr::Unsupported(format!("NOTICE {m}"))),
            // The relay may interleave unrelated messages; none is part of the exchange.
            _ => {}
        }
    }
    let dt = t0.elapsed();
    c.send_text(&format!("[\"NEG-CLOSE\",\"{sub}\"]")).await.map_err(|e| net(&e))?;

    let mut got_need: Vec<[u8; 32]> = need.iter().map(|i| *i.as_bytes()).collect();
    let mut got_have: Vec<[u8; 32]> = have.iter().map(|i| *i.as_bytes()).collect();
    got_need.sort_unstable();
    got_have.sort_unstable();
    got_need.dedup();
    got_have.dedup();
    let wrong = if got_need != want_need || got_have != want_have {
        Some(format!(
            "need {} ids (expected {}), have {} ids (expected {}) for {}",
            got_need.len(),
            want_need.len(),
            got_have.len(),
            want_have.len(),
            clip(&mb.filter_json, 120)
        ))
    } else {
        None
    };
    Ok(SessionDone { dt, rounds, up, down, need: got_need.len(), have: got_have.len(), wrong })
}

#[derive(Default)]
struct Agg {
    sessions: u64,
    errors: u64,
    wrong: u64,
    rounds: u64,
    max_rounds: u64,
    up: u64,
    down: u64,
    need: u64,
    have: u64,
}

struct Shared {
    target: Target,
    boxes: Vec<Mailbox>,
    opts: NegOpts,
    next: AtomicU64,
    /// Sessions finished; zero means the relay has never answered a reconciliation.
    completed: AtomicU64,
    stop: AtomicBool,
    unsupported: Mutex<Option<String>>,
    notes: Mutex<Vec<String>>,
}

async fn worker(id: usize, sh: Arc<Shared>) -> (Histogram, Agg) {
    let mut hist = Histogram::new();
    let mut agg = Agg::default();
    let mut conn = None;
    let mut fails = 0;
    let note = |t: String| {
        let mut n = sh.notes.lock().unwrap();
        if n.len() < 5 {
            n.push(t);
        }
    };
    while !sh.stop.load(Relaxed) {
        let s = sh.next.fetch_add(1, Relaxed);
        if s >= sh.opts.sessions {
            break;
        }
        if conn.is_none() {
            match connect(&sh.target, source_ip(id, sh.opts.src_ips)).await {
                Ok(c) => conn = Some(c),
                Err(e) => {
                    agg.errors += 1;
                    note(format!("connect failed: {e}"));
                    fails += 1;
                    if fails >= 3 {
                        break;
                    }
                    continue;
                }
            }
        }
        let mb = &sh.boxes[(s % sh.boxes.len() as u64) as usize];
        match session(conn.as_mut().unwrap(), &format!("n{id}-{s}"), mb, s, &sh.opts).await {
            Ok(d) => {
                fails = 0;
                sh.completed.fetch_add(1, Relaxed);
                agg.sessions += 1;
                agg.rounds += d.rounds;
                agg.max_rounds = agg.max_rounds.max(d.rounds);
                agg.up += d.up;
                agg.down += d.down;
                agg.need += d.need as u64;
                agg.have += d.have as u64;
                hist.record(d.dt.as_nanos().min(u128::from(u64::MAX)) as u64);
                if let Some(w) = d.wrong {
                    agg.wrong += 1;
                    note(format!("WRONG ANSWER: {w}"));
                }
            }
            Err(SessionErr::Unsupported(m)) => {
                *sh.unsupported.lock().unwrap() = Some(m);
                sh.stop.store(true, Relaxed);
            }
            Err(SessionErr::NoReply) if sh.completed.load(Relaxed) == 0 => {
                *sh.unsupported.lock().unwrap() = Some(format!("no reply to NEG-OPEN within {}s", sh.opts.timeout.as_secs()));
                sh.stop.store(true, Relaxed);
            }
            Err(SessionErr::NoReply) => {
                agg.errors += 1;
                note("no reply to NEG-OPEN".into());
                conn = None;
            }
            Err(SessionErr::Net(m)) => {
                agg.errors += 1;
                note(m);
                conn = None;
                fails += 1;
                if fails >= 3 {
                    break;
                }
            }
            Err(SessionErr::Protocol(m)) => {
                agg.errors += 1;
                note(m);
            }
        }
    }
    (hist, agg)
}

pub async fn run(o: NegOpts, ds: &Dataset) -> Result<RunResult, String> {
    if o.have_pct > 100 {
        return Err("--have must be a percentage from 0 to 100".into());
    }
    let target = resolve(&o.url).await?;
    let boxes = pick_mailboxes(ds, o.mode, o.seed)?;
    let workload = format!("neg_{}_{}", if o.mode == Mode::Heavy { "heavy" } else { "light" }, o.have_pct);
    let (conns, sessions) = (o.conns.max(1), o.sessions);
    let sizes: Vec<usize> = boxes.iter().map(|b| b.members.len()).collect();
    let sh = Arc::new(Shared {
        target,
        boxes,
        opts: o,
        next: AtomicU64::new(0),
        completed: AtomicU64::new(0),
        stop: AtomicBool::new(false),
        unsupported: Mutex::new(None),
        notes: Mutex::new(Vec::new()),
    });
    let started = Instant::now();
    let tasks: Vec<_> = (0..conns.min(sessions.max(1) as usize)).map(|i| tokio::spawn(worker(i, sh.clone()))).collect();
    let mut hist = Histogram::new();
    let mut agg = Agg::default();
    for t in tasks {
        let (h, a) = t.await.map_err(|e| format!("worker panicked: {e}"))?;
        hist.merge(&h);
        agg.sessions += a.sessions;
        agg.errors += a.errors;
        agg.wrong += a.wrong;
        agg.rounds += a.rounds;
        agg.max_rounds = agg.max_rounds.max(a.max_rounds);
        agg.up += a.up;
        agg.down += a.down;
        agg.need += a.need;
        agg.have += a.have;
    }
    let o = &sh.opts;
    let mut r = RunResult::new(&o.label, "neg", &workload);
    r.conns = conns;
    r.param("url", o.url.as_str());
    r.param("recipient_mode", if o.mode == Mode::Heavy { "heavy" } else { "light" });
    r.param("have_pct", o.have_pct);
    r.param("sessions", o.sessions);
    r.param("frame_limit", o.frame_limit);
    r.param("seed", o.seed);
    r.param("dataset_events", ds.len());
    r.param("dataset_fingerprint", format!("{:016x}", ds.fingerprint));
    r.param("mailbox_sizes", Json::Arr(sizes.iter().map(|&n| Json::from(n)).collect()));
    if let Some(why) = sh.unsupported.lock().unwrap().clone() {
        r.supported = false;
        r.unsupported_reason = format!("unsupported by the relay: {}", clip(&why, 160));
    } else {
        r.ops = agg.sessions;
        r.secs = started.elapsed().as_secs_f64();
        r.hist = hist;
        r.errors = agg.errors;
        r.mismatches = agg.wrong;
        r.notes = std::mem::take(&mut *sh.notes.lock().unwrap());
        let div = agg.sessions.max(1) as f64;
        r.detail("round_trips_avg", agg.rounds as f64 / div);
        r.detail("round_trips_max", agg.max_rounds);
        r.detail("bytes_up_avg", agg.up as f64 / div);
        r.detail("bytes_down_avg", agg.down as f64 / div);
        r.detail("need_ids_avg", agg.need as f64 / div);
        r.detail("have_ids_avg", agg.have as f64 / div);
        r.info.push(format!(
            "{:.1} round trips per session (max {}), {:.1} KB up and {:.1} KB down, {:.0} ids to fetch and {:.0} to offer",
            agg.rounds as f64 / div,
            agg.max_rounds,
            agg.up as f64 / div / 1024.0,
            agg.down as f64 / div / 1024.0,
            agg.need as f64 / div,
            agg.have as f64 / div
        ));
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
    fn modes_parse() {
        assert_eq!(Mode::parse("heavy"), Ok(Mode::Heavy));
        assert_eq!(Mode::parse("light"), Ok(Mode::Light));
        assert!(Mode::parse("medium").is_err());
    }

    #[test]
    fn heavy_picks_the_biggest_and_light_the_lower_half() {
        let ds = crate::workload::tests_synthetic(3000);
        let sizes = |m: Mode| pick_mailboxes(&ds, m, 1).unwrap().iter().map(|b| b.members.len()).collect::<Vec<_>>();
        let heavy = sizes(Mode::Heavy);
        let light = sizes(Mode::Light);
        assert!(heavy.windows(2).all(|w| w[0] >= w[1]), "heavy are sorted biggest first: {heavy:?}");
        assert!(heavy[0] > light.iter().copied().max().unwrap(), "{heavy:?} vs {light:?}");
        assert!(light.iter().all(|&n| n >= 2));
    }
}
