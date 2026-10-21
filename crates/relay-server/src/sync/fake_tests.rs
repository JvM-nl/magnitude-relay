//! The sync engine against a scripted relay: one that refuses large sets the
//! way strfry does, tells us to slow down, leaves out events it was asked for,
//! sends ones it was not, and holds forgeries. Our own relays are tested end to
//! end in tests/sync.rs; these are the behaviours a real relay will not
//! produce on demand.

use super::local::Direct;
use super::remote::Remote;
use super::{sync_filter, Opts, Report};
use crate::config::{Config, Direction};
use crate::session::SessionCfg;
use relay_net::conn::server_handshake;
use relay_net::connector::{Connector, RelayUrl};
use relay_net::ws::{write_text, Decoder, Event, Role};
use relay_proto::event::parse_event_json;
use relay_proto::negentropy::{reconcile, VecStorage};
use relay_proto::{hex, EventParser, Filter};
use relay_store::{Options, Store};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// How the fake relay behaves.
#[derive(Default, Clone)]
struct Script {
    /// Its set: created_at, id, and the event's JSON when it can send it.
    events: Vec<(u64, [u8; 32], Option<String>)>,
    /// A NEG-OPEN over more than this many is refused as strfry refuses it.
    max_set: usize,
    /// EVENTs answered "rate-limited" before any is taken.
    slow_first: usize,
    /// Asked for, never sent.
    withhold: HashSet<[u8; 32]>,
    /// Sent with every answer to a REQ, though nobody asked.
    extra: Option<String>,
}

#[derive(Default)]
struct Seen {
    neg_opens: usize,
    too_big: usize,
    accepted: Vec<[u8; 32]>,
    slowed: usize,
}

fn id_of(v: &Value) -> [u8; 32] {
    hex::decode_32(v.as_str().unwrap().as_bytes()).unwrap()
}

/// Serves one connection by `script`, recording what happened in `seen`.
async fn fake_relay(script: Script, seen: Arc<Mutex<Seen>>) -> RelayUrl {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = RelayUrl::parse(&format!("ws://127.0.0.1:{}", listener.local_addr().unwrap().port())).unwrap();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        server_handshake(&mut s, &mut buf, 8192).await.unwrap();
        let mut dec = Decoder::new(Role::Server, 1 << 24, 1 << 24);
        let mut sessions: HashMap<String, VecStorage> = HashMap::new();
        loop {
            let mut texts = Vec::new();
            let mut off = 0;
            while let Ok(d) = dec.decode(&mut buf[off..]) {
                off += d.consumed;
                match d.event {
                    Some(Event::Text(t)) => texts.push(t.to_string()),
                    Some(Event::Close(_)) => return,
                    Some(_) => {}
                    None => break,
                }
            }
            buf.drain(..off);
            let mut out = Vec::new();
            for t in texts {
                let m: Value = serde_json::from_str(&t).unwrap();
                let mut reply = |v: Value| write_text(&mut out, v.to_string().as_bytes());
                match m[0].as_str().unwrap() {
                    "NEG-OPEN" => {
                        let sub = m[1].as_str().unwrap().to_string();
                        let since = m[2]["since"].as_u64().unwrap_or(0);
                        let until = m[2]["until"].as_u64().unwrap_or(u64::MAX);
                        let set: Vec<(u64, [u8; 32])> = script.events.iter().filter(|e| (since..=until).contains(&e.0)).map(|e| (e.0, e.1)).collect();
                        seen.lock().unwrap().neg_opens += 1;
                        if set.len() > script.max_set {
                            seen.lock().unwrap().too_big += 1;
                            reply(json!(["NEG-ERR", sub, "blocked: too many query results", script.max_set]));
                            continue;
                        }
                        let st = VecStorage::new(set);
                        let msg = hex::decode_any_case(m[3].as_str().unwrap().as_bytes()).unwrap();
                        reply(json!(["NEG-MSG", sub, hex::encode_string(&reconcile(&st, &msg, 500_000).unwrap())]));
                        sessions.insert(sub, st);
                    }
                    "NEG-MSG" => {
                        let sub = m[1].as_str().unwrap();
                        let msg = hex::decode_any_case(m[2].as_str().unwrap().as_bytes()).unwrap();
                        reply(json!(["NEG-MSG", sub, hex::encode_string(&reconcile(&sessions[sub], &msg, 500_000).unwrap())]));
                    }
                    "NEG-CLOSE" => {
                        sessions.remove(m[1].as_str().unwrap());
                    }
                    "REQ" => {
                        let sub = m[1].as_str().unwrap();
                        for id in m[2]["ids"].as_array().unwrap().iter().map(id_of) {
                            let found = script.events.iter().find(|e| e.1 == id).and_then(|e| e.2.clone());
                            if let (Some(json), false) = (found, script.withhold.contains(&id)) {
                                write_text(&mut out, format!("[\"EVENT\",\"{sub}\",{json}]").as_bytes());
                            }
                        }
                        if let Some(extra) = &script.extra {
                            write_text(&mut out, format!("[\"EVENT\",\"{sub}\",{extra}]").as_bytes());
                        }
                        write_text(&mut out, json!(["EOSE", sub]).to_string().as_bytes());
                    }
                    "EVENT" => {
                        let id = m[1]["id"].as_str().unwrap();
                        let mut seen = seen.lock().unwrap();
                        if seen.slowed < script.slow_first {
                            seen.slowed += 1;
                            reply(json!(["OK", id, false, "rate-limited: slow down"]));
                        } else {
                            seen.accepted.push(id_of(&m[1]["id"]));
                            reply(json!(["OK", id, true, ""]));
                        }
                    }
                    _ => {}
                }
            }
            if !out.is_empty() {
                s.write_all(&out).await.unwrap();
            }
            let mut chunk = vec![0u8; 1 << 16];
            match s.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
    });
    url
}

/// A store of our own, holding `events` (written directly: the store does
/// not check signatures, and these tests are about the sync).
fn local_store(tag: &str, events: &[(u64, [u8; 32])]) -> Direct {
    let dir = std::env::temp_dir().join(format!("relay-sync-fake-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (store, mut w) = Store::open(&dir, Options { segment_size: 16 << 20, ..Options::default() }).unwrap();
    let mut p = EventParser::new();
    let recs: Vec<Vec<u8>> = events
        .iter()
        .map(|(ca, id)| {
            let json = format!(
                r#"{{"id":"{}","pubkey":"{}","created_at":{ca},"kind":1,"tags":[],"content":"x","sig":"{}"}}"#,
                hex::encode_string(id),
                "11".repeat(32),
                "00".repeat(64)
            );
            let mut rec = Vec::new();
            parse_event_json(&json, &mut p, &mut rec, false).unwrap();
            rec
        })
        .collect();
    for chunk in recs.chunks(5000) {
        let refs: Vec<&[u8]> = chunk.iter().map(Vec::as_slice).collect();
        w.write(&refs).unwrap();
    }
    let cfg = Config { policy: crate::config::PolicyCfg { kinds: crate::config::KindBase::All, ..Default::default() }, ..Config::default() };
    Direct::new(store, w, SessionCfg::from_config(&cfg))
}

fn id(n: u64) -> [u8; 32] {
    let mut id = [0x5a; 32];
    id[..8].copy_from_slice(&n.to_be_bytes());
    id
}

fn kind1() -> Filter {
    Filter { kinds: Some(vec![1]), ..Filter::default() }
}

#[tokio::test]
async fn windows_shrink_for_the_remote_and_for_us() {
    // Ten thousand events over two years, and ten thousand more in one hour:
    // the hour cannot be compared whole (the fake takes 1500 at a time).
    let base = 1_700_000_000;
    let mut all: Vec<(u64, [u8; 32])> = (0..10_000u64).map(|i| (base + i * 6_000, id(i))).collect();
    all.extend((10_000..20_000u64).map(|i| (base + 30_000_000 + (i % 3600), id(i))));
    // We hold a quarter of them, plus a hundred of our own.
    let mut ours: Vec<(u64, [u8; 32])> = all.iter().step_by(4).copied().collect();
    ours.extend((50_000..50_100u64).map(|i| (base + i, id(i))));
    let script = Script { events: all.iter().map(|&(ca, id)| (ca, id, None)).collect(), max_set: 1500, ..Script::default() };
    let seen = Arc::new(Mutex::new(Seen::default()));
    let url = fake_relay(script, seen.clone()).await;
    let mut remote = Remote::connect(&Connector::new().unwrap(), &url).await.unwrap();
    let mut local = local_store("windows", &ours);
    let opts = Opts { dry_run: true, target: 1000, cap: 800, ..Opts::new(Direction::Down) };
    let mut r = Report::default();
    sync_filter(&mut remote, &mut local, &kind1(), &opts, &mut r).await.unwrap();
    assert_eq!((r.need, r.have), (15_000, 100));
    assert_eq!((r.ours, r.theirs), (5_100, 20_000));
    let seen = seen.lock().unwrap();
    assert!(seen.too_big > 0, "the dense hour was refused at least once");
    assert_eq!(seen.neg_opens as u64, r.windows + seen.too_big as u64);
    // Every window fitted both limits, so it took at least this many.
    assert!(r.windows >= 20_000 / 1500, "{} windows", r.windows);
}

#[tokio::test]
async fn publishing_backs_off_when_told_to() {
    let ours: Vec<(u64, [u8; 32])> = (0..300u64).map(|i| (1_700_000_000 + i, id(i))).collect();
    let script = Script { max_set: usize::MAX, slow_first: 40, ..Script::default() };
    let seen = Arc::new(Mutex::new(Seen::default()));
    let url = fake_relay(script, seen.clone()).await;
    let mut remote = Remote::connect(&Connector::new().unwrap(), &url).await.unwrap();
    let mut local = local_store("push", &ours);
    let mut r = Report::default();
    let t = Instant::now();
    sync_filter(&mut remote, &mut local, &kind1(), &Opts::new(Direction::Up), &mut r).await.unwrap();
    // Forty answers to slow down, one pause, then everything.
    assert_eq!((r.have, r.up.stored, r.up_slowed, r.up_unanswered), (300, 300, 40, 0));
    assert!(t.elapsed() >= Duration::from_secs(1) && t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    let mut got = seen.lock().unwrap().accepted.clone();
    got.sort_unstable();
    got.dedup();
    assert_eq!(got.len(), 300);
}

#[tokio::test]
async fn fetched_events_are_checked_and_accounted_for() {
    use secp256k1::{schnorr, Keypair};
    use sha2::{Digest, Sha256};
    let key = Keypair::from_secret_bytes([3; 32]).unwrap();
    let pk = hex::encode_string(&key.x_only_public_key().0.to_byte_array());
    let sign = |at: u64, kind: u64, content: &str| -> (u64, [u8; 32], String) {
        let pre = serde_json::to_string(&json!([0, pk, at, kind, [], content])).unwrap();
        let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
        let sig = schnorr::sign_no_aux_rand(&id, &key);
        let ev = json!({"id": hex::encode_string(&id), "pubkey": pk, "created_at": at, "kind": kind, "tags": [], "content": content, "sig": hex::encode_string(&sig.to_byte_array())});
        (at, id, ev.to_string())
    };
    let t0 = 1_700_000_000;
    let mut events: Vec<(u64, [u8; 32], Option<String>)> = Vec::new();
    // 25 good ones, 2 of which the fake will not send.
    let good: Vec<_> = (0..25).map(|i| sign(t0 + i, 8, &format!("good {i}"))).collect();
    // 3 of a kind our policy refuses (the store here takes Vector's kinds only).
    let refused: Vec<_> = (0..3).map(|i| sign(t0 + 100 + i, 4, &format!("dm {i}"))).collect();
    // One whose signature was tampered with.
    let (at, fid, json) = sign(t0 + 200, 8, "forged");
    let mut v: Value = serde_json::from_str(&json).unwrap();
    let sig = v["sig"].as_str().unwrap();
    let flipped = if sig.starts_with('0') { "1" } else { "0" };
    v["sig"] = Value::String(format!("{flipped}{}", &sig[1..]));
    let forged = v.to_string();
    for (at, id, json) in good.iter().chain(&refused) {
        events.push((*at, *id, Some(json.clone())));
    }
    events.push((at, fid, Some(forged)));
    let withhold: HashSet<[u8; 32]> = good.iter().take(2).map(|g| g.1).collect();
    let extra = sign(t0 + 300, 8, "nobody asked").2;
    let script = Script { events, max_set: usize::MAX, withhold, extra: Some(extra), ..Script::default() };
    let url = fake_relay(script, Arc::new(Mutex::new(Seen::default()))).await;
    let mut remote = Remote::connect(&Connector::new().unwrap(), &url).await.unwrap();
    // Vector's kinds only here.
    let dir = std::env::temp_dir().join(format!("relay-sync-fake-fetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (store, w) = Store::open(&dir, Options { segment_size: 16 << 20, ..Options::default() }).unwrap();
    let mut local = Direct::new(store, w, SessionCfg::from_config(&Config::default()));
    let mut r = Report::default();
    sync_filter(&mut remote, &mut local, &Filter::default(), &Opts::new(Direction::Down), &mut r).await.unwrap();
    assert_eq!((r.need, r.fetched, r.not_returned, r.unrequested), (29, 27, 2, 1));
    assert_eq!(r.down.stored, 23);
    assert_eq!(r.down.refused.get("blocked: kind 4 is not accepted by this relay"), Some(&3), "{:?}", r.down);
    assert_eq!(r.down.invalid.get("invalid: bad signature"), Some(&1), "{:?}", r.down);
    assert_eq!(r.down.total(), 27);
    // And the stored ones are really there.
    let mut again = Report::default();
    let opts = Opts { dry_run: true, ..Opts::new(Direction::Down) };
    let url2 = fake_relay(Script { events: good.iter().map(|g| (g.0, g.1, None)).collect(), max_set: usize::MAX, ..Script::default() }, Arc::new(Mutex::new(Seen::default()))).await;
    let mut remote2 = Remote::connect(&Connector::new().unwrap(), &url2).await.unwrap();
    sync_filter(&mut remote2, &mut local, &Filter::default(), &opts, &mut again).await.unwrap();
    assert_eq!((again.need, again.have), (2, 0), "only the two withheld are missing");
}
