//! The attacks. Each runs against the live relay for a while and returns what
//! it observed; the orchestrator (mod.rs) watches the canary, memory and
//! descriptors around it and decides pass or fail.

use super::client::{tcp, Conn, Msg, Opts};
use super::Env;
use crate::gen;
use crate::mutate::Mutator;
use crate::rng::Rng;
use crate::sign::Keys;
use crate::wsframe::{self, Frame};
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Default, Debug)]
pub struct Outcome {
    /// Observations worth reporting either way.
    pub notes: Vec<String>,
    /// Broken expectations: these fail the scenario.
    pub findings: Vec<String>,
}

impl Outcome {
    fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }

    fn finding(&mut self, s: impl Into<String>) {
        self.findings.push(s.into());
    }
}

/// An address of its own for each hostile connection, so the relay's per-IP
/// limits do not stop an attack that is about something else.
pub fn ip(n: u64) -> String {
    format!("10.{}.{}.{}", 1 + (n >> 16) % 200, (n >> 8) & 255, n & 255)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn conn(env: &Env, n: u64) -> std::io::Result<Conn> {
    Conn::connect(env.addr, &Opts { ip: Some(&ip(n)), ..Opts::default() })
}

/// Runs `f(i)` on `n` threads until `secs` pass or `stop` is set.
fn swarm(n: u64, secs: f64, f: impl Fn(u64, &AtomicBool) + Send + Sync + 'static) {
    let stop = Arc::new(AtomicBool::new(false));
    let f = Arc::new(f);
    let hs: Vec<_> = (0..n)
        .map(|i| {
            let (stop, f) = (stop.clone(), f.clone());
            std::thread::spawn(move || f(i, &stop))
        })
        .collect();
    std::thread::sleep(Duration::from_secs_f64(secs));
    stop.store(true, Ordering::Relaxed);
    for h in hs {
        let _ = h.join();
    }
}

// ---------------------------------------------------------------- garbage over the wire

/// Mutated and random client messages at full speed from several connections:
/// every answer must be a well-formed relay message, and the connection may
/// only be closed with a proper code.
pub fn garbage(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let bad = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sent = Arc::new(AtomicU64::new(0));
    let (addr, seed, secs) = (env.addr, env.seed, env.secs);
    let (b2, s2) = (bad.clone(), sent.clone());
    swarm(6, secs, move |i, stop| {
        let mut rng = Rng::derive(seed ^ 0x6A6B, i);
        let keys = Keys::from_seed(seed ^ i);
        let m = Mutator::new(64 << 10, &[b"[\"EVENT\",", b"[\"REQ\",\"x\",", b"{\"kinds\":[", b"\\u0000", b"\"#p\":["]);
        let mut c: Option<Conn> = None;
        let mut k = 0u64;
        while !stop.load(Ordering::Relaxed) {
            k += 1;
            if c.is_none() {
                c = Conn::connect(addr, &Opts { ip: Some(&ip(1000 + i * 100 + k % 100)), ..Opts::default() }).ok();
                if c.is_none() {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
            }
            let cc = c.as_mut().unwrap();
            let signed = rng.chance(1, 3);
            let base = gen::client_msg(&mut rng, if signed { Some(&keys) } else { None });
            let msg = if rng.chance(1, 2) { m.mutate(&mut rng, base.as_bytes(), b"") } else { base.into_bytes() };
            let f = match String::from_utf8(msg) {
                Ok(t) => Frame::text(&t),
                // Invalid UTF-8 in a text frame: the relay must close with 1007.
                Err(e) => Frame::new(1, e.as_bytes()),
            };
            if cc.send_frame(&f).is_err() {
                c = None;
                continue;
            }
            s2.fetch_add(1, Ordering::Relaxed);
            // Read whatever came back, briefly.
            cc.s.set_read_timeout(Some(Duration::from_millis(2))).ok();
            loop {
                match cc.recv() {
                    Ok(Msg::Text(t)) => {
                        let v: Result<serde_json::Value, _> = serde_json::from_str(&t);
                        let ok = v.as_ref().is_ok_and(|v| v.as_array().is_some_and(|a| a.first().and_then(|x| x.as_str()).is_some_and(|c| ["OK", "NOTICE", "CLOSED", "EOSE", "EVENT", "COUNT", "NEG-MSG", "NEG-ERR"].contains(&c))));
                        if !ok {
                            b2.lock().unwrap().push(format!("malformed reply: {}", t.chars().take(200).collect::<String>()));
                        }
                    }
                    Ok(Msg::Close(code)) => {
                        if !matches!(code, Some(1002 | 1007 | 1008 | 1009 | 1011) | None) {
                            b2.lock().unwrap().push(format!("closed with code {code:?}"));
                        }
                        c = None;
                        break;
                    }
                    Ok(_) => {}
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
                    Err(_) => {
                        c = None;
                        break;
                    }
                }
            }
        }
    });
    out.note(format!("{} hostile messages sent", sent.load(Ordering::Relaxed)));
    for b in bad.lock().unwrap().iter().take(5) {
        out.finding(b.clone());
    }
    out
}

// ---------------------------------------------------------------- subscriptions

/// Subscription-state abuse: the limit, duplicate and replaced ids, CLOSE of
/// unknown ids, ids at and past 64 characters, and REQ/CLOSE churn.
pub fn subscriptions(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let Ok(mut c) = conn(env, 2000) else {
        out.finding("could not connect");
        return out;
    };
    let read_until = |c: &mut Conn, pred: &dyn Fn(&serde_json::Value) -> bool| -> Option<serde_json::Value> {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(10) {
            let s = c.recv_text().ok()?;
            let v: serde_json::Value = serde_json::from_str(&s).ok()?;
            if pred(&v) {
                return Some(v);
            }
        }
        None
    };
    // Fill to the limit (200 by default), then one more.
    for i in 0..200 {
        let _ = c.send_text(&format!("[\"REQ\",\"s{i}\",{{\"kinds\":[7],\"limit\":1}}]"));
    }
    let _ = c.send_text("[\"REQ\",\"over\",{\"kinds\":[7]}]");
    match read_until(&mut c, &|v| v[1] == "over") {
        Some(v) if v[0] == "CLOSED" => out.note(format!("201st subscription refused: {}", v[2])),
        other => out.finding(format!("201st subscription not refused: {other:?}")),
    }
    // Replacing an existing id is not a new subscription.
    let _ = c.send_text("[\"REQ\",\"s5\",{\"kinds\":[7]}]");
    match read_until(&mut c, &|v| v[1] == "s5" && (v[0] == "EOSE" || v[0] == "CLOSED")) {
        Some(v) if v[0] == "EOSE" => {}
        other => out.finding(format!("replacing a subscription at the limit failed: {other:?}")),
    }
    for id in ["", &"x".repeat(65), "with\\\"quote", "\\u0041"] {
        let _ = c.send_text(&format!("[\"REQ\",\"{id}\",{{}}]"));
        match read_until(&mut c, &|v| v[0] == "NOTICE" || v[0] == "CLOSED" || v[0] == "EOSE") {
            Some(v) if v[0] == "NOTICE" => {}
            other => out.finding(format!("bad subscription id {id:?} answered with {other:?}")),
        }
    }
    let _ = c.send_text(&format!("[\"REQ\",\"{}\",{{\"kinds\":[7]}}]", "y".repeat(64)));
    let _ = c.send_text("[\"CLOSE\",\"never-opened\"]");
    // Churn: thousands of open/close pairs.
    let t = Instant::now();
    let mut n = 0;
    while t.elapsed() < Duration::from_secs_f64(env.secs) {
        for k in 0..50 {
            let _ = c.send_text(&format!("[\"REQ\",\"c{k}\",{{\"authors\":[\"{}\"]}}]", "ab".repeat(32)));
            let _ = c.send_text(&format!("[\"CLOSE\",\"c{k}\"]"));
            n += 1;
        }
        c.s.set_read_timeout(Some(Duration::from_millis(5))).ok();
        while c.recv().is_ok() {}
        c.s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    }
    out.note(format!("{n} REQ/CLOSE pairs"));
    // The connection must still work.
    let _ = c.send_text("[\"COUNT\",\"alive\",{\"kinds\":[7]}]");
    if read_until(&mut c, &|v| v[1] == "alive").is_none() {
        out.finding("connection unusable after subscription churn");
    }
    out
}

// ---------------------------------------------------------------- filters

/// Filters at and past every limit, and every odd shape: the planner's
/// product explosion, giant id lists, inverted windows, odd numbers,
/// duplicate keys, wrong types, deep nesting.
pub fn filters(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let mut rng = Rng::new(env.seed ^ 0xF117);
    let hexes = |rng: &mut Rng, n: usize| (0..n).map(|_| format!("\"{}\"", gen::hex(&rng.bytes32()))).collect::<Vec<_>>().join(",");
    let kinds = |n: usize| (0..n).map(|k| k.to_string()).collect::<Vec<_>>().join(",");
    let cases: Vec<(String, String)> = vec![
        // A message is at most 256 KiB, which bounds lists of 64-hex values to
        // about 3,800: the cases below are the largest that fit.
        ("3500 authors x 5000 kinds".into(), format!("{{\"authors\":[{}],\"kinds\":[{}]}}", hexes(&mut rng, 3500), kinds(5000))),
        ("3800 ids".into(), format!("{{\"ids\":[{}]}}", hexes(&mut rng, 3800))),
        ("3500 #p x 5000 kinds".into(), format!("{{\"#p\":[{}],\"kinds\":[{}]}}", hexes(&mut rng, 3500), kinds(5000))),
        ("5001 kinds (over the limit)".into(), format!("{{\"kinds\":[{}]}}", kinds(5001))),
        ("4096-product #e x kinds".into(), format!("{{\"#e\":[{}],\"kinds\":[{}]}}", hexes(&mut rng, 64), kinds(64))),
        // The planner's worst case per byte: products just under its cap,
        // as many filters as fit in one message.
        (
            "50 filters x (64 authors x 64 kinds)".into(),
            (0..50).map(|_| format!("{{\"authors\":[{}],\"kinds\":[{}]}}", hexes(&mut rng, 60), kinds(64))).collect::<Vec<_>>().join(","),
        ),
        (
            "50 filters x (64 #p x 64 kinds)".into(),
            (0..50).map(|_| format!("{{\"#p\":[{}],\"kinds\":[{}]}}", hexes(&mut rng, 60), kinds(64))).collect::<Vec<_>>().join(","),
        ),
        ("since > until".into(), "{\"since\":2000000000,\"until\":1}".into()),
        ("float limit".into(), "{\"limit\":1.5}".into()),
        ("exponent".into(), "{\"since\":1e9}".into()),
        ("leading zero".into(), "{\"until\":0100}".into()),
        ("2^64".into(), "{\"limit\":18446744073709551616}".into()),
        ("u64::MAX limit".into(), "{\"limit\":18446744073709551615}".into()),
        ("negative".into(), "{\"kinds\":[-1]}".into()),
        ("duplicate key".into(), "{\"kinds\":[1],\"kinds\":[2]}".into()),
        ("wrong type".into(), "{\"authors\":\"x\"}".into()),
        ("wrong element type".into(), "{\"kinds\":[\"1\"]}".into()),
        ("deep nesting".into(), format!("{{\"x\":{}{}}}", "[".repeat(100_000), "]".repeat(100_000))),
        ("unknown key".into(), "{\"nonsense\":1}".into()),
        ("search".into(), "{\"search\":\"x\"}".into()),
        ("long tag name".into(), "{\"#pp\":[\"x\"]}".into()),
        ("empty lists".into(), "{\"ids\":[],\"authors\":[],\"kinds\":[]}".into()),
        ("1059 broad".into(), "{\"kinds\":[1059]}".into()),
        ("huge tag value".into(), format!("{{\"#t\":[\"{}\"]}}", "v".repeat(200_000))),
    ];
    let Ok(mut c) = conn(env, 3000) else {
        out.finding("could not connect");
        return out;
    };
    for (name, f) in &cases {
        for msg in [format!("[\"REQ\",\"f\",{f}]"), format!("[\"COUNT\",\"f\",{f}]")] {
            let t = Instant::now();
            if c.send_text(&msg).is_err() {
                out.finding(format!("{name}: connection lost on send"));
                c = match conn(env, 3001) {
                    Ok(c) => c,
                    Err(_) => return out,
                };
                continue;
            }
            // An answer must come: EOSE, CLOSED, COUNT, NOTICE, or a close for a too-big message.
            let mut answered = None;
            while t.elapsed() < Duration::from_secs(30) {
                match c.recv() {
                    Ok(Msg::Text(s)) => {
                        let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
                        if ["EOSE", "CLOSED", "COUNT", "NOTICE"].contains(&v[0].as_str().unwrap_or("")) {
                            answered = Some(format!("{} {}", v[0], v.get(2).map(|x| x.to_string()).unwrap_or_default()));
                            break;
                        }
                    }
                    Ok(Msg::Close(code)) => {
                        answered = Some(format!("close {code:?}"));
                        c = match conn(env, 3002) {
                            Ok(c) => c,
                            Err(_) => return out,
                        };
                        break;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        answered = Some(format!("error {e}"));
                        c = match conn(env, 3003) {
                            Ok(c) => c,
                            Err(_) => return out,
                        };
                        break;
                    }
                }
            }
            let took = t.elapsed();
            match answered {
                Some(a) => out.note(format!("{name} ({}): {} in {:.1} ms", &msg[..msg.find('"').map_or(0, |i| i + 6).min(msg.len())], a.chars().take(80).collect::<String>(), took.as_secs_f64() * 1e3)),
                None => out.finding(format!("{name}: no answer within 30 s")),
            }
            if took > Duration::from_secs(2) {
                out.finding(format!("{name}: took {took:?} to answer"));
            }
        }
    }
    out
}

// ---------------------------------------------------------------- events

/// Events with every kind of invalid or weird content, and the expensive
/// valid ones: thousands of tags (the index writes a key per distinct tag),
/// maximum size.
pub fn events(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let keys = Keys::from_seed(env.seed ^ 0xE7);
    let Ok(mut c) = conn(env, 4000) else {
        out.finding("could not connect");
        return out;
    };
    let mut expect = |c: &mut Conn, name: &str, ev: &str, accepted: Option<bool>| {
        let t = Instant::now();
        if c.send_text(&format!("[\"EVENT\",{ev}]")).is_err() {
            out.finding(format!("{name}: send failed"));
            return;
        }
        loop {
            match c.recv_text() {
                Ok(s) => {
                    let v: serde_json::Value = serde_json::from_str(&s).unwrap_or_default();
                    if v[0] == "OK" || v[0] == "NOTICE" {
                        let ok = v[0] == "OK" && v[2] == true;
                        if accepted.is_some_and(|a| a != ok) {
                            out.finding(format!("{name}: expected accepted={accepted:?}, got {s}"));
                        } else {
                            out.note(format!("{name}: {} in {:.1} ms", s.chars().take(100).collect::<String>(), t.elapsed().as_secs_f64() * 1e3));
                        }
                        return;
                    }
                }
                Err(e) => {
                    out.finding(format!("{name}: no answer ({e})"));
                    return;
                }
            }
        }
    };
    let n = now();
    let s = |v: &str| v.to_string();
    // As many distinct 64-hex p tags as fit in a 64 KiB event (~72 bytes each).
    let p_tags: Vec<Vec<String>> = (0..880).map(|i| vec![s("p"), gen::hex(&crate::torture::work::key(i, 7))]).collect();
    let flip_sig = |ev: String| {
        // A well-formed signature that does not verify: one hex digit changed.
        let at = ev.find("\"sig\":\"").unwrap() + 7;
        let mut b = ev.into_bytes();
        b[at] = if b[at] == b'0' { b'1' } else { b'0' };
        String::from_utf8(b).unwrap()
    };
    let big = "x".repeat(60_000);
    let cases: Vec<(&str, String, Option<bool>)> = vec![
        ("valid", keys.event(n, 1, serde_json::json!([]), "hello").0, Some(true)),
        ("bad signature", flip_sig(keys.event(n, 1, serde_json::json!([]), "x").0), Some(false)),
        ("sig of the wrong length", keys.event(n, 1, serde_json::json!([]), "x").0.replace("\"sig\":\"", "\"sig\":\"0"), Some(false)),
        ("bad id", { let (e, id) = keys.event(n, 1, serde_json::json!([]), "y"); e.replace(&gen::hex(&id), &"00".repeat(32)) }, Some(false)),
        ("every escape", keys.sign_json(n, 1, "[[\"t\",\"\\u0000\\b\\f\\n\\r\\t\\\"\\\\\\/\\u00e9\\ud83d\\ude00\"]]", "\\u0001\\u001f \\ud83d\\ude00 \\/").unwrap_or_default(), Some(true)),
        ("lone surrogate (signed raw)", keys.event(n, 1, serde_json::json!([]), "lone").0.replace("\"content\":\"lone\"", "\"content\":\"\\ud800\""), Some(false)),
        ("880 distinct p tags", keys.event(n, 1, serde_json::json!(p_tags), "tags").0, Some(true)),
        ("2000 short tags", keys.event(n, 1, serde_json::json!((0..2000).map(|i| vec!["t".to_string(), i.to_string()]).collect::<Vec<_>>()), "").0, Some(true)),
        ("2001 tags", keys.event(n, 1, serde_json::json!((0..2001).map(|i| vec!["t".to_string(), i.to_string()]).collect::<Vec<_>>()), "").0, Some(false)),
        ("60 KB content", keys.event(n, 1, serde_json::json!([]), &big).0, Some(true)),
        ("over 64 KiB", keys.event(n, 1, serde_json::json!([]), &"x".repeat(70_000)).0, Some(false)),
        ("far future", keys.event(n + 100_000, 1, serde_json::json!([]), "f").0, Some(false)),
        ("already expired", keys.event(n, 1, serde_json::json!([["expiration", "1000"]]), "e").0, Some(false)),
        ("protected", keys.event(n, 1, serde_json::json!([["-"]]), "p").0, Some(false)),
        ("created_at 0", keys.event(0, 1, serde_json::json!([]), "zero").0, Some(true)),
        ("kind u64::MAX>>1", keys.event(n, u64::MAX >> 1, serde_json::json!([]), "k").0, None),
        ("missing sig", keys.event(n, 1, serde_json::json!([]), "m").0.replace("\"sig\":", "\"sog\":"), Some(false)),
        ("duplicate content", keys.event(n, 1, serde_json::json!([]), "d").0.replacen("\"content\":", "\"content\":\"a\",\"content\":", 1), Some(false)),
        ("ephemeral", keys.event(n, 20001, serde_json::json!([]), "eph").0, Some(true)),
        ("gift wrap without p", keys.event(n, 1059, serde_json::json!([]), "w").0, Some(true)),
    ];
    for (name, ev, accepted) in &cases {
        if ev.is_empty() {
            continue;
        }
        expect(&mut c, name, ev, *accepted);
    }
    // Invalid UTF-8 inside an EVENT: the relay must close with 1007.
    let mut raw = b"[\"EVENT\",{\"content\":\"".to_vec();
    raw.extend_from_slice(&[0xC3, 0x28, 0xFF]);
    raw.extend_from_slice(b"\"}]");
    let _ = c.send_frame(&Frame::new(1, &raw));
    match c.wait_closed(Duration::from_secs(5)) {
        Ok(Some(1007)) => out.note("invalid UTF-8 text: closed with 1007"),
        other => out.finding(format!("invalid UTF-8 text: {other:?} (want close 1007)")),
    }
    // The tag-heavy event's cost to the writer, from several addresses at once
    // (each within its own per-IP allowance).
    let addr = env.addr;
    let seed = env.seed;
    let done = Arc::new(AtomicU64::new(0));
    let d2 = done.clone();
    let t = Instant::now();
    swarm(8, env.secs, move |i, stop| {
        let keys = Keys::from_seed(seed ^ 0x7A65 ^ i);
        let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(5000 + i)), ..Opts::default() }) else { return };
        let mut k = 0u64;
        while !stop.load(Ordering::Relaxed) {
            k += 1;
            let tags: Vec<Vec<String>> = (0..880).map(|j| vec!["p".to_string(), gen::hex(&crate::torture::work::key(i * 1_000_000 + k * 3000 + j, 9))]).collect();
            let (ev, _) = keys.event(now(), 1, serde_json::json!(tags), "heavy");
            if c.send_text(&format!("[\"EVENT\",{ev}]")).is_err() {
                return;
            }
            match c.recv_text() {
                Ok(s) if s.contains(",true,") => {
                    d2.fetch_add(1, Ordering::Relaxed);
                }
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    out.note(format!("{} events with 880 distinct p tags stored in {:.1} s ({:.0}/s)", done.load(Ordering::Relaxed), t.elapsed().as_secs_f64(), done.load(Ordering::Relaxed) as f64 / t.elapsed().as_secs_f64()));
    out
}

// ---------------------------------------------------------------- frames

/// Frame-level abuse: oversized frames, fragmentation tricks, control-frame
/// floods, reserved bits and opcodes, unmasked frames, compression bombs.
/// Each case expects a specific close code (or none) and a relay that serves
/// the next connection normally.
pub fn frames(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let mut case = |name: &str, deflate: bool, frames: Vec<Frame>, want: Option<u16>| {
        let Ok(mut c) = Conn::connect(env.addr, &Opts { ip: Some(&ip(6000)), deflate, ..Opts::default() }) else {
            out.finding(format!("{name}: could not connect"));
            return;
        };
        if deflate && !c.deflate {
            out.note(format!("{name}: compression not negotiated, skipped"));
            return;
        }
        for f in &frames {
            if c.send_frame(f).is_err() {
                break;
            }
        }
        let got = c.wait_closed(Duration::from_secs(5));
        match (got, want) {
            (Ok(code), Some(w)) if code == Some(w) => out.note(format!("{name}: closed with {w}")),
            (Err(_), None) => out.note(format!("{name}: still open, as it should be")),
            (got, want) => out.finding(format!("{name}: got {got:?}, want close {want:?}")),
        }
    };
    let ping = |n: usize| Frame::new(9, &vec![b'p'; n]);
    let frag = |op: u8, fin: bool, p: &[u8]| {
        let mut f = Frame::new(op, p);
        f.fin = fin;
        f
    };
    case("frame over max_message_bytes", false, vec![Frame::text(&"x".repeat(300_000))], Some(1009));
    let mut lie = Frame::text("x");
    lie.claimed_len = Some(1 << 40);
    case("length 2^40", false, vec![lie], Some(1009));
    let mut top = Frame::text("x");
    top.claimed_len = Some(u64::MAX);
    case("length with the top bit", false, vec![top], Some(1002));
    case("control frame of 126 bytes", false, vec![ping(126)], Some(1002));
    let mut fping = ping(10);
    fping.fin = false;
    case("fragmented ping", false, vec![fping], Some(1002));
    case("continuation without a message", false, vec![frag(0, true, b"x")], Some(1002));
    case("text inside a fragmented message", false, vec![frag(1, false, b"[\"REQ\""), frag(1, true, b"x")], Some(1002));
    let mut rsv = Frame::text("[]");
    rsv.rsv = 0x20;
    case("RSV2 set", false, vec![rsv], Some(1002));
    let mut rsv1 = Frame::text("[]");
    rsv1.rsv = 0x40;
    case("RSV1 without compression", false, vec![rsv1], Some(1002));
    case("reserved opcode 3", false, vec![Frame::new(3, b"x")], Some(1002));
    case("reserved opcode 0xB", false, vec![Frame::new(0xB, b"x")], Some(1002));
    let mut unmasked = Frame::text("[]");
    unmasked.mask = None;
    case("unmasked client frame", false, vec![unmasked], Some(1002));
    case("close with code 999", false, vec![Frame::new(8, &999u16.to_be_bytes())], Some(1002));
    case("close with a 1-byte payload", false, vec![Frame::new(8, &[3])], Some(1002));
    case("close with invalid UTF-8 reason", false, vec![Frame::new(8, &[3, 232, 0xFF])], Some(1007));
    case("binary message", false, vec![Frame::new(2, b"\x00\x01")], None);
    // A message assembled from 4096 one-byte fragments with pings between.
    let mut many = vec![frag(1, false, b"[")];
    for i in 0..4096 {
        many.push(frag(0, false, b" "));
        if i % 64 == 0 {
            many.push(ping(4));
        }
    }
    many.push(frag(0, true, b"]"));
    case("4096 fragments with pings between", false, many, Some(1002).filter(|_| false));
    // Fragments adding up past the message limit.
    let mut past = vec![frag(1, false, &vec![b' '; 100_000])];
    past.push(frag(0, false, &vec![b' '; 100_000]));
    past.push(frag(0, true, &vec![b' '; 100_000]));
    case("fragments past the message limit", false, past, Some(1009));
    // Compression: a bomb (1000:1), garbage compressed data, RSV1 on a continuation.
    let mut bomb = Frame::new(1, &wsframe::deflate_bomb(64 << 20, b' '));
    bomb.rsv = 0x40;
    case("compression bomb (64 MiB of spaces)", true, vec![bomb], Some(1009));
    let mut junk = Frame::new(1, &[0xFF, 0xFF, 0xFF, 0x00, 0x01]);
    junk.rsv = 0x40;
    case("compressed garbage", true, vec![junk], Some(1007));
    let mut c1 = frag(1, false, &wsframe::deflate_message(b"[\"REQ\",\"z\",{}]"));
    c1.rsv = 0x40;
    let mut c2 = frag(0, true, b"");
    c2.rsv = 0x40;
    case("RSV1 on a continuation", true, vec![c1, c2], Some(1002));
    let mut good = Frame::new(1, &wsframe::deflate_message(b"[\"REQ\",\"z\",{\"kinds\":[7],\"limit\":1}]"));
    good.rsv = 0x40;
    case("a valid compressed REQ", true, vec![good], None);

    // A ping flood from a client that never reads: the pongs must not pile up.
    let rss0 = env.relay.rss_kb().unwrap_or(0);
    let flood_secs = env.secs;
    let addr = env.addr;
    swarm(4, flood_secs, move |i, stop| {
        let Ok(mut s) = tcp(addr) else { return };
        let _ = s.write_all(&super::client::handshake_bytes(Some(&ip(6100 + i)), false));
        let chunk: Vec<u8> = (0..400).flat_map(|_| Frame::new(9, &[b'x'; 125]).bytes()).collect();
        s.set_write_timeout(Some(Duration::from_millis(200))).ok();
        while !stop.load(Ordering::Relaxed) {
            if s.write_all(&chunk).is_err() {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    });
    let rss1 = env.relay.rss_kb().unwrap_or(0);
    out.note(format!("ping flood (4 clients that never read): RSS {} -> {} MB", rss0 / 1024, rss1 / 1024));
    if rss1 > rss0 + 256 * 1024 {
        out.finding(format!("ping flood grew the relay by {} MB", (rss1 - rss0) / 1024));
    }
    out
}

// ---------------------------------------------------------------- slow and silent clients

/// Slowloris before the handshake (connections that send nothing, or a byte
/// at a time) and after it (a frame trickled a byte at a time), plus how many
/// silent connections it takes to stop new clients from getting in.
pub fn slowloris(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let addr = env.addr;
    // A valid handshake, one byte every 20 ms: ~4 s, inside the 10 s limit.
    let t = Instant::now();
    let slow_ok = (|| -> std::io::Result<bool> {
        let mut s = tcp(addr)?;
        for b in super::client::handshake_bytes(Some(&ip(7000)), false) {
            s.write_all(&[b])?;
            std::thread::sleep(Duration::from_millis(20));
        }
        s.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf)?;
        Ok(buf[..n].starts_with(b"HTTP/1.1 101"))
    })();
    match slow_ok {
        Ok(true) => out.note(format!("byte-at-a-time handshake accepted after {:.1} s", t.elapsed().as_secs_f64())),
        other => out.finding(format!("byte-at-a-time handshake (within the timeout) failed: {other:?}")),
    }
    // Silent connections: hold as many as the relay accepts, see whether a
    // well-behaved client still gets in, and whether they are let go.
    let target = env.silent;
    let mut held = Vec::new();
    let t = Instant::now();
    for _ in 0..target {
        match tcp(addr) {
            Ok(s) => held.push(s),
            Err(e) => {
                out.note(format!("stopped opening silent connections after {}: {e}", held.len()));
                break;
            }
        }
    }
    out.note(format!("{} silent connections opened in {:.1} s", held.len(), t.elapsed().as_secs_f64()));
    let fds = env.relay.fds().unwrap_or(0);
    out.note(format!("relay holds {fds} descriptors"));
    let probe = Conn::connect(addr, &Opts { ip: Some(&ip(7001)), ..Opts::default() });
    match probe {
        Ok(_) => out.note("a new client still connects while they are held"),
        Err(e) => out.finding(format!("with {} silent connections held, a new client cannot connect: {e}", held.len())),
    }
    // They must be dropped within the handshake timeout (10 s).
    std::thread::sleep(Duration::from_secs(12));
    let mut closed = 0;
    for s in &mut held {
        s.set_read_timeout(Some(Duration::from_millis(1))).ok();
        let mut b = [0u8; 1];
        if matches!(s.read(&mut b), Ok(0) | Err(_)) && !matches!(s.read(&mut b), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock) {
            closed += 1;
        }
    }
    out.note(format!("{closed} of {} silent connections closed by the relay after 12 s", held.len()));
    if closed * 10 < held.len() * 9 {
        out.finding(format!("only {closed} of {} silent connections were dropped after 12 s (handshake timeout 10 s)", held.len()));
    }
    drop(held);
    // After the handshake: a 200 KB frame header, then the payload at 1 byte per 10 ms.
    let mut c = match Conn::connect(addr, &Opts { ip: Some(&ip(7002)), ..Opts::default() }) {
        Ok(c) => c,
        Err(e) => {
            out.finding(format!("connect: {e}"));
            return out;
        }
    };
    let f = Frame::text(&format!("[\"REQ\",\"slow\",{{\"kinds\":[7]{}}}]", " ".repeat(200_000)));
    let bytes = f.bytes();
    let t = Instant::now();
    let mut sent = 0;
    for b in bytes.iter().take(500) {
        if c.send_raw(&[*b]).is_err() {
            break;
        }
        sent += 1;
        std::thread::sleep(Duration::from_millis(5));
    }
    out.note(format!("trickled {sent} bytes of a 200 KB frame over {:.1} s; connection kept (idle ping at 60 s)", t.elapsed().as_secs_f64()));
    out
}

// ---------------------------------------------------------------- clients that never read

/// Subscribers that never read while events pour in: once a subscriber's
/// outbound limit is reached the relay must let it go (and what it buffered
/// for it), without the subscriber having to read anything first.
pub fn noread(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let addr = env.addr;
    let fds0 = env.relay.fds().unwrap_or(0);
    let mut sinks = Vec::new();
    for i in 0..env.noread {
        let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(8000 + i)), ..Opts::default() }) else { continue };
        let _ = c.send_text("[\"REQ\",\"all\",{\"kinds\":[1,20001],\"limit\":1}]");
        sinks.push(c);
    }
    std::thread::sleep(Duration::from_millis(500));
    let fds1 = env.relay.fds().unwrap_or(0);
    out.note(format!("{} subscribers that never read (relay descriptors {fds0} -> {fds1})", sinks.len()));
    let rss0 = env.relay.rss_kb().unwrap_or(0);
    let seed = env.seed;
    let published = Arc::new(AtomicU64::new(0));
    let p2 = published.clone();
    let t = Instant::now();
    swarm(16, env.secs, move |i, stop| {
        let keys = Keys::from_seed(seed ^ 0x9E ^ i);
        let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(9000 + i)), ..Opts::default() }) else { return };
        let body = "z".repeat(30_000);
        let mut k = 0;
        while !stop.load(Ordering::Relaxed) {
            k += 1;
            // Ephemeral (kind 2xxxx): relayed live, never stored, so the disk stays small.
            let (ev, _) = keys.event(now(), 20001, serde_json::json!([]), &format!("{k} {body}"));
            if c.send_text(&format!("[\"EVENT\",{ev}]")).is_err() || c.recv_text().is_err() {
                return;
            }
            p2.fetch_add(1, Ordering::Relaxed);
        }
    });
    let mb = published.load(Ordering::Relaxed) * 30 / 1000;
    std::thread::sleep(Duration::from_secs(3));
    // Nothing has been read yet: what the relay still holds now is what a
    // client that never reads costs it.
    let rss1 = env.relay.rss_kb().unwrap_or(0);
    let fds2 = env.relay.fds().unwrap_or(0);
    out.note(format!(
        "{} ephemeral 30 KB events ({mb} MB) published in {:.1} s; then, with nothing read: relay memory {} -> {} MB, descriptors {fds1} -> {fds2}",
        published.load(Ordering::Relaxed),
        t.elapsed().as_secs_f64(),
        rss0 / 1024,
        rss1 / 1024
    ));
    let held = fds2.saturating_sub(fds0);
    if held >= sinks.len() as u64 / 2 && !sinks.is_empty() {
        out.finding(format!(
            "after a flood far past their outbound limit, the relay still holds {held} of {} subscribers that never read, and what it buffered for them",
            sinks.len()
        ));
    }
    let per = rss1.saturating_sub(rss0) / sinks.len().max(1) as u64;
    if per > 16 * 1024 {
        out.finding(format!("{} MB of relay memory per subscriber that never reads", per / 1024));
    }
    out
}

// ---------------------------------------------------------------- expensive requests

/// Requests that cost the relay far more than they cost the client, sent
/// back to back from a few connections: the planner's worst case per byte
/// (50 filters, each a product of authors and kinds just under the cap), and
/// events with as many distinct tags as fit in 64 KiB (each one an index key).
/// The canary must stay within its latency budget.
pub fn expensive(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let addr = env.addr;
    let seed = env.seed;
    let reqs = Arc::new(AtomicU64::new(0));
    let r2 = reqs.clone();
    let slowest = Arc::new(AtomicU64::new(0));
    let s2 = slowest.clone();
    let t = Instant::now();
    swarm(4, env.secs, move |i, stop| {
        let mut rng = Rng::derive(seed ^ 0xE4, i);
        let hexes = |rng: &mut Rng, n: usize| (0..n).map(|_| format!("\"{}\"", gen::hex(&rng.bytes32()))).collect::<Vec<_>>().join(",");
        let kinds = (0..64).map(|k| k.to_string()).collect::<Vec<_>>().join(",");
        let filters: Vec<String> = (0..50).map(|_| format!("{{\"authors\":[{}],\"kinds\":[{kinds}]}}", hexes(&mut rng, 60))).collect();
        let req = format!("[\"REQ\",\"p\",{}]", filters.join(","));
        let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(15_000 + i)), ..Opts::default() }) else { return };
        while !stop.load(Ordering::Relaxed) {
            let t1 = Instant::now();
            if c.send_text(&req).is_err() {
                return;
            }
            loop {
                match c.recv_text() {
                    Ok(s) if s.starts_with("[\"EOSE\"") || s.starts_with("[\"CLOSED\"") => break,
                    Ok(_) => {}
                    Err(_) => return,
                }
            }
            s2.fetch_max(t1.elapsed().as_micros() as u64, Ordering::Relaxed);
            r2.fetch_add(1, Ordering::Relaxed);
        }
    });
    let n = reqs.load(Ordering::Relaxed);
    out.note(format!(
        "{n} REQs of 50 filters x 60 authors x 64 kinds (~240 KB each) from 4 connections in {:.1} s: {:.0} per second, slowest answer {:.1} ms",
        t.elapsed().as_secs_f64(),
        n as f64 / t.elapsed().as_secs_f64(),
        slowest.load(Ordering::Relaxed) as f64 / 1e3
    ));
    out
}

// ---------------------------------------------------------------- large requests

/// REQs whose answers are huge (50 filters of 5000 each over a full store),
/// from clients that do not read them: how much memory one costs, and
/// whether the reactor stalls while building it.
pub fn bigreq(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let addr = env.addr;
    let rss0 = env.relay.rss_kb().unwrap_or(0);
    let filters: Vec<String> = (0..50).map(|i| format!("{{\"kinds\":[1],\"limit\":5000,\"until\":{}}}", now() - i * 2)).collect();
    let req = format!("[\"REQ\",\"big\",{}]", filters.join(","));
    let mut held = Vec::new();
    let t = Instant::now();
    for i in 0..env.bigreq {
        let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(10_000 + i)), ..Opts::default() }) else { continue };
        let _ = c.send_text(&req);
        held.push(c);
    }
    std::thread::sleep(Duration::from_secs(3));
    let rss1 = env.relay.rss_kb().unwrap_or(0);
    out.note(format!("{} unread 50-filter REQs: relay RSS {} -> {} MB ({:.1} s)", held.len(), rss0 / 1024, rss1 / 1024, t.elapsed().as_secs_f64()));
    let per = rss1.saturating_sub(rss0) / held.len().max(1) as u64;
    out.note(format!("{per} KB per unread REQ"));
    if per > 64 * 1024 {
        out.finding(format!("one unread REQ pins {} MB of relay memory", per / 1024));
    }
    // One read to the end: how long it takes and how much it is.
    if let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(11_000)), ..Opts::default() }) {
        let t = Instant::now();
        let _ = c.send_text(&req);
        let (mut n, mut bytes) = (0u64, 0u64);
        loop {
            match c.recv_text() {
                Ok(s) if s.starts_with("[\"EOSE\"") => break,
                Ok(s) => {
                    n += 1;
                    bytes += s.len() as u64;
                }
                Err(e) => {
                    out.finding(format!("reading a big REQ: {e}"));
                    break;
                }
            }
        }
        out.note(format!("a read big REQ: {n} events, {} MB in {:.2} s", bytes / 1_000_000, t.elapsed().as_secs_f64()));
    }
    drop(held);
    out
}

// ---------------------------------------------------------------- negentropy

/// NEG-OPEN with filters that match the whole store, eight sessions per
/// connection on many connections: the sets are held in memory per session.
pub fn neg(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let addr = env.addr;
    let rss0 = env.relay.rss_kb().unwrap_or(0);
    let mut held = Vec::new();
    let t = Instant::now();
    let mut max_open = Duration::ZERO;
    for i in 0..env.neg_conns {
        let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(12_000 + i)), ..Opts::default() }) else { continue };
        for s in 0..8 {
            let t1 = Instant::now();
            let _ = c.send_text(&format!("[\"NEG-OPEN\",\"n{s}\",{{\"kinds\":[1]}},\"6100000200\"]"));
            match c.recv_text() {
                Ok(m) if m.starts_with("[\"NEG-MSG\"") => {}
                Ok(m) => {
                    out.note(format!("NEG-OPEN answered {}", m.chars().take(120).collect::<String>()));
                    break;
                }
                Err(e) => {
                    out.finding(format!("NEG-OPEN: {e}"));
                    break;
                }
            }
            max_open = max_open.max(t1.elapsed());
        }
        held.push(c);
    }
    let rss1 = env.relay.rss_kb().unwrap_or(0);
    out.note(format!(
        "{} connections x 8 whole-store NEG sessions: RSS {} -> {} MB in {:.1} s; slowest NEG-OPEN {:.1} ms",
        held.len(),
        rss0 / 1024,
        rss1 / 1024,
        t.elapsed().as_secs_f64(),
        max_open.as_secs_f64() * 1e3
    ));
    let sessions = held.len() as u64 * 8;
    out.note(format!("{} KB per session", rss1.saturating_sub(rss0) / sessions.max(1)));
    drop(held);
    out
}

// ---------------------------------------------------------------- churn and per-IP limits

/// Connect/disconnect churn (clean closes, resets mid-frame, handshakes cut
/// short), then the per-IP connection limit and EVENT rate limit.
pub fn churn(env: &mut Env) -> Outcome {
    let mut out = Outcome::default();
    let addr = env.addr;
    let fds0 = env.relay.fds().unwrap_or(0);
    let cycles = Arc::new(AtomicU64::new(0));
    let c2 = cycles.clone();
    swarm(16, env.secs, move |i, stop| {
        let mut rng = Rng::derive(0xC4, i);
        let mut k = 0;
        while !stop.load(Ordering::Relaxed) {
            k += 1;
            match rng.below(4) {
                0 => {
                    // A cut-short handshake.
                    if let Ok(mut s) = tcp(addr) {
                        let h = super::client::handshake_bytes(None, false);
                        let _ = s.write_all(&h[..rng.usize(h.len())]);
                    }
                }
                1 => {
                    // A reset in the middle of a frame.
                    if let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(13_000 + i * 1000 + k % 1000)), ..Opts::default() }) {
                        let b = Frame::text("[\"REQ\",\"x\",{}]").bytes();
                        let _ = c.send_raw(&b[..b.len() / 2]);
                        super::client::reset_on_close(&c.s);
                    }
                }
                _ => {
                    if let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some(&ip(13_000 + i * 1000 + k % 1000)), ..Opts::default() }) {
                        let _ = c.send_text("[\"REQ\",\"x\",{\"kinds\":[7],\"limit\":1}]");
                        let _ = c.recv_text();
                        let _ = c.send_frame(&Frame::new(8, &1000u16.to_be_bytes()));
                    }
                }
            }
            c2.fetch_add(1, Ordering::Relaxed);
        }
    });
    std::thread::sleep(Duration::from_secs(3));
    let fds1 = env.relay.fds().unwrap_or(0);
    out.note(format!("{} connection cycles; relay descriptors {fds0} -> {fds1}", cycles.load(Ordering::Relaxed)));
    if fds1 > fds0 + 32 {
        out.finding(format!("descriptors grew from {fds0} to {fds1} after churn: connections leak"));
    }
    // Per-IP: 64 connections are allowed from one address (the default).
    let mut held = Vec::new();
    let mut refused = None;
    for k in 0..70 {
        match Conn::connect(addr, &Opts { ip: Some("10.250.0.1"), ..Opts::default() }) {
            Ok(mut c) => {
                c.s.set_read_timeout(Some(Duration::from_millis(100))).ok();
                if let Ok(Msg::Close(code)) = c.recv() {
                    refused = Some((k, code));
                    break;
                }
                held.push(c);
            }
            Err(e) => {
                refused = Some((k, Some(0)));
                out.note(format!("connection {k} from one address: {e}"));
                break;
            }
        }
    }
    match refused {
        Some((64, Some(1008))) => out.note("65th connection from one address refused with 1008"),
        other => out.finding(format!("per-IP limit: refused at {other:?}, expected the 65th with 1008")),
    }
    drop(held);
    std::thread::sleep(Duration::from_millis(500));
    // The slots come back.
    if Conn::connect(addr, &Opts { ip: Some("10.250.0.1"), ..Opts::default() }).is_err() {
        out.finding("the address's connection slots did not come back after its connections closed");
    }
    // EVENT rate: 1200 a minute per address by default.
    if let Ok(mut c) = Conn::connect(addr, &Opts { ip: Some("10.250.0.2"), ..Opts::default() }) {
        let keys = Keys::from_seed(0x1A7E);
        let (mut ok, mut limited) = (0, 0);
        for k in 0..1500 {
            let (ev, _) = keys.event(now(), 1, serde_json::json!([]), &format!("rate {k}"));
            let _ = c.send_text(&format!("[\"EVENT\",{ev}]"));
            match c.recv_text() {
                Ok(s) if s.contains("rate-limited") => limited += 1,
                Ok(s) if s.contains(",true,") => ok += 1,
                _ => {}
            }
        }
        out.note(format!("1500 EVENTs from one address: {ok} accepted, {limited} rate-limited"));
        if !(1150..=1260).contains(&ok) {
            out.finding(format!("EVENT rate limit let {ok} of 1500 through (allowance 1200 a minute)"));
        }
    }
    out
}
