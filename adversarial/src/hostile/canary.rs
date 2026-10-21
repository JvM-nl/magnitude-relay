//! The canary: a well-behaved client that keeps using the relay while it is
//! attacked, and checks every answer. Each round it publishes a fresh signed
//! event (OK true expected), receives it on a live subscription, fetches it
//! back by id (exactly that event, then EOSE), and now and then counts its
//! own events (COUNT must equal what was published). Every step has a
//! deadline; latencies are kept per phase so a scenario can be judged on them.

use super::client::{Conn, Opts};
use crate::sign::Keys;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default, Clone)]
pub struct Window {
    pub rounds: u64,
    pub errors: Vec<String>,
    pub ok: Vec<Duration>,
    pub live: Vec<Duration>,
    pub fetch: Vec<Duration>,
}

impl Window {
    fn pct(v: &[Duration], p: f64) -> Duration {
        if v.is_empty() {
            return Duration::ZERO;
        }
        let mut s = v.to_vec();
        s.sort_unstable();
        s[((s.len() - 1) as f64 * p).round() as usize]
    }

    /// (p50, p99, max) of every phase together.
    pub fn summary(&self) -> (Duration, Duration, Duration) {
        let all: Vec<Duration> = self.ok.iter().chain(&self.live).chain(&self.fetch).copied().collect();
        (Self::pct(&all, 0.5), Self::pct(&all, 0.99), all.iter().copied().max().unwrap_or_default())
    }

    pub fn describe(&self) -> String {
        let (p50, p99, max) = self.summary();
        format!(
            "{} rounds, {} errors, latency p50 {:.1} ms p99 {:.1} ms max {:.1} ms (OK p99 {:.1}, live p99 {:.1}, fetch p99 {:.1})",
            self.rounds,
            self.errors.len(),
            p50.as_secs_f64() * 1e3,
            p99.as_secs_f64() * 1e3,
            max.as_secs_f64() * 1e3,
            Self::pct(&self.ok, 0.99).as_secs_f64() * 1e3,
            Self::pct(&self.live, 0.99).as_secs_f64() * 1e3,
            Self::pct(&self.fetch, 0.99).as_secs_f64() * 1e3,
        )
    }
}

pub struct Canary {
    stop: Arc<AtomicBool>,
    window: Arc<Mutex<Window>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

const STEP: Duration = Duration::from_secs(5);
/// The canary's own address, which no attack shares.
pub const IP: &str = "10.99.99.99";

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn wait_for(c: &mut Conn, what: &str, pred: impl Fn(&serde_json::Value) -> bool) -> Result<serde_json::Value, String> {
    let deadline = Instant::now() + STEP;
    loop {
        if Instant::now() > deadline {
            return Err(format!("no {what} within {STEP:?}"));
        }
        let t = c.recv_text().map_err(|e| format!("waiting for {what}: {e}"))?;
        let v: serde_json::Value = serde_json::from_str(&t).map_err(|e| format!("relay sent invalid JSON ({e}): {t}"))?;
        if pred(&v) {
            return Ok(v);
        }
    }
}

struct Session {
    pubc: Conn,
    subc: Conn,
}

fn open(addr: SocketAddr, keys: &Keys, since: u64) -> Result<Session, String> {
    let o = Opts { ip: Some(IP), ..Opts::default() };
    let pubc = Conn::connect(addr, &o).map_err(|e| format!("connect: {e}"))?;
    let mut subc = Conn::connect(addr, &Opts { ip: Some(IP), deflate: true, ..Opts::default() }).map_err(|e| format!("connect: {e}"))?;
    subc.send_text(&format!("[\"REQ\",\"live\",{{\"authors\":[\"{}\"],\"since\":{since}}}]", keys.pk_hex)).map_err(|e| e.to_string())?;
    wait_for(&mut subc, "EOSE of the live subscription", |v| v[0] == "EOSE" && v[1] == "live")?;
    Ok(Session { pubc, subc })
}

fn round(s: &mut Session, keys: &Keys, n: u64, published: &mut u64, w: &Arc<Mutex<Window>>) -> Result<(), String> {
    let content = format!("canary {n} {}", "x".repeat((n % 7) as usize * 40));
    let tags = serde_json::json!([["t", "canary"]]);
    let (ev, id) = keys.event(now(), 1, tags, &content);
    let id_hex = relay_proto::hex::encode_string(&id);
    let t0 = Instant::now();
    s.pubc.send_text(&format!("[\"EVENT\",{ev}]")).map_err(|e| format!("send EVENT: {e}"))?;
    let ok = wait_for(&mut s.pubc, "OK", |v| v[0] == "OK" && v[1] == id_hex.as_str())?;
    let t_ok = t0.elapsed();
    if ok[2] != true {
        return Err(format!("EVENT refused: {ok}"));
    }
    *published += 1;
    let live = wait_for(&mut s.subc, "live delivery", |v| v[0] == "EVENT" && v[1] == "live")?;
    let t_live = t0.elapsed();
    if live[2]["id"] != id_hex.as_str() {
        return Err(format!("live subscription delivered {} instead of {id_hex}", live[2]["id"]));
    }
    let t1 = Instant::now();
    s.pubc.send_text(&format!("[\"REQ\",\"q{n}\",{{\"ids\":[\"{id_hex}\"]}}]")).map_err(|e| e.to_string())?;
    let got = wait_for(&mut s.pubc, "the event by id", |v| (v[0] == "EVENT" || v[0] == "EOSE" || v[0] == "CLOSED") && v[1] == format!("q{n}").as_str())?;
    if got[0] != "EVENT" || got[2]["id"] != id_hex.as_str() || got[2]["content"] != content.as_str() {
        return Err(format!("fetch by id returned {got}"));
    }
    wait_for(&mut s.pubc, "EOSE", |v| v[0] == "EOSE" && v[1] == format!("q{n}").as_str())?;
    s.pubc.send_text(&format!("[\"CLOSE\",\"q{n}\"]")).map_err(|e| e.to_string())?;
    let t_fetch = t1.elapsed();
    if n.is_multiple_of(10) {
        s.pubc.send_text(&format!("[\"COUNT\",\"c{n}\",{{\"authors\":[\"{}\"]}}]", keys.pk_hex)).map_err(|e| e.to_string())?;
        let c = wait_for(&mut s.pubc, "COUNT", |v| v[0] == "COUNT" || (v[0] == "CLOSED" && v[1] == format!("c{n}").as_str()))?;
        if c[2]["count"] != *published {
            return Err(format!("COUNT says {} of my events, I published {}", c[2]["count"], published));
        }
    }
    let mut g = w.lock().unwrap();
    g.rounds += 1;
    g.ok.push(t_ok);
    g.live.push(t_live);
    g.fetch.push(t_fetch);
    Ok(())
}

impl Canary {
    pub fn start(addr: SocketAddr, seed: u64) -> Canary {
        let stop = Arc::new(AtomicBool::new(false));
        let window = Arc::new(Mutex::new(Window::default()));
        let (st, w) = (stop.clone(), window.clone());
        let handle = std::thread::Builder::new()
            .name("canary".into())
            .spawn(move || {
                let keys = Keys::from_seed(seed);
                let since = now().saturating_sub(5);
                let mut published = 0u64;
                let mut n = 0u64;
                let mut s: Option<Session> = None;
                while !st.load(Ordering::Relaxed) {
                    if s.is_none() {
                        match open(addr, &keys, since) {
                            Ok(x) => s = Some(x),
                            Err(e) => {
                                w.lock().unwrap().errors.push(e);
                                std::thread::sleep(Duration::from_millis(200));
                                continue;
                            }
                        }
                    }
                    n += 1;
                    if let Err(e) = round(s.as_mut().unwrap(), &keys, n, &mut published, &w) {
                        w.lock().unwrap().errors.push(format!("round {n}: {e}"));
                        // Start over on fresh connections: whatever went wrong may
                        // have left one in an unknown state.
                        s = None;
                        // Its event may or may not have been stored; recount on the next COUNT.
                        published = u64::MAX;
                    }
                    if published == u64::MAX {
                        published = recount(addr, &keys).unwrap_or(0);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            })
            .expect("canary thread");
        Canary { stop, window, handle: Some(handle) }
    }

    /// The measurements since the last call.
    pub fn take(&self) -> Window {
        std::mem::take(&mut *self.window.lock().unwrap())
    }

    pub fn stop(mut self) -> Window {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        self.take()
    }
}

fn recount(addr: SocketAddr, keys: &Keys) -> Option<u64> {
    let mut c = Conn::connect(addr, &Opts { ip: Some(IP), ..Opts::default() }).ok()?;
    c.send_text(&format!("[\"COUNT\",\"r\",{{\"authors\":[\"{}\"]}}]", keys.pk_hex)).ok()?;
    let v = wait_for(&mut c, "COUNT", |v| v[0] == "COUNT").ok()?;
    v[2]["count"].as_u64()
}
