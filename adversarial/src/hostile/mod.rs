//! Hostile clients against the real relay binary, with a canary.
//!
//! The relay is started on a loopback port with a store prefilled by its own
//! `import` (so large answers are large), trusting `X-Real-IP` so one machine
//! can play many clients. A canary (canary.rs) keeps publishing, subscribing,
//! fetching and counting throughout. Each scenario (attacks.rs) runs for a
//! while; around it the harness samples the relay's memory (peak and after)
//! and open descriptors, and judges: the relay alive, the canary correct and
//! within its latency budget, memory bounded and given back, descriptors not
//! leaking, plus the scenario's own expectations.

pub mod attacks;
pub mod canary;
pub mod client;
pub mod diskfull;
pub mod relay;

use crate::sign::Keys;
use relay::Relay;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What a scenario gets to work with.
pub struct Env<'a> {
    pub addr: SocketAddr,
    pub relay: &'a mut Relay,
    pub seed: u64,
    pub secs: f64,
    /// Silent connections the slowloris scenario holds.
    pub silent: usize,
    /// Subscribers that never read, in the backpressure scenario.
    pub noread: u64,
    /// Unread huge REQs.
    pub bigreq: u64,
    /// Connections holding eight whole-store NEG sessions each.
    pub neg_conns: u64,
}

pub struct Cfg {
    pub bin: PathBuf,
    pub dir: PathBuf,
    pub seed: u64,
    pub secs: f64,
    pub threads: usize,
    /// Events imported before the relay starts.
    pub prefill: usize,
    pub scenarios: Vec<String>,
    /// The canary's p99 budget under attack.
    pub latency: Duration,
    pub silent: usize,
    pub noread: u64,
    pub bigreq: u64,
    pub neg_conns: u64,
    /// Passes over the scenarios (a soak runs many), or until `hours` is up.
    pub rounds: u64,
    pub hours: f64,
    /// Well-behaved clients beside the canary, as normal traffic (each one
    /// checked like the canary).
    pub load: usize,
    /// A CSV line per scenario run: time, memory, descriptors, latency.
    pub log: Option<PathBuf>,
}

pub type Scenario = (&'static str, fn(&mut Env<'_>) -> attacks::Outcome);

pub fn scenarios() -> Vec<Scenario> {
    vec![
        ("garbage", attacks::garbage),
        ("subscriptions", attacks::subscriptions),
        ("filters", attacks::filters),
        ("events", attacks::events),
        ("frames", attacks::frames),
        ("slowloris", attacks::slowloris),
        ("expensive", attacks::expensive),
        ("noread", attacks::noread),
        ("bigreq", attacks::bigreq),
        ("neg", attacks::neg),
        ("churn", attacks::churn),
    ]
}

/// Writes `n` signed kind-1 events (about 1 KB each, a few dozen authors,
/// spread over the last day) as an export file.
fn prefill_file(path: &Path, n: usize, seed: u64) -> std::io::Result<()> {
    use std::io::Write;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    let keys: Vec<Keys> = (0..32).map(|i| Keys::from_seed(seed ^ 0xF111 ^ i)).collect();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let body = "lorem ipsum ".repeat(80);
    for i in 0..n {
        let k = &keys[i % keys.len()];
        let (ev, _) = k.event(now - 86_400 + (i as u64 * 86_400 / n.max(1) as u64), 1, serde_json::json!([["t", "prefill"]]), &format!("{i} {body}"));
        writeln!(f, "{ev}")?;
    }
    f.flush()
}

pub struct Verdict {
    pub name: &'static str,
    pub ok: bool,
    pub lines: Vec<String>,
}

pub fn run(cfg: &Cfg) -> Result<Vec<Verdict>, String> {
    let limit = relay::raise_nofile(65_536);
    let _ = std::fs::remove_dir_all(&cfg.dir);
    std::fs::create_dir_all(&cfg.dir).map_err(|e| e.to_string())?;
    // The store, prefilled through the relay's own import.
    let port = relay::free_port();
    let settings = format!(
        "[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = {}\nreal_ip_header = \"x-real-ip\"\n[policy]\nkinds = \"all\"\n[store]\ndata = \"{}\"\n",
        cfg.threads,
        cfg.dir.join("data").display()
    );
    if cfg.prefill > 0 {
        let file = cfg.dir.join("prefill.jsonl");
        prefill_file(&file, cfg.prefill, cfg.seed).map_err(|e| e.to_string())?;
        std::fs::write(cfg.dir.join("relay.toml"), &settings).map_err(|e| e.to_string())?;
        let out = std::process::Command::new(&cfg.bin)
            .arg("--config")
            .arg(cfg.dir.join("relay.toml"))
            .arg("import")
            .arg(&file)
            .output()
            .map_err(|e| format!("{}: {e}", cfg.bin.display()))?;
        if !out.status.success() {
            return Err(format!("import failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
    }
    let mut relay = Relay::start_at(&cfg.bin, &cfg.dir, port, cfg.threads, &settings).map_err(|e| e.to_string())?;
    eprintln!("relay up at {} (pid {}, {} events imported, our fd limit {limit})", relay.addr, relay.pid(), cfg.prefill);
    let canary = canary::Canary::start(relay.addr, cfg.seed ^ 0xCA);
    let load: Vec<canary::Canary> = (0..cfg.load).map(|i| canary::Canary::start_from(relay.addr, cfg.seed ^ 0x10AD ^ (i as u64 + 1), format!("10.99.98.{}", i + 1))).collect();
    std::thread::sleep(Duration::from_secs(2));
    let base = canary.take();
    let mut verdicts = vec![Verdict { name: "baseline", ok: base.errors.is_empty(), lines: vec![format!("canary: {}", base.describe())] }];
    let mut log = match &cfg.log {
        Some(p) => {
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).map_err(|e| format!("{}: {e}", p.display()))?;
            use std::io::Write;
            let _ = writeln!(f, "unix_time,round,scenario,ok,secs,rss_before_kb,rss_peak_kb,rss_after_kb,fds_before,fds_after,canary_rounds,p50_ms,p99_ms,max_ms,errors,load_rounds,load_errors");
            Some(f)
        }
        None => None,
    };
    let began = Instant::now();
    let chosen: Vec<Scenario> = scenarios().into_iter().filter(|(name, _)| cfg.scenarios.is_empty() || cfg.scenarios.iter().any(|s| s == name)).collect();
    let mut round = 0u64;
    'rounds: loop {
        round += 1;
        for &(name, f) in &chosen {
            if cfg.hours > 0.0 && began.elapsed().as_secs_f64() >= cfg.hours * 3600.0 {
                break 'rounds;
            }
            eprintln!("round {round}, scenario {name}...");
            let _ = canary.take();
            for c in &load {
                let _ = c.take();
            }
            let rss0 = relay.rss_kb().unwrap_or(0);
            let fds0 = relay.fds().unwrap_or(0);
            // Peak memory while the scenario runs.
            let stop = Arc::new(AtomicBool::new(false));
            let peak = Arc::new(AtomicU64::new(rss0));
            let sampler = {
                let (stop, peak, pid) = (stop.clone(), peak.clone(), relay.pid());
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        if let Some(r) = relay::rss_kb(pid) {
                            peak.fetch_max(r, Ordering::Relaxed);
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                })
            };
            let t = Instant::now();
            let out = {
                let addr = relay.addr;
                let mut env = Env { addr, relay: &mut relay, seed: cfg.seed, secs: cfg.secs, silent: cfg.silent, noread: cfg.noread, bigreq: cfg.bigreq, neg_conns: cfg.neg_conns };
                f(&mut env)
            };
            let took = t.elapsed();
            stop.store(true, Ordering::Relaxed);
            let _ = sampler.join();
            let w = canary.take();
            // Let what the scenario left behind drain, then see what stayed.
            std::thread::sleep(Duration::from_secs(3));
            let rss1 = relay.rss_kb().unwrap_or(0);
            let fds1 = relay.fds().unwrap_or(0);
            let mut v = Verdict { name, ok: true, lines: Vec::new() };
            if let Some(status) = relay.exited() {
                v.ok = false;
                v.lines.push(format!("RELAY DIED ({status}): {}", relay.log_tail(15)));
            }
            v.lines.push(format!("took {:.1} s; canary: {}", took.as_secs_f64(), w.describe()));
            v.lines.push(format!(
                "relay RSS {} MB before, {} MB peak, {} MB after; descriptors {fds0} -> {fds1}",
                rss0 / 1024,
                peak.load(Ordering::Relaxed) / 1024,
                rss1 / 1024
            ));
            for e in w.errors.iter().take(5) {
                v.ok = false;
                v.lines.push(format!("CANARY ERROR: {e}"));
            }
            let (_, p99, _) = w.summary();
            if p99 > cfg.latency {
                v.ok = false;
                v.lines.push(format!("CANARY SLOW: p99 {:.0} ms over the {:.0} ms budget", p99.as_secs_f64() * 1e3, cfg.latency.as_secs_f64() * 1e3));
            }
            if w.rounds == 0 {
                v.ok = false;
                v.lines.push("CANARY STALLED: no round completed".into());
            }
            for n in &out.notes {
                v.lines.push(format!("  {n}"));
            }
            for f in &out.findings {
                v.ok = false;
                v.lines.push(format!("FINDING: {f}"));
            }
            let (mut load_rounds, mut load_errors) = (0, 0);
            for c in &load {
                let lw = c.take();
                load_rounds += lw.rounds;
                load_errors += lw.errors.len();
                for e in lw.errors.iter().take(2) {
                    v.ok = false;
                    v.lines.push(format!("LOAD CLIENT ERROR: {e}"));
                }
            }
            if let Some(f) = log.as_mut() {
                use std::io::Write;
                let (p50, p99, max) = w.summary();
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                let _ = writeln!(
                    f,
                    "{now},{round},{name},{},{:.1},{rss0},{},{rss1},{fds0},{fds1},{},{:.2},{:.2},{:.2},{},{load_rounds},{load_errors}",
                    v.ok,
                    took.as_secs_f64(),
                    peak.load(Ordering::Relaxed),
                    w.rounds,
                    p50.as_secs_f64() * 1e3,
                    p99.as_secs_f64() * 1e3,
                    max.as_secs_f64() * 1e3,
                    w.errors.len()
                );
                let _ = f.flush();
            }
            eprintln!("  {}", if v.ok { "pass" } else { "FAIL" });
            verdicts.push(v);
            if relay.exited().is_some() {
                break 'rounds;
            }
        }
        if round >= cfg.rounds && (cfg.hours <= 0.0 || began.elapsed().as_secs_f64() >= cfg.hours * 3600.0) {
            break;
        }
    }
    for c in load {
        let _ = c.stop();
    }
    let end = canary.stop();
    let mut last = Verdict { name: "shutdown", ok: true, lines: vec![format!("canary at the end: {}", end.describe())] };
    let log = std::fs::read_to_string(&relay.log).unwrap_or_default();
    for bad in ["panicked", "corrupt", "failed:"] {
        if let Some(l) = log.lines().find(|l| l.contains(bad)) {
            last.ok = false;
            last.lines.push(format!("relay log: {l}"));
        }
    }
    if relay.exited().is_none() {
        if let Err(e) = relay.stop() {
            last.ok = false;
            last.lines.push(e);
        }
    }
    verdicts.push(last);
    Ok(verdicts)
}
