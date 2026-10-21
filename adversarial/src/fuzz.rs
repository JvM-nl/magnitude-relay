//! The stable fuzz runner: mutational, deterministic from a seed, no coverage
//! instrumentation (that is the box's job, under libFuzzer). Every input runs
//! under a memory budget (the counting allocator) and a time budget; a panic,
//! a budget overrun or a hang is a finding, saved with the input that caused it.

use crate::alloc;
use crate::mutate::Mutator;
use crate::rng::Rng;
use crate::targets::{fp_str, Target};
use std::collections::{HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub struct Opts {
    pub iters: u64,
    pub secs: Option<u64>,
    pub seed: u64,
    /// Findings and the grown corpus go under `<out>/<target>/`.
    pub out: PathBuf,
    /// An input taking longer than this is a finding.
    pub slow: Duration,
    pub corpus_cap: usize,
    pub quiet: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Kind {
    Panic,
    Memory,
    Slow,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: Kind,
    pub detail: String,
    pub input: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Report {
    pub runs: u64,
    pub fingerprints: usize,
    pub corpus: usize,
    pub findings: Vec<Finding>,
    pub max_peak: usize,
    pub max_time: Duration,
}

/// What the input being run is, for the hang watchdog to save if it never returns.
struct Current {
    target: &'static str,
    since: Instant,
    input: Vec<u8>,
    out: PathBuf,
    active: bool,
}

fn current() -> &'static Mutex<Option<Current>> {
    static C: OnceLock<Mutex<Option<Current>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

static LAST_PANIC: Mutex<String> = Mutex::new(String::new());

/// Panics are captured (message and location), not printed: the runner reports them.
pub fn install_panic_hook() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        std::panic::set_hook(Box::new(|info| {
            *LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()) = info.to_string();
        }));
    });
}

/// Saves the input of a run that has not returned after `hang` and exits: a
/// hang cannot be interrupted in-process, only reported.
pub fn start_watchdog(hang: Duration) {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(200));
            let g = current().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(c) = g.as_ref() {
                if c.active && c.since.elapsed() > hang {
                    let p = save(&c.out, c.target, "hang", &c.input, &format!("no return after {hang:?}"));
                    eprintln!("HANG in target {}: input saved to {}", c.target, p.display());
                    std::process::exit(3);
                }
            }
        });
    });
}

fn hash(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &x| (h ^ u64::from(x)).wrapping_mul(0x100_0000_01b3))
}

fn save(out: &Path, target: &str, kind: &str, input: &[u8], detail: &str) -> PathBuf {
    let dir = out.join(target);
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join(format!("{kind}-{:016x}.bin", hash(input)));
    let _ = std::fs::write(&p, input);
    let _ = std::fs::write(p.with_extension("txt"), detail);
    p
}

/// Runs one input with every check. `Ok` carries the target's fingerprint.
pub fn run_one(t: &Target, input: &[u8], slow: Duration) -> Result<(u64, usize, Duration), Finding> {
    let base = alloc::live();
    alloc::reset();
    let started = Instant::now();
    let r = std::panic::catch_unwind(AssertUnwindSafe(|| (t.run)(input)));
    let took = started.elapsed();
    let peak = alloc::peak_since(base);
    match r {
        Err(_) => {
            let msg = LAST_PANIC.lock().unwrap_or_else(|e| e.into_inner()).clone();
            Err(Finding { kind: Kind::Panic, detail: msg, input: input.to_vec() })
        }
        Ok(f) => {
            let cap = (t.mem_cap)(input.len());
            if peak > cap {
                return Err(Finding {
                    kind: Kind::Memory,
                    detail: format!("peak heap {peak} bytes (largest allocation {}) for a {}-byte input; budget {cap}", alloc::largest(), input.len()),
                    input: input.to_vec(),
                });
            }
            if took > slow {
                return Err(Finding { kind: Kind::Slow, detail: format!("{took:?} for a {}-byte input", input.len()), input: input.to_vec() });
            }
            Ok((f, peak, took))
        }
    }
}

/// The first line of a finding, without the varying parts, to tell findings apart.
fn signature(f: &Finding) -> String {
    let first = f.detail.lines().next().unwrap_or("");
    // Panic messages begin "panicked at file:line:col:"; the location is the identity.
    let sig = match first.split_once(":\n") {
        Some((loc, _)) => loc.to_string(),
        None => first.chars().take(120).collect(),
    };
    format!("{:?} {}", f.kind, sig)
}

fn load_dir(dir: &Path) -> Vec<Vec<u8>> {
    let mut v: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
        .filter_map(|e| Some((e.path(), std::fs::read(e.path()).ok()?)))
        .collect();
    v.sort();
    v.into_iter().map(|x| x.1).collect()
}

pub fn campaign(t: &Target, o: &Opts) -> Report {
    install_panic_hook();
    let mut rng = Rng::new(o.seed ^ fp_str(t.name));
    let m = Mutator::new(t.max_len, t.dict);
    let corpus_dir = o.out.join(t.name).join("corpus");
    let mut corpus: Vec<Vec<u8>> = (t.seeds)();
    corpus.extend(load_dir(&corpus_dir));
    let mut seen: HashSet<u64> = HashSet::new();
    let mut found: HashMap<String, Finding> = HashMap::new();
    let mut rep = Report::default();
    let deadline = o.secs.map(|s| Instant::now() + Duration::from_secs(s));
    let started = Instant::now();
    let mut last_print = Instant::now();
    let initial = corpus.len();
    let mut i = 0u64;
    loop {
        if i >= o.iters || deadline.is_some_and(|d| Instant::now() >= d) {
            break;
        }
        let input = if (i as usize) < initial {
            corpus[i as usize].clone()
        } else if corpus.is_empty() || rng.chance(1, 4) {
            let mut g = (t.generate)(&mut rng);
            g.truncate(t.max_len);
            g
        } else {
            let a = rng.usize(corpus.len());
            let b = rng.usize(corpus.len());
            m.mutate(&mut rng, &corpus[a], &corpus[b])
        };
        {
            let mut g = current().lock().unwrap_or_else(|e| e.into_inner());
            *g = Some(Current { target: t.name, since: Instant::now(), input: input.clone(), out: o.out.clone(), active: true });
        }
        let r = run_one(t, &input, o.slow);
        if let Some(c) = current().lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
            c.active = false;
        }
        rep.runs += 1;
        match r {
            Ok((f, peak, took)) => {
                rep.max_peak = rep.max_peak.max(peak);
                rep.max_time = rep.max_time.max(took);
                if seen.insert(f) && (i as usize) >= initial {
                    if corpus.len() < o.corpus_cap {
                        corpus.push(input);
                    } else {
                        let j = rng.usize(corpus.len());
                        corpus[j] = input;
                    }
                }
            }
            Err(f) => {
                let sig = signature(&f);
                let keep = match found.get(&sig) {
                    Some(old) => f.input.len() < old.input.len(),
                    None => true,
                };
                if keep {
                    if !found.contains_key(&sig) && !o.quiet {
                        let d: String = f.detail.lines().take(3).collect::<Vec<_>>().join(" | ").chars().take(300).collect();
                        eprintln!("  [{}] FINDING {:?}: {d}", t.name, f.kind);
                    }
                    found.insert(sig, f);
                }
            }
        }
        i += 1;
        if !o.quiet && last_print.elapsed() > Duration::from_secs(30) {
            eprintln!("  [{}] {} runs, {} fingerprints, corpus {}, {:.0} runs/s", t.name, rep.runs, seen.len(), corpus.len(), rep.runs as f64 / started.elapsed().as_secs_f64());
            last_print = Instant::now();
        }
    }
    // Keep what was learned for the next campaign (bounded).
    let _ = std::fs::create_dir_all(&corpus_dir);
    for c in corpus.iter().skip(initial).take(o.corpus_cap) {
        let _ = std::fs::write(corpus_dir.join(format!("{:016x}.bin", hash(c))), c);
    }
    for f in found.values() {
        let kind = match f.kind {
            Kind::Panic => "panic",
            Kind::Memory => "memory",
            Kind::Slow => "slow",
        };
        save(&o.out, t.name, kind, &f.input, &f.detail);
    }
    rep.fingerprints = seen.len();
    rep.corpus = corpus.len();
    rep.findings = found.into_values().collect();
    rep
}

/// Shrinks a failing input while it still fails with the same signature.
pub fn minimize(t: &Target, input: &[u8], slow: Duration) -> Vec<u8> {
    install_panic_hook();
    let Err(f0) = run_one(t, input, slow) else { return input.to_vec() };
    let sig = signature(&f0);
    let fails = |b: &[u8]| matches!(run_one(t, b, slow), Err(f) if signature(&f) == sig);
    let mut cur = input.to_vec();
    let mut chunk = cur.len() / 2;
    while chunk >= 1 {
        let mut i = 0;
        let mut progress = false;
        while i < cur.len() {
            let mut cand = cur.clone();
            cand.drain(i..(i + chunk).min(cur.len()));
            if fails(&cand) {
                cur = cand;
                progress = true;
            } else {
                i += chunk;
            }
        }
        if !progress {
            chunk /= 2;
        }
    }
    cur
}
