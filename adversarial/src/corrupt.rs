//! On-disk damage. A store is built by the crash torture's workload (in one
//! process, no crashes, closed cleanly or not), then one of its files is
//! damaged (a flipped bit, a zeroed or garbled stretch, a cut) and a fresh
//! process opens it and reads everything. Allowed: refusing to open with an
//! error that says what is wrong, or opening without what the damage
//! destroyed (counted as loss). Not allowed: a panic or crash, a hang, or a
//! wrong answer: a record that is not what was stored, a removed event back,
//! a query result that is not live or does not match, an id that looks up to
//! another event.

use crate::rng::{mix, Rng};
use crate::torture::child::{Shape, NOW};
use crate::torture::model::{parse_filter, Model};
use crate::torture::{all_shapes, work};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Cfg {
    pub root: PathBuf,
    pub seed: u64,
    pub cases: u64,
    /// Damaged copies per built store.
    pub per_store: u64,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub stores: u64,
    pub cases: u64,
    /// Outcome class -> count, per damaged file kind.
    pub outcomes: BTreeMap<String, u64>,
    /// Cases that broke the rules: (damage, outcome).
    pub findings: Vec<(String, String)>,
}

/// The files of a store worth damaging, by kind.
fn files(dir: &Path) -> Vec<(&'static str, PathBuf)> {
    let mut v = Vec::new();
    let mut add = |kind: &'static str, d: PathBuf, ext: &str| {
        if let Ok(rd) = std::fs::read_dir(&d) {
            let mut ps: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == ext)).collect();
            ps.sort();
            v.extend(ps.into_iter().map(|p| (kind, p)));
        }
    };
    add("log", dir.join("log"), "log");
    add("cold", dir.join("log").join("cold"), "log");
    add("index", dir.join("idx"), "seg");
    for (kind, name) in [("locs", "locs"), ("dead.bits", "dead.bits"), ("checkpoint", "checkpoint"), ("meta", "meta")] {
        if dir.join(name).exists() {
            v.push((kind, dir.join(name)));
        }
    }
    v
}

/// How much of a file holds data: up to its last non-zero byte.
fn used(path: &Path) -> u64 {
    let Ok(b) = std::fs::read(path) else { return 0 };
    b.iter().rposition(|&x| x != 0).map_or(0, |p| p as u64 + 1)
}

/// Damages one file of `dir`; says what it did.
fn damage(dir: &Path, rng: &mut Rng) -> Option<(String, String)> {
    use std::os::unix::fs::FileExt;
    let fs = files(dir);
    if fs.is_empty() {
        return None;
    }
    // The log and locs hold most of the data, so most of the damage.
    let weights: Vec<u64> = fs.iter().map(|(k, _)| match *k {
        "log" | "cold" => 6,
        "locs" | "index" => 3,
        _ => 1,
    }).collect();
    let total: u64 = weights.iter().sum();
    let mut pick = rng.below(total);
    let i = weights.iter().position(|&w| {
        if pick < w {
            true
        } else {
            pick -= w;
            false
        }
    })?;
    let (kind, path) = &fs[i];
    let n = used(path);
    if n == 0 {
        return None;
    }
    let f = std::fs::OpenOptions::new().read(true).write(true).open(path).ok()?;
    let name = path.strip_prefix(dir).unwrap_or(path).display().to_string();
    let what = match rng.below(5) {
        0 | 1 => {
            let off = rng.below(n);
            let bit = rng.below(8) as u8;
            let mut b = [0u8];
            f.read_exact_at(&mut b, off).ok()?;
            b[0] ^= 1 << bit;
            f.write_all_at(&b, off).ok()?;
            format!("flipped bit {bit} of byte {off} of {name}")
        }
        2 => {
            let off = rng.below(n);
            let len = 1 + rng.below(64);
            f.write_all_at(&vec![0u8; len as usize], off).ok()?;
            format!("zeroed {len} bytes at {off} of {name}")
        }
        3 => {
            let off = rng.below(n) / 4096 * 4096;
            let mut r = rng.clone();
            let junk: Vec<u8> = (0..4096).map(|_| r.next_u64() as u8).collect();
            f.write_all_at(&junk, off).ok()?;
            format!("garbled the 4 KiB page at {off} of {name}")
        }
        _ => {
            let len = rng.below(n);
            f.set_len(len).ok()?;
            format!("cut {name} to {len} bytes (of {n} used)")
        }
    };
    Some((kind.to_string(), what))
}

/// Builds the store for one batch of cases: (epoch seed, shape, ops).
fn build(dir: &Path, k: u64, seed: u64) -> Result<(u64, Shape, u64), String> {
    let eseed = mix(seed ^ mix(k + 1));
    let mut r = Rng::new(eseed);
    let shapes = all_shapes();
    let shape = *r.pick(&shapes);
    let ops = 120 + r.below(300);
    crate::torture::replay_model(dir, eseed, shape, ops, 0, 0)?;
    Ok((eseed, shape, ops))
}

fn copy_dir(from: &Path, to: &Path) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(to);
    let flags: &[&str] = if cfg!(target_os = "macos") { &["-cR"] } else { &["-R", "--sparse=always"] };
    let st = Command::new("cp").args(flags).arg(from).arg(to).status().map_err(|e| e.to_string())?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("cp {} failed", from.display()))
    }
}

pub fn run(cfg: &Cfg) -> Result<Stats, String> {
    let mut st = Stats::default();
    let mut rng = Rng::new(cfg.seed ^ 0xC0FF);
    std::fs::create_dir_all(&cfg.root).map_err(|e| e.to_string())?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let base = cfg.root.join("base");
    let mut k = 0;
    while st.cases < cfg.cases {
        let (eseed, shape, ops) = build(&base, k, cfg.seed)?;
        st.stores += 1;
        k += 1;
        for _ in 0..cfg.per_store {
            if st.cases >= cfg.cases {
                break;
            }
            let case = cfg.root.join("case");
            copy_dir(&base, &case)?;
            let Some((kind, what)) = damage(&case, &mut rng) else { continue };
            st.cases += 1;
            let mut child = Command::new(&exe)
                .args(["corrupt-check", "--dir"])
                .arg(&case)
                .args(["--seed", &eseed.to_string(), "--shape", &shape.encode(), "--ops", &ops.to_string()])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| e.to_string())?;
            let t = Instant::now();
            let status = loop {
                if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
                    break Some(s);
                }
                if t.elapsed() > Duration::from_secs(60) {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            let mut out = String::new();
            if let Some(mut so) = child.stdout.take() {
                use std::io::Read;
                let _ = so.read_to_string(&mut out);
            }
            let line = out.lines().find(|l| l.starts_with("RESULT ")).unwrap_or("").trim_start_matches("RESULT ").to_string();
            let class = match (&status, line.split_whitespace().next()) {
                (None, _) => "hang".to_string(),
                (_, Some(c)) => c.to_string(),
                (Some(s), None) => format!("crash ({s})"),
            };
            *st.outcomes.entry(format!("{kind}: {class}")).or_default() += 1;
            if !matches!(class.as_str(), "ok" | "loss" | "refused") {
                let keep = cfg.root.join(format!("finding-{}", st.findings.len()));
                let _ = std::fs::rename(&case, &keep);
                st.findings.push((format!("{what} (store seed {eseed:#x}, shape {}, {ops} ops; kept in {})", shape.encode(), keep.display()), line.clone()));
                eprintln!("FINDING: {what}: {line}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(cfg.root.join("case"));
    Ok(st)
}

/// The checking side, in its own process: prints one `RESULT <class> ...`
/// line, class `refused`, `ok`, `loss`, `wrong` or `panic`.
pub fn check(dir: &Path, eseed: u64, shape: Shape, ops: u64) -> ! {
    std::panic::set_hook(Box::new(|info| {
        let bt = std::backtrace::Backtrace::force_capture().to_string();
        let at: Vec<&str> = bt.lines().map(str::trim).filter(|l| l.starts_with("at ") && l.contains("relay-")).take(4).collect();
        println!("RESULT panic {} | {}", info.to_string().replace('\n', " | "), at.join(" < "));
        std::process::exit(3);
    }));
    // The model of what was stored, and of the open's expiry sweep.
    let mut m = Model::new(eseed);
    for i in 0..ops {
        let op = work::op(eseed, i);
        if !matches!(op, work::Op::Restart) {
            m.apply_op(&op, NOW);
        }
    }
    m.sweep(work::PAST);
    let (store, w) = match relay_store::Store::open(dir, shape.options()) {
        Ok(x) => x,
        Err(e) => {
            println!("RESULT refused {e}");
            std::process::exit(0);
        }
    };
    let v = store.snapshot();
    // Records as the store keeps them: base64 content decoded (`record::compact_into`).
    let kept = |rec: &[u8]| {
        let mut out = Vec::new();
        relay_proto::record::compact_into(rec, &mut out);
        out
    };
    let mut wrong: Vec<String> = Vec::new();
    let mut lost = 0u64;
    for s in &m.slots {
        let live = v.is_live(s.seq);
        // A live seq whose record the store will not read (damaged) is lost.
        let rec = if live { v.record(s.seq).map(|r| r.0.to_vec()) } else { None };
        if let Some(rec) = rec {
            if !s.alive {
                wrong.push(format!("seq {} (removed) is live again", s.seq));
            } else if rec != kept(&s.rec) {
                wrong.push(format!("seq {} reads as other bytes", s.seq));
            }
        } else if s.alive {
            lost += 1;
        }
    }
    for seq in m.next_seq()..v.count {
        if v.record(seq).is_some() {
            wrong.push(format!("seq {seq} is live but was never stored"));
        }
    }
    // Lookups and queries answer only with what was stored, live, matching.
    for s in m.live_seqs().take(400) {
        if let Some(q) = v.lookup_id(&s.ev.id) {
            if v.record(q).is_some_and(|r| r.id() != &s.ev.id) {
                wrong.push(format!("the id of seq {} looks up to seq {q}, another record", s.seq));
            }
        }
    }
    let mut rng = Rng::new(eseed ^ 0xF1);
    for _ in 0..30 {
        let f = parse_filter(&work::filter_json(eseed, &mut rng));
        for h in v.query(&f, 500, NOW) {
            let ok = m.slots.get(h.seq as usize).is_some_and(|s| s.alive && v.record(h.seq).is_some_and(|r| r.0 == kept(&s.rec).as_slice() && f.matches(r)));
            if !ok {
                wrong.push(format!("a query returned seq {}, which is not a live stored event matching it", h.seq));
                break;
            }
        }
        let _ = v.count(&f, NOW);
    }
    drop(v);
    drop((store, w));
    if !wrong.is_empty() {
        wrong.sort();
        wrong.dedup();
        println!("RESULT wrong {} problems: {}", wrong.len(), wrong.iter().take(4).cloned().collect::<Vec<_>>().join("; "));
    } else if lost > 0 {
        println!("RESULT loss {lost} events");
    } else {
        println!("RESULT ok");
    }
    std::process::exit(0);
}
