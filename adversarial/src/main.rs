//! `adv`: the adversarial suite's command line. See docs/ADVERSARIAL.md.

use relay_adversarial::{fuzz, targets};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[global_allocator]
static ALLOC: relay_adversarial::alloc::Counting = relay_adversarial::alloc::Counting;

const USAGE: &str = "\
usage: adv <command> [options]

  fuzz [--target NAME|all] [--iters N] [--secs S] [--seed S] [--out DIR]
                       mutational fuzzing of the parsers (stable, deterministic)
  replay TARGET FILE...
                       run saved inputs through a target (regressions, findings)
  minimize TARGET FILE shrink a failing input; writes FILE.min
  targets              list the fuzz targets
  torture --dir DIR [--iterations N] [--seed S] [--max-kill-ms MS] [--epoch-ops N]
          [--no-crash-points] [--no-readers] [--queries N]
                       SIGKILL a writer child at random moments and crash points,
                       reopen, check against the model of acknowledged writes
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("adv: {e}");
            ExitCode::from(2)
        }
    }
}

/// `--name value` from `args`, removed.
fn opt(args: &mut Vec<String>, name: &str) -> Result<Option<String>, String> {
    match args.iter().position(|a| a == name) {
        Some(i) => {
            let v = args.get(i + 1).ok_or(format!("{name} needs a value"))?.clone();
            args.drain(i..i + 2);
            Ok(Some(v))
        }
        None => Ok(None),
    }
}

fn num(args: &mut Vec<String>, name: &str) -> Result<Option<u64>, String> {
    opt(args, name)?.map(|v| v.parse().map_err(|_| format!("{name}: not a number"))).transpose()
}

fn run(mut args: Vec<String>) -> Result<bool, String> {
    if args.is_empty() {
        print!("{USAGE}");
        return Ok(true);
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "targets" => {
            for t in targets::all() {
                println!("{}", t.name);
            }
            Ok(true)
        }
        "fuzz" => {
            let which = opt(&mut args, "--target")?.unwrap_or_else(|| "all".into());
            let iters = num(&mut args, "--iters")?.unwrap_or(u64::MAX);
            let secs = num(&mut args, "--secs")?;
            let seed = num(&mut args, "--seed")?.unwrap_or(1);
            let out = PathBuf::from(opt(&mut args, "--out")?.unwrap_or_else(|| "fuzz-out".into()));
            let slow = Duration::from_millis(num(&mut args, "--slow-ms")?.unwrap_or(2000));
            if iters == u64::MAX && secs.is_none() {
                return Err("give --iters or --secs".into());
            }
            fuzz::start_watchdog(Duration::from_secs(30));
            let list: Vec<targets::Target> = if which == "all" { targets::all() } else { which.split(',').map(|n| targets::find(n).ok_or(format!("no target {n:?}"))).collect::<Result<_, _>>()? };
            let per = secs.map(|s| (s / list.len() as u64).max(1));
            let mut ok = true;
            for t in &list {
                let o = fuzz::Opts { iters, secs: per, seed, out: out.clone(), slow, corpus_cap: 4096, quiet: false };
                let r = fuzz::campaign(t, &o);
                println!(
                    "{:18} {:>10} runs  {:>5} fingerprints  corpus {:>5}  peak heap {:>9} B  slowest {:>8.2?}  findings {}",
                    t.name,
                    r.runs,
                    r.fingerprints,
                    r.corpus,
                    r.max_peak,
                    r.max_time,
                    r.findings.len()
                );
                for f in &r.findings {
                    let d: String = f.detail.lines().take(4).collect::<Vec<_>>().join(" | ").chars().take(400).collect();
                    println!("    {:?}: {d}", f.kind);
                }
                ok &= r.findings.is_empty();
            }
            Ok(ok)
        }
        "replay" => {
            let name = args.first().ok_or("replay needs a target")?.clone();
            let t = targets::find(&name).ok_or(format!("no target {name:?}"))?;
            fuzz::install_panic_hook();
            let mut ok = true;
            let mut files: Vec<PathBuf> = Vec::new();
            for a in &args[1..] {
                let p = PathBuf::from(a);
                if p.is_dir() {
                    let mut v: Vec<PathBuf> = std::fs::read_dir(&p).map_err(|e| e.to_string())?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "bin")).collect();
                    v.sort();
                    files.extend(v);
                } else {
                    files.push(p);
                }
            }
            for f in files {
                let data = std::fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
                match fuzz::run_one(&t, &data, Duration::from_secs(10)) {
                    Ok((_, peak, took)) => println!("ok    {} ({} B, peak {peak} B, {took:.2?})", f.display(), data.len()),
                    Err(e) => {
                        ok = false;
                        println!("FAIL  {} {:?}: {}", f.display(), e.kind, e.detail);
                    }
                }
            }
            Ok(ok)
        }
        "minimize" => {
            let name = args.first().ok_or("minimize needs a target")?.clone();
            let file = PathBuf::from(args.get(1).ok_or("minimize needs a file")?);
            let t = targets::find(&name).ok_or(format!("no target {name:?}"))?;
            let data = std::fs::read(&file).map_err(|e| e.to_string())?;
            let min = fuzz::minimize(&t, &data, Duration::from_secs(10));
            let out = file.with_extension("min");
            std::fs::write(&out, &min).map_err(|e| e.to_string())?;
            println!("{} -> {} bytes: {}", data.len(), min.len(), out.display());
            println!("{:?}", String::from_utf8_lossy(&min));
            Ok(true)
        }
        "torture" => {
            let root = PathBuf::from(opt(&mut args, "--dir")?.ok_or("torture needs --dir")?);
            let flag = |args: &mut Vec<String>, n: &str| match args.iter().position(|a| a == n) {
                Some(i) => {
                    args.remove(i);
                    true
                }
                None => false,
            };
            let cfg = relay_adversarial::torture::Cfg {
                seed: num(&mut args, "--seed")?.unwrap_or(1),
                iterations: num(&mut args, "--iterations")?.unwrap_or(200),
                max_kill_ms: num(&mut args, "--max-kill-ms")?.unwrap_or(400),
                epoch_ops: num(&mut args, "--epoch-ops")?.unwrap_or(600),
                queries: num(&mut args, "--queries")?.unwrap_or(24) as usize,
                crash_points: !flag(&mut args, "--no-crash-points"),
                readers: !flag(&mut args, "--no-readers"),
                verbose: flag(&mut args, "--verbose"),
                root,
            };
            let t = std::time::Instant::now();
            match relay_adversarial::torture::run(&cfg) {
                Ok(st) => {
                    println!("torture passed in {:.1?}: {st:#?}", t.elapsed());
                    Ok(true)
                }
                Err(e) => {
                    println!("TORTURE FAILURE: {e}");
                    Ok(false)
                }
            }
        }
        "torture-replay" => {
            let dir = PathBuf::from(opt(&mut args, "--dir")?.ok_or("--dir")?);
            let seed = num(&mut args, "--seed")?.unwrap_or(1);
            let ops = num(&mut args, "--ops")?.unwrap_or(2000);
            let every = num(&mut args, "--check-every")?.unwrap_or(10);
            let shapes: Vec<relay_adversarial::torture::child::Shape> = match opt(&mut args, "--shape")? {
                Some(s) => vec![relay_adversarial::torture::child::Shape::decode(&s).ok_or("bad --shape")?],
                None => relay_adversarial::torture::all_shapes(),
            };
            fuzz::install_panic_hook();
            let mut ok = true;
            for shape in shapes {
                match relay_adversarial::torture::replay(&dir, seed, shape, ops, every, 16) {
                    Ok(q) => println!("replay ok: seed {seed} shape {} ops {ops} ({q} queries checked)", shape.encode()),
                    Err(e) => {
                        println!("REPLAY FAILURE: {e}");
                        ok = false;
                    }
                }
            }
            Ok(ok)
        }
        "hostile" => {
            use relay_adversarial::hostile;
            let bin = opt(&mut args, "--bin")?.map(PathBuf::from).unwrap_or_else(hostile::relay::default_binary);
            let cfg = hostile::Cfg {
                dir: PathBuf::from(opt(&mut args, "--dir")?.ok_or("hostile needs --dir")?),
                seed: num(&mut args, "--seed")?.unwrap_or(1),
                secs: opt(&mut args, "--secs")?.map(|s| s.parse().map_err(|_| "--secs: not a number")).transpose()?.unwrap_or(10.0),
                threads: num(&mut args, "--threads")?.unwrap_or(4) as usize,
                prefill: num(&mut args, "--prefill")?.unwrap_or(20_000) as usize,
                scenarios: opt(&mut args, "--scenario")?.map(|s| s.split(',').map(String::from).collect()).unwrap_or_default(),
                latency: Duration::from_millis(num(&mut args, "--latency-ms")?.unwrap_or(500)),
                silent: num(&mut args, "--silent")?.unwrap_or(2000) as usize,
                noread: num(&mut args, "--noread")?.unwrap_or(8),
                bigreq: num(&mut args, "--bigreq")?.unwrap_or(8),
                neg_conns: num(&mut args, "--neg-conns")?.unwrap_or(16),
                bin,
            };
            let verdicts = hostile::run(&cfg)?;
            let mut ok = true;
            for v in &verdicts {
                println!("{} {}", if v.ok { "PASS" } else { "FAIL" }, v.name);
                for l in &v.lines {
                    println!("    {l}");
                }
                ok &= v.ok;
            }
            Ok(ok)
        }
        "open" => {
            // Opens a store as the torture does (for a failure left on disk).
            let dir = PathBuf::from(opt(&mut args, "--dir")?.ok_or("--dir")?);
            let shape = relay_adversarial::torture::child::Shape::decode(&opt(&mut args, "--shape")?.ok_or("--shape")?).ok_or("bad --shape")?;
            println!("{}", relay_adversarial::torture::describe_dir(&dir));
            match relay_store::Store::open(&dir, shape.options()) {
                Ok((s, w)) => {
                    println!("opened: next_seq {}, {} dead", w.next_seq(), s.snapshot().dead_count());
                    Ok(true)
                }
                Err(e) => {
                    println!("open failed: {e}");
                    Ok(false)
                }
            }
        }
        "torture-child" => {
            let dir = PathBuf::from(opt(&mut args, "--dir")?.ok_or("--dir")?);
            let seed = num(&mut args, "--seed")?.ok_or("--seed")?;
            let start = num(&mut args, "--start")?.ok_or("--start")?;
            let shape = relay_adversarial::torture::child::Shape::decode(&opt(&mut args, "--shape")?.ok_or("--shape")?).ok_or("bad --shape")?;
            let faults = num(&mut args, "--fault-budget")?;
            let readers = args.iter().any(|a| a == "--readers");
            relay_adversarial::torture::child::run(&dir, seed, start, shape, faults, readers)
        }
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(true)
        }
        other => Err(format!("unknown command {other:?}")),
    }
}
