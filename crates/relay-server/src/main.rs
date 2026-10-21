//! The relay binary.

mod brand;
mod config;
mod export;
mod import;
mod ingest;
mod metrics;
mod reactor;
mod serve;
mod session;
mod stats;
mod subs;
mod toml;

use config::{store_options, Config};
use relay_store::{Options, Store};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

const USAGE: &str = "\
usage: {bin} [--config FILE] [--data DIR] <command> [options]

commands:
  serve                run the relay (the default when no command is given)
  init [FILE]          write a fully commented settings file (default: ./relay.toml);
                       never overwrites an existing file
  import <file|->      load a JSONL export (strfry format), verifying every event
      --no-verify      skip id and signature checks (trusted input only)
      --relaxed        do not sync per batch (one sync at the end)
  export [--since T] [--until T]
                       write every live event as JSONL to stdout
  stats                print store statistics

  --config FILE        settings file (default: ./relay.toml if it exists; every
                       setting is optional, see `{bin} init`)
  --data DIR           data directory (default: [store] data, else ./data)
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}: {e}", brand::SLUG);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut data: Option<PathBuf> = None;
    if let Some(i) = args.iter().position(|a| a == "--data") {
        data = Some(PathBuf::from(args.get(i + 1).ok_or("--data needs a directory")?));
        args.drain(i..i + 2);
    }
    let mut config_path: Option<PathBuf> = None;
    if let Some(i) = args.iter().position(|a| a == "--config") {
        config_path = Some(PathBuf::from(args.get(i + 1).ok_or("--config needs a file")?));
        args.drain(i..i + 2);
    }
    // Settings are read only by the commands that need them, so `help` and `init`
    // work even when relay.toml is broken. `--data` beats `[store] data`.
    let load = || -> Result<Config, String> {
        let mut cfg = Config::load(config_path.as_deref()).map_err(|e| e.to_string())?;
        if let Some(d) = &data {
            cfg.store.data.clone_from(d);
        }
        Ok(cfg)
    };
    let flag = |args: &mut Vec<String>, name: &str| -> bool {
        if let Some(i) = args.iter().position(|a| a == name) {
            args.remove(i);
            true
        } else {
            false
        }
    };
    let value = |args: &mut Vec<String>, name: &str| -> Result<Option<u64>, String> {
        match args.iter().position(|a| a == name) {
            Some(i) => {
                let v = args.get(i + 1).ok_or(format!("{name} needs a value"))?.parse().map_err(|_| format!("{name}: not a number"))?;
                args.drain(i..i + 2);
                Ok(Some(v))
            }
            None => Ok(None),
        }
    };

    let cmd = if args.is_empty() { String::from("serve") } else { args.remove(0) };
    match cmd.as_str() {
        "serve" => serve::run(load()?),
        "init" => {
            let target = args.first().map(PathBuf::from).or_else(|| config_path.clone()).unwrap_or_else(|| PathBuf::from(config::DEFAULT_FILE));
            init(&target)
        }
        "import" => {
            let verify = !flag(&mut args, "--no-verify");
            let relaxed = flag(&mut args, "--relaxed");
            let path = args.first().ok_or("import needs a file (or - for stdin)")?.clone();
            let cfg = load()?;
            let opts = Options { sync: cfg.store.sync && !relaxed, ..store_options(&cfg) };
            let (_store, mut w) = Store::open(&cfg.store.data, opts).map_err(|e| e.to_string())?;
            let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
            let opts = import::ImportOptions { verify, skip_kind: None, threads };
            let t = Instant::now();
            let report = |s: &import::ImportStats| {
                let secs = t.elapsed().as_secs_f64();
                eprintln!("  {} lines, {} stored, {:.0} lines/s", s.lines, s.stored, s.lines as f64 / secs);
            };
            let stats = if path == "-" {
                import::run(std::io::stdin(), &mut w, opts, report)
            } else {
                let f = std::fs::File::open(&path).map_err(|e| format!("{path}: {e}"))?;
                import::run(f, &mut w, opts, report)
            }
            .map_err(|e| e.to_string())?;
            let secs = t.elapsed().as_secs_f64();
            // One segment means one probe per lookup: worth doing once after a bulk load.
            let tc = Instant::now();
            w.compact_all().map_err(|e| e.to_string())?;
            eprintln!("index flushed and compacted into {} segment(s) in {:.2}s", w.segment_count(), tc.elapsed().as_secs_f64());
            eprintln!(
                "imported {} lines ({:.1} MB) in {:.2}s: {:.0} lines/s, {:.1} MB/s",
                stats.lines,
                stats.bytes as f64 / 1e6,
                secs,
                stats.lines as f64 / secs,
                stats.bytes as f64 / 1e6 / secs
            );
            eprintln!(
                "  stored {}, duplicate {}, superseded {}, deleted {}, ephemeral skipped {}, kind skipped {}",
                stats.stored, stats.duplicate, stats.superseded, stats.deleted, stats.ephemeral, stats.skipped_kind
            );
            let mut inv: Vec<_> = stats.invalid.into_iter().collect();
            inv.sort_by_key(|e| std::cmp::Reverse(e.1));
            for (reason, n) in inv {
                eprintln!("  invalid ({reason}): {n}");
            }
            Ok(())
        }
        "export" => {
            let since = value(&mut args, "--since")?;
            let until = value(&mut args, "--until")?;
            let cfg = load()?;
            let (store, _w) = Store::open(&cfg.store.data, store_options(&cfg)).map_err(|e| e.to_string())?;
            let v = store.snapshot();
            let stdout = std::io::stdout();
            let mut out = std::io::BufWriter::with_capacity(1 << 20, stdout.lock());
            let n = export::run(&v, &mut out, since, until).map_err(|e| e.to_string())?;
            eprintln!("exported {n} events");
            Ok(())
        }
        "stats" => {
            let cfg = load()?;
            let t = Instant::now();
            let (store, w) = Store::open(&cfg.store.data, store_options(&cfg)).map_err(|e| e.to_string())?;
            let v = store.snapshot();
            println!("opened in {:.2}s", t.elapsed().as_secs_f64());
            println!("events (seqs): {}", w.next_seq());
            println!("dead: {}", v.dead_count());
            println!("index keys: {} ({:.1} MB in memory, {:.1} MB in {} segment files)", v.index_keys(), v.index_bytes() as f64 / 1e6, v.segment_bytes() as f64 / 1e6, w.segment_count());
            Ok(())
        }
        "help" | "--help" | "-h" => {
            print!("{} {}\n\n{}", brand::NAME, brand::VERSION, USAGE.replace("{bin}", brand::SLUG));
            Ok(())
        }
        other => Err(format!("unknown command {other:?}; try --help")),
    }
}

/// `init`: writes the commented settings file. `create_new` makes the refusal to
/// overwrite atomic, so a hand-edited relay.toml can never be clobbered.
fn init(target: &Path) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(target).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => format!("{} already exists; not overwriting it (delete it first, or name another file)", target.display()),
        _ => format!("{}: {e}", target.display()),
    })?;
    f.write_all(config::default_config_text().as_bytes()).map_err(|e| format!("{}: {e}", target.display()))?;
    eprintln!("wrote {}: every setting is there, commented out at its default. Delete the \"# \" before a line to change it.", target.display());
    Ok(())
}
