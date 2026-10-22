//! The relay binary.

mod admin;
mod brand;
mod config;
mod ephemeral;
mod export;
mod health;
mod import;
mod inbound;
mod ingest;
mod landing;
mod metrics;
mod operator;
mod reactor;
mod serve;
mod session;
mod sock;
mod stats;
mod subs;
mod sync;
mod toml;
mod verify;

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
  import <file|->      load a JSONL export (strfry format), verifying every event;
                       kinds the policy refuses are skipped
      --no-verify      skip id and signature checks (trusted input only)
      --relaxed        do not sync per batch (one sync at the end)
  export [--since T] [--until T]
                       write every live event as JSONL to stdout
  stats                print store statistics
  cert                 print the HTTPS certificate's names and when it expires
  backup <DIR> [--no-verify]
                       copy the store into DIR (which must not exist) as it is
                       at this moment, while the relay keeps serving; then open
                       the copy and check a spread of its events. The copy is a
                       data directory: to restore or move, start a relay on it
  query --filter JSON [--limit N]
                       print matching events as JSONL, newest first
  count --filter JSON  print how many events match
  delete --filter JSON [--age SECS] [--all] (--dry-run | --yes)
                       remove matching events. --dry-run prints how many would
                       go, with a few samples, and changes nothing; --yes does
                       it. This is not a NIP-09 deletion: nothing is kept to
                       block it, so a deleted event can be published again
      --age SECS       only events created more than SECS seconds ago
      --all            allow a filter with no conditions, which matches every
                       event ({})
  sync <url> [--filter JSON] [--dir down|up|both] [--dry-run] [--trusted]
                       compare this relay's events with another relay's (ws://
                       or wss://, NIP-77) and copy what one side lacks: down
                       (theirs to here, the default), up (ours to there) or
                       both. Events copied here are checked like any app's:
                       signatures, accepted kinds, deletions. --filter
                       defaults to {} (everything); --dry-run only counts what
                       differs. --trusted: the other relay is one of yours
                       that lists this one as a [[peer]] (see `trusted` under
                       [[sync]]). For a lasting sync, see [[sync]] in the
                       settings file

  --filter takes one NIP-01 filter or a JSON array of them (their union); a
  limit inside a filter is refused (query has --limit). While the relay runs,
  query, count, delete, backup and sync reach it through <data>/admin.sock,
  which only the user running the relay can open; otherwise they open the data
  directory.

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

    let text = |args: &mut Vec<String>, name: &str| -> Result<Option<String>, String> {
        match args.iter().position(|a| a == name) {
            Some(i) => {
                let v = args.get(i + 1).ok_or(format!("{name} needs a value"))?.clone();
                args.drain(i..i + 2);
                Ok(Some(v))
            }
            None => Ok(None),
        }
    };
    // A misspelt option must not be dropped: for `delete` it would mean a
    // wider delete than the one typed.
    let no_more = |args: &[String]| -> Result<(), String> {
        match args.first() {
            Some(a) => Err(format!("unexpected argument {a:?}; try --help")),
            None => Ok(()),
        }
    };
    let filters = |args: &mut Vec<String>, cmd: &str| -> Result<Vec<relay_proto::Filter>, String> {
        let f = text(args, "--filter")?.ok_or(format!("{cmd} needs --filter"))?;
        operator::parse_filters(&f)
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
            // Kinds the relay refuses from apps are left out, as sync leaves them out.
            let policy = cfg.policy.kind_policy();
            let skip_kind: Option<Box<dyn Fn(u64) -> bool + Send + Sync>> =
                cfg.policy.restricts_writes().then(|| Box::new(move |k| !policy.allows(k)) as _);
            let opts = import::ImportOptions { verify, skip_kind, threads };
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
            // And the log laid out by reader: a conversation's events end up
            // next to each other instead of scattered across arrival order.
            let tl = Instant::now();
            w.compact_log_all().map_err(|e| e.to_string())?;
            eprintln!("log clustered in {:.2}s", tl.elapsed().as_secs_f64());
            eprintln!(
                "imported {} lines ({:.1} MB) in {:.2}s: {:.0} lines/s, {:.1} MB/s",
                stats.lines,
                stats.bytes as f64 / 1e6,
                secs,
                stats.lines as f64 / secs,
                stats.bytes as f64 / 1e6 / secs
            );
            eprintln!(
                "  stored {}, duplicate {}, superseded {}, deleted {}, vanished {}, ephemeral skipped {}, kind skipped {}",
                stats.stored, stats.duplicate, stats.superseded, stats.deleted, stats.vanished, stats.ephemeral, stats.skipped_kind
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
            // Events are read by seq, never through the index: this is how a
            // damaged index is rebuilt, so it does not refuse one.
            let opts = relay_store::Options { verify_index: false, ..store_options(&cfg) };
            let (store, _w) = Store::open(&cfg.store.data, opts).map_err(|e| e.to_string())?;
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
        "query" => {
            let fs = filters(&mut args, "query")?;
            let limit = value(&mut args, "--limit")?;
            no_more(&args)?;
            operator::run_query(&load()?, fs, limit)
        }
        "count" => {
            let fs = filters(&mut args, "count")?;
            no_more(&args)?;
            operator::run_count(&load()?, fs)
        }
        "delete" => {
            let fs = filters(&mut args, "delete")?;
            let age = value(&mut args, "--age")?;
            let (all, dry_run, yes) = (flag(&mut args, "--all"), flag(&mut args, "--dry-run"), flag(&mut args, "--yes"));
            no_more(&args)?;
            operator::run_delete(&load()?, fs, age, all, dry_run, yes)
        }
        "backup" => {
            let no_verify = flag(&mut args, "--no-verify");
            let dest = match args.as_slice() {
                [d] => PathBuf::from(d),
                [] => return Err("backup needs a destination directory".into()),
                _ => return Err(format!("unexpected arguments: {}", args[1..].join(" "))),
            };
            operator::run_backup(&load()?, &dest, !no_verify)
        }
        "cert" => cert(&load()?),
        "sync" => {
            let fs = match text(&mut args, "--filter")? {
                Some(f) => operator::parse_filters(&f)?,
                None => vec![relay_proto::Filter::default()],
            };
            let dir = match text(&mut args, "--dir")? {
                Some(d) => config::Direction::parse(&d).ok_or(format!("--dir is down, up or both, not {d:?}"))?,
                None => config::Direction::Down,
            };
            let dry_run = flag(&mut args, "--dry-run");
            let trusted = flag(&mut args, "--trusted");
            if args.is_empty() {
                return Err("sync needs the other relay's URL, like wss://relay.example.com".into());
            }
            let url = args.remove(0);
            no_more(&args)?;
            sync::run_command(&load()?, &url, fs, dir, dry_run, trusted)
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

/// `cert`: what the HTTPS certificate is for and how long it has. Reads the file the
/// relay serves (its own `cert`, else the one it saved), so it works while the relay
/// runs and never opens the store.
fn cert(cfg: &Config) -> Result<(), String> {
    let path = if cfg.tls.uses_files() { PathBuf::from(&cfg.tls.cert) } else { cfg.store.data.join("tls").join("cert.pem") };
    let text = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound if !cfg.tls.enabled => format!("no certificate: HTTPS is off (see [tls] in the settings) and {} does not exist", path.display()),
        std::io::ErrorKind::NotFound => format!("no certificate yet: {} does not exist (a relay that is starting up for the first time is still asking for one; its log says how that is going)", path.display()),
        _ => format!("{}: {e}", path.display()),
    })?;
    let chain = relay_tls::pem::certificates(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let info = relay_tls::x509::parse_certificate(&chain[0]).map_err(|e| format!("{}: {e}", path.display()))?;
    let now = relay_tls::time::now();
    println!("certificate: {}", path.display());
    println!("names: {}", info.names.join(", "));
    println!("issuer: {}", info.issuer_cn.as_deref().unwrap_or("(unnamed)"));
    println!("valid from: {}", relay_tls::time::format(info.not_before));
    let left = info.not_after - now;
    if left < 0 {
        println!("expires: {} (EXPIRED {} days ago)", relay_tls::time::format(info.not_after), -left / 86_400);
        return Err("the certificate has expired".to_string());
    }
    println!("expires: {} (in {} days)", relay_tls::time::format(info.not_after), left / 86_400);
    Ok(())
}
