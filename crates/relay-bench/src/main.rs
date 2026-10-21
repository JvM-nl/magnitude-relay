//! `relay-bench`: command-line front end. See `relay-bench help`.

use relay_bench::args::Args;
use relay_bench::data::Dataset;
use relay_bench::generate::{generate, GenParams, DEFAULT_END};
use relay_bench::report::{print_header, print_verdict, RunResult};
use relay_bench::{fanout, idle, load, neg, net, par, query, workload};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "\
relay-bench: load generator and validating tester for Nostr relays

  relay-bench gen    --events N --out FILE [--seed S] [--rate R] [--end TS] [--recipients N] [--planes N] [--authors N] [--threads T]
  relay-bench load   --url ws://HOST:PORT --file FILE [--conns C] [--window W] [--batch-ack] [--duplicates] [--count N] [--skip N]
  relay-bench query  --url ws://HOST:PORT --file FILE [--workload W] [--conns C] [--queries Q] [--limit L] [--distinct D] [--strict-ties] [--warmup N]
  relay-bench neg    --url ws://HOST:PORT --file FILE [--recipient-mode heavy|light] [--have PCT] [--sessions S] [--conns C]
  relay-bench fanout --url ws://HOST:PORT [--subscribers N] [--publishers P] [--rate R] [--duration D] [--community K] [--dm-share PCT] [--drain SECS]
  relay-bench idle   --url ws://HOST:PORT [--conns N] [--hold SECS] [--pid PID] [--src-ips K]

Common to every command but gen:
  --label NAME     relay name in reports (default: relay)
  --json FILE      append one JSON object per run to FILE
  --seed S         seeds the choice of queries, mailboxes and keys (default 1); the dataset file is the source of truth
  --timeout SECS   give up on a reply after this long (default 30)
  --threads T      client runtime threads (default min(cpus, 4)); the relay shares the box
  --src-ips K      spread connections over K loopback source addresses (127.0.0.2...) past ~28k ports

Counts take k/m/g suffixes (20k, 5M). A run that finds a wrong answer, a refused event or a lost
connection exits with status 2.

gen:   events are 70% gift wraps (Zipf mailboxes), 15% plane traffic, 10% kinds 1/7/30023, 5% replaceables.
       --rate is events/s on the dataset timeline (default 2, max 20); --end is the newest created_at
       (default 1792000000, or `now`). Same seed + flags = same bytes.
query: workloads: classic latest_1 latest_100 latest_500 author kind author_kind tag time_window exact_id
       exact_ids_100 miss multi_filter | vector dm_inbox dm_catchup concord_page concord_paging dm_ids |
       count. --workload takes names, a comma list, or classic|vector|all (default all).
       --limit overrides the page size of every workload that has one except latest_N.
       --strict-ties makes NIP-01's same-second order (lowest id first) a requirement.
neg:   NIP-77 sessions on {kinds:[1059],#p:[r]}; the client holds PCT% (default 90) of the relay's set plus 5 extras.
fanout: half DM subscribers, half Concord (200 plane authors, --community members share them); publishers send
       at --rate (total) for --duration seconds; deliveries still missing --drain seconds (default 5) later count as lost.
load:  --window W events in flight per connection (default 64); --batch-ack waits for all W OKs before sending the next W;
       --duplicates re-sends events the relay holds; --count/--skip select part of the file.
idle:  N quiet connections each with a live REQ, held --hold seconds (default 30). `ulimit -n` may need raising.
";

fn run() -> Result<bool, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || matches!(argv[0].as_str(), "help" | "--help" | "-h") {
        print!("{USAGE}");
        return Ok(false);
    }
    let mut a = Args::parse(&argv, &["batch-ack", "duplicates", "strict-ties"])?;
    let cmd = a.cmd.clone();
    if cmd == "gen" {
        return gen(a).map(|()| false);
    }
    let url = a.req("url")?;
    let label = a.str_or("label", "relay");
    let json = a.str("json");
    let seed = a.count("seed", 1)?;
    let timeout = Duration::from_secs_f64(a.num("timeout", 30.0f64)?);
    let threads = a.count("threads", par::cpus().min(4) as u64)? as usize;
    let src_ips = a.count("src-ips", 1)? as usize;
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(threads.max(1)).enable_all().build().map_err(|e| e.to_string())?;

    let results: Vec<RunResult> = match cmd.as_str() {
        "load" => {
            let file = PathBuf::from(a.req("file")?);
            let o = load::LoadOpts {
                url,
                file,
                conns: a.count("conns", 16)? as usize,
                window: a.count("window", 64)? as usize,
                batch_ack: a.flag("batch-ack"),
                duplicates: a.flag("duplicates"),
                count: a.opt_count("count")?,
                skip: a.count("skip", 0)?,
                timeout,
                label,
                src_ips,
                json,
            };
            a.finish()?;
            print_header();
            vec![rt.block_on(load::run(&o))?]
        }
        "query" => {
            let file = PathBuf::from(a.req("file")?);
            let o = query::QueryOpts {
                url,
                file,
                workloads: workload::expand(&a.str_or("workload", "all"))?,
                conns: a.count("conns", 16)? as usize,
                queries: a.count("queries", 10_000)?,
                limit: a.opt_count("limit")?.map(|l| l as usize),
                distinct: a.count("distinct", 256)? as usize,
                seed,
                strict_ties: a.flag("strict-ties"),
                timeout,
                warmup: a.count("warmup", 0)?,
                label,
                src_ips,
                json,
            };
            a.finish()?;
            let ds = Dataset::load(&o.file, true)?;
            eprintln!("dataset: {}", ds.describe());
            print_header();
            rt.block_on(query::run(&o, &ds))?
        }
        "neg" => {
            let file = PathBuf::from(a.req("file")?);
            let o = neg::NegOpts {
                url,
                mode: neg::Mode::parse(&a.str_or("recipient-mode", "heavy"))?,
                have_pct: a.count("have", 90)? as u32,
                sessions: a.count("sessions", 50)?,
                conns: a.count("conns", 4)? as usize,
                seed,
                timeout,
                frame_limit: a.count("frame-limit", 60_000)?,
                label,
                src_ips,
                json,
            };
            a.finish()?;
            let ds = Dataset::load(&file, true)?;
            eprintln!("dataset: {}", ds.describe());
            print_header();
            vec![rt.block_on(neg::run(o, &ds))?]
        }
        "fanout" => {
            let o = fanout::FanoutOpts {
                url,
                subscribers: a.count("subscribers", 1000)? as usize,
                publishers: a.count("publishers", 4)? as usize,
                rate: a.num("rate", 200.0f64)?,
                duration: a.num("duration", 20.0f64)?,
                community: a.count("community", 20)? as usize,
                dm_share: a.count("dm-share", 50)? as u32,
                seed,
                drain: Duration::from_secs_f64(a.num("drain", 5.0f64)?),
                timeout,
                label,
                src_ips,
                json,
            };
            a.finish()?;
            print_header();
            vec![rt.block_on(fanout::run(o))?]
        }
        "idle" => {
            let o = idle::IdleOpts {
                url,
                conns: a.count("conns", 10_000)? as usize,
                hold: Duration::from_secs_f64(a.num("hold", 30.0f64)?),
                pid: a.opt_num("pid")?,
                parallel: a.count("parallel", 256)? as usize,
                seed,
                timeout,
                label,
                src_ips,
                json,
            };
            a.finish()?;
            print_header();
            vec![rt.block_on(idle::run(o))?]
        }
        other => return Err(format!("unknown command '{other}' (try `relay-bench help`)")),
    };
    print_verdict(&results);
    Ok(results.iter().any(RunResult::failed))
}

fn gen(mut a: Args) -> Result<(), String> {
    let events = a.count("events", 0)?;
    let out = PathBuf::from(a.req("out")?);
    let mut p = GenParams::new(events, a.count("seed", 1)?);
    let rate: f64 = a.num("rate", 2.0)?;
    p.rate_milli = (rate * 1000.0).round() as u64;
    p.end = match a.str("end").as_deref() {
        None => DEFAULT_END,
        Some("now") => net::unix_time(),
        Some(v) => v.parse().map_err(|_| format!("--end: '{v}' is not a unix timestamp (or `now`)"))?,
    };
    p.recipients = a.count("recipients", p.recipients as u64)? as usize;
    p.planes = a.count("planes", p.planes as u64)? as usize;
    p.authors = a.count("authors", p.authors as u64)? as usize;
    p.threads = a.count("threads", p.threads as u64)? as usize;
    a.finish()?;
    p.validate()?;
    eprintln!("gen: {} events, seed {}, {} threads -> {}", p.events, p.seed, p.threads, out.display());
    let started = std::time::Instant::now();
    let stats = generate(&p, &out).map_err(|e| format!("{}: {e}", out.display()))?;
    let c = stats.classes;
    eprintln!(
        "gen: wrote {} events ({:.2} GB) in {:.1}s: {} wraps, {} plane events, {} generic, {} replaceable",
        p.events,
        stats.bytes as f64 / 1e9,
        started.elapsed().as_secs_f64(),
        c.wraps,
        c.planes,
        c.generic,
        c.replaceable
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(2),
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}
