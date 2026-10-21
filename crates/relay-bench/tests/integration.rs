//! The benchmark tool against our own relay, end to end: generate a dataset, load it
//! through the real binary, and run every validating workload. Proves the tool and the
//! relay agree on what the right answers are; any disagreement is either a tool bug
//! or a relay bug, and both are worth knowing about before a benchmark campaign.
//!
//! Needs the relay binary and takes about a minute in a debug build, so it is
//! `#[ignore]`d: `cargo test -p relay-bench -- --ignored --nocapture`. The binary is
//! built on demand (`cargo build -p relay-server` in the same profile as this test),
//! or taken from `RELAY_SERVER_BIN`.

use relay_bench::data::Dataset;
use relay_bench::fanout::{self, FanoutOpts};
use relay_bench::generate::{generate, GenParams};
use relay_bench::idle::{self, IdleOpts};
use relay_bench::load::{self, LoadOpts};
use relay_bench::neg::{self, Mode, NegOpts};
use relay_bench::query::{self, QueryOpts};
use relay_bench::report::RunResult;
use relay_bench::workload;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const EVENTS: u64 = 20_000;

fn relay_binary() -> PathBuf {
    if let Ok(p) = std::env::var("RELAY_SERVER_BIN") {
        return PathBuf::from(p);
    }
    // target/<profile>/deps/<this test>: the relay binary is built next to it.
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap().to_path_buf();
    let release = profile_dir.file_name().is_some_and(|n| n == "release");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.args(["build", "-p", "relay-server", "--manifest-path"]).arg(manifest);
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().expect("run cargo build -p relay-server");
    assert!(status.success(), "building the relay failed");
    let bin = profile_dir.join("magnitude-relay");
    assert!(bin.exists(), "no relay binary at {}", bin.display());
    bin
}

struct Relay {
    child: Child,
    addr: SocketAddr,
    dir: PathBuf,
}

impl Relay {
    fn start() -> Relay {
        let dir = std::env::temp_dir().join(format!("relay-bench-it-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let cfg = dir.join("relay.toml");
        std::fs::write(
            &cfg,
            format!(
                "[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = 4\n[policy]\nkinds = \"all\"\n[limits]\nevents_per_minute_per_ip = 0\nmax_connections_per_ip = 0\n[store]\ndata = \"{}\"\n",
                dir.join("data").display()
            ),
        )
        .unwrap();
        let child = Command::new(relay_binary()).arg("--config").arg(&cfg).stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("start the relay");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let t = Instant::now();
        while std::net::TcpStream::connect(addr).is_err() {
            assert!(t.elapsed() < Duration::from_secs(20), "the relay did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Relay { child, addr, dir }
    }

    fn url(&self) -> String {
        format!("ws://{}", self.addr)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Panics with every note of every failed run, which is where the exact filter,
/// the expected and the received counts are.
fn assert_clean(what: &str, runs: &[RunResult]) {
    let mut report = String::new();
    for r in runs {
        if r.failed() || !r.supported {
            report.push_str(&format!("{}: errors {} wrong {} supported {} ({})\n", r.workload, r.errors, r.mismatches, r.supported, r.unsupported_reason));
            for n in &r.notes {
                report.push_str(&format!("    {n}\n"));
            }
        }
    }
    assert!(report.is_empty(), "{what} found problems:\n{report}");
}

fn query_opts(relay: &Relay, file: &Path, limit: Option<usize>) -> QueryOpts {
    QueryOpts {
        url: relay.url(),
        file: file.to_path_buf(),
        workloads: workload::expand("all").unwrap(),
        conns: 4,
        queries: 300,
        limit,
        distinct: 40,
        seed: 1,
        // Our relay promises NIP-01's tie order, so hold it to it.
        strict_ties: true,
        timeout: Duration::from_secs(30),
        warmup: 0,
        label: "ours".into(),
        src_ips: 1,
        json: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "starts the relay binary and takes about a minute; run with --ignored"]
async fn every_workload_validates_against_our_relay() {
    let relay = Relay::start();
    let url = relay.url();
    let file = std::env::temp_dir().join(format!("relay-bench-it-{}.jsonl", std::process::id()));

    // Small pools make the heavy mailboxes (~1,000 wraps) deep enough that a limit of
    // 500 truncates, and the slow timeline (0.05 events/s) puts a few days between events.
    let p = GenParams { recipients: 300, planes: 40, authors: 150, rate_milli: 50, threads: 4, ..GenParams::new(EVENTS, 7) };
    let gen_params = p.clone();
    let gen_path = file.clone();
    let stats = tokio::task::spawn_blocking(move || generate(&gen_params, &gen_path)).await.unwrap().unwrap();
    assert_eq!(stats.classes.wraps, EVENTS * 7 / 10);

    // Ingest. Replaceable versions race, so some are legitimately answered "duplicate"/"replaced".
    let ingest = |dup: bool, batch_ack: bool, count: Option<u64>| LoadOpts {
        url: url.clone(),
        file: file.clone(),
        conns: 8,
        window: 64,
        batch_ack,
        duplicates: dup,
        count,
        skip: 0,
        timeout: Duration::from_secs(60),
        label: "ours".into(),
        src_ips: 1,
        json: None,
    };
    let r = load::run(&ingest(false, false, None)).await.unwrap();
    assert_clean("ingest", std::slice::from_ref(&r));
    assert_eq!(r.ops, EVENTS, "every event gets an OK");

    // Resending what is stored must be answered as duplicates, and quickly.
    let r = load::run(&ingest(true, false, Some(4000))).await.unwrap();
    assert_clean("duplicate ingest", std::slice::from_ref(&r));
    assert_eq!(r.ops, 4000);
    let r = load::run(&ingest(true, true, Some(2000))).await.unwrap();
    assert_clean("lock-step duplicate ingest", std::slice::from_ref(&r));

    // The expected answers come from the file alone.
    let ds = Dataset::load(&file, false).unwrap();
    eprintln!("dataset: {}", ds.describe());
    assert!(ds.superseded > 0, "the dataset has replaceable versions to supersede");

    // Default page sizes, then small ones so limits cut through same-second groups.
    for limit in [None, Some(30)] {
        let runs = query::run(&query_opts(&relay, &file, limit), &ds).await.unwrap();
        assert_eq!(runs.len(), 18);
        assert_clean(&format!("queries (limit {limit:?})"), &runs);
        for r in &runs {
            assert!(r.ops > 0, "{} ran nothing", r.workload);
        }
    }

    // NIP-77: heavy and light mailboxes, a client holding none, half, most and all of the set.
    for mode in [Mode::Heavy, Mode::Light] {
        for have_pct in [0, 50, 90, 100] {
            let o = NegOpts {
                url: url.clone(),
                mode,
                have_pct,
                sessions: 8,
                conns: 2,
                seed: 3,
                timeout: Duration::from_secs(30),
                frame_limit: 60_000,
                label: "ours".into(),
                src_ips: 1,
                json: None,
            };
            let r = neg::run(o, &ds).await.unwrap();
            assert_clean(&format!("neg {mode:?} {have_pct}%"), std::slice::from_ref(&r));
            assert_eq!(r.ops, 8);
        }
    }

    // Live delivery: every published event must reach every matching subscriber.
    let o = FanoutOpts {
        url: url.clone(),
        subscribers: 40,
        publishers: 2,
        rate: 100.0,
        duration: 3.0,
        community: 5,
        dm_share: 50,
        seed: 5,
        drain: Duration::from_secs(3),
        timeout: Duration::from_secs(30),
        label: "ours".into(),
        src_ips: 1,
        json: None,
        pad: 0,
    };
    let r = fanout::run(o).await.unwrap();
    assert_clean("fanout", std::slice::from_ref(&r));
    assert!(r.ops >= 150, "only {} deliveries", r.ops);

    // Idle connections, with the relay's RSS sampled where /proc exists.
    let o = IdleOpts {
        url,
        conns: 150,
        hold: Duration::from_secs(2),
        pid: Some(relay.child.id()),
        parallel: 64,
        seed: 1,
        timeout: Duration::from_secs(30),
        label: "ours".into(),
        src_ips: 1,
        json: None,
    };
    let r = idle::run(o).await.unwrap();
    assert_clean("idle", std::slice::from_ref(&r));
    assert_eq!(r.ops, 150);

    let _ = std::fs::remove_file(&file);
}
