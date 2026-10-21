//! The command line as a campaign script sees it: exit codes, error text, and the
//! dataset file `gen` writes.

use relay_bench::sign::verify_event_line;
use std::path::PathBuf;
use std::process::{Command, Output};

fn bench(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_relay-bench")).args(args).output().expect("run relay-bench")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("relay-bench-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn help_succeeds_and_mistakes_fail_with_a_message() {
    let o = bench(&["help"]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("relay-bench query"));
    assert!(bench(&[]).status.success(), "no arguments prints the usage");

    // Exit status 1 is "could not run"; 2 is reserved for "ran and found a wrong answer".
    let o = bench(&["frobnicate", "--url", "ws://127.0.0.1:1"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("unknown command 'frobnicate'"), "{}", stderr(&o));
    let o = bench(&["query", "--file", "x"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("--url is required"), "{}", stderr(&o));
    let o = bench(&["query", "--url", "ws://127.0.0.1:1", "--file", "x", "--conn", "4"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("unknown option --conn"), "a typo must not silently use the default: {}", stderr(&o));
    let o = bench(&["query", "--url", "ws://127.0.0.1:1", "--file", "/nonexistent/events.jsonl", "--workload", "nope"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("unknown workload 'nope'"), "{}", stderr(&o));
    let o = bench(&["query", "--url", "ws://127.0.0.1:1", "--file", "/nonexistent/events.jsonl"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("/nonexistent/events.jsonl"), "{}", stderr(&o));
    let o = bench(&["gen", "--events", "10"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("--out is required"));
    let o = bench(&["gen", "--events", "10", "--out", "/dev/null", "--rate", "50"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(stderr(&o).contains("--rate"), "{}", stderr(&o));
}

#[test]
fn gen_is_deterministic_across_thread_counts_and_signs_validly() {
    let (a, b, c) = (scratch("a.jsonl"), scratch("b.jsonl"), scratch("c.jsonl"));
    let gen = |out: &PathBuf, seed: &str, threads: &str| {
        let o = bench(&[
            "gen", "--events", "400", "--seed", seed, "--out", out.to_str().unwrap(), "--rate", "0.5", "--recipients", "20", "--planes", "6", "--authors", "20", "--threads", threads,
        ]);
        assert!(o.status.success(), "{}", stderr(&o));
        assert!(stderr(&o).contains("280 wraps, 60 plane events, 40 generic, 20 replaceable"), "{}", stderr(&o));
    };
    gen(&a, "5", "1");
    gen(&b, "5", "3");
    gen(&c, "6", "2");
    let (ta, tb, tc) = (std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap(), std::fs::read(&c).unwrap());
    assert_eq!(ta, tb, "same seed, same bytes, whatever the thread count");
    assert_ne!(ta, tc);
    let text = String::from_utf8(ta).unwrap();
    assert_eq!(text.lines().count(), 400);
    assert!(text.ends_with('\n'));
    for line in text.lines().step_by(7) {
        verify_event_line(line).unwrap_or_else(|e| panic!("{e}: {line}"));
    }
    for p in [a, b, c] {
        let _ = std::fs::remove_file(p);
    }
}
