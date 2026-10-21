//! One result per run: a table row for the person at the terminal and one JSON
//! line for the campaign script.
//!
//! The JSON is append-only (`--json FILE`, one object per line), so a campaign
//! over four relays and thirty workloads is one file that `jq` reads directly.
//! Latencies are microseconds as floats; counts are integers. `ok` is the single
//! bit a script needs: no errors and no mismatches.

use crate::hist::Histogram;
use crate::jsonw::Json;
use crate::net::unix_time;
use std::io::Write;

pub struct RunResult {
    pub label: String,
    pub command: &'static str,
    pub workload: String,
    pub conns: usize,
    /// Operations completed (requests answered, events acknowledged, ...).
    pub ops: u64,
    pub secs: f64,
    pub hist: Histogram,
    /// Operations that failed outright: timeouts, closed connections, refused events.
    pub errors: u64,
    /// Answers that were wrong (see `check`).
    pub mismatches: u64,
    /// False when the relay does not implement the feature (NIP-77, COUNT): the run
    /// is reported, not failed.
    pub supported: bool,
    /// Why, for a run that did not happen ("unsupported by the relay: ...", "skipped:
    /// ..."); shown in the table instead of numbers.
    pub unsupported_reason: String,
    /// The first few failures, one line each, printed under the row.
    pub notes: Vec<String>,
    /// Context worth reading next to the numbers (round trips, loss, replies); not a failure.
    pub info: Vec<String>,
    pub params: Vec<(String, Json)>,
    pub detail: Vec<(String, Json)>,
}

impl RunResult {
    pub fn new(label: &str, command: &'static str, workload: &str) -> RunResult {
        RunResult {
            label: label.to_owned(),
            command,
            workload: workload.to_owned(),
            conns: 0,
            ops: 0,
            secs: 0.0,
            hist: Histogram::new(),
            errors: 0,
            mismatches: 0,
            supported: true,
            unsupported_reason: String::new(),
            notes: Vec::new(),
            info: Vec::new(),
            params: Vec::new(),
            detail: Vec::new(),
        }
    }

    pub fn param(&mut self, k: &str, v: impl Into<Json>) {
        self.params.push((k.to_owned(), v.into()));
    }

    pub fn detail(&mut self, k: &str, v: impl Into<Json>) {
        self.detail.push((k.to_owned(), v.into()));
    }

    pub fn ops_per_sec(&self) -> f64 {
        if self.secs > 0.0 {
            self.ops as f64 / self.secs
        } else {
            0.0
        }
    }

    /// True when the run found anything wrong with the relay.
    pub fn failed(&self) -> bool {
        self.supported && (self.errors > 0 || self.mismatches > 0)
    }

    pub fn to_json(&self) -> Json {
        let us = |ns: u64| ns as f64 / 1000.0;
        let h = &self.hist;
        let lat = Json::obj()
            .with("count", h.count())
            .with("mean", h.mean() / 1000.0)
            .with("min", us(h.min()))
            .with("p50", us(h.quantile(0.50)))
            .with("p90", us(h.quantile(0.90)))
            .with("p95", us(h.quantile(0.95)))
            .with("p99", us(h.quantile(0.99)))
            .with("p999", us(h.quantile(0.999)))
            .with("max", us(h.max()));
        Json::obj()
            .with("label", self.label.as_str())
            .with("command", self.command)
            .with("workload", self.workload.as_str())
            .with("time", unix_time())
            .with("tool_version", env!("CARGO_PKG_VERSION"))
            .with("conns", self.conns)
            .with("ops", self.ops)
            .with("duration_s", self.secs)
            .with("ops_per_s", self.ops_per_sec())
            .with("lat_us", lat)
            .with("errors", self.errors)
            .with("mismatches", self.mismatches)
            .with("supported", self.supported)
            .with("ok", self.supported && !self.failed())
            .with("params", Json::Obj(self.params.iter().map(|(k, v)| (k.clone(), clone_json(v))).collect()))
            .with("detail", Json::Obj(self.detail.iter().map(|(k, v)| (k.clone(), clone_json(v))).collect()))
    }

    pub fn row(&self) -> String {
        if !self.supported {
            return format!("{:<16} {:>5}  {}", self.workload, self.conns, self.unsupported_reason);
        }
        let h = &self.hist;
        format!(
            "{:<16} {:>5} {:>9} {:>10.0} {:>9} {:>9} {:>9} {:>9} {:>9} {:>6} {:>6}",
            self.workload,
            self.conns,
            self.ops,
            self.ops_per_sec(),
            fmt_ns(h.quantile(0.50)),
            fmt_ns(h.quantile(0.90)),
            fmt_ns(h.quantile(0.99)),
            fmt_ns(h.quantile(0.999)),
            fmt_ns(h.max()),
            self.errors,
            self.mismatches
        )
    }

    /// Prints the row and its notes to stderr.
    pub fn print(&self) {
        eprintln!("{}", self.row());
        for i in &self.info {
            eprintln!("    {i}");
        }
        for n in &self.notes {
            eprintln!("    {n}");
        }
    }

    /// Appends the JSON line to `path`.
    pub fn append_json(&self, path: &str) -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        let mut line = self.to_json().render();
        line.push('\n');
        // One write per line, so concurrent bench processes do not interleave halves.
        f.write_all(line.as_bytes())
    }
}

/// `s` cut to at most `n` bytes (on a character boundary), with "..." if it was longer.
pub fn clip(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_owned();
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

pub fn print_header() {
    eprintln!(
        "{:<16} {:>5} {:>9} {:>10} {:>9} {:>9} {:>9} {:>9} {:>9} {:>6} {:>6}",
        "workload", "conns", "ops", "ops/s", "p50", "p90", "p99", "p99.9", "max", "errors", "wrong"
    );
}

/// 3 significant digits with a unit: `850ns`, `12.3us`, `1.52ms`, `2.10s`.
pub fn fmt_ns(ns: u64) -> String {
    let f = ns as f64;
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        sig3(f / 1e3, "us")
    } else if ns < 1_000_000_000 {
        sig3(f / 1e6, "ms")
    } else {
        sig3(f / 1e9, "s")
    }
}

fn sig3(v: f64, unit: &str) -> String {
    if v >= 100.0 {
        format!("{v:.0}{unit}")
    } else if v >= 10.0 {
        format!("{v:.1}{unit}")
    } else {
        format!("{v:.2}{unit}")
    }
}

fn clone_json(j: &Json) -> Json {
    match j {
        Json::Null => Json::Null,
        Json::Bool(b) => Json::Bool(*b),
        Json::U64(n) => Json::U64(*n),
        Json::F64(f) => Json::F64(*f),
        Json::Str(s) => Json::Str(s.clone()),
        Json::Arr(a) => Json::Arr(a.iter().map(clone_json).collect()),
        Json::Obj(o) => Json::Obj(o.iter().map(|(k, v)| (k.clone(), clone_json(v))).collect()),
    }
}

/// Prints a one-line notice that a run failed validation, for the end of a command.
pub fn print_verdict(results: &[RunResult]) {
    let bad: Vec<&RunResult> = results.iter().filter(|r| r.failed()).collect();
    if bad.is_empty() {
        return;
    }
    eprintln!();
    eprintln!("FAILED: {} of {} runs found problems:", bad.len(), results.len());
    for r in bad {
        eprintln!("  {}: {} errors, {} wrong answers", r.workload, r.errors, r.mismatches);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Cur;

    #[test]
    fn units_have_three_significant_digits() {
        assert_eq!(fmt_ns(850), "850ns");
        assert_eq!(fmt_ns(12_345), "12.3us");
        assert_eq!(fmt_ns(999_000), "999us");
        assert_eq!(fmt_ns(1_520_000), "1.52ms");
        assert_eq!(fmt_ns(2_100_000_000), "2.10s");
        assert_eq!(fmt_ns(0), "0ns");
    }

    fn sample() -> RunResult {
        let mut r = RunResult::new("ours", "query", "dm_inbox");
        r.conns = 16;
        r.ops = 1000;
        r.secs = 2.0;
        for v in 1..=1000u64 {
            r.hist.record(v * 1000);
        }
        r.errors = 1;
        r.mismatches = 2;
        r.param("queries", 1000u64);
        r.param("file", "a \"quoted\" path");
        r.detail("tie_pick", 3u64);
        r
    }

    #[test]
    fn json_line_is_valid_and_complete() {
        let r = sample();
        let line = r.to_json().render();
        // The checker's own scanner must accept it as one well-formed object.
        let mut c = Cur::new(&line);
        assert!(c.skip_value().is_some());
        assert!(c.peek().is_none(), "trailing garbage");
        for key in ["\"p95\":", "\"tool_version\":", "\"label\":\"ours\"", "\"workload\":\"dm_inbox\"", "\"conns\":16", "\"ops\":1000", "\"ops_per_s\":500", "\"errors\":1", "\"mismatches\":2", "\"ok\":false", "\"p999\":", "\"p50\":", "\"max\":1000"] {
            assert!(line.contains(key), "{key} missing from {line}");
        }
        assert!(line.contains(r#""file":"a \"quoted\" path""#));
        assert!(!line.contains('\n'));
    }

    #[test]
    fn clip_respects_char_boundaries() {
        assert_eq!(clip("abc", 10), "abc");
        assert_eq!(clip("abcdef", 3), "abc...");
        assert_eq!(clip("\u{e9}\u{e9}\u{e9}", 3), "\u{e9}...");
    }

    #[test]
    fn failure_flags() {
        let mut r = sample();
        assert!(r.failed());
        r.errors = 0;
        r.mismatches = 0;
        assert!(!r.failed());
        r.supported = false;
        r.unsupported_reason = "unsupported by the relay: NEG-ERR".into();
        r.errors = 5;
        assert!(!r.failed(), "an unsupported feature is reported, not failed");
        assert!(r.row().contains("unsupported"));
        assert!(r.to_json().render().contains("\"ok\":false"));
    }

    #[test]
    fn json_lines_are_appended() {
        let path = std::env::temp_dir().join(format!("relay-bench-report-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let p = path.to_str().unwrap();
        sample().append_json(p).unwrap();
        sample().append_json(p).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        let _ = std::fs::remove_file(&path);
    }
}
