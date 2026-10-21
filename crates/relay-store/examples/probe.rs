//! Times one filter against a store, in-process: where a query's time goes.
//!
//! `cargo run --release -p relay-store --example probe -- <data dir> '<filter json>' [limit] [reps]`

use relay_proto::json::Scanner;
use relay_proto::Filter;
use relay_store::{Options, Store};
use std::time::Instant;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dir = &a[1];
    let f = Filter::parse(&mut Scanner::new(&a[2])).expect("filter");
    let limit: usize = a.get(3).and_then(|x| x.parse().ok()).unwrap_or(500);
    let reps: usize = a.get(4).and_then(|x| x.parse().ok()).unwrap_or(2000);
    let (store, _w) = Store::open(std::path::Path::new(dir), Options::default()).unwrap();
    let v = store.snapshot();
    let runs = v.runs().len();
    let t = Instant::now();
    let plan = v.plan(&f);
    let plan_us = t.elapsed().as_secs_f64() * 1e6;
    eprintln!("runs: {runs}; plan ({plan_us:.1} µs): {plan:?}");
    let mut n = 0;
    let t = Instant::now();
    for _ in 0..reps {
        n += v.query(&f, limit, 1_900_000_000).len();
    }
    let per = t.elapsed().as_secs_f64() * 1e6 / reps as f64;
    eprintln!("query: {per:.1} µs, {} results", n / reps);
    let t = Instant::now();
    for _ in 0..reps {
        let _ = v.plan(&f);
    }
    eprintln!("plan alone: {:.1} µs", t.elapsed().as_secs_f64() * 1e6 / reps as f64);
}
