//! Engine benchmark on a real store (no network): Vector's query shapes with
//! parameters drawn from the data itself.
//!
//! `cargo run --release -p relay-store --example real -- <data dir> [threads]`
//!
//! Run it inside a memory-capped cgroup to see the RAM-constrained case, e.g.
//! `systemd-run --scope -p MemoryMax=1G ...`: the page cache available to the
//! process is then far smaller than the database.

use relay_proto::json::Scanner;
use relay_proto::negentropy::VecStorage;
use relay_proto::{hex, Filter};
use relay_store::keys::{T_AUTHOR_KIND, T_TAG_KIND};
use relay_store::{Options, Store, Version};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

fn filt(j: &str) -> Filter {
    Filter::parse(&mut Scanner::new(j)).unwrap()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).expect("data dir");
    let threads: usize = args.get(2).and_then(|t| t.parse().ok()).unwrap_or(6);
    let t = Instant::now();
    let (store, _w) = Store::open(std::path::Path::new(dir), Options::default()).unwrap();
    let v = store.snapshot();
    eprintln!("open {:.3}s, {} events, {} index keys", t.elapsed().as_secs_f64(), v.count, v.index_keys());

    // Recipients of gift wraps, and authors of many gift wraps (plane-like keys).
    let t = Instant::now();
    let mut recips: HashMap<[u8; 32], u32> = HashMap::new();
    let mut lo = vec![T_TAG_KIND, b'p', 1];
    lo.extend_from_slice(&[0; 32]);
    let mut hi = vec![T_TAG_KIND, b'p', 1];
    hi.extend_from_slice(&[0xFF; 33]);
    v.for_range(&lo, &hi, |k| {
        if u64::from_be_bytes(k[35..43].try_into().unwrap()) == 1059 {
            *recips.entry(k[3..35].try_into().unwrap()).or_default() += 1;
        }
    });
    let mut planes: HashMap<[u8; 32], u32> = HashMap::new();
    v.for_range(&[T_AUTHOR_KIND], &[T_AUTHOR_KIND + 1], |k| {
        if u64::from_be_bytes(k[33..41].try_into().unwrap()) == 1059 {
            *planes.entry(k[1..33].try_into().unwrap()).or_default() += 1;
        }
    });
    let mut recips: Vec<([u8; 32], u32)> = recips.into_iter().collect();
    recips.sort_by(|a, b| b.1.cmp(&a.1));
    let mut planes: Vec<([u8; 32], u32)> = planes.into_iter().filter(|p| p.1 >= 20).collect();
    planes.sort_by(|a, b| b.1.cmp(&a.1));
    eprintln!(
        "{} recipients (heaviest {} wraps, median {}), {} plane-like authors (>=20 wraps, heaviest {}) in {:.2}s",
        recips.len(),
        recips[0].1,
        recips[recips.len() / 2].1,
        planes.len(),
        planes.first().map_or(0, |p| p.1),
        t.elapsed().as_secs_f64()
    );
    let heavy: Vec<String> = recips.iter().take(50).map(|r| hex::encode_string(&r.0)).collect();
    let typical: Vec<String> = recips.iter().skip(50).step_by((recips.len() / 2000).max(1)).take(2000).map(|r| hex::encode_string(&r.0)).collect();
    let plane: Vec<String> = planes.iter().take(500).map(|p| hex::encode_string(&p.0)).collect();
    let now = 1_800_000_000u64;

    if std::env::var("DEBUG_COUNTS").is_ok() {
        for r in typical.iter().take(8) {
            let f = filt(&format!(r##"{{"kinds":[1059],"#p":["{r}"],"limit":500}}"##));
            let fc = filt(&format!(r##"{{"kinds":[1059],"#p":["{r}"]}}"##));
            eprintln!(
                "{}: plan {:?} query(now) {} query(0) {} count {} neg {}",
                &r[..8],
                match v.plan(&f) { relay_store::Plan::Scan { prefixes, exact } => format!("scan {} prefixes exact={exact} type={}", prefixes.len(), prefixes[0][0]), p => format!("{p:?}") },
                v.query(&f, 500, now).len(),
                v.query(&f, 500, 0).len(),
                v.count(&fc, now),
                v.neg_items(&fc, now).unwrap().len()
            );
        }
        return;
    }
    let shapes: Vec<(&str, Vec<Filter>)> = vec![
        ("DM inbox, typical (limit 500)", typical.iter().map(|r| filt(&format!(r##"{{"kinds":[1059],"#p":["{r}"],"limit":500}}"##))).collect()),
        ("DM inbox, heaviest 50 (limit 500)", heavy.iter().map(|r| filt(&format!(r##"{{"kinds":[1059],"#p":["{r}"],"limit":500}}"##))).collect()),
        ("DM catch-up, typical (2 days)", typical.iter().map(|r| filt(&format!(r##"{{"kinds":[1059],"#p":["{r}"],"since":{}}}"##, 1_792_400_000))).collect()),
        ("Concord page (limit 500)", plane.iter().map(|a| filt(&format!(r#"{{"kinds":[1059],"authors":["{a}"],"limit":500}}"#))).collect()),
        ("profile lookup (kind 0, limit 1)", typical.iter().map(|a| filt(&format!(r#"{{"kinds":[0],"authors":["{a}"],"limit":1}}"#))).collect()),
        ("synced list (30078 + #d)", typical.iter().map(|a| filt(&format!(r##"{{"kinds":[30078],"authors":["{a}"],"#d":["vector/pinned"]}}"##))).collect()),
    ];
    let run = |v: &Arc<Version>, fs: &[Filter], threads: usize| -> (f64, f64, usize) {
        let t = Instant::now();
        let results: usize = std::thread::scope(|s| {
            let chunk = fs.len().div_ceil(threads);
            let hs: Vec<_> = fs.chunks(chunk).map(|c| s.spawn(move || c.iter().map(|f| v.query(f, 500, now).len()).sum::<usize>())).collect();
            hs.into_iter().map(|h| h.join().unwrap()).sum()
        });
        let secs = t.elapsed().as_secs_f64();
        (secs / fs.len() as f64 * 1e6 * threads as f64, fs.len() as f64 / secs, results)
    };
    eprintln!("{:<36} {:>12} {:>12} {:>14} {:>10}", "query", "µs/q (1 thr)", "µs/q warm", format!("q/s ({threads} thr)"), "avg rows");
    for (name, fs) in &shapes {
        let (cold, _, _) = run(&v, fs, 1);
        let (warm, _, rows) = run(&v, fs, 1);
        let (_, qps, _) = run(&v, fs, threads);
        eprintln!("{name:<36} {cold:>12.1} {warm:>12.1} {qps:>14.0} {:>10.1}", rows as f64 / fs.len() as f64);
    }

    // COUNT and NIP-77 set building.
    let t = Instant::now();
    let c: u64 = typical.iter().map(|r| v.count(&filt(&format!(r##"{{"kinds":[1059],"#p":["{r}"]}}"##)), now)).sum();
    eprintln!("COUNT DM inbox, typical: {:.1} µs/count (avg {:.0})", t.elapsed().as_secs_f64() * 1e6 / typical.len() as f64, c as f64 / typical.len() as f64);
    for (label, set) in [("typical", &typical), ("heaviest", &heavy)] {
        let t = Instant::now();
        let mut items = 0;
        for r in set.iter() {
            let s = VecStorage::new(v.neg_items(&filt(&format!(r##"{{"kinds":[1059],"#p":["{r}"]}}"##)), now).unwrap());
            items += s.len();
        }
        eprintln!(
            "NIP-77 set build (covering index), {label}: {:.1} µs/set (avg {:.0} items)",
            t.elapsed().as_secs_f64() * 1e6 / set.len() as f64,
            items as f64 / set.len() as f64
        );
    }
}
