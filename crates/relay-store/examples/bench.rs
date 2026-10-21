//! Store micro-benchmark on Vector-shaped data.
//!
//! `cargo run --release -p relay-store --example bench -- [events] [dir]`
//!
//! Builds a synthetic mailbox-heavy dataset (gift wraps p-tagged to many
//! recipients, Concord plane traffic by shared authors, some replaceables), then
//! times ingest and the query shapes Vector actually sends. Numbers are only
//! meaningful on the production box; the Mac is for checking it runs.

use relay_proto::event::parse_event_json;
use relay_proto::json::Scanner;
use relay_proto::{hex, EventParser, Filter};
use relay_store::{Options, Store};
use std::time::Instant;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn key(tag: u8, n: u64) -> String {
    let mut v = [tag; 32];
    v[..8].copy_from_slice(&n.to_le_bytes());
    hex::encode_string(&v)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let total: u64 = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(1_000_000);
    let dir = args.get(2).cloned().unwrap_or_else(|| std::env::temp_dir().join("relay-bench").display().to_string());
    let _ = std::fs::remove_dir_all(&dir);
    let recipients = 10_000u64;
    let planes = 2_000u64;
    let content = "A".repeat(1200); // a typical NIP-44 wrap is 1-2 KB

    // ---- generate records ----
    let t = Instant::now();
    let mut rng = Rng(42);
    let mut p = EventParser::new();
    let mut recs: Vec<Vec<u8>> = Vec::with_capacity(total as usize);
    let mut rec = Vec::new();
    for n in 0..total {
        let r = rng.next();
        let created = 1_700_000_000 + n / 4 + (r % 172_800); // NIP-17 backdating jitter
        let json = match r % 10 {
            0..=6 => format!(
                r#"{{"id":"{}","pubkey":"{}","created_at":{created},"kind":1059,"tags":[["p","{}"]],"content":"{content}","sig":"{}"}}"#,
                key(1, n),
                key(2, n),
                key(3, (r >> 8) % recipients),
                "00".repeat(64)
            ),
            7 | 8 => format!(
                r#"{{"id":"{}","pubkey":"{}","created_at":{created},"kind":1059,"tags":[["p","{}"]],"content":"{content}","sig":"{}"}}"#,
                key(1, n),
                key(4, (r >> 8) % planes),
                key(5, n),
                "00".repeat(64)
            ),
            _ => format!(
                r#"{{"id":"{}","pubkey":"{}","created_at":{created},"kind":30078,"tags":[["d","vector/pinned"]],"content":"x","sig":"{}"}}"#,
                key(1, n),
                key(3, (r >> 8) % recipients),
                "00".repeat(64)
            ),
        };
        parse_event_json(&json, &mut p, &mut rec, false).unwrap();
        recs.push(rec.clone());
    }
    let bytes: usize = recs.iter().map(|r| r.len()).sum();
    eprintln!("generated {total} records ({:.0} MB) in {:.2}s", bytes as f64 / 1e6, t.elapsed().as_secs_f64());

    // ---- ingest ----
    let (store, mut w) = Store::open(std::path::Path::new(&dir), Options::default()).unwrap();
    let t = Instant::now();
    for chunk in recs.chunks(4096) {
        let refs: Vec<&[u8]> = chunk.iter().map(|r| r.as_slice()).collect();
        w.write(&refs).unwrap();
    }
    let secs = t.elapsed().as_secs_f64();
    eprintln!("ingest (synced batches of 4096): {:.0} events/s ({:.2}s)", total as f64 / secs, secs);
    let v = store.snapshot();
    eprintln!("index: {} keys, {:.0} MB, {} runs", v.index_keys(), v.index_bytes() as f64 / 1e6, 0);
    drop(recs);

    // ---- queries ----
    let filt = |j: String| Filter::parse(&mut Scanner::new(&j)).unwrap();
    let bench = |name: &str, filters: Vec<Filter>, limit: usize| {
        let t = Instant::now();
        let mut results = 0usize;
        for f in &filters {
            results += v.query(f, limit, 0).len();
        }
        let per = t.elapsed().as_secs_f64() / filters.len() as f64;
        eprintln!("{name:<34} {:>9.1} µs/query {:>9.0} q/s/core  avg {:.0} results", per * 1e6, 1.0 / per, results as f64 / filters.len() as f64);
    };
    let count = |name: &str, filters: Vec<Filter>| {
        let t = Instant::now();
        let mut total = 0u64;
        for f in &filters {
            total += v.count(f, 0);
        }
        let per = t.elapsed().as_secs_f64() / filters.len() as f64;
        eprintln!("{name:<34} {:>9.1} µs/count {:>9.0} q/s/core  avg {:.0}", per * 1e6, 1.0 / per, total as f64 / filters.len() as f64);
    };

    let n = 2000u64;
    bench(
        "DM inbox {1059,#p,limit:500}",
        (0..n).map(|i| filt(format!(r##"{{"kinds":[1059],"#p":["{}"],"limit":500}}"##, key(3, i * 7 % recipients)))).collect(),
        500,
    );
    bench(
        "DM catch-up {1059,#p,since}",
        (0..n).map(|i| filt(format!(r##"{{"kinds":[1059],"#p":["{}"],"since":1700150000}}"##, key(3, i * 7 % recipients)))).collect(),
        500,
    );
    bench(
        "Concord page {1059,authors,500}",
        (0..n).map(|i| filt(format!(r#"{{"kinds":[1059],"authors":["{}"],"limit":500}}"#, key(4, i % planes)))).collect(),
        500,
    );
    bench(
        "synced list {30078,authors,#d}",
        (0..n).map(|i| filt(format!(r##"{{"kinds":[30078],"authors":["{}"],"#d":["vector/pinned"]}}"##, key(3, i % recipients)))).collect(),
        500,
    );
    bench(
        "ids x100",
        (0..n / 10)
            .map(|i| filt(format!(r#"{{"ids":[{}]}}"#, (0..100).map(|j| format!("\"{}\"", key(1, (i * 977 + j * 131) % total))).collect::<Vec<_>>().join(","))))
            .collect(),
        500,
    );
    bench("miss (unknown id)", (0..n).map(|i| filt(format!(r#"{{"ids":["{}"]}}"#, key(9, i)))).collect(), 500);
    bench("latest 500 of kind 1059", (0..200).map(|_| filt(r#"{"kinds":[1059],"limit":500}"#.into())).collect(), 500);
    count("COUNT {1059,#p}", (0..n).map(|i| filt(format!(r##"{{"kinds":[1059],"#p":["{}"]}}"##, key(3, i * 7 % recipients)))).collect());
    count("COUNT {1059,authors}", (0..n).map(|i| filt(format!(r#"{{"kinds":[1059],"authors":["{}"]}}"#, key(4, i % planes)))).collect());

    let t = Instant::now();
    drop((store, w, v));
    let (_s, _w) = Store::open(std::path::Path::new(&dir), Options::default()).unwrap();
    eprintln!("reopen (full replay): {:.2}s", t.elapsed().as_secs_f64());
}
