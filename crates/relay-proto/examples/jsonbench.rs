//! What writing an event's JSON costs, and what storing gift-wrap content as
//! decoded bytes changes about it, measured on real events (a JSONL file).
//!
//! `cargo run --release -p relay-proto --example jsonbench -- <mode> [events.jsonl] [max] [arena MiB]`
//!
//! * `codec`: base64 encode and decode against a plain copy of the same text,
//!   by length, in ns per call.
//! * `write <events.jsonl>`: `Record::write_json` by event size, records as
//!   stored before (text content) and after (`compact_into`), in three
//!   memory states: warm (a few hundred records, in L1/L2), cold (copies
//!   spread over an arena far larger than the last-level cache, visited in
//!   random order) and cold with the relay's prefetch (each record's first
//!   lines requested four records ahead, as a query does). A plain copy of
//!   the record bytes in the same states separates the memory misses from
//!   the encoding.
//! * `parse <events.jsonl>`: the ingest side per event: JSON to record
//!   (`parse_unchecked`), the id preimage and its hash, and `compact_into`.
//!
//! Timings are the best of three passes: the production box is never idle.

use relay_proto::event::compute_id;
use relay_proto::json::Scanner;
use relay_proto::record::compact_into;
use relay_proto::{base64, EventParser, Record};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: jsonbench codec | jsonbench <write|parse> <events.jsonl> [max] [arena MiB]";
    let mode = args.get(1).expect(usage).as_str();
    if mode == "codec" {
        return codec();
    }
    let path = args.get(2).expect(usage);
    let max: usize = args.get(3).map_or(usize::MAX, |s| s.parse().unwrap());
    let arena_mib: usize = args.get(4).map_or(1024, |s| s.parse().unwrap());
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).take(max).collect();
    match mode {
        "write" => write(&lines, arena_mib),
        "parse" => parse(&lines),
        _ => panic!("{usage}"),
    }
}

/// Best of three timings of `f`, which does `n` items: ns per item.
fn best(n: usize, mut f: impl FnMut()) -> f64 {
    (0..3)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_nanos() as f64 / n as f64
        })
        .fold(f64::MAX, f64::min)
}

fn codec() {
    println!("{:>7} {:>9} {:>9} {:>9} {:>9} {:>9} {:>11}", "bytes", "copy ns", "enc ns", "dec ns", "json ns", "late ns", "enc GB/s");
    for len in [99usize, 132, 256, 512, 1024, 1050, 1400, 2048, 4096, 16384, 49152] {
        let bytes: Vec<u8> = (0..len as u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let mut text = Vec::new();
        base64::encode_into(&bytes, &mut text);
        // Not base64: a profile's JSON (fails in the first block), and the
        // payload with one bad character near its end (fails last).
        let json: Vec<u8> = br#"{"name":"vector user","about":"hello","picture":"https://example.com/a.png"}"#.iter().cycle().take(text.len()).copied().collect();
        let mut late = text.clone();
        let at = late.len() - 8;
        late[at] = b'-';
        let reps = (4_000_000 / text.len()).max(100);
        let mut out = Vec::with_capacity(text.len() * 2);
        let copy = best(reps, || {
            for _ in 0..reps {
                out.clear();
                out.extend_from_slice(black_box(&text));
                black_box(&out);
            }
        });
        let enc = best(reps, || {
            for _ in 0..reps {
                out.clear();
                base64::encode_into(black_box(&bytes), &mut out);
                black_box(&out);
            }
        });
        let mut dec = |t: &[u8], ok: bool| {
            best(reps, || {
                for _ in 0..reps {
                    out.clear();
                    assert_eq!(base64::decode_canonical_into(black_box(t), &mut out), ok);
                    black_box(&out);
                }
            })
        };
        let (d, j, l) = (dec(&text, true), dec(&json, false), dec(&late, false));
        println!("{len:>7} {copy:>9.1} {enc:>9.1} {d:>9.1} {j:>9.1} {l:>9.1} {:>11.2}", text.len() as f64 / enc);
    }
}

/// JSON size classes the results are split by.
const BUCKETS: [(usize, &str); 5] = [(512, "<0.5K"), (1024, "0.5-1K"), (2048, "1-2K"), (4096, "2-4K"), (usize::MAX, ">=4K")];

fn bucket_of(json_len: usize) -> usize {
    BUCKETS.iter().position(|&(hi, _)| json_len < hi).unwrap()
}

fn records(lines: &[&str]) -> Vec<Vec<u8>> {
    let mut p = EventParser::new();
    let mut out = Vec::new();
    for l in lines {
        let mut rec = Vec::new();
        if p.parse_unchecked(&mut Scanner::new(l), &mut rec).is_ok() {
            out.push(rec);
        }
    }
    out
}

/// xorshift64*, for shuffles.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, (self.next() % (i as u64 + 1)) as usize);
        }
    }
}

/// Copies of `recs` back to back until `bytes` is filled: (arena, spans).
fn arena(recs: &[Vec<u8>], bytes: usize) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut a = Vec::with_capacity(bytes + 70_000);
    let mut spans = Vec::new();
    'fill: loop {
        for r in recs {
            if a.len() + r.len() > bytes {
                break 'fill;
            }
            // Cache-line aligned, as the log's 20-byte frame headers roughly
            // give: records start anywhere in a line, so offset by the frame.
            let pad = (64 - a.len() % 64) % 64 + 20;
            a.resize(a.len() + pad, 0);
            spans.push((a.len(), r.len()));
            a.extend_from_slice(r);
        }
    }
    (a, spans)
}

#[inline]
fn prefetch(p: *const u8) {
    // SAFETY: a prefetch only hints the CPU; any address is fine.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        std::arch::x86_64::_mm_prefetch(p as *const i8, std::arch::x86_64::_MM_HINT_T0);
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!("prfm pldl1keep, [{0}]", in(reg) p, options(nostack, preserves_flags, readonly));
    }
}

/// ns per record of `op` over `order` (indexes into `spans`), with or without
/// the relay's prefetch of each record's first three lines four ahead.
fn run(a: &[u8], spans: &[(usize, usize)], order: &[usize], pf: bool, op: &mut impl FnMut(&[u8], &mut Vec<u8>)) -> f64 {
    let mut out = Vec::with_capacity(1 << 20);
    best(order.len(), || {
        for (k, &i) in order.iter().enumerate() {
            if pf {
                if let Some(&j) = order.get(k + 4) {
                    let p = a[spans[j].0..].as_ptr();
                    for line in 0..3 {
                        prefetch(p.wrapping_add(line * 64));
                    }
                }
            }
            let (o, n) = spans[i];
            out.clear();
            op(&a[o..o + n], &mut out);
            black_box(&out);
        }
    })
}

fn write(lines: &[&str], arena_mib: usize) {
    let text = records(lines);
    let stored: Vec<Vec<u8>> = text
        .iter()
        .map(|r| {
            let mut s = Vec::new();
            compact_into(r, &mut s);
            s
        })
        .collect();
    let compacted = stored.iter().filter(|r| Record(r).is_base64()).count();
    let (tb, sb): (usize, usize) = (text.iter().map(Vec::len).sum(), stored.iter().map(Vec::len).sum());
    println!(
        "{} events: {} with base64 content ({:.1}%); records {:.1} MB as text, {:.1} MB stored ({:.1}% smaller)",
        text.len(),
        compacted,
        100.0 * compacted as f64 / text.len() as f64,
        tb as f64 / 1e6,
        sb as f64 / 1e6,
        100.0 * (1.0 - sb as f64 / tb as f64)
    );
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let copy = &mut |r: &[u8], out: &mut Vec<u8>| out.extend_from_slice(r);
    let json = &mut |r: &[u8], out: &mut Vec<u8>| Record(r).write_json(out);
    println!(
        "{:<8} {:>7} {:>8} | {:>7} {:>7} {:>7} {:>7} | {:>7} {:>7} {:>7} {:>7} | {:>7} {:>7} {:>7} {:>7}",
        "json", "events", "avg B", "warm:", "", "", "", "cold:", "", "", "", "cold+pf:", "", "", ""
    );
    println!(
        "{:<8} {:>7} {:>8} | {:>7} {:>7} {:>7} {:>7} | {:>7} {:>7} {:>7} {:>7} | {:>7} {:>7} {:>7} {:>7}",
        "", "", "", "copy", "json", "copy'", "json'", "copy", "json", "copy'", "json'", "copy", "json", "copy'", "json'"
    );
    // Cold: one arena per form, each record copied over and over, in random order.
    let mut by_form = Vec::new();
    for recs in [&text, &stored] {
        let mut idx: Vec<usize> = (0..recs.len()).collect();
        rng.shuffle(&mut idx);
        let shuffled: Vec<Vec<u8>> = idx.iter().map(|&i| recs[i].clone()).collect();
        let (a, spans) = arena(&shuffled, arena_mib << 20);
        let src: Vec<usize> = (0..spans.len()).map(|k| idx[k % idx.len()]).collect();
        by_form.push((a, spans, src));
    }
    for (b, &(_, name)) in BUCKETS.iter().enumerate() {
        let members: Vec<usize> = (0..text.len()).filter(|&i| bucket_of(Record(&text[i]).json_len()) == b).collect();
        if members.is_empty() {
            continue;
        }
        let avg = members.iter().map(|&i| Record(&text[i]).json_len()).sum::<usize>() / members.len();
        let mut cells = Vec::new();
        // Warm: the first 64 of the class (about 100 KB), 256 times over.
        let warm_ids: Vec<usize> = members.iter().take(64).copied().collect();
        for recs in [&text, &stored] {
            let (a, spans) = arena(&warm_ids.iter().map(|&i| recs[i].clone()).collect::<Vec<_>>(), 1 << 20);
            let spans = &spans[..warm_ids.len().min(spans.len())];
            let order: Vec<usize> = (0..256).flat_map(|_| 0..spans.len()).collect();
            cells.push(run(&a, spans, &order, false, copy));
            cells.push(run(&a, spans, &order, false, json));
        }
        for pf in [false, true] {
            for (a, spans, src) in &by_form {
                let mut order: Vec<usize> = (0..spans.len()).filter(|&k| bucket_of(Record(&text[src[k]]).json_len()) == b).collect();
                rng.shuffle(&mut order);
                order.truncate(400_000);
                cells.push(run(a, spans, &order, pf, copy));
                cells.push(run(a, spans, &order, pf, json));
            }
        }
        let c: Vec<String> = cells.iter().map(|v| format!("{v:>7.1}")).collect();
        println!("{name:<8} {:>7} {avg:>8} | {} | {} | {}", members.len(), c[0..4].join(" "), c[4..8].join(" "), c[8..12].join(" "));
    }
    println!("ns per event; ' = records as stored with base64 content decoded; pf = the relay's prefetch, 4 records ahead");
}

fn parse(lines: &[&str]) {
    let mut p = EventParser::new();
    let mut rec = Vec::new();
    let mut scratch = Vec::new();
    let mut out = Vec::new();
    let recs = records(lines);
    let n = recs.len();
    let bytes: usize = lines.iter().map(|l| l.len()).sum();
    let t_parse = best(lines.len(), || {
        for l in lines {
            black_box(p.parse_unchecked(&mut Scanner::new(l), &mut rec).is_ok());
        }
    });
    let t_id = best(n, || {
        for r in &recs {
            black_box(compute_id(Record(r), &mut scratch));
        }
    });
    let t_compact = best(n, || {
        for r in &recs {
            out.clear();
            compact_into(r, &mut out);
            black_box(&out);
        }
    });
    let t_copy = best(n, || {
        for r in &recs {
            black_box(r.to_vec());
        }
    });
    let stored: Vec<Vec<u8>> = recs
        .iter()
        .map(|r| {
            let mut s = Vec::new();
            compact_into(r, &mut s);
            s
        })
        .collect();
    let t_id_stored = best(n, || {
        for r in &stored {
            black_box(compute_id(Record(r), &mut scratch));
        }
    });
    println!("{n} events, {:.0} bytes of JSON on average", bytes as f64 / n as f64);
    println!("parse_unchecked (JSON -> record)       {t_parse:8.1} ns/event");
    println!("compute_id (preimage + SHA-256)        {t_id:8.1} ns/event");
    println!("compute_id of a decoded record         {t_id_stored:8.1} ns/event");
    println!("record copy (to_vec, the writer's)     {t_copy:8.1} ns/event");
    println!("compact_into (the writer's, now)       {t_compact:8.1} ns/event");
}
