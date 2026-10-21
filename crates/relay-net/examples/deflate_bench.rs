//! Speed and ratio of the in-house DEFLATE against miniz_oxide (a dev-dependency used
//! only here and in the tests).
//!
//! ```text
//! cargo run --release -p relay-net --example deflate_bench
//! ```
//!
//! The corpus is 1000 synthetic Nostr relay messages (`["EVENT","sub",{...}]`):
//! lowercase-hex ids, pubkeys and signatures, short text, and about one in eight
//! carries a 1-2 KB base64 gift-wrap body. Each workload is run for about a second and
//! reported as MB/s of *uncompressed* bytes for its fastest run.

#[path = "../src/deflate/testdata.rs"]
#[allow(dead_code)]
mod testdata;

use miniz_oxide::deflate::core::{compress, create_comp_flags_from_zip_params, CompressorOxide, TDEFLFlush};
use miniz_oxide::deflate::stream::deflate as miniz_stream_deflate;
use miniz_oxide::inflate::stream::{inflate as miniz_stream_inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush};
use relay_net::deflate::{Deflater, Flush, Inflater};
use std::hint::black_box;
use std::time::{Duration, Instant};

/// Runs `f` (which processes `bytes` bytes per call) repeatedly for about a second and
/// returns the MB/s of its *fastest* call. Minimum rather than mean: this machine is
/// shared, and a call that was descheduled or lost its core measures the neighbours,
/// not the code.
fn mbps(bytes: usize, mut f: impl FnMut()) -> f64 {
    f(); // warm up: scratch allocation, page faults
    let mut best = f64::MAX;
    let start = Instant::now();
    let mut runs = 0;
    while start.elapsed() < Duration::from_millis(1000) || runs < 8 {
        let t = Instant::now();
        f();
        best = best.min(t.elapsed().as_secs_f64());
        runs += 1;
    }
    bytes as f64 / best / 1e6
}

fn miniz_flags(level: i32) -> u32 {
    create_comp_flags_from_zip_params(level, -15, 0)
}

/// One miniz compress call into a fresh-enough buffer with the given flush mode.
fn miniz_compress(c: &mut CompressorOxide, input: &[u8], out: &mut Vec<u8>, flush: TDEFLFlush) {
    out.clear();
    out.resize(input.len() + input.len() / 8 + 1024, 0);
    let (_, consumed, written) = compress(c, input, out, flush);
    assert_eq!(consumed, input.len());
    out.truncate(written);
}

fn main() {
    let events = testdata::nostr_corpus(1, 1000);
    let total: usize = events.iter().map(Vec::len).sum();
    let bulk: Vec<u8> = events.concat();
    let sizes: Vec<usize> = events.iter().map(Vec::len).collect();
    println!(
        "corpus: {} messages, {} bytes (avg {}, min {}, max {}); bulk payload {} bytes\n",
        events.len(),
        total,
        total / events.len(),
        sizes.iter().min().unwrap(),
        sizes.iter().max().unwrap(),
        bulk.len()
    );

    // ---------------- ratio ----------------
    // Sizes count the payload as permessage-deflate would send it: the sync marker's four
    // bytes stripped from every message.
    let strip = |n: usize| n.saturating_sub(4);
    let mut ours_indep = 0;
    let mut ours_ctx = 0;
    let mut ours_ctx12 = 0;
    let mut d_ctx = Deflater::new(15, true);
    let mut d_ctx12 = Deflater::new(12, true);
    let mut d_indep = Deflater::new(15, false);
    let mut out = Vec::new();
    for e in &events {
        out.clear();
        d_indep.deflate(e, &mut out, Flush::Sync);
        ours_indep += strip(out.len());
        out.clear();
        d_ctx.deflate(e, &mut out, Flush::Sync);
        ours_ctx += strip(out.len());
        out.clear();
        d_ctx12.deflate(e, &mut out, Flush::Sync);
        ours_ctx12 += strip(out.len());
    }
    let mut mz_indep = [0usize; 2];
    let mut mz_ctx = [0usize; 2];
    for (k, level) in [1, 6].into_iter().enumerate() {
        let mut c = CompressorOxide::new(miniz_flags(level));
        let mut ctx = CompressorOxide::new(miniz_flags(level));
        let mut buf = Vec::new();
        for e in &events {
            c.reset();
            miniz_compress(&mut c, e, &mut buf, TDEFLFlush::Sync);
            mz_indep[k] += strip(buf.len());
            miniz_compress(&mut ctx, e, &mut buf, TDEFLFlush::Sync);
            mz_ctx[k] += strip(buf.len());
        }
    }
    let mut ours_bulk = Vec::new();
    Deflater::new(15, false).deflate(&bulk, &mut ours_bulk, Flush::Sync);
    let mut mz_bulk = [0usize; 2];
    for (k, level) in [1, 6].into_iter().enumerate() {
        let mut c = CompressorOxide::new(miniz_flags(level));
        let mut buf = Vec::new();
        miniz_compress(&mut c, &bulk, &mut buf, TDEFLFlush::Sync);
        mz_bulk[k] = buf.len();
    }
    let pct = |n: usize, of: usize| 100.0 * n as f64 / of as f64;
    println!("compressed size, % of input (lower is better)");
    println!("{:<44}{:>10}{:>10}{:>10}", "", "ours", "miniz L1", "miniz L6");
    println!(
        "{:<44}{:>9.1}%{:>9.1}%{:>9.1}%",
        "per message, no context",
        pct(ours_indep, total),
        pct(mz_indep[0], total),
        pct(mz_indep[1], total)
    );
    println!(
        "{:<44}{:>9.1}%{:>9.1}%{:>9.1}%",
        "per message, context takeover (32 KiB)",
        pct(ours_ctx, total),
        pct(mz_ctx[0], total),
        pct(mz_ctx[1], total)
    );
    println!("{:<44}{:>9.1}%   (4 KiB window)", "per message, context takeover (4 KiB)", pct(ours_ctx12, total));
    println!(
        "{:<44}{:>9.1}%{:>9.1}%{:>9.1}%",
        "one bulk payload (REQ answer)",
        pct(ours_bulk.len(), bulk.len()),
        pct(mz_bulk[0], bulk.len()),
        pct(mz_bulk[1], bulk.len())
    );

    // ---------------- compression speed ----------------
    println!("\ncompress, MB/s of input");
    println!("{:<44}{:>10}{:>10}{:>10}", "", "ours", "miniz L1", "miniz L6");
    let ours = mbps(total, || {
        let mut d = Deflater::new(15, false);
        let mut out = Vec::with_capacity(4096);
        for e in &events {
            out.clear();
            d.deflate(black_box(e), &mut out, Flush::Sync);
            black_box(&out);
        }
    });
    let mut mz = [0f64; 2];
    for (k, level) in [1, 6].into_iter().enumerate() {
        let mut c = CompressorOxide::new(miniz_flags(level));
        let mut buf = Vec::with_capacity(4096);
        mz[k] = mbps(total, || {
            for e in &events {
                c.reset();
                miniz_compress(&mut c, black_box(e), &mut buf, TDEFLFlush::Sync);
                black_box(&buf);
            }
        });
    }
    println!("{:<44}{:>10.0}{:>10.0}{:>10.0}", "per message, no context", ours, mz[0], mz[1]);

    let ours = mbps(total, || {
        let mut d = Deflater::new(15, true);
        let mut out = Vec::with_capacity(4096);
        for e in &events {
            out.clear();
            d.deflate(black_box(e), &mut out, Flush::Sync);
            black_box(&out);
        }
    });
    let mut mz = [0f64; 2];
    for (k, level) in [1, 6].into_iter().enumerate() {
        let mut buf = Vec::with_capacity(4096);
        mz[k] = mbps(total, || {
            let mut c = CompressorOxide::new(miniz_flags(level));
            for e in &events {
                miniz_compress(&mut c, black_box(e), &mut buf, TDEFLFlush::Sync);
                black_box(&buf);
            }
        });
    }
    println!("{:<44}{:>10.0}{:>10.0}{:>10.0}", "per message, context takeover", ours, mz[0], mz[1]);

    let ours = mbps(bulk.len(), || {
        let mut d = Deflater::new(15, false);
        let mut out = Vec::with_capacity(bulk.len());
        d.deflate(black_box(&bulk), &mut out, Flush::Sync);
        black_box(&out);
    });
    let mut mz = [0f64; 2];
    for (k, level) in [1, 6].into_iter().enumerate() {
        let mut c = CompressorOxide::new(miniz_flags(level));
        let mut buf = Vec::new();
        mz[k] = mbps(bulk.len(), || {
            c.reset();
            miniz_compress(&mut c, black_box(&bulk), &mut buf, TDEFLFlush::Sync);
            black_box(&buf);
        });
    }
    println!("{:<44}{:>10.0}{:>10.0}{:>10.0}", "one bulk payload", ours, mz[0], mz[1]);

    // ---------------- decompression speed ----------------
    println!("\ndecompress, MB/s of output");
    println!("{:<44}{:>10}{:>10}", "stream", "ours", "miniz");
    let stateless = |level: Option<i32>| -> Vec<Vec<u8>> {
        events
            .iter()
            .map(|e| match level {
                None => {
                    let mut out = Vec::new();
                    Deflater::new(15, false).deflate(e, &mut out, Flush::Finish);
                    out
                }
                Some(l) => miniz_oxide::deflate::compress_to_vec(e, l as u8),
            })
            .collect()
    };
    for (name, level) in [
        ("per message, our L1-like output", None),
        ("per message, miniz L1 output", Some(1)),
        ("per message, miniz L6 output", Some(6)),
    ] {
        let packed = stateless(level);
        let mut inf = Inflater::new(15, false);
        let mut buf = Vec::with_capacity(4096);
        let o = mbps(total, || {
            for p in &packed {
                buf.clear();
                inf.inflate(black_box(p), &mut buf, 1 << 20).unwrap();
                black_box(&buf);
            }
        });
        let m = mbps(total, || {
            for p in &packed {
                black_box(miniz_oxide::inflate::decompress_to_vec(black_box(p)).unwrap());
            }
        });
        println!("{:<44}{:>10.0}{:>10.0}", name, o, m);
    }
    // Context takeover: our Sync output message by message.
    let mut d = Deflater::new(15, true);
    let packed: Vec<Vec<u8>> = events
        .iter()
        .map(|e| {
            let mut out = Vec::new();
            d.deflate(e, &mut out, Flush::Sync);
            out
        })
        .collect();
    let mut buf = Vec::with_capacity(4096);
    let o = mbps(total, || {
        let mut inf = Inflater::new(15, true);
        for p in &packed {
            buf.clear();
            inf.inflate(black_box(p), &mut buf, 1 << 20).unwrap();
            black_box(&buf);
        }
    });
    let m = mbps(total, || {
        let mut st = InflateState::new_boxed(DataFormat::Raw);
        let mut out = vec![0u8; 1 << 16];
        for p in &packed {
            let r = miniz_stream_inflate(&mut st, black_box(p), &mut out, MZFlush::Sync);
            black_box(r.bytes_written);
        }
    });
    println!("{:<44}{:>10.0}{:>10.0}", "per message, context takeover (our output)", o, m);
    // The same, but through the permessage-deflate entry point with the virtual tail.
    let mut stripped: Vec<Vec<u8>> = packed.clone();
    for p in &mut stripped {
        p.truncate(p.len() - 4);
    }
    let o = mbps(total, || {
        let mut inf = Inflater::new(15, true);
        for p in &stripped {
            buf.clear();
            inf.inflate_message(black_box(p), &mut buf, 1 << 20).unwrap();
            black_box(&buf);
        }
    });
    println!("{:<44}{:>10.0}{:>10}", "  same via inflate_message (tail stripped)", o, "-");

    for (name, level) in [
        ("one bulk payload, our output", None),
        ("one bulk payload, miniz L1 output", Some(1)),
        ("one bulk payload, miniz L6 output", Some(6)),
    ] {
        let packed = match level {
            None => {
                let mut out = Vec::new();
                Deflater::new(15, false).deflate(&bulk, &mut out, Flush::Finish);
                out
            }
            Some(l) => miniz_oxide::deflate::compress_to_vec(&bulk, l as u8),
        };
        let mut inf = Inflater::new(15, false);
        let mut buf = Vec::with_capacity(bulk.len() + 1024);
        let o = mbps(bulk.len(), || {
            buf.clear();
            inf.inflate(black_box(&packed), &mut buf, 1 << 26).unwrap();
            black_box(&buf);
        });
        let m = mbps(bulk.len(), || {
            black_box(miniz_oxide::inflate::decompress_to_vec(black_box(&packed)).unwrap());
        });
        println!("{:<44}{:>10.0}{:>10.0}", name, o, m);
    }

    // ---------------- the extremes ----------------
    println!("\nspecial inputs (ours, MB/s compress / decompress, size ratio)");
    let mut rng = testdata::Rng::new(5);
    let hexonly = testdata::hex(&mut rng, 1 << 20);
    let b64 = testdata::base64(&mut rng, 1 << 20);
    let random = rng.bytes(1 << 20);
    let zeros = vec![0u8; 1 << 20];
    for (name, data) in [
        ("1 MiB lowercase hex", &hexonly),
        ("1 MiB base64", &b64),
        ("1 MiB random bytes", &random),
        ("1 MiB zeros", &zeros),
    ] {
        let mut packed = Vec::new();
        Deflater::new(15, false).deflate(data, &mut packed, Flush::Sync);
        let c = mbps(data.len(), || {
            let mut out = Vec::with_capacity(data.len() + 4096);
            Deflater::new(15, false).deflate(black_box(data), &mut out, Flush::Sync);
            black_box(&out);
        });
        let mut inf = Inflater::new(15, false);
        let mut buf = Vec::with_capacity(data.len() + 1024);
        let d = mbps(data.len(), || {
            buf.clear();
            inf.inflate(black_box(&packed), &mut buf, 1 << 26).unwrap();
            black_box(&buf);
        });
        println!("{:<24}{:>8.0}{:>8.0}{:>9.1}%", name, c, d, pct(packed.len(), data.len()));
    }

    // ---------------- memory ----------------
    println!("\nheap held between messages by one connection (after 1000 events, 701 KB)");
    for bits in [15u8, 12, 9] {
        let mut d = Deflater::new(bits, true);
        let mut inf = Inflater::new(bits, true);
        let mut out = Vec::new();
        for e in &events {
            out.clear();
            d.deflate(e, &mut out, Flush::Sync);
            let mut plain = Vec::new();
            inf.inflate(&out, &mut plain, 1 << 20).unwrap();
        }
        println!(
            "{:<44}{:>9} B compress   {:>7} B decompress",
            format!("context takeover, {} KiB window", (1usize << bits) / 1024).replace("0 KiB", "0.5 KiB"),
            d.heap_bytes(),
            inf.heap_bytes()
        );
    }
    let d = Deflater::new(15, false);
    let inf = Inflater::new(15, false);
    println!("{:<44}{:>9} B compress   {:>7} B decompress", "no context takeover", d.heap_bytes(), inf.heap_bytes());
    let _ = miniz_stream_deflate;
}
