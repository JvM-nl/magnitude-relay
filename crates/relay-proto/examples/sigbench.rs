//! Where an event's verification time goes, measured on real events (a JSONL
//! file, one event per line).
//!
//! `cargo run --release -p relay-proto --example sigbench -- <mode> <events.jsonl> [max]`
//!
//! * `steps`: every line goes through the steps the relay ran before batching,
//!   one at a time, timed with the cycle counter: JSON parse to a record, the
//!   NIP-01 preimage, its SHA-256 (sha2 crate), the pubkey parse (lift_x) and
//!   the Schnorr verify (libsecp256k1). ns per event by line size.
//!
//! Timings are the best of three passes: the production box is never idle.

use relay_proto::event::{parse_event_json, EventParser};
use relay_proto::json::Scanner;
use relay_proto::Record;
use secp256k1::{schnorr, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: sigbench steps <events.jsonl> [max]";
    let mode = args.get(1).expect(usage).clone();
    let path = args.get(2).expect(usage);
    let max: usize = args.get(3).map_or(usize::MAX, |s| s.parse().unwrap());
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).take(max).collect();
    match mode.as_str() {
        "steps" => steps(&lines),
        _ => panic!("{usage}"),
    }
}

const CLASSES: [(&str, usize); 5] = [("<1K", 1024), ("1-2K", 2048), ("2-4K", 4096), ("4-16K", 16384), (">=16K", usize::MAX)];
const STEPS: [&str; 5] = ["parse", "preimage", "sha256", "lift_x", "verify"];

fn class_of(len: usize) -> usize {
    CLASSES.iter().position(|&(_, max)| len < max).unwrap()
}

#[inline(always)]
fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_rdtsc()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        use std::sync::OnceLock;
        static T0: OnceLock<Instant> = OnceLock::new();
        T0.get_or_init(Instant::now).elapsed().as_nanos() as u64
    }
}

/// Nanoseconds per tick, measured against the monotonic clock.
fn ns_per_tick() -> f64 {
    let (t0, c0) = (Instant::now(), ticks());
    while t0.elapsed().as_millis() < 300 {
        std::hint::spin_loop();
    }
    t0.elapsed().as_nanos() as f64 / (ticks() - c0) as f64
}

fn steps(lines: &[&str]) {
    let npt = ns_per_tick();
    eprintln!("{} events, {:.4} ns/tick", lines.len(), npt);
    let mut parser = EventParser::new();
    let mut rec = Vec::new();
    let mut pre = Vec::new();
    let mut count = [0u64; CLASSES.len()];
    for l in lines {
        count[class_of(l.len())] += 1;
    }
    // best[class][step], in ticks, summed over the class.
    let mut best = [[u64::MAX; STEPS.len()]; CLASSES.len()];
    let mut bad = 0;
    for _pass in 0..3 {
        let mut sum = [[0u64; STEPS.len()]; CLASSES.len()];
        bad = 0;
        for l in lines {
            let c = class_of(l.len());
            let t0 = ticks();
            if parser.parse_unchecked(&mut Scanner::new(l), &mut rec).is_err() {
                bad += 1;
                continue;
            }
            let t1 = ticks();
            pre.clear();
            Record(&rec).write_id_preimage(&mut pre);
            let t2 = ticks();
            let id: [u8; 32] = Sha256::digest(&pre).into();
            let t3 = ticks();
            let pk = XOnlyPublicKey::from_byte_array(*Record(&rec).pubkey());
            let t4 = ticks();
            let ok = pk.as_ref().is_ok_and(|pk| schnorr::verify(&schnorr::Signature::from_byte_array(*Record(&rec).sig()), &id, pk).is_ok());
            let t5 = ticks();
            if id != *Record(&rec).id() || !ok {
                bad += 1;
            }
            let s = &mut sum[c];
            s[0] += t1 - t0;
            s[1] += t2 - t1;
            s[2] += t3 - t2;
            s[3] += t4 - t3;
            s[4] += t5 - t4;
        }
        for c in 0..CLASSES.len() {
            for s in 0..STEPS.len() {
                best[c][s] = best[c][s].min(sum[c][s]);
            }
        }
    }
    println!("{bad} events failed parse/id/sig (the raw-form fallback is not taken here)");
    println!("ns per event, best of 3 passes");
    print!("{:>8} {:>7}", "class", "events");
    for s in STEPS {
        print!(" {s:>9}");
    }
    println!(" {:>9}", "total");
    let mut all = [0u64; STEPS.len()];
    for c in 0..CLASSES.len() {
        if count[c] == 0 {
            continue;
        }
        print!("{:>8} {:>7}", CLASSES[c].0, count[c]);
        let mut tot = 0.0;
        for s in 0..STEPS.len() {
            let ns = best[c][s] as f64 * npt / count[c] as f64;
            tot += ns;
            all[s] += best[c][s];
            print!(" {ns:>9.0}");
        }
        println!(" {tot:>9.0}");
    }
    print!("{:>8} {:>7}", "all", lines.len());
    let mut tot = 0.0;
    for v in all {
        let ns = v as f64 * npt / lines.len() as f64;
        tot += ns;
        print!(" {ns:>9.0}");
    }
    println!(" {tot:>9.0}");

    // The whole verified parse as the relay calls it, back to back.
    let mut best_rate = 0.0f64;
    for _ in 0..3 {
        let t = Instant::now();
        let mut ok = 0u64;
        for l in lines {
            ok += u64::from(parse_event_json(l, &mut parser, &mut rec, true).is_ok());
        }
        let rate = lines.len() as f64 / t.elapsed().as_secs_f64();
        best_rate = best_rate.max(rate);
        black_box(ok);
    }
    println!("parse_event_json(verify): {best_rate:.0} events/s on one thread ({:.0} ns/event)", 1e9 / best_rate);
}

