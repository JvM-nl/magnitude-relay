//! Where an event's verification time goes, and what each change to it buys,
//! measured on real events (a JSONL file, one event per line).
//!
//! `cargo run --release -p relay-proto --example sigbench -- <mode> <events.jsonl> [max]`
//!
//! * `steps`: every line goes through the steps the relay ran before batching,
//!   one at a time, timed with the cycle counter: JSON parse to a record, the
//!   NIP-01 preimage, its SHA-256 (sha2 crate), the pubkey parse (lift_x) and
//!   the Schnorr verify (libsecp256k1). ns per event by line size.
//! * `sha`: event-id hashing, the sha2 crate against ours, one preimage at a
//!   time and eight at once.
//! * `batch`: signature verification alone: libsecp256k1 one at a time (with
//!   and without the key cache) against our batch verifier at sizes 1 to 4096,
//!   plus the curve primitives and per-signature bookkeeping underneath.
//! * `tune`: multi-scalar multiplication, Strauss against Pippenger at each
//!   window width, by number of terms (`TUNE_MIN=<n>` skips smaller sums).
//!
//! Timings are the best of three passes: the production box is never idle.

use relay_proto::event::{parse_event_json, EventParser};
use relay_proto::json::Scanner;
use relay_proto::secp::field::Fe;
use relay_proto::secp::group::{Affine, Jacobian};
use relay_proto::secp::msm::{self, Term};
use relay_proto::secp::{verify_one, SigRef, Verifier};
use relay_proto::{sha256, Record};
use secp256k1::{schnorr, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::hint::black_box;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: sigbench <steps|sha|batch|tune> <events.jsonl> [max]";
    let mode = args.get(1).expect(usage).clone();
    let path = args.get(2).expect(usage);
    let max: usize = args.get(3).map_or(usize::MAX, |s| s.parse().unwrap());
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).take(max).collect();
    match mode.as_str() {
        "steps" => steps(&lines),
        "sha" => sha(&lines),
        "batch" => batch(&lines),
        "tune" => tune(&lines),
        _ => panic!("{usage}"),
    }
}

/// Best of three timings of `f`, in ns per item.
fn best_ns(items: usize, mut f: impl FnMut()) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..3 {
        let t = Instant::now();
        f();
        best = best.min(t.elapsed().as_nanos() as f64 / items as f64);
    }
    best
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

/// Event-id hashing over the same preimages: the sha2 crate one at a time,
/// ours one at a time, and ours eight lanes at once in groups of each size.
fn sha(lines: &[&str]) {
    let mut parser = EventParser::new();
    let mut rec = Vec::new();
    let mut pres: Vec<Vec<u8>> = Vec::new();
    for l in lines {
        if parser.parse_unchecked(&mut Scanner::new(l), &mut rec).is_ok() {
            let mut p = Vec::new();
            Record(&rec).write_id_preimage(&mut p);
            pres.push(p);
        }
    }
    let n = pres.len();
    let bytes: usize = pres.iter().map(Vec::len).sum();
    println!("{n} preimages, mean {} bytes", bytes / n);
    let refs: Vec<&[u8]> = pres.iter().map(|p| p.as_slice()).collect();
    let mut out = vec![[0u8; 32]; n];
    let one = best_ns(n, || {
        for (p, o) in refs.iter().zip(out.iter_mut()) {
            *o = Sha256::digest(p).into();
        }
    });
    let want = out.clone();
    println!("sha2 one at a time: {one:.0} ns/event, {:.2} ns/byte", one * n as f64 / bytes as f64);
    let ours = best_ns(n, || {
        for (p, o) in refs.iter().zip(out.iter_mut()) {
            *o = sha256::digest(p);
        }
    });
    assert!(out == want, "digest disagrees with sha2");
    println!("ours one at a time: {ours:.0} ns/event, {:.2} ns/byte, {:.2}x", ours * n as f64 / bytes as f64, one / ours);
    for group in [8usize, 16, 64, 256, 2048] {
        let ns = best_ns(n, || {
            for (r, o) in refs.chunks(group).zip(out.chunks_mut(group)) {
                sha256::digest_many(r, o);
            }
        });
        assert!(out == want, "digest_many disagrees with sha2");
        println!("digest_many in groups of {group:>4}: {ns:.0} ns/event, {:.2} ns/byte, {:.2}x", ns * n as f64 / bytes as f64, one / ns);
    }
}

fn batch(lines: &[&str]) {
    let mut parser = EventParser::new();
    let mut rec = Vec::new();
    let mut recs: Vec<Vec<u8>> = Vec::new();
    for l in lines {
        if parse_event_json(l, &mut parser, &mut rec, true).is_ok() {
            recs.push(rec.clone());
        }
    }
    let sigs: Vec<SigRef<'_>> = recs.iter().map(|r| SigRef { pubkey: Record(r).pubkey(), msg: Record(r).id(), sig: Record(r).sig() }).collect();
    let n = sigs.len();
    eprintln!("{n} valid events");

    // Curve primitives, ns per operation.
    let x = Fe::from_bytes(Record(&recs[0]).pubkey()).unwrap();
    let k = 200_000;
    let mut a = x;
    let mul = best_ns(k, || {
        for _ in 0..k {
            a = a.mul(&x);
        }
        black_box(a);
    });
    let sqr = best_ns(k, || {
        for _ in 0..k {
            a = a.sqr();
        }
        black_box(a);
    });
    let k2 = 2000;
    let inv = best_ns(k2, || {
        for _ in 0..k2 {
            a = black_box(a).inv();
        }
    });
    let pts: Vec<Affine> = sigs.iter().take(1000).filter_map(|s| Affine::lift_x(s.pubkey)).collect();
    let mut j = Jacobian::from_affine(&pts[0]);
    let dbl = best_ns(k, || {
        for _ in 0..k {
            j = j.double();
        }
        black_box(j);
    });
    let add_aff = best_ns(k, || {
        for i in 0..k {
            j = j.add_affine(&pts[i % pts.len()]);
        }
        black_box(j);
    });
    let jpts: Vec<Jacobian> = pts.iter().map(|p| Jacobian::from_affine(p).double()).collect();
    let add_j = best_ns(k, || {
        for i in 0..k {
            j = j.add(&jpts[i % jpts.len()]);
        }
        black_box(j);
    });
    let lift_ours = best_ns(n, || {
        for s in &sigs {
            black_box(Affine::lift_x(s.pubkey));
        }
    });
    let lift_lib = best_ns(n, || {
        for s in &sigs {
            black_box(XOnlyPublicKey::from_byte_array(*s.pubkey).is_ok());
        }
    });
    println!("ours: fe mul {mul:.1} ns, sqr {sqr:.1} ns, inv {inv:.0} ns; double {dbl:.0} ns, add_affine {add_aff:.0} ns, add {add_j:.0} ns");
    println!("lift_x: ours {lift_ours:.0} ns, libsecp256k1 {lift_lib:.0} ns");

    // The per-signature bookkeeping around the curve work in a batch.
    {
        use relay_proto::secp::rng::Weights;
        use relay_proto::secp::scalar::Scalar;
        let tag = Sha256::digest(b"BIP0340/challenge");
        let mut prefix = [0u8; 64];
        prefix[..32].copy_from_slice(&tag);
        prefix[32..].copy_from_slice(&tag);
        let mut base = Sha256::new();
        base.update(prefix);
        let chal_one = best_ns(n, || {
            for s in &sigs {
                let mut h = base.clone();
                h.update(&s.sig[..32]);
                h.update(s.pubkey);
                h.update(s.msg);
                black_box(Scalar::from_bytes_mod(&h.finalize().into()));
            }
        });
        let mid = sha256::Midstate::after(&prefix);
        let msgs: Vec<[u8; 96]> = sigs
            .iter()
            .map(|s| {
                let mut m = [0u8; 96];
                m[..32].copy_from_slice(&s.sig[..32]);
                m[32..64].copy_from_slice(s.pubkey);
                m[64..].copy_from_slice(s.msg);
                m
            })
            .collect();
        let mrefs: Vec<&[u8]> = msgs.iter().map(|m| &m[..]).collect();
        let mut digests = vec![[0u8; 32]; n];
        let chal_lanes = best_ns(n, || {
            for (r, o) in mrefs.chunks(2048).zip(digests.chunks_mut(2048)) {
                sha256::digest_many_after(&mid, r, o);
            }
            for d in &digests {
                black_box(Scalar::from_bytes_mod(d));
            }
        });
        let mut map = std::collections::HashMap::new();
        let hmap = best_ns(n, || {
            map.clear();
            for (i, s) in sigs.iter().enumerate() {
                black_box(*map.entry(*s.pubkey).or_insert(i));
            }
        });
        let mut w = Weights::new();
        let weight_one = best_ns(n, || {
            for _ in 0..n {
                black_box(w.weight());
            }
        });
        let mut ws = vec![0u128; 2048];
        let weight_lanes = best_ns(n / 2048 * 2048, || {
            for _ in 0..n / 2048 {
                w.fill(&mut ws);
                black_box(&ws);
            }
        });
        let sc: Vec<Scalar> = sigs.iter().map(|s| Scalar::from_bytes_mod(s.msg)).collect();
        let smul = best_ns(n, || {
            let mut acc = Scalar::ONE;
            for x in &sc {
                acc = acc.mul(x);
            }
            black_box(acc);
        });
        let split = best_ns(n, || {
            for x in &sc {
                black_box(x.split_lambda());
            }
        });
        println!("per signature: challenge {chal_one:.0} ns one at a time, {chal_lanes:.0} ns in lanes; weight {weight_one:.0} ns one at a time, {weight_lanes:.0} ns in lanes; key map {hmap:.0} ns; scalar mul {smul:.0} ns; GLV split {split:.0} ns");
    }

    let one = best_ns(n, || {
        let ok = sigs.iter().filter(|s| verify_one(s)).count();
        assert_eq!(ok, n);
    });
    let mut cached = Verifier::new();
    let one_cached = best_ns(n, || {
        let ok = sigs.iter().filter(|s| cached.verify_one(s)).count();
        assert_eq!(ok, n);
    });
    println!("libsecp256k1 one at a time (lift_x + verify): {one:.0} ns/sig; with the key cache: {one_cached:.0} ns/sig, {:.2}x", one / one_cached);
    let mut v = Verifier::new();
    println!("{:>6} {:>10} {:>8}", "batch", "ns/sig", "speedup");
    for size in [1usize, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
        if size > n {
            break;
        }
        let used = n / size * size;
        let ns = best_ns(used, || {
            for chunk in sigs[..used].chunks(size) {
                assert!(v.verify_all(chunk));
            }
        });
        println!("{size:>6} {ns:>10.0} {:>7.2}x", one / ns);
    }
}

/// MSM method and window per number of terms (128-bit scalars on real pubkeys).
fn tune(lines: &[&str]) {
    let mut parser = EventParser::new();
    let mut rec = Vec::new();
    let mut pts = Vec::new();
    for l in lines.iter().take(20_000) {
        if parse_event_json(l, &mut parser, &mut rec, false).is_ok() {
            if let Some(p) = Affine::lift_x(Record(&rec).pubkey()) {
                pts.push(p);
            }
        }
    }
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut s = msm::Scratch::default();
    println!("ns per term");
    print!("{:>6}", "terms");
    for w in [4, 5] {
        print!(" {:>6}", format!("S{w}"));
    }
    for c in 4..=11 {
        print!(" {:>6}", format!("P{c}"));
    }
    println!();
    // Each cell runs for about 0.1 s, calibrated from one call.
    let cell = |f: &mut dyn FnMut()| -> f64 {
        let t = Instant::now();
        f();
        let one = t.elapsed().as_secs_f64();
        let reps = ((0.1 / one) as usize).clamp(1, 100_000);
        best_ns(reps, || {
            for _ in 0..reps {
                f();
            }
        })
    };
    let min: usize = std::env::var("TUNE_MIN").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    for n in [8usize, 16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384] {
        if n < min {
            continue;
        }
        let terms: Vec<Term> = (0..n).map(|i| Term { point: pts[i % pts.len()], k: u128::from(next()) | (u128::from(next()) << 64) }).collect();
        print!("{n:>6}");
        for w in [4, 5] {
            let ns = cell(&mut || {
                black_box(msm::strauss(&terms, w, &mut s));
            }) / n as f64;
            print!(" {ns:>6.0}");
        }
        for c in 4..=11u32 {
            // Far more buckets than terms only wastes time.
            if (1usize << (c - 1)) > 2 * n.max(8) {
                print!(" {:>6}", "-");
                continue;
            }
            let ns = cell(&mut || {
                black_box(msm::pippenger(&terms, c, &mut s));
            }) / n as f64;
            print!(" {ns:>6.0}");
        }
        println!();
    }
}

