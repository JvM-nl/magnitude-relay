//! Differential check of two relays: the same REQs to both, answers compared.
//!
//! `cargo run --release -p relay-bench --example diff -- --a ws://HOST:PORT --b ws://HOST:PORT --filters FILE [--max N]`
//!
//! FILE holds one filter JSON object per line. Each REQ goes to both relays (one
//! connection each, one request at a time, so a production relay sees only light
//! read traffic). Answers are compared as id sets; ordering within a second is a
//! known difference (strfry orders ties by insertion, NIP-01 by id) and is not
//! counted. Every differing request is printed with what only one side returned.

use relay_bench::net::{connect, recv_text, resolve};
use relay_bench::wire::{parse_relay_msg, RelayMsg};
use relay_proto::hex;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

async fn ask(c: &mut relay_bench::net::Conn, n: usize, filter: &str) -> Result<(Vec<([u8; 32], u64)>, Duration), String> {
    let sub = format!("d{n}");
    let t = Instant::now();
    c.send_text(&format!("[\"REQ\",\"{sub}\",{filter}]")).await.map_err(|e| e.to_string())?;
    let mut got = Vec::new();
    loop {
        let text = recv_text(c, Duration::from_secs(30)).await.map_err(|e| format!("{e:?}"))?;
        match parse_relay_msg(&text) {
            RelayMsg::Event { sub: s, id, created_at, .. } if s == sub => got.push((id, created_at)),
            RelayMsg::Eose { sub: s } if s == sub => break,
            RelayMsg::Closed { sub: s, msg } if s == sub => return Err(format!("CLOSED {msg}")),
            RelayMsg::Notice(m) => return Err(format!("NOTICE {m}")),
            _ => {}
        }
    }
    let dt = t.elapsed();
    c.send_text(&format!("[\"CLOSE\",\"{sub}\"]")).await.map_err(|e| e.to_string())?;
    Ok((got, dt))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let a_url = get("--a").expect("--a ws://...");
    let b_url = get("--b").expect("--b ws://...");
    let file = get("--filters").expect("--filters FILE");
    let max: usize = get("--max").and_then(|m| m.parse().ok()).unwrap_or(usize::MAX);
    let filters: Vec<String> = std::fs::read_to_string(&file).expect("filters file").lines().filter(|l| !l.trim().is_empty()).take(max).map(String::from).collect();

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async move {
        let ta = resolve(&a_url).await.expect("a url");
        let tb = resolve(&b_url).await.expect("b url");
        let mut ca = connect(&ta, None).await.expect("connect a");
        let mut cb = connect(&tb, None).await.expect("connect b");
        let (mut same, mut differ, mut errors) = (0usize, 0usize, 0usize);
        let (mut ta_total, mut tb_total) = (Duration::ZERO, Duration::ZERO);
        let (mut events_a, mut events_b) = (0usize, 0usize);
        let (mut only_a_total, mut only_b_total) = (0usize, 0usize);
        for (n, f) in filters.iter().enumerate() {
            let (ra, rb) = (ask(&mut ca, n, f).await, ask(&mut cb, n, f).await);
            let ((ga, da), (gb, db)) = match (ra, rb) {
                (Ok(a), Ok(b)) => (a, b),
                (ra, rb) => {
                    errors += 1;
                    println!("ERROR {f}\n  a: {:?}\n  b: {:?}", ra.err(), rb.err());
                    continue;
                }
            };
            ta_total += da;
            tb_total += db;
            events_a += ga.len();
            events_b += gb.len();
            let sa: BTreeSet<[u8; 32]> = ga.iter().map(|x| x.0).collect();
            let sb: BTreeSet<[u8; 32]> = gb.iter().map(|x| x.0).collect();
            if sa == sb {
                same += 1;
                continue;
            }
            // A limit cut inside a tied second may pick different members: not a
            // real difference when every differing event shares the oldest second.
            let oldest = |g: &[([u8; 32], u64)]| g.iter().map(|x| x.1).min();
            let only_a: Vec<_> = ga.iter().filter(|x| !sb.contains(&x.0)).collect();
            let only_b: Vec<_> = gb.iter().filter(|x| !sa.contains(&x.0)).collect();
            let boundary = ga.len() == gb.len()
                && only_a.iter().all(|x| Some(x.1) == oldest(&ga))
                && only_b.iter().all(|x| Some(x.1) == oldest(&gb));
            if boundary {
                same += 1;
                continue;
            }
            differ += 1;
            only_a_total += only_a.len();
            only_b_total += only_b.len();
            println!(
                "DIFF {f}\n  a returned {} events, b {}; only in a: {} {}; only in b: {} {}",
                ga.len(),
                gb.len(),
                only_a.len(),
                only_a.iter().take(3).map(|x| hex::encode_string(&x.0[..6])).collect::<Vec<_>>().join(","),
                only_b.len(),
                only_b.iter().take(3).map(|x| hex::encode_string(&x.0[..6])).collect::<Vec<_>>().join(",")
            );
        }
        let n = filters.len().max(1) as f64;
        println!(
            "\n{} requests: {same} identical, {differ} differ, {errors} errors; events a {events_a}, b {events_b}; only-in-a {only_a_total}, only-in-b {only_b_total}",
            filters.len()
        );
        println!("mean time to EOSE: a {:.0} us, b {:.0} us", ta_total.as_secs_f64() * 1e6 / n, tb_total.as_secs_f64() * 1e6 / n);
    });
}
