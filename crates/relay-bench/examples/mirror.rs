//! Mirrors live traffic from one relay into another: a REQ for everything new
//! on `--from`, each event republished to `--to`, every OK tallied.
//!
//! `cargo run --release -p relay-bench --example mirror -- --from ws://HOST:PORT --to ws://HOST:PORT [--since TS] [--stats SECS]`
//!
//! Used to keep a hidden instance fed with real production traffic. Reconnects
//! on any error; prints a tally line every `--stats` seconds.
//!
//! A live REQ alone misses things: relays cap what a REQ returns from storage
//! (strfry at 500), so after a gap only the newest events come back, and gift
//! wraps are backdated up to two days, so a wrap that arrived during the gap can
//! be older than all of those. strfry's live feed also skips some events outright
//! (measured: about 80 in an hour, mostly backdated). So on every (re)connect,
//! and every ten minutes after, the window is copied page by page on
//! connections of its own, beside the live feed.

use relay_bench::net::{connect, recv_text, resolve, RecvError};
use relay_bench::wire::{parse_relay_msg, RelayMsg};
use std::collections::{BTreeMap, HashSet};
use std::time::{Duration, Instant};

/// Events asked for per backfill page (strfry's cap).
const PAGE: usize = 500;
/// Gift wraps are backdated up to this much (NIP-59).
const BACKDATE: u64 = 2 * 86400;
/// How often the window is copied again while connected.
const REFILL_EVERY: Duration = Duration::from_secs(600);

/// The raw event object inside `["EVENT","sub",{...}]`.
fn event_json(msg: &str) -> Option<&str> {
    let start = msg.find('{')?;
    let end = msg.rfind('}')?;
    (end > start).then(|| &msg[start..=end])
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Copies every event with `created_at >= since` from `from` to `to`, newest
/// first, paging back with `until`. A page's oldest second is asked for again
/// (its other events may not have fit), so ids already sent are skipped.
async fn backfill(from: &str, to: &str, since: u64) -> Result<BTreeMap<String, u64>, String> {
    let mut src = connect(&resolve(from).await?, None).await.map_err(|e| e.to_string())?;
    let mut dst = connect(&resolve(to).await?, None).await.map_err(|e| e.to_string())?;
    let mut tally: BTreeMap<String, u64> = BTreeMap::new();
    let mut sent: HashSet<[u8; 32]> = HashSet::new();
    let mut until = now();
    let mut page = 0u64;
    let drain = |text: &str, tally: &mut BTreeMap<String, u64>| {
        if let RelayMsg::Ok { accepted, msg, .. } = parse_relay_msg(text) {
            let prefix = msg.split(':').next().unwrap_or("").to_string();
            *tally.entry(format!("{}{}", if accepted { "ok " } else { "refused " }, if prefix.is_empty() { "stored".into() } else { prefix })).or_default() += 1;
        }
    };
    while until >= since {
        page += 1;
        let sub = format!("b{page}");
        src.send_text(&format!("[\"REQ\",\"{sub}\",{{\"since\":{since},\"until\":{until},\"limit\":{PAGE}}}]")).await.map_err(|e| e.to_string())?;
        let (mut n, mut oldest) = (0usize, u64::MAX);
        loop {
            let text = recv_text(&mut src, Duration::from_secs(60)).await.map_err(|e| format!("backfill source: {e:?}"))?;
            match parse_relay_msg(&text) {
                RelayMsg::Event { sub: s, id, created_at, .. } if s == sub => {
                    n += 1;
                    oldest = oldest.min(created_at);
                    if sent.insert(id) {
                        if let Some(ev) = event_json(&text) {
                            dst.send_text(&format!("[\"EVENT\",{ev}]")).await.map_err(|e| e.to_string())?;
                            *tally.entry("sent".into()).or_default() += 1;
                        }
                    }
                }
                RelayMsg::Eose { sub: s } if s == sub => break,
                RelayMsg::Closed { sub: s, msg } if s == sub => return Err(format!("backfill refused: {msg}")),
                _ => {}
            }
        }
        src.send_text(&format!("[\"CLOSE\",\"{sub}\"]")).await.map_err(|e| e.to_string())?;
        while let Ok(text) = recv_text(&mut dst, Duration::from_millis(1)).await {
            drain(&text, &mut tally);
        }
        if n == 0 {
            break;
        }
        // A full page all in one second: more of that second than one page holds.
        if oldest >= until {
            if n >= PAGE {
                *tally.entry("crowded seconds".into()).or_default() += 1;
            }
            until = until.saturating_sub(1);
            if until == 0 {
                break;
            }
        } else {
            until = oldest;
        }
    }
    // The last OKs.
    let quiet = Instant::now() + Duration::from_secs(5);
    while Instant::now() < quiet {
        match recv_text(&mut dst, Duration::from_millis(200)).await {
            Ok(text) => drain(&text, &mut tally),
            Err(RecvError::Timeout) => {
                let acked: u64 = tally.iter().filter(|(k, _)| k.starts_with("ok") || k.starts_with("refused")).map(|(_, v)| v).sum();
                if acked >= tally.get("sent").copied().unwrap_or(0) {
                    break;
                }
            }
            Err(e) => return Err(format!("backfill destination: {e:?}")),
        }
    }
    *tally.entry("pages".into()).or_default() = page;
    Ok(tally)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let get = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let from = get("--from").expect("--from ws://...");
    let to = get("--to").expect("--to ws://...");
    let mut since: u64 = get("--since").and_then(|s| s.parse().ok()).unwrap_or_else(now);
    let every = Duration::from_secs(get("--stats").and_then(|s| s.parse().ok()).unwrap_or(60));

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async move {
        let mut tally: BTreeMap<String, u64> = BTreeMap::new();
        let mut last = Instant::now();
        loop {
            let fill = async {
                let mut window_start = since.saturating_sub(BACKDATE);
                loop {
                    let started = now();
                    match backfill(&from, &to, window_start).await {
                        Ok(t) => println!("{} backfill since {window_start} done: {:?}", now(), t),
                        Err(e) => println!("{} backfill since {window_start} failed: {e}", now()),
                    }
                    tokio::time::sleep(REFILL_EVERY).await;
                    window_start = started.saturating_sub(BACKDATE);
                }
            };
            let run = async {
                let mut src = connect(&resolve(&from).await?, None).await.map_err(|e| e.to_string())?;
                let mut dst = connect(&resolve(&to).await?, None).await.map_err(|e| e.to_string())?;
                // Backdated gift wraps carry created_at up to two days in the past,
                // so "new" is defined by arrival: ask for the last two days and let
                // the destination's duplicate check absorb what it already has.
                let req = format!("[\"REQ\",\"m\",{{\"since\":{}}}]", since.saturating_sub(2 * 86400));
                src.send_text(&req).await.map_err(|e| e.to_string())?;
                loop {
                    match recv_text(&mut src, Duration::from_millis(200)).await {
                        Ok(text) => {
                            if let RelayMsg::Event { .. } = parse_relay_msg(&text) {
                                if let Some(ev) = event_json(&text) {
                                    dst.send_text(&format!("[\"EVENT\",{ev}]")).await.map_err(|e| e.to_string())?;
                                    *tally.entry("sent".into()).or_default() += 1;
                                }
                            }
                        }
                        Err(RecvError::Timeout) => {}
                        Err(e) => return Err::<(), String>(format!("source: {e:?}")),
                    }
                    // Drain the destination's OKs without blocking.
                    while let Ok(text) = recv_text(&mut dst, Duration::from_millis(1)).await {
                        if let RelayMsg::Ok { accepted, msg, .. } = parse_relay_msg(&text) {
                            let prefix = msg.split(':').next().unwrap_or("").to_string();
                            *tally.entry(format!("{}{}", if accepted { "ok " } else { "refused " }, if prefix.is_empty() { "stored".into() } else { prefix })).or_default() += 1;
                        }
                    }
                    if last.elapsed() >= every {
                        println!("{} {:?}", now(), tally);
                        last = Instant::now();
                    }
                }
            };
            let result = tokio::select! {
                r = run => r,
                () = fill => unreachable!(),
            };
            if let Err(e) = result {
                println!("{} reconnecting after: {e}", now());
                since = now();
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    });
}
