//! Mirrors live traffic from one relay into another: a REQ for everything new
//! on `--from`, each event republished to `--to`, every OK tallied.
//!
//! `cargo run --release -p relay-bench --example mirror -- --from ws://HOST:PORT --to ws://HOST:PORT [--since TS] [--stats SECS]`
//!
//! Used to keep a hidden instance fed with real production traffic. Reconnects
//! on any error; prints a tally line every `--stats` seconds.

use relay_bench::net::{connect, recv_text, resolve, RecvError};
use relay_bench::wire::{parse_relay_msg, RelayMsg};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// The raw event object inside `["EVENT","sub",{...}]`.
fn event_json(msg: &str) -> Option<&str> {
    let start = msg.find('{')?;
    let end = msg.rfind('}')?;
    (end > start).then(|| &msg[start..=end])
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
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
            if let Err(e) = run.await {
                println!("{} reconnecting after: {e}", now());
                since = now();
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    });
}
