//! A real full disk: the relay's data on a small filesystem (on the box, a
//! tmpfs under /root/bench/adv), which a client fills up. Where the crash
//! torture's disk faults are simulated inside the store, this one is the
//! kernel's ENOSPC, met by the whole relay.
//!
//! 1. A filler file takes all of the filesystem but `room` MiB.
//! 2. A client publishes events one at a time until the relay keeps refusing
//!    them; every OK true is remembered.
//! 3. While full: the relay must stay up and keep serving what it has.
//! 4. The filler goes. The relay must take events again, without a restart.
//! 5. A clean restart: every acknowledged event must be there.

use super::client::{Conn, Opts};
use super::relay::{free_port, Relay};
use crate::sign::Keys;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct Cfg {
    pub bin: PathBuf,
    /// A directory on the small filesystem; the relay's data goes in it.
    pub dir: PathBuf,
    /// MiB left free for the relay.
    pub room: u64,
    pub seed: u64,
    /// Events published after space comes back.
    pub after: usize,
}

/// Fills the filesystem holding `path` with zeros, then gives back `room` MiB.
fn fill(path: &Path, room: u64) -> std::io::Result<u64> {
    let mut f = std::fs::File::create(path)?;
    let chunk = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        match f.write(&chunk) {
            Ok(0) => break,
            Ok(w) => n += w as u64,
            Err(e) if e.raw_os_error() == Some(libc::ENOSPC) => break,
            Err(e) => return Err(e),
        }
    }
    let keep = n.saturating_sub(room << 20);
    f.set_len(keep)?;
    f.sync_all()?;
    Ok(keep)
}

/// Publishes one event and waits for its OK: (accepted, message).
fn publish(c: &mut Conn, ev: &str) -> Result<(bool, String), String> {
    c.send_text(&format!("[\"EVENT\",{ev}]")).map_err(|e| e.to_string())?;
    let t = Instant::now();
    loop {
        let m = c.recv_text().map_err(|e| format!("waiting for OK: {e}"))?;
        let v: serde_json::Value = serde_json::from_str(&m).map_err(|e| e.to_string())?;
        if v[0] == "OK" {
            return Ok((v[2].as_bool().unwrap_or(false), v[3].as_str().unwrap_or("").to_string()));
        }
        if t.elapsed() > Duration::from_secs(30) {
            return Err("no OK within 30 s".into());
        }
    }
}

/// The ids of `ids` the relay has, asked 200 at a time.
fn present(addr: SocketAddr, ids: &[String]) -> Result<std::collections::HashSet<String>, String> {
    let mut c = Conn::connect(addr, &Opts { timeout: Duration::from_secs(30), ..Opts::default() }).map_err(|e| e.to_string())?;
    let mut got = std::collections::HashSet::new();
    for (i, chunk) in ids.chunks(200).enumerate() {
        let sub = format!("d{i}");
        c.send_text(&serde_json::json!(["REQ", sub, {"ids": chunk}]).to_string()).map_err(|e| e.to_string())?;
        loop {
            let m = c.recv_text().map_err(|e| e.to_string())?;
            let v: serde_json::Value = serde_json::from_str(&m).map_err(|e| e.to_string())?;
            match v[0].as_str() {
                Some("EVENT") if v[1] == sub.as_str() => {
                    got.insert(v[2]["id"].as_str().unwrap_or("").to_string());
                }
                Some("EOSE") | Some("CLOSED") if v[1] == sub.as_str() => break,
                _ => {}
            }
        }
    }
    Ok(got)
}

pub fn run(cfg: &Cfg) -> Result<Vec<String>, String> {
    let mut report = Vec::new();
    std::fs::create_dir_all(&cfg.dir).map_err(|e| e.to_string())?;
    let filler = cfg.dir.join("filler");
    let kept = fill(&filler, cfg.room).map_err(|e| format!("filling {}: {e}", filler.display()))?;
    report.push(format!("filler takes {} MiB, {} MiB left", kept >> 20, cfg.room));
    let relay_dir = cfg.dir.join("relay");
    let port = free_port();
    let mut relay = Relay::start_at(&cfg.bin, &relay_dir, port, 2, "").map_err(|e| e.to_string())?;
    let keys = Keys::from_seed(cfg.seed ^ 0xD15C);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let body = "full disk ".repeat(100);
    let mut c = Conn::connect(relay.addr, &Opts { timeout: Duration::from_secs(30), ..Opts::default() }).map_err(|e| e.to_string())?;
    let (mut acked, mut refused, mut streak) = (Vec::new(), 0usize, 0usize);
    let mut n = 0u64;
    let t = Instant::now();
    let mut first_refusal = String::new();
    // 2. Until the relay has refused 200 in a row (or 200k events).
    while streak < 200 && n < 200_000 {
        let (ev, id) = keys.event(now - 100_000 + n, 1, serde_json::json!([["t", "full"]]), &format!("{n} {body}"));
        n += 1;
        match publish(&mut c, &ev) {
            Ok((true, _)) => {
                acked.push(relay_proto::hex::encode_string(&id));
                streak = 0;
            }
            Ok((false, msg)) => {
                refused += 1;
                streak += 1;
                if first_refusal.is_empty() {
                    first_refusal = msg;
                }
            }
            Err(e) => return Err(format!("after {n} events: {e}; relay log: {}", relay.log_tail(10))),
        }
    }
    report.push(format!("{} events acknowledged, {refused} refused (first: {first_refusal:?}) in {:.1} s", acked.len(), t.elapsed().as_secs_f64()));
    if streak < 200 {
        report.push("FINDING: the disk never filled up".into());
    }
    // 3. Full, and still serving.
    if let Some(status) = relay.exited() {
        return Err(format!("FINDING: the relay died on a full disk ({status}): {}", relay.log_tail(15)));
    }
    let sample: Vec<String> = acked.iter().rev().take(500).cloned().collect();
    let have = present(relay.addr, &sample)?;
    if have.len() != sample.len() {
        report.push(format!("FINDING: while full, {} of the last {} acknowledged events cannot be read", sample.len() - have.len(), sample.len()));
    } else {
        report.push(format!("while full: the last {} acknowledged events all read back", sample.len()));
    }
    // 4. Room again: writes must work without a restart.
    std::fs::remove_file(&filler).map_err(|e| e.to_string())?;
    let mut ok_after = 0;
    let mut refused_after = Vec::new();
    for i in 0..cfg.after {
        let (ev, id) = keys.event(now - 50_000 + i as u64, 1, serde_json::json!([["t", "room"]]), &format!("after {i}"));
        match publish(&mut c, &ev) {
            Ok((true, _)) => {
                acked.push(relay_proto::hex::encode_string(&id));
                ok_after += 1;
            }
            Ok((false, msg)) => refused_after.push(msg),
            Err(e) => return Err(format!("after space came back: {e}")),
        }
    }
    if ok_after < cfg.after {
        report.push(format!("FINDING: with room again, {} of {} events refused (first: {:?})", cfg.after - ok_after, cfg.after, refused_after.first()));
    } else {
        report.push(format!("room again: {ok_after} of {} events accepted at once", cfg.after));
    }
    drop(c);
    // 5. A clean restart keeps every acknowledged event.
    let log_before = std::fs::read_to_string(&relay.log).unwrap_or_default();
    relay.stop().map_err(|e| format!("stopping: {e}"))?;
    let relay = Relay::start_at(&cfg.bin, &relay_dir, port, 2, "").map_err(|e| format!("restart: {e}"))?;
    let have = present(relay.addr, &acked)?;
    let missing: Vec<&String> = acked.iter().filter(|id| !have.contains(*id)).collect();
    if missing.is_empty() {
        report.push(format!("after a restart: all {} acknowledged events are there", acked.len()));
    } else {
        report.push(format!("FINDING: after a restart, {} of {} acknowledged events are missing (first {:?})", missing.len(), acked.len(), &missing[..missing.len().min(3)]));
    }
    let errors: Vec<&str> = log_before.lines().filter(|l| l.contains("failed") || l.contains("panicked")).collect();
    report.push(format!("relay log: {} failure lines, first {:?}", errors.len(), errors.first()));
    if log_before.contains("panicked") {
        report.push("FINDING: the relay panicked".into());
    }
    relay.stop().map_err(|e| format!("stopping after the check: {e}"))?;
    Ok(report)
}
