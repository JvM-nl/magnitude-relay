//! End to end: the real binary, real sockets, Vector-shaped traffic.

use relay_net::conn::{client_connect, ClientConn, Message};
use relay_proto::hex;
use secp256k1::{schnorr, Keypair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Relay {
    child: Child,
    addr: SocketAddr,
    dir: PathBuf,
}

impl Relay {
    fn start(dir: PathBuf, port: u16) -> Relay {
        Self::start_with(dir, port, "")
    }

    /// `store` is extra lines for the `[store]` section.
    fn start_with(dir: PathBuf, port: u16, store: &str) -> Relay {
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("relay.toml");
        std::fs::write(
            &cfg,
            format!("[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = 2\n[limits]\nevents_per_minute_per_ip = 0\n[store]\ndata = \"{}\"\n{store}", dir.join("data").display()),
        )
        .unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_magnitude-relay"))
            .arg("--config")
            .arg(&cfg)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let t = Instant::now();
        while std::net::TcpStream::connect(addr).is_err() {
            assert!(t.elapsed() < Duration::from_secs(10), "relay did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        Relay { child, addr, dir }
    }

    fn stop(mut self) -> PathBuf {
        // SIGTERM: the graceful path.
        unsafe { libc_kill(self.child.id() as i32, 15) };
        let t = Instant::now();
        while self.child.try_wait().unwrap().is_none() {
            assert!(t.elapsed() < Duration::from_secs(10), "relay did not stop on SIGTERM");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::mem::take(&mut self.dir)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

extern "C" {
    #[link_name = "kill"]
    fn libc_kill(pid: i32, sig: i32) -> i32;
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Signer(Keypair);
impl Signer {
    fn new(seed: u8) -> Signer {
        Signer(Keypair::from_secret_bytes([seed; 32]).unwrap())
    }
    fn pk(&self) -> String {
        hex::encode_string(&self.0.x_only_public_key().0.to_byte_array())
    }
    fn event(&self, created_at: u64, kind: u64, tags: Value, content: &str) -> Value {
        let pk = self.pk();
        let pre = serde_json::to_string(&json!([0, pk, created_at, kind, tags, content])).unwrap();
        let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
        let sig = schnorr::sign_no_aux_rand(&id, &self.0);
        json!({"id": hex::encode_string(&id), "pubkey": pk, "created_at": created_at, "kind": kind, "tags": tags, "content": content, "sig": hex::encode_string(&sig.to_byte_array())})
    }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

async fn send(c: &mut ClientConn, v: Value) {
    c.send_text(&v.to_string()).await.unwrap();
}

async fn recv(c: &mut ClientConn) -> Value {
    loop {
        match tokio::time::timeout(Duration::from_secs(5), c.recv()).await.expect("timed out waiting for a message").unwrap() {
            Message::Text(t) => return serde_json::from_str(&t).unwrap(),
            _ => continue,
        }
    }
}

/// Reads until EOSE (or CLOSED) for `sub`, returning the events.
async fn collect(c: &mut ClientConn, sub: &str) -> (Vec<Value>, Value) {
    let mut evs = Vec::new();
    loop {
        let m = recv(c).await;
        match m[0].as_str().unwrap() {
            "EVENT" if m[1] == sub => evs.push(m[2].clone()),
            "EOSE" | "CLOSED" if m[1] == sub => return (evs, m),
            _ => {}
        }
    }
}

async fn ok_of(c: &mut ClientConn) -> (bool, String) {
    loop {
        let m = recv(c).await;
        if m[0] == "OK" {
            return (m[2].as_bool().unwrap(), m[3].as_str().unwrap().to_string());
        }
    }
}

#[tokio::test]
async fn vector_flows_end_to_end() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir, port);
    let host = format!("127.0.0.1:{port}");

    let me = Signer::new(1);
    let sender = Signer::new(2);
    let mut a = client_connect(relay.addr, &host, "/").await.unwrap();
    let mut b = client_connect(relay.addr, &host, "/").await.unwrap();

    // A: live DM subscription, Vector's exact shape.
    send(&mut a, json!(["REQ", "dm", {"kinds": [1059], "#p": [me.pk()], "limit": 0}])).await;
    let (evs, end) = collect(&mut a, "dm").await;
    assert!(evs.is_empty());
    assert_eq!(end[0], "EOSE");

    // B publishes a wrap (backdated a day, as NIP-17 does); A gets it live.
    let wrap = sender.event(now() - 86_400, 1059, json!([["p", me.pk()]]), "ciphertext");
    let t = Instant::now();
    send(&mut b, json!(["EVENT", wrap])).await;
    assert_eq!(ok_of(&mut b).await, (true, String::new()));
    let live = recv(&mut a).await;
    let latency = t.elapsed();
    assert_eq!(live[0], "EVENT");
    assert_eq!(live[1], "dm");
    assert_eq!(live[2]["id"], wrap["id"]);
    eprintln!("publish -> OK -> live delivery: {latency:?}");

    // A resend is a duplicate, answered without storing again.
    send(&mut b, json!(["EVENT", wrap])).await;
    let (okv, msg) = ok_of(&mut b).await;
    assert!(okv && msg.starts_with("duplicate:"), "{msg}");

    // History and COUNT.
    send(&mut a, json!(["REQ", "hist", {"kinds": [1059], "#p": [me.pk()]}])).await;
    let (evs, _) = collect(&mut a, "hist").await;
    assert_eq!(evs.len(), 1);
    assert_eq!(serde_json::to_string(&evs[0]).unwrap().len(), wrap.to_string().len());
    send(&mut a, json!(["COUNT", "c", {"kinds": [1059], "#p": [me.pk()]}])).await;
    let m = recv(&mut a).await;
    assert_eq!(m, json!(["COUNT", "c", {"count": 1}]));

    // NIP-77: Vector's DM sync. The client holds the first wrap plus one the
    // relay never saw; the relay holds three more. The reference client must
    // learn exactly which three to fetch.
    let mut more = Vec::new();
    for i in 0..3 {
        let w = sender.event(now() - 3600 * (i + 2), 1059, json!([["p", me.pk()]]), &format!("w{i}"));
        send(&mut b, json!(["EVENT", w])).await;
        assert!(ok_of(&mut b).await.0);
        more.push(w["id"].as_str().unwrap().to_string());
    }
    {
        use negentropy::{Id, Negentropy, NegentropyStorageVector};
        let mut st = NegentropyStorageVector::new();
        let held = [(wrap["created_at"].as_u64().unwrap(), wrap["id"].as_str().unwrap().to_string()), (now() - 99_999, "ab".repeat(32))];
        for (t, id) in &held {
            st.insert(*t, Id::from_byte_array(hex::decode_32(id.as_bytes()).unwrap())).unwrap();
        }
        st.seal().unwrap();
        let mut neg = Negentropy::owned(st, 60_000).unwrap();
        let init = neg.initiate().unwrap();
        send(&mut a, json!(["NEG-OPEN", "neg", {"kinds": [1059], "#p": [me.pk()]}, hex::encode_string(&init)])).await;
        let (mut have, mut need) = (Vec::new(), Vec::new());
        loop {
            // The live "dm" subscription is still open, so the new wraps arrive too.
            let m = loop {
                let m = recv(&mut a).await;
                if m[0] != "EVENT" {
                    break m;
                }
            };
            assert_eq!(m[0], "NEG-MSG", "{m}");
            let bytes = hex::decode_any_case(m[2].as_str().unwrap().as_bytes()).unwrap();
            match neg.reconcile_with_ids(&bytes, &mut have, &mut need).unwrap() {
                Some(next) => send(&mut a, json!(["NEG-MSG", "neg", hex::encode_string(&next)])).await,
                None => break,
            }
        }
        send(&mut a, json!(["NEG-CLOSE", "neg"])).await;
        let mut need: Vec<String> = need.iter().map(|i| hex::encode_string(i.as_bytes())).collect();
        need.sort();
        more.sort();
        assert_eq!(need, more);
        assert_eq!(have.len(), 1, "the wrap the relay never saw");
    }

    // Ephemeral Concord wrap: delivered live, never stored.
    let plane = Signer::new(3);
    send(&mut a, json!(["REQ", "plane", {"kinds": [1059, 21059], "authors": [plane.pk()], "since": now() - 300, "limit": 0}])).await;
    collect(&mut a, "plane").await;
    let typing = plane.event(now(), 21059, json!([["p", Signer::new(9).pk()]]), "typing");
    send(&mut b, json!(["EVENT", typing])).await;
    assert_eq!(ok_of(&mut b).await, (true, String::new()));
    let m = recv(&mut a).await;
    assert_eq!((m[0].as_str(), m[1].as_str()), (Some("EVENT"), Some("plane")));
    send(&mut a, json!(["REQ", "plane2", {"kinds": [21059], "authors": [plane.pk()]}])).await;
    assert!(collect(&mut a, "plane2").await.0.is_empty(), "ephemeral events are not stored");

    // Policy: public notes are refused; forged signatures are refused.
    send(&mut b, json!(["EVENT", sender.event(now(), 1, json!([]), "hello world")])).await;
    let (okv, msg) = ok_of(&mut b).await;
    assert!(!okv && msg.starts_with("blocked:"), "{msg}");
    let mut forged = sender.event(now(), 1059, json!([["p", me.pk()]]), "x");
    forged["sig"] = json!("00".repeat(64));
    send(&mut b, json!(["EVENT", forged])).await;
    let (okv, msg) = ok_of(&mut b).await;
    assert!(!okv && msg.contains("signature"), "{msg}");

    // No bulk scraping of gift wraps.
    send(&mut a, json!(["REQ", "scrape", {"kinds": [1059], "limit": 10}])).await;
    let (_, end) = collect(&mut a, "scrape").await;
    assert_eq!(end[0], "CLOSED");
    assert!(end[2].as_str().unwrap().starts_with("restricted:"));

    // NIP-11 over plain HTTP.
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\nAccept: application/nostr+json\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let body = &resp[resp.find("\r\n\r\n").unwrap() + 4..];
    let info: Value = serde_json::from_str(body).unwrap();
    assert!(info["supported_nips"].as_array().unwrap().contains(&json!(77)));
    assert!(!info["supported_nips"].as_array().unwrap().contains(&json!(42)));

    // Stats and metrics over plain HTTP.
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert!(stats["events_stored"].as_u64().unwrap() >= 4, "{stats}");
    assert!(stats["reqs"].as_u64().unwrap() >= 4);
    assert_eq!(stats["store"]["live"].as_u64().unwrap(), 4);

    // A clean restart keeps everything.
    drop((a, b));
    let dir = relay.stop();
    let relay = Relay::start(dir, port);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["REQ", "again", {"ids": [wrap["id"]], "kinds": [1059], "#p": [me.pk()]}])).await;
    let (evs, _) = collect(&mut c, "again").await;
    assert_eq!(evs.len(), 1);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// Every log file under the relay's data directory, read whole.
fn log_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    let mut stack = vec![dir.join("data").join("log")];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            if e.path().is_dir() {
                stack.push(e.path());
            } else {
                out.extend(std::fs::read(e.path()).unwrap());
            }
        }
    }
    out
}

#[tokio::test]
async fn deleted_content_leaves_the_disk_with_idle_reactors() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-zero-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    // Small log segments, so the files can be read whole while polling.
    let relay = Relay::start_with(dir.clone(), port, "segment_mb = 16\n");
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(7);
    let secret = "SECRET-SETTINGS-QQQQ";
    let ev = me.event(now(), 30078, json!([["d", "vector/settings"]]), secret);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["EVENT", ev])).await;
    assert!(ok_of(&mut c).await.0);
    let del = me.event(now(), 5, json!([["e", ev["id"]]]), "");
    send(&mut c, json!(["EVENT", del])).await;
    assert!(ok_of(&mut c).await.0);
    drop(c);
    // Nothing else talks to the relay: its other reactor still holds the
    // snapshot it took at startup, from before the deletion.
    let t = Instant::now();
    while log_bytes(&dir).windows(secret.len()).any(|w| w == secret.as_bytes()) {
        assert!(t.elapsed() < Duration::from_secs(5), "deleted content still on disk after 5 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn compressing_clients_get_stateless_deflate() {
    use relay_net::conn::{client_connect_with, ClientDeflate};
    use relay_net::ws::Role;
    let dir = std::env::temp_dir().join(format!("relay-e2e-deflate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(9);

    // A browser-style offer (context takeover both ways): the relay answers
    // stateless, so it keeps no codec memory for this connection.
    let mut c = client_connect_with(relay.addr, &host, "/", Some(ClientDeflate::default())).await.unwrap();
    let p = *c.deflate_params().expect("deflate negotiated");
    assert!(!p.send(Role::Server).context_takeover && !p.send(Role::Client).context_takeover);

    // Big enough to be compressed both ways; repetitive enough to show it.
    let content = "vector settings ".repeat(400);
    let ev = me.event(now(), 30078, json!([["d", "vector/settings"]]), &content);
    send(&mut c, json!(["EVENT", ev])).await;
    assert!(ok_of(&mut c).await.0);
    send(&mut c, json!(["REQ", "s", {"kinds": [30078], "authors": [me.pk()]}])).await;
    let (evs, end) = collect(&mut c, "s").await;
    assert_eq!(end[0], "EOSE");
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0]["content"], content);
    assert_eq!(evs[0]["id"], ev["id"]);

    // A client that offers nothing still gets plain frames.
    let mut plain = client_connect(relay.addr, &host, "/").await.unwrap();
    assert!(plain.deflate_params().is_none());
    send(&mut plain, json!(["REQ", "s", {"kinds": [30078], "authors": [me.pk()]}])).await;
    let (evs, _) = collect(&mut plain, "s").await;
    assert_eq!(evs[0]["content"], content);

    // Counted.
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(stats["connections_deflate"].as_u64(), Some(1), "{stats}");
    // The plain client got the 6.4 KB event as is; the compressing one a few
    // hundred bytes for it.
    let out = stats["bytes_out"].as_u64().unwrap();
    eprintln!("bytes out: {out}");
    assert!(out < 9_000, "the event went out uncompressed to both: {out} bytes");

    drop((c, plain));
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn large_live_events_reach_every_subscriber_intact() {
    use relay_net::conn::{client_connect_with, ClientDeflate};
    let dir = std::env::temp_dir().join(format!("relay-e2e-share-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(11);
    let author = Signer::new(12);

    // Two plain subscribers (they share each large event's bytes), one that
    // compresses (it gets its own), and one that stops reading for a while.
    let filter = json!({"kinds": [1059], "#p": [me.pk()], "limit": 0});
    let mut subs = Vec::new();
    for i in 0..4 {
        let mut c = if i == 2 {
            client_connect_with(relay.addr, &host, "/", Some(ClientDeflate::default())).await.unwrap()
        } else {
            client_connect(relay.addr, &host, "/").await.unwrap()
        };
        send(&mut c, json!(["REQ", format!("s{i}"), filter])).await;
        let (_, end) = collect(&mut c, &format!("s{i}")).await;
        assert_eq!(end[0], "EOSE");
        subs.push(c);
    }

    // A burst of large wraps, interleaved with small ones (which are copied).
    let mut publisher = client_connect(relay.addr, &host, "/").await.unwrap();
    let mut sent = Vec::new();
    for n in 0..200u64 {
        let size = if n % 5 == 0 { 300 } else { 4000 + (n as usize * 37) % 3000 };
        let content: String = (0..size).map(|k| (b'a' + ((k as u64 + n) % 26) as u8) as char).collect();
        let ev = author.event(now() - n, 1059, json!([["p", me.pk()]]), &content);
        send(&mut publisher, json!(["EVENT", ev])).await;
        sent.push(ev);
    }
    for _ in 0..sent.len() {
        assert!(ok_of(&mut publisher).await.0);
    }

    // Every subscriber, the slow one included, gets every event, in order, byte for byte.
    for (i, c) in subs.iter_mut().enumerate() {
        if i == 3 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        for (n, ev) in sent.iter().enumerate() {
            let m = recv(c).await;
            assert_eq!(m[0], "EVENT", "subscriber {i}, event {n}: {m}");
            assert_eq!(m[1], format!("s{i}"));
            assert_eq!(&m[2], ev, "subscriber {i}, event {n}");
        }
    }

    // The large ones went out shared to the three plain subscribers.
    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(stats["events_shared"].as_u64(), Some(160 * 3), "{stats}");

    drop((subs, publisher));
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

/// Runs one of the binary's commands against the relay whose settings are in
/// `dir`: (success, stdout, stderr).
fn run(dir: &std::path::Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_magnitude-relay")).arg("--config").arg(dir.join("relay.toml")).args(args).output().unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

/// A command that must succeed; its stdout.
fn run_ok(dir: &std::path::Path, args: &[&str]) -> String {
    let (ok, out, err) = run(dir, args);
    assert!(ok, "{args:?} failed: {err}");
    out
}

/// A command that must be refused, whose complaint contains `why`.
fn run_refused(dir: &std::path::Path, args: &[&str], why: &str) {
    let (ok, out, err) = run(dir, args);
    assert!(!ok, "{args:?} should have been refused; it printed {out:?}");
    assert!(err.contains(why), "{args:?}: wanted {why:?} in {err:?}");
}

/// The ids of the JSONL events a command printed, in order.
fn ids_printed(out: &str) -> Vec<String> {
    out.lines().map(|l| serde_json::from_str::<Value>(l).unwrap()["id"].as_str().unwrap().to_string()).collect()
}

async fn ids_over_req(relay: &Relay, filter: Value) -> Vec<String> {
    let host = relay.addr.to_string();
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["REQ", "r", filter])).await;
    let (evs, _) = collect(&mut c, "r").await;
    evs.iter().map(|e| e["id"].as_str().unwrap().to_string()).collect()
}

#[tokio::test]
async fn operator_commands_reach_a_running_relay_and_a_stopped_one() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("relay-e2e-adm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let (me, other) = (Signer::new(11), Signer::new(12));

    // Four wraps to `me`, 4000 to 1000 seconds old, and a profile each.
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let mut wrap_events = Vec::new();
    for age in [4000, 3000, 2000, 1000] {
        let wrap = other.event(now() - age, 1059, json!([["p", me.pk()]]), &format!("wrap {age}"));
        send(&mut c, json!(["EVENT", wrap])).await;
        assert!(ok_of(&mut c).await.0);
        wrap_events.push(wrap);
    }
    let wraps: Vec<String> = wrap_events.iter().map(|w| w["id"].as_str().unwrap().to_string()).collect();
    let mut profiles = Vec::new();
    for s in [&me, &other] {
        let p = s.event(now() - 10, 0, json!([]), "{}");
        send(&mut c, json!(["EVENT", p])).await;
        assert!(ok_of(&mut c).await.0);
        profiles.push(p["id"].as_str().unwrap().to_string());
    }
    drop(c);
    let to_me = json!({"kinds": [1059], "#p": [me.pk()]});
    let newest_first = |ids: &[String]| ids.iter().rev().cloned().collect::<Vec<_>>();

    // The socket is there, and only its owner can open it.
    let sock = dir.join("data").join("admin.sock");
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(!dir.join("data").join("admin.tmp").exists(), "the staging directory is gone");

    // Reading through the running relay.
    assert_eq!(run_ok(&dir, &["count", "--filter", r#"{"kinds":[1059]}"#]), "4\n");
    assert_eq!(run_ok(&dir, &["count", "--filter", r#"[{"kinds":[1059]},{"kinds":[0]},{"kinds":[1059,0]}]"#]), "6\n", "a union counts an event once");
    let q = run_ok(&dir, &["query", "--filter", r#"{"kinds":[1059]}"#]);
    assert_eq!(ids_printed(&q), newest_first(&wraps));
    // The same bytes REQ would send for it.
    let first: Value = serde_json::from_str(q.lines().next().unwrap()).unwrap();
    assert_eq!(first["content"], "wrap 1000");
    assert_eq!(ids_printed(&run_ok(&dir, &["query", "--filter", r#"{"kinds":[1059]}"#, "--limit", "2"])), newest_first(&wraps)[..2]);

    // Refusals change nothing.
    run_refused(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#], "--dry-run");
    run_refused(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--dry-run", "--yes"], "not both");
    run_refused(&dir, &["delete", "--filter", "{}", "--yes"], "--all");
    run_refused(&dir, &["delete", "--filter", "{}", "--dry-run"], "--all");
    run_refused(&dir, &["delete", "--filter", r#"[{"kinds":[1059]},{}]"#, "--age", "5", "--yes"], "--all");
    run_refused(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes", "--agee", "5"], "unexpected argument");
    run_refused(&dir, &["delete", "--filter", r#"{"kinds":[1059],"limit":1}"#, "--yes"], "limit");
    run_refused(&dir, &["delete", "--yes"], "needs --filter");
    run_refused(&dir, &["query", "--filter", r#"{"kinds":[1059]"#], "bad");
    assert_eq!(run_ok(&dir, &["count", "--filter", "[{}]"]), "6\n");

    // A dry run says what would go and touches nothing.
    let dry = run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--dry-run"]);
    assert!(dry.starts_with("would delete 4 events"), "{dry}");
    for id in &wraps {
        assert!(dry.contains(id.as_str()), "{id} not among the samples: {dry}");
    }
    assert!(dry.contains("kind 1059") && dry.contains(&other.pk()[..8]), "{dry}");
    let aged = run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--age", "2500", "--dry-run"]);
    assert!(aged.starts_with("would delete 2 events"), "{aged}");
    run_refused(&dir, &["count", "--filter", "{}", "--age", "5"], "unexpected argument");
    assert_eq!(ids_over_req(&relay, to_me.clone()).await.len(), 4);

    // Delete the old ones, then the rest: gone for a client too, and the
    // profiles are never touched.
    assert_eq!(run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--age", "2500", "--yes"]), "deleted 2 events\n");
    assert_eq!(ids_over_req(&relay, to_me.clone()).await, newest_first(&wraps[2..]));
    assert_eq!(run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes"]), "deleted 2 events\n");
    assert!(ids_over_req(&relay, to_me.clone()).await.is_empty());
    assert_eq!(run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes"]), "deleted 0 events\n");
    assert_eq!(ids_over_req(&relay, json!({"kinds": [0]})).await.len(), 2);
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "2\n");
    assert_eq!(ids_printed(&run_ok(&dir, &["query", "--filter", "{}"])).len(), 2);

    // A deleted event can be published again: no tombstone is kept.
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["EVENT", wrap_events[3]])).await;
    assert!(ok_of(&mut c).await.0);
    drop(c);
    assert_eq!(ids_over_req(&relay, to_me.clone()).await, vec![wraps[3].clone()]);
    assert_eq!(run_ok(&dir, &["delete", "--filter", r#"{"kinds":[1059]}"#, "--yes"]), "deleted 1 event\n");

    // Stopped cleanly, the relay takes its socket with it. The same commands
    // now open the data directory.
    let dir = relay.stop();
    assert!(!sock.exists(), "the socket is removed on clean shutdown");
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "2\n");
    let mut stored = ids_printed(&run_ok(&dir, &["query", "--filter", r#"{"kinds":[0]}"#]));
    stored.sort();
    let mut want = profiles.clone();
    want.sort();
    assert_eq!(stored, want);
    assert_eq!(run_ok(&dir, &["count", "--filter", r#"{"kinds":[1059]}"#]), "0\n");
    let dry = run_ok(&dir, &["delete", "--filter", &format!(r#"{{"authors":["{}"]}}"#, other.pk()), "--dry-run"]);
    assert!(dry.starts_with("would delete 1 event "), "{dry}");
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "2\n");
    assert_eq!(run_ok(&dir, &["delete", "--filter", &format!(r#"{{"authors":["{}"]}}"#, other.pk()), "--yes"]), "deleted 1 event\n");
    assert_eq!(ids_printed(&run_ok(&dir, &["query", "--filter", "{}"])), vec![profiles[0].clone()]);

    // Neither delete came back with a restart.
    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    assert_eq!(ids_over_req(&relay, json!({"kinds": [0]})).await, vec![profiles[0].clone()]);
    assert!(ids_over_req(&relay, to_me).await.is_empty());
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn operator_deleted_content_leaves_the_disk() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-adm-zero-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    let relay = Relay::start_with(dir.clone(), port, "segment_mb = 16\n");
    let host = format!("127.0.0.1:{port}");
    let me = Signer::new(31);
    let secret = "SECRET-NOTE-WWWW";
    let ev = me.event(now(), 30078, json!([["d", "notes"]]), secret);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    send(&mut c, json!(["EVENT", ev])).await;
    assert!(ok_of(&mut c).await.0);
    drop(c);
    assert!(log_bytes(&dir).windows(secret.len()).any(|w| w == secret.as_bytes()));

    let by_id = format!(r#"{{"ids":["{}"]}}"#, ev["id"].as_str().unwrap());
    assert_eq!(run_ok(&dir, &["delete", "--filter", &by_id, "--yes"]), "deleted 1 event\n");
    // The relay's own readers and the command's snapshot are gone a moment
    // later, and then the bytes are too.
    let t = Instant::now();
    while log_bytes(&dir).windows(secret.len()).any(|w| w == secret.as_bytes()) {
        assert!(t.elapsed() < Duration::from_secs(5), "deleted content still on disk after 5 s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_crashed_relays_admin_socket_is_replaced() {
    use std::os::unix::net::UnixListener;
    let dir = std::env::temp_dir().join(format!("relay-e2e-stale-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // What a killed relay leaves: a socket file no one is listening on.
    let sock = dir.join("data").join("admin.sock");
    std::fs::create_dir_all(sock.parent().unwrap()).unwrap();
    drop(UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());

    let relay = Relay::start(dir.clone(), free_port());
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "0\n");
    let dir = relay.stop();
    assert!(!sock.exists());

    // A file that is not a socket is left alone, and the relay serves without it.
    std::fs::write(&sock, "mine").unwrap();
    let relay = Relay::start(dir.clone(), free_port());
    assert_eq!(std::fs::read_to_string(&sock).unwrap(), "mine");
    run_refused(&dir, &["count", "--filter", "{}"], "admin socket");
    let dir = relay.stop();
    assert_eq!(std::fs::read_to_string(&sock).unwrap(), "mine");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_big_delete_runs_beside_live_writes() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("relay-e2e-big-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Settings written by a first start; then 60,000 events loaded offline.
    drop(Relay::start(dir.clone(), free_port()).stop());
    let n = 60_000u64;
    let file = dir.join("in.jsonl");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&file).unwrap());
    for i in 0..n {
        let (id, pk) = (format!("{:064x}", i + 1), format!("{:064x}", i % 7 + 1));
        let (at, sig) = (1_700_000_000 + i, "00".repeat(64));
        writeln!(f, r#"{{"content":"x","created_at":{at},"id":"{id}","kind":14,"pubkey":"{pk}","sig":"{sig}","tags":[]}}"#).unwrap();
    }
    drop(f);
    run_ok(&dir, &["import", "--no-verify", file.to_str().unwrap()]);
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), format!("{n}\n"));

    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let mut delete = Command::new(env!("CARGO_BIN_EXE_magnitude-relay"))
        .arg("--config")
        .arg(dir.join("relay.toml"))
        .args(["delete", "--filter", r#"{"kinds":[14]}"#, "--yes"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Writes made while it runs are all accepted.
    let me = Signer::new(21);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let mut slowest = Duration::ZERO;
    for i in 0..40 {
        let ev = me.event(now(), 30078, json!([["d", format!("note-{i}")]]), "live");
        let t = Instant::now();
        send(&mut c, json!(["EVENT", ev])).await;
        assert!(ok_of(&mut c).await.0);
        slowest = slowest.max(t.elapsed());
    }
    eprintln!("slowest OK while the delete ran: {slowest:?} (delete still running afterwards: {})", delete.try_wait().unwrap().is_none());
    let out = delete.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("deleted {n} events\n"));
    assert_eq!(run_ok(&dir, &["count", "--filter", r#"{"kinds":[14]}"#]), "0\n");
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), "40\n", "the live writes are all there, and nothing else");
    assert_eq!(ids_over_req(&relay, json!({"kinds": [30078], "authors": [me.pk()]})).await.len(), 40);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn counts_are_exact_and_big_ones_leave_the_reactors() {
    let dir = std::env::temp_dir().join(format!("relay-e2e-count-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let port = free_port();
    // Settings first, then a mailbox of 60 000 wraps loaded unsigned (signing
    // that many in a debug build would take minutes).
    relay_stop_quietly(Relay::start(dir.clone(), port));
    let hex = |b: u8, n: u64| {
        let mut v = [b; 32];
        v[..8].copy_from_slice(&n.to_le_bytes());
        hex::encode_string(&v)
    };
    let (big, small) = (hex(0xB1, 0), hex(0xB2, 0));
    let mut lines = String::new();
    for n in 0..60_100u64 {
        let to = if n < 60_000 { &big } else { &small };
        lines.push_str(&format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":{},"kind":1059,"tags":[["p","{to}"]],"content":"w","sig":"{}"}}"#,
            hex(0xEE, n),
            hex(0xC0, n),
            1_700_000_000 + n,
            "00".repeat(64)
        ));
        lines.push('\n');
    }
    let file = dir.join("wraps.jsonl");
    std::fs::write(&file, lines).unwrap();
    run_ok(&dir, &["import", "--no-verify", file.to_str().unwrap()]);

    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    let count = |sub: &str, filters: Vec<Value>| {
        let mut m = vec![json!("COUNT"), json!(sub)];
        m.extend(filters);
        Value::Array(m)
    };
    // Small: answered on the spot. Big: by a counting worker. Both exact.
    send(&mut c, count("s", vec![json!({"kinds": [1059], "#p": [small]})])).await;
    let m = recv(&mut c).await;
    assert_eq!(m, json!(["COUNT", "s", {"count": 100}]));
    send(&mut c, count("b", vec![json!({"kinds": [1059], "#p": [big]})])).await;
    let m = recv(&mut c).await;
    assert_eq!(m, json!(["COUNT", "b", {"count": 60_000}]), "exact, no approximation");
    // A union counts each event once.
    send(&mut c, count("u", vec![json!({"kinds": [1059], "#p": [big]}), json!({"kinds": [1059], "#p": [big, small]})])).await;
    assert_eq!(recv(&mut c).await, json!(["COUNT", "u", {"count": 60_100}]));
    // A window inside the big mailbox.
    send(&mut c, count("w", vec![json!({"kinds": [1059], "#p": [big], "since": 1_700_010_000u64, "until": 1_700_019_999u64})])).await;
    assert_eq!(recv(&mut c).await, json!(["COUNT", "w", {"count": 10_000}]));

    let mut s = tokio::net::TcpStream::connect(relay.addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET /stats HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let stats: Value = serde_json::from_str(&resp[resp.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(stats["counts_offloaded"].as_u64(), Some(2), "{stats}");

    drop(c);
    let dir = relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}

fn relay_stop_quietly(r: Relay) {
    let _ = r.stop();
}

#[tokio::test]
async fn a_backup_runs_beside_live_writes_and_restores() {
    use std::io::Write;
    let dir = std::env::temp_dir().join(format!("relay-e2e-backup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    drop(Relay::start(dir.clone(), free_port()).stop());
    let n = 60_000u64;
    let file = dir.join("in.jsonl");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&file).unwrap());
    for i in 0..n {
        let (id, pk) = (format!("{:064x}", i + 1), format!("{:064x}", i % 7 + 1));
        let (at, sig) = (1_700_000_000 + i, "00".repeat(64));
        writeln!(f, r#"{{"content":"x","created_at":{at},"id":"{id}","kind":14,"pubkey":"{pk}","sig":"{sig}","tags":[]}}"#).unwrap();
    }
    drop(f);
    run_ok(&dir, &["import", "--no-verify", file.to_str().unwrap()]);

    let port = free_port();
    let relay = Relay::start(dir.clone(), port);
    let host = format!("127.0.0.1:{port}");
    let dest = dir.join("backup");
    let backup = Command::new(env!("CARGO_BIN_EXE_magnitude-relay"))
        .arg("--config")
        .arg(dir.join("relay.toml"))
        .args(["backup", dest.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Writes made while it runs are all accepted.
    let me = Signer::new(31);
    let mut c = client_connect(relay.addr, &host, "/").await.unwrap();
    for i in 0..40 {
        send(&mut c, json!(["EVENT", me.event(now(), 30078, json!([["d", format!("note-{i}")]]), "live")])).await;
        assert!(ok_of(&mut c).await.0);
    }
    let out = backup.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let held = said.lines().next().unwrap().strip_prefix("backed up ").unwrap().split(' ').next().unwrap().parse::<u64>().unwrap();
    assert!((n..=n + 40).contains(&held), "{said}");
    assert!(said.contains("verified: it opens as a store of"), "{said}");

    // The relay carries on; a second backup to the same place, or one into the
    // data directory, is refused and changes nothing.
    assert_eq!(run_ok(&dir, &["count", "--filter", "{}"]), format!("{}\n", n + 40));
    run_refused(&dir, &["backup", dest.to_str().unwrap()], "already exists");
    run_refused(&dir, &["backup", dir.join("data").join("copies").join("one").to_str().unwrap()], "inside the data directory");
    assert!(!dir.join("data").join("copies").exists());
    run_refused(&dir, &["backup"], "needs a destination");
    drop(c);
    let dir = relay.stop();

    // Offline too: the stopped relay's directory is opened directly.
    let offline = run_ok(&dir, &["backup", dir.join("backup-offline").to_str().unwrap(), "--no-verify"]);
    assert!(offline.starts_with(&format!("backed up {} events", n + 40)), "{offline}");

    // Restore: a relay started on the backup serves what it held, and takes new events.
    let restored = dir.join("restored");
    std::fs::create_dir_all(&restored).unwrap();
    std::fs::rename(&dest, restored.join("data")).unwrap();
    let port = free_port();
    let relay = Relay::start(restored.clone(), port);
    assert_eq!(run_ok(&restored, &["count", "--filter", r#"{"kinds":[14]}"#]), format!("{n}\n"));
    assert_eq!(run_ok(&restored, &["count", "--filter", "{}"]), format!("{held}\n"));
    let mut c = client_connect(relay.addr, &format!("127.0.0.1:{port}"), "/").await.unwrap();
    send(&mut c, json!(["EVENT", me.event(now(), 30078, json!([["d", "after"]]), "after restore")])).await;
    assert!(ok_of(&mut c).await.0);
    assert_eq!(run_ok(&restored, &["count", "--filter", "{}"]), format!("{}\n", held + 1));
    drop(c);
    relay.stop();
    let _ = std::fs::remove_dir_all(dir);
}
