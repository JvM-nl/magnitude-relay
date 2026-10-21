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
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("relay.toml");
        std::fs::write(
            &cfg,
            format!("[relay]\nbind = \"127.0.0.1:{port}\"\nthreads = 2\n[limits]\nevents_per_minute_per_ip = 0\n[store]\ndata = \"{}\"\n", dir.join("data").display()),
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
