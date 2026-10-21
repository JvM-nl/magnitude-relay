//! The whole of this crate against the in-process CA in [`crate::mock`]: obtaining,
//! serving, renewing and reloading, and the connection type under load.

use crate::certs::{self, Certs};
use crate::mock::{MockCa, Settings};
use crate::x509::{self, CertInfo, CertSpec, EcKey};
use crate::{acme, pem, store, time, Options, Source, Timing, Tls, TlsConn};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::io;
use std::net::{SocketAddr, TcpListener as StdListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const DAY: i64 = 86_400;

/// Folders made by the test running on this thread, removed when the thread ends.
struct Folders(Vec<PathBuf>);

impl Drop for Folders {
    fn drop(&mut self) {
        for d in &self.0 {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

thread_local! {
    static FOLDERS: std::cell::RefCell<Folders> = const { std::cell::RefCell::new(Folders(Vec::new())) };
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("relay-tls-flow-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    FOLDERS.with(|f| f.borrow_mut().0.push(d.clone()));
    d
}

/// Timings short enough for a test and long enough to be seen: a failed attempt
/// is retried after 100 ms, 200 ms, then every 400 ms.
fn fast() -> Timing {
    Timing {
        retry_initial: Duration::from_millis(100),
        retry_max: Duration::from_millis(400),
        check: Duration::from_millis(200),
        files_poll: Duration::from_millis(50),
        acme: acme::Timing { poll_interval: Duration::from_millis(20), poll_timeout: Duration::from_secs(10) },
    }
}

fn bind() -> (StdListener, SocketAddr) {
    let l = StdListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

/// Polls `f` until it gives something, for up to 20 seconds.
async fn until<T>(what: &str, mut f: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return v;
        }
        assert!(start.elapsed() < Duration::from_secs(20), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The relay's side of an HTTPS connection, written the way a reactor reads one:
/// wait for readiness, read what is there, answer when a request is complete.
fn serve_tls(listener: StdListener, config: Arc<ServerConfig>) {
    listener.set_nonblocking(true).unwrap();
    let l = TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { continue };
            let config = config.clone();
            tokio::spawn(async move {
                let Ok(mut c) = TlsConn::accept(s, config).await else { return };
                let mut request = Vec::new();
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    if c.readable().await.is_err() {
                        return;
                    }
                    match c.try_read(&mut buf) {
                        Ok(0) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(_) => return,
                    }
                    if request.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let mut out = Vec::new();
                relay_net::http::write_response(&mut out, 200, "OK", "text/plain", &[], b"hello over tls", true);
                if c.send(&out).await.is_ok() {
                    let _ = c.shutdown().await;
                }
            });
        }
    });
}

fn client_config(roots: &[Vec<u8>]) -> Arc<ClientConfig> {
    let mut store = RootCertStore::empty();
    for r in roots {
        store.add(CertificateDer::from(r.clone())).unwrap();
    }
    Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(store)
            .with_no_client_auth(),
    )
}

struct Fetched {
    leaf: CertInfo,
    body: String,
}

/// A browser's view: connect, verify against `roots`, ask for `/`.
async fn fetch(addr: SocketAddr, name: &str, roots: &[Vec<u8>]) -> io::Result<Fetched> {
    let tcp = TcpStream::connect(addr).await?;
    let tls = TlsConnector::from(client_config(roots)).connect(ServerName::try_from(name.to_string()).unwrap(), tcp).await?;
    let leaf = x509::parse_certificate(tls.get_ref().1.peer_certificates().unwrap().first().unwrap()).unwrap();
    let mut tls = tls;
    tls.write_all(format!("GET / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await?;
    Ok(Fetched { leaf, body: String::from_utf8_lossy(&out).into_owned() })
}

struct Setup {
    ca: MockCa,
    tls: Tls,
    data: PathBuf,
    https: SocketAddr,
    http: SocketAddr,
}

async fn setup_with(tag: &str, domains: &[&str], email: Option<&str>, lifetime: i64, timing: Timing) -> Setup {
    let data = temp_dir(tag);
    let ca = MockCa::start(Settings { https_target: None, http_target: None, lifetime, tls: false }).await;
    let s = start_relay(&ca, data, domains, email, timing);
    Setup { ca, tls: s.0, data: s.1, https: s.2, http: s.3 }
}

/// Starts the relay's TLS side against `ca` with the data directory `data`.
fn start_relay(
    ca: &MockCa,
    data: PathBuf,
    domains: &[&str],
    email: Option<&str>,
    timing: Timing,
) -> (Tls, PathBuf, SocketAddr, SocketAddr) {
    let ((https_l, https), (http_l, http)) = (bind(), bind());
    ca.set_targets(Some(https), Some(http));
    let tls = Tls::start(Options {
        data_dir: data.clone(),
        source: Source::Acme {
            domains: domains.iter().map(|d| d.to_string()).collect(),
            email: email.map(str::to_string),
            directory: ca.directory(),
        },
        http: Some(http_l),
        https_port: https.port(),
        redirect_hosts: domains.iter().map(|d| d.to_string()).collect(),
        user_agent: "relay-tls-test/0".to_string(),
        ca_roots: vec![],
        timing,
    })
    .unwrap();
    serve_tls(https_l, tls.config.clone());
    (tls, data, https, http)
}

#[tokio::test]
async fn obtains_a_certificate_by_tls_alpn_and_serves_it() {
    let s = setup_with("alpn", &["relay.test"], Some("ops@relay.test"), 90 * DAY, fast()).await;
    let cert = until("the first certificate", || s.tls.certificate()).await;
    assert_eq!(cert.info.names, ["relay.test"]);

    // The CA validated the way a CA does, and only that way.
    assert_eq!(s.ca.validations(), ["tls-alpn-01 relay.test ok"]);
    assert_eq!((s.ca.issued(), s.ca.accounts()), (1, 1));
    assert_eq!(s.ca.contacts(), [["mailto:ops@relay.test"]]);

    // A browser trusting the CA gets the page, over the certificate we obtained.
    let got = fetch(s.https, "relay.test", &[s.ca.root_der()]).await.unwrap();
    assert!(got.body.ends_with("hello over tls"), "{}", got.body);
    assert_eq!(got.leaf.serial, cert.info.serial);

    // The challenge answers are gone again.
    assert!(s.tls.challenges().alpn("relay.test").is_none());

    // The account and certificate are saved, privately, for the next start.
    let dir = store::Dir::open(&s.data).unwrap();
    let saved = dir.load().unwrap().unwrap();
    assert_eq!(saved.directory.as_deref(), Some(s.ca.directory().as_str()));
    assert!(saved.chain_pem.starts_with("-----BEGIN CERTIFICATE-----") && saved.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(dir.path().join("account.key").exists());
    #[cfg(unix)]
    for f in ["account.key", "cert.pem", "key.pem", "directory"] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(dir.path().join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
    }
    // A browser not trusting the CA does not.
    assert!(fetch(s.https, "relay.test", &[]).await.is_err());
    // Nor does one that asks for another name.
    assert!(fetch(s.https, "other.test", &[s.ca.root_der()]).await.is_err());
}

#[tokio::test]
async fn falls_back_to_http_01_when_tls_alpn_fails() {
    let data = temp_dir("fallback");
    let ca = MockCa::start(Settings { https_target: None, http_target: None, lifetime: 90 * DAY, tls: false }).await;
    ca.fail_validation("tls-alpn-01", true);
    let (tls, _, https, http) = start_relay(&ca, data, &["relay.test"], None, fast());
    let cert = until("a certificate", || tls.certificate()).await;
    assert_eq!(ca.validations(), ["tls-alpn-01 relay.test failed: simulated validation failure", "http-01 relay.test ok"]);
    assert_eq!(ca.issued(), 1);
    assert!(tls.challenges().http("anything").is_none());
    let got = fetch(https, "relay.test", &[ca.root_der()]).await.unwrap();
    assert_eq!(got.leaf.serial, cert.info.serial);
    let _ = http;
}

#[tokio::test]
async fn a_ca_that_offers_only_http_01_is_served_by_the_fallback() {
    let data = temp_dir("only-http");
    let ca = MockCa::start(Settings { https_target: None, http_target: None, lifetime: 90 * DAY, tls: false }).await;
    ca.offer_only(&["http-01"]);
    let (tls, ..) = start_relay(&ca, data, &["relay.test"], None, fast());
    until("a certificate", || tls.certificate()).await;
    // No TLS-ALPN-01 validation was ever attempted: the CA never offered one.
    assert_eq!(ca.validations(), ["http-01 relay.test ok"]);
}

#[tokio::test]
async fn without_a_plain_port_only_tls_alpn_is_tried() {
    let data = temp_dir("nohttp");
    let ca = MockCa::start(Settings { https_target: None, http_target: None, lifetime: 90 * DAY, tls: false }).await;
    let (https_l, https) = bind();
    ca.set_targets(Some(https), None);
    ca.fail_validation("tls-alpn-01", true);
    let tls = Tls::start(Options {
        data_dir: data,
        source: Source::Acme { domains: vec!["relay.test".into()], email: None, directory: ca.directory() },
        http: None,
        https_port: https.port(),
        redirect_hosts: vec![],
        user_agent: "t".into(),
        ca_roots: vec![],
        timing: fast(),
    })
    .unwrap();
    serve_tls(https_l, tls.config.clone());
    until("two failed attempts", || (ca.validations().len() >= 2).then_some(())).await;
    assert!(ca.validations().iter().all(|v| v.starts_with("tls-alpn-01 ")), "{:?}", ca.validations());
    assert!(tls.certificate().is_none());
    // And once the CA can validate, it succeeds on a retry.
    ca.fail_validation("tls-alpn-01", false);
    until("the certificate", || tls.certificate()).await;
}

#[tokio::test]
async fn failures_back_off_and_then_succeed() {
    let data = temp_dir("backoff");
    let ca = MockCa::start(Settings { https_target: None, http_target: None, lifetime: 90 * DAY, tls: false }).await;
    // Each attempt places one order per method (TLS-ALPN-01, then HTTP-01), so six
    // refusals fail three attempts.
    ca.fail_next_orders(6);
    let t = Instant::now();
    let (tls, ..) = start_relay(&ca, data, &["relay.test"], None, fast());
    until("a certificate after three failed attempts", || tls.certificate()).await;
    // Waits of 100, 200 and 400 ms came between the four attempts.
    assert!(t.elapsed() >= Duration::from_millis(700), "{:?}", t.elapsed());
    assert_eq!(ca.issued(), 1);
}

#[tokio::test]
async fn an_invalid_nonce_is_retried_transparently() {
    let data = temp_dir("nonce");
    let ca = MockCa::start(Settings { https_target: None, http_target: None, lifetime: 90 * DAY, tls: false }).await;
    ca.bad_nonces(2);
    let (tls, ..) = start_relay(&ca, data, &["relay.test"], None, fast());
    until("a certificate", || tls.certificate()).await;
    assert_eq!(ca.issued(), 1);
}

#[tokio::test]
async fn a_restart_serves_the_saved_certificate_at_once() {
    let s = setup_with("restart", &["relay.test"], None, 90 * DAY, fast()).await;
    let first = until("the first certificate", || s.tls.certificate()).await;
    let issued = s.ca.issued();

    // A second instance on the same data directory, whose CA is unreachable: it must
    // not need one.
    let ((https_l, https), (http_l, _)) = (bind(), bind());
    let dead = bind().1;
    let t = Tls::start(Options {
        data_dir: s.data.clone(),
        source: Source::Acme { domains: vec!["relay.test".into()], email: None, directory: s.ca.directory() },
        http: Some(http_l),
        https_port: https.port(),
        redirect_hosts: vec![],
        user_agent: "t".into(),
        ca_roots: vec![],
        timing: fast(),
    })
    .unwrap();
    let _ = dead;
    // No waiting: it is there when start returns.
    let again = t.certificate().expect("the saved certificate is loaded synchronously");
    assert_eq!(again.info.serial, first.info.serial);
    serve_tls(https_l, t.config.clone());
    let got = fetch(https, "relay.test", &[s.ca.root_der()]).await.unwrap();
    assert_eq!(got.leaf.serial, first.info.serial);
    // And being fresh, it asks for nothing.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(s.ca.issued(), issued);
}

#[tokio::test]
async fn an_account_survives_restarts() {
    let s = setup_with("account", &["relay.test"], None, 90 * DAY, fast()).await;
    until("a certificate", || s.tls.certificate()).await;
    // Drop the saved certificate but keep the account key: the next start orders
    // again, under the same account.
    let dir = store::Dir::open(&s.data).unwrap();
    std::fs::remove_file(dir.path().join("cert.pem")).unwrap();
    let (t2, ..) = start_relay(&s.ca, s.data.clone(), &["relay.test"], None, fast());
    until("a second certificate", || t2.certificate()).await;
    assert_eq!(s.ca.issued(), 2);
    assert_eq!(s.ca.accounts(), 1, "the same key found its account again");
}

#[tokio::test]
async fn renews_when_a_third_of_the_lifetime_is_left_without_a_restart() {
    // Six-second certificates: due after four.
    let s = setup_with("renew", &["relay.test"], None, 6, fast()).await;
    let first = until("the first certificate", || s.tls.certificate()).await;
    let a = fetch(s.https, "relay.test", &[s.ca.root_der()]).await.unwrap();
    assert_eq!(a.leaf.serial, first.info.serial);
    let t = Instant::now();
    let second = until("the renewal", || s.tls.certificate().filter(|c| c.info.serial != first.info.serial)).await;
    // Not early (due at 2/3 of 6 s = 4 s after issue), and not late.
    assert!(t.elapsed() >= Duration::from_secs(2), "{:?}", t.elapsed());
    assert!(second.info.not_after > first.info.not_after);
    // The very next handshake sees it: same listener, same process.
    let b = fetch(s.https, "relay.test", &[s.ca.root_der()]).await.unwrap();
    assert_eq!(b.leaf.serial, second.info.serial);
    assert_ne!(a.leaf.serial, b.leaf.serial);
    assert_eq!(s.ca.accounts(), 1);
}

#[tokio::test]
async fn a_forced_renewal_replaces_the_certificate_for_the_next_connection() {
    let s = setup_with("force", &["relay.test"], None, 90 * DAY, fast()).await;
    let first = until("the first certificate", || s.tls.certificate()).await;
    let before = fetch(s.https, "relay.test", &[s.ca.root_der()]).await.unwrap();
    assert_eq!(before.leaf.serial, first.info.serial);
    s.tls.renew_now();
    let second = until("the renewal", || s.tls.certificate().filter(|c| c.info.serial != first.info.serial)).await;
    let after = fetch(s.https, "relay.test", &[s.ca.root_der()]).await.unwrap();
    assert_eq!(after.leaf.serial, second.info.serial);
    assert_eq!(s.ca.issued(), 2);
    // The renewal is saved too.
    let saved = store::Dir::open(&s.data).unwrap().load().unwrap().unwrap();
    assert_eq!(x509::parse_certificate(&pem::certificates(&saved.chain_pem).unwrap()[0]).unwrap().serial, second.info.serial);
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_replaced_at_start() {
    let one = setup_with("switch", &["relay.test"], None, 90 * DAY, fast()).await;
    let old = until("a certificate", || one.tls.certificate()).await;
    // The operator switches CA (staging to production, say), keeping the data directory.
    let ca2 = MockCa::start(Settings { https_target: None, http_target: None, lifetime: 90 * DAY, tls: false }).await;
    let (t2, _, https2, _) = start_relay(&ca2, one.data.clone(), &["relay.test"], None, fast());
    let loaded = t2.certificate().expect("the old one is served meanwhile");
    assert_eq!(loaded.info.serial, old.info.serial);
    let new = until("a certificate from the new CA", || t2.certificate().filter(|c| c.info.serial != old.info.serial)).await;
    assert_eq!(ca2.issued(), 1);
    let got = fetch(https2, "relay.test", &[ca2.root_der()]).await.unwrap();
    assert_eq!(got.leaf.serial, new.info.serial);
    assert_eq!(store::Dir::open(&one.data).unwrap().load().unwrap().unwrap().directory.as_deref(), Some(ca2.directory().as_str()));
}

#[tokio::test]
async fn new_names_get_a_new_certificate() {
    let one = setup_with("names", &["a.test"], None, 90 * DAY, fast()).await;
    let old = until("a certificate", || one.tls.certificate()).await;
    assert_eq!(old.info.names, ["a.test"]);
    let (t2, _, https2, _) = start_relay(&one.ca, one.data.clone(), &["a.test", "b.test"], None, fast());
    let new = until("a certificate for both", || t2.certificate().filter(|c| c.info.covers(&["b.test".to_string()]))).await;
    assert_eq!(new.info.names, ["a.test", "b.test"]);
    for name in ["a.test", "b.test"] {
        assert_eq!(fetch(https2, name, &[one.ca.root_der()]).await.unwrap().leaf.serial, new.info.serial);
    }
}

#[tokio::test]
async fn several_names_are_validated_and_certified_together() {
    let s = setup_with("many", &["one.test", "two.test", "three.test"], None, 90 * DAY, fast()).await;
    let c = until("a certificate", || s.tls.certificate()).await;
    assert_eq!(c.info.names, ["one.test", "two.test", "three.test"]);
    let mut v = s.ca.validations();
    v.sort();
    assert_eq!(v, ["tls-alpn-01 one.test ok", "tls-alpn-01 three.test ok", "tls-alpn-01 two.test ok"]);
    assert_eq!(s.ca.issued(), 1);
}

#[tokio::test]
async fn the_plain_port_redirects_while_everything_else_runs() {
    let s = setup_with("redirect", &["relay.test"], None, 90 * DAY, fast()).await;
    until("a certificate", || s.tls.certificate()).await;
    let mut c = TcpStream::connect(s.http).await.unwrap();
    c.write_all(b"GET /nostr?x=1 HTTP/1.1\r\nHost: relay.test\r\nConnection: close\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    c.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{text}");
    assert!(text.contains(&format!("Location: https://relay.test:{}/nostr?x=1\r\n", s.https.port())), "{text}");
}

#[tokio::test]
async fn dropping_the_handle_stops_the_background_work() {
    let s = setup_with("drop", &["relay.test"], None, 90 * DAY, fast()).await;
    until("a certificate", || s.tls.certificate()).await;
    let http = s.http;
    assert!(TcpStream::connect(http).await.is_ok());
    drop(s.tls);
    // The plain-HTTP port goes with the thread that served it.
    let t = Instant::now();
    while TcpStream::connect(http).await.is_ok() {
        assert!(t.elapsed() < Duration::from_secs(5), "the plain-HTTP port is still open");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn an_unreachable_ca_leaves_handshakes_failing_cleanly() {
    let data = temp_dir("dead-ca");
    let (https_l, https) = bind();
    let dead = bind().1; // nothing listens here once the listener is dropped
    let tls = Tls::start(Options {
        data_dir: data,
        source: Source::Acme { domains: vec!["relay.test".into()], email: None, directory: format!("http://{dead}/directory") },
        http: None,
        https_port: https.port(),
        redirect_hosts: vec![],
        user_agent: "t".into(),
        ca_roots: vec![],
        timing: fast(),
    })
    .unwrap();
    serve_tls(https_l, tls.config.clone());
    assert!(tls.certificate().is_none());
    let t = Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(5), fetch(https, "relay.test", &[]))
        .await
        .expect("a handshake without a certificate ends, it does not hang");
    assert!(r.is_err());
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn the_ca_can_itself_be_reached_over_https_with_a_private_root() {
    let ca = MockCa::start(Settings { https_target: None, http_target: None, lifetime: 90 * DAY, tls: true }).await;
    assert!(ca.directory().starts_with("https://localhost:"));
    let data = temp_dir("https-ca");
    let ((https_l, https), (http_l, http)) = (bind(), bind());
    ca.set_targets(Some(https), Some(http));
    let mk = |roots: Vec<Vec<u8>>, data: PathBuf, http: Option<StdListener>| {
        Tls::start(Options {
            data_dir: data,
            source: Source::Acme { domains: vec!["relay.test".into()], email: None, directory: ca.directory() },
            http,
            https_port: https.port(),
            redirect_hosts: vec![],
            user_agent: "t".into(),
            ca_roots: roots,
            timing: fast(),
        })
        .unwrap()
    };
    // Without the root the CA is not trusted, and nothing is issued.
    let untrusting = mk(vec![], temp_dir("https-ca-no"), None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(untrusting.certificate().is_none() && ca.issued() == 0);
    // With it, the full flow runs over TLS.
    let tls = mk(vec![ca.root_der()], data, Some(http_l));
    serve_tls(https_l, tls.config.clone());
    until("a certificate", || tls.certificate()).await;
    assert!(fetch(https, "relay.test", &[ca.root_der()]).await.unwrap().body.ends_with("hello over tls"));
}

// ---------------------------------------------------------------------------
// Certificates from files.

/// A test CA and a leaf for `name` signed by it: `(root, chain pem, key pem)`.
fn pki(name: &str) -> (Vec<u8>, String, String) {
    let (ca, leaf) = (EcKey::generate().unwrap(), EcKey::generate().unwrap());
    let now = time::now();
    let root = x509::build_certificate(
        &CertSpec {
            serial: &x509::random_serial(),
            issuer_cn: "File Root",
            subject_cn: "File Root",
            not_before: now - 60,
            not_after: now + DAY,
            spki: &ca.spki(),
            dns_names: &[],
            ca: true,
            acme_identifier: None,
        },
        &ca,
    );
    let names = [name.to_string()];
    let leaf_der = x509::build_certificate(
        &CertSpec {
            serial: &x509::random_serial(),
            issuer_cn: "File Root",
            subject_cn: name,
            not_before: now - 60,
            not_after: now + DAY,
            spki: &leaf.spki(),
            dns_names: &names,
            ca: false,
            acme_identifier: None,
        },
        &ca,
    );
    (root.clone(), pem::encode("CERTIFICATE", &leaf_der) + &pem::encode("CERTIFICATE", &root), pem::encode("PRIVATE KEY", leaf.pkcs8()))
}

fn start_files(data: PathBuf, cert: &std::path::Path, key: &std::path::Path) -> Result<Tls, String> {
    Tls::start(Options {
        data_dir: data,
        source: Source::Files { cert: cert.to_path_buf(), key: key.to_path_buf() },
        http: None,
        https_port: 443,
        redirect_hosts: vec![],
        user_agent: "t".into(),
        ca_roots: vec![],
        timing: fast(),
    })
}

#[tokio::test]
async fn file_certificates_are_served_and_reloaded_when_they_change() {
    let dir = temp_dir("files");
    let (root1, chain1, key1) = pki("one.test");
    let (cert_path, key_path) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
    std::fs::write(&cert_path, &chain1).unwrap();
    std::fs::write(&key_path, &key1).unwrap();
    let (https_l, https) = bind();
    let tls = start_files(dir.clone(), &cert_path, &key_path).unwrap();
    serve_tls(https_l, tls.config.clone());
    let first = fetch(https, "one.test", std::slice::from_ref(&root1)).await.unwrap();
    assert_eq!(first.leaf.names, ["one.test"]);
    assert!(first.body.ends_with("hello over tls"));

    // Replace the files, key last, as a deploy script would (the CA of the new pair differs).
    let (root2, chain2, key2) = pki("two.test");
    store::write_atomic(&cert_path, chain2.as_bytes()).unwrap();
    // The new certificate with the old key is not served: the pair does not match, so
    // the old one stays in place meanwhile.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fetch(https, "one.test", std::slice::from_ref(&root1)).await.unwrap().leaf.serial, first.leaf.serial);
    store::write_atomic(&key_path, key2.as_bytes()).unwrap();
    let second = until("the new certificate", || tls.certificate().filter(|c| c.info.names == ["two.test"])).await;
    let got = fetch(https, "two.test", std::slice::from_ref(&root2)).await.unwrap();
    assert_eq!(got.leaf.serial, second.info.serial);
    assert!(fetch(https, "one.test", &[root1]).await.is_err(), "the old name is no longer served");
}

#[tokio::test]
async fn a_broken_replacement_keeps_the_old_certificate_until_fixed() {
    let dir = temp_dir("files-broken");
    let (root, chain, key) = pki("one.test");
    let (cert_path, key_path) = (dir.join("c.pem"), dir.join("k.pem"));
    std::fs::write(&cert_path, &chain).unwrap();
    std::fs::write(&key_path, &key).unwrap();
    let (https_l, https) = bind();
    let tls = start_files(dir.clone(), &cert_path, &key_path).unwrap();
    serve_tls(https_l, tls.config.clone());
    let serial = tls.certificate().unwrap().info.serial.clone();
    store::write_atomic(&cert_path, b"this is not a certificate").unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fetch(https, "one.test", std::slice::from_ref(&root)).await.unwrap().leaf.serial, serial);
    let (root2, chain2, key2) = pki("one.test");
    store::write_atomic(&key_path, key2.as_bytes()).unwrap();
    store::write_atomic(&cert_path, chain2.as_bytes()).unwrap();
    let new = until("the repaired pair", || tls.certificate().filter(|c| c.info.serial != serial)).await;
    assert_eq!(fetch(https, "one.test", &[root2]).await.unwrap().leaf.serial, new.info.serial);
}

#[test]
fn bad_certificate_files_stop_the_start_with_a_clear_message() {
    let dir = temp_dir("files-bad");
    let (_, chain, key) = pki("one.test");
    let (c, k) = (dir.join("c.pem"), dir.join("k.pem"));
    let err = |t: Result<Tls, String>| t.err().expect("should fail");
    assert!(err(start_files(dir.clone(), &c, &k)).contains("cannot read the certificate"));
    std::fs::write(&c, &chain).unwrap();
    assert!(err(start_files(dir.clone(), &c, &k)).contains("cannot read the private key"));
    std::fs::write(&k, "nope").unwrap();
    assert!(err(start_files(dir.clone(), &c, &k)).contains("no private key"));
    std::fs::write(&k, pki("other.test").2).unwrap();
    assert!(err(start_files(dir.clone(), &c, &k)).contains("does not belong"));
    std::fs::write(&k, &key).unwrap();
    assert!(start_files(dir, &c, &k).is_ok());
}

// ---------------------------------------------------------------------------
// The connection type.

/// A server config for tests of [`TlsConn`] alone, and the root to trust.
fn plain_server(name: &str) -> (Arc<ServerConfig>, Vec<u8>) {
    let (root, chain, key) = pki(name);
    let certs = Arc::new(Certs::default());
    certs.set(certs::load(&chain, &key).unwrap());
    (certs::server_config(certs).unwrap(), root)
}

/// Serves each connection with `f`, returning the listening address.
async fn spawn_conn_server<F, Fut>(config: Arc<ServerConfig>, f: F) -> SocketAddr
where
    F: Fn(TlsConn) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let f = Arc::new(f);
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { continue };
            let (config, f) = (config.clone(), f.clone());
            tokio::spawn(async move {
                if let Ok(c) = TlsConn::accept(s, config).await {
                    f(c).await;
                }
            });
        }
    });
    addr
}

/// Reads until the peer is done, the way a reactor does.
async fn read_all(c: &mut TlsConn) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        c.readable().await?;
        match c.try_read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
    }
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed).wrapping_add((i >> 8) as u8)).collect()
}

#[tokio::test]
async fn a_large_transfer_in_both_directions_arrives_intact() {
    let (config, root) = plain_server("big.test");
    let want = pattern(3 << 20, 7);
    let reply = pattern(2 << 20, 99);
    let (w, r) = (want.clone(), reply.clone());
    let addr = spawn_conn_server(config, move |mut c| {
        let (w, r) = (w.clone(), r.clone());
        async move {
            let got = read_all(&mut c).await.unwrap();
            assert!(got == w, "server received {} bytes", got.len());
            c.send(&r).await.unwrap();
            c.shutdown().await.unwrap();
        }
    })
    .await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(client_config(&[root])).connect(ServerName::try_from("big.test").unwrap(), tcp).await.unwrap();
    tls.write_all(&want).await.unwrap();
    tls.shutdown().await.unwrap();
    let mut got = Vec::new();
    tls.read_to_end(&mut got).await.unwrap();
    assert!(got == reply, "client received {} bytes", got.len());
}

#[tokio::test]
async fn small_messages_ping_pong_without_stalling() {
    let (config, root) = plain_server("pp.test");
    let addr = spawn_conn_server(config, |mut c| async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if c.readable().await.is_err() {
                return;
            }
            match c.try_read(&mut buf) {
                Ok(0) => return,
                Ok(n) => {
                    let echo = buf[..n].to_vec();
                    if c.send(&echo).await.is_err() {
                        return;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
    })
    .await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(client_config(&[root])).connect(ServerName::try_from("pp.test").unwrap(), tcp).await.unwrap();
    for i in 0..300u32 {
        let msg = format!("message {i} {}", "x".repeat((i % 50) as usize));
        tls.write_all(msg.as_bytes()).await.unwrap();
        let mut back = vec![0u8; msg.len()];
        tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut back)).await.expect("echo arrives").unwrap();
        assert_eq!(back, msg.as_bytes());
    }
}

#[tokio::test]
async fn a_peer_that_vanishes_without_close_notify_is_an_end_of_stream() {
    let (config, root) = plain_server("gone.test");
    let (tx, rx) = tokio::sync::oneshot::channel();
    let tx = Arc::new(std::sync::Mutex::new(Some(tx)));
    let addr = spawn_conn_server(config, move |mut c| {
        let tx = tx.clone();
        async move {
            let got = read_all(&mut c).await;
            if let Some(tx) = tx.lock().unwrap().take() {
                let _ = tx.send(got.map_err(|e| e.to_string()));
            }
        }
    })
    .await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(client_config(&[root])).connect(ServerName::try_from("gone.test").unwrap(), tcp).await.unwrap();
    tls.write_all(b"partial request").await.unwrap();
    tls.flush().await.unwrap();
    // Dropping the stream closes the socket with no TLS goodbye.
    drop(tls);
    let got = tokio::time::timeout(Duration::from_secs(5), rx).await.unwrap().unwrap();
    // The server sees the stream end with what was sent. If the client's close finds
    // unread session tickets in its buffer the OS resets the connection instead, and
    // the server sees that: either way the read ends, with no hang and no panic.
    match got {
        Ok(data) => assert_eq!(data, b"partial request"),
        Err(e) => assert!(e.contains("reset") || e.contains("Reset") || e.contains("os error"), "{e}"),
    }
}

#[tokio::test]
async fn garbage_instead_of_a_handshake_is_an_error_not_a_hang() {
    let (config, _) = plain_server("junk.test");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        TlsConn::accept(s, config).await.err().map(|e| e.kind())
    });
    let mut c = TcpStream::connect(addr).await.unwrap();
    c.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let kind = tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    assert_eq!(kind, Some(io::ErrorKind::InvalidData));
    // A client that connects and says nothing is the caller's timeout to handle;
    // one that hangs up mid-handshake ends it.
    let (config, _) = plain_server("junk.test");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        TlsConn::accept(s, config).await.err().map(|e| e.kind())
    });
    drop(TcpStream::connect(addr).await.unwrap());
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap(), Some(io::ErrorKind::UnexpectedEof));
}

#[tokio::test]
async fn an_acme_validation_connection_is_closed_after_the_handshake() {
    let certs = Arc::new(Certs::default());
    let (_, chain, key) = pki("probe.test");
    certs.set(certs::load(&chain, &key).unwrap());
    let key = EcKey::generate().unwrap();
    certs
        .challenges
        .set_alpn("probe.test", certs::certified(x509::acme_challenge_certificate(&key, "probe.test", [9; 32], time::now()), &key));
    let config = certs::server_config(certs).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        TlsConn::accept(s, config).await.err().map(|e| e.to_string())
    });
    // A validator: no chain checking, ALPN acme-tls/1 only.
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::mock::AcceptAny))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![crate::ACME_ALPN.to_vec()];
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(cfg)).connect(ServerName::try_from("probe.test").unwrap(), tcp).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(crate::ACME_ALPN));
    let info = x509::parse_certificate(tls.get_ref().1.peer_certificates().unwrap().first().unwrap()).unwrap();
    assert_eq!(info.acme_identifier.map(|(critical, _)| critical), Some(true));
    // The server says nothing more and closes.
    let mut rest = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut rest)).await.expect("closed");
    assert!(rest.is_empty());
    assert_eq!(server.await.unwrap().as_deref(), Some(crate::conn::ACME_PROBE));
}

#[tokio::test]
async fn http_and_websocket_handshakes_run_over_the_connection() {
    use relay_net::conn::{client_handshake, server_handshake_with, Handshake, Message};
    use relay_net::http::{write_response, ExtensionPolicy};
    let (config, root) = plain_server("ws.test");
    let addr = spawn_conn_server(config, |mut c| async move {
        let mut buf = Vec::new();
        match server_handshake_with(&mut c, &mut buf, 8192, &ExtensionPolicy::NONE).await {
            Ok((Handshake::Upgraded(_), _)) => {
                let mut out = Vec::new();
                relay_net::ws::write_text(&mut out, b"[\"NOTICE\",\"hello over wss\"]");
                c.send(&out).await.unwrap();
                // Wait for the client's close, then end.
                let mut b = vec![0u8; 1024];
                loop {
                    if c.readable().await.is_err() {
                        break;
                    }
                    match c.try_read(&mut b) {
                        Ok(0) => break,
                        Ok(_) => {
                            let mut close = Vec::new();
                            relay_net::ws::write_close_empty(&mut close);
                            let _ = c.send(&close).await;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => break,
                    }
                }
            }
            Ok((Handshake::PlainHttp(req), _)) => {
                let mut out = Vec::new();
                write_response(&mut out, 200, "OK", "text/plain", &[], format!("plain {}", req.path).as_bytes(), true);
                c.write_all(&out).await.unwrap();
                c.shutdown().await.unwrap();
            }
            Err(_) => {}
        }
    })
    .await;
    let connector = TlsConnector::from(client_config(&[root]));
    let name = || ServerName::try_from("ws.test").unwrap();

    // A WebSocket upgrade, then a message from the server, then a clean close.
    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = connector.connect(name(), tcp).await.unwrap();
    let mut ws = client_handshake(tls, "ws.test", "/").await.unwrap();
    assert_eq!(ws.recv().await.unwrap(), Message::Text("[\"NOTICE\",\"hello over wss\"]".into()));
    ws.close().await.unwrap();

    // A plain GET gets its page.
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = connector.connect(name(), tcp).await.unwrap();
    tls.write_all(b"GET /nip11 HTTP/1.1\r\nHost: ws.test\r\n\r\n").await.unwrap();
    let mut out = Vec::new();
    tls.read_to_end(&mut out).await.unwrap();
    assert!(String::from_utf8_lossy(&out).ends_with("plain /nip11"));
}

#[tokio::test]
async fn http_2_only_clients_are_refused_and_clients_without_alpn_are_served() {
    let (config, root) = plain_server("alpn.test");
    let addr = spawn_conn_server(config, |mut c| async move {
        let _ = c.send(b"ok").await;
        let _ = c.shutdown().await;
    })
    .await;
    let connect = |protocols: Vec<Vec<u8>>| {
        let root = root.clone();
        async move {
            let mut cfg = Arc::try_unwrap(client_config(&[root])).ok().unwrap();
            cfg.alpn_protocols = protocols;
            let tcp = TcpStream::connect(addr).await.unwrap();
            TlsConnector::from(Arc::new(cfg))
                .connect(ServerName::try_from("alpn.test").unwrap(), tcp)
                .await
                .map(|t| t.get_ref().1.alpn_protocol().map(<[u8]>::to_vec))
        }
    };
    assert_eq!(connect(vec![]).await.unwrap(), None);
    assert_eq!(connect(vec![b"h2".to_vec(), b"http/1.1".to_vec()]).await.unwrap(), Some(b"http/1.1".to_vec()));
    assert!(connect(vec![b"h2".to_vec()]).await.is_err());
}
