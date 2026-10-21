//! An in-process ACME CA for tests: the subset of RFC 8555 this crate speaks,
//! checked the way a CA checks it.
//!
//! It verifies every JWS (algorithm, signature, a fresh single-use nonce, the URL,
//! the account), keeps accounts, orders and authorizations, validates TLS-ALPN-01
//! by connecting to the relay's TLS port and looking for the critical
//! acmeIdentifier extension, validates HTTP-01 by fetching the token from the
//! relay's plain-HTTP port, checks the CSR's signature and names, and issues
//! certificates signed by a test root that clients under test are told to trust.
//! Nothing here is meant for anything but tests.

use crate::der::{self, Reader};
use crate::x509::{self, CertSpec, EcKey};
use crate::{b64url, json, pem, time};
use json::Value;
use relay_net::http::{parse_request_with, reason_phrase, write_response};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const TLS_ALPN: &str = "tls-alpn-01";
const HTTP: &str = "http-01";

/// Where the CA validates, and what it issues.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The relay's TLS port, where TLS-ALPN-01 validation connects.
    pub https_target: Option<SocketAddr>,
    /// The relay's plain-HTTP port, where HTTP-01 validation connects.
    pub http_target: Option<SocketAddr>,
    /// Lifetime of issued certificates, in seconds.
    pub lifetime: i64,
    /// Serve the API over HTTPS (with a certificate for `localhost` from the test
    /// root) instead of plain HTTP.
    pub tls: bool,
}

struct Account {
    point: Vec<u8>,
    thumbprint: String,
    contact: Vec<String>,
}

struct Authz {
    account: String,
    domain: String,
    /// `(type, token, status, error)` per challenge.
    challenges: Vec<(&'static str, String, &'static str, Option<String>)>,
}

struct Order {
    account: String,
    domains: Vec<String>,
    authzs: Vec<String>,
    cert: Option<String>,
    /// Polls of a finalized order that still answer `processing`.
    processing: usize,
}

#[derive(Default)]
struct Book {
    nonces: HashSet<String>,
    accounts: HashMap<String, Account>,
    authzs: HashMap<String, Authz>,
    orders: HashMap<String, Order>,
    validations: Vec<String>,
    issued: usize,
}

struct State {
    base: String,
    ca_key: EcKey,
    ca_der: Vec<u8>,
    settings: Mutex<Settings>,
    book: Mutex<Book>,
    fail: Mutex<HashSet<&'static str>>,
    /// The challenge types offered; both by default.
    offer: Mutex<Vec<&'static str>>,
    fail_orders: AtomicUsize,
    bad_nonces: AtomicUsize,
    counter: AtomicUsize,
}

pub struct MockCa {
    state: Arc<State>,
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn random_token() -> String {
    let mut b = [0u8; 18];
    SystemRandom::new().fill(&mut b).unwrap();
    b64url::encode(&b)
}

fn problem(status: u16, kind: &str, detail: &str) -> Reply {
    let body = Value::obj([
        ("type", Value::str(format!("urn:ietf:params:acme:error:{kind}"))),
        ("detail", Value::str(detail)),
        ("status", Value::Num(f64::from(status))),
    ]);
    Reply { status, headers: vec![("Content-Type".into(), "application/problem+json".into())], body: body.to_string().into_bytes() }
}

fn json_reply(status: u16, v: &Value) -> Reply {
    Reply { status, headers: vec![("Content-Type".into(), "application/json".into())], body: v.to_string().into_bytes() }
}

impl MockCa {
    pub async fn start(settings: Settings) -> MockCa {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let base = if settings.tls { format!("https://localhost:{port}") } else { format!("http://127.0.0.1:{port}") };
        let ca_key = EcKey::generate().unwrap();
        let now = time::now();
        let ca_der = x509::build_certificate(
            &CertSpec {
                serial: &x509::random_serial(),
                issuer_cn: "Test Root",
                subject_cn: "Test Root",
                not_before: now - 3600,
                not_after: now + 10 * 365 * 86_400,
                spki: &ca_key.spki(),
                dns_names: &[],
                ca: true,
                acme_identifier: None,
            },
            &ca_key,
        );
        let state = Arc::new(State {
            base,
            ca_key,
            ca_der,
            settings: Mutex::new(settings.clone()),
            book: Mutex::new(Book::default()),
            fail: Mutex::new(HashSet::new()),
            offer: Mutex::new(vec![TLS_ALPN, HTTP]),
            fail_orders: AtomicUsize::new(0),
            bad_nonces: AtomicUsize::new(0),
            counter: AtomicUsize::new(1),
        });
        let acceptor = settings.tls.then(|| {
            let leaf = EcKey::generate().unwrap();
            let der = x509::build_certificate(
                &CertSpec {
                    serial: &x509::random_serial(),
                    issuer_cn: "Test Root",
                    subject_cn: "localhost",
                    not_before: now - 3600,
                    not_after: now + 86_400,
                    spki: &leaf.spki(),
                    dns_names: &["localhost".to_string()],
                    ca: false,
                    acme_identifier: None,
                },
                &state.ca_key,
            );
            let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(der), CertificateDer::from(state.ca_der.clone())],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf.pkcs8().to_vec())),
                )
                .unwrap();
            TlsAcceptor::from(Arc::new(cfg))
        });
        let st = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { continue };
                let (st, acceptor) = (st.clone(), acceptor.clone());
                tokio::spawn(async move {
                    match acceptor {
                        Some(a) => {
                            if let Ok(tls) = a.accept(tcp).await {
                                serve_one(st, tls).await;
                            }
                        }
                        None => serve_one(st, tcp).await,
                    }
                });
            }
        });
        MockCa { state }
    }

    /// The directory URL to point a client at.
    pub fn directory(&self) -> String {
        format!("{}/directory", self.state.base)
    }

    /// The test root, DER: what a client of the issued certificates must trust (and,
    /// in TLS mode, what the ACME client itself must trust).
    pub fn root_der(&self) -> Vec<u8> {
        self.state.ca_der.clone()
    }

    pub fn set_targets(&self, https: Option<SocketAddr>, http: Option<SocketAddr>) {
        let mut s = lock(&self.state.settings);
        s.https_target = https;
        s.http_target = http;
    }

    pub fn set_lifetime(&self, seconds: i64) {
        lock(&self.state.settings).lifetime = seconds;
    }

    /// Makes every validation of challenge type `method` fail (or stop failing).
    pub fn fail_validation(&self, method: &'static str, fail: bool) {
        let mut f = lock(&self.state.fail);
        if fail {
            f.insert(method);
        } else {
            f.remove(method);
        }
    }

    /// Offers only the challenge types named (`"tls-alpn-01"`, `"http-01"`).
    pub fn offer_only(&self, types: &[&'static str]) {
        *lock(&self.state.offer) = types.to_vec();
    }

    /// The next `n` new-order requests are refused with a server error.
    pub fn fail_next_orders(&self, n: usize) {
        self.state.fail_orders.store(n, Ordering::SeqCst);
    }

    /// The next `n` signed requests are refused with `badNonce`.
    pub fn bad_nonces(&self, n: usize) {
        self.state.bad_nonces.store(n, Ordering::SeqCst);
    }

    /// Certificates issued so far.
    pub fn issued(&self) -> usize {
        lock(&self.state.book).issued
    }

    /// Accounts registered so far.
    pub fn accounts(&self) -> usize {
        lock(&self.state.book).accounts.len()
    }

    /// The contact lists of the registered accounts.
    pub fn contacts(&self) -> Vec<Vec<String>> {
        lock(&self.state.book).accounts.values().map(|a| a.contact.clone()).collect()
    }

    /// Every validation attempted, as `"type domain ok"` or `"type domain failed: why"`.
    pub fn validations(&self) -> Vec<String> {
        lock(&self.state.book).validations.clone()
    }
}

/// Reads one request, answers it, closes.
async fn serve_one<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(st: Arc<State>, mut s: S) {
    let mut buf = Vec::new();
    let (method, path, accept, body) = loop {
        match parse_request_with(&buf, 64 * 1024) {
            Ok(Some((req, n))) => {
                let len: usize =
                    req.header("content-length").and_then(|v| std::str::from_utf8(v).ok()).and_then(|v| v.parse().ok()).unwrap_or(0);
                let (method, path) = (req.method.to_string(), req.path.to_string());
                let accept = req.header("accept").map(|a| String::from_utf8_lossy(a).into_owned());
                while buf.len() < n + len {
                    if s.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                        return;
                    }
                }
                break (method, path, accept, buf[n..n + len].to_vec());
            }
            Ok(None) => {
                if s.read_buf(&mut buf).await.unwrap_or(0) == 0 {
                    return;
                }
            }
            Err(_) => return,
        }
    };
    let mut reply = route(&st, &method, &path, accept.as_deref(), &body);
    let nonce = random_token();
    lock(&st.book).nonces.insert(nonce.clone());
    reply.headers.push(("Replay-Nonce".into(), nonce));
    reply.headers.push(("Cache-Control".into(), "no-store".into()));
    let content_type = reply.headers.iter().find(|(n, _)| n == "Content-Type").map_or("text/plain", |(_, v)| v.as_str()).to_string();
    let extra: Vec<(&str, &str)> =
        reply.headers.iter().filter(|(n, _)| n != "Content-Type").map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let mut out = Vec::new();
    write_response(
        &mut out,
        reply.status,
        reason_phrase(reply.status),
        &content_type,
        &extra,
        if method == "HEAD" { b"" } else { &reply.body },
        true,
    );
    let _ = s.write_all(&out).await;
    let _ = s.shutdown().await;
}

struct Verified {
    payload: Vec<u8>,
    /// The account id when the request was signed with a `kid`.
    account: Option<String>,
    /// The JWK's public point and its members, when signed with a `jwk`.
    jwk: Option<(Vec<u8>, String, String)>,
}

impl State {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    fn fresh_id(&self) -> String {
        format!("{}", self.counter.fetch_add(1, Ordering::SeqCst))
    }

    /// Verifies a JWS body for a POST to `path`.
    fn verify(&self, path: &str, body: &[u8]) -> Result<Verified, Reply> {
        let bad = |kind: &str, detail: &str| problem(400, kind, detail);
        let v = json::parse(&String::from_utf8_lossy(body)).map_err(|e| bad("malformed", &e.to_string()))?;
        let (p, pl, s) = (v.str_of("protected"), v.str_of("payload"), v.str_of("signature"));
        let (Some(p), Some(pl), Some(s)) = (p, pl, s) else { return Err(bad("malformed", "not a flattened JWS")) };
        let header = b64url::decode(p)
            .and_then(|h| String::from_utf8(h).ok())
            .and_then(|h| json::parse(&h).ok())
            .ok_or_else(|| bad("malformed", "bad protected header"))?;
        if header.str_of("alg") != Some("ES256") {
            return Err(bad("badSignatureAlgorithm", "only ES256"));
        }
        let nonce = header.str_of("nonce").ok_or_else(|| bad("badNonce", "no nonce"))?;
        let simulated = self.bad_nonces.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok();
        if simulated || !lock(&self.book).nonces.remove(nonce) {
            return Err(bad("badNonce", "JWS has an invalid anti-replay nonce"));
        }
        if header.str_of("url") != Some(self.url(path).as_str()) {
            return Err(bad("unauthorized", "the JWS url does not match the request"));
        }
        let (point, account, jwk) = match (header.get("jwk"), header.str_of("kid")) {
            (Some(jwk), None) => {
                let (x, y) = (jwk.str_of("x").and_then(b64url::decode), jwk.str_of("y").and_then(b64url::decode));
                let (true, Some(x), Some(y)) = (jwk.str_of("kty") == Some("EC") && jwk.str_of("crv") == Some("P-256"), x, y) else {
                    return Err(bad("malformed", "unusable jwk"));
                };
                let point = [&[4u8][..], &x, &y].concat();
                (point.clone(), None, Some((point, jwk.str_of("x").unwrap().to_string(), jwk.str_of("y").unwrap().to_string())))
            }
            (None, Some(kid)) => {
                let id = kid.strip_prefix(&self.url("/acct/")).ok_or_else(|| bad("accountDoesNotExist", "unknown account URL"))?;
                let book = lock(&self.book);
                let acct = book.accounts.get(id).ok_or_else(|| bad("accountDoesNotExist", "unknown account"))?;
                (acct.point.clone(), Some(id.to_string()), None)
            }
            _ => return Err(bad("malformed", "need exactly one of jwk and kid")),
        };
        let sig = b64url::decode(s).ok_or_else(|| bad("malformed", "bad signature encoding"))?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
            .verify(format!("{p}.{pl}").as_bytes(), &sig)
            .map_err(|_| bad("malformed", "JWS verification error"))?;
        let payload = b64url::decode(pl).ok_or_else(|| bad("malformed", "bad payload encoding"))?;
        Ok(Verified { payload, account, jwk })
    }

    fn authz_json(&self, id: &str, a: &Authz) -> Value {
        let status = authz_status(a);
        let chals = a
            .challenges
            .iter()
            .map(|(ty, token, st, err)| {
                let mut m = vec![
                    ("type", Value::str(*ty)),
                    ("url", Value::str(self.url(&format!("/chall/{id}/{ty}")))),
                    ("status", Value::str(*st)),
                    ("token", Value::str(token.clone())),
                ];
                if let Some(e) = err {
                    m.push((
                        "error",
                        Value::obj([("type", Value::str("urn:ietf:params:acme:error:unauthorized")), ("detail", Value::str(e.clone()))]),
                    ));
                }
                Value::obj_vec(m)
            })
            .collect();
        Value::obj([
            ("identifier", Value::obj([("type", Value::str("dns")), ("value", Value::str(a.domain.clone()))])),
            ("status", Value::str(status)),
            ("expires", Value::str("2099-01-01T00:00:00Z")),
            ("challenges", Value::Arr(chals)),
        ])
    }

    /// An order's status follows from its authorizations and whether it was finalized.
    fn order_json(&self, id: &str, book: &mut Book) -> Value {
        let o = &book.orders[id];
        let statuses: Vec<&str> = o.authzs.iter().map(|a| authz_status(&book.authzs[a])).collect();
        let mut status = if o.cert.is_some() {
            "valid"
        } else if statuses.contains(&"invalid") {
            "invalid"
        } else if statuses.iter().all(|s| *s == "valid") {
            "ready"
        } else {
            "pending"
        };
        let o = book.orders.get_mut(id).unwrap();
        if status == "valid" && o.processing > 0 {
            o.processing -= 1;
            status = "processing";
        }
        let mut m = vec![
            ("status", Value::str(status)),
            ("expires", Value::str("2099-01-01T00:00:00Z")),
            (
                "identifiers",
                Value::Arr(o.domains.iter().map(|d| Value::obj([("type", Value::str("dns")), ("value", Value::str(d.clone()))])).collect()),
            ),
            ("authorizations", Value::Arr(o.authzs.iter().map(|a| Value::str(self.url(&format!("/authz/{a}")))).collect())),
            ("finalize", Value::str(self.url(&format!("/finalize/{id}")))),
        ];
        if status == "valid" {
            m.push(("certificate", Value::str(self.url(&format!("/cert/{id}")))));
        }
        Value::obj_vec(m)
    }
}

fn authz_status(a: &Authz) -> &'static str {
    if a.challenges.iter().any(|c| c.2 == "valid") {
        "valid"
    } else if a.challenges.iter().any(|c| c.2 == "invalid") {
        "invalid"
    } else {
        "pending"
    }
}

fn route(st: &Arc<State>, method: &str, path: &str, accept: Option<&str>, body: &[u8]) -> Reply {
    match (method, path) {
        ("GET", "/directory") => {
            let meta = Value::obj([("termsOfService", Value::str(st.url("/terms")))]);
            return json_reply(
                200,
                &Value::obj([
                    ("newNonce", Value::str(st.url("/new-nonce"))),
                    ("newAccount", Value::str(st.url("/new-acct"))),
                    ("newOrder", Value::str(st.url("/new-order"))),
                    ("meta", meta),
                ]),
            );
        }
        ("HEAD" | "GET", "/new-nonce") => return Reply { status: 200, headers: vec![], body: vec![] },
        ("POST", _) => {}
        _ => return problem(404, "malformed", "no such resource"),
    }
    let v = match st.verify(path, body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let payload = if v.payload.is_empty() { None } else { json::parse(&String::from_utf8_lossy(&v.payload)).ok() };
    match path {
        "/new-acct" => new_account(st, &v, payload),
        "/new-order" => new_order(st, &v, payload),
        _ => {
            let (Some(account), parts) = (v.account.clone(), path.trim_start_matches('/').split('/').collect::<Vec<_>>()) else {
                return problem(400, "malformed", "needs an account");
            };
            match parts.as_slice() {
                ["authz", id] => {
                    let book = lock(&st.book);
                    match book.authzs.get(*id).filter(|a| a.account == account) {
                        Some(a) => json_reply(200, &st.authz_json(id, a)),
                        None => problem(404, "malformed", "no such authorization"),
                    }
                }
                ["chall", id, ty] => challenge(st, id, ty, &account),
                ["order", id] => {
                    let mut book = lock(&st.book);
                    if book.orders.get(*id).is_none_or(|o| o.account != account) {
                        return problem(404, "malformed", "no such order");
                    }
                    let j = st.order_json(id, &mut book);
                    json_reply(200, &j)
                }
                ["finalize", id] => finalize(st, id, &account, payload),
                ["cert", id] => {
                    // RFC 8555 section 7.4.2: the client says which format it wants.
                    if accept != Some("application/pem-certificate-chain") {
                        return problem(406, "malformed", "ask for application/pem-certificate-chain");
                    }
                    let book = lock(&st.book);
                    match book.orders.get(*id).filter(|o| o.account == account).and_then(|o| o.cert.clone()) {
                        Some(pem) => Reply {
                            status: 200,
                            headers: vec![("Content-Type".into(), "application/pem-certificate-chain".into())],
                            body: pem.into_bytes(),
                        },
                        None => problem(404, "malformed", "no certificate"),
                    }
                }
                _ => problem(404, "malformed", "no such resource"),
            }
        }
    }
}

fn new_account(st: &Arc<State>, v: &Verified, payload: Option<Value>) -> Reply {
    let Some((point, x, y)) = &v.jwk else { return problem(400, "malformed", "newAccount must be signed with a jwk") };
    let payload = payload.unwrap_or(Value::Null);
    if payload.get("termsOfServiceAgreed") != Some(&Value::Bool(true)) {
        return problem(403, "userActionRequired", "you must agree to the terms of service");
    }
    let canonical = format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}");
    let thumbprint = b64url::encode(digest(&SHA256, canonical.as_bytes()).as_ref());
    let mut book = lock(&st.book);
    let existing = book.accounts.iter().find(|(_, a)| a.thumbprint == thumbprint).map(|(id, _)| id.clone());
    let (id, status) = match existing {
        Some(id) => (id, 200),
        None => {
            let id = st.fresh_id();
            let contact = payload
                .get("contact")
                .and_then(Value::as_array)
                .unwrap_or_default()
                .iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect();
            book.accounts.insert(id.clone(), Account { point: point.clone(), thumbprint, contact });
            (id, 201)
        }
    };
    let mut r = json_reply(status, &Value::obj([("status", Value::str("valid"))]));
    r.headers.push(("Location".into(), st.url(&format!("/acct/{id}"))));
    r
}

fn new_order(st: &Arc<State>, v: &Verified, payload: Option<Value>) -> Reply {
    let Some(account) = v.account.clone() else { return problem(400, "malformed", "needs an account") };
    if st.fail_orders.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)).is_ok() {
        return problem(500, "serverInternal", "the mock CA is having a bad day");
    }
    let domains: Vec<String> = payload
        .as_ref()
        .and_then(|p| p.get("identifiers"))
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter(|i| i.str_of("type") == Some("dns"))
        .filter_map(|i| i.str_of("value").map(str::to_ascii_lowercase))
        .collect();
    if domains.is_empty() {
        return problem(400, "malformed", "no identifiers");
    }
    let mut book = lock(&st.book);
    let mut authz_ids = Vec::new();
    for d in &domains {
        let id = st.fresh_id();
        let challenges = lock(&st.offer).iter().map(|&ty| (ty, random_token(), "pending", None)).collect();
        book.authzs.insert(id.clone(), Authz { account: account.clone(), domain: d.clone(), challenges });
        authz_ids.push(id);
    }
    let id = st.fresh_id();
    book.orders.insert(id.clone(), Order { account, domains, authzs: authz_ids, cert: None, processing: 0 });
    let mut r = json_reply(201, &st.order_json(&id, &mut book));
    r.headers.push(("Location".into(), st.url(&format!("/order/{id}"))));
    r
}

fn challenge(st: &Arc<State>, authz_id: &str, ty: &str, account: &str) -> Reply {
    let mut book = lock(&st.book);
    let Some(a) = book.authzs.get_mut(authz_id).filter(|a| a.account == account) else {
        return problem(404, "malformed", "no such challenge");
    };
    let Some(c) = a.challenges.iter_mut().find(|c| c.0 == ty) else { return problem(404, "malformed", "no such challenge") };
    if c.2 != "pending" {
        return problem(400, "malformed", "the challenge is not pending");
    }
    c.2 = "processing";
    let reply = json_reply(
        200,
        &Value::obj([
            ("type", Value::str(ty)),
            ("url", Value::str(st.url(&format!("/chall/{authz_id}/{ty}")))),
            ("status", Value::str("processing")),
            ("token", Value::str(c.1.clone())),
        ]),
    );
    let ty: &'static str = if ty == TLS_ALPN { TLS_ALPN } else { HTTP };
    let (domain, token, thumbprint) = (a.domain.clone(), c.1.clone(), book.accounts[account].thumbprint.clone());
    let (st, authz_id) = (st.clone(), authz_id.to_string());
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        let key_authorization = format!("{token}.{thumbprint}");
        let outcome = if lock(&st.fail).contains(ty) {
            Err("simulated validation failure".to_string())
        } else if ty == TLS_ALPN {
            validate_alpn(&st, &domain, &key_authorization).await
        } else {
            validate_http(&st, &domain, &token, &key_authorization).await
        };
        let mut book = lock(&st.book);
        book.validations.push(match &outcome {
            Ok(()) => format!("{ty} {domain} ok"),
            Err(e) => format!("{ty} {domain} failed: {e}"),
        });
        if let Some(c) = book.authzs.get_mut(&authz_id).and_then(|a| a.challenges.iter_mut().find(|c| c.0 == ty)) {
            match outcome {
                Ok(()) => c.2 = "valid",
                Err(e) => (c.2, c.3) = ("invalid", Some(e)),
            }
        }
    });
    reply
}

/// What a CA's validator accepts as a server's proof: the handshake signature must
/// verify under the certificate's own key (the server holds it), but the chain is not
/// checked. It reads the certificate with this crate's parser: a general-purpose
/// one (webpki) rejects the critical acmeIdentifier extension, which is exactly why
/// validators do not use one.
#[derive(Debug)]
pub(crate) struct AcceptAny;

impl AcceptAny {
    fn verify(message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        let bad = |m: &str| rustls::Error::General(m.to_string());
        if dss.scheme != SignatureScheme::ECDSA_NISTP256_SHA256 {
            return Err(bad("the mock CA only verifies ECDSA P-256 signatures"));
        }
        let info = x509::parse_certificate(cert).map_err(|e| bad(&e.to_string()))?;
        let mut parts = Reader::new(&info.spki).expect(der::SEQUENCE).map_err(|e| bad(&e.to_string()))?.children();
        parts.next().map_err(|e| bad(&e.to_string()))?;
        let point = parts.expect(der::BIT_STRING).map_err(|e| bad(&e.to_string()))?.content[1..].to_vec();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point)
            .verify(message, dss.signature())
            .map_err(|_| bad("the handshake signature is wrong"))?;
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        AcceptAny::verify(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        AcceptAny::verify(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// RFC 8737 §3: connect with ALPN `acme-tls/1` and SNI of the domain; the server's
/// certificate must name exactly the domain and carry the critical acmeIdentifier
/// extension with the SHA-256 of the key authorization.
async fn validate_alpn(st: &State, domain: &str, key_authorization: &str) -> Result<(), String> {
    let target = lock(&st.settings).https_target.ok_or("no TLS target configured")?;
    let tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target))
        .await
        .map_err(|_| "connection timed out".to_string())?
        .map_err(|e| format!("connection failed: {e}"))?;
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![crate::ACME_ALPN.to_vec()];
    let name = ServerName::try_from(domain.to_string()).map_err(|e| e.to_string())?;
    let tls = tokio::time::timeout(Duration::from_secs(5), TlsConnector::from(Arc::new(cfg)).connect(name, tcp))
        .await
        .map_err(|_| "handshake timed out".to_string())?
        .map_err(|e| format!("handshake failed: {e}"))?;
    let (_, conn) = tls.get_ref();
    if conn.alpn_protocol() != Some(crate::ACME_ALPN) {
        return Err("the server did not agree to acme-tls/1".to_string());
    }
    let cert = conn.peer_certificates().and_then(|c| c.first()).ok_or("the server sent no certificate")?;
    let info = x509::parse_certificate(cert).map_err(|e| e.to_string())?;
    if info.names != [domain.to_ascii_lowercase()] {
        return Err(format!("the certificate names {:?}, not just {domain}", info.names));
    }
    let (critical, value) = info.acme_identifier.ok_or("the certificate has no acmeIdentifier extension")?;
    if !critical {
        return Err("the acmeIdentifier extension is not critical".to_string());
    }
    let expected = [&[0x04, 0x20][..], digest(&SHA256, key_authorization.as_bytes()).as_ref()].concat();
    if value != expected {
        return Err("the acmeIdentifier does not match the key authorization".to_string());
    }
    Ok(())
}

/// RFC 8555 §8.3: GET the token's path on port 80 with the domain as Host.
async fn validate_http(st: &State, domain: &str, token: &str, key_authorization: &str) -> Result<(), String> {
    let target = lock(&st.settings).http_target.ok_or("no HTTP target configured")?;
    let mut tcp = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(target))
        .await
        .map_err(|_| "connection timed out".to_string())?
        .map_err(|e| format!("connection failed: {e}"))?;
    tcp.write_all(format!("GET /.well-known/acme-challenge/{token} HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut raw))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no HTTP response")?;
    if !head.starts_with("HTTP/1.1 200") {
        return Err(format!("unexpected response: {}", head.lines().next().unwrap_or("")));
    }
    if body.trim() != key_authorization {
        return Err("the response is not the key authorization".to_string());
    }
    Ok(())
}

struct Csr {
    names: Vec<String>,
    spki: Vec<u8>,
}

/// Reads a PKCS#10 request and checks that the key it names signed it.
fn parse_csr(csr: &[u8]) -> Result<Csr, String> {
    let e = |e: der::DerError| e.to_string();
    let mut top = Reader::new(csr).expect(der::SEQUENCE).map_err(e)?.children();
    let info = top.expect(der::SEQUENCE).map_err(e)?;
    top.expect(der::SEQUENCE).map_err(e)?;
    let sig = top.expect(der::BIT_STRING).map_err(e)?;
    let mut f = info.children();
    f.expect(der::INTEGER).map_err(e)?;
    f.expect(der::SEQUENCE).map_err(e)?;
    let spki = f.expect(der::SEQUENCE).map_err(e)?;
    let mut parts = spki.children();
    parts.expect(der::SEQUENCE).map_err(e)?;
    let point = parts.expect(der::BIT_STRING).map_err(e)?.content[1..].to_vec();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point)
        .verify(info.raw, &sig.content[1..])
        .map_err(|_| "the CSR's signature is wrong".to_string())?;
    let attrs = f.expect(der::context(0)).map_err(e)?;
    let mut names = Vec::new();
    let mut list = attrs.children();
    while !list.is_empty() {
        let mut attr = list.expect(der::SEQUENCE).map_err(e)?.children();
        let id = der::oid_to_string(attr.expect(der::OID).map_err(e)?.content).map_err(e)?;
        let set = attr.expect(der::SET).map_err(e)?;
        if id != "1.2.840.113549.1.9.14" {
            continue;
        }
        let mut exts = set.children().expect(der::SEQUENCE).map_err(e)?.children();
        while !exts.is_empty() {
            let mut ext = exts.expect(der::SEQUENCE).map_err(e)?.children();
            let id = der::oid_to_string(ext.expect(der::OID).map_err(e)?.content).map_err(e)?;
            let value = ext.expect(der::OCTET_STRING).map_err(e)?.content;
            if id == "2.5.29.17" {
                let mut general = Reader::new(value).expect(der::SEQUENCE).map_err(e)?.children();
                while !general.is_empty() {
                    let g = general.next().map_err(e)?;
                    names.push(String::from_utf8_lossy(g.content).to_ascii_lowercase());
                }
            }
        }
    }
    Ok(Csr { names, spki: spki.raw.to_vec() })
}

fn finalize(st: &Arc<State>, id: &str, account: &str, payload: Option<Value>) -> Reply {
    let mut book = lock(&st.book);
    let statuses: Vec<&str> = match book.orders.get(id).filter(|o| o.account == account) {
        Some(o) => o.authzs.iter().map(|a| authz_status(&book.authzs[a])).collect(),
        None => return problem(404, "malformed", "no such order"),
    };
    if statuses.iter().any(|s| *s != "valid") || book.orders[id].cert.is_some() {
        return problem(403, "orderNotReady", "the order is not ready to be finalized");
    }
    let Some(csr_der) = payload.as_ref().and_then(|p| p.str_of("csr")).and_then(b64url::decode) else {
        return problem(400, "badCSR", "no csr");
    };
    let csr = match parse_csr(&csr_der) {
        Ok(c) => c,
        Err(e) => return problem(400, "badCSR", &e),
    };
    // The certificate names what the order asked for, in the order asked.
    let want = book.orders[id].domains.clone();
    let (mut a, mut b) = (want.clone(), csr.names.clone());
    a.sort();
    b.sort();
    if a != b {
        return problem(400, "badCSR", &format!("the CSR names {:?} but the order is for {want:?}", csr.names));
    }
    let (lifetime, now) = (lock(&st.settings).lifetime, time::now());
    let leaf = x509::build_certificate(
        &CertSpec {
            serial: &x509::random_serial(),
            issuer_cn: "Test Root",
            subject_cn: &want[0],
            not_before: now,
            not_after: now + lifetime,
            spki: &csr.spki,
            dns_names: &want,
            ca: false,
            acme_identifier: None,
        },
        &st.ca_key,
    );
    let chain = pem::encode("CERTIFICATE", &leaf) + &pem::encode("CERTIFICATE", &st.ca_der);
    let o = book.orders.get_mut(id).unwrap();
    o.cert = Some(chain);
    o.processing = 2;
    book.issued += 1;
    let j = st.order_json(id, &mut book);
    json_reply(200, &j)
}
