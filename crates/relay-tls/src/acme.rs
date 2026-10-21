//! An ACME client (RFC 8555) for one account at one CA: directory, nonces, account,
//! order, authorizations answered by TLS-ALPN-01 (RFC 8737) or HTTP-01, finalize
//! with a CSR, and download of the certificate chain.
//!
//! One [`Client`] runs one order at a time. Challenge answers are put where the
//! servers look for them ([`Challenges`]) before the CA is told to validate, and
//! removed again whatever happens.

use crate::certs::{self, Challenges};
use crate::json::{self, Value};
use crate::jws::{self, Signer};
use crate::x509::{self, CertInfo, EcKey};
use crate::{b64url, http, pem};
use ring::digest::{digest, SHA256};
use std::fmt;
use std::time::{Duration, Instant};

/// How a domain proves it is ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    TlsAlpn01,
    Http01,
}

impl Method {
    /// The challenge type's name in the protocol.
    pub fn name(self) -> &'static str {
        match self {
            Method::TlsAlpn01 => "tls-alpn-01",
            Method::Http01 => "http-01",
        }
    }
}

#[derive(Debug, Clone)]
pub enum Error {
    /// The CA refused, with an RFC 7807 problem document (RFC 8555 §6.7).
    Problem { status: u16, kind: String, detail: String },
    /// Anything else: the CA unreachable or incoherent, a validation that failed.
    Failed(String),
}

impl Error {
    fn is_bad_nonce(&self) -> bool {
        matches!(self, Error::Problem { kind, .. } if kind == "urn:ietf:params:acme:error:badNonce")
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Problem { status, kind, detail } => {
                let short = kind.strip_prefix("urn:ietf:params:acme:error:").unwrap_or(kind);
                let sep = if detail.is_empty() { "" } else { ": " };
                write!(f, "the CA refused ({short}, HTTP {status}){sep}{detail}")
            }
            Error::Failed(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for Error {}

fn failed(msg: impl Into<String>) -> Error {
    Error::Failed(msg.into())
}

/// How long the client waits on the CA.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Between looks at an authorization or order that is still being worked on.
    pub poll_interval: Duration,
    /// How long one of them may take before the attempt is given up.
    pub poll_timeout: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing { poll_interval: Duration::from_secs(2), poll_timeout: Duration::from_secs(120) }
    }
}

/// A certificate the CA issued, with the key made for it.
#[derive(Debug)]
pub struct Issued {
    /// The chain as PEM, leaf first.
    pub chain_pem: String,
    /// The certificate's private key as PKCS#8 PEM.
    pub key_pem: String,
    pub info: CertInfo,
    pub method: Method,
}

pub struct Client {
    http: http::Client,
    key: EcKey,
    new_nonce: String,
    new_order: String,
    /// The account URL, once registered.
    kid: Option<String>,
    nonce: Option<String>,
    https: bool,
    terms: Option<String>,
    timing: Timing,
}

/// A problem document in a response, as an error.
fn problem(resp: &http::Response) -> Error {
    let text = String::from_utf8_lossy(&resp.body);
    let Ok(v) = json::parse(&text) else {
        let snippet: String = text.chars().take(200).collect();
        return Error::Problem { status: resp.status, kind: String::new(), detail: snippet.trim().to_string() };
    };
    let mut detail = v.str_of("detail").unwrap_or_default().to_string();
    for sub in v.get("subproblems").and_then(Value::as_array).unwrap_or_default() {
        let who = sub.get("identifier").and_then(|i| i.str_of("value")).unwrap_or("?");
        detail.push_str(&format!("; {who}: {}", sub.str_of("detail").unwrap_or_default()));
    }
    Error::Problem { status: resp.status, kind: v.str_of("type").unwrap_or_default().to_string(), detail }
}

fn transport(what: &str, e: std::io::Error) -> Error {
    failed(format!("{what}: {e}"))
}

impl Client {
    /// Reads the CA's directory and registers (or finds) the account for `key`.
    /// Registering agrees to the CA's terms of service ([`terms`](Self::terms)).
    pub async fn connect(http: http::Client, directory: &str, key: EcKey, email: Option<&str>, timing: Timing) -> Result<Client, Error> {
        let resp = http
            .request("GET", directory, &[("Accept", "application/json")], b"")
            .await
            .map_err(|e| transport(&format!("cannot reach the CA at {directory}"), e))?;
        if resp.status != 200 {
            return Err(match problem(&resp) {
                Error::Problem { kind, detail, .. } if !kind.is_empty() => Error::Problem { status: resp.status, kind, detail },
                _ => failed(format!("the CA's directory at {directory} answered HTTP {}", resp.status)),
            });
        }
        let dir = json::parse(&String::from_utf8_lossy(&resp.body)).map_err(|e| failed(format!("the CA's directory is not JSON: {e}")))?;
        let url = |name: &str| dir.str_of(name).map(str::to_string).ok_or_else(|| failed(format!("the CA's directory has no {name}")));
        let mut c = Client {
            http,
            key,
            new_nonce: url("newNonce")?,
            new_order: url("newOrder")?,
            kid: None,
            nonce: None,
            https: directory.starts_with("https://"),
            terms: dir.get("meta").and_then(|m| m.str_of("termsOfService")).map(str::to_string),
            timing,
        };
        let new_account = url("newAccount")?;
        for u in [&c.new_nonce, &c.new_order, &new_account] {
            c.check_url(u)?;
        }
        let mut payload = vec![("termsOfServiceAgreed", Value::Bool(true))];
        if let Some(e) = email {
            payload.push(("contact", Value::Arr(vec![Value::str(format!("mailto:{e}"))])));
        }
        let resp = c.post(&new_account, Some(&Value::obj_vec(payload))).await?;
        let kid = resp.header("location").ok_or_else(|| failed("the CA did not say where the account lives"))?.to_string();
        c.check_url(&kid)?;
        c.kid = Some(kid);
        Ok(c)
    }

    /// The CA's terms of service, which registering agreed to.
    pub fn terms(&self) -> Option<&str> {
        self.terms.as_deref()
    }

    /// URLs the CA hands out are fetched only over the same kind of connection as
    /// the directory: a CA cannot send the client to plain HTTP.
    fn check_url(&self, url: &str) -> Result<(), Error> {
        if self.https && !url.starts_with("https://") {
            return Err(failed(format!("the CA sent a URL that is not https: {url}")));
        }
        Ok(())
    }

    async fn fetch_nonce(&mut self) -> Result<String, Error> {
        let resp =
            self.http.request("HEAD", &self.new_nonce, &[], b"").await.map_err(|e| transport("cannot get a nonce from the CA", e))?;
        resp.header("replay-nonce")
            .map(str::to_string)
            .ok_or_else(|| failed(format!("the CA's nonce endpoint answered HTTP {} without a Replay-Nonce", resp.status)))
    }

    /// A signed POST. `payload: None` is POST-as-GET. Every answer's nonce is kept for
    /// the next request, and a `badNonce` refusal is retried with the fresh one.
    async fn post(&mut self, url: &str, payload: Option<&Value>) -> Result<http::Response, Error> {
        self.post_accepting(url, payload, "application/json").await
    }

    async fn post_accepting(&mut self, url: &str, payload: Option<&Value>, accept: &str) -> Result<http::Response, Error> {
        self.check_url(url)?;
        let mut retries = 0;
        loop {
            let nonce = match self.nonce.take() {
                Some(n) => n,
                None => self.fetch_nonce().await?,
            };
            let signer = self.kid.as_deref().map_or(Signer::Jwk, Signer::Kid);
            let body = jws::sign(&self.key, signer, &nonce, url, payload);
            let resp = self
                .http
                .request("POST", url, &[("Content-Type", "application/jose+json"), ("Accept", accept)], body.as_bytes())
                .await
                .map_err(|e| transport(&format!("request to {url} failed"), e))?;
            self.nonce = resp.header("replay-nonce").map(str::to_string);
            if resp.status < 400 {
                return Ok(resp);
            }
            let err = problem(&resp);
            if err.is_bad_nonce() && retries < 3 && self.nonce.is_some() {
                retries += 1;
                continue;
            }
            return Err(err);
        }
    }

    async fn post_json(&mut self, url: &str, payload: Option<&Value>) -> Result<(Value, http::Response), Error> {
        let resp = self.post(url, payload).await?;
        let v = json::parse(&String::from_utf8_lossy(&resp.body))
            .map_err(|e| failed(format!("{url} answered something that is not JSON: {e}")))?;
        Ok((v, resp))
    }

    /// Gets a certificate for `domains`, proving control by `method`.
    pub async fn obtain(&mut self, domains: &[String], method: Method, challenges: &Challenges) -> Result<Issued, Error> {
        let mut installed = Installed::default();
        let result = self.order(domains, method, challenges, &mut installed).await;
        installed.remove(challenges);
        result
    }

    async fn order(
        &mut self,
        domains: &[String],
        method: Method,
        challenges: &Challenges,
        installed: &mut Installed,
    ) -> Result<Issued, Error> {
        let identifiers =
            Value::Arr(domains.iter().map(|d| Value::obj([("type", Value::str("dns")), ("value", Value::str(d.clone()))])).collect());
        let new_order = self.new_order.clone();
        let (order, resp) = self.post_json(&new_order, Some(&Value::obj([("identifiers", identifiers)]))).await?;
        let order_url = resp.header("location").ok_or_else(|| failed("the CA did not say where the order lives"))?.to_string();
        let finalize = order.str_of("finalize").ok_or_else(|| failed("the order has no finalize URL"))?.to_string();
        let authz_urls: Vec<String> = order
            .get("authorizations")
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|a| a.as_str().map(str::to_string))
            .collect();

        // Answer every pending authorization, then wait for the CA's verdicts together.
        let challenge_key = EcKey::generate().map_err(failed)?;
        let mut waiting = Vec::new();
        for url in &authz_urls {
            let (authz, _) = self.post_json(url, None).await?;
            let domain = authz
                .get("identifier")
                .and_then(|i| i.str_of("value"))
                .ok_or_else(|| failed("an authorization names no domain"))?
                .to_string();
            match authz.str_of("status") {
                Some("valid") => continue,
                Some("pending") => {}
                other => return Err(failed(format!("the CA's authorization for {domain} is {}", other.unwrap_or("in an unknown state")))),
            }
            let offered = authz.get("challenges").and_then(Value::as_array).unwrap_or_default();
            let Some(chal) = offered.iter().find(|c| c.str_of("type") == Some(method.name())) else {
                return Err(failed(format!("the CA does not offer {} for {domain}", method.name())));
            };
            let (Some(token), Some(chal_url)) = (chal.str_of("token"), chal.str_of("url")) else {
                return Err(failed(format!("the CA's {} challenge for {domain} is incomplete", method.name())));
            };
            let key_authorization = jws::key_authorization(token, &self.key);
            match method {
                Method::Http01 => {
                    challenges.set_http(token, key_authorization);
                    installed.tokens.push(token.to_string());
                }
                Method::TlsAlpn01 => {
                    let digest: [u8; 32] = digest(&SHA256, key_authorization.as_bytes()).as_ref().try_into().expect("SHA-256 is 32 bytes");
                    let cert = x509::acme_challenge_certificate(&challenge_key, &domain, digest, crate::time::now());
                    challenges.set_alpn(&domain, certs::certified(cert, &challenge_key));
                    installed.domains.push(domain.clone());
                }
            }
            self.check_url(chal_url)?;
            let chal_url = chal_url.to_string();
            self.post_json(&chal_url, Some(&Value::obj([]))).await?;
            waiting.push((url.clone(), domain));
        }
        for (url, domain) in &waiting {
            self.await_authorization(url, domain, method).await?;
        }

        self.await_order(&order_url, &["ready", "valid"]).await?;
        let cert_key = EcKey::generate().map_err(failed)?;
        let csr = x509::csr(&cert_key, domains);
        let (finalized, _) = self.post_json(&finalize, Some(&Value::obj([("csr", Value::Str(b64url::encode(&csr)))]))).await?;
        let done = if finalized.str_of("status") == Some("valid") { finalized } else { self.await_order(&order_url, &["valid"]).await? };
        let cert_url = done.str_of("certificate").ok_or_else(|| failed("the CA finished the order without a certificate"))?.to_string();
        let resp = self.post_accepting(&cert_url, None, "application/pem-certificate-chain").await?;
        let chain_pem = String::from_utf8(resp.body).map_err(|_| failed("the certificate is not text"))?;
        let chain = pem::certificates(&chain_pem).map_err(|e| failed(format!("the CA's certificate cannot be read: {e}")))?;
        let info = x509::parse_certificate(&chain[0]).map_err(|e| failed(format!("the CA's certificate cannot be read: {e}")))?;
        if !info.covers(domains) || info.spki != cert_key.spki() {
            return Err(failed("the CA issued a certificate that is not for the names and key requested"));
        }
        Ok(Issued { chain_pem, key_pem: pem::encode("PRIVATE KEY", cert_key.pkcs8()), info, method })
    }

    /// Waits until the authorization is valid; an invalid one is an error carrying the
    /// CA's explanation.
    async fn await_authorization(&mut self, url: &str, domain: &str, method: Method) -> Result<(), Error> {
        let deadline = Instant::now() + self.timing.poll_timeout;
        loop {
            let (authz, _) = self.post_json(url, None).await?;
            match authz.str_of("status") {
                Some("valid") => return Ok(()),
                Some("pending" | "processing") => {}
                other => {
                    let why = authz
                        .get("challenges")
                        .and_then(Value::as_array)
                        .unwrap_or_default()
                        .iter()
                        .find(|c| c.str_of("type") == Some(method.name()))
                        .and_then(|c| c.get("error"))
                        .and_then(|e| e.str_of("detail"))
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("the authorization is {}", other.unwrap_or("in an unknown state")));
                    return Err(failed(format!("{} validation of {domain} failed: {why}", method.name())));
                }
            }
            if Instant::now() >= deadline {
                return Err(failed(format!(
                    "the CA did not finish validating {domain} within {} seconds",
                    self.timing.poll_timeout.as_secs()
                )));
            }
            tokio::time::sleep(self.timing.poll_interval).await;
        }
    }

    /// Waits until the order reaches one of `wanted`; an invalid order is an error.
    async fn await_order(&mut self, url: &str, wanted: &[&str]) -> Result<Value, Error> {
        let deadline = Instant::now() + self.timing.poll_timeout;
        loop {
            let (order, _) = self.post_json(url, None).await?;
            let status = order.str_of("status").unwrap_or("unknown").to_string();
            if wanted.contains(&status.as_str()) {
                return Ok(order);
            }
            if status == "invalid" {
                let detail = order.get("error").and_then(|e| e.str_of("detail")).unwrap_or("no reason given");
                return Err(failed(format!("the CA rejected the order: {detail}")));
            }
            if Instant::now() >= deadline {
                return Err(failed(format!("the order was still {status} after {} seconds", self.timing.poll_timeout.as_secs())));
            }
            tokio::time::sleep(self.timing.poll_interval).await;
        }
    }
}

/// What was put in [`Challenges`] for one order, to take out again.
#[derive(Default)]
struct Installed {
    domains: Vec<String>,
    tokens: Vec<String>,
}

impl Installed {
    fn remove(&self, challenges: &Challenges) {
        for d in &self.domains {
            challenges.clear_alpn(d);
        }
        for t in &self.tokens {
            challenges.clear_http(t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &str) -> http::Response {
        http::Response { status, headers: vec![], body: body.as_bytes().to_vec() }
    }

    #[test]
    fn refusals_read_as_sentences() {
        let e = problem(&response(
            429,
            r#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many certificates already issued for this exact set of identifiers","status":429}"#,
        ));
        assert_eq!(
            e.to_string(),
            "the CA refused (rateLimited, HTTP 429): too many certificates already issued for this exact set of identifiers"
        );
    }

    #[test]
    fn subproblems_name_their_domain() {
        let e = problem(&response(
            400,
            r#"{"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"Invalid identifiers requested","subproblems":[
                {"type":"urn:ietf:params:acme:error:rejectedIdentifier","detail":"Policy forbids issuing for name","identifier":{"type":"dns","value":"a.example"}},
                {"type":"urn:ietf:params:acme:error:malformed","detail":"bad name","identifier":{"type":"dns","value":"b.example"}}]}"#,
        ));
        let text = e.to_string();
        assert!(
            text.contains("rejectedIdentifier")
                && text.contains("Invalid identifiers requested; a.example: Policy forbids issuing for name; b.example: bad name"),
            "{text}"
        );
    }

    #[test]
    fn a_refusal_that_is_not_json_still_says_something() {
        let e = problem(&response(503, "<html>Service Unavailable</html>"));
        assert_eq!(e.to_string(), "the CA refused (, HTTP 503): <html>Service Unavailable</html>");
        let long = "x".repeat(1000);
        let Error::Problem { detail, .. } = problem(&response(500, &long)) else { panic!() };
        assert_eq!(detail.len(), 200, "long bodies are cut");
    }

    #[test]
    fn only_a_bad_nonce_refusal_is_retried() {
        assert!(problem(&response(400, r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"x"}"#)).is_bad_nonce());
        assert!(!problem(&response(400, r#"{"type":"urn:ietf:params:acme:error:malformed","detail":"x"}"#)).is_bad_nonce());
        assert!(!failed("badNonce").is_bad_nonce());
    }

    #[test]
    fn method_names_are_the_protocols() {
        assert_eq!((Method::TlsAlpn01.name(), Method::Http01.name()), ("tls-alpn-01", "http-01"));
    }
}
