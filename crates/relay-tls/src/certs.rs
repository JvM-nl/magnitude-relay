//! The certificates a server hands out: the current one behind a lock, the
//! short-lived challenge answers, and the rustls hook that picks between them.

use crate::x509::{self, CertInfo, EcKey};
use crate::{pem, ACME_ALPN};
use rustls::crypto::ring::{default_provider, sign::any_supported_type};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::{TLS12, TLS13};
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A certificate in service: what rustls signs with, and what it says about itself.
#[derive(Debug)]
pub struct Current {
    pub key: Arc<CertifiedKey>,
    pub info: CertInfo,
}

/// Parses a PEM chain (leaf first) and its private key into something rustls can
/// serve, refusing a key that does not belong to the leaf.
pub fn load(chain_pem: &str, key_pem: &str) -> Result<Current, String> {
    let chain = pem::certificates(chain_pem)?;
    let key = pem::private_key(key_pem)?;
    let key_der = match key.label.as_str() {
        "PRIVATE KEY" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.der)),
        "EC PRIVATE KEY" => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(key.der)),
        _ => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(key.der)),
    };
    let info = x509::parse_certificate(&chain[0]).map_err(|e| format!("the certificate cannot be read: {e}"))?;
    let chain = chain.into_iter().map(CertificateDer::from).collect();
    let key = CertifiedKey::from_der(chain, key_der, &default_provider()).map_err(|e| match e {
        rustls::Error::InconsistentKeys(_) => "the private key does not belong to the certificate".to_string(),
        e => format!("the private key cannot be used: {e}"),
    })?;
    Ok(Current { key: Arc::new(key), info })
}

/// A single-certificate chain signed with `key`, for challenge answers.
pub fn certified(cert_der: Vec<u8>, key: &EcKey) -> Arc<CertifiedKey> {
    let signer =
        any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.pkcs8().to_vec()))).expect("a P-256 key we generated loads");
    Arc::new(CertifiedKey::new(vec![CertificateDer::from(cert_der)], signer))
}

/// The answers to challenges in flight. Both kinds are looked up by something the CA
/// sends: the SNI of a TLS-ALPN-01 hello, the token in an HTTP-01 request path.
#[derive(Default, Debug)]
pub struct Challenges {
    alpn: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    http: RwLock<HashMap<String, String>>,
}

impl Challenges {
    pub fn set_alpn(&self, domain: &str, cert: Arc<CertifiedKey>) {
        self.alpn.write().unwrap_or_else(|e| e.into_inner()).insert(domain.to_ascii_lowercase(), cert);
    }

    pub fn clear_alpn(&self, domain: &str) {
        self.alpn.write().unwrap_or_else(|e| e.into_inner()).remove(&domain.to_ascii_lowercase());
    }

    pub fn alpn(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        self.alpn.read().unwrap_or_else(|e| e.into_inner()).get(&domain.to_ascii_lowercase()).cloned()
    }

    pub fn set_http(&self, token: &str, key_authorization: String) {
        self.http.write().unwrap_or_else(|e| e.into_inner()).insert(token.to_string(), key_authorization);
    }

    pub fn clear_http(&self, token: &str) {
        self.http.write().unwrap_or_else(|e| e.into_inner()).remove(token);
    }

    pub fn http(&self, token: &str) -> Option<String> {
        self.http.read().unwrap_or_else(|e| e.into_inner()).get(token).cloned()
    }
}

/// The certificate every handshake gets, swapped whole when it is renewed: a
/// handshake in progress keeps the one it started with, the next one gets the new.
#[derive(Default, Debug)]
pub struct Certs {
    current: RwLock<Option<Arc<Current>>>,
    pub challenges: Challenges,
}

impl Certs {
    pub fn current(&self) -> Option<Arc<Current>> {
        self.current.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set(&self, cert: Current) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(cert));
    }
}

impl ResolvesServerCert for Certs {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // A CA validating TLS-ALPN-01 offers this protocol and nothing else, and wants
        // the challenge certificate for the name it asked about (RFC 8737 §3).
        if hello.alpn().is_some_and(|mut p| p.any(|p| p == ACME_ALPN)) {
            return self.challenges.alpn(hello.server_name()?);
        }
        self.current().map(|c| c.key.clone())
    }
}

/// The server side of every TLS connection: TLS 1.3 and 1.2, no client certificates,
/// certificates from `certs`. HTTP/1.1 is the only application protocol offered (a
/// client that insists on h2 is refused rather than served something it cannot
/// speak), plus the validation protocol.
pub fn server_config(certs: Arc<Certs>) -> Result<Arc<ServerConfig>, String> {
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(certs);
    config.alpn_protocols = vec![b"http/1.1".to_vec(), ACME_ALPN.to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::{build_certificate, CertSpec};

    /// A self-signed certificate for `name` and its PEM key, valid around now.
    pub(crate) fn self_signed(name: &str) -> (String, String) {
        let key = EcKey::generate().unwrap();
        let now = crate::time::now();
        let der = build_certificate(
            &CertSpec {
                serial: &x509::random_serial(),
                issuer_cn: name,
                subject_cn: name,
                not_before: now - 60,
                not_after: now + 86_400,
                spki: &key.spki(),
                dns_names: &[name.to_string()],
                ca: false,
                acme_identifier: None,
            },
            &key,
        );
        (pem::encode("CERTIFICATE", &der), pem::encode("PRIVATE KEY", key.pkcs8()))
    }

    #[test]
    fn loads_a_matching_pair() {
        let (cert, key) = self_signed("relay.example.com");
        let c = load(&cert, &key).unwrap();
        assert_eq!(c.info.names, ["relay.example.com"]);
        assert_eq!(c.key.cert.len(), 1);
    }

    #[test]
    fn refuses_a_key_that_is_not_the_certificates() {
        let (cert, _) = self_signed("a.example.com");
        let (_, other_key) = self_signed("b.example.com");
        assert!(load(&cert, &other_key).unwrap_err().contains("does not belong"));
    }

    #[test]
    fn explains_unusable_files() {
        let (cert, key) = self_signed("a.example.com");
        assert!(load("", &key).unwrap_err().contains("no certificate"));
        assert!(load(&cert, "").unwrap_err().contains("no private key"));
        assert!(load(&cert, &pem::encode("PRIVATE KEY", b"junk")).unwrap_err().contains("cannot be used"));
        assert!(load(&pem::encode("CERTIFICATE", b"junk"), &key).unwrap_err().contains("cannot be read"));
    }

    #[test]
    fn challenge_maps_are_case_insensitive_and_clearable() {
        let c = Challenges::default();
        let key = EcKey::generate().unwrap();
        let cert = certified(x509::acme_challenge_certificate(&key, "a.example.com", [1; 32], crate::time::now()), &key);
        c.set_alpn("A.Example.COM", cert.clone());
        assert!(c.alpn("a.example.com").is_some() && c.alpn("b.example.com").is_none());
        c.clear_alpn("a.EXAMPLE.com");
        assert!(c.alpn("a.example.com").is_none());
        c.set_http("tok", "tok.thumb".into());
        assert_eq!(c.http("tok").as_deref(), Some("tok.thumb"));
        c.clear_http("tok");
        assert!(c.http("tok").is_none());
    }

    #[test]
    fn swapping_the_certificate_applies_to_the_next_reader() {
        let certs = Certs::default();
        assert!(certs.current().is_none());
        let (c1, k1) = self_signed("one.example.com");
        certs.set(load(&c1, &k1).unwrap());
        let held = certs.current().unwrap();
        let (c2, k2) = self_signed("two.example.com");
        certs.set(load(&c2, &k2).unwrap());
        assert_eq!(held.info.names, ["one.example.com"], "a holder keeps what it had");
        assert_eq!(certs.current().unwrap().info.names, ["two.example.com"]);
    }

    #[test]
    fn server_config_offers_http_and_the_validation_protocol() {
        let cfg = server_config(Arc::new(Certs::default())).unwrap();
        assert_eq!(cfg.alpn_protocols, [b"http/1.1".to_vec(), b"acme-tls/1".to_vec()]);
    }
}
