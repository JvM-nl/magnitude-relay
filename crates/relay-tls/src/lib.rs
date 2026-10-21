//! HTTPS for the relay: certificates obtained from an ACME CA (Let's Encrypt) or
//! read from files, kept fresh in the background, and served through rustls.
//!
//! TLS itself, its cryptography and the CA trust store are rustls, ring and
//! webpki-roots. Everything around them is ours: the ACME client ([`acme`], RFC 8555
//! with the TLS-ALPN-01 and HTTP-01 challenges), JWS signing ([`jws`]), the DER
//! ([`der`], [`x509`]) and PEM ([`pem`]) it needs, JSON for ACME's few documents
//! ([`json`]), a small HTTP client for the CA ([`http`]), the plain-HTTP port for
//! challenges and the redirect ([`port80`]), and the connection type the relay's
//! reactors drive ([`conn`]).
//!
//! [`manager::Tls::start`] is the front door: it loads what is saved, starts a
//! background thread that obtains and renews, and returns the rustls
//! `ServerConfig` to accept connections with. A renewed certificate applies to the
//! next handshake; nothing restarts.

pub mod acme;
pub mod b64url;
pub mod certs;
pub mod conn;
pub mod der;
pub mod http;
pub mod json;
pub mod jws;
pub mod manager;
pub mod pem;
pub mod port80;
pub mod store;
pub mod time;
pub mod x509;

#[cfg(any(test, feature = "testing"))]
pub mod mock;

#[cfg(test)]
mod flow_tests;

pub use conn::TlsConn;
pub use manager::{Options, Source, Timing, Tls};
pub use rustls::ServerConfig;

/// The application protocol a CA asks for when it validates TLS-ALPN-01 (RFC 8737).
pub const ACME_ALPN: &[u8] = b"acme-tls/1";
