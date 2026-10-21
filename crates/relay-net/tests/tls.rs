//! wss:// end to end: the connector against a TLS WebSocket server on this
//! machine. The certificates in `tests/tls/` are a test CA and a certificate
//! it issued for `localhost` and `127.0.0.1` (P-256, valid to 2126), made with
//! openssl for these tests and good for nothing else.

#![cfg(feature = "tls")]

use relay_net::conn::{server_handshake, Message};
use relay_net::connector::{Connector, RelayUrl};
use relay_net::ws::{write_text, Decoder, Event, Role};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const CA: &[u8] = include_bytes!("tls/ca.der");
const LEAF: &[u8] = include_bytes!("tls/leaf.der");
const KEY: &[u8] = include_bytes!("tls/leaf.key.der");

/// A TLS WebSocket server that echoes text messages, for `conns` connections.
async fn echo_server(conns: usize) -> u16 {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(LEAF.to_vec())], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KEY.to_vec())))
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        for _ in 0..conns {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // A client that gave up on our certificate ends here.
                let Ok(mut s) = acceptor.accept(tcp).await else { return };
                let mut buf = Vec::new();
                server_handshake(&mut s, &mut buf, 8192).await.unwrap();
                let mut dec = Decoder::new(Role::Server, 1 << 24, 1 << 24);
                loop {
                    let mut out = Vec::new();
                    let mut off = 0;
                    while let Ok(d) = dec.decode(&mut buf[off..]) {
                        off += d.consumed;
                        match d.event {
                            Some(Event::Text(t)) => write_text(&mut out, t.as_bytes()),
                            Some(_) => {}
                            None => break,
                        }
                    }
                    buf.drain(..off);
                    if !out.is_empty() {
                        s.write_all(&out).await.unwrap();
                    }
                    let mut chunk = [0u8; 65536];
                    match s.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
            });
        }
    });
    port
}

fn test_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(CA.to_vec())).unwrap();
    roots
}

#[tokio::test]
async fn wss_round_trip_by_name_and_by_address() {
    let port = echo_server(2).await;
    let c = Connector::with_roots(test_roots()).unwrap();
    for host in ["localhost", "127.0.0.1"] {
        let url = RelayUrl::parse(&format!("wss://{host}:{port}/nostr")).unwrap();
        let mut conn = c.connect(&url, None).await.unwrap();
        // Big enough to span many TLS records.
        let big = "x".repeat(300_000);
        for msg in ["[\"REQ\",\"a\",{}]", big.as_str()] {
            conn.send_text(msg).await.unwrap();
            assert_eq!(conn.recv().await.unwrap(), Message::Text(msg.to_string()), "{host}");
        }
    }
}

#[tokio::test]
async fn an_untrusted_certificate_is_refused() {
    let port = echo_server(1).await;
    // The web's roots do not include our test CA.
    let c = Connector::new().unwrap();
    let url = RelayUrl::parse(&format!("wss://localhost:{port}")).unwrap();
    let err = c.connect(&url, None).await.err().expect("an untrusted certificate must not connect");
    assert!(err.to_string().to_lowercase().contains("certificate"), "{err}");
}
