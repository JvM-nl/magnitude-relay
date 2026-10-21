//! Opening a WebSocket to a relay by its URL: `ws://` over TCP, `wss://` over
//! TLS. This is how the relay reaches other relays (to sync from them); clients
//! never come in this way.
//!
//! TLS is rustls with the ring provider, trusting the web's roots
//! (webpki-roots), behind the `tls` feature. Without it a `wss://` URL is an
//! error that says so. The TLS session ends in a [`Stream`], which the same
//! [`ClientConn`] runs over as it does over plain TCP.

use crate::conn::{client_handshake_with, ClientConn, ClientDeflate};
use std::fmt;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// A `ws://` or `wss://` URL, taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl {
    pub tls: bool,
    /// A DNS name or an IP address (IPv6 without its brackets).
    pub host: String,
    pub port: u16,
    /// The request target: path and query, at least `/`.
    pub path: String,
}

impl RelayUrl {
    pub fn parse(url: &str) -> Result<RelayUrl, String> {
        let bad = |why: &str| format!("{url:?} is not a relay URL: {why}");
        let (tls, rest) = if let Some(r) = url.strip_prefix("wss://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("ws://") {
            (false, r)
        } else {
            return Err(bad("it must start with ws:// or wss://"));
        };
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) if rest.as_bytes()[i] == b'?' => (&rest[..i], format!("/{}", &rest[i..])),
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, String::from("/")),
        };
        if authority.contains('@') {
            return Err(bad("user names and passwords are not supported"));
        }
        let default = if tls { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or_else(|| bad("an IPv6 address needs its closing ]"))?;
            h.parse::<std::net::Ipv6Addr>().map_err(|_| bad("not an IPv6 address between the brackets"))?;
            let port = match after {
                "" => default,
                p => p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or_else(|| bad("bad port"))?,
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse().map_err(|_| bad("bad port"))?),
                None => (authority.to_string(), default),
            }
        };
        let token = |b: u8| b.is_ascii_alphanumeric() || b"-._:".contains(&b);
        if host.is_empty() || !host.bytes().all(token) {
            return Err(bad("bad host name"));
        }
        if path.bytes().any(|b| b <= b' ' || b == 0x7F) {
            return Err(bad("spaces and control characters are not allowed"));
        }
        Ok(RelayUrl { tls, host: host.to_ascii_lowercase(), port, path })
    }

    /// The `Host` header: the port only when it is not the scheme's own.
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == if self.tls { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// This machine: no need to spend CPU on compression over loopback.
    pub fn is_loopback(&self) -> bool {
        self.host == "localhost" || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
}

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}{}", if self.tls { "wss" } else { "ws" }, self.host_header(), self.path)
    }
}

/// A connection's byte stream: plain TCP, or TLS over it.
pub enum Stream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, data),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Opens WebSockets to relays. Holds the TLS settings, which are built once.
#[derive(Clone)]
pub struct Connector {
    #[cfg(feature = "tls")]
    tls: tokio_rustls::TlsConnector,
    /// For the TCP connect, the TLS handshake and the upgrade together.
    pub timeout: Duration,
}

impl Connector {
    /// Trusting the web's public roots.
    pub fn new() -> io::Result<Connector> {
        #[cfg(feature = "tls")]
        {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Connector::with_roots(roots)
        }
        #[cfg(not(feature = "tls"))]
        Ok(Connector { timeout: Duration::from_secs(15) })
    }

    /// Trusting exactly `roots` (a private CA, or a test's).
    #[cfg(feature = "tls")]
    pub fn with_roots(roots: rustls::RootCertStore) -> io::Result<Connector> {
        let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Connector { tls: tokio_rustls::TlsConnector::from(std::sync::Arc::new(config)), timeout: Duration::from_secs(15) })
    }

    /// Connects and upgrades. `deflate` offers permessage-deflate.
    pub async fn connect(&self, url: &RelayUrl, deflate: Option<ClientDeflate>) -> io::Result<ClientConn<Stream>> {
        let work = async {
            let tcp = TcpStream::connect((url.host.as_str(), url.port)).await?;
            // Small request/response frames: Nagle plus delayed ACK would add 40 ms each.
            tcp.set_nodelay(true)?;
            let stream = self.secure(url, tcp).await?;
            client_handshake_with(stream, &url.host_header(), &url.path, deflate).await
        };
        tokio::time::timeout(self.timeout, work)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{url} did not answer within {} s", self.timeout.as_secs())))?
    }

    #[cfg(feature = "tls")]
    async fn secure(&self, url: &RelayUrl, tcp: TcpStream) -> io::Result<Stream> {
        if !url.tls {
            return Ok(Stream::Plain(tcp));
        }
        let name = rustls::pki_types::ServerName::try_from(url.host.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?} is not a valid server name", url.host)))?;
        Ok(Stream::Tls(Box::new(self.tls.connect(name, tcp).await?)))
    }

    #[cfg(not(feature = "tls"))]
    async fn secure(&self, url: &RelayUrl, tcp: TcpStream) -> io::Result<Stream> {
        if url.tls {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "wss:// needs a build with TLS (relay-net's tls feature)"));
        }
        Ok(Stream::Plain(tcp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = |s: &str| RelayUrl::parse(s).unwrap();
        assert_eq!(u("ws://127.0.0.1:7777"), RelayUrl { tls: false, host: "127.0.0.1".into(), port: 7777, path: "/".into() });
        assert_eq!(u("wss://Relay.Example.com/nostr"), RelayUrl { tls: true, host: "relay.example.com".into(), port: 443, path: "/nostr".into() });
        assert_eq!(u("ws://[::1]:8080/x?y=1").host, "::1");
        assert_eq!(u("ws://[::1]:8080/x?y=1").path, "/x?y=1");
        assert_eq!(u("ws://h?q").path, "/?q");
        assert_eq!(u("wss://h:443").host_header(), "h");
        assert_eq!(u("wss://h:444").host_header(), "h:444");
        assert_eq!(u("ws://[::1]:80").host_header(), "[::1]");
        assert_eq!(u("ws://[::1]:81/a").to_string(), "ws://[::1]:81/a");
        assert!(u("ws://localhost:1").is_loopback() && u("ws://127.0.0.2").is_loopback() && u("ws://[::1]").is_loopback());
        assert!(!u("wss://relay.example.com").is_loopback());
        for bad in ["http://x", "ws://", "ws://h:port", "ws://h:99999", "ws://[::1", "ws://[zz]:1", "ws://u:p@h", "ws://h/a b", "ws://h h"] {
            assert!(RelayUrl::parse(bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn plain_connect_and_refusal() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            crate::conn::server_handshake(&mut s, &mut buf, 8192).await.unwrap();
            let mut out = Vec::new();
            crate::ws::write_text(&mut out, b"hello");
            tokio::io::AsyncWriteExt::write_all(&mut s, &out).await.unwrap();
            // Hold the socket until the client has read.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let c = Connector::new().unwrap();
        let mut conn = c.connect(&RelayUrl::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(), None).await.unwrap();
        assert_eq!(conn.recv().await.unwrap(), crate::conn::Message::Text("hello".into()));
        server.await.unwrap();
        // Nothing listening: an error, not a hang.
        let closed = RelayUrl::parse(&format!("ws://127.0.0.1:{port}/")).unwrap();
        assert!(c.connect(&closed, None).await.is_err());
    }
}
