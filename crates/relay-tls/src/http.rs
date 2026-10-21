//! A small HTTP/1.1 client for talking to the CA: one request per connection, over
//! rustls (trusting the web's roots) or, for a CA on this machine, plain TCP.
//!
//! Request writing and response parsing are relay-net's; what lives here is the
//! framing of a response body (`Content-Length`, chunked, or until close) and the
//! connection. It reads at most [`MAX_BODY`] bytes, follows no redirects and keeps no
//! connection alive: ACME makes a handful of requests every few weeks.

use relay_net::http::{parse_response, Response as Head};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The largest response body read: a certificate chain is a few KiB.
pub const MAX_BODY: usize = 1 << 20;
const MAX_HEAD: usize = 16 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

fn invalid(msg: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A parsed `http://` or `https://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// Path and query, always starting with `/`.
    pub target: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url, String> {
        let (tls, rest) = match (s.strip_prefix("https://"), s.strip_prefix("http://")) {
            (Some(r), _) => (true, r),
            (None, Some(r)) => (false, r),
            _ => return Err(format!("\"{s}\" is not an http:// or https:// URL")),
        };
        // Nothing that could split a request line or header.
        if s.bytes().any(|b| b <= b' ' || b == 0x7F || b >= 0x80) {
            return Err(format!("\"{s}\" contains a space or control character"));
        }
        let (authority, target) = match rest.find(['/', '?']) {
            Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_string()),
            Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
            None => (rest, "/".to_string()),
        };
        let target = target.split('#').next().unwrap_or("/").to_string();
        if authority.contains('@') {
            return Err(format!("\"{s}\" has a user name in it, which is not supported"));
        }
        let default = if tls { 443 } else { 80 };
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or_else(|| format!("\"{s}\": unclosed [ in the address"))?;
            match after {
                "" => (h, default),
                p => (h, p.strip_prefix(':').and_then(|p| p.parse().ok()).ok_or_else(|| format!("\"{s}\": bad port"))?),
            }
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h, p.parse().map_err(|_| format!("\"{s}\": bad port"))?),
                None => (authority, default),
            }
        };
        if host.is_empty() {
            return Err(format!("\"{s}\" has no host name"));
        }
        Ok(Url { tls, host: host.to_string(), port, target })
    }

    /// The `Host` header value: the port only when it is not the scheme's default.
    fn host_header(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == if self.tls { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// Names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

pub struct Client {
    connector: TlsConnector,
    user_agent: String,
}

impl Client {
    /// A client trusting the web's public roots plus `extra_roots` (a private CA).
    pub fn new(user_agent: &str, extra_roots: &[CertificateDer<'static>]) -> Result<Client, String> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for r in extra_roots {
            roots.add(r.clone()).map_err(|e| format!("unusable CA certificate: {e}"))?;
        }
        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Client { connector: TlsConnector::from(Arc::new(config)), user_agent: user_agent.to_string() })
    }

    /// One request. `headers` are extra request headers; a `body` is sent with its length.
    pub async fn request(&self, method: &str, url: &str, headers: &[(&str, &str)], body: &[u8]) -> io::Result<Response> {
        let url = Url::parse(url).map_err(invalid)?;
        let mut req = Vec::with_capacity(256 + body.len());
        req.extend_from_slice(
            format!(
                "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nConnection: close\r\n",
                url.target,
                url.host_header(),
                self.user_agent
            )
            .as_bytes(),
        );
        for (n, v) in headers {
            if n.bytes().chain(v.bytes()).any(|b| b == b'\r' || b == b'\n') {
                return Err(invalid("header injection"));
            }
            req.extend_from_slice(format!("{n}: {v}\r\n").as_bytes());
        }
        if !body.is_empty() || method == "POST" {
            req.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
        }
        req.extend_from_slice(b"\r\n");
        req.extend_from_slice(body);

        let work = async {
            let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((url.host.as_str(), url.port)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("connecting to {}:{} timed out", url.host, url.port)))??;
            tcp.set_nodelay(true)?;
            if url.tls {
                let name =
                    ServerName::try_from(url.host.clone()).map_err(|_| invalid(format!("\"{}\" is not a valid server name", url.host)))?;
                let tls = self.connector.connect(name, tcp).await?;
                exchange(tls, &req, method == "HEAD").await
            } else {
                exchange(tcp, &req, method == "HEAD").await
            }
        };
        tokio::time::timeout(REQUEST_TIMEOUT, work)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{} {} timed out", method, url.host)))?
    }
}

/// Sends `req` and reads the whole response.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, req: &[u8], head_only: bool) -> io::Result<Response> {
    s.write_all(req).await?;
    s.flush().await?;
    let mut buf = Vec::with_capacity(4096);
    let (status, headers, head_len) = loop {
        match parse_response(&buf, MAX_HEAD) {
            Ok(Some((r, n))) => break (r.status, owned_headers(&r), n),
            Ok(None) => {
                if read_more(&mut s, &mut buf).await? == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the server closed the connection before answering"));
                }
            }
            Err(e) => return Err(invalid(e)),
        }
    };
    let get = |name: &str| headers.iter().find(|(n, _)| n == name).map(|(_, v): &(String, String)| v.as_str());
    let body = if head_only || status == 204 || status == 304 || (100..200).contains(&status) {
        Vec::new()
    } else if get("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked")) {
        loop {
            match decode_chunked(&buf[head_len..], MAX_BODY).map_err(invalid)? {
                Some((body, _)) => break body,
                None => {
                    if read_more(&mut s, &mut buf).await? == 0 {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the response body was cut short"));
                    }
                }
            }
        }
    } else if let Some(len) = get("content-length") {
        let len: usize = len.trim().parse().map_err(|_| invalid("bad Content-Length"))?;
        if len > MAX_BODY {
            return Err(invalid("the response body is too large"));
        }
        while buf.len() - head_len < len {
            if read_more(&mut s, &mut buf).await? == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the response body was cut short"));
            }
        }
        buf[head_len..head_len + len].to_vec()
    } else {
        // Framed by the close, which `Connection: close` asked for.
        while read_more(&mut s, &mut buf).await? != 0 {
            if buf.len() - head_len > MAX_BODY {
                return Err(invalid("the response body is too large"));
            }
        }
        buf[head_len..].to_vec()
    };
    Ok(Response { status, headers, body })
}

fn owned_headers(r: &Head<'_>) -> Vec<(String, String)> {
    r.headers
        .iter()
        .map(|h| (String::from_utf8_lossy(h.name).to_ascii_lowercase(), String::from_utf8_lossy(h.value).into_owned()))
        .collect()
}

async fn read_more<S: AsyncRead + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> io::Result<usize> {
    if buf.capacity() - buf.len() < 2048 {
        buf.reserve(8192);
    }
    s.read_buf(buf).await
}

/// Decodes a chunked body (RFC 9112 §7.1) from `data`: the body and the bytes used,
/// or `None` while the terminating chunk and trailers have not all arrived.
pub fn decode_chunked(data: &[u8], max: usize) -> Result<Option<(Vec<u8>, usize)>, String> {
    let mut out = Vec::new();
    let mut pos = 0;
    loop {
        let Some(nl) = data[pos..].iter().position(|&b| b == b'\n') else { return Ok(None) };
        let line = data[pos..pos + nl].strip_suffix(b"\r").unwrap_or(&data[pos..pos + nl]);
        // Chunk extensions follow a semicolon and are ignored.
        let size_text = line.split(|&b| b == b';').next().unwrap_or(&[]).trim_ascii();
        let size = std::str::from_utf8(size_text)
            .ok()
            .filter(|s| !s.is_empty() && s.len() <= 8 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|s| usize::from_str_radix(s, 16).ok())
            .ok_or("bad chunk size")?;
        pos += nl + 1;
        if size == 0 {
            // Trailer lines, then a blank line.
            loop {
                let Some(nl) = data[pos..].iter().position(|&b| b == b'\n') else { return Ok(None) };
                let blank = data[pos..pos + nl].strip_suffix(b"\r").unwrap_or(&data[pos..pos + nl]).is_empty();
                pos += nl + 1;
                if blank {
                    return Ok(Some((out, pos)));
                }
            }
        }
        if out.len() + size > max {
            return Err("the response body is too large".to_string());
        }
        if data.len() < pos + size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size;
        match &data[pos..pos + 2] {
            b"\r\n" => pos += 2,
            _ if data[pos] == b'\n' => pos += 1,
            _ => return Err("chunk is not followed by a line break".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn urls() {
        let u = Url::parse("https://acme-v02.api.letsencrypt.org/directory").unwrap();
        assert_eq!((u.tls, u.host.as_str(), u.port, u.target.as_str()), (true, "acme-v02.api.letsencrypt.org", 443, "/directory"));
        assert_eq!(u.host_header(), "acme-v02.api.letsencrypt.org");
        let u = Url::parse("http://127.0.0.1:14000/dir?x=1#frag").unwrap();
        assert_eq!((u.tls, u.host.as_str(), u.port, u.target.as_str()), (false, "127.0.0.1", 14000, "/dir?x=1"));
        assert_eq!(u.host_header(), "127.0.0.1:14000");
        let u = Url::parse("https://[::1]:8443").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.target.as_str(), u.host_header().as_str()), ("::1", 8443, "/", "[::1]:8443"));
        assert_eq!(Url::parse("https://example.com?q=1").unwrap().target, "/?q=1");
        assert_eq!(Url::parse("https://[::1]/x").unwrap().port, 443);
    }

    #[test]
    fn bad_urls() {
        for bad in [
            "ftp://x",
            "example.com",
            "https://",
            "https://:443/",
            "https://a:b/",
            "https://a:99999/",
            "https://u@h/",
            "https://h/a b",
            "https://h/\r\nX: y",
            "https://[::1/",
            "https://h\u{e9}/",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn chunked_bodies() {
        let ok = |data: &[u8]| decode_chunked(data, 100).unwrap();
        assert_eq!(ok(b"5\r\nhello\r\n0\r\n\r\n"), Some((b"hello".to_vec(), 15)));
        assert_eq!(ok(b"3\r\nabc\r\n2;ext=1\r\nde\r\n0\r\nTrailer: x\r\n\r\nleftover"), Some((b"abcde".to_vec(), 38)));
        assert_eq!(ok(b"A\r\n0123456789\r\n0\r\n\r\n").unwrap().0, b"0123456789");
        assert_eq!(ok(b"0\r\n\r\n"), Some((Vec::new(), 5)));
        // Incomplete at every prefix is "need more", never an error or a wrong answer.
        let whole = b"5\r\nhello\r\n3\r\nabc\r\n0\r\n\r\n";
        for n in 0..whole.len() {
            assert_eq!(ok(&whole[..n]), None, "prefix {n}");
        }
        assert_eq!(ok(whole).unwrap().0, b"helloabc");
    }

    #[test]
    fn bad_chunked_bodies() {
        for bad in [&b"zz\r\n"[..], b"\r\n", b"5\r\nhelloXX", b"99999999999\r\n", b"-1\r\n"] {
            assert!(decode_chunked(bad, 100).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        assert!(decode_chunked(b"65\r\n", 100).is_err(), "101 bytes over a limit of 100");
    }

    async fn serve_once(raw: &'static [u8]) -> io::Result<Response> {
        let (a, mut b) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let _ = b.read(&mut buf).await;
            b.write_all(raw).await.unwrap();
            b.shutdown().await.unwrap();
        });
        let r = exchange(a, b"GET / HTTP/1.1\r\n\r\n", false).await;
        server.await.unwrap();
        r
    }

    #[tokio::test]
    async fn reads_each_kind_of_framing() {
        let r = serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nReplay-Nonce: abc\r\n\r\nhelloEXTRA").await.unwrap();
        assert_eq!((r.status, r.body.as_slice(), r.header("replay-nonce")), (200, &b"hello"[..], Some("abc")));
        let r = serve_once(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n").await.unwrap();
        assert_eq!((r.status, r.body.as_slice()), (201, &b"abc"[..]));
        let r = serve_once(b"HTTP/1.1 200 OK\r\n\r\nuntil the close").await.unwrap();
        assert_eq!(r.body, b"until the close");
        let r = serve_once(b"HTTP/1.1 204 No Content\r\nReplay-Nonce: n\r\n\r\n").await.unwrap();
        assert!(r.body.is_empty() && r.header("replay-nonce") == Some("n"));
    }

    #[tokio::test]
    async fn short_or_broken_responses_are_errors() {
        assert!(serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort").await.is_err());
        assert!(serve_once(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel").await.is_err());
        assert!(serve_once(b"").await.is_err());
        assert!(serve_once(b"garbage\r\n\r\n").await.is_err());
        assert!(serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 99999999\r\n\r\n").await.is_err());
    }

    #[tokio::test]
    async fn plain_http_against_a_local_listener() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.unwrap();
            req
        });
        let c = Client::new("test-agent/1", &[]).unwrap();
        let r = c
            .request("POST", &format!("http://127.0.0.1:{port}/new?x=1"), &[("Content-Type", "application/jose+json")], b"{\"a\":1}")
            .await
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        let req = server.await.unwrap();
        assert!(req.starts_with("POST /new?x=1 HTTP/1.1\r\n"), "{req}");
        assert!(req.contains(&format!("Host: 127.0.0.1:{port}\r\n")) && req.contains("User-Agent: test-agent/1\r\n"));
        assert!(
            req.contains("Connection: close\r\n")
                && req.contains("Content-Type: application/jose+json\r\n")
                && req.contains("Content-Length: 7\r\n")
        );
        assert!(req.ends_with("\r\n\r\n{\"a\":1}"));
    }

    #[tokio::test]
    async fn refuses_header_injection() {
        let c = Client::new("t", &[]).unwrap();
        assert!(c.request("GET", "http://127.0.0.1:1/", &[("X", "a\r\nInjected: 1")], b"").await.is_err());
        assert!(c.request("GET", "http://127.0.0.1:1/x\r\nInjected: 1", &[], b"").await.is_err());
    }

    #[tokio::test]
    async fn connection_errors_are_reported() {
        // A port nothing listens on.
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let c = Client::new("t", &[]).unwrap();
        let e = c.request("GET", &format!("http://127.0.0.1:{port}/"), &[], b"").await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
    }
}
