//! The plain-HTTP port: answers HTTP-01 challenges while one is in flight and sends
//! every other request to the same address over HTTPS.

use crate::certs::Certs;
use relay_net::http::{parse_request_with, write_response};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

const MAX_HEAD: usize = 8 * 1024;
/// A client has this long to send its request.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Simultaneous connections; further ones are dropped until a slot frees.
const MAX_CONNECTIONS: usize = 256;
const CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

/// Where requests are sent.
#[derive(Debug, Clone, Default)]
pub struct Redirect {
    /// The names this relay answers to, the first being the default for a request
    /// that names none of them. With none configured the request's own host is used.
    pub hosts: Vec<String>,
    /// The HTTPS port; the redirect names it when it is not 443.
    pub https_port: u16,
}

/// Serves `listener` until the process ends.
pub async fn serve(listener: TcpListener, certs: Arc<Certs>, redirect: Arc<Redirect>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                eprintln!("tls: accept on the plain-HTTP port failed: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
        let (certs, redirect) = (certs.clone(), redirect.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let _ = tokio::time::timeout(HEAD_TIMEOUT, handle(stream, &certs, &redirect)).await;
        });
    }
}

async fn handle(mut s: TcpStream, certs: &Certs, redirect: &Redirect) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let reply = loop {
        match parse_request_with(&buf, MAX_HEAD) {
            Ok(Some((req, _))) => break respond(req.method, req.path, req.header("host"), certs, redirect),
            Ok(None) => {
                if s.read_buf(&mut buf).await? == 0 {
                    return Ok(());
                }
            }
            Err(e) => {
                let mut out = Vec::new();
                write_response(
                    &mut out,
                    e.status(),
                    relay_net::http::reason_phrase(e.status()),
                    "text/plain",
                    &[],
                    e.message().as_bytes(),
                    true,
                );
                break out;
            }
        }
    };
    s.write_all(&reply).await?;
    s.shutdown().await?;
    // Closing with the client's bytes unread would reset the connection and could
    // eat the reply; read until it hangs up (the caller's timeout bounds this).
    let mut sink = [0u8; 4096];
    while s.read(&mut sink).await.is_ok_and(|n| n > 0) {}
    Ok(())
}

/// The host part of a `Host` header, if it is a name or address we would put in a
/// URL: lowercase, no port, and nothing that could carry a second URL.
fn host_of(header: &[u8]) -> Option<String> {
    let h = std::str::from_utf8(header).ok()?.trim().to_ascii_lowercase();
    let host = if h.starts_with('[') {
        let end = h.find(']')?;
        let v6 = &h[1..end];
        if v6.is_empty() || !v6.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.') {
            return None;
        }
        &h[..=end]
    } else {
        let name = h.split(':').next()?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
            return None;
        }
        name
    };
    Some(host.to_string())
}

/// The whole response to one request.
pub fn respond(method: &str, target: &str, host: Option<&[u8]>, certs: &Certs, redirect: &Redirect) -> Vec<u8> {
    let mut out = Vec::new();
    if method == "GET" {
        if let Some(rest) = target.strip_prefix(CHALLENGE_PREFIX) {
            let token = rest.split('?').next().unwrap_or("");
            let answer = (!token.is_empty() && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
                .then(|| certs.challenges.http(token))
                .flatten();
            match answer {
                Some(key_authorization) => write_response(&mut out, 200, "OK", "text/plain", &[], key_authorization.as_bytes(), true),
                None => write_response(&mut out, 404, "Not Found", "text/plain", &[], b"no such challenge\n", true),
            }
            return out;
        }
    }
    let wanted = host.and_then(host_of);
    let host = match (&wanted, redirect.hosts.first()) {
        (Some(h), _) if redirect.hosts.iter().any(|k| k == h) => Some(h.clone()),
        (_, Some(first)) => Some(first.clone()),
        (Some(h), None) => Some(h.clone()),
        (None, None) => None,
    };
    let (Some(host), true) = (host, target.starts_with('/')) else {
        write_response(&mut out, 400, "Bad Request", "text/plain", &[], b"bad request\n", true);
        return out;
    };
    let port = if redirect.https_port == 443 || redirect.https_port == 0 { String::new() } else { format!(":{}", redirect.https_port) };
    let location = format!("https://{host}{port}{target}");
    write_response(
        &mut out,
        301,
        "Moved Permanently",
        "text/plain",
        &[("Location", &location)],
        format!("Moved to {location}\n").as_bytes(),
        true,
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect(hosts: &[&str], port: u16) -> Redirect {
        Redirect { hosts: hosts.iter().map(|h| h.to_string()).collect(), https_port: port }
    }

    fn text(v: &[u8]) -> String {
        String::from_utf8_lossy(v).into_owned()
    }

    #[test]
    fn serves_a_challenge_and_only_while_it_is_set() {
        let certs = Certs::default();
        let r = redirect(&["relay.example.com"], 443);
        certs.challenges.set_http("tok-1_x", "tok-1_x.thumbprint".into());
        let out = text(&respond("GET", "/.well-known/acme-challenge/tok-1_x", Some(b"relay.example.com"), &certs, &r));
        assert!(out.starts_with("HTTP/1.1 200 OK\r\n") && out.ends_with("\r\n\r\ntok-1_x.thumbprint"), "{out}");
        certs.challenges.clear_http("tok-1_x");
        let out = text(&respond("GET", "/.well-known/acme-challenge/tok-1_x", Some(b"relay.example.com"), &certs, &r));
        assert!(out.starts_with("HTTP/1.1 404 "), "{out}");
    }

    #[test]
    fn odd_tokens_are_not_looked_up() {
        let certs = Certs::default();
        let r = redirect(&["a.example"], 443);
        for target in [
            "/.well-known/acme-challenge/",
            "/.well-known/acme-challenge/../x",
            "/.well-known/acme-challenge/a%20b",
            "/.well-known/acme-challenge/a/b",
        ] {
            let out = text(&respond("GET", target, None, &certs, &r));
            assert!(out.starts_with("HTTP/1.1 404 "), "{target}: {out}");
        }
    }

    #[test]
    fn everything_else_goes_to_https_with_the_same_path() {
        let certs = Certs::default();
        let r = redirect(&["relay.example.com", "www.example.com"], 443);
        let out = text(&respond("GET", "/some/path?x=1&y=2", Some(b"relay.example.com"), &certs, &r));
        assert!(out.starts_with("HTTP/1.1 301 Moved Permanently\r\n"), "{out}");
        assert!(out.contains("\r\nLocation: https://relay.example.com/some/path?x=1&y=2\r\n"), "{out}");
        let out = text(&respond("GET", "/", Some(b"WWW.Example.com:80"), &certs, &r));
        assert!(out.contains("\r\nLocation: https://www.example.com/\r\n"), "host matched case-insensitively, port dropped: {out}");
        // Methods other than GET are sent along too.
        let out = text(&respond("POST", "/x", Some(b"relay.example.com"), &certs, &r));
        assert!(out.contains("Location: https://relay.example.com/x"), "{out}");
    }

    #[test]
    fn the_redirect_names_a_non_default_port() {
        let certs = Certs::default();
        let out = text(&respond("GET", "/x", Some(b"relay.example.com"), &certs, &redirect(&["relay.example.com"], 8443)));
        assert!(out.contains("Location: https://relay.example.com:8443/x"), "{out}");
    }

    #[test]
    fn a_stranger_host_header_cannot_steer_the_redirect() {
        let certs = Certs::default();
        let r = redirect(&["relay.example.com"], 443);
        for host in [&b"evil.example"[..], b"evil.example/x", b"a b", b"", b"\xff"] {
            let out = text(&respond("GET", "/x", Some(host), &certs, &r));
            assert!(out.contains("Location: https://relay.example.com/x"), "{host:?}: {out}");
        }
        let out = text(&respond("GET", "/x", None, &certs, &r));
        assert!(out.contains("Location: https://relay.example.com/x"));
    }

    #[test]
    fn with_no_configured_names_the_requests_own_host_is_used_if_sane() {
        let certs = Certs::default();
        let r = redirect(&[], 443);
        assert!(text(&respond("GET", "/x", Some(b"203.0.113.9:80"), &certs, &r)).contains("Location: https://203.0.113.9/x"));
        assert!(text(&respond("GET", "/x", Some(b"[2001:db8::1]:80"), &certs, &r)).contains("Location: https://[2001:db8::1]/x"));
        assert!(text(&respond("GET", "/x", Some(b"bad/host"), &certs, &r)).starts_with("HTTP/1.1 400 "));
        assert!(text(&respond("GET", "/x", None, &certs, &r)).starts_with("HTTP/1.1 400 "));
    }

    #[test]
    fn a_proxy_style_target_is_refused() {
        let certs = Certs::default();
        let out =
            text(&respond("GET", "http://evil.example/x", Some(b"relay.example.com"), &certs, &redirect(&["relay.example.com"], 443)));
        assert!(out.starts_with("HTTP/1.1 400 "), "{out}");
    }

    #[test]
    fn host_parsing() {
        assert_eq!(host_of(b"Example.COM").as_deref(), Some("example.com"));
        assert_eq!(host_of(b"example.com:8080").as_deref(), Some("example.com"));
        assert_eq!(host_of(b" 1.2.3.4 ").as_deref(), Some("1.2.3.4"));
        assert_eq!(host_of(b"[::1]:80").as_deref(), Some("[::1]"));
        for bad in [&b""[..], b":80", b"[]", b"[zz]", b"a_b", b"[::1", b"a@b"] {
            assert_eq!(host_of(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[tokio::test]
    async fn over_a_socket() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let certs = Arc::new(Certs::default());
        certs.challenges.set_http("abc", "abc.key".into());
        tokio::spawn(serve(l, certs, Arc::new(redirect(&["relay.example.com"], 443))));
        let get = |path: &'static str| async move {
            let mut s = TcpStream::connect(addr).await.unwrap();
            s.write_all(format!("GET {path} HTTP/1.1\r\nHost: relay.example.com\r\n\r\n").as_bytes()).await.unwrap();
            let mut out = Vec::new();
            s.read_to_end(&mut out).await.unwrap();
            text(&out)
        };
        assert!(get("/.well-known/acme-challenge/abc").await.ends_with("abc.key"));
        assert!(get("/anything").await.contains("Location: https://relay.example.com/anything"));
        // A head that never ends gets an error status, not a hang.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(format!("GET / HTTP/1.1\r\nX: {}\r\n", "a".repeat(20_000)).as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert!(text(&out).starts_with("HTTP/1.1 431 "), "{}", text(&out));
        // Garbage gets a 400.
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(b"\x16\x03\x01 not http\r\n\r\n").await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        assert!(text(&out).starts_with("HTTP/1.1 400 "), "{}", text(&out));
    }
}
