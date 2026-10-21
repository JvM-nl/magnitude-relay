//! Connections and small OS facts: URL parsing, connecting (optionally from a chosen
//! loopback source address), receive-with-deadline, the file-descriptor limit and a
//! process's resident memory.

use relay_net::conn::{client_handshake, ClientConn, Message};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream, UnixStream};

/// A connection to the relay: TCP, or the Unix socket a web server in front of
/// it would use (`unix:/path` URLs).
pub enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

pub type Conn = ClientConn<Stream>;

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Unix(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Stream::Unix(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_flush(cx),
            Stream::Unix(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Unix(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// A relay endpoint: where to connect and what to put in the handshake.
#[derive(Clone, Debug)]
pub struct Target {
    /// Unused when `unix` is set.
    pub addr: SocketAddr,
    /// A Unix socket to connect to instead.
    pub unix: Option<PathBuf>,
    /// `Host` header value.
    pub host: String,
    pub path: String,
    pub url: String,
}

/// `ws://host[:port][/path]`, or `unix:/path/to/socket`. TLS is out of scope:
/// every relay under test is local, and a TLS handshake per connection would
/// measure the TLS library.
pub async fn resolve(url: &str) -> Result<Target, String> {
    if let Some(path) = url.strip_prefix("unix:") {
        if path.is_empty() {
            return Err(format!("no socket path in '{url}'"));
        }
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        return Ok(Target { addr, unix: Some(path.into()), host: "localhost".into(), path: "/".into(), url: url.to_owned() });
    }
    let rest = match url.strip_prefix("ws://") {
        Some(r) => r,
        None if url.starts_with("wss://") => return Err("wss:// is not supported: point the bench at the relay's plain ws:// port".into()),
        None => return Err(format!("expected a ws:// URL, got '{url}'")),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (name, port) = match authority.rsplit_once(':') {
        Some((n, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (n, p.parse::<u16>().map_err(|_| format!("bad port in '{url}'"))?),
        _ => (authority, 80),
    };
    if name.is_empty() {
        return Err(format!("no host in '{url}'"));
    }
    let name = name.trim_start_matches('[').trim_end_matches(']');
    let addr = tokio::net::lookup_host((name, port))
        .await
        .map_err(|e| format!("cannot resolve '{name}': {e}"))?
        .next()
        .ok_or_else(|| format!("'{name}' resolved to nothing"))?;
    Ok(Target { addr, unix: None, host: authority.to_owned(), path: path.to_owned(), url: url.to_owned() })
}

/// The loopback source address for connection number `i` when spreading over `k`
/// addresses, or `None` for the kernel's choice. One source IP offers ~28k ephemeral
/// ports to one destination; 100k idle connections need several (Linux treats all of
/// 127.0.0.0/8 as local, so no setup is required there).
pub fn source_ip(i: usize, k: usize) -> Option<IpAddr> {
    if k <= 1 {
        return None;
    }
    let j = (i % k.min(60_000)) as u32;
    Some(IpAddr::V4(Ipv4Addr::new(127, 0, (j / 250) as u8, 2 + (j % 250) as u8)))
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn connect(t: &Target, src: Option<IpAddr>) -> io::Result<Conn> {
    let attempt = async {
        if let Some(path) = &t.unix {
            return client_handshake(Stream::Unix(UnixStream::connect(path).await?), &t.host, &t.path).await;
        }
        let sock = if t.addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        if let (Some(ip), true) = (src, t.addr.is_ipv4() && t.addr.ip().is_loopback()) {
            sock.bind(SocketAddr::new(ip, 0))?;
        }
        let stream = sock.connect(t.addr).await?;
        // Small request/response frames: Nagle plus delayed ACK would add 40 ms each.
        stream.set_nodelay(true)?;
        client_handshake(Stream::Tcp(stream), &t.host, &t.path).await
    };
    match tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timed out")),
    }
}

#[derive(Debug)]
pub enum RecvError {
    Timeout,
    /// The relay closed the connection (close frame or EOF).
    Closed(String),
    Io(io::Error),
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvError::Timeout => f.write_str("timed out waiting for the relay"),
            RecvError::Closed(why) => write!(f, "connection closed by the relay ({why})"),
            RecvError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// The next text message, waiting at most `wait` in total. Binary frames and pongs
/// are skipped (pings are answered inside `recv`).
pub async fn recv_text(c: &mut Conn, wait: Duration) -> Result<String, RecvError> {
    let deadline = Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(left, c.recv()).await {
            Err(_) => return Err(RecvError::Timeout),
            Ok(Err(e)) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::NotConnected | io::ErrorKind::ConnectionReset) => {
                return Err(RecvError::Closed(e.to_string()))
            }
            Ok(Err(e)) => return Err(RecvError::Io(e)),
            Ok(Ok(Message::Text(t))) => return Ok(t),
            Ok(Ok(Message::Close(c))) => return Err(RecvError::Closed(c.map_or_else(|| "no status".into(), |(code, why)| format!("{code} {why}")))),
            Ok(Ok(_)) => continue,
        }
    }
}

/// Polls `fut` exactly once: its output if it was already ready, otherwise `None`
/// (the future is dropped, so it must be cancel-safe, as a socket read is). This is
/// how a pacing loop checks for input without waiting: a zero `timeout` is *not* that,
/// because the timer wheel rounds a deadline up to the next millisecond.
pub async fn now_or_never<F: std::future::Future>(fut: F) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| match fut.as_mut().poll(cx) {
        std::task::Poll::Ready(v) => std::task::Poll::Ready(Some(v)),
        std::task::Poll::Pending => std::task::Poll::Ready(None),
    })
    .await
}

#[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
mod rlimit {
    #[repr(C)]
    struct RLimit {
        cur: u64,
        max: u64,
    }
    extern "C" {
        fn getrlimit(resource: i32, rlim: *mut RLimit) -> i32;
        fn setrlimit(resource: i32, rlim: *const RLimit) -> i32;
    }
    #[cfg(target_os = "linux")]
    const RLIMIT_NOFILE: i32 = 7;
    #[cfg(target_os = "macos")]
    const RLIMIT_NOFILE: i32 = 8;

    pub fn raise(want: u64) -> Option<u64> {
        let mut lim = RLimit { cur: 0, max: 0 };
        // SAFETY: `lim` is a valid, writable struct with the C layout of `struct rlimit`
        // on 64-bit Linux and macOS (two 64-bit words).
        if unsafe { getrlimit(RLIMIT_NOFILE, &mut lim) } != 0 {
            return None;
        }
        let mut try_cur = want.min(lim.max);
        // macOS reports an unlimited hard limit but refuses a soft limit above its
        // per-process maximum: back off until the kernel accepts.
        while try_cur > lim.cur {
            let new = RLimit { cur: try_cur, max: lim.max };
            // SAFETY: `new` is a valid struct of the same layout.
            if unsafe { setrlimit(RLIMIT_NOFILE, &new) } == 0 {
                return Some(try_cur);
            }
            try_cur = lim.cur + (try_cur - lim.cur) / 2;
        }
        Some(lim.cur)
    }
}

/// Raises this process's soft `RLIMIT_NOFILE` towards `want` (best effort) and
/// returns the limit now in force. Beyond the *hard* limit only root, or `ulimit -n`
/// in the shell before launching, can go: the idle and fanout commands warn when
/// the limit is below what they need.
pub fn raise_nofile(want: u64) -> Option<u64> {
    #[cfg(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64"))]
    {
        rlimit::raise(want)
    }
    #[cfg(not(all(any(target_os = "linux", target_os = "macos"), target_pointer_width = "64")))]
    {
        let _ = want;
        None
    }
}

/// Resident set size of process `pid` in KiB, from `/proc/<pid>/status` (Linux).
pub fn rss_kb(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_vmrss(&status)
}

pub fn parse_vmrss(status: &str) -> Option<u64> {
    status.lines().find_map(|l| l.strip_prefix("VmRSS:")).and_then(|v| v.split_whitespace().next()).and_then(|n| n.parse().ok())
}

pub fn unix_time() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn url_forms() {
        let t = resolve("ws://127.0.0.1:7777").await.unwrap();
        assert_eq!((t.addr, t.host.as_str(), t.path.as_str()), ("127.0.0.1:7777".parse().unwrap(), "127.0.0.1:7777", "/"));
        let t = resolve("ws://127.0.0.1:9/nostr?x=1").await.unwrap();
        assert_eq!((t.addr.port(), t.path.as_str()), (9, "/nostr?x=1"));
        let t = resolve("ws://localhost/").await.unwrap();
        assert_eq!(t.addr.port(), 80);
        assert!(resolve("wss://127.0.0.1").await.unwrap_err().contains("not supported"));
        assert!(resolve("http://127.0.0.1").await.is_err());
        assert!(resolve("ws://:80").await.is_err());
        assert!(resolve("ws://127.0.0.1:99999").await.is_err());
    }

    #[test]
    fn source_addresses_cycle_and_stay_loopback() {
        assert_eq!(source_ip(5, 1), None);
        assert_eq!(source_ip(0, 0), None);
        assert_eq!(source_ip(0, 4), Some("127.0.0.2".parse().unwrap()));
        assert_eq!(source_ip(5, 4), Some("127.0.0.3".parse().unwrap()));
        assert_eq!(source_ip(250, 1000), Some("127.0.1.2".parse().unwrap()));
        for i in 0..2000 {
            assert!(source_ip(i, 300).unwrap().is_loopback());
        }
    }

    #[tokio::test]
    async fn now_or_never_does_not_wait() {
        let t = Instant::now();
        assert_eq!(now_or_never(async { 7 }).await, Some(7));
        assert_eq!(now_or_never(std::future::pending::<u8>()).await, None);
        assert_eq!(now_or_never(tokio::time::sleep(Duration::from_secs(5))).await, None);
        assert!(t.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn vmrss_parsing() {
        let status = "Name:\trelay\nVmPeak:\t  900000 kB\nVmRSS:\t   12345 kB\nThreads:\t8\n";
        assert_eq!(parse_vmrss(status), Some(12345));
        assert_eq!(parse_vmrss("Name: x\n"), None);
    }

    #[test]
    fn nofile_limit_is_reported() {
        if let Some(n) = raise_nofile(4096) {
            assert!(n >= 256, "{n}");
        }
    }
}
