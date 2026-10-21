//! Thin tokio layer over the sans-IO core, for tests and the benchmark client.
//!
//! The relay's reactors do not use this module: they own their read buffers and
//! drive [`http`](crate::http) and [`ws`](crate::ws) directly. What lives here is
//! the same logic wrapped in `async fn`s that are simple and correct rather than
//! tuned.
//!
//! * [`server_handshake`] reads a request head, answers a valid WebSocket upgrade
//!   with `101` (or an error status), and otherwise hands the plain request back.
//! * [`client_connect`] / [`client_handshake`] open a WebSocket and return a
//!   [`ClientConn`] that sends masked frames and yields owned [`Message`]s. The `_with`
//!   forms can offer permessage-deflate ([`ClientDeflate`]); the server side is
//!   [`server_handshake_with`] and an [`ExtensionPolicy`].
//!
//! No timeouts are applied here; wrap calls in `tokio::time::timeout` where a
//! stalled peer must not hold a task.

use crate::http::{
    accept_key, parse_request_with, parse_response, reason_phrase, write_response, write_upgrade_response,
    ExtensionPolicy, Extensions, Request, DEFAULT_MAX_HEAD,
};
use crate::ws::{close_code, ClientEncoder, Compressor, Decoder, DeflateParams, Event, Opcode, Role, WsError};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

/// Largest frame or message the client side will reassemble.
const CLIENT_MAX_MESSAGE: usize = 64 * 1024 * 1024;

fn invalid_data(msg: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Reads more bytes into `buf`, first making room for at least `want` of them
/// (`read_buf` otherwise reads only into whatever spare capacity exists). EOF is an
/// error: every caller is mid-message.
async fn fill<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut Vec<u8>, want: usize) -> io::Result<()> {
    if buf.capacity() - buf.len() < want {
        buf.reserve(want);
    }
    if stream.read_buf(buf).await? == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

/// An owned copy of the parts of a request a server acts on after the read buffer
/// has moved on: the plain-HTTP path (NIP-11 and other GETs) and the client
/// address headers for an upgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedRequest {
    pub method: String,
    /// The request target as sent (path and query).
    pub path: String,
    /// Every header, names lowercased, values as sent minus surrounding space.
    pub headers: Vec<(String, Vec<u8>)>,
}

impl OwnedRequest {
    pub fn from_request(req: &Request<'_>) -> Self {
        OwnedRequest {
            method: req.method.to_owned(),
            path: req.path.to_owned(),
            headers: req
                .headers
                .iter()
                .map(|h| (String::from_utf8_lossy(h.name).to_ascii_lowercase(), h.value.to_vec()))
                .collect(),
        }
    }

    /// Value of the first header called `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_slice())
    }

    /// Whether the `Accept` header lists `media_type` (see [`Request::accepts`]).
    pub fn accepts(&self, media_type: &str) -> bool {
        self.headers.iter().filter(|(n, _)| n == "accept").any(|(_, v)| {
            v.split(|&b| b == b',').any(|item| {
                let item = item.split(|&b| b == b';').next().unwrap_or(&[]);
                item.trim_ascii().eq_ignore_ascii_case(media_type.as_bytes())
            })
        })
    }
}

/// How a connection's first request turned out.
#[derive(Debug)]
pub enum Handshake {
    /// A valid WebSocket upgrade; the `101` has been written. Bytes the client sent
    /// after its request head (typically the first frames) are still in the
    /// caller's buffer, ready for the frame decoder.
    Upgraded(OwnedRequest),
    /// Any other request. Nothing has been written; the caller answers with
    /// [`write_response`] and closes (this layer never reads request bodies).
    PlainHttp(OwnedRequest),
}

/// Reads one request head from `stream` into `buf` and settles the handshake.
///
/// * Valid upgrade: writes `101`, removes the head from `buf`, returns `Upgraded`.
/// * Upgrade to websocket that is invalid: writes `426` (wrong
///   `Sec-WebSocket-Version`, with the supported one) or `400`, then errors.
/// * Malformed or oversize head: writes the matching status (400, 431, 505) and errors.
/// * Anything else, including `Upgrade: h2c` from `curl --http2`: `PlainHttp`.
///
/// `buf` may already hold bytes (a previous read); `max_head` caps the head size.
///
/// No extensions are negotiated: a client's permessage-deflate offer is ignored and the
/// connection runs uncompressed. Use [`server_handshake_with`] to accept it.
pub async fn server_handshake<S>(stream: &mut S, buf: &mut Vec<u8>, max_head: usize) -> io::Result<Handshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    server_handshake_with(stream, buf, max_head, &ExtensionPolicy::NONE).await.map(|(h, _)| h)
}

/// [`server_handshake`] that also negotiates extensions under `policy`, returning what
/// was agreed (for an upgrade; `Extensions::NONE` otherwise). Configure the frame decoder
/// with `Decoder::with_deflate` and the sender with `Compressor::for_role` from it.
pub async fn server_handshake_with<S>(
    stream: &mut S,
    buf: &mut Vec<u8>,
    max_head: usize,
    policy: &ExtensionPolicy,
) -> io::Result<(Handshake, Extensions)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let mut reply = Vec::new();
        match parse_request_with(buf, max_head) {
            Ok(Some((req, n))) => {
                let owned = OwnedRequest::from_request(&req);
                if !req.wants_websocket() {
                    buf.drain(..n);
                    return Ok((Handshake::PlainHttp(owned), Extensions::NONE));
                }
                let Some(key) = req.websocket_key() else {
                    // Wrong version gets 426 so a client can retry with ours.
                    let version_ok = req.headers.get("sec-websocket-version") == Some(b"13");
                    if version_ok {
                        write_response(
                            &mut reply,
                            400,
                            "Bad Request",
                            "text/plain",
                            &[],
                            b"bad websocket handshake\n",
                            true,
                        );
                    } else {
                        write_response(
                            &mut reply,
                            426,
                            "Upgrade Required",
                            "text/plain",
                            &[("Sec-WebSocket-Version", "13")],
                            b"unsupported websocket version\n",
                            true,
                        );
                    }
                    stream.write_all(&reply).await?;
                    // FIN right behind the reply, so closing with request bytes unread
                    // cannot turn into a reset that eats it.
                    let _ = stream.shutdown().await;
                    return Err(invalid_data("invalid websocket handshake"));
                };
                let extensions = Extensions::negotiate(&req, policy);
                write_upgrade_response(&mut reply, &accept_key(key), &extensions);
                buf.drain(..n);
                stream.write_all(&reply).await?;
                stream.flush().await?;
                return Ok((Handshake::Upgraded(owned), extensions));
            }
            Ok(None) => fill(stream, buf, 1024).await?,
            Err(e) => {
                let status = e.status();
                write_response(
                    &mut reply,
                    status,
                    reason_phrase(status),
                    "text/plain",
                    &[],
                    e.message().as_bytes(),
                    true,
                );
                // Best effort: the peer may already be gone.
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
                return Err(invalid_data(e));
            }
        }
    }
}

/// Something received from the peer, owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    /// The peer's close frame (status and reason, if it sent any).
    Close(Option<(u16, String)>),
}

impl From<Event<'_>> for Message {
    fn from(e: Event<'_>) -> Message {
        match e {
            Event::Text(s) => Message::Text(s.to_owned()),
            Event::Binary(b) => Message::Binary(b.to_vec()),
            Event::Ping(b) => Message::Ping(b.to_vec()),
            Event::Pong(b) => Message::Pong(b.to_vec()),
            Event::Close(c) => Message::Close(c.map(|(code, r)| (code, r.to_owned()))),
        }
    }
}

/// How a client offers permessage-deflate (RFC 7692). The offer always carries
/// `client_max_window_bits` (so a server may cap the client's window) and adds the
/// other parameters on request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientDeflate {
    /// Messages shorter than this are sent uncompressed (see [`Compressor`]).
    pub min_len: usize,
    pub client_no_context_takeover: bool,
    pub server_no_context_takeover: bool,
    /// Ask the server to compress with at most this window (8..=15).
    pub server_max_window_bits: Option<u8>,
    /// Promise to compress with at most this window (8..=15).
    pub client_max_window_bits: Option<u8>,
}

impl Default for ClientDeflate {
    fn default() -> Self {
        ClientDeflate {
            min_len: Compressor::DEFAULT_MIN_LEN,
            client_no_context_takeover: false,
            server_no_context_takeover: false,
            server_max_window_bits: None,
            client_max_window_bits: None,
        }
    }
}

impl ClientDeflate {
    fn offer(&self) -> String {
        let mut s = String::from("permessage-deflate");
        match self.client_max_window_bits {
            Some(b) => s.push_str(&format!("; client_max_window_bits={}", b.clamp(8, 15))),
            None => s.push_str("; client_max_window_bits"),
        }
        if let Some(b) = self.server_max_window_bits {
            s.push_str(&format!("; server_max_window_bits={}", b.clamp(8, 15)));
        }
        if self.client_no_context_takeover {
            s.push_str("; client_no_context_takeover");
        }
        if self.server_no_context_takeover {
            s.push_str("; server_no_context_takeover");
        }
        s
    }
}

/// Asks for `bytes` of send and receive buffer on a Unix stream socket (the
/// kernel caps it). macOS gives one 8 KB (Linux about 200 KB), so a large answer
/// would otherwise cross 8 KB per wakeup: slower than loopback TCP, whose buffers
/// grow on their own. Best effort: a refusal leaves the default.
#[cfg(unix)]
pub fn unix_buffers(fd: std::os::fd::RawFd, bytes: usize) {
    let n = bytes.min(i32::MAX as usize) as libc::c_int;
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: a valid descriptor and a c_int option value of the right size.
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, opt, (&n as *const libc::c_int).cast(), std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        }
    }
}

/// Connects to `addr` and performs the client handshake. `host` is the `Host`
/// header value and `path` the request target (`"/"`, `"/nostr"`).
pub async fn client_connect(addr: impl ToSocketAddrs, host: &str, path: &str) -> io::Result<ClientConn<TcpStream>> {
    client_connect_with(addr, host, path, None).await
}

/// [`client_connect`] that offers permessage-deflate when `deflate` is given. Whether the
/// server accepted is [`ClientConn::deflate_params`].
pub async fn client_connect_with(
    addr: impl ToSocketAddrs,
    host: &str,
    path: &str,
    deflate: Option<ClientDeflate>,
) -> io::Result<ClientConn<TcpStream>> {
    let stream = TcpStream::connect(addr).await?;
    // Small request/response frames: Nagle plus delayed ACK would add 40 ms each.
    stream.set_nodelay(true)?;
    client_handshake_with(stream, host, path, deflate).await
}

/// Performs the client handshake over an already connected stream.
pub async fn client_handshake<S>(stream: S, host: &str, path: &str) -> io::Result<ClientConn<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client_handshake_with(stream, host, path, None).await
}

/// [`client_handshake`] that offers permessage-deflate when `deflate` is given.
pub async fn client_handshake_with<S>(
    mut stream: S,
    host: &str,
    path: &str,
    deflate: Option<ClientDeflate>,
) -> io::Result<ClientConn<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let clean = |s: &str| !s.is_empty() && !s.bytes().any(|b| b <= b' ' || b == 0x7F);
    if !clean(path) || host.bytes().any(|b| b < b' ' || b == 0x7F) || host.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid host or path"));
    }

    let mut enc = ClientEncoder::new();
    let mut raw_key = [0u8; 16];
    enc.fill(&mut raw_key);
    let mut key = Vec::new();
    crate::base64::encode(&raw_key, &mut key);
    let mut req = Vec::with_capacity(256);
    req.extend_from_slice(b"GET ");
    req.extend_from_slice(path.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(b"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    req.extend_from_slice(&key);
    req.extend_from_slice(b"\r\nSec-WebSocket-Version: 13\r\n");
    if let Some(d) = &deflate {
        req.extend_from_slice(b"Sec-WebSocket-Extensions: ");
        req.extend_from_slice(d.offer().as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut rbuf = Vec::new();
    loop {
        match parse_response(&rbuf, DEFAULT_MAX_HEAD) {
            Ok(Some((resp, n))) => {
                if resp.status != 101 {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        format!("websocket handshake refused: HTTP {}", resp.status),
                    ));
                }
                let h = &resp.headers;
                // Only what we offered may come back: nothing, or one permessage-deflate.
                let params = match (h.get("sec-websocket-extensions"), &deflate) {
                    (None, _) => Some(None),
                    (Some(v), Some(_)) if !v.contains(&b',') => DeflateParams::from_response(v).map(Some),
                    _ => None,
                };
                let ok = h.has_token("upgrade", "websocket")
                    && h.has_token("connection", "upgrade")
                    && h.get("sec-websocket-accept") == Some(&accept_key(&key)[..]);
                let (true, Some(params)) = (ok, params) else {
                    return Err(invalid_data("bad websocket handshake response"));
                };
                // Frames the server sent right behind the 101 stay buffered.
                rbuf.drain(..n);
                let mut dec = Decoder::new(Role::Client, CLIENT_MAX_MESSAGE, CLIENT_MAX_MESSAGE);
                let mut comp = None;
                if let (Some(p), Some(d)) = (&params, &deflate) {
                    dec = dec.with_deflate(p);
                    comp = Some(Compressor::for_role(p, Role::Client, d.min_len));
                }
                return Ok(ClientConn {
                    stream,
                    rbuf,
                    rpos: 0,
                    wbuf: Vec::new(),
                    wpos: 0,
                    dec,
                    enc,
                    comp,
                    params,
                    scratch: Vec::new(),
                    sent_close: false,
                    peer_close: None,
                });
            }
            Ok(None) => fill(&mut stream, &mut rbuf, 1024).await?,
            Err(e) => return Err(invalid_data(e)),
        }
    }
}

/// A client-side WebSocket connection: masked frames out, owned messages in.
///
/// `queue_*` buffer frames and [`flush`](Self::flush) writes them in one go, so a
/// benchmark can pipeline many requests per syscall; `send_*` do both.
///
/// [`recv`](Self::recv) and [`flush`](Self::flush) are cancel-safe: dropping
/// either mid-way (a `select!` that took another branch, a timeout) loses no
/// input and leaves no half-written frame behind, so a caller can wait for a
/// message and for something else at once.
pub struct ClientConn<S = TcpStream> {
    stream: S,
    rbuf: Vec<u8>,
    /// Start of the unconsumed input in `rbuf` (consumed bytes are dropped lazily).
    rpos: usize,
    wbuf: Vec<u8>,
    /// Bytes of `wbuf` already written: a flush that was cancelled resumes here.
    wpos: usize,
    dec: Decoder,
    enc: ClientEncoder,
    /// Present when permessage-deflate was negotiated.
    comp: Option<Compressor>,
    params: Option<DeflateParams>,
    /// Compressed payload under construction; reused.
    scratch: Vec<u8>,
    sent_close: bool,
    peer_close: Option<Option<(u16, String)>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> ClientConn<S> {
    /// The permessage-deflate parameters the server accepted, if it did.
    pub fn deflate_params(&self) -> Option<&DeflateParams> {
        self.params.as_ref()
    }

    /// Queues one data message, compressed when the extension is on and the payload is
    /// long enough to be worth it.
    fn queue_data(&mut self, opcode: Opcode, payload: &[u8]) {
        if let Some(c) = self.comp.as_mut().filter(|c| c.will_compress(payload.len())) {
            self.scratch.clear();
            c.deflate_payload(payload, &mut self.scratch);
            self.enc.write_frame_ext(&mut self.wbuf, opcode, true, true, &self.scratch);
        } else {
            self.enc.write_frame(&mut self.wbuf, opcode, true, payload);
        }
    }

    pub fn queue_text(&mut self, text: &str) {
        self.queue_data(Opcode::Text, text.as_bytes());
    }

    pub fn queue_binary(&mut self, data: &[u8]) {
        self.queue_data(Opcode::Binary, data);
    }

    pub fn queue_ping(&mut self, payload: &[u8]) {
        self.enc.write_ping(&mut self.wbuf, payload);
    }

    /// Writes everything queued. Progress is kept between calls, so a flush
    /// that is cancelled and called again sends each byte exactly once.
    pub async fn flush(&mut self) -> io::Result<()> {
        while self.wpos < self.wbuf.len() {
            let n = self.stream.write(&self.wbuf[self.wpos..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            self.wpos += n;
        }
        self.wbuf.clear();
        self.wpos = 0;
        self.stream.flush().await
    }

    /// Bytes queued and not yet written.
    pub fn pending_bytes(&self) -> usize {
        self.wbuf.len() - self.wpos
    }

    pub async fn send_text(&mut self, text: &str) -> io::Result<()> {
        self.queue_text(text);
        self.flush().await
    }

    pub async fn send_binary(&mut self, data: &[u8]) -> io::Result<()> {
        self.queue_binary(data);
        self.flush().await
    }

    pub async fn send_ping(&mut self, payload: &[u8]) -> io::Result<()> {
        self.queue_ping(payload);
        self.flush().await
    }

    /// Waits for the next message. Pings are answered with a pong before being
    /// returned; a close frame is echoed (once) and returned, after which `recv`
    /// fails with `NotConnected`. A protocol violation by the server is answered
    /// with the matching close code and returned as `InvalidData`.
    pub async fn recv(&mut self) -> io::Result<Message> {
        if self.peer_close.is_some() {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "websocket closed"));
        }
        loop {
            let decoded = match self.dec.decode(&mut self.rbuf[self.rpos..]) {
                Ok(d) => d,
                Err(e) => return Err(self.fail(e).await),
            };
            self.rpos += decoded.consumed;
            if let Some(event) = decoded.event {
                let msg = Message::from(event);
                match &msg {
                    Message::Ping(p) => {
                        self.enc.write_pong(&mut self.wbuf, p);
                        self.flush().await?;
                    }
                    Message::Close(c) => {
                        self.peer_close = Some(c.clone());
                        if !self.sent_close {
                            self.sent_close = true;
                            match c {
                                Some((code, _)) => self.enc.write_close(&mut self.wbuf, *code, ""),
                                None => self.enc.write_close(&mut self.wbuf, close_code::NORMAL, ""),
                            }
                            // The server may already be gone; the close still arrived.
                            let _ = self.flush().await;
                        }
                    }
                    _ => {}
                }
                return Ok(msg);
            }
            self.rbuf.drain(..self.rpos);
            self.rpos = 0;
            let missing = self.dec.needed().saturating_sub(self.rbuf.len());
            fill(&mut self.stream, &mut self.rbuf, missing.max(4096)).await?;
        }
    }

    /// Reports a decode failure to the server (best effort) and builds the error.
    async fn fail(&mut self, e: WsError) -> io::Error {
        if !self.sent_close {
            self.sent_close = true;
            self.enc.write_close(&mut self.wbuf, e.close_code(), e.reason());
            let _ = self.flush().await;
        }
        invalid_data(e)
    }

    /// Closes cleanly: sends a 1000 close (unless one went out already), waits for
    /// the server's close frame, and shuts the stream down. Returns the server's
    /// close status, if it sent one.
    pub async fn close(mut self) -> io::Result<Option<(u16, String)>> {
        if !self.sent_close {
            self.sent_close = true;
            self.enc.write_close(&mut self.wbuf, close_code::NORMAL, "");
            self.flush().await?;
        }
        let peer = loop {
            if let Some(c) = self.peer_close.take() {
                break c;
            }
            match self.recv().await {
                Ok(_) => {}
                // The server hung up without a close frame.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break None,
                Err(e) => return Err(e),
            }
        };
        let _ = self.stream.shutdown().await;
        Ok(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::{write_binary, write_close, write_close_empty, write_pong, write_text, Decoder, Event, Role};
    use tokio::net::TcpListener;

    /// The benchmark client moves connections into spawned tasks, so every future
    /// here must be `Send`. Compile-time check only; nothing calls these.
    #[allow(dead_code)]
    fn futures_are_send(c: ClientConn, s: &mut TcpStream, buf: &mut Vec<u8>) {
        fn assert_send<T: Send>(_: &T) {}
        async fn drive(mut c: ClientConn) {
            c.send_text("x").await.unwrap();
            let _ = c.recv().await;
            let _ = c.close().await;
        }
        assert_send(&drive(c));
        assert_send(&server_handshake(s, buf, 1));
        assert_send(&client_connect("127.0.0.1:1", "h", "/"));
    }

    /// The loop every connection owner writes: decode what is buffered, answer in
    /// one output buffer, flush once, read more.
    async fn echo_server(listener: TcpListener) -> io::Result<()> {
        let (s, _) = listener.accept().await?;
        s.set_nodelay(true)?;
        echo_on(s).await
    }

    async fn echo_on<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) -> io::Result<()> {
        let mut buf = Vec::new();
        match server_handshake(&mut s, &mut buf, DEFAULT_MAX_HEAD).await? {
            Handshake::Upgraded(req) => assert_eq!(req.path, "/echo"),
            Handshake::PlainHttp(_) => panic!("expected an upgrade"),
        }
        let mut dec = Decoder::new(Role::Server, 1 << 20, 1 << 20);
        let mut out = Vec::new();
        loop {
            let mut off = 0;
            let mut closing = false;
            loop {
                let d = match dec.decode(&mut buf[off..]) {
                    Ok(d) => d,
                    Err(e) => {
                        write_close(&mut out, e.close_code(), e.reason());
                        closing = true;
                        break;
                    }
                };
                off += d.consumed;
                match d.event {
                    Some(Event::Text(t)) => write_text(&mut out, t.as_bytes()),
                    Some(Event::Binary(b)) => write_binary(&mut out, b),
                    Some(Event::Ping(p)) => write_pong(&mut out, p),
                    Some(Event::Pong(_)) => {}
                    Some(Event::Close(c)) => {
                        match c {
                            Some((code, _)) => write_close(&mut out, code, ""),
                            None => write_close_empty(&mut out),
                        }
                        closing = true;
                        break;
                    }
                    None => break,
                }
            }
            buf.drain(..off);
            if !out.is_empty() {
                s.write_all(&out).await?;
                out.clear();
            }
            if closing {
                return Ok(());
            }
            let missing = dec.needed().saturating_sub(buf.len());
            fill(&mut s, &mut buf, missing.max(4096)).await?;
        }
    }

    async fn spawn_echo() -> (std::net::SocketAddr, tokio::task::JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (addr, tokio::spawn(echo_server(listener)))
    }

    /// Deterministic text of `n` bytes that is valid UTF-8 and exercises
    /// multi-byte characters (2-byte e-acute, 3-byte euro sign, 4-byte emoji).
    fn text_of(n: usize, seed: u64) -> String {
        let pieces = ["a", "Z", " ", "{", "\u{e9}", "\u{20ac}", "\u{1F600}"];
        let mut s = String::with_capacity(n + 4);
        let mut x = seed | 1;
        while s.len() < n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let p = pieces[(x % pieces.len() as u64) as usize];
            if s.len() + p.len() > n {
                s.push('x');
            } else {
                s.push_str(p);
            }
        }
        s
    }

    #[tokio::test]
    async fn echoes_a_thousand_random_messages_then_closes_cleanly() {
        let (addr, server) = spawn_echo().await;
        let mut c = client_connect(addr, "localhost", "/echo").await.unwrap();

        let mut x = 0x2545_F491_4F6C_DD1Du64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for i in 0..1000 {
            // Mostly small, sometimes across the 16-bit and 64 KiB length boundaries.
            let n = match rnd() % 20 {
                0 => 60_000 + (rnd() % 20_000) as usize,
                1 | 2 => (rnd() % 5000) as usize,
                _ => (rnd() % 300) as usize,
            };
            if rnd() % 4 == 0 {
                let data: Vec<u8> = (0..n).map(|_| rnd() as u8).collect();
                c.send_binary(&data).await.unwrap();
                assert_eq!(c.recv().await.unwrap(), Message::Binary(data), "message {i}");
            } else {
                let t = text_of(n, rnd());
                c.send_text(&t).await.unwrap();
                assert_eq!(c.recv().await.unwrap(), Message::Text(t), "message {i}");
            }
        }

        let closed = c.close().await.unwrap();
        assert_eq!(closed, Some((1000, String::new())));
        server.await.unwrap().unwrap();
    }

    /// A caller that waits on `recv` and `flush` beside other things cancels
    /// them all the time: nothing may be lost or sent twice when it does.
    /// Over a pipe that holds 16 KiB, a message ten times that size cannot be
    /// sent or received in one go, and each call here is dropped the first
    /// time it has to wait, so both are cut short many times per message.
    #[tokio::test]
    async fn recv_and_flush_survive_cancellation() {
        let (client_end, server_end) = tokio::io::duplex(16 * 1024);
        let server = tokio::spawn(echo_on(server_end));
        let mut c = client_handshake(client_end, "localhost", "/echo").await.unwrap();
        let mut cancelled = (0, 0);
        // A byte sent twice or lost corrupts the stream and the echo never
        // comes: that must fail, not spin forever.
        // Each message takes a dozen or so cut-short calls each way.
        let stuck = |n: u64| assert!(n < 5_000, "the echo stopped coming: bytes were lost or sent twice");
        for i in 0..12 {
            let m = text_of(160_000 + i * 1000, i as u64 + 7);
            c.queue_text(&m);
            loop {
                tokio::select! {
                    biased;
                    r = c.flush() => break r.unwrap(),
                    () = std::future::ready(()) => cancelled.0 += 1,
                }
                stuck(cancelled.0);
                // Let the other end take what was written.
                tokio::task::yield_now().await;
            }
            assert_eq!(c.pending_bytes(), 0);
            let got = loop {
                tokio::select! {
                    biased;
                    r = c.recv() => break r.unwrap(),
                    () = std::future::ready(()) => cancelled.1 += 1,
                }
                stuck(cancelled.1);
                tokio::task::yield_now().await;
            };
            assert_eq!(got, Message::Text(m), "message {i}");
        }
        assert!(cancelled.0 >= 12 && cancelled.1 >= 12, "both must actually be cut short: {cancelled:?}");
        assert_eq!(c.close().await.unwrap(), Some((1000, String::new())));
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pipelined_messages_come_back_in_order() {
        let (addr, server) = spawn_echo().await;
        let mut c = client_connect(addr, "localhost", "/echo").await.unwrap();
        let msgs: Vec<String> = (0..200).map(|i| text_of(i * 37 % 4000, i as u64 + 1)).collect();
        for m in &msgs {
            c.queue_text(m);
        }
        c.flush().await.unwrap();
        for m in &msgs {
            assert_eq!(c.recv().await.unwrap(), Message::Text(m.clone()));
        }
        // A ping is answered by the server and by recv() on this side.
        c.send_ping(b"are you there").await.unwrap();
        assert_eq!(c.recv().await.unwrap(), Message::Pong(b"are you there".to_vec()));
        assert_eq!(c.close().await.unwrap(), Some((1000, String::new())));
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn frames_pipelined_behind_the_handshake_are_kept() {
        // A client that sends its first frame in the same write as the request head.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(echo_server(listener));

        let mut s = TcpStream::connect(addr).await.unwrap();
        let mut req = b"GET /echo HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
            .to_vec();
        let mut enc = ClientEncoder::with_seed(77);
        enc.write_text(&mut req, b"early bird");
        enc.write_close(&mut req, 1000, "");
        s.write_all(&req).await.unwrap();

        // Everything the server sends until it hangs up: 101 head, echo, close.
        let mut all = Vec::new();
        s.read_to_end(&mut all).await.unwrap();
        let (resp, n) = parse_response(&all, 4096).unwrap().unwrap();
        assert_eq!(resp.status, 101);
        assert_eq!(resp.headers.get("sec-websocket-accept"), Some(&b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="[..]));
        let mut rest = all[n..].to_vec();
        let mut dec = Decoder::new(Role::Client, 1 << 20, 1 << 20);
        let d = dec.decode(&mut rest).unwrap();
        assert_eq!(d.event, Some(Event::Text("early bird")));
        let consumed = d.consumed;
        let d = dec.decode(&mut rest[consumed..]).unwrap();
        assert_eq!(d.event, Some(Event::Close(Some((1000, "")))));
        server.await.unwrap().unwrap();
    }

    /// Runs `server_handshake` against raw bytes sent by a plain TCP client.
    async fn raw_exchange(request: &[u8]) -> (io::Result<Handshake>, Vec<u8>, Vec<u8>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let r = server_handshake(&mut s, &mut buf, 2048).await;
            if let Ok(Handshake::PlainHttp(req)) = &r {
                let mut out = Vec::new();
                let ct = if req.accepts("application/nostr+json") { "application/nostr+json" } else { "text/plain" };
                write_response(&mut out, 200, "OK", ct, &[], b"hi", true);
                s.write_all(&out).await.unwrap();
            }
            s.shutdown().await.ok();
            (r, buf)
        });
        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(request).await.unwrap();
        let mut reply = Vec::new();
        // The server may reset the connection when it closes with request bytes
        // unread (oversize heads); whatever arrived before that is the reply.
        let _ = c.read_to_end(&mut reply).await;
        let (r, buf) = server.await.unwrap();
        (r, reply, buf)
    }

    #[tokio::test]
    async fn plain_http_is_handed_back_with_its_headers() {
        let (r, reply, _) = raw_exchange(
            b"GET /info HTTP/1.1\r\nHost: relay.example\r\nAccept: application/nostr+json\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
        )
        .await;
        match r.unwrap() {
            Handshake::PlainHttp(req) => {
                assert_eq!((req.method.as_str(), req.path.as_str()), ("GET", "/info"));
                assert_eq!(req.header("x-forwarded-for"), Some(&b"1.2.3.4"[..]));
                assert_eq!(req.header("Host"), Some(&b"relay.example"[..]));
                assert!(req.accepts("application/nostr+json"));
            }
            Handshake::Upgraded(_) => panic!("not an upgrade"),
        }
        let reply = String::from_utf8(reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\n"));
        assert!(reply.ends_with("\r\n\r\nhi"));
    }

    #[tokio::test]
    async fn h2c_upgrade_request_is_plain_http() {
        let (r, _, _) =
            raw_exchange(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\n\r\n")
                .await;
        assert!(matches!(r.unwrap(), Handshake::PlainHttp(_)));
    }

    #[tokio::test]
    async fn wrong_websocket_version_gets_426() {
        let (r, reply, _) = raw_exchange(
            b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n",
        )
        .await;
        assert!(r.is_err());
        let reply = String::from_utf8(reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 426 Upgrade Required\r\n"), "{reply}");
        assert!(reply.contains("Sec-WebSocket-Version: 13\r\n"));
    }

    #[tokio::test]
    async fn bad_key_gets_400() {
        let (r, reply, _) = raw_exchange(
            b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Key: short\r\nSec-WebSocket-Version: 13\r\n\r\n",
        )
        .await;
        assert!(r.is_err());
        assert!(String::from_utf8(reply).unwrap().starts_with("HTTP/1.1 400 "));
    }

    #[tokio::test]
    async fn garbage_and_oversize_heads_get_error_statuses() {
        let (r, reply, _) = raw_exchange(b"NOT HTTP AT ALL\r\n\r\n").await;
        assert!(r.is_err());
        assert!(String::from_utf8(reply).unwrap().starts_with("HTTP/1.1 400 "));

        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', 4000));
        big.extend_from_slice(b"\r\n\r\n");
        let (r, reply, _) = raw_exchange(&big).await;
        assert!(r.is_err());
        assert!(String::from_utf8(reply).unwrap().starts_with("HTTP/1.1 431 "));
    }

    #[tokio::test]
    async fn handshake_head_split_across_reads() {
        // Drive server_handshake over an in-memory pipe, one byte at a time.
        let (mut client, mut server_side) = tokio::io::duplex(4096);
        let head: &'static [u8] = b"GET /s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n\x81\x80abcd";
        let writer = tokio::spawn(async move {
            // The head trickles in a byte at a time; the last head byte arrives in the
            // same write as the first frame, as from a client that pipelines.
            let (trickle, tail) = head.split_at(head.len() - 7);
            for b in trickle {
                client.write_all(std::slice::from_ref(b)).await.unwrap();
                tokio::task::yield_now().await;
            }
            client.write_all(tail).await.unwrap();
            let mut resp = Vec::new();
            client.read_buf(&mut resp).await.unwrap();
            resp
        });
        let mut buf = Vec::new();
        let h = server_handshake(&mut server_side, &mut buf, DEFAULT_MAX_HEAD).await.unwrap();
        assert!(matches!(h, Handshake::Upgraded(ref r) if r.path == "/s"));
        // The six bytes behind the head survived for the frame decoder.
        assert_eq!(buf, b"\x81\x80abcd");
        let resp = writer.await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));
    }

    #[tokio::test]
    async fn client_rejects_a_wrong_accept_key() {
        let (client_side, mut server_side) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut buf = Vec::new();
            server_side.read_buf(&mut buf).await.unwrap();
            server_side
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
                )
                .await
                .unwrap();
        });
        let err = client_handshake(client_side, "x", "/").await.err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn client_reports_a_refused_upgrade() {
        let (client_side, mut server_side) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut buf = Vec::new();
            server_side.read_buf(&mut buf).await.unwrap();
            server_side.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        });
        let err = client_handshake(client_side, "x", "/").await.err().expect("must fail");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn client_rejects_header_injection_in_host_and_path() {
        for (host, path) in [("a\r\nX: y", "/"), ("a", "/ HTTP/1.1\r\nX: y"), ("", "/"), ("a", "")] {
            let (c, _s) = tokio::io::duplex(64);
            let err = client_handshake(c, host, path).await.err().expect("must fail");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{host:?} {path:?}");
        }
    }

    #[tokio::test]
    async fn server_violation_is_reported_and_answered() {
        // A raw server that completes the handshake and then sends a masked frame.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            server_handshake(&mut s, &mut buf, DEFAULT_MAX_HEAD).await.unwrap();
            s.write_all(&[0x81, 0x81, 1, 2, 3, 4, 5]).await.unwrap(); // masked: illegal from a server
            let mut got = Vec::new();
            s.read_buf(&mut got).await.unwrap();
            got
        });
        let mut c = client_connect(addr, "x", "/").await.unwrap();
        let err = c.recv().await.expect_err("must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        // The client told the server why: a masked close frame with code 1002.
        let got = server.await.unwrap();
        assert_eq!(got[0], 0x88);
        let mut dec = Decoder::new(Role::Server, 4096, 4096);
        let mut got = got;
        assert_eq!(dec.decode(&mut got).unwrap().event, Some(Event::Close(Some((1002, "server frame masked")))));
    }

    #[tokio::test]
    async fn server_initiated_close_is_echoed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            server_handshake(&mut s, &mut buf, DEFAULT_MAX_HEAD).await.unwrap();
            let mut out = Vec::new();
            write_close(&mut out, 1001, "going away");
            s.write_all(&out).await.unwrap();
            // Read the client's echo until it hangs up.
            let mut got = Vec::new();
            s.read_to_end(&mut got).await.unwrap();
            got
        });
        let mut c = client_connect(addr, "x", "/").await.unwrap();
        assert_eq!(c.recv().await.unwrap(), Message::Close(Some((1001, "going away".into()))));
        assert_eq!(c.recv().await.unwrap_err().kind(), io::ErrorKind::NotConnected);
        assert_eq!(c.close().await.unwrap(), Some((1001, "going away".into())));
        let mut got = server.await.unwrap();
        let mut dec = Decoder::new(Role::Server, 4096, 4096);
        assert_eq!(dec.decode(&mut got).unwrap().event, Some(Event::Close(Some((1001, "")))));
    }

    // ---- permessage-deflate over real sockets ----

    use crate::http::DEFAULT_MAX_HEAD as MAX_HEAD;
    use crate::ws::{Compressor as Comp, DeflatePolicy};

    /// What a deflate-aware echo server observed.
    #[derive(Debug)]
    struct Observed {
        extensions: Extensions,
        /// Bytes of frames received (headers, masks and compressed payloads).
        wire_in: usize,
        /// Bytes of message payload they decoded to.
        plain_in: usize,
        /// Frames the server sent with RSV1 set.
        compressed_out: usize,
    }

    async fn deflate_echo_server(
        listener: TcpListener,
        policy: ExtensionPolicy,
        min_len: usize,
    ) -> io::Result<Observed> {
        let (mut s, _) = listener.accept().await?;
        s.set_nodelay(true)?;
        let mut buf = Vec::new();
        let (h, extensions) = server_handshake_with(&mut s, &mut buf, MAX_HEAD, &policy).await?;
        assert!(matches!(h, Handshake::Upgraded(_)));
        let mut dec = Decoder::new(Role::Server, 1 << 22, 1 << 22);
        let mut comp = None;
        if let Some(p) = &extensions.deflate {
            dec = dec.with_deflate(p);
            comp = Some(Comp::for_role(p, Role::Server, min_len));
        }
        let mut obs = Observed { extensions, wire_in: 0, plain_in: 0, compressed_out: 0 };
        let mut out = Vec::new();
        loop {
            let mut off = 0;
            let mut closing = false;
            loop {
                let d = dec.decode(&mut buf[off..]).expect("a valid stream");
                off += d.consumed;
                obs.wire_in += d.consumed;
                let first_out = out.len();
                match d.event {
                    Some(Event::Text(t)) => {
                        obs.plain_in += t.len();
                        match comp.as_mut() {
                            Some(c) => c.compress_text(&mut out, t.as_bytes()),
                            None => write_text(&mut out, t.as_bytes()),
                        }
                    }
                    Some(Event::Binary(b)) => {
                        obs.plain_in += b.len();
                        match comp.as_mut() {
                            Some(c) => c.compress_binary(&mut out, b),
                            None => write_binary(&mut out, b),
                        }
                    }
                    Some(Event::Ping(p)) => write_pong(&mut out, p),
                    Some(Event::Pong(_)) => {}
                    Some(Event::Close(c)) => {
                        match c {
                            Some((code, _)) => write_close(&mut out, code, ""),
                            None => write_close_empty(&mut out),
                        }
                        closing = true;
                        break;
                    }
                    None => break,
                }
                if out.len() > first_out && out[first_out] & 0x40 != 0 {
                    obs.compressed_out += 1;
                }
            }
            buf.drain(..off);
            if !out.is_empty() {
                s.write_all(&out).await?;
                out.clear();
            }
            if closing {
                return Ok(obs);
            }
            let missing = dec.needed().saturating_sub(buf.len());
            fill(&mut s, &mut buf, missing.max(4096)).await?;
        }
    }

    async fn run_deflate_session(
        policy: ExtensionPolicy,
        client: Option<ClientDeflate>,
        server_min_len: usize,
    ) -> (Observed, Option<DeflateParams>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(deflate_echo_server(listener, policy, server_min_len));
        let mut c = client_connect_with(addr, "localhost", "/", client).await.unwrap();
        let params = c.deflate_params().copied();
        let events = crate::deflate::testutil::nostr_corpus(5, 120);
        for (i, e) in events.iter().enumerate() {
            let t = String::from_utf8(e.clone()).unwrap();
            // Pipeline a few messages per flush, as a benchmark client does.
            c.queue_text(&t);
            c.queue_text(&t[..t.len() / 2]);
            c.queue_binary(&e[..e.len() / 3]);
            c.flush().await.unwrap();
            assert_eq!(c.recv().await.unwrap(), Message::Text(t.clone()), "message {i}");
            assert_eq!(c.recv().await.unwrap(), Message::Text(t[..t.len() / 2].to_owned()));
            assert_eq!(c.recv().await.unwrap(), Message::Binary(e[..e.len() / 3].to_vec()));
        }
        // Big ones, across the 16-bit and 64-bit length forms.
        for n in [60_000usize, 70_000, 300_000] {
            let t = text_of(n, n as u64);
            c.send_text(&t).await.unwrap();
            assert_eq!(c.recv().await.unwrap(), Message::Text(t));
        }
        assert_eq!(c.close().await.unwrap(), Some((1000, String::new())));
        (server.await.unwrap().unwrap(), params)
    }

    #[tokio::test]
    async fn negotiated_deflate_works_over_a_socket_in_every_mode() {
        let on = ExtensionPolicy::with_deflate(DeflatePolicy::default());
        let modes: Vec<(&str, ExtensionPolicy, ClientDeflate)> = vec![
            ("default", on, ClientDeflate::default()),
            ("min_len 0", on, ClientDeflate { min_len: 0, ..Default::default() }),
            (
                "no takeover (client asks)",
                on,
                ClientDeflate {
                    client_no_context_takeover: true,
                    server_no_context_takeover: true,
                    ..Default::default()
                },
            ),
            (
                "no takeover (server insists)",
                ExtensionPolicy::with_deflate(DeflatePolicy {
                    server_no_context_takeover: true,
                    client_no_context_takeover: true,
                    ..Default::default()
                }),
                ClientDeflate::default(),
            ),
            (
                "small windows",
                on,
                ClientDeflate {
                    server_max_window_bits: Some(9),
                    client_max_window_bits: Some(10),
                    ..Default::default()
                },
            ),
            (
                "policy caps the client window",
                ExtensionPolicy::with_deflate(DeflatePolicy { max_client_window_bits: 9, ..Default::default() }),
                ClientDeflate::default(),
            ),
        ];
        for (name, policy, client) in modes {
            let (obs, params) = run_deflate_session(policy, Some(client), client.min_len).await;
            assert!(params.is_some() && obs.extensions.deflate.is_some(), "{name}: negotiated");
            assert!(obs.compressed_out > 100, "{name}: server compressed {} frames", obs.compressed_out.min(1000));
            assert!(
                obs.wire_in * 10 < obs.plain_in * 9,
                "{name}: client frames should be smaller than their payloads ({} vs {})",
                obs.wire_in,
                obs.plain_in
            );
        }
    }

    #[tokio::test]
    async fn without_agreement_the_connection_is_plain() {
        let on = ExtensionPolicy::with_deflate(DeflatePolicy::default());
        // Server declines (the default policy): the client's offer is ignored.
        let (obs, params) = run_deflate_session(ExtensionPolicy::NONE, Some(ClientDeflate::default()), 0).await;
        assert!(params.is_none() && obs.extensions.deflate.is_none());
        assert_eq!(obs.compressed_out, 0);
        assert!(obs.wire_in > obs.plain_in, "plain frames are payload plus headers and masks");
        // Client does not offer: the server must not compress even though it would.
        let (obs, params) = run_deflate_session(on, None, 0).await;
        assert!(params.is_none() && obs.extensions.deflate.is_none());
        assert_eq!(obs.compressed_out, 0);
        // The old entry point behaves as before: offers ignored.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(echo_server(listener));
        let mut c = client_connect_with(addr, "localhost", "/echo", Some(ClientDeflate::default())).await.unwrap();
        assert!(c.deflate_params().is_none());
        c.send_text("still works").await.unwrap();
        assert_eq!(c.recv().await.unwrap(), Message::Text("still works".into()));
        c.close().await.unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn an_extension_the_client_did_not_offer_is_refused() {
        for (offer, header) in [
            (None, "permessage-deflate"),
            (Some(ClientDeflate::default()), "permessage-deflate; bogus_param"),
            (Some(ClientDeflate::default()), "permessage-deflate, x-other"),
            (Some(ClientDeflate::default()), "x-other"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let value = header.to_owned();
            tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                loop {
                    fill(&mut s, &mut buf, 1024).await.unwrap();
                    if let Some((req, _)) = parse_request_with(&buf, MAX_HEAD).unwrap() {
                        let key = req.websocket_key().unwrap();
                        let accept = String::from_utf8(accept_key(key).to_vec()).unwrap();
                        let reply = format!(
                            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Extensions: {value}\r\n\r\n"
                        );
                        s.write_all(reply.as_bytes()).await.unwrap();
                        return;
                    }
                }
            });
            let r = client_connect_with(addr, "localhost", "/", offer).await;
            assert!(r.is_err(), "{header:?} with offer {offer:?} must be refused");
        }
    }
}
