//! The slice of HTTP/1.1 a WebSocket server needs: parse a request head, decide
//! whether it is a valid WebSocket upgrade, write the 101 or a plain response.
//!
//! Everything is a pure function over byte slices. Parsed requests borrow from the
//! caller's buffer (no allocation, headers in a fixed array), so accepting a
//! connection costs one scan of the head.
//!
//! Strict on structure, lenient on line endings: a request line and header lines
//! must be well formed (single-space request line, token header names, no folded
//! lines, no control characters), but a bare LF is accepted as a line ending.
//! Request bodies are not supported: the server answers a plain request and
//! closes, so any body bytes after the head are never interpreted (no
//! request-smuggling surface).

use crate::base64;
use crate::sha1::Sha1;
use crate::ws::pmd::{self, DeflateParams, DeflatePolicy};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

/// Default cap on the request head (request line + headers + blank line).
pub const DEFAULT_MAX_HEAD: usize = 8 * 1024;
/// Header lines a request may carry before it is refused.
pub const MAX_HEADERS: usize = 64;

/// The magic string RFC 6455 §1.3 appends to the client key before hashing.
const GUID: &[u8; 36] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// The head is larger than the cap, or does not end within it.
    HeadTooLarge,
    /// More than [`MAX_HEADERS`] header lines.
    TooManyHeaders,
    BadRequestLine,
    BadStatusLine,
    /// Not HTTP/1.0 or HTTP/1.1.
    BadVersion,
    BadHeader,
}

impl HttpError {
    /// The status code a server should answer this error with.
    pub fn status(self) -> u16 {
        match self {
            HttpError::HeadTooLarge | HttpError::TooManyHeaders => 431,
            HttpError::BadVersion => 505,
            _ => 400,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            HttpError::HeadTooLarge => "request head too large",
            HttpError::TooManyHeaders => "too many header fields",
            HttpError::BadRequestLine => "malformed request line",
            HttpError::BadStatusLine => "malformed status line",
            HttpError::BadVersion => "unsupported HTTP version",
            HttpError::BadHeader => "malformed header field",
        }
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for HttpError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a [u8],
    /// Without leading and trailing whitespace.
    pub value: &'a [u8],
}

/// A request's or response's header lines: a fixed array, no allocation.
#[derive(Clone)]
pub struct Headers<'a> {
    items: [Header<'a>; MAX_HEADERS],
    len: usize,
}

impl<'a> Headers<'a> {
    fn new() -> Self {
        Headers { items: [Header { name: b"", value: b"" }; MAX_HEADERS], len: 0 }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &Header<'a>> {
        self.items[..self.len].iter()
    }

    /// Value of the first header called `name` (case-insensitive).
    pub fn get(&self, name: &str) -> Option<&'a [u8]> {
        self.get_all(name).next()
    }

    /// Values of every header called `name`, in order of appearance.
    pub fn get_all<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'a [u8]> + 's {
        self.iter().filter(move |h| h.name.eq_ignore_ascii_case(name.as_bytes())).map(|h| h.value)
    }

    /// True when some `name` header lists `token` among its comma-separated
    /// values (both compared case-insensitively), as `Connection: keep-alive,
    /// Upgrade` lists `upgrade`. Repeated headers count as one list (RFC 7230 §3.2.2).
    pub fn has_token(&self, name: &str, token: &str) -> bool {
        self.get_all(name).any(|v| has_token(v, token.as_bytes()))
    }
}

/// A parsed request head, borrowing the bytes it was parsed from.
pub struct Request<'a> {
    pub method: &'a str,
    /// The request target as sent: path and query, still percent-encoded.
    pub path: &'a str,
    pub version: Version,
    pub headers: Headers<'a>,
}

impl<'a> Request<'a> {
    /// Value of the first header called `name` (case-insensitive).
    #[inline]
    pub fn header(&self, name: &str) -> Option<&'a [u8]> {
        self.headers.get(name)
    }

    /// The request carries an `Upgrade` header at all. Lets a server tell "wanted a
    /// protocol switch but got it wrong" (answer 426 or 400) from a plain request.
    #[inline]
    pub fn wants_upgrade(&self) -> bool {
        self.headers.get("upgrade").is_some()
    }

    /// The `Upgrade` header names `websocket`. Other upgrades (`h2c` from `curl
    /// --http2`) are not ours and a server should treat them as plain requests.
    pub fn wants_websocket(&self) -> bool {
        self.headers.has_token("upgrade", "websocket")
    }

    /// Whether the `Accept` header lists `media_type` (parameters such as `;q=0.8`
    /// ignored). Enough to spot NIP-11's `application/nostr+json`.
    pub fn accepts(&self, media_type: &str) -> bool {
        self.headers.get_all("accept").any(|v| {
            v.split(|&b| b == b',').any(|item| {
                let item = item.split(|&b| b == b';').next().unwrap_or(&[]);
                trim_ows(item).eq_ignore_ascii_case(media_type.as_bytes())
            })
        })
    }

    /// The `Sec-WebSocket-Key` of a valid WebSocket opening handshake, or `None`.
    ///
    /// Valid means (RFC 6455 §4.2.1): a GET over HTTP/1.1, `Upgrade` listing
    /// `websocket`, `Connection` listing `upgrade`, `Sec-WebSocket-Version: 13`, and
    /// exactly one `Sec-WebSocket-Key` that is base64 for 16 bytes. The key is
    /// returned as sent, ready for [`accept_key`].
    pub fn websocket_key(&self) -> Option<&'a [u8]> {
        if self.method != "GET" || self.version != Version::Http11 {
            return None;
        }
        if !self.headers.has_token("upgrade", "websocket") || !self.headers.has_token("connection", "upgrade") {
            return None;
        }
        // A handshake never has a body. Refusing one keeps a proxy and this server
        // from disagreeing about where the request ends and the frames begin.
        if self.headers.get("transfer-encoding").is_some() || self.headers.get_all("content-length").any(|v| v != b"0")
        {
            return None;
        }
        let mut versions = self.headers.get_all("sec-websocket-version");
        if versions.next() != Some(b"13") || versions.next().is_some() {
            return None;
        }
        // Two keys would be ambiguous; refuse rather than pick one.
        let mut keys = self.headers.get_all("sec-websocket-key");
        let key = keys.next()?;
        if keys.next().is_some() || key.len() != 24 {
            return None;
        }
        let mut raw = [0u8; 18];
        match base64::decode_slice(key, &mut raw) {
            Ok(16) => Some(key),
            _ => None,
        }
    }
}

/// A parsed status line and headers, for the client side of the handshake.
pub struct Response<'a> {
    pub status: u16,
    pub reason: &'a [u8],
    pub headers: Headers<'a>,
}

#[inline]
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

#[inline]
fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if is_ows(*first) {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if is_ows(*last) {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn has_token(list: &[u8], token: &[u8]) -> bool {
    list.split(|&b| b == b',').any(|t| trim_ows(t).eq_ignore_ascii_case(token))
}

/// Control characters (other than HTAB) and DEL never belong in a head line. A
/// stray CR is the interesting one: lenient parsers that treat it as a line break
/// disagree with strict ones about where a header ends.
#[inline]
fn has_ctl(line: &[u8]) -> bool {
    line.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7F)
}

/// Splits off the next line (without its LF or a CR before it).
fn next_line<'a>(b: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let rest = &b[*pos..];
    let nl = rest.iter().position(|&c| c == b'\n')?;
    *pos += nl + 1;
    let line = &rest[..nl];
    Some(line.strip_suffix(b"\r").unwrap_or(line))
}

/// Locates the end of the head: the index just past the blank line, or `None`.
fn find_head_end(b: &[u8], from: usize) -> Option<usize> {
    let mut pos = from;
    loop {
        let line = next_line(b, &mut pos)?;
        if line.is_empty() {
            return Some(pos);
        }
    }
}

/// Head framing shared by requests and responses: size cap, leading-blank-line
/// skip, header block. Returns the first line, the headers, and the total head
/// length (the offset of the first byte after it).
#[allow(clippy::type_complexity)]
fn parse_head(buf: &[u8], max_head: usize) -> Result<Option<(&[u8], Headers<'_>, usize)>, HttpError> {
    // RFC 7230 §3.5: tolerate empty lines before the request line.
    let start = buf.iter().position(|&b| b != b'\r' && b != b'\n').unwrap_or(buf.len());
    let end = match find_head_end(buf, start) {
        Some(end) if end > max_head => return Err(HttpError::HeadTooLarge),
        Some(end) => end,
        None if buf.len() >= max_head => return Err(HttpError::HeadTooLarge),
        None => return Ok(None),
    };
    // `start < end` because a non-blank byte exists before the terminating blank line.
    let mut pos = start;
    let first = next_line(buf, &mut pos).ok_or(HttpError::BadRequestLine)?;
    let mut headers = Headers::new();
    loop {
        let line = next_line(buf, &mut pos).ok_or(HttpError::BadHeader)?;
        if line.is_empty() {
            break;
        }
        if has_ctl(line) || is_ows(line[0]) {
            // Control characters, or an obs-fold continuation line (RFC 7230 §3.2.4
            // tells servers to reject it).
            return Err(HttpError::BadHeader);
        }
        let colon = line.iter().position(|&b| b == b':').ok_or(HttpError::BadHeader)?;
        let name = &line[..colon];
        // No whitespace before the colon (RFC 7230 §3.2.4), and a real token.
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err(HttpError::BadHeader);
        }
        if headers.len == MAX_HEADERS {
            return Err(HttpError::TooManyHeaders);
        }
        headers.items[headers.len] = Header { name, value: trim_ows(&line[colon + 1..]) };
        headers.len += 1;
    }
    debug_assert_eq!(pos, end);
    Ok(Some((first, headers, end)))
}

fn parse_version(v: &[u8]) -> Result<Version, HttpError> {
    match v {
        b"HTTP/1.1" => Ok(Version::Http11),
        b"HTTP/1.0" => Ok(Version::Http10),
        v if v.starts_with(b"HTTP/") => Err(HttpError::BadVersion),
        _ => Err(HttpError::BadRequestLine),
    }
}

/// Parses a request head from the start of `buf` with the default size cap.
/// See [`parse_request_with`].
pub fn parse_request(buf: &[u8]) -> Result<Option<(Request<'_>, usize)>, HttpError> {
    parse_request_with(buf, DEFAULT_MAX_HEAD)
}

/// Incrementally parses a request head.
///
/// * `Ok(None)`: the head (ending in a blank line) is not all here yet; call again
///   with more bytes.
/// * `Ok(Some((request, n)))`: a complete head occupying `buf[..n]`; bytes after it
///   (the first WebSocket frames, if the client was quick) are left alone.
/// * `Err`: malformed, or longer than `max_head` bytes, which is checked as bytes
///   arrive so a peer cannot make the server buffer an endless head.
///
/// Reparsing from the start on each call is quadratic in the worst case, but the
/// head is capped at a few KiB, so the worst case is microseconds.
pub fn parse_request_with(buf: &[u8], max_head: usize) -> Result<Option<(Request<'_>, usize)>, HttpError> {
    let Some((line, headers, n)) = parse_head(buf, max_head)? else {
        return Ok(None);
    };
    if has_ctl(line) || !line.is_ascii() {
        return Err(HttpError::BadRequestLine);
    }
    // METHOD SP target SP HTTP-version, single spaces, nothing else.
    let mut parts = line.split(|&b| b == b' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(HttpError::BadRequestLine);
    };
    if method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
        return Err(HttpError::BadRequestLine);
    }
    if target.is_empty() {
        return Err(HttpError::BadRequestLine);
    }
    let version = parse_version(version)?;
    // Both slices are ASCII (checked above), hence valid UTF-8.
    let method = std::str::from_utf8(method).map_err(|_| HttpError::BadRequestLine)?;
    let path = std::str::from_utf8(target).map_err(|_| HttpError::BadRequestLine)?;
    Ok(Some((Request { method, path, version, headers }, n)))
}

/// Incrementally parses a response head (the client side of the handshake). Same
/// contract as [`parse_request_with`].
pub fn parse_response(buf: &[u8], max_head: usize) -> Result<Option<(Response<'_>, usize)>, HttpError> {
    let Some((line, headers, n)) = parse_head(buf, max_head)? else {
        return Ok(None);
    };
    if has_ctl(line) {
        return Err(HttpError::BadStatusLine);
    }
    // HTTP-version SP status-code [SP reason]
    let (version, rest) = match line.iter().position(|&b| b == b' ') {
        Some(i) => (&line[..i], &line[i + 1..]),
        None => return Err(HttpError::BadStatusLine),
    };
    if !version.starts_with(b"HTTP/1.") || version.len() != 8 {
        return Err(HttpError::BadVersion);
    }
    let (code, reason) = match rest.iter().position(|&b| b == b' ') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &rest[rest.len()..]),
    };
    if code.len() != 3 || !code.iter().all(u8::is_ascii_digit) {
        return Err(HttpError::BadStatusLine);
    }
    let status = code.iter().fold(0u16, |a, &d| a * 10 + u16::from(d - b'0'));
    Ok(Some((Response { status, reason, headers }, n)))
}

/// The standard reason phrase for the statuses a relay answers with.
pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        426 => "Upgrade Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

/// Which extensions a server is willing to run. Offers for anything not listed
/// here are ignored, which the protocol allows (the client then runs without them).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExtensionPolicy {
    /// permessage-deflate (RFC 7692) under this policy, or `None` to decline it.
    pub deflate: Option<DeflatePolicy>,
}

impl ExtensionPolicy {
    /// Declines every extension: what [`Extensions::negotiate`] did before compression existed.
    pub const NONE: ExtensionPolicy = ExtensionPolicy { deflate: None };

    /// Accepts permessage-deflate under `policy`.
    pub fn with_deflate(policy: DeflatePolicy) -> ExtensionPolicy {
        ExtensionPolicy { deflate: Some(policy) }
    }
}

/// Which extensions the server agreed to for this connection: the result of
/// [`negotiate`](Extensions::negotiate), echoed by the 101 response and then used to
/// configure the frame [`Decoder`](crate::ws::Decoder) and the
/// [`Compressor`](crate::ws::Compressor).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Extensions {
    /// The negotiated permessage-deflate parameters, if the extension is on.
    pub deflate: Option<DeflateParams>,
}

impl Extensions {
    /// No extensions.
    pub const NONE: Extensions = Extensions { deflate: None };

    /// Chooses extensions from a handshake request under `policy`. Never fails: an
    /// offer that cannot be accepted just means the connection runs without it.
    pub fn negotiate(req: &Request<'_>, policy: &ExtensionPolicy) -> Extensions {
        let deflate =
            policy.deflate.as_ref().and_then(|p| pmd::negotiate(req.headers.get_all("sec-websocket-extensions"), p));
        Extensions { deflate }
    }
}

/// `base64(SHA-1(key ++ GUID))` (RFC 6455 §4.2.2): the proof the server read the
/// handshake. `key` is the `Sec-WebSocket-Key` header value as received.
pub fn accept_key(key: &[u8]) -> [u8; 28] {
    let mut sha = Sha1::new();
    sha.update(key);
    sha.update(GUID);
    let digest = sha.finalize();
    let mut out = [0u8; 28];
    let n = base64::encode_slice(&digest, &mut out);
    debug_assert_eq!(n, 28);
    out
}

/// Appends the `101 Switching Protocols` response that completes the handshake.
pub fn write_upgrade_response(out: &mut Vec<u8>, accept: &[u8; 28], extensions: &Extensions) {
    out.extend_from_slice(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ",
    );
    out.extend_from_slice(accept);
    out.extend_from_slice(b"\r\n");
    if let Some(deflate) = &extensions.deflate {
        out.extend_from_slice(b"Sec-WebSocket-Extensions: ");
        deflate.write_response_value(out);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
}

fn push_u64(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0u8; 20];
    let mut i = digits.len();
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[i..]);
}

/// Appends a complete HTTP/1.1 response with `Content-Length`.
///
/// `extra_headers` are written verbatim (CORS, `Retry-After`, ...); an entry
/// containing CR, LF or NUL is dropped rather than risk response splitting, so
/// never feed it request-derived text. `close` adds `Connection: close`, which a
/// server that closes after answering should always set.
pub fn write_response(
    out: &mut Vec<u8>,
    status: u16,
    reason: &str,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
    close: bool,
) {
    let clean = |s: &str| !s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    debug_assert!(clean(reason) && clean(content_type));
    out.reserve(160 + body.len());
    out.extend_from_slice(b"HTTP/1.1 ");
    push_u64(out, u64::from(status));
    out.push(b' ');
    out.extend_from_slice(reason.as_bytes());
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(content_type.as_bytes());
    out.extend_from_slice(b"\r\nContent-Length: ");
    push_u64(out, body.len() as u64);
    out.extend_from_slice(b"\r\n");
    if close {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    for (name, value) in extra_headers {
        debug_assert!(clean(name) && clean(value), "header injection: {name}");
        if clean(name) && clean(value) {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
}

/// The client's address, honouring one trusted proxy header.
///
/// With `trusted_header: None` this is the TCP peer. With `Some("x-forwarded-for")`
/// (or `x-real-ip`, ...) the address comes from that header, because behind nginx
/// the peer is always nginx. For a list the **right-most** entry is used: nginx's
/// `$proxy_add_x_forwarded_for` *appends* the address it saw to whatever the client
/// sent, so everything to the left is client-controlled and spoofable, while the
/// last entry is what our own proxy observed. Repeated header lines are one list,
/// so the last line's last entry wins. If the header is absent or its entry does not
/// parse, the peer is returned: never a guess from the spoofable part.
///
/// Only set `trusted_header` when the listener is reachable solely through the
/// proxy; otherwise any client can claim to be anyone.
pub fn client_ip(peer: SocketAddr, req: &Request<'_>, trusted_header: Option<&str>) -> IpAddr {
    let fallback = peer.ip().to_canonical();
    let Some(name) = trusted_header else {
        return fallback;
    };
    let Some(value) = req.headers.get_all(name).last() else {
        return fallback;
    };
    let last = value.rsplit(|&b| b == b',').next().unwrap_or(&[]);
    parse_ip(last).unwrap_or(fallback)
}

/// An address as proxies write it: bare, `ip:port`, or `[v6]` / `[v6]:port`.
fn parse_ip(entry: &[u8]) -> Option<IpAddr> {
    let s = std::str::from_utf8(trim_ows(entry)).ok()?;
    let ip = IpAddr::from_str(s)
        .ok()
        .or_else(|| SocketAddr::from_str(s).ok().map(|a| a.ip()))
        .or_else(|| s.strip_prefix('[')?.strip_suffix(']').and_then(|v| IpAddr::from_str(v).ok()))?;
    Some(ip.to_canonical())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::pmd::DeflatePolicy;

    const FIREFOX: &[u8] = b"GET /nostr HTTP/1.1\r\n\
Host: relay.example.com\r\n\
User-Agent: Mozilla/5.0\r\n\
Accept: */*\r\n\
Sec-WebSocket-Version: 13\r\n\
Origin: https://app.example.com\r\n\
Sec-WebSocket-Extensions: permessage-deflate\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
Connection: keep-alive, Upgrade\r\n\
Upgrade: websocket\r\n\
\r\n";

    fn parse(b: &[u8]) -> (Request<'_>, usize) {
        parse_request(b).unwrap().unwrap()
    }

    #[test]
    fn rfc_accept_key_vector() {
        assert_eq!(&accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="), b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn parses_a_browser_handshake() {
        let (req, n) = parse(FIREFOX);
        assert_eq!(n, FIREFOX.len());
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/nostr");
        assert_eq!(req.version, Version::Http11);
        assert_eq!(req.headers.len(), 9);
        assert_eq!(req.header("host"), Some(&b"relay.example.com"[..]));
        assert_eq!(req.header("HOST"), Some(&b"relay.example.com"[..]));
        assert_eq!(req.header("x-missing"), None);
        assert_eq!(req.websocket_key(), Some(&b"dGhlIHNhbXBsZSBub25jZQ=="[..]));
        assert!(req.wants_upgrade() && req.wants_websocket());
    }

    #[test]
    fn leftover_bytes_after_the_head_are_not_consumed() {
        let mut b = FIREFOX.to_vec();
        b.extend_from_slice(&[0x81, 0x80, 1, 2, 3, 4]);
        let (_, n) = parse(&b);
        assert_eq!(n, FIREFOX.len());
    }

    #[test]
    fn partial_heads_yield_none_until_complete() {
        for cut in 0..FIREFOX.len() {
            assert!(parse_request(&FIREFOX[..cut]).unwrap().is_none(), "cut {cut}");
        }
        assert!(parse_request(FIREFOX).unwrap().is_some());
    }

    #[test]
    fn partial_heads_with_lf_only_endings() {
        let lf = b"GET / HTTP/1.1\nHost: x\nUpgrade: websocket\n\n";
        for cut in 0..lf.len() {
            assert!(parse_request(&lf[..cut]).unwrap().is_none(), "cut {cut}");
        }
        let (req, n) = parse(lf);
        assert_eq!(n, lf.len());
        assert_eq!(req.header("upgrade"), Some(&b"websocket"[..]));
        // Mixed endings too.
        let mixed = b"GET / HTTP/1.1\r\nHost: x\n\r\n";
        assert_eq!(parse(mixed).1, mixed.len());
    }

    #[test]
    fn damaged_heads_never_panic_and_arrive_the_same_way_in_pieces() {
        // Differential property: the outcome for the whole buffer equals the outcome
        // at the first prefix that is conclusive, for random single-byte damage.
        fn summary(
            r: Result<Option<(Request<'_>, usize)>, HttpError>,
        ) -> Result<Option<(String, String, usize, usize)>, HttpError> {
            r.map(|o| o.map(|(q, n)| (q.method.to_owned(), q.path.to_owned(), q.headers.len(), n)))
        }
        let mut x = 0x0bad_cafe_1234_5678u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for iter in 0..3000 {
            let mut data = FIREFOX.to_vec();
            for _ in 0..rnd() % 3 {
                let i = rnd() as usize % data.len();
                data[i] = match rnd() % 6 {
                    0 => b'\r',
                    1 => b'\n',
                    2 => b' ',
                    3 => b':',
                    4 => 0,
                    _ => rnd() as u8,
                };
            }
            let max_head = if iter % 3 == 0 { 200 } else { DEFAULT_MAX_HEAD };
            let whole = summary(parse_request_with(&data, max_head));
            let conclusive = (0..=data.len())
                .map(|k| summary(parse_request_with(&data[..k], max_head)))
                .find(|r| !matches!(r, Ok(None)))
                .unwrap_or(Ok(None));
            assert_eq!(whole, conclusive, "iter {iter}: {:?}", String::from_utf8_lossy(&data));
            if let Ok(Some((.., n))) = whole {
                assert!(n <= data.len());
            }
        }
    }

    #[test]
    fn byte_by_byte_arrival_finds_the_same_head() {
        let mut buf = Vec::new();
        let mut found = None;
        for &b in FIREFOX {
            buf.push(b);
            if let Some((req, n)) = parse_request(&buf).unwrap() {
                found = Some((req.path.to_owned(), n));
                break;
            }
        }
        assert_eq!(found, Some(("/nostr".to_owned(), FIREFOX.len())));
    }

    #[test]
    fn leading_blank_lines_are_skipped() {
        let b = b"\r\n\r\nGET /a HTTP/1.1\r\nHost: x\r\n\r\n";
        let (req, n) = parse(b);
        assert_eq!(req.path, "/a");
        assert_eq!(n, b.len());
        // Only blank lines so far: wait for more.
        assert!(parse_request(b"\r\n\r\n").unwrap().is_none());
    }

    #[test]
    fn oversize_head_is_an_error() {
        // Never terminates.
        let mut b = b"GET / HTTP/1.1\r\n".to_vec();
        b.extend(std::iter::repeat_n(b'a', 100));
        assert_eq!(parse_request_with(&b, 64).err(), Some(HttpError::HeadTooLarge));
        assert!(parse_request_with(&b, 4096).unwrap().is_none());
        // Terminates, but past the cap.
        let mut b = b"GET / HTTP/1.1\r\nX: ".to_vec();
        b.extend(std::iter::repeat_n(b'a', 100));
        b.extend_from_slice(b"\r\n\r\n");
        assert_eq!(parse_request_with(&b, 64).err(), Some(HttpError::HeadTooLarge));
        assert!(parse_request_with(&b, b.len()).unwrap().is_some());
        assert_eq!(parse_request_with(&b, b.len() - 1).err(), Some(HttpError::HeadTooLarge));
        // The default cap is 8 KiB.
        let mut b = b"GET / HTTP/1.1\r\n".to_vec();
        b.extend(std::iter::repeat_n(b'a', DEFAULT_MAX_HEAD));
        assert_eq!(parse_request(&b).err(), Some(HttpError::HeadTooLarge));
        assert_eq!(HttpError::HeadTooLarge.status(), 431);
    }

    #[test]
    fn header_count_limit() {
        let build = |n: usize| {
            let mut b = b"GET / HTTP/1.1\r\n".to_vec();
            for i in 0..n {
                b.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
            }
            b.extend_from_slice(b"\r\n");
            b
        };
        let ok = build(MAX_HEADERS);
        assert_eq!(parse_request(&ok).unwrap().unwrap().0.headers.len(), MAX_HEADERS);
        let too_many = build(MAX_HEADERS + 1);
        assert_eq!(parse_request(&too_many).err(), Some(HttpError::TooManyHeaders));
    }

    #[test]
    fn rejects_malformed_request_lines() {
        for bad in [
            &b"GET /\r\n\r\n"[..],
            b"GET  / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1 x\r\n\r\n",
            b"GET / FTP/1.1\r\n\r\n",
            b" GET / HTTP/1.1\r\n\r\n",
            b"G(T / HTTP/1.1\r\n\r\n",
            b"GET  HTTP/1.1\r\n\r\n",
            b"GET /\x00 HTTP/1.1\r\n\r\n",
            b"GET /\xc3\xa9 HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\rX\r\n\r\n",
        ] {
            assert_eq!(parse_request(bad).err(), Some(HttpError::BadRequestLine), "{:?}", String::from_utf8_lossy(bad));
        }
        assert_eq!(parse_request(b"GET / HTTP/2.0\r\n\r\n").err(), Some(HttpError::BadVersion));
        assert_eq!(HttpError::BadVersion.status(), 505);
    }

    #[test]
    fn rejects_malformed_headers() {
        for bad in [
            &b"GET / HTTP/1.1\r\nHost : x\r\n\r\n"[..], // space before colon
            b"GET / HTTP/1.1\r\n Host: x\r\n\r\n",      // obs-fold / leading space
            b"GET / HTTP/1.1\r\nHost: x\r\n y\r\n\r\n", // folded continuation
            b"GET / HTTP/1.1\r\nHost: x\r\n\ty\r\n\r\n",
            b"GET / HTTP/1.1\r\nNoColon\r\n\r\n",
            b"GET / HTTP/1.1\r\n: x\r\n\r\n",
            b"GET / HTTP/1.1\r\nHo st: x\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\x00y\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: x\ry\r\n\r\n", // bare CR inside a line
            b"GET / HTTP/1.1\r\nHost: x\x7fy\r\n\r\n",
        ] {
            assert_eq!(parse_request(bad).err(), Some(HttpError::BadHeader), "{:?}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn header_values_are_trimmed_and_may_be_empty() {
        let (req, _) = parse(b"GET / HTTP/1.1\r\nA:   spaced \t \r\nB:\r\nC: a: b\r\n\r\n");
        assert_eq!(req.header("a"), Some(&b"spaced"[..]));
        assert_eq!(req.header("b"), Some(&b""[..]));
        assert_eq!(req.header("c"), Some(&b"a: b"[..]));
    }

    #[test]
    fn duplicate_headers_and_tokens() {
        let (req, _) = parse(
            b"GET / HTTP/1.1\r\nConnection: keep-alive\r\nConnection: UPGRADE\r\nAccept: text/html, application/nostr+json;q=0.9\r\n\r\n",
        );
        assert_eq!(req.header("connection"), Some(&b"keep-alive"[..]), "first wins for get");
        assert!(req.headers.has_token("connection", "upgrade"), "any line may carry the token");
        assert!(!req.headers.has_token("connection", "close"));
        assert!(req.accepts("application/nostr+json"));
        assert!(req.accepts("text/html"));
        assert!(!req.accepts("application/json"));
        assert!(!req.accepts("application/nostr"));
    }

    #[test]
    fn tokens_are_whole_words() {
        let (req, _) = parse(b"GET / HTTP/1.1\r\nUpgrade: websocketx\r\nConnection: notupgrade\r\n\r\n");
        assert!(!req.headers.has_token("upgrade", "websocket"));
        assert!(!req.headers.has_token("connection", "upgrade"));
        assert!(req.wants_upgrade());
        assert!(!req.wants_websocket());
    }

    /// A valid upgrade with one piece replaced or removed.
    fn handshake_with(edit: impl Fn(&str) -> String) -> Vec<u8> {
        let base = "GET /nostr HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        edit(base).into_bytes()
    }

    fn key_of(b: &[u8]) -> Option<Vec<u8>> {
        parse(b).0.websocket_key().map(<[u8]>::to_vec)
    }

    #[test]
    fn websocket_key_requires_every_piece() {
        let good = handshake_with(str::to_owned);
        assert_eq!(key_of(&good).as_deref(), Some(&b"dGhlIHNhbXBsZSBub25jZQ=="[..]));

        for (what, edit) in [
            ("method", (|s: &str| s.replacen("GET", "POST", 1)) as fn(&str) -> String),
            ("lowercase method", |s| s.replacen("GET", "get", 1)),
            ("http/1.0", |s| s.replacen("HTTP/1.1", "HTTP/1.0", 1)),
            ("no upgrade", |s| s.replacen("Upgrade: websocket\r\n", "", 1)),
            ("wrong upgrade", |s| s.replacen("Upgrade: websocket", "Upgrade: h2c", 1)),
            ("no connection", |s| s.replacen("Connection: Upgrade\r\n", "", 1)),
            ("wrong connection", |s| s.replacen("Connection: Upgrade", "Connection: close", 1)),
            ("no version", |s| s.replacen("Sec-WebSocket-Version: 13\r\n", "", 1)),
            ("old version", |s| s.replacen("Version: 13", "Version: 8", 1)),
            ("no key", |s| s.replacen("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", "", 1)),
            ("short key", |s| s.replacen("dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZQ==", 1)),
            ("long key", |s| s.replacen("dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25jZQAA", 1)),
            ("not base64", |s| s.replacen("dGhlIHNhbXBsZSBub25jZQ==", "dGhlIHNhbXBsZSBub25jZ!==", 1)),
        ] {
            assert_eq!(key_of(&handshake_with(edit)), None, "{what}");
        }
    }

    #[test]
    fn websocket_key_accepts_case_and_list_variants() {
        let b = handshake_with(|s| {
            s.replacen("Upgrade: websocket", "upgrade: WebSocket", 1).replacen(
                "Connection: Upgrade",
                "CONNECTION: keep-alive,  upgrade ,x",
                1,
            )
        });
        assert!(key_of(&b).is_some());
    }

    #[test]
    fn handshake_with_a_body_is_refused() {
        for extra in
            ["Content-Length: 5\r\n", "Transfer-Encoding: chunked\r\n", "Content-Length: 0\r\nContent-Length: 5\r\n"]
        {
            let b = handshake_with(|s| s.replacen("\r\n\r\n", &format!("\r\n{extra}\r\n"), 1));
            assert_eq!(key_of(&b), None, "{extra:?}");
        }
        let b = handshake_with(|s| s.replacen("\r\n\r\n", "\r\nContent-Length: 0\r\n\r\n", 1));
        assert!(key_of(&b).is_some(), "an explicit zero length is fine");
    }

    #[test]
    fn reason_phrases() {
        assert_eq!(reason_phrase(431), "Request Header Fields Too Large");
        assert_eq!(reason_phrase(426), "Upgrade Required");
        assert_eq!(reason_phrase(799), "Unknown");
    }

    #[test]
    fn duplicate_key_or_version_is_refused() {
        let two_keys =
            handshake_with(|s| s.replacen("\r\n\r\n", "\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", 1));
        assert_eq!(key_of(&two_keys), None);
        let two_versions = handshake_with(|s| s.replacen("\r\n\r\n", "\r\nSec-WebSocket-Version: 13\r\n\r\n", 1));
        assert_eq!(key_of(&two_versions), None);
    }

    #[test]
    fn wants_upgrade_distinguishes_failed_handshakes() {
        let b = handshake_with(|s| s.replacen("Version: 13", "Version: 8", 1));
        let (req, _) = parse(&b);
        assert!(req.wants_upgrade());
        assert_eq!(req.websocket_key(), None);
        let (plain, _) = parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(!plain.wants_upgrade());
    }

    #[test]
    fn upgrade_response_bytes() {
        let mut out = Vec::new();
        let accept = accept_key(b"dGhlIHNhbXBsZSBub25jZQ==");
        write_upgrade_response(&mut out, &accept, &Extensions::NONE);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
        );
    }

    #[test]
    fn upgrade_response_parses_as_a_response() {
        let mut out = Vec::new();
        write_upgrade_response(
            &mut out,
            &accept_key(b"k"),
            &Extensions::negotiate(&parse(FIREFOX).0, &ExtensionPolicy::NONE),
        );
        let (resp, n) = parse_response(&out, 4096).unwrap().unwrap();
        assert_eq!(n, out.len());
        assert_eq!(resp.status, 101);
        assert_eq!(resp.reason, b"Switching Protocols");
        assert!(resp.headers.has_token("upgrade", "websocket"));
        assert_eq!(resp.headers.get("sec-websocket-accept"), Some(&accept_key(b"k")[..]));
        assert!(resp.headers.get("sec-websocket-extensions").is_none(), "no extensions negotiated");
    }

    #[test]
    fn negotiation_follows_the_policy() {
        let (req, _) = parse(FIREFOX);
        // The browser offered permessage-deflate; a server that does not run it ignores the offer.
        assert_eq!(Extensions::negotiate(&req, &ExtensionPolicy::NONE), Extensions::NONE);
        assert_eq!(Extensions::negotiate(&req, &ExtensionPolicy::default()), Extensions::NONE);
        let on = ExtensionPolicy::with_deflate(DeflatePolicy::default());
        let ext = Extensions::negotiate(&req, &on);
        assert!(ext.deflate.is_some());
        // A request that offers nothing gets nothing, whatever the policy.
        let (plain, _) = parse(b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\r\n");
        assert_eq!(Extensions::negotiate(&plain, &on), Extensions::NONE);
    }

    #[test]
    fn upgrade_response_carries_the_negotiated_extension() {
        let mut head = b"GET /nostr HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            .to_vec();
        head.extend_from_slice(b"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n");
        head.extend_from_slice(b"Sec-WebSocket-Extensions: x-other\r\n\r\n");
        let (req, _) = parse(&head);
        assert!(req.websocket_key().is_some());
        let policy = ExtensionPolicy::with_deflate(DeflatePolicy {
            server_no_context_takeover: true,
            max_client_window_bits: 12,
            ..Default::default()
        });
        let ext = Extensions::negotiate(&req, &policy);
        let mut out = Vec::new();
        write_upgrade_response(&mut out, &accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="), &ext);
        assert_eq!(
            String::from_utf8(out.clone()).unwrap(),
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_max_window_bits=12\r\n\r\n"
        );
        let (resp, n) = parse_response(&out, 4096).unwrap().unwrap();
        assert_eq!(n, out.len());
        assert_eq!(resp.status, 101);
        assert!(resp.headers.get("sec-websocket-extensions").is_some());
    }

    #[test]
    fn plain_response_layout() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            200,
            "OK",
            "application/nostr+json",
            &[("Access-Control-Allow-Origin", "*"), ("Cache-Control", "no-store")],
            b"{\"name\":\"x\"}",
            true,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Type: application/nostr+json\r\nContent-Length: 12\r\n\
Connection: close\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-store\r\n\r\n{\"name\":\"x\"}"
        );
        let mut out = Vec::new();
        write_response(&mut out, 404, "Not Found", "text/plain", &[], b"", false);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn response_roundtrips_through_the_parser() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            426,
            "Upgrade Required",
            "text/plain",
            &[("Sec-WebSocket-Version", "13")],
            b"nope",
            true,
        );
        let (resp, n) = parse_response(&out, 4096).unwrap().unwrap();
        assert_eq!(resp.status, 426);
        assert_eq!(resp.headers.get("content-length"), Some(&b"4"[..]));
        assert_eq!(&out[n..], b"nope");
    }

    #[test]
    fn response_parse_errors_and_partials() {
        assert!(parse_response(b"HTTP/1.1 101 Sw", 4096).unwrap().is_none());
        assert_eq!(parse_response(b"HTTP/1.1\r\n\r\n", 4096).err(), Some(HttpError::BadStatusLine));
        assert_eq!(parse_response(b"HTTP/1.1 10 X\r\n\r\n", 4096).err(), Some(HttpError::BadStatusLine));
        assert_eq!(parse_response(b"HTTP/1.1 1x1 X\r\n\r\n", 4096).err(), Some(HttpError::BadStatusLine));
        assert_eq!(parse_response(b"HTTP/2.0 200 OK\r\n\r\n", 4096).err(), Some(HttpError::BadVersion));
        // Reason phrase is optional.
        let (r, _) = parse_response(b"HTTP/1.1 204\r\n\r\n", 4096).unwrap().unwrap();
        assert_eq!((r.status, r.reason), (204, &b""[..]));
    }

    // In debug builds the assertion catches the caller's bug instead, so this
    // checks the release behaviour only.
    #[cfg(not(debug_assertions))]
    #[test]
    fn extra_headers_with_line_breaks_are_dropped() {
        let mut out = Vec::new();
        write_response(
            &mut out,
            200,
            "OK",
            "text/plain",
            &[("X-Evil", "a\r\nSet-Cookie: x=1"), ("X-Good", "1")],
            b"",
            true,
        );
        let s = String::from_utf8(out).unwrap();
        assert!(!s.contains("Set-Cookie") && s.contains("X-Good: 1"));
    }

    // ---- client_ip ----

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ip_with(headers: &str, peer: &str, trusted: Option<&str>) -> IpAddr {
        let raw = format!("GET / HTTP/1.1\r\n{headers}\r\n");
        let (req, _) = parse(raw.as_bytes());
        client_ip(sa(peer), &req, trusted)
    }

    #[test]
    fn client_ip_defaults_to_the_peer() {
        let h = "X-Forwarded-For: 9.9.9.9\r\n";
        assert_eq!(ip_with(h, "10.0.0.1:5000", None), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(ip_with("", "[2001:db8::1]:5000", None), "2001:db8::1".parse::<IpAddr>().unwrap());
        // IPv4-mapped peers (dual-stack sockets) come back as plain IPv4.
        assert_eq!(ip_with("", "[::ffff:10.1.2.3]:5000", None), "10.1.2.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_takes_the_rightmost_forwarded_entry() {
        // The client claimed 1.1.1.1; nginx appended the real 203.0.113.7.
        let h = "X-Forwarded-For: 1.1.1.1, 203.0.113.7\r\n";
        assert_eq!(ip_with(h, "127.0.0.1:1", Some("x-forwarded-for")), "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(ip_with(h, "127.0.0.1:1", Some("X-Forwarded-For")), "203.0.113.7".parse::<IpAddr>().unwrap());
        // Several header lines are one list; the last line's last entry wins.
        let h = "X-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 2.2.2.2, 198.51.100.4\r\n";
        assert_eq!(ip_with(h, "127.0.0.1:1", Some("x-forwarded-for")), "198.51.100.4".parse::<IpAddr>().unwrap());
        // Single value.
        let h = "X-Forwarded-For: 198.51.100.9\r\n";
        assert_eq!(ip_with(h, "127.0.0.1:1", Some("x-forwarded-for")), "198.51.100.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn client_ip_other_headers_and_formats() {
        let t = Some("x-real-ip");
        assert_eq!(ip_with("X-Real-IP: 192.0.2.5\r\n", "127.0.0.1:1", t), "192.0.2.5".parse::<IpAddr>().unwrap());
        assert_eq!(ip_with("X-Real-IP: 2001:db8::7\r\n", "127.0.0.1:1", t), "2001:db8::7".parse::<IpAddr>().unwrap());
        assert_eq!(ip_with("X-Real-IP: 192.0.2.5:4444\r\n", "127.0.0.1:1", t), "192.0.2.5".parse::<IpAddr>().unwrap());
        assert_eq!(
            ip_with("X-Real-IP: [2001:db8::7]:4444\r\n", "127.0.0.1:1", t),
            "2001:db8::7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(ip_with("X-Real-IP: [2001:db8::7]\r\n", "127.0.0.1:1", t), "2001:db8::7".parse::<IpAddr>().unwrap());
        assert_eq!(
            ip_with("X-Real-IP: ::ffff:192.0.2.5\r\n", "127.0.0.1:1", t),
            "192.0.2.5".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn client_ip_falls_back_to_the_peer_on_junk() {
        let peer = "10.9.8.7".parse::<IpAddr>().unwrap();
        let t = Some("x-forwarded-for");
        for h in [
            "",
            "X-Forwarded-For: \r\n",
            "X-Forwarded-For: not-an-ip\r\n",
            "X-Forwarded-For: 1.2.3.4, garbage\r\n", // do not fall back to the spoofable left side
            "X-Forwarded-For: 1.2.3.4,\r\n",
            "X-Forwarded-For: 1.2.3\r\n",
            "X-Forwarded-For: 300.1.1.1\r\n",
        ] {
            assert_eq!(ip_with(h, "10.9.8.7:80", t), peer, "{h:?}");
        }
    }
}
