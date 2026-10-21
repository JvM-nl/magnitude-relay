//! A WebSocket client with nothing between it and the wire: the handshake is
//! written by hand (any headers, any extension offer), frames are built raw
//! (see `wsframe`), and reading is optional, so it can misbehave in every way
//! the relay must survive. Blocking std sockets: each hostile connection is
//! cheap, and timing (a byte at a time, never reading) is easy to control.

use crate::wsframe::Frame;
use relay_net::deflate::Inflater;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub struct Conn {
    pub s: TcpStream,
    buf: Vec<u8>,
    /// The server agreed to permessage-deflate (its messages may be compressed).
    pub deflate: bool,
    inflater: Inflater,
}

/// A message from the relay.
#[derive(Debug)]
pub enum Msg {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<u16>),
}

pub struct Opts<'a> {
    /// The client address the relay should count this connection against
    /// (sent as `X-Real-IP`; the relay under test trusts that header).
    pub ip: Option<&'a str>,
    pub deflate: bool,
    pub timeout: Duration,
}

impl Default for Opts<'_> {
    fn default() -> Self {
        Opts { ip: None, deflate: false, timeout: Duration::from_secs(5) }
    }
}

pub fn handshake_bytes(ip: Option<&str>, deflate: bool) -> Vec<u8> {
    let mut h = String::from("GET / HTTP/1.1\r\nHost: relay\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n");
    if let Some(ip) = ip {
        h.push_str(&format!("X-Real-IP: {ip}\r\n"));
    }
    if deflate {
        h.push_str("Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n");
    }
    h.push_str("\r\n");
    h.into_bytes()
}

impl Conn {
    pub fn connect(addr: SocketAddr, o: &Opts<'_>) -> io::Result<Conn> {
        let s = TcpStream::connect_timeout(&addr, o.timeout)?;
        s.set_nodelay(true)?;
        s.set_read_timeout(Some(o.timeout))?;
        s.set_write_timeout(Some(o.timeout))?;
        let mut c = Conn { s, buf: Vec::new(), deflate: false, inflater: Inflater::new(15, false) };
        c.s.write_all(&handshake_bytes(o.ip, o.deflate))?;
        // Read the response head.
        let deadline = Instant::now() + o.timeout;
        loop {
            if let Some(end) = c.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&c.buf[..end]).to_string();
                c.buf.drain(..end + 4);
                if !head.starts_with("HTTP/1.1 101") {
                    return Err(io::Error::other(format!("handshake refused: {}", head.lines().next().unwrap_or(""))));
                }
                let lower = head.to_ascii_lowercase();
                c.deflate = lower.contains("permessage-deflate");
                if c.deflate {
                    let no_ctx = lower.contains("server_no_context_takeover");
                    c.inflater = Inflater::new(15, !no_ctx);
                }
                return Ok(c);
            }
            if Instant::now() > deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"));
            }
            c.fill()?;
        }
    }

    fn fill(&mut self) -> io::Result<usize> {
        let mut tmp = [0u8; 64 * 1024];
        let n = self.s.read(&mut tmp)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed"));
        }
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    pub fn send_raw(&mut self, b: &[u8]) -> io::Result<()> {
        self.s.write_all(b)
    }

    pub fn send_frame(&mut self, f: &Frame) -> io::Result<()> {
        self.s.write_all(&f.bytes())
    }

    pub fn send_text(&mut self, t: &str) -> io::Result<()> {
        self.send_frame(&Frame::text(t))
    }

    /// The next whole message (control frames included), or an error on
    /// timeout, close or a malformed frame from the server.
    pub fn recv(&mut self) -> io::Result<Msg> {
        let mut assembling: Option<(u8, bool, Vec<u8>)> = None;
        loop {
            while let Some((fin, rsv1, op, payload, used)) = parse_server_frame(&self.buf)? {
                self.buf.drain(..used);
                match op {
                    0x8 => return Ok(Msg::Close(payload.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]])))),
                    0x9 => return Ok(Msg::Ping(payload)),
                    0xA => return Ok(Msg::Pong(payload)),
                    0x0 => {
                        let (op0, comp, mut acc) = assembling.take().ok_or_else(|| io::Error::other("continuation without a message"))?;
                        acc.extend_from_slice(&payload);
                        if fin {
                            return self.finish(op0, comp, acc);
                        }
                        assembling = Some((op0, comp, acc));
                    }
                    0x1 | 0x2 => {
                        if fin {
                            return self.finish(op, rsv1, payload);
                        }
                        assembling = Some((op, rsv1, payload));
                    }
                    other => return Err(io::Error::other(format!("server sent opcode {other}"))),
                }
            }
            self.fill()?;
        }
    }

    fn finish(&mut self, op: u8, compressed: bool, payload: Vec<u8>) -> io::Result<Msg> {
        let data = if compressed {
            let mut out = Vec::new();
            self.inflater.inflate_message(&payload, &mut out, 64 << 20).map_err(|e| io::Error::other(format!("server sent bad deflate: {e}")))?;
            out
        } else {
            payload
        };
        if op == 0x1 {
            String::from_utf8(data).map(Msg::Text).map_err(|_| io::Error::other("server sent invalid UTF-8"))
        } else {
            Ok(Msg::Binary(data))
        }
    }

    /// The next text message, answering pings and skipping pongs.
    pub fn recv_text(&mut self) -> io::Result<String> {
        loop {
            match self.recv()? {
                Msg::Text(t) => return Ok(t),
                Msg::Ping(p) => {
                    let mut f = Frame::new(0xA, &p);
                    f.mask = Some([1, 2, 3, 4]);
                    self.send_frame(&f)?;
                }
                Msg::Close(c) => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("closed by the relay ({c:?})"))),
                _ => {}
            }
        }
    }

    /// Reads until the relay closes the connection or `wait` passes; returns
    /// the close code if a close frame came, `Err` on timeout.
    pub fn wait_closed(&mut self, wait: Duration) -> io::Result<Option<u16>> {
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "still open"));
            }
            self.s.set_read_timeout(Some(left.min(Duration::from_secs(1))))?;
            match self.recv() {
                Ok(Msg::Close(c)) => return Ok(c),
                Ok(_) => {}
                Err(e) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe) => return Ok(None),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// One server frame from the front of `b`: (fin, rsv1, opcode, payload, bytes used).
#[allow(clippy::type_complexity)]
fn parse_server_frame(b: &[u8]) -> io::Result<Option<(bool, bool, u8, Vec<u8>, usize)>> {
    if b.len() < 2 {
        return Ok(None);
    }
    let fin = b[0] & 0x80 != 0;
    let rsv1 = b[0] & 0x40 != 0;
    let op = b[0] & 0x0F;
    if b[1] & 0x80 != 0 {
        return Err(io::Error::other("server frame is masked"));
    }
    let (len, h) = match b[1] & 0x7F {
        126 if b.len() >= 4 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
        127 if b.len() >= 10 => (u64::from_be_bytes(b[2..10].try_into().unwrap()) as usize, 10),
        126 | 127 => return Ok(None),
        n => (n as usize, 2),
    };
    if b.len() < h + len {
        return Ok(None);
    }
    Ok(Some((fin, rsv1, op, b[h..h + len].to_vec(), h + len)))
}

/// Makes closing `s` send a reset instead of a FIN (SO_LINGER 0): a client
/// that vanishes mid-frame.
pub fn reset_on_close(s: &TcpStream) {
    use std::os::fd::AsRawFd;
    let l = libc::linger { l_onoff: 1, l_linger: 0 };
    // SAFETY: setting a socket option on a descriptor we own, with a valid struct.
    unsafe {
        libc::setsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_LINGER, (&l as *const libc::linger).cast(), std::mem::size_of::<libc::linger>() as libc::socklen_t);
    }
}

/// A bare TCP connection (for attacks below the WebSocket layer).
pub fn tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    s.set_nodelay(true)?;
    Ok(s)
}
