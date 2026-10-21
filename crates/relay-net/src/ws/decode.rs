//! Incremental frame decoder with in-place unmasking.
//!
//! The decoder owns no input buffer. The connection keeps one `Vec<u8>` per
//! socket, reads into it, and calls [`Decoder::decode`] on the unconsumed part:
//!
//! ```
//! # use relay_net::ws::{Decoder, Event, WsError};
//! # fn handle(_: Event<'_>) {}
//! # fn on_readable(dec: &mut Decoder, buf: &mut Vec<u8>) -> Result<(), WsError> {
//! let mut off = 0;
//! loop {
//!     let d = dec.decode(&mut buf[off..])?;
//!     off += d.consumed;
//!     match d.event {
//!         Some(ev) => handle(ev),
//!         None => break, // every complete frame is consumed; read more
//!     }
//! }
//! buf.drain(..off);
//! # Ok(())
//! # }
//! ```
//!
//! **Why whole frames.** A frame is parsed only once all of it is buffered; until
//! then nothing is consumed and nothing is unmasked, so the header is simply
//! re-parsed on the next call (at most 14 bytes). That keeps the decoder free of
//! partial-frame state and lets the common case (one unfragmented frame, fully
//! buffered) return a slice straight into the caller's buffer after one in-place
//! unmask: zero copies. The cost is that the buffer must be able to hold a whole
//! frame, which `max_frame` bounds, and which [`Decoder::needed`] reports so the
//! caller can size its reads. An oversized length is rejected as soon as the header
//! is complete, before any payload arrives, so a hostile length costs nothing.
//!
//! **Fragmented messages** are the only thing copied: each fragment is appended to
//! one reusable reassembly buffer and the finished message is returned from it.
//! Control frames may arrive between fragments and are returned immediately.
//!
//! **permessage-deflate.** After [`Decoder::enable_deflate`], RSV1 on the first frame of
//! a data message means its payload (reassembled first, if fragmented) is a compressed
//! message; the decoder inflates it and returns the plain text or bytes, with UTF-8
//! checked on the *decompressed* text. RSV1 on a control frame, on a continuation, or
//! with the extension off is a protocol error. The size limit applies to the decompressed
//! message (a bomb is cut off at `max_message`, close code 1009), and the compressed form
//! gets a little headroom over it, because incompressible data genuinely grows by a few
//! bytes. A message that fails to inflate is close code 1007, as in the `ws` library.

use super::pmd::{DeflateParams, StreamConfig};
use super::unmask::unmask;
use super::{is_valid_close_code, Opcode, WsError};
use crate::deflate::{InflateError, Inflater};

const CONT: u8 = Opcode::Continuation as u8;
const TEXT: u8 = Opcode::Text as u8;
const BINARY: u8 = Opcode::Binary as u8;
const CLOSE: u8 = Opcode::Close as u8;
const PING: u8 = Opcode::Ping as u8;
const PONG: u8 = Opcode::Pong as u8;

/// A reassembly buffer that grew past this is dropped when the next fragmented
/// message starts, so one huge message does not pin its memory for the life of
/// the connection.
const RETAIN_CAP: usize = 256 * 1024;

/// The same for the buffer decompressed messages are written to.
const OUT_RETAIN_CAP: usize = 64 * 1024;

/// Which end of the connection the decoder reads for. Clients must mask their
/// frames and servers must not (RFC 6455 §5.1); each side rejects the other
/// convention as a protocol error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Decodes frames from a client: masked, unmasked in place.
    Server,
    /// Decodes frames from a server: unmasked.
    Client,
}

/// One complete message or control frame. Payloads borrow from the buffer passed
/// to [`Decoder::decode`] (or the decoder's reassembly buffer) and are valid until
/// the next call.
#[derive(Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// A complete text message, UTF-8 validated.
    Text(&'a str),
    Binary(&'a [u8]),
    /// The caller should answer with a pong carrying the same payload.
    Ping(&'a [u8]),
    Pong(&'a [u8]),
    /// The peer's close frame: validated status code and reason, or `None` for an
    /// empty close. The caller should echo a close and drop the connection.
    Close(Option<(u16, &'a str)>),
}

/// Result of one [`Decoder::decode`] call.
#[derive(Debug, PartialEq, Eq)]
pub struct Decoded<'a> {
    /// Bytes at the front of the input that are finished with: the frames behind
    /// `event`, plus any fragments of a message still being assembled.
    pub consumed: usize,
    /// The next event, or `None` when the input holds no further complete frame.
    pub event: Option<Event<'a>>,
}

pub struct Decoder {
    role: Role,
    max_frame: usize,
    max_message: usize,
    /// Reassembly buffer for fragmented messages; reused across messages.
    msg: Vec<u8>,
    /// Opcode of the fragmented message in progress, or 0 when none.
    msg_op: u8,
    /// Bytes the input must hold, counted from the first unconsumed byte, before
    /// the next call can make progress.
    need: usize,
    /// A close frame was delivered; everything after it is discarded.
    closed: bool,
    failed: Option<WsError>,
    /// Present once permessage-deflate is enabled: the history of the peer's stream.
    deflate: Option<Inflater>,
    /// The fragmented message in progress had RSV1 on its first frame.
    msg_compressed: bool,
    /// Where a compressed message is inflated to; reused.
    out: Vec<u8>,
}

struct Head {
    fin: bool,
    /// RSV1 on a data frame that starts a message: the message is compressed.
    compressed: bool,
    op: u8,
    mask: Option<[u8; 4]>,
    head_len: usize,
    len: usize,
}

enum Parsed {
    /// The header is incomplete; the frame needs at least this many bytes.
    Need(usize),
    Head(Head),
}

/// What one `decode` call decided, as indices only. The event itself is built once
/// at the end: borrowing the caller's buffer inside the frame loop would keep it
/// borrowed across iterations.
enum Plan {
    Stall,
    Data { op: u8, start: usize, end: usize, compressed: bool },
    Assembled { op: u8, compressed: bool },
    Control { op: u8, start: usize, end: usize },
}

impl Decoder {
    /// `max_frame` bounds one frame's payload and `max_message` a whole
    /// (reassembled) message; both are enforced at header time, before the payload
    /// is buffered. `max_frame` is raised to 125 so control frames always fit, and
    /// capped at half the address space so `header + payload` cannot overflow.
    pub fn new(role: Role, max_frame: usize, max_message: usize) -> Self {
        Decoder {
            role,
            max_frame: max_frame.clamp(125, usize::MAX >> 1),
            max_message,
            msg: Vec::new(),
            msg_op: 0,
            need: 2,
            closed: false,
            failed: None,
            deflate: None,
            msg_compressed: false,
            out: Vec::new(),
        }
    }

    /// Accepts permessage-deflate messages from the peer, with this configuration for
    /// the *peer's* sending stream (its context takeover and window). Call it once,
    /// right after the handshake that negotiated the extension.
    pub fn enable_deflate(&mut self, peer_stream: StreamConfig) {
        self.deflate = Some(Inflater::new(peer_stream.window_bits, peer_stream.context_takeover));
    }

    /// Builder form of [`enable_deflate`](Self::enable_deflate) taking negotiated parameters:
    /// this decoder reads the stream its own role *receives*.
    pub fn with_deflate(mut self, params: &DeflateParams) -> Self {
        let cfg = params.receive(self.role);
        self.enable_deflate(cfg);
        self
    }

    /// Whether RSV1 is currently legal.
    #[inline]
    pub fn deflate_enabled(&self) -> bool {
        self.deflate.is_some()
    }

    /// Heap this decoder holds between calls: reassembly and inflate buffers and the
    /// peer's compression history. For memory accounting.
    pub fn heap_bytes(&self) -> usize {
        self.msg.capacity() + self.out.capacity() + self.deflate.as_ref().map_or(0, Inflater::heap_bytes)
    }

    /// Drops the message buffers' memory (not the compression history, which the
    /// peer's next message may need). For a connection that has gone idle.
    pub fn trim(&mut self) {
        if self.msg_op == 0 {
            self.msg = Vec::new();
        }
        self.out = Vec::new();
    }

    pub fn server(max_frame: usize, max_message: usize) -> Self {
        Self::new(Role::Server, max_frame, max_message)
    }

    pub fn client(max_frame: usize, max_message: usize) -> Self {
        Self::new(Role::Client, max_frame, max_message)
    }

    /// After a call that returned no event: the number of bytes the input, counted
    /// from its first unconsumed byte, must hold before another call can make
    /// progress. A header-only estimate (2) until the length is known, then the
    /// whole frame. Callers use it to reserve buffer space and to avoid waking up
    /// for every few bytes of a large frame.
    #[inline]
    pub fn needed(&self) -> usize {
        self.need
    }

    /// Whether a fragmented message is partway through reassembly.
    #[inline]
    pub fn in_message(&self) -> bool {
        self.msg_op != 0
    }

    /// Decodes as much of `buf` as it can, unmasking frames in place.
    ///
    /// Returns the first event found plus how many bytes to drop from the front
    /// of the buffer. Call again on `buf[consumed..]` until `event` is `None`.
    /// After `Ok` with no event, a partial frame may remain unconsumed; keep it
    /// and append the next read behind it. After an `Err` the connection must be
    /// failed (send the error's close code, then drop it); the decoder keeps
    /// returning the same error. After a `Close` event all further input is
    /// discarded.
    pub fn decode<'a>(&'a mut self, buf: &'a mut [u8]) -> Result<Decoded<'a>, WsError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if self.closed {
            return Ok(Decoded { consumed: buf.len(), event: None });
        }
        // The previous event, which may have borrowed `out`, is gone by now: a big
        // decompressed message must not stay allocated until the next compressed one.
        if self.out.capacity() > OUT_RETAIN_CAP {
            self.out = Vec::new();
        }

        let mut off = 0usize;
        let plan = loop {
            let rest = &buf[off..];
            let head = match self.parse_head(rest) {
                Ok(Parsed::Head(h)) => h,
                Ok(Parsed::Need(n)) => {
                    self.need = n;
                    break Plan::Stall;
                }
                Err(e) => {
                    self.failed = Some(e);
                    return Err(e);
                }
            };
            let total = head.head_len + head.len;
            if rest.len() < total {
                self.need = total;
                break Plan::Stall;
            }
            let start = off + head.head_len;
            let end = off + total;
            if let Some(mask) = head.mask {
                unmask(&mut buf[start..end], mask, 0);
            }
            off = end;

            match head.op {
                CONT => {
                    // parse_head checked a message is in progress and the size cap.
                    self.msg.extend_from_slice(&buf[start..end]);
                    if head.fin {
                        let op = self.msg_op;
                        self.msg_op = 0;
                        let compressed = std::mem::take(&mut self.msg_compressed);
                        break Plan::Assembled { op, compressed };
                    }
                }
                TEXT | BINARY => {
                    if head.fin {
                        break Plan::Data { op: head.op, start, end, compressed: head.compressed };
                    }
                    self.begin_message(head.op, head.compressed);
                    self.msg.extend_from_slice(&buf[start..end]);
                }
                op => break Plan::Control { op, start, end },
            }
        };

        // Phase two: build the one event, borrowing the buffer a single time. Only
        // plain field assignments below, so borrowing `self.msg` does not conflict
        // with recording a failure.
        let buf: &'a [u8] = buf;
        let consumed = off;
        let built: Result<Option<Event<'a>>, WsError> = match plan {
            Plan::Stall => Ok(None),
            Plan::Data { op, start, end, compressed } => {
                let p = &buf[start..end];
                if compressed {
                    inflate_message(&mut self.deflate, &mut self.out, self.max_message, p)
                        .and_then(|()| data_event(op, &self.out))
                } else {
                    data_event(op, p)
                }
            }
            Plan::Assembled { op, compressed } => {
                if compressed {
                    inflate_message(&mut self.deflate, &mut self.out, self.max_message, &self.msg)
                        .and_then(|()| data_event(op, &self.out))
                } else {
                    data_event(op, &self.msg)
                }
            }
            Plan::Control { op, start, end } => {
                let p = &buf[start..end];
                match op {
                    PING => Ok(Some(Event::Ping(p))),
                    PONG => Ok(Some(Event::Pong(p))),
                    CLOSE => {
                        self.closed = true;
                        parse_close(p).map(|c| Some(Event::Close(c)))
                    }
                    // parse_head admits only the six defined opcodes.
                    _ => Err(WsError::Protocol("reserved opcode")),
                }
            }
        };
        match built {
            Ok(event) => Ok(Decoded { consumed, event }),
            Err(e) => {
                self.failed = Some(e);
                Err(e)
            }
        }
    }

    fn begin_message(&mut self, op: u8, compressed: bool) {
        if self.msg.capacity() > RETAIN_CAP {
            self.msg = Vec::new();
        } else {
            self.msg.clear();
        }
        self.msg_op = op;
        self.msg_compressed = compressed;
    }

    /// Parses and validates the frame header at the start of `b`, as far as `b`
    /// goes. Every check that does not need the payload happens here so a bad
    /// frame fails on its first bytes.
    #[inline]
    fn parse_head(&self, b: &[u8]) -> Result<Parsed, WsError> {
        if b.len() < 2 {
            return Ok(Parsed::Need(2));
        }
        let (b0, b1) = (b[0], b[1]);
        let rsv1 = b0 & 0x40 != 0;
        // RSV2 and RSV3 have no meaning here, and RSV1 only with permessage-deflate.
        if b0 & 0x30 != 0 || (rsv1 && self.deflate.is_none()) {
            return Err(WsError::Protocol("reserved bits set"));
        }
        let fin = b0 & 0x80 != 0;
        let op = b0 & 0x0F;
        if !matches!(op, CONT | TEXT | BINARY | CLOSE | PING | PONG) {
            return Err(WsError::Protocol("reserved opcode"));
        }
        if rsv1 {
            // RFC 7692 section 6: only the first frame of a data message carries it.
            if op & 0x8 != 0 {
                return Err(WsError::Protocol("compressed control frame"));
            }
            if op == CONT {
                return Err(WsError::Protocol("compressed continuation frame"));
            }
        }
        // Whether the frame belongs to a compressed message decides its size allowance.
        let compressed_msg = if op == CONT { self.msg_compressed } else { rsv1 };
        let (max_frame, max_message) = if compressed_msg {
            let slack = self.max_message / 64 + 64;
            (self.max_frame.saturating_add(slack), self.max_message.saturating_add(slack))
        } else {
            (self.max_frame, self.max_message)
        };
        let masked = b1 & 0x80 != 0;
        match (self.role, masked) {
            (Role::Server, false) => return Err(WsError::Protocol("client frame not masked")),
            (Role::Client, true) => return Err(WsError::Protocol("server frame masked")),
            _ => {}
        }
        let l7 = usize::from(b1 & 0x7F);
        if op & 0x8 != 0 {
            if !fin {
                return Err(WsError::Protocol("fragmented control frame"));
            }
            if l7 > 125 {
                return Err(WsError::Protocol("control frame too long"));
            }
        }

        let ext = match l7 {
            126 => 2,
            127 => 8,
            _ => 0,
        };
        let head_len = 2 + ext + if masked { 4 } else { 0 };
        if b.len() < head_len {
            return Ok(Parsed::Need(head_len));
        }
        // Non-minimal length encodings are accepted (the RFC forbids sending
        // them, but they are unambiguous); a set top bit is not.
        let len64 = match l7 {
            126 => u64::from(u16::from_be_bytes([b[2], b[3]])),
            127 => {
                let v = u64::from_be_bytes([b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]]);
                if v >> 63 != 0 {
                    return Err(WsError::Protocol("payload length has top bit set"));
                }
                v
            }
            n => n as u64,
        };
        if len64 > max_frame as u64 {
            return Err(WsError::TooBig("frame too big"));
        }

        match op {
            CONT => {
                if self.msg_op == 0 {
                    return Err(WsError::Protocol("continuation without a message"));
                }
                if self.msg.len() as u64 + len64 > max_message as u64 {
                    return Err(WsError::TooBig("message too big"));
                }
            }
            TEXT | BINARY => {
                if self.msg_op != 0 {
                    return Err(WsError::Protocol("data frame inside a fragmented message"));
                }
                if len64 > max_message as u64 {
                    return Err(WsError::TooBig("message too big"));
                }
            }
            _ => {}
        }

        let mask = masked.then(|| [b[head_len - 4], b[head_len - 3], b[head_len - 2], b[head_len - 1]]);
        Ok(Parsed::Head(Head { fin, compressed: rsv1, op, mask, head_len, len: len64 as usize }))
    }
}

#[inline]
fn text(p: &[u8]) -> Result<&str, WsError> {
    std::str::from_utf8(p).map_err(|_| WsError::InvalidPayload("invalid UTF-8 in text message"))
}

/// The event for a complete data message.
#[inline]
fn data_event(op: u8, p: &[u8]) -> Result<Option<Event<'_>>, WsError> {
    if op == TEXT {
        text(p).map(|s| Some(Event::Text(s)))
    } else {
        Ok(Some(Event::Binary(p)))
    }
}

/// Inflates one compressed message into `out` (cleared first, or replaced if an earlier
/// message left it oversized), refusing to produce more than `max_message` bytes.
fn inflate_message(
    deflate: &mut Option<Inflater>,
    out: &mut Vec<u8>,
    max_message: usize,
    compressed: &[u8],
) -> Result<(), WsError> {
    let Some(inflater) = deflate.as_mut() else {
        return Err(WsError::Protocol("reserved bits set"));
    };
    if out.capacity() > OUT_RETAIN_CAP {
        *out = Vec::new();
    } else {
        out.clear();
    }
    match inflater.inflate_message(compressed, out, max_message) {
        Ok(_) => Ok(()),
        Err(InflateError::LimitExceeded) => Err(WsError::TooBig("message too big")),
        Err(_) => Err(WsError::InvalidPayload("invalid compressed data")),
    }
}

/// Validates a close payload: empty, or a valid status code and a UTF-8 reason. A
/// one-byte payload cannot hold a code and is a protocol error.
fn parse_close(p: &[u8]) -> Result<Option<(u16, &str)>, WsError> {
    match p {
        [] => Ok(None),
        [_] => Err(WsError::Protocol("close frame with a 1-byte payload")),
        [a, b, reason @ ..] => {
            let code = u16::from_be_bytes([*a, *b]);
            if !is_valid_close_code(code) {
                return Err(WsError::Protocol("invalid close code"));
            }
            let reason =
                std::str::from_utf8(reason).map_err(|_| WsError::InvalidPayload("invalid UTF-8 in close reason"))?;
            Ok(Some((code, reason)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{run, run_whole, Ev};
    use super::super::{
        write_binary, write_close, write_frame, write_ping, write_pong, write_text, ClientEncoder, Opcode,
    };
    use super::*;

    fn server() -> Decoder {
        Decoder::server(1 << 20, 1 << 20)
    }

    fn client() -> Decoder {
        Decoder::client(1 << 20, 1 << 20)
    }

    /// Masks `payload` by hand with `mask` and prefixes the 2-byte header.
    fn masked(first: u8, mask: [u8; 4], payload: &[u8]) -> Vec<u8> {
        assert!(payload.len() < 126);
        let mut v = vec![first, 0x80 | payload.len() as u8];
        v.extend_from_slice(&mask);
        v.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        v
    }

    const M: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

    // ---- RFC 6455 section 5.7 examples ----

    #[test]
    fn rfc_unmasked_hello_is_valid_only_from_a_server() {
        let frame = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        assert_eq!(run_whole(&mut client(), &frame).unwrap(), vec![Ev::Text("Hello".into())]);
        assert_eq!(run_whole(&mut server(), &frame), Err(WsError::Protocol("client frame not masked")));
    }

    #[test]
    fn rfc_masked_hello_is_valid_only_from_a_client() {
        let frame = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
        assert_eq!(run_whole(&mut server(), &frame).unwrap(), vec![Ev::Text("Hello".into())]);
        assert_eq!(run_whole(&mut client(), &frame), Err(WsError::Protocol("server frame masked")));
    }

    #[test]
    fn rfc_fragmented_hello() {
        // 0x01 0x03 "Hel" (FIN=0, text), 0x80 0x02 "lo" (FIN=1, continuation)
        let frames = [0x01, 0x03, 0x48, 0x65, 0x6c, 0x80, 0x02, 0x6c, 0x6f];
        assert_eq!(run_whole(&mut client(), &frames).unwrap(), vec![Ev::Text("Hello".into())]);

        let mut f = masked(0x01, M, b"Hel");
        f.extend(masked(0x80, [1, 2, 3, 4], b"lo"));
        assert_eq!(run_whole(&mut server(), &f).unwrap(), vec![Ev::Text("Hello".into())]);
    }

    #[test]
    fn rfc_ping_and_pong() {
        let ping = [0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        assert_eq!(run_whole(&mut client(), &ping).unwrap(), vec![Ev::Ping(b"Hello".to_vec())]);
        let mping = [0x89, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
        assert_eq!(run_whole(&mut server(), &mping).unwrap(), vec![Ev::Ping(b"Hello".to_vec())]);
        let mpong = [0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
        assert_eq!(run_whole(&mut server(), &mpong).unwrap(), vec![Ev::Pong(b"Hello".to_vec())]);
        let pong = [0x8a, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
        assert_eq!(run_whole(&mut client(), &pong).unwrap(), vec![Ev::Pong(b"Hello".to_vec())]);
    }

    #[test]
    fn rfc_256_byte_binary_uses_16_bit_length() {
        let p: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let mut f = vec![0x82, 0x7E, 0x01, 0x00];
        f.extend_from_slice(&p);
        assert_eq!(run_whole(&mut client(), &f).unwrap(), vec![Ev::Binary(p.clone())]);

        let mut f = vec![0x82, 0xFE, 0x01, 0x00, 9, 8, 7, 6];
        f.extend(p.iter().enumerate().map(|(i, b)| b ^ [9, 8, 7, 6][i % 4]));
        assert_eq!(run_whole(&mut server(), &f).unwrap(), vec![Ev::Binary(p)]);
    }

    #[test]
    fn rfc_64kib_binary_uses_64_bit_length() {
        let p: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let mut f = vec![0x82, 0x7F, 0, 0, 0, 0, 0, 1, 0, 0];
        f.extend_from_slice(&p);
        assert_eq!(run_whole(&mut client(), &f).unwrap(), vec![Ev::Binary(p)]);
    }

    #[test]
    fn non_minimal_length_is_accepted() {
        // 5 bytes sent with a 64-bit length field: illegal to send, harmless to read.
        let mut f = vec![0x82, 0x7F, 0, 0, 0, 0, 0, 0, 0, 5];
        f.extend_from_slice(b"hello");
        assert_eq!(run_whole(&mut client(), &f).unwrap(), vec![Ev::Binary(b"hello".to_vec())]);
        let mut f = vec![0x82, 0x7E, 0, 5];
        f.extend_from_slice(b"hello");
        assert_eq!(run_whole(&mut client(), &f).unwrap(), vec![Ev::Binary(b"hello".to_vec())]);
    }

    // ---- header errors ----

    #[test]
    fn length_top_bit_is_a_protocol_error() {
        let f = [0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(run_whole(&mut client(), &f), Err(WsError::Protocol("payload length has top bit set")));
    }

    #[test]
    fn reserved_bits_are_errors() {
        for rsv in [0x40, 0x20, 0x10, 0x70] {
            let f = [0x81 | rsv, 0x00];
            assert_eq!(run_whole(&mut client(), &f), Err(WsError::Protocol("reserved bits set")), "{rsv:#x}");
        }
    }

    #[test]
    fn reserved_opcodes_are_errors() {
        for op in [3u8, 4, 5, 6, 7, 11, 12, 13, 14, 15] {
            let f = [0x80 | op, 0x00];
            assert_eq!(run_whole(&mut client(), &f), Err(WsError::Protocol("reserved opcode")), "{op}");
        }
    }

    #[test]
    fn control_frame_rules() {
        // Fragmented control frame.
        assert_eq!(run_whole(&mut client(), &[0x09, 0x00]), Err(WsError::Protocol("fragmented control frame")));
        // 126-byte control payload (needs the 16-bit length form).
        let mut f = vec![0x89, 126, 0, 126];
        f.extend(std::iter::repeat_n(0u8, 126));
        assert_eq!(run_whole(&mut client(), &f), Err(WsError::Protocol("control frame too long")));
        // 125 is the maximum and fine.
        let mut f = vec![0x89, 125];
        f.extend(std::iter::repeat_n(7u8, 125));
        assert_eq!(run_whole(&mut client(), &f).unwrap(), vec![Ev::Ping(vec![7; 125])]);
    }

    #[test]
    fn errors_fire_before_the_payload_arrives() {
        // Reserved opcode with a huge declared length: rejected on two bytes.
        let mut d = client();
        assert_eq!(run_whole(&mut d, &[0x83, 0x7F]), Err(WsError::Protocol("reserved opcode")));
        // Oversize frame: rejected as soon as the header is complete.
        let mut d = Decoder::client(1000, 1 << 20);
        let hdr = [0x82, 0x7E, 0x04, 0x00]; // 1024 > 1000
        assert_eq!(run_whole(&mut d, &hdr), Err(WsError::TooBig("frame too big")));
    }

    #[test]
    fn needed_tracks_the_partial_frame() {
        let mut d = client();
        let mut buf = vec![0x82];
        assert_eq!(d.decode(&mut buf).unwrap().consumed, 0);
        assert_eq!(d.needed(), 2);
        let mut buf = vec![0x82, 0x7E, 0x01];
        d.decode(&mut buf).unwrap();
        assert_eq!(d.needed(), 4);
        let mut buf = vec![0x82, 0x7E, 0x01, 0x00, 1, 2, 3];
        d.decode(&mut buf).unwrap();
        assert_eq!(d.needed(), 4 + 256);
    }

    // ---- fragmentation ----

    #[test]
    fn control_frame_between_fragments() {
        let mut f = masked(0x01, M, b"Hel");
        f.extend(masked(0x89, M, b"ping"));
        f.extend(masked(0x00, M, b"l"));
        f.extend(masked(0x8A, M, b"pong"));
        f.extend(masked(0x80, M, b"o"));
        let evs = run_whole(&mut server(), &f).unwrap();
        assert_eq!(evs, vec![Ev::Ping(b"ping".to_vec()), Ev::Pong(b"pong".to_vec()), Ev::Text("Hello".into())]);
    }

    #[test]
    fn many_small_fragments() {
        let mut f = masked(0x02, M, b"a");
        for _ in 0..98 {
            f.extend(masked(0x00, M, b"b"));
        }
        f.extend(masked(0x80, M, b"c"));
        let mut want = b"a".to_vec();
        want.extend(std::iter::repeat_n(b'b', 98));
        want.push(b'c');
        assert_eq!(run_whole(&mut server(), &f).unwrap(), vec![Ev::Binary(want)]);
    }

    #[test]
    fn empty_fragments_are_fine() {
        let mut f = masked(0x01, M, b"");
        f.extend(masked(0x00, M, b""));
        f.extend(masked(0x80, M, b"x"));
        assert_eq!(run_whole(&mut server(), &f).unwrap(), vec![Ev::Text("x".into())]);
    }

    #[test]
    fn continuation_without_message_is_an_error() {
        let f = masked(0x80, M, b"x");
        assert_eq!(run_whole(&mut server(), &f), Err(WsError::Protocol("continuation without a message")));
        // Also after a finished message.
        let mut f = masked(0x81, M, b"x");
        f.extend(masked(0x80, M, b"y"));
        assert!(run_whole(&mut server(), &f).is_err());
    }

    #[test]
    fn new_data_frame_mid_message_is_an_error() {
        for second in [0x01, 0x81, 0x02, 0x82] {
            let mut f = masked(0x01, M, b"a");
            f.extend(masked(second, M, b"b"));
            assert_eq!(
                run_whole(&mut server(), &f),
                Err(WsError::Protocol("data frame inside a fragmented message")),
                "{second:#x}"
            );
        }
    }

    #[test]
    fn message_after_message_reuses_the_decoder() {
        let mut f = masked(0x01, M, b"ab");
        f.extend(masked(0x80, M, b"cd"));
        f.extend(masked(0x81, M, b"single"));
        f.extend(masked(0x02, M, b"x"));
        f.extend(masked(0x80, M, b"yz"));
        assert_eq!(
            run_whole(&mut server(), &f).unwrap(),
            vec![Ev::Text("abcd".into()), Ev::Text("single".into()), Ev::Binary(b"xyz".to_vec())]
        );
    }

    // ---- limits ----

    #[test]
    fn oversize_single_frame_is_1009() {
        let mut f = Vec::new();
        ClientEncoder::with_seed(1).write_binary(&mut f, &[0u8; 126]);
        let mut d = Decoder::server(200, 200);
        assert!(run_whole(&mut d, &f).is_ok());
        let mut d = Decoder::server(125, 200);
        let e = run_whole(&mut d, &f).unwrap_err();
        assert_eq!(e, WsError::TooBig("frame too big"));
        assert_eq!(e.close_code(), 1009);
        // A frame within max_frame can still exceed max_message.
        let mut d = Decoder::server(1000, 100);
        let e = run_whole(&mut d, &f).unwrap_err();
        assert_eq!(e, WsError::TooBig("message too big"));
    }

    #[test]
    fn max_frame_is_raised_to_fit_control_frames() {
        let mut d = Decoder::server(10, 10);
        let f = masked(0x89, M, &[1u8; 125]);
        assert_eq!(run_whole(&mut d, &f).unwrap(), vec![Ev::Ping(vec![1; 125])]);
    }

    #[test]
    fn oversize_message_across_fragments_is_1009() {
        // Each frame is within max_frame, the sum is not.
        let mut d = Decoder::server(64, 100);
        let mut f = masked(0x02, M, &[1u8; 60]);
        f.extend(masked(0x00, M, &[2u8; 40]));
        assert_eq!(run_whole(&mut d, &f).unwrap().len(), 0, "100 bytes is exactly at the limit");
        let mut d = Decoder::server(64, 100);
        let mut f = masked(0x02, M, &[1u8; 60]);
        f.extend(masked(0x00, M, &[2u8; 41]));
        assert_eq!(run_whole(&mut d, &f), Err(WsError::TooBig("message too big")));
    }

    #[test]
    fn frame_exactly_at_the_limit_is_accepted() {
        let mut d = Decoder::server(125, 125);
        let f = masked(0x82, M, &[9u8; 125]);
        assert_eq!(run_whole(&mut d, &f).unwrap(), vec![Ev::Binary(vec![9; 125])]);
    }

    #[test]
    fn errors_are_sticky() {
        let mut d = server();
        let bad = [0x81, 0x00]; // unmasked
        assert!(run_whole(&mut d, &bad).is_err());
        let good = masked(0x81, M, b"x");
        assert_eq!(run_whole(&mut d, &good), Err(WsError::Protocol("client frame not masked")));
    }

    // ---- UTF-8 ----

    #[test]
    fn invalid_utf8_text_is_1007() {
        let f = masked(0x81, M, &[0xff, 0xfe]);
        let e = run_whole(&mut server(), &f).unwrap_err();
        assert_eq!(e.close_code(), 1007);
        // Binary frames are never validated.
        let f = masked(0x82, M, &[0xff, 0xfe]);
        assert_eq!(run_whole(&mut server(), &f).unwrap(), vec![Ev::Binary(vec![0xff, 0xfe])]);
    }

    #[test]
    fn invalid_utf8_in_fragmented_text_is_1007() {
        let mut f = masked(0x01, M, b"ok");
        f.extend(masked(0x80, M, &[0xc0, 0x80])); // overlong encoding
        assert_eq!(run_whole(&mut server(), &f).unwrap_err().close_code(), 1007);
    }

    #[test]
    fn utf8_sequence_split_across_fragments_is_accepted() {
        // U+20AC (euro sign) is E2 82 AC; cut it after each byte.
        let euro = "\u{20ac}".as_bytes();
        assert_eq!(euro, [0xe2, 0x82, 0xac]);
        for cut in 1..3 {
            let mut f = masked(0x01, M, &euro[..cut]);
            f.extend(masked(0x80, M, &euro[cut..]));
            assert_eq!(run_whole(&mut server(), &f).unwrap(), vec![Ev::Text("\u{20ac}".into())], "cut {cut}");
        }
        // Four-byte sequence split across three fragments.
        let smile = "\u{1F600}".as_bytes();
        let mut f = masked(0x01, M, &smile[..1]);
        f.extend(masked(0x00, M, &smile[1..3]));
        f.extend(masked(0x80, M, &smile[3..]));
        assert_eq!(run_whole(&mut server(), &f).unwrap(), vec![Ev::Text("\u{1F600}".into())]);
    }

    #[test]
    fn truncated_utf8_at_message_end_is_1007() {
        let euro = "\u{20ac}".as_bytes();
        let mut f = masked(0x01, M, &euro[..2]);
        f.extend(masked(0x80, M, b""));
        assert_eq!(run_whole(&mut server(), &f).unwrap_err().close_code(), 1007);
    }

    // ---- close frames ----

    #[test]
    fn close_payload_shapes() {
        assert_eq!(run_whole(&mut server(), &masked(0x88, M, b"")).unwrap(), vec![Ev::Close(None)]);
        assert_eq!(
            run_whole(&mut server(), &masked(0x88, M, &[0x03, 0xe8])).unwrap(),
            vec![Ev::Close(Some((1000, String::new())))]
        );
        let mut p = vec![0x03, 0xe9];
        p.extend_from_slice(b"bye");
        assert_eq!(
            run_whole(&mut server(), &masked(0x88, M, &p)).unwrap(),
            vec![Ev::Close(Some((1001, "bye".into())))]
        );
        // A one-byte payload cannot carry a code.
        assert_eq!(
            run_whole(&mut server(), &masked(0x88, M, &[0x03])),
            Err(WsError::Protocol("close frame with a 1-byte payload"))
        );
    }

    #[test]
    fn close_codes_on_the_wire() {
        for (code, ok) in [
            (1000u16, true),
            (1001, true),
            (1003, true),
            (1004, false),
            (1005, false),
            (1006, false),
            (1007, true),
            (1011, true),
            (1012, true),
            (1015, false),
            (999, false),
            (0, false),
            (2999, false),
            (3000, true),
            (4999, true),
            (5000, false),
        ] {
            let f = masked(0x88, M, &code.to_be_bytes());
            let r = run_whole(&mut server(), &f);
            assert_eq!(r.is_ok(), ok, "code {code}");
            if !ok {
                assert_eq!(r.unwrap_err().close_code(), 1002, "code {code}");
            }
        }
    }

    #[test]
    fn invalid_utf8_close_reason_is_rejected() {
        let mut p = vec![0x03, 0xe8];
        p.extend_from_slice(&[0xff, 0xfe]);
        let e = run_whole(&mut server(), &masked(0x88, M, &p)).unwrap_err();
        assert_eq!(e, WsError::InvalidPayload("invalid UTF-8 in close reason"));
    }

    #[test]
    fn input_after_close_is_discarded() {
        let mut d = server();
        let mut f = masked(0x88, M, &[0x03, 0xe8]);
        f.extend(masked(0x81, M, b"late"));
        f.extend_from_slice(&[0xff; 7]); // garbage that would be a protocol error
        let evs = run_whole(&mut d, &f).unwrap();
        assert_eq!(evs, vec![Ev::Close(Some((1000, String::new())))]);
        // Later reads are ignored too, and report everything as consumed.
        let mut more = vec![1, 2, 3];
        let r = d.decode(&mut more).unwrap();
        assert_eq!((r.consumed, r.event), (3, None));
    }

    // ---- zero-copy and framing mechanics ----

    #[test]
    fn single_frame_event_points_into_the_input() {
        let mut f = masked(0x81, M, b"zero copy");
        let range = f.as_ptr_range();
        let mut d = server();
        let r = d.decode(&mut f).unwrap();
        assert_eq!(r.consumed, 2 + 4 + 9);
        match r.event.unwrap() {
            Event::Text(s) => {
                assert_eq!(s, "zero copy");
                assert!(range.contains(&s.as_ptr()), "payload must borrow from the caller's buffer");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn consumed_covers_swallowed_fragments() {
        let mut f = masked(0x01, M, b"ab");
        f.extend(masked(0x00, M, b"cd"));
        let total = f.len();
        let mut d = server();
        // Everything is consumed even though no event came out.
        let r = d.decode(&mut f).unwrap();
        assert_eq!((r.consumed, r.event), (total, None));
        assert!(d.in_message());
        // The rest of the message arrives later.
        let mut g = masked(0x80, M, b"ef");
        let r = d.decode(&mut g).unwrap();
        assert_eq!(r.event, Some(Event::Text("abcdef")));
        assert!(!d.in_message());
    }

    #[test]
    fn a_partial_frame_is_not_consumed_or_modified() {
        let full = masked(0x81, M, b"payload");
        for cut in 0..full.len() {
            let mut part = full[..cut].to_vec();
            let mut d = server();
            let r = d.decode(&mut part).unwrap();
            assert_eq!((r.consumed, r.event), (0, None), "cut {cut}");
            assert_eq!(part, &full[..cut], "partial frame must not be unmasked");
        }
    }

    // ---- the streams ----

    /// A realistic stream: every frame kind, all three length forms (the 64-bit one
    /// via a legal non-minimal encoding), fragments with controls between them.
    fn stream() -> (Vec<u8>, Vec<Ev>) {
        let mut enc = ClientEncoder::with_seed(1234);
        let mut out = Vec::new();
        let mut want = Vec::new();

        enc.write_text(&mut out, b"hello");
        want.push(Ev::Text("hello".into()));
        enc.write_text(&mut out, b"");
        want.push(Ev::Text(String::new()));
        enc.write_binary(&mut out, &[7u8; 300]); // 16-bit length
        want.push(Ev::Binary(vec![7; 300]));

        // 64-bit length form for a 12-byte payload, masked by hand.
        out.extend_from_slice(&[0x82, 0xFF, 0, 0, 0, 0, 0, 0, 0, 12, 1, 2, 3, 4]);
        out.extend((0..12u8).map(|i| (i * 3) ^ [1, 2, 3, 4][usize::from(i) % 4]));
        want.push(Ev::Binary((0..12u8).map(|i| i * 3).collect()));

        // Fragmented text with a UTF-8 sequence cut across fragments and controls between.
        let euro = "\u{20ac}".as_bytes();
        enc.write_frame(&mut out, Opcode::Text, false, &[b'a', euro[0]]);
        enc.write_frame(&mut out, Opcode::Ping, true, b"mid");
        enc.write_frame(&mut out, Opcode::Continuation, false, &euro[1..2]);
        enc.write_frame(&mut out, Opcode::Continuation, false, b"");
        enc.write_frame(&mut out, Opcode::Pong, true, b"");
        enc.write_frame(&mut out, Opcode::Continuation, true, &[euro[2], b'z']);
        want.push(Ev::Ping(b"mid".to_vec()));
        want.push(Ev::Pong(Vec::new()));
        want.push(Ev::Text("a\u{20ac}z".into()));

        enc.write_ping(&mut out, b"x");
        want.push(Ev::Ping(b"x".to_vec()));
        enc.write_binary(&mut out, &[0xAB; 1000]);
        want.push(Ev::Binary(vec![0xAB; 1000]));
        enc.write_close(&mut out, 1000, "done");
        want.push(Ev::Close(Some((1000, "done".into()))));
        (out, want)
    }

    /// The same traffic as `stream`, as a server would send it (unmasked).
    fn server_stream() -> Vec<u8> {
        let mut out = Vec::new();
        write_text(&mut out, b"hello");
        write_binary(&mut out, &[7u8; 300]);
        write_frame(&mut out, Opcode::Text, false, b"fra");
        write_ping(&mut out, b"mid");
        write_frame(&mut out, Opcode::Continuation, true, b"gment");
        write_binary(&mut out, &[1u8; 3000]);
        write_pong(&mut out, b"");
        write_close(&mut out, 1001, "bye");
        out
    }

    fn xorshift(x: &mut u64) -> u64 {
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        *x
    }

    /// Random chunk boundaries over `data`.
    fn random_chunks<'a>(data: &'a [u8], x: &mut u64, max: u64) -> Vec<&'a [u8]> {
        let mut chunks = Vec::new();
        let mut at = 0;
        while at < data.len() {
            let end = (at + 1 + (xorshift(x) % max) as usize).min(data.len());
            chunks.push(&data[at..end]);
            at = end;
        }
        chunks
    }

    #[test]
    fn chunking_never_changes_the_outcome() {
        // Differential property over damaged streams: bit flips, truncation, random
        // splices. Whatever the bytes, the events (or the error) must not depend on
        // where the reads happened to end, and nothing may panic.
        let bases = [(Role::Server, stream().0), (Role::Client, server_stream())];
        let mut x = 0x1234_5678_9abc_def1u64;
        for iter in 0..4000 {
            for (role, base) in &bases {
                let mut data = base.clone();
                for _ in 0..xorshift(&mut x) % 4 {
                    let i = xorshift(&mut x) as usize % data.len();
                    data[i] ^= 1 << (xorshift(&mut x) % 8);
                }
                if xorshift(&mut x) % 4 == 0 {
                    let cut = xorshift(&mut x) as usize % data.len();
                    data.truncate(cut);
                }
                if xorshift(&mut x) % 8 == 0 {
                    let at = xorshift(&mut x) as usize % (data.len() + 1);
                    data.splice(at..at, (0..xorshift(&mut x) % 12).map(|_| xorshift(&mut x) as u8));
                }
                let limits = (4096, 4096);
                let whole = run_whole(&mut Decoder::new(*role, limits.0, limits.1), &data);
                let chunks = random_chunks(&data, &mut x, if iter % 2 == 0 { 7 } else { 300 });
                let chunked = run(&mut Decoder::new(*role, limits.0, limits.1), chunks);
                assert_eq!(whole, chunked, "iter {iter} role {role:?}");
            }
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let mut x = 0xfeed_beef_dead_f00du64;
        for _ in 0..20_000 {
            let n = (xorshift(&mut x) % 40) as usize;
            let mut data: Vec<u8> = (0..n).map(|_| xorshift(&mut x) as u8).collect();
            // Bias the first byte toward plausible frames so deeper paths get hit.
            if !data.is_empty() && xorshift(&mut x) % 2 == 0 {
                data[0] = [0x81, 0x82, 0x01, 0x00, 0x88, 0x89, 0x8A][(xorshift(&mut x) % 7) as usize];
            }
            for role in [Role::Server, Role::Client] {
                let _ = run_whole(&mut Decoder::new(role, 64, 128), &data);
            }
        }
    }

    #[test]
    fn stream_decodes_whole() {
        let (bytes, want) = stream();
        assert_eq!(run_whole(&mut server(), &bytes).unwrap(), want);
    }

    #[test]
    fn stream_split_at_every_byte_boundary() {
        let (bytes, want) = stream();
        for cut in 0..=bytes.len() {
            let got = run(&mut server(), [&bytes[..cut], &bytes[cut..]]).unwrap();
            assert_eq!(got, want, "split at {cut}");
        }
    }

    #[test]
    fn stream_one_byte_at_a_time() {
        let (bytes, want) = stream();
        let got = run(&mut server(), bytes.chunks(1)).unwrap();
        assert_eq!(got, want);
    }

    #[test]
    fn stream_in_random_chunk_sizes() {
        let (bytes, want) = stream();
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for round in 0..300 {
            let mut chunks: Vec<&[u8]> = Vec::new();
            let mut at = 0;
            while at < bytes.len() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let n = 1 + (x % 97) as usize * if round % 3 == 0 { 1 } else { 5 };
                let end = (at + n).min(bytes.len());
                chunks.push(&bytes[at..end]);
                at = end;
            }
            assert_eq!(run(&mut server(), chunks).unwrap(), want, "round {round}");
        }
    }

    #[test]
    fn large_frames_in_random_chunks() {
        // 64-bit-length-sized payloads crossing many reads.
        let mut enc = ClientEncoder::with_seed(99);
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        let mut bytes = Vec::new();
        enc.write_binary(&mut bytes, &big);
        enc.write_text(&mut bytes, "w".repeat(70_000).as_bytes());
        let want = vec![Ev::Binary(big), Ev::Text("w".repeat(70_000))];
        let mut x = 0xDEAD_BEEF_CAFE_F00Du64;
        for _ in 0..6 {
            let mut chunks: Vec<&[u8]> = Vec::new();
            let mut at = 0;
            while at < bytes.len() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let end = (at + 1 + (x % 9000) as usize).min(bytes.len());
                chunks.push(&bytes[at..end]);
                at = end;
            }
            assert_eq!(run(&mut Decoder::server(1 << 20, 1 << 20), chunks).unwrap(), want);
        }
    }

    #[test]
    fn reassembly_buffer_is_released_after_a_huge_message() {
        let mut enc = ClientEncoder::with_seed(5);
        let mut d = Decoder::server(1 << 21, 1 << 21);
        let mut bytes = Vec::new();
        enc.write_frame(&mut bytes, Opcode::Binary, false, &vec![1u8; RETAIN_CAP + 10]);
        enc.write_frame(&mut bytes, Opcode::Continuation, true, b"tail");
        run_whole(&mut d, &bytes).unwrap();
        assert!(d.msg.capacity() > RETAIN_CAP);
        let mut bytes = Vec::new();
        enc.write_frame(&mut bytes, Opcode::Binary, false, b"a");
        enc.write_frame(&mut bytes, Opcode::Continuation, true, b"b");
        let evs = run_whole(&mut d, &bytes).unwrap();
        assert_eq!(evs, vec![Ev::Binary(b"ab".to_vec())]);
        assert!(d.msg.capacity() <= RETAIN_CAP, "oversized buffer dropped at the next message");
    }
}
