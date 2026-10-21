//! RFC 6455 frames, sans-IO.
//!
//! Nothing here reads or writes a socket. The [`Decoder`] is handed the bytes a
//! connection has buffered and says what they contain; the encoders append frames
//! to a `Vec<u8>` the caller flushes with one write. A connection therefore costs
//! no allocation per frame in the steady state, and the same code serves the
//! relay, the tests and the benchmark client.
//!
//! * [`decode`]: incremental parser with in-place unmasking, fragment reassembly,
//!   UTF-8 and close-code validation. Works for either side of a connection.
//! * [`encode`]: server-side (unmasked) frame writers, the reserve-then-patch API
//!   for building a message directly in the output buffer, and the masking
//!   [`ClientEncoder`] for tests and benchmarks.
//! * [`mod@unmask`]: the payload XOR, isolated so a SIMD version can replace it.
//!
//! Extensions are not negotiated, so every RSV bit must be zero. permessage-deflate
//! will need the decoder to accept RSV1 on the first frame of a message and report
//! it with the event; that is the only decoder change it implies.

pub mod decode;
pub mod encode;
pub mod unmask;

pub use decode::{Decoded, Decoder, Event, Role};
pub use encode::{
    begin_binary, begin_frame, begin_text, finish_binary, finish_frame, finish_text, header_len, write_binary,
    write_close, write_close_empty, write_frame, write_frame_header, write_ping, write_pong, write_text, ClientEncoder,
    Mark,
};
pub use unmask::unmask;

use std::fmt;

/// Frame opcodes (RFC 6455 §5.2). Reserved values are not representable: the
/// decoder rejects them before they could be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

/// Close status codes the relay sends or reacts to (RFC 6455 §7.4.1).
pub mod close_code {
    pub const NORMAL: u16 = 1000;
    pub const GOING_AWAY: u16 = 1001;
    pub const PROTOCOL_ERROR: u16 = 1002;
    pub const UNSUPPORTED_DATA: u16 = 1003;
    pub const INVALID_PAYLOAD: u16 = 1007;
    pub const POLICY_VIOLATION: u16 = 1008;
    pub const MESSAGE_TOO_BIG: u16 = 1009;
    pub const INTERNAL_ERROR: u16 = 1011;
    pub const TRY_AGAIN_LATER: u16 = 1013;
}

/// Whether `code` may appear in a close frame on the wire (RFC 6455 §7.4.1-2):
/// the defined codes 1000-1003 and 1007-1011, and the application range
/// 3000-4999. 1004 is reserved, 1005/1006/1015 are local-only markers that must
/// never be sent, and 2000-2999 belongs to extensions we do not negotiate.
#[inline]
pub fn is_valid_close_code(code: u16) -> bool {
    // 1012-1014 are IANA-registered (service restart, try again later, bad gateway).
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
}

/// A reason to fail the connection, carrying the close code to send. The reason
/// text is static, short and safe to put in a close frame (<= 123 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsError {
    /// 1002: the peer broke the framing rules.
    Protocol(&'static str),
    /// 1007: a text message or close reason was not valid UTF-8.
    InvalidPayload(&'static str),
    /// 1009: a frame or message exceeded the configured limits.
    TooBig(&'static str),
}

impl WsError {
    /// The close status to send before dropping the connection.
    #[inline]
    pub fn close_code(&self) -> u16 {
        match self {
            WsError::Protocol(_) => close_code::PROTOCOL_ERROR,
            WsError::InvalidPayload(_) => close_code::INVALID_PAYLOAD,
            WsError::TooBig(_) => close_code::MESSAGE_TOO_BIG,
        }
    }

    #[inline]
    pub fn reason(&self) -> &'static str {
        match self {
            WsError::Protocol(r) | WsError::InvalidPayload(r) | WsError::TooBig(r) => r,
        }
    }
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "websocket error {}: {}", self.close_code(), self.reason())
    }
}

impl std::error::Error for WsError {}

#[cfg(test)]
mod tests {
    //! Cross-module tests: what one side encodes the other side must decode.
    use super::*;

    /// Everything the decoder can report, owned, so streams can be compared.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum Ev {
        Text(String),
        Binary(Vec<u8>),
        Ping(Vec<u8>),
        Pong(Vec<u8>),
        Close(Option<(u16, String)>),
    }

    impl From<Event<'_>> for Ev {
        fn from(e: Event<'_>) -> Ev {
            match e {
                Event::Text(s) => Ev::Text(s.to_owned()),
                Event::Binary(b) => Ev::Binary(b.to_vec()),
                Event::Ping(b) => Ev::Ping(b.to_vec()),
                Event::Pong(b) => Ev::Pong(b.to_vec()),
                Event::Close(c) => Ev::Close(c.map(|(code, r)| (code, r.to_owned()))),
            }
        }
    }

    /// Feeds `chunks` to `dec` the way a connection does: append to a buffer, decode
    /// until it stalls, drop what was consumed. Returns every event, or the error.
    pub(crate) fn run<'c>(dec: &mut Decoder, chunks: impl IntoIterator<Item = &'c [u8]>) -> Result<Vec<Ev>, WsError> {
        let mut buf: Vec<u8> = Vec::new();
        let mut evs = Vec::new();
        for chunk in chunks {
            buf.extend_from_slice(chunk);
            let mut off = 0;
            loop {
                let d = dec.decode(&mut buf[off..])?;
                off += d.consumed;
                match d.event {
                    Some(e) => evs.push(Ev::from(e)),
                    None => break,
                }
            }
            buf.drain(..off);
            if !buf.is_empty() {
                assert!(dec.needed() > buf.len(), "stalled with a complete frame buffered");
            }
        }
        Ok(evs)
    }

    pub(crate) fn run_whole(dec: &mut Decoder, bytes: &[u8]) -> Result<Vec<Ev>, WsError> {
        run(dec, [bytes])
    }

    #[test]
    fn close_code_validity() {
        for c in [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 3999, 4000, 4999] {
            assert!(is_valid_close_code(c), "{c}");
        }
        for c in [0, 999, 1004, 1005, 1006, 1015, 1016, 1100, 2000, 2999, 5000, 65535] {
            assert!(!is_valid_close_code(c), "{c}");
        }
    }

    #[test]
    fn error_codes() {
        assert_eq!(WsError::Protocol("x").close_code(), 1002);
        assert_eq!(WsError::InvalidPayload("x").close_code(), 1007);
        assert_eq!(WsError::TooBig("x").close_code(), 1009);
        assert!(WsError::TooBig("message too big").to_string().contains("1009"));
    }

    const LENGTHS: [usize; 8] = [0, 1, 125, 126, 127, 65535, 65536, 200_000];

    fn payload(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(131) >> 3) as u8).collect()
    }

    #[test]
    fn client_encode_server_decode_round_trip() {
        let mut enc = ClientEncoder::with_seed(42);
        for n in LENGTHS {
            let p = payload(n);
            let mut out = Vec::new();
            enc.write_binary(&mut out, &p);
            let mut dec = Decoder::new(Role::Server, 1 << 20, 1 << 20);
            let evs = run_whole(&mut dec, &out).unwrap();
            assert_eq!(evs, vec![Ev::Binary(p.clone())], "binary {n}");

            // Text needs valid UTF-8: use ASCII filler of the same length.
            let t = "x".repeat(n);
            let mut out = Vec::new();
            enc.write_text(&mut out, t.as_bytes());
            let mut dec = Decoder::new(Role::Server, 1 << 20, 1 << 20);
            assert_eq!(run_whole(&mut dec, &out).unwrap(), vec![Ev::Text(t)], "text {n}");
        }
    }

    #[test]
    fn server_encode_client_decode_round_trip() {
        for n in LENGTHS {
            let p = payload(n);
            let mut out = Vec::new();
            write_binary(&mut out, &p);
            let mut dec = Decoder::new(Role::Client, 1 << 20, 1 << 20);
            assert_eq!(run_whole(&mut dec, &out).unwrap(), vec![Ev::Binary(p)], "binary {n}");

            let t = "y".repeat(n);
            let mut out = Vec::new();
            write_text(&mut out, t.as_bytes());
            let mut dec = Decoder::new(Role::Client, 1 << 20, 1 << 20);
            assert_eq!(run_whole(&mut dec, &out).unwrap(), vec![Ev::Text(t)], "text {n}");
        }
    }

    #[test]
    fn control_frames_round_trip() {
        let mut out = Vec::new();
        write_ping(&mut out, b"are you there");
        write_pong(&mut out, b"yes");
        write_close(&mut out, 1001, "going away");
        let mut dec = Decoder::new(Role::Client, 1 << 20, 1 << 20);
        assert_eq!(
            run_whole(&mut dec, &out).unwrap(),
            vec![
                Ev::Ping(b"are you there".to_vec()),
                Ev::Pong(b"yes".to_vec()),
                Ev::Close(Some((1001, "going away".to_owned()))),
            ]
        );

        let mut enc = ClientEncoder::with_seed(7);
        let mut out = Vec::new();
        enc.write_ping(&mut out, b"p");
        enc.write_close(&mut out, 1000, "");
        let mut dec = Decoder::new(Role::Server, 1 << 20, 1 << 20);
        assert_eq!(
            run_whole(&mut dec, &out).unwrap(),
            vec![Ev::Ping(b"p".to_vec()), Ev::Close(Some((1000, String::new())))]
        );
    }

    #[test]
    fn begin_finish_matches_write_text_for_every_length_class() {
        for n in [0, 1, 124, 125, 126, 127, 1000, 65534, 65535, 65536, 65537, 200_000] {
            let p = payload(n);
            // A prefix (an earlier frame) and nothing after: the patch must not
            // disturb what came before.
            let mut want = Vec::new();
            write_pong(&mut want, b"before");
            let mut got = want.clone();
            write_binary(&mut want, &p);

            let mark = begin_binary(&mut got);
            got.extend_from_slice(&p);
            finish_binary(&mut got, mark);
            assert_eq!(got, want, "binary {n}");

            let t = "z".repeat(n);
            let mut want = Vec::new();
            write_text(&mut want, t.as_bytes());
            let mut got = Vec::new();
            let mark = begin_text(&mut got);
            got.extend_from_slice(t.as_bytes());
            finish_text(&mut got, mark);
            assert_eq!(got, want, "text {n}");
        }
    }

    #[test]
    fn begin_finish_in_several_appends() {
        // The relay builds `["EVENT","sub",<event>]` from several pieces.
        let mut out = Vec::new();
        let mark = begin_text(&mut out);
        out.extend_from_slice(b"[\"EVENT\",\"s\",");
        out.extend_from_slice(&[b'1'; 300]);
        out.extend_from_slice(b"]");
        finish_text(&mut out, mark);
        let mut dec = Decoder::new(Role::Client, 1 << 20, 1 << 20);
        let evs = run_whole(&mut dec, &out).unwrap();
        let mut want = String::from("[\"EVENT\",\"s\",");
        want.push_str(&"1".repeat(300));
        want.push(']');
        assert_eq!(evs, vec![Ev::Text(want)]);
    }
}
