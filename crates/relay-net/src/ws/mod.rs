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
//! * [`pmd`]: permessage-deflate (RFC 7692): negotiation and the per-connection
//!   compressor. The decompressing half is inside the [`Decoder`].
//!
//! Without a negotiated extension every RSV bit must be zero. With permessage-deflate
//! RSV1 marks a compressed message on its first frame; the decoder then inflates the
//! reassembled message (enforcing the size limit on the *decompressed* size) and hands
//! back the plain text or bytes, so callers never see compressed data.

pub mod decode;
pub mod encode;
pub mod pmd;
pub mod unmask;

pub use decode::{Decoded, Decoder, Event, Role};
pub use encode::{
    begin_binary, begin_frame, begin_frame_ext, begin_text, finish_binary, finish_frame, finish_text, header_len,
    write_binary, write_close, write_close_empty, write_frame, write_frame_ext, write_frame_header, write_ping,
    write_pong, write_text, ClientEncoder, Mark,
};
pub use pmd::{write_compressed_frame, Compressor, DeflateParams, DeflatePolicy, StreamConfig};
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

    // ---- permessage-deflate end to end ----

    use crate::deflate::testutil::{base64, nostr_corpus, Rng};
    use crate::http::{accept_key, parse_request, parse_response, write_upgrade_response, ExtensionPolicy, Extensions};

    /// Both ends of a negotiated connection, built the way a server and a client would:
    /// the request is parsed, the policy applied, the 101 written and the client's view
    /// read back out of the response header.
    struct Session {
        srv_dec: Decoder,
        cli_dec: Decoder,
        srv_comp: Compressor,
        cli_comp: Compressor,
        enc: ClientEncoder,
        server_params: DeflateParams,
        client_params: DeflateParams,
    }

    fn session_with(offer: &str, policy: DeflatePolicy, min_len: usize, max_message: usize) -> Session {
        let req = format!(
            "GET /nostr HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Extensions: {offer}\r\n\r\n"
        );
        let (r, _) = parse_request(req.as_bytes()).unwrap().unwrap();
        let ext = Extensions::negotiate(&r, &ExtensionPolicy::with_deflate(policy));
        let server_params = ext.deflate.expect("the offer should be accepted");
        let mut resp = Vec::new();
        write_upgrade_response(&mut resp, &accept_key(b"dGhlIHNhbXBsZSBub25jZQ=="), &ext);
        let (rp, _) = parse_response(&resp, 4096).unwrap().unwrap();
        let client_params =
            DeflateParams::from_response(rp.headers.get("sec-websocket-extensions").expect("response header")).unwrap();
        Session {
            srv_dec: Decoder::server(max_message, max_message).with_deflate(&server_params),
            cli_dec: Decoder::client(max_message, max_message).with_deflate(&client_params),
            srv_comp: Compressor::for_role(&server_params, Role::Server, min_len),
            cli_comp: Compressor::for_role(&client_params, Role::Client, min_len),
            enc: ClientEncoder::with_seed(77),
            server_params,
            client_params,
        }
    }

    fn session(offer: &str) -> Session {
        session_with(offer, DeflatePolicy::default(), Compressor::DEFAULT_MIN_LEN, 1 << 22)
    }

    impl Session {
        /// A masked client text frame, compressed when the compressor's threshold says so.
        fn client_text(&mut self, out: &mut Vec<u8>, payload: &[u8]) {
            if self.cli_comp.will_compress(payload.len()) {
                let mut c = Vec::new();
                self.cli_comp.deflate_payload(payload, &mut c);
                self.enc.write_frame_ext(out, Opcode::Text, true, true, &c);
            } else {
                self.enc.write_text(out, payload);
            }
        }
    }

    fn text(b: &[u8]) -> Ev {
        Ev::Text(String::from_utf8(b.to_vec()).unwrap())
    }

    #[test]
    fn every_negotiated_mode_round_trips_in_both_directions() {
        let events = nostr_corpus(7, 150);
        let d = DeflatePolicy::default();
        let cases: Vec<(&str, DeflatePolicy)> = vec![
            ("permessage-deflate", d),
            ("permessage-deflate; client_max_window_bits", d),
            ("permessage-deflate; server_no_context_takeover; client_no_context_takeover", d),
            ("permessage-deflate; server_max_window_bits=9; client_max_window_bits=9", d),
            ("permessage-deflate; client_max_window_bits=12", DeflatePolicy { max_server_window_bits: 11, ..d }),
            (
                "permessage-deflate",
                DeflatePolicy { server_no_context_takeover: true, client_no_context_takeover: true, ..d },
            ),
            ("permessage-deflate; client_max_window_bits", DeflatePolicy { max_client_window_bits: 8, ..d }),
        ];
        for (offer, policy) in cases {
            for min_len in [0, Compressor::DEFAULT_MIN_LEN, 5000] {
                let mut s = session_with(offer, policy, min_len, 1 << 22);
                let mut compressed_seen = 0;
                for (i, e) in events.iter().enumerate() {
                    let mut wire = Vec::new();
                    s.client_text(&mut wire, e);
                    // Deliver in odd-sized pieces: the decoder must not care.
                    let evs = run(&mut s.srv_dec, wire.chunks(1 + i % 23)).unwrap_or_else(|e| panic!("{offer}: {e}"));
                    assert_eq!(evs, vec![text(e)], "{offer} client message {i}");

                    let mut wire = Vec::new();
                    s.srv_comp.compress_text(&mut wire, e);
                    compressed_seen += usize::from(wire[0] & 0x40 != 0);
                    let evs = run_whole(&mut s.cli_dec, &wire).unwrap_or_else(|e| panic!("{offer}: {e}"));
                    assert_eq!(evs, vec![text(e)], "{offer} server message {i}");
                }
                assert_eq!(compressed_seen > 0, min_len < 5000, "{offer} min_len {min_len}");
            }
        }
    }

    #[test]
    fn compressed_text_is_smaller_on_the_wire_and_flagged() {
        let mut s = session("permessage-deflate");
        let e = &nostr_corpus(3, 1)[0];
        let mut plain = Vec::new();
        write_text(&mut plain, e);
        let mut packed = Vec::new();
        s.srv_comp.compress_text(&mut packed, e);
        assert_eq!(packed[0], 0xc1, "FIN, RSV1, text");
        assert!(packed.len() < plain.len() * 9 / 10, "{} vs {}", packed.len(), plain.len());
        // Binary works the same way, with the opcode preserved.
        let mut bin = Vec::new();
        s.srv_comp.compress_binary(&mut bin, &[7u8; 1000]);
        assert_eq!(bin[0], 0xc2);
        assert_eq!(run_whole(&mut s.cli_dec, &bin).unwrap(), vec![Ev::Binary(vec![7; 1000])]);
    }

    #[test]
    fn rsv1_without_negotiation_is_a_protocol_error() {
        let mut enc = ClientEncoder::with_seed(1);
        let mut wire = Vec::new();
        enc.write_frame_ext(&mut wire, Opcode::Text, true, true, b"\x00");
        let e = run_whole(&mut Decoder::server(1 << 20, 1 << 20), &wire).unwrap_err();
        assert_eq!(e, WsError::Protocol("reserved bits set"));
        assert_eq!(e.close_code(), 1002);
        // The server side of the same rule: a client decoder without the extension.
        let mut wire = Vec::new();
        write_frame_ext(&mut wire, Opcode::Text, true, true, b"\x00");
        assert_eq!(run_whole(&mut Decoder::client(1 << 20, 1 << 20), &wire).unwrap_err().close_code(), 1002);
    }

    #[test]
    fn rsv1_rules_with_the_extension_on() {
        let params = session("permessage-deflate").server_params;
        let mut enc = ClientEncoder::with_seed(2);
        let fresh = || Decoder::server(1 << 20, 1 << 20).with_deflate(&params);
        // Control frames are never compressed.
        for op in [Opcode::Ping, Opcode::Pong, Opcode::Close] {
            let mut wire = Vec::new();
            enc.write_frame_ext(&mut wire, op, true, true, b"");
            let e = run_whole(&mut fresh(), &wire).unwrap_err();
            assert_eq!(e, WsError::Protocol("compressed control frame"), "{op:?}");
        }
        // Only the first frame of a message may carry it.
        let mut wire = Vec::new();
        enc.write_frame_ext(&mut wire, Opcode::Text, false, true, b"\xf2\x48");
        enc.write_frame_ext(&mut wire, Opcode::Continuation, true, true, b"\x05\x00");
        assert_eq!(run_whole(&mut fresh(), &wire).unwrap_err(), WsError::Protocol("compressed continuation frame"));
        // RSV2 and RSV3 stay errors.
        for bad in [0x20u8, 0x10] {
            let mut wire = Vec::new();
            enc.write_frame(&mut wire, Opcode::Text, true, b"x");
            wire[0] |= bad;
            assert_eq!(run_whole(&mut fresh(), &wire).unwrap_err(), WsError::Protocol("reserved bits set"));
        }
        // An uncompressed message needs no RSV1, before, between and after compressed ones.
        let mut s = session("permessage-deflate");
        let mut wire = Vec::new();
        s.enc.write_text(&mut wire, b"plain one");
        s.client_text(&mut wire, &nostr_corpus(1, 1)[0]);
        s.enc.write_text(&mut wire, b"plain two");
        let evs = run_whole(&mut s.srv_dec, &wire).unwrap();
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0], Ev::Text("plain one".into()));
    }

    #[test]
    fn fragmented_compressed_messages_with_control_frames_between() {
        let mut s = session("permessage-deflate");
        let payload = nostr_corpus(5, 1).remove(0);
        let mut c = Vec::new();
        s.cli_comp.deflate_payload(&payload, &mut c);
        let cuts = [0, c.len() / 3, c.len() / 3, 2 * c.len() / 3, c.len()]; // one empty fragment too
        let mut wire = Vec::new();
        s.enc.write_frame_ext(&mut wire, Opcode::Text, false, true, &c[cuts[0]..cuts[1]]);
        s.enc.write_frame(&mut wire, Opcode::Ping, true, b"p1");
        s.enc.write_frame(&mut wire, Opcode::Continuation, false, &c[cuts[1]..cuts[2]]);
        s.enc.write_frame(&mut wire, Opcode::Pong, true, b"");
        s.enc.write_frame(&mut wire, Opcode::Continuation, false, &c[cuts[2]..cuts[3]]);
        s.enc.write_frame(&mut wire, Opcode::Continuation, true, &c[cuts[3]..cuts[4]]);
        // A plain message and a second compressed one right behind it (history continues).
        s.enc.write_text(&mut wire, b"after");
        s.client_text(&mut wire, &payload);
        let want = vec![
            Ev::Ping(b"p1".to_vec()),
            Ev::Pong(Vec::new()),
            text(&payload),
            Ev::Text("after".into()),
            text(&payload),
        ];
        assert_eq!(run_whole(&mut s.srv_dec, &wire).unwrap(), want);
        // Same bytes, one at a time.
        let mut s2 = session("permessage-deflate");
        let mut c2 = Vec::new();
        s2.cli_comp.deflate_payload(&payload, &mut c2);
        let mut wire2 = Vec::new();
        s2.enc.write_frame_ext(&mut wire2, Opcode::Text, false, true, &c2[..c2.len() / 2]);
        s2.enc.write_frame(&mut wire2, Opcode::Ping, true, b"p1");
        s2.enc.write_frame(&mut wire2, Opcode::Continuation, true, &c2[c2.len() / 2..]);
        let got = run(&mut s2.srv_dec, wire2.chunks(1)).unwrap();
        assert_eq!(got, vec![Ev::Ping(b"p1".to_vec()), text(&payload)]);
    }

    #[test]
    fn the_limit_applies_to_the_decompressed_size() {
        let params = session("permessage-deflate").server_params;
        let limit = 1000;
        let mut enc = ClientEncoder::with_seed(3);
        let mut send = |n: usize| {
            // A fresh stream each time so history does not interfere.
            let mut comp = Compressor::for_role(&params, Role::Client, 0);
            let mut c = Vec::new();
            comp.deflate_payload(&vec![b'a'; n], &mut c);
            let mut wire = Vec::new();
            enc.write_frame_ext(&mut wire, Opcode::Text, true, true, &c);
            wire
        };
        let mut dec = Decoder::server(1 << 20, limit).with_deflate(&params);
        assert_eq!(run_whole(&mut dec, &send(limit)).unwrap(), vec![Ev::Text("a".repeat(limit))]);
        let wire = send(limit + 1);
        assert!(wire.len() < 30, "the bomb is tiny on the wire: {}", wire.len());
        let e = run_whole(&mut Decoder::server(1 << 20, limit).with_deflate(&params), &wire).unwrap_err();
        assert_eq!(e, WsError::TooBig("message too big"));
        assert_eq!(e.close_code(), 1009);
        // A much bigger bomb fails the same way and early.
        let e = run_whole(&mut Decoder::server(1 << 20, limit).with_deflate(&params), &send(50_000_000)).unwrap_err();
        assert_eq!(e.close_code(), 1009);
        // Fragmented bombs too.
        let mut comp = Compressor::for_role(&params, Role::Client, 0);
        let mut c = Vec::new();
        comp.deflate_payload(&vec![b'a'; 100_000], &mut c);
        let mut wire = Vec::new();
        enc.write_frame_ext(&mut wire, Opcode::Text, false, true, &c[..c.len() / 2]);
        enc.write_frame(&mut wire, Opcode::Continuation, true, &c[c.len() / 2..]);
        let e = run_whole(&mut Decoder::server(1 << 20, limit).with_deflate(&params), &wire).unwrap_err();
        assert_eq!(e.close_code(), 1009);
    }

    #[test]
    fn compressed_form_gets_headroom_over_the_limit() {
        // A message of exactly the limit that does not compress is a few bytes bigger on the
        // wire; refusing it would make the limit lie.
        let params = session("permessage-deflate").server_params;
        let limit = 1000;
        let data = Rng::new(9).bytes(limit);
        let mut comp = Compressor::for_role(&params, Role::Client, 0);
        let mut c = Vec::new();
        comp.deflate_payload(&data, &mut c);
        assert!(c.len() > limit, "stored block framing makes it larger: {}", c.len());
        let mut enc = ClientEncoder::with_seed(4);
        let mut wire = Vec::new();
        enc.write_frame_ext(&mut wire, Opcode::Binary, true, true, &c);
        let got = run_whole(&mut Decoder::server(1 << 20, limit).with_deflate(&params), &wire).unwrap();
        assert_eq!(got, vec![Ev::Binary(data.clone())]);
        // One byte more than the limit is refused after inflating.
        let mut c = Vec::new();
        Compressor::for_role(&params, Role::Client, 0).deflate_payload(&Rng::new(9).bytes(limit + 1), &mut c);
        let mut wire = Vec::new();
        enc.write_frame_ext(&mut wire, Opcode::Binary, true, true, &c);
        let e = run_whole(&mut Decoder::server(1 << 20, limit).with_deflate(&params), &wire).unwrap_err();
        assert_eq!(e, WsError::TooBig("message too big"));
        // A frame far beyond any plausible compressed form is refused at its header, as
        // soon as the length is known (here by the frame limit, in the case below by the message limit).
        let mut wire = Vec::new();
        enc.write_frame_ext(&mut wire, Opcode::Binary, true, true, &vec![0u8; limit + 400]);
        let e = run_whole(&mut Decoder::server(limit, limit).with_deflate(&params), &wire).unwrap_err();
        assert_eq!(e, WsError::TooBig("frame too big"));
        let e = run_whole(&mut Decoder::server(1 << 20, limit).with_deflate(&params), &wire).unwrap_err();
        assert_eq!(e, WsError::TooBig("message too big"));
        // Uncompressed messages keep the exact limit.
        let mut wire = Vec::new();
        enc.write_frame(&mut wire, Opcode::Binary, true, &vec![0u8; limit + 1]);
        let e = run_whole(&mut Decoder::server(1 << 20, limit).with_deflate(&params), &wire).unwrap_err();
        assert_eq!(e, WsError::TooBig("message too big"));
    }

    #[test]
    fn corrupt_compressed_data_is_1007_and_sticky() {
        let params = session("permessage-deflate").server_params;
        let mut enc = ClientEncoder::with_seed(5);
        let mut dec = Decoder::server(1 << 20, 1 << 20).with_deflate(&params);
        let mut wire = Vec::new();
        enc.write_frame_ext(&mut wire, Opcode::Text, true, true, &[0xff, 0xff, 0xff]);
        let e = run_whole(&mut dec, &wire).unwrap_err();
        assert_eq!(e, WsError::InvalidPayload("invalid compressed data"));
        assert_eq!(e.close_code(), 1007);
        // The decoder stays failed, even for a good message.
        let mut s = session("permessage-deflate");
        let mut good = Vec::new();
        s.client_text(&mut good, &nostr_corpus(2, 1)[0]);
        assert_eq!(run_whole(&mut dec, &good).unwrap_err().close_code(), 1007);
        // Truncated message (the sync marker's header byte missing) and an empty payload.
        let mut c = Vec::new();
        s.cli_comp.deflate_payload(&nostr_corpus(2, 1)[0], &mut c);
        for bad in [&c[..c.len() - 1], &c[..1], &[][..]] {
            let mut fresh = Decoder::server(1 << 20, 1 << 20).with_deflate(&params);
            let mut wire = Vec::new();
            enc.write_frame_ext(&mut wire, Opcode::Text, true, true, bad);
            assert_eq!(run_whole(&mut fresh, &wire).unwrap_err().close_code(), 1007, "{} bytes", bad.len());
        }
    }

    #[test]
    fn invalid_utf8_after_inflating_is_1007() {
        let params = session("permessage-deflate").server_params;
        let mut comp = Compressor::for_role(&params, Role::Client, 0);
        let mut c = Vec::new();
        comp.deflate_payload(&[b'o', b'k', 0xff, 0xfe], &mut c);
        let mut wire = Vec::new();
        ClientEncoder::with_seed(6).write_frame_ext(&mut wire, Opcode::Text, true, true, &c);
        let e = run_whole(&mut Decoder::server(1 << 20, 1 << 20).with_deflate(&params), &wire).unwrap_err();
        assert_eq!(e, WsError::InvalidPayload("invalid UTF-8 in text message"));
        // As a binary message the same bytes are fine.
        let mut wire = Vec::new();
        ClientEncoder::with_seed(6).write_frame_ext(&mut wire, Opcode::Binary, true, true, &c);
        let got = run_whole(&mut Decoder::server(1 << 20, 1 << 20).with_deflate(&params), &wire).unwrap();
        assert_eq!(got, vec![Ev::Binary(vec![b'o', b'k', 0xff, 0xfe])]);
    }

    #[test]
    fn rfc_7692_wire_examples_decode() {
        // Section 7.2.3.1: "Hello" in a single compressed message.
        let params = session("permessage-deflate").server_params;
        let mut wire = Vec::new();
        ClientEncoder::with_seed(1).write_frame_ext(
            &mut wire,
            Opcode::Text,
            true,
            true,
            &[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00],
        );
        let mut dec = Decoder::server(1 << 20, 1 << 20).with_deflate(&params);
        assert_eq!(run_whole(&mut dec, &wire).unwrap(), vec![Ev::Text("Hello".into())]);
        // And our compressor's output for it is a valid message the same decoder accepts.
        let mut c = Vec::new();
        Compressor::for_role(&params, Role::Client, 0).deflate_payload(b"Hello", &mut c);
        let mut wire = Vec::new();
        ClientEncoder::with_seed(1).write_frame_ext(&mut wire, Opcode::Text, true, true, &c);
        assert_eq!(run_whole(&mut dec, &wire).unwrap(), vec![Ev::Text("Hello".into())]);
    }

    #[test]
    fn small_messages_go_plain_and_leave_the_history_alone() {
        let mut s = session("permessage-deflate");
        let big = nostr_corpus(8, 40);
        let mut wire = Vec::new();
        let mut kinds = Vec::new();
        for (i, e) in big.iter().enumerate() {
            let start = wire.len();
            // Alternate a short notice with a real event.
            s.srv_comp.compress_text(&mut wire, format!("[\"NOTICE\",\"n{i}\"]").as_bytes());
            kinds.push(wire[start] & 0x40);
            let start = wire.len();
            s.srv_comp.compress_text(&mut wire, e);
            kinds.push(wire[start] & 0x40);
        }
        assert!(kinds.chunks(2).all(|k| k[0] == 0 && k[1] != 0));
        let evs = run(&mut s.cli_dec, wire.chunks(97)).unwrap();
        assert_eq!(evs.len(), 80);
        for (i, e) in big.iter().enumerate() {
            assert_eq!(evs[2 * i], Ev::Text(format!("[\"NOTICE\",\"n{i}\"]")));
            assert_eq!(evs[2 * i + 1], text(e));
        }
    }

    #[test]
    fn empty_and_tiny_payloads_when_the_threshold_is_zero() {
        let mut s = session_with("permessage-deflate", DeflatePolicy::default(), 0, 1 << 20);
        let mut wire = Vec::new();
        for p in ["", "a", "ab", "hello hello"] {
            s.srv_comp.compress_text(&mut wire, p.as_bytes());
        }
        let evs = run_whole(&mut s.cli_dec, &wire).unwrap();
        assert_eq!(
            evs,
            vec![Ev::Text("".into()), Ev::Text("a".into()), Ev::Text("ab".into()), Ev::Text("hello hello".into())]
        );
        // RFC 7692 section 7.2.3.6: an empty compressed message is one 0x00 byte.
        let mut empty = Vec::new();
        s.srv_comp.compress_text(&mut empty, b"");
        assert_eq!(empty, [0xc1, 0x01, 0x00]);
    }

    #[test]
    fn no_context_takeover_makes_every_message_stand_alone() {
        let events = nostr_corpus(11, 30);
        // Server side stateless: any client decoder, fresh each time, can read any message.
        let s = session("permessage-deflate; server_no_context_takeover");
        let mut comp = Compressor::for_role(&s.server_params, Role::Server, 0);
        assert_eq!(comp.heap_bytes(), 0);
        for e in &events {
            let mut wire = Vec::new();
            comp.compress_text(&mut wire, e);
            let mut fresh = Decoder::client(1 << 20, 1 << 20).with_deflate(&s.client_params);
            assert_eq!(run_whole(&mut fresh, &wire).unwrap(), vec![text(e)]);
            assert_eq!(fresh.heap_bytes(), fresh.heap_bytes().min(64 * 1024));
        }
        // Compress once, send to many: the same bytes decode on independent connections.
        let mut shared = Vec::new();
        comp.deflate_payload(&events[0], &mut shared);
        let mut frame = Vec::new();
        write_compressed_frame(&mut frame, Opcode::Text, &shared);
        for _ in 0..3 {
            let mut other = Decoder::client(1 << 20, 1 << 20).with_deflate(&s.client_params);
            assert_eq!(run_whole(&mut other, &frame).unwrap(), vec![text(&events[0])]);
        }
        // With takeover the later messages lean on the earlier ones, so a fresh decoder fails.
        let t = session("permessage-deflate");
        let mut comp = Compressor::for_role(&t.server_params, Role::Server, 0);
        let (mut first, mut second) = (Vec::new(), Vec::new());
        comp.compress_text(&mut first, &events[0]);
        comp.compress_text(&mut second, &events[0]);
        assert!(
            second.len() * 2 < first.len(),
            "a repeat is nearly free with history: {} vs {}",
            second.len(),
            first.len()
        );
        let mut fresh = Decoder::client(1 << 20, 1 << 20).with_deflate(&t.client_params);
        assert!(run_whole(&mut fresh, &second).is_err());
        let mut both = Decoder::client(1 << 20, 1 << 20).with_deflate(&t.client_params);
        assert_eq!(run_whole(&mut both, &first).unwrap(), vec![text(&events[0])]);
        assert_eq!(run_whole(&mut both, &second).unwrap(), vec![text(&events[0])]);
        // Client side stateless: the server decoder holds no history.
        let c = session("permessage-deflate; client_no_context_takeover");
        let mut s2 = c;
        for e in &events {
            let mut wire = Vec::new();
            s2.client_text(&mut wire, e);
            assert_eq!(run_whole(&mut s2.srv_dec, &wire).unwrap(), vec![text(e)]);
        }
        assert!(s2.srv_dec.heap_bytes() < 64 * 1024, "{}", s2.srv_dec.heap_bytes());
    }

    #[test]
    fn a_megabyte_answer_uses_a_64_bit_length_and_round_trips() {
        let events = nostr_corpus(21, 1500);
        let bulk = events.concat();
        assert!(bulk.len() > 1_000_000);
        let mut s = session_with("permessage-deflate", DeflatePolicy::default(), 192, 4 << 20);
        let mut wire = Vec::new();
        s.srv_comp.compress_text(&mut wire, &bulk);
        assert_eq!(wire[0], 0xc1);
        assert!(wire.len() < bulk.len() * 7 / 10);
        assert_eq!(wire[1], 127, "compressed length above 64 KiB");
        let got = run(&mut s.cli_dec, wire.chunks(40_000)).unwrap();
        assert_eq!(got, vec![text(&bulk)]);
        // And the server can take the same from a client.
        let mut c = Vec::new();
        s.cli_comp.deflate_payload(&bulk, &mut c);
        let mut wire = Vec::new();
        s.enc.write_frame_ext(&mut wire, Opcode::Text, true, true, &c);
        assert_eq!(run_whole(&mut s.srv_dec, &wire).unwrap(), vec![text(&bulk)]);
        // Memory afterwards: message buffers bounded, history within its window.
        assert!(s.srv_dec.heap_bytes() < 100 * 1024, "{}", s.srv_dec.heap_bytes());
    }

    #[test]
    fn small_negotiated_windows_hold_to_their_limits_over_a_long_stream() {
        // 9-bit windows both ways: the receiver keeps only 512 bytes of history, so any
        // match the sender made beyond that would fail to decode.
        let events = nostr_corpus(31, 300);
        let mut s = session("permessage-deflate; server_max_window_bits=9; client_max_window_bits=9");
        assert_eq!(s.client_params.receive(Role::Client).window_bits, 9);
        assert_eq!(s.client_params.send(Role::Client).window_bits, 9);
        let mut total = (0, 0);
        for e in &events {
            let mut wire = Vec::new();
            s.srv_comp.compress_text(&mut wire, e);
            total.0 += wire.len();
            total.1 += e.len();
            assert_eq!(run_whole(&mut s.cli_dec, &wire).unwrap(), vec![text(e)]);
            let mut wire = Vec::new();
            s.client_text(&mut wire, e);
            assert_eq!(run_whole(&mut s.srv_dec, &wire).unwrap(), vec![text(e)]);
        }
        assert!(total.0 < total.1 * 85 / 100, "a 512-byte window still helps: {total:?}");
        assert!(s.cli_comp.heap_bytes() + s.srv_comp.heap_bytes() < 40 * 1024);
    }

    #[test]
    fn damaged_compressed_streams_never_panic_and_chunking_never_matters() {
        let events = nostr_corpus(41, 12);
        let mut s = session("permessage-deflate");
        let mut stream = Vec::new();
        for e in &events {
            s.client_text(&mut stream, e);
        }
        // A fragmented one too.
        let mut c = Vec::new();
        s.cli_comp.deflate_payload(&events[0], &mut c);
        s.enc.write_frame_ext(&mut stream, Opcode::Text, false, true, &c[..c.len() / 2]);
        s.enc.write_frame(&mut stream, Opcode::Continuation, true, &c[c.len() / 2..]);
        let params = s.server_params;
        let fresh = || Decoder::server(1 << 16, 1 << 16).with_deflate(&params);
        assert_eq!(run_whole(&mut fresh(), &stream).unwrap().len(), 13);

        let mut rng = Rng::new(0xFA11);
        let mut failures = 0;
        for case in 0..3000 {
            let mut data = stream.clone();
            for _ in 0..1 + rng.below(3) {
                let i = rng.below(data.len() as u64) as usize;
                data[i] ^= 1 << rng.below(8);
            }
            if rng.below(5) == 0 {
                let cut = rng.below(data.len() as u64) as usize;
                data.truncate(cut);
            }
            let whole = run_whole(&mut fresh(), &data);
            let mut chunks = Vec::new();
            let mut at = 0;
            while at < data.len() {
                let end = (at + 1 + rng.below(if case % 2 == 0 { 9 } else { 400 }) as usize).min(data.len());
                chunks.push(&data[at..end]);
                at = end;
            }
            let chunked = run(&mut fresh(), chunks);
            assert_eq!(whole, chunked, "case {case}");
            if let Err(e) = whole {
                failures += 1;
                assert!([1002, 1007, 1009].contains(&e.close_code()), "case {case}: {e}");
            }
        }
        // (Many bit flips land in literal text and decode to different but valid messages.)
        assert!(failures > 200, "{failures}");
    }

    #[test]
    fn payloads_of_every_alphabet_survive_the_wire() {
        let mut rng = Rng::new(99);
        let mut s = session_with("permessage-deflate", DeflatePolicy::default(), 0, 1 << 22);
        for n in [0usize, 1, 7, 100, 191, 192, 193, 1000, 4096, 16_383, 16_384, 16_385, 70_000, 200_000] {
            for payload in [vec![b'a'; n], crate::deflate::testutil::hex(&mut rng, n), base64(&mut rng, n)] {
                let mut wire = Vec::new();
                s.srv_comp.compress_text(&mut wire, &payload);
                assert_eq!(run_whole(&mut s.cli_dec, &wire).unwrap(), vec![text(&payload)], "len {n}");
            }
        }
    }
}
