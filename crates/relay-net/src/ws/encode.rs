//! Frame writers.
//!
//! Server-to-client frames are unmasked and appended to a caller-owned `Vec<u8>`,
//! so a reactor can queue many messages and flush them with one write. Two ways to
//! write a message:
//!
//! * [`write_text`] and friends when the payload already exists as a slice.
//! * [`begin_text`] / [`finish_text`] when the payload is being *built*: the relay
//!   appends `["EVENT","sub",<event>]` piece by piece straight into the output
//!   buffer. The length is unknown until the end, so `begin` reserves a 4-byte
//!   header (2 bytes of framing plus the 16-bit length: right for 126..=65535
//!   byte payloads, which is nearly every Nostr message) and `finish` patches it.
//!   Only a message outside that range pays for a move: a short one slides left by
//!   two bytes (at most 125 bytes of memmove) and a 64 KiB+ one slides right by six.
//!
//! [`ClientEncoder`] writes masked frames for the benchmark client and the tests.

use super::unmask::unmask;
use super::Opcode;

/// Largest possible header: 2 bytes + 8-byte length (server frames carry no mask).
const MAX_HEADER: usize = 10;
/// Header bytes reserved by `begin_*`: the 16-bit length form.
const RESERVED: usize = 4;

/// Header size for a payload of `len` bytes.
#[inline]
pub const fn header_len(len: usize) -> usize {
    if len < 126 {
        2
    } else if len <= 0xFFFF {
        4
    } else {
        10
    }
}

#[inline]
const fn first_byte(opcode: Opcode, fin: bool) -> u8 {
    (opcode as u8) | if fin { 0x80 } else { 0 }
}

/// Writes the unmasked header for `len` payload bytes into `h`, returning its size.
#[inline]
fn encode_header(first: u8, len: usize, h: &mut [u8; MAX_HEADER]) -> usize {
    h[0] = first;
    if len < 126 {
        h[1] = len as u8;
        2
    } else if len <= 0xFFFF {
        h[1] = 126;
        h[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        4
    } else {
        h[1] = 127;
        h[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        10
    }
}

/// Appends an unmasked frame header announcing `payload_len` bytes to follow.
#[inline]
pub fn write_frame_header(out: &mut Vec<u8>, opcode: Opcode, fin: bool, payload_len: usize) {
    let mut h = [0u8; MAX_HEADER];
    let n = encode_header(first_byte(opcode, fin), payload_len, &mut h);
    out.extend_from_slice(&h[..n]);
}

/// Appends a complete unmasked frame.
#[inline]
pub fn write_frame(out: &mut Vec<u8>, opcode: Opcode, fin: bool, payload: &[u8]) {
    out.reserve(MAX_HEADER + payload.len());
    write_frame_header(out, opcode, fin, payload.len());
    out.extend_from_slice(payload);
}

/// A text message. `payload` must be valid UTF-8; the relay's JSON always is, and
/// re-validating on the hot path would buy nothing.
#[inline]
pub fn write_text(out: &mut Vec<u8>, payload: &[u8]) {
    write_frame(out, Opcode::Text, true, payload);
}

#[inline]
pub fn write_binary(out: &mut Vec<u8>, payload: &[u8]) {
    write_frame(out, Opcode::Binary, true, payload);
}

/// A ping. Control payloads are capped at 125 bytes; longer input is truncated.
pub fn write_ping(out: &mut Vec<u8>, payload: &[u8]) {
    write_frame(out, Opcode::Ping, true, &payload[..payload.len().min(125)]);
}

/// A pong, normally echoing a ping's payload (already <= 125 bytes).
pub fn write_pong(out: &mut Vec<u8>, payload: &[u8]) {
    write_frame(out, Opcode::Pong, true, &payload[..payload.len().min(125)]);
}

/// Longest prefix of `reason` that fits a close frame (125 - 2 code bytes) without
/// cutting a UTF-8 sequence.
fn clip_reason(reason: &str) -> &[u8] {
    let mut n = reason.len().min(123);
    while !reason.is_char_boundary(n) {
        n -= 1;
    }
    &reason.as_bytes()[..n]
}

/// A close frame with a status code and a (clipped to fit) reason.
pub fn write_close(out: &mut Vec<u8>, code: u16, reason: &str) {
    let reason = clip_reason(reason);
    write_frame_header(out, Opcode::Close, true, 2 + reason.len());
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(reason);
}

/// A close frame with no status, for answering a peer's empty close.
pub fn write_close_empty(out: &mut Vec<u8>) {
    write_frame_header(out, Opcode::Close, true, 0);
}

/// Where a frame under construction starts in the output buffer. An index, not a
/// pointer, so the buffer can grow freely while the payload is appended.
#[derive(Debug, Clone, Copy)]
#[must_use = "a frame begun but never finished leaves a placeholder header in the buffer"]
pub struct Mark {
    start: usize,
    first: u8,
}

/// Starts a frame whose length is not yet known: reserves its header. Append the
/// payload to `out`, then call [`finish_frame`] with the returned mark.
#[inline]
pub fn begin_frame(out: &mut Vec<u8>, opcode: Opcode, fin: bool) -> Mark {
    let start = out.len();
    out.extend_from_slice(&[0; RESERVED]);
    Mark { start, first: first_byte(opcode, fin) }
}

/// Completes a frame started with [`begin_frame`]: everything appended since is
/// its payload. Nothing else may have been appended to `out` between the `begin`
/// and this call except that payload.
#[inline]
pub fn finish_frame(out: &mut Vec<u8>, mark: Mark) {
    let payload_start = mark.start + RESERVED;
    debug_assert!(out.len() >= payload_start, "buffer shrank below the reserved header");
    let len = out.len() - payload_start;
    let mut h = [0u8; MAX_HEADER];
    let n = encode_header(mark.first, len, &mut h);
    if n < RESERVED {
        // Short payload: close the gap the reserved header left.
        out.copy_within(payload_start.., mark.start + n);
        out.truncate(mark.start + n + len);
    } else if n > RESERVED {
        // 64 KiB or more: make room for the 10-byte header.
        out.resize(out.len() + (n - RESERVED), 0);
        out.copy_within(payload_start..payload_start + len, mark.start + n);
    }
    out[mark.start..mark.start + n].copy_from_slice(&h[..n]);
}

#[inline]
pub fn begin_text(out: &mut Vec<u8>) -> Mark {
    begin_frame(out, Opcode::Text, true)
}

#[inline]
pub fn finish_text(out: &mut Vec<u8>, mark: Mark) {
    finish_frame(out, mark);
}

#[inline]
pub fn begin_binary(out: &mut Vec<u8>) -> Mark {
    begin_frame(out, Opcode::Binary, true)
}

#[inline]
pub fn finish_binary(out: &mut Vec<u8>, mark: Mark) {
    finish_frame(out, mark);
}

/// Writes masked client frames, for the benchmark client and the tests.
///
/// RFC 6455 asks for masks a hostile script cannot predict, to defeat cache
/// poisoning through a confused proxy. That threat is about browsers talking
/// through proxies; this encoder only ever drives our own server and test
/// harnesses, so masks come from a fast xorshift generator seeded from the clock
/// and a process-wide counter. Do not use it where the mask must be unpredictable.
pub struct ClientEncoder {
    state: u64,
}

impl Default for ClientEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientEncoder {
    /// Seeded from the clock, so independent encoders produce different masks.
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = u64::from(std::process::id());
        Self::with_seed(nanos ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (pid << 32))
    }

    /// Deterministic masks, for reproducible tests.
    pub fn with_seed(seed: u64) -> Self {
        // SplitMix64 finaliser, so small seeds still give well-mixed state, and
        // never zero (xorshift's one fixed point).
        let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        ClientEncoder { state: if z == 0 { 0x2545_F491_4F6C_DD1D } else { z } }
    }

    /// xorshift64*.
    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    #[inline]
    fn next_mask(&mut self) -> [u8; 4] {
        ((self.next_u64() >> 32) as u32).to_le_bytes()
    }

    /// Fills `buf` with generator output (the handshake key uses this).
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let r = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
    }

    /// Appends one masked frame.
    pub fn write_frame(&mut self, out: &mut Vec<u8>, opcode: Opcode, fin: bool, payload: &[u8]) {
        let mask = self.next_mask();
        let mut h = [0u8; MAX_HEADER];
        let n = encode_header(first_byte(opcode, fin), payload.len(), &mut h);
        h[1] |= 0x80;
        out.reserve(n + 4 + payload.len());
        out.extend_from_slice(&h[..n]);
        out.extend_from_slice(&mask);
        let start = out.len();
        out.extend_from_slice(payload);
        unmask(&mut out[start..], mask, 0);
    }

    pub fn write_text(&mut self, out: &mut Vec<u8>, payload: &[u8]) {
        self.write_frame(out, Opcode::Text, true, payload);
    }

    pub fn write_binary(&mut self, out: &mut Vec<u8>, payload: &[u8]) {
        self.write_frame(out, Opcode::Binary, true, payload);
    }

    pub fn write_ping(&mut self, out: &mut Vec<u8>, payload: &[u8]) {
        self.write_frame(out, Opcode::Ping, true, &payload[..payload.len().min(125)]);
    }

    pub fn write_pong(&mut self, out: &mut Vec<u8>, payload: &[u8]) {
        self.write_frame(out, Opcode::Pong, true, &payload[..payload.len().min(125)]);
    }

    pub fn write_close(&mut self, out: &mut Vec<u8>, code: u16, reason: &str) {
        let reason = clip_reason(reason);
        let mut p = Vec::with_capacity(2 + reason.len());
        p.extend_from_slice(&code.to_be_bytes());
        p.extend_from_slice(reason);
        self.write_frame(out, Opcode::Close, true, &p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_server_frames_byte_for_byte() {
        let mut out = Vec::new();
        write_text(&mut out, b"Hello");
        assert_eq!(out, [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);

        let mut out = Vec::new();
        write_pong(&mut out, b"Hello");
        assert_eq!(out, [0x8a, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);

        let mut out = Vec::new();
        write_ping(&mut out, b"Hello");
        assert_eq!(out, [0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);

        // Fragmented "Hel" + "lo".
        let mut out = Vec::new();
        write_frame(&mut out, Opcode::Text, false, b"Hel");
        write_frame(&mut out, Opcode::Continuation, true, b"lo");
        assert_eq!(out, [0x01, 0x03, 0x48, 0x65, 0x6c, 0x80, 0x02, 0x6c, 0x6f]);
    }

    #[test]
    fn header_forms() {
        let mut out = Vec::new();
        write_frame_header(&mut out, Opcode::Binary, true, 256);
        assert_eq!(out, [0x82, 0x7e, 0x01, 0x00]);

        let mut out = Vec::new();
        write_frame_header(&mut out, Opcode::Binary, true, 65536);
        assert_eq!(out, [0x82, 0x7f, 0, 0, 0, 0, 0, 1, 0, 0]);

        let mut out = Vec::new();
        write_frame_header(&mut out, Opcode::Text, true, 125);
        write_frame_header(&mut out, Opcode::Text, true, 126);
        write_frame_header(&mut out, Opcode::Text, true, 65535);
        assert_eq!(out, [0x81, 125, 0x81, 126, 0, 126, 0x81, 126, 0xff, 0xff]);

        assert_eq!(header_len(125), 2);
        assert_eq!(header_len(126), 4);
        assert_eq!(header_len(65535), 4);
        assert_eq!(header_len(65536), 10);
    }

    #[test]
    fn close_frame_layout_and_clipping() {
        let mut out = Vec::new();
        write_close(&mut out, 1000, "bye");
        assert_eq!(out, [0x88, 5, 0x03, 0xe8, b'b', b'y', b'e']);

        let mut out = Vec::new();
        write_close_empty(&mut out);
        assert_eq!(out, [0x88, 0]);

        // A long reason is clipped to 123 bytes so the frame stays a legal control frame.
        let mut out = Vec::new();
        write_close(&mut out, 1001, &"r".repeat(500));
        assert_eq!(out[1], 125);
        assert_eq!(out.len(), 2 + 125);

        // ...and never in the middle of a multi-byte character (each is 2 bytes here).
        let reason: String = std::iter::repeat_n('\u{e9}', 100).collect();
        let mut out = Vec::new();
        write_close(&mut out, 1001, &reason);
        assert_eq!(out[1] as usize, 2 + 122);
        assert!(std::str::from_utf8(&out[4..]).is_ok());
    }

    #[test]
    fn control_payloads_are_capped() {
        let mut out = Vec::new();
        write_ping(&mut out, &[1u8; 300]);
        assert_eq!(out.len(), 2 + 125);
        let mut out = Vec::new();
        write_pong(&mut out, &[1u8; 300]);
        assert_eq!(out.len(), 2 + 125);
    }

    #[test]
    fn finish_only_moves_when_the_header_guess_was_wrong() {
        // 126..=65535: the reserved 4 bytes are exactly right.
        let mut out = Vec::new();
        let mark = begin_text(&mut out);
        out.extend_from_slice(&[b'a'; 1000]);
        finish_text(&mut out, mark);
        assert_eq!(&out[..4], [0x81, 126, 0x03, 0xe8]);
        assert_eq!(out.len(), 1004);
        // Short.
        let mut out = Vec::new();
        let mark = begin_text(&mut out);
        out.extend_from_slice(b"hi");
        finish_text(&mut out, mark);
        assert_eq!(out, [0x81, 2, b'h', b'i']);
        // Empty.
        let mut out = Vec::new();
        let mark = begin_text(&mut out);
        finish_text(&mut out, mark);
        assert_eq!(out, [0x81, 0]);
    }

    #[test]
    fn several_frames_built_in_one_buffer() {
        let mut out = Vec::new();
        let mut want = Vec::new();
        for (i, n) in [3usize, 500, 70_000, 0, 126].into_iter().enumerate() {
            let p = vec![b'a' + i as u8; n];
            let mark = begin_text(&mut out);
            out.extend_from_slice(&p);
            finish_text(&mut out, mark);
            write_text(&mut want, &p);
        }
        assert_eq!(out, want);
    }

    #[test]
    fn client_frames_are_masked_and_round_trip_through_unmask() {
        let mut enc = ClientEncoder::with_seed(1);
        let mut out = Vec::new();
        enc.write_text(&mut out, b"Hello");
        assert_eq!(out[0], 0x81);
        assert_eq!(out[1], 0x80 | 5);
        let mask = [out[2], out[3], out[4], out[5]];
        let mut payload = out[6..].to_vec();
        assert_ne!(payload, b"Hello", "payload must be masked on the wire");
        unmask(&mut payload, mask, 0);
        assert_eq!(payload, b"Hello");
    }

    #[test]
    fn client_header_forms() {
        let mut enc = ClientEncoder::with_seed(2);
        for (n, hdr) in [(125usize, 2usize), (126, 4), (65535, 4), (65536, 10)] {
            let mut out = Vec::new();
            enc.write_binary(&mut out, &vec![0u8; n]);
            assert_eq!(out.len(), hdr + 4 + n, "payload {n}");
            assert_eq!(out[1] & 0x80, 0x80);
        }
    }

    #[test]
    fn masks_vary_and_seeds_are_reproducible() {
        let mut a = ClientEncoder::with_seed(10);
        let mut b = ClientEncoder::with_seed(10);
        let mut c = ClientEncoder::with_seed(11);
        let (mut oa, mut ob, mut oc) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..4 {
            a.write_text(&mut oa, b"same");
            b.write_text(&mut ob, b"same");
            c.write_text(&mut oc, b"same");
        }
        assert_eq!(oa, ob);
        assert_ne!(oa, oc);
        // Consecutive frames from one encoder use different masks.
        let masks: Vec<[u8; 4]> = oa.chunks(2 + 4 + 4).map(|f| [f[2], f[3], f[4], f[5]]).collect();
        assert!(masks.windows(2).all(|w| w[0] != w[1]));
    }

    #[test]
    fn clock_seeded_encoders_differ() {
        let mut a = ClientEncoder::new();
        let mut b = ClientEncoder::new();
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn fill_covers_odd_lengths() {
        let mut enc = ClientEncoder::with_seed(3);
        for n in [0, 1, 7, 8, 9, 16, 17] {
            let mut buf = vec![0u8; n];
            enc.fill(&mut buf);
            if n >= 8 {
                assert!(buf.iter().any(|&b| b != 0));
            }
        }
    }
}
