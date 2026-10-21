//! permessage-deflate (RFC 7692): negotiation, and the per-connection compressor.
//!
//! The decompressing half lives in [`Decoder`](super::Decoder), which needs it
//! inside frame reassembly; this module owns everything else.
//!
//! **Negotiation.** [`negotiate`] reads the `Sec-WebSocket-Extensions` offers and
//! accepts the first acceptable `permessage-deflate` one under a [`DeflatePolicy`],
//! producing the [`DeflateParams`] both sides then run with. An offer is declined
//! (and the next one tried) if it has an unknown parameter, a repeated one, or a
//! value out of range (RFC 7692 section 5.1); a header that does not even parse
//! declines everything, which is always allowed and leaves the connection
//! uncompressed. Nothing here can fail a handshake.
//!
//! **What each parameter costs.** Per connection, on top of the socket buffers:
//!
//! | mode | compress (server to client) | decompress (client to server) |
//! |---|---|---|
//! | context takeover (default), 15-bit windows | up to 48 KiB: history buffer (window + one 8 KiB chunk) and an 8 KiB hash table, grown with use | up to 32 KiB: the history ring, grown with use |
//! | context takeover, 12-bit windows | up to 16 KiB (4 KiB window + 4 KiB chunk + 8 KiB table) | up to 4 KiB |
//! | context takeover, 9-bit windows | up to 5.5 KiB | up to 512 B |
//! | `server_no_context_takeover` / `client_no_context_takeover` | **0**: a thread-wide scratch is shared | **0**: nothing kept between messages |
//!
//! plus, for the decoder, its message buffers (which already existed for
//! fragmentation) while a message is in flight. A connection that has exchanged
//! little holds little in takeover mode: history is only ever as long as the data so
//! far. Window sizes: the server can always compress with a smaller window than the
//! 32 KiB default (a decoder with a bigger window reads it), so `max_server_window_bits`
//! applies to every client. The *client's* window can be limited only if the client
//! offered `client_max_window_bits`, because a response may only carry parameters the
//! offer carried; Firefox offers neither, so its stream may use the full 32 KiB and
//! the server's decompressor must keep that much.
//!
//! **Sharing work across subscribers.** With `server_no_context_takeover` every
//! message's compressed bytes depend only on the message (and the window bits), so
//! a fan-out can compress once and send the same bytes to every such connection:
//! [`Compressor::deflate_payload`] produces them and [`write_compressed_frame`]
//! frames them. With takeover each connection's stream is its own and must be
//! compressed per connection.

use super::decode::Role;
use super::encode::{begin_frame_ext, finish_frame, write_frame, write_frame_ext};
use super::Opcode;
use crate::deflate::{Deflater, Flush, SYNC_TAIL};

pub const EXTENSION_NAME: &str = "permessage-deflate";

/// What the server is willing to run. The default keeps context on both sides at the
/// full 32 KiB window: best ratio, most memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflatePolicy {
    /// Always compress server messages independently (and say so). Zero per-connection
    /// compressor memory, and one compression can serve every subscriber.
    pub server_no_context_takeover: bool,
    /// Ask clients to compress each message independently: zero per-connection
    /// decompressor memory. A client must accept this parameter even if it did not offer it.
    pub client_no_context_takeover: bool,
    /// Largest window the server will compress with (8..=15); also bounds what
    /// `server_max_window_bits` a client can ask for.
    pub max_server_window_bits: u8,
    /// Largest window the server will let the client compress with (8..=15). Only
    /// enforceable on clients that offered `client_max_window_bits`.
    pub max_client_window_bits: u8,
}

impl Default for DeflatePolicy {
    fn default() -> Self {
        DeflatePolicy {
            server_no_context_takeover: false,
            client_no_context_takeover: false,
            max_server_window_bits: 15,
            max_client_window_bits: 15,
        }
    }
}

/// One direction of a negotiated stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    /// Whether history carries over from one message to the next.
    pub context_takeover: bool,
    /// LZ77 window is `1 << window_bits` bytes.
    pub window_bits: u8,
}

/// The outcome of negotiation: what the 101 response carries and both ends run with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeflateParams {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_window_bits: u8,
    client_window_bits: u8,
    /// Whether the response names the window parameters (it may only if the offer did).
    echo_server_bits: bool,
    echo_client_bits: bool,
}

impl DeflateParams {
    /// Parameters for a client that took the server's response as is, built from the
    /// response header's parameter list. For the tests and the benchmark client.
    pub fn from_response(value: &[u8]) -> Option<DeflateParams> {
        for ext in split_outside_quotes(value, b',') {
            let mut parts = split_outside_quotes(ext, b';');
            let name = trim(parts.next()?);
            if !name.eq_ignore_ascii_case(EXTENSION_NAME.as_bytes()) {
                continue;
            }
            let o = parse_params(parts)?;
            return Some(DeflateParams {
                server_no_context_takeover: o.server_no_ct,
                client_no_context_takeover: o.client_no_ct,
                server_window_bits: o.server_bits.unwrap_or(15),
                client_window_bits: o.client_bits.flatten().unwrap_or(15),
                echo_server_bits: o.server_bits.is_some(),
                echo_client_bits: o.client_bits.flatten().is_some(),
            });
        }
        None
    }

    /// The stream this endpoint *sends* on: the server compresses with the server
    /// parameters, a client with the client ones.
    pub fn send(&self, role: Role) -> StreamConfig {
        match role {
            Role::Server => StreamConfig {
                context_takeover: !self.server_no_context_takeover,
                window_bits: self.server_window_bits,
            },
            Role::Client => StreamConfig {
                context_takeover: !self.client_no_context_takeover,
                window_bits: self.client_window_bits,
            },
        }
    }

    /// The stream this endpoint *receives*: the other side's.
    pub fn receive(&self, role: Role) -> StreamConfig {
        match role {
            Role::Server => self.send(Role::Client),
            Role::Client => self.send(Role::Server),
        }
    }

    /// Appends the response header's value, e.g. `permessage-deflate; client_max_window_bits=10`.
    pub fn write_response_value(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(EXTENSION_NAME.as_bytes());
        if self.server_no_context_takeover {
            out.extend_from_slice(b"; server_no_context_takeover");
        }
        if self.client_no_context_takeover {
            out.extend_from_slice(b"; client_no_context_takeover");
        }
        if self.echo_server_bits {
            out.extend_from_slice(b"; server_max_window_bits=");
            push_bits(out, self.server_window_bits);
        }
        if self.echo_client_bits {
            out.extend_from_slice(b"; client_max_window_bits=");
            push_bits(out, self.client_window_bits);
        }
    }
}

fn push_bits(out: &mut Vec<u8>, bits: u8) {
    if bits >= 10 {
        out.push(b'1');
    }
    out.push(b'0' + bits % 10);
}

// ---- header parsing ----

fn trim(s: &[u8]) -> &[u8] {
    s.trim_ascii()
}

/// Splits on `sep` except inside double quotes.
fn split_outside_quotes(s: &[u8], sep: u8) -> impl Iterator<Item = &[u8]> {
    let mut rest = Some(s);
    std::iter::from_fn(move || {
        let r = rest?;
        let mut in_quotes = false;
        let mut escaped = false;
        for (i, &b) in r.iter().enumerate() {
            if escaped {
                escaped = false;
            } else if in_quotes && b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_quotes = !in_quotes;
            } else if b == sep && !in_quotes {
                rest = Some(&r[i + 1..]);
                return Some(&r[..i]);
            }
        }
        rest = None;
        Some(r)
    })
}

fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// A parameter value: a token, or a quoted string without escapes (none of the
/// parameters here has a use for them).
fn param_value(v: &[u8]) -> Option<&[u8]> {
    let v = trim(v);
    if let Some(inner) = v.strip_prefix(b"\"").and_then(|r| r.strip_suffix(b"\"")) {
        return (!inner.contains(&b'\\') && !inner.contains(&b'"')).then_some(inner);
    }
    is_token(v).then_some(v)
}

/// A window-bits value: decimal 8..=15 with no sign or leading zeros (RFC 7692 section 7.1.2).
fn window_bits(v: &[u8]) -> Option<u8> {
    match v {
        [a @ b'8'..=b'9'] => Some(a - b'0'),
        [b'1', b @ b'0'..=b'5'] => Some(10 + (b - b'0')),
        _ => None,
    }
}

/// An offer's parameters, validated syntactically.
#[derive(Default)]
struct Offer {
    server_no_ct: bool,
    client_no_ct: bool,
    server_bits: Option<u8>,
    /// `None`: absent; `Some(None)`: present without a value (support, no preference).
    client_bits: Option<Option<u8>>,
}

/// Parses `name[=value]` items; `None` if any is malformed, unknown, repeated or out of range.
fn parse_params<'a>(items: impl Iterator<Item = &'a [u8]>) -> Option<Offer> {
    let mut o = Offer::default();
    let (mut seen_snct, mut seen_cnct) = (false, false);
    for item in items {
        let item = trim(item);
        let (name, value) = match item.iter().position(|&b| b == b'=') {
            Some(i) => (trim(&item[..i]), Some(param_value(&item[i + 1..])?)),
            None => (item, None),
        };
        if !is_token(name) {
            return None;
        }
        let is = |s: &str| name.eq_ignore_ascii_case(s.as_bytes());
        if is("server_no_context_takeover") {
            if value.is_some() || std::mem::replace(&mut seen_snct, true) {
                return None;
            }
            o.server_no_ct = true;
        } else if is("client_no_context_takeover") {
            if value.is_some() || std::mem::replace(&mut seen_cnct, true) {
                return None;
            }
            o.client_no_ct = true;
        } else if is("server_max_window_bits") {
            if o.server_bits.is_some() {
                return None;
            }
            o.server_bits = Some(window_bits(value?)?);
        } else if is("client_max_window_bits") {
            if o.client_bits.is_some() {
                return None;
            }
            o.client_bits = Some(match value {
                Some(v) => Some(window_bits(v)?),
                None => None,
            });
        } else {
            return None;
        }
    }
    Some(o)
}

/// Picks the first acceptable `permessage-deflate` offer among the `Sec-WebSocket-Extensions`
/// header values and decides the parameters (see the module docs for the rules).
pub fn negotiate<'a>(headers: impl Iterator<Item = &'a [u8]>, policy: &DeflatePolicy) -> Option<DeflateParams> {
    let clamp = |b: u8| b.clamp(8, 15);
    for value in headers {
        for ext in split_outside_quotes(value, b',') {
            let mut parts = split_outside_quotes(ext, b';');
            let Some(name) = parts.next() else { continue };
            if !trim(name).eq_ignore_ascii_case(EXTENSION_NAME.as_bytes()) {
                continue;
            }
            let Some(offer) = parse_params(parts) else { continue };

            let server_bits = clamp(policy.max_server_window_bits).min(offer.server_bits.unwrap_or(15));
            let (client_bits, echo_client_bits) = match offer.client_bits {
                // Not offered: the response may not mention it, so the client keeps 15.
                None => (15, false),
                Some(preferred) => {
                    let bits = clamp(policy.max_client_window_bits).min(preferred.unwrap_or(15));
                    // Name it when it limits anything: a value the client gave, or a policy cap.
                    (bits, preferred.is_some() || bits < 15)
                }
            };
            return Some(DeflateParams {
                server_no_context_takeover: offer.server_no_ct || policy.server_no_context_takeover,
                client_no_context_takeover: offer.client_no_ct || policy.client_no_context_takeover,
                server_window_bits: server_bits,
                client_window_bits: client_bits,
                echo_server_bits: offer.server_bits.is_some(),
                echo_client_bits,
            });
        }
    }
    None
}

// ---- compressor ----

/// Per-connection message compressor.
///
/// Small messages are sent uncompressed: below `min_len` bytes the sync marker, the
/// block header and the call overhead cost more than they save. A message sent
/// uncompressed never enters the compressor's history, because the peer's decompressor
/// never sees it either; history must contain exactly what the peer's window will.
pub struct Compressor {
    df: Deflater,
    min_len: usize,
}

impl Compressor {
    /// Below this many payload bytes a message goes out uncompressed unless the caller
    /// chooses otherwise.
    pub const DEFAULT_MIN_LEN: usize = 192;

    pub fn new(cfg: StreamConfig, min_len: usize) -> Compressor {
        Compressor { df: Deflater::new(cfg.window_bits, cfg.context_takeover), min_len }
    }

    /// The compressor for `role`'s sending direction.
    pub fn for_role(params: &DeflateParams, role: Role, min_len: usize) -> Compressor {
        Compressor::new(params.send(role), min_len)
    }

    pub fn min_len(&self) -> usize {
        self.min_len
    }

    /// Whether a payload of `len` bytes would be compressed.
    pub fn will_compress(&self, len: usize) -> bool {
        len >= self.min_len
    }

    /// Heap this connection's compressor holds between messages (0 without context takeover).
    pub fn heap_bytes(&self) -> usize {
        self.df.heap_bytes()
    }

    /// Frees the history; the next message starts a new window on both sides' view,
    /// so only call it when the peer will do the same (it won't: use sparingly, for
    /// connections that are about to close).
    pub fn release(&mut self) {
        self.df.release();
    }

    /// Appends the compressed form of `payload` (RFC 7692 section 7.2.1): a sync-flushed
    /// DEFLATE stream with the trailing `00 00 ff ff` removed. Always compresses; the
    /// threshold is for [`compress_frame`](Self::compress_frame). Updates the history.
    pub fn deflate_payload(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        self.df.deflate(payload, out, Flush::Sync);
        debug_assert!(out.len() >= start + 4 && out[out.len() - 4..] == SYNC_TAIL);
        out.truncate(out.len().saturating_sub(4).max(start));
    }

    /// Appends a complete server frame for `payload`: compressed with RSV1 set, or
    /// plain when the payload is under the threshold.
    pub fn compress_frame(&mut self, out: &mut Vec<u8>, opcode: Opcode, payload: &[u8]) {
        if !self.will_compress(payload.len()) {
            write_frame(out, opcode, true, payload);
            return;
        }
        let mark = begin_frame_ext(out, opcode, true, true);
        self.deflate_payload(payload, out);
        finish_frame(out, mark);
    }

    /// A text message (`payload` must be valid UTF-8, as for [`write_text`](super::write_text)).
    pub fn compress_text(&mut self, out: &mut Vec<u8>, payload: &[u8]) {
        self.compress_frame(out, Opcode::Text, payload);
    }

    pub fn compress_binary(&mut self, out: &mut Vec<u8>, payload: &[u8]) {
        self.compress_frame(out, Opcode::Binary, payload);
    }
}

/// Frames an already-compressed payload (from [`Compressor::deflate_payload`]) as a
/// server frame with RSV1 set.
pub fn write_compressed_frame(out: &mut Vec<u8>, opcode: Opcode, compressed: &[u8]) {
    write_frame_ext(out, opcode, true, true, compressed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn neg(header: &str, policy: &DeflatePolicy) -> Option<String> {
        negotiate([header.as_bytes()].into_iter(), policy).map(|p| {
            let mut v = Vec::new();
            p.write_response_value(&mut v);
            String::from_utf8(v).unwrap()
        })
    }

    fn default_neg(header: &str) -> Option<String> {
        neg(header, &DeflatePolicy::default())
    }

    #[test]
    fn real_browser_offers() {
        // Chrome, Edge, Safari: ask for the parameter without a value.
        assert_eq!(default_neg("permessage-deflate; client_max_window_bits").unwrap(), "permessage-deflate");
        // Firefox: bare.
        assert_eq!(default_neg("permessage-deflate").unwrap(), "permessage-deflate");
        // The `ws` library for Node and websocat-style clients.
        assert_eq!(
            default_neg("permessage-deflate; client_max_window_bits=15; server_max_window_bits=15").unwrap(),
            "permessage-deflate; server_max_window_bits=15; client_max_window_bits=15"
        );
        // Older Chrome also offered x-webkit-deflate-frame first.
        assert_eq!(
            default_neg("x-webkit-deflate-frame, permessage-deflate; client_max_window_bits").unwrap(),
            "permessage-deflate"
        );
    }

    #[test]
    fn client_requests_are_honoured() {
        assert_eq!(
            default_neg("permessage-deflate; server_no_context_takeover; client_no_context_takeover").unwrap(),
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
        );
        assert_eq!(
            default_neg("permessage-deflate; server_max_window_bits=10").unwrap(),
            "permessage-deflate; server_max_window_bits=10"
        );
        assert_eq!(
            default_neg("permessage-deflate; client_max_window_bits=9").unwrap(),
            "permessage-deflate; client_max_window_bits=9"
        );
        // Quoted values and odd casing and spacing.
        assert_eq!(
            default_neg("Permessage-Deflate ;Server_Max_Window_Bits=\"11\" ;  CLIENT_NO_CONTEXT_TAKEOVER").unwrap(),
            "permessage-deflate; client_no_context_takeover; server_max_window_bits=11"
        );
    }

    #[test]
    fn policy_can_force_modes_and_caps() {
        let p =
            DeflatePolicy { server_no_context_takeover: true, client_no_context_takeover: true, ..Default::default() };
        // Forcing takeover off works even for a client that offered nothing.
        assert_eq!(
            neg("permessage-deflate", &p).unwrap(),
            "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
        );
        // A policy cap on the server window needs no mention: it is only a promise about
        // how much of the client's window we use, and a client that did not ask need not be told.
        let p = DeflatePolicy { max_server_window_bits: 11, max_client_window_bits: 10, ..Default::default() };
        assert_eq!(neg("permessage-deflate", &p).unwrap(), "permessage-deflate");
        let params = negotiate([&b"permessage-deflate"[..]].into_iter(), &p).unwrap();
        assert_eq!(params.send(Role::Server).window_bits, 11, "we still compress with the smaller window");
        assert_eq!(params.receive(Role::Server).window_bits, 15, "but the client was never told to limit its own");
        // A client that offered client_max_window_bits can be capped.
        assert_eq!(
            neg("permessage-deflate; client_max_window_bits", &p).unwrap(),
            "permessage-deflate; client_max_window_bits=10"
        );
        // A client's own smaller ask wins over a larger cap.
        assert_eq!(
            neg("permessage-deflate; client_max_window_bits=9; server_max_window_bits=9", &p).unwrap(),
            "permessage-deflate; server_max_window_bits=9; client_max_window_bits=9"
        );
        // And the policy wins over a larger ask.
        assert_eq!(
            neg("permessage-deflate; server_max_window_bits=14", &p).unwrap(),
            "permessage-deflate; server_max_window_bits=11"
        );
        // Out-of-range policy values are clamped to what the RFC allows.
        let p = DeflatePolicy { max_server_window_bits: 3, max_client_window_bits: 99, ..Default::default() };
        let params = negotiate([&b"permessage-deflate; server_max_window_bits=12"[..]].into_iter(), &p).unwrap();
        assert_eq!(params.send(Role::Server).window_bits, 8);
        assert_eq!(params.receive(Role::Server).window_bits, 15);
    }

    #[test]
    fn invalid_offers_are_declined_and_the_next_is_tried() {
        for bad in [
            "permessage-deflate; unknown_param",
            "permessage-deflate; server_no_context_takeover; server_no_context_takeover",
            "permessage-deflate; server_no_context_takeover=1",
            "permessage-deflate; server_max_window_bits",
            "permessage-deflate; server_max_window_bits=7",
            "permessage-deflate; server_max_window_bits=16",
            "permessage-deflate; server_max_window_bits=08",
            "permessage-deflate; server_max_window_bits=+9",
            "permessage-deflate; server_max_window_bits=9; server_max_window_bits=9",
            "permessage-deflate; client_max_window_bits=abc",
            "permessage-deflate; client_max_window_bits=9; client_max_window_bits",
            "permessage-deflate; =5",
            "permessage-deflate; server_max_window_bits=\"9",
            "permessage-deflate;; client_no_context_takeover",
        ] {
            assert_eq!(default_neg(bad), None, "{bad:?}");
            // A later acceptable offer is taken (unless an open quote swallowed the comma).
            let combined = default_neg(&format!("{bad}, permessage-deflate; client_max_window_bits"));
            if bad.matches('"').count() % 2 == 0 {
                assert_eq!(combined.unwrap(), "permessage-deflate", "{bad:?}");
            } else {
                assert_eq!(combined, None, "{bad:?}");
            }
        }
        for none in ["", "gzip", "x-webkit-deflate-frame", "permessage-deflate-v2", "permessage"] {
            assert_eq!(default_neg(none), None, "{none:?}");
        }
    }

    #[test]
    fn several_header_lines_are_one_list() {
        let h1 = b"x-unknown";
        let h2 = b"permessage-deflate; client_max_window_bits";
        let p = negotiate([&h1[..], &h2[..]].into_iter(), &DeflatePolicy::default()).unwrap();
        assert_eq!(p.send(Role::Server), StreamConfig { context_takeover: true, window_bits: 15 });
        // Commas inside quotes do not split offers.
        assert!(default_neg("permessage-deflate; server_max_window_bits=\"1,0\"").is_none());
    }

    #[test]
    fn roles_see_opposite_directions() {
        let p = negotiate(
            [&b"permessage-deflate; server_no_context_takeover; client_max_window_bits=9"[..]].into_iter(),
            &DeflatePolicy::default(),
        )
        .unwrap();
        let s = StreamConfig { context_takeover: false, window_bits: 15 };
        let c = StreamConfig { context_takeover: true, window_bits: 9 };
        assert_eq!(p.send(Role::Server), s);
        assert_eq!(p.receive(Role::Client), s);
        assert_eq!(p.send(Role::Client), c);
        assert_eq!(p.receive(Role::Server), c);
    }

    #[test]
    fn response_round_trips_through_the_client_parser() {
        let policies = [
            DeflatePolicy::default(),
            DeflatePolicy { server_no_context_takeover: true, ..Default::default() },
            DeflatePolicy { max_client_window_bits: 9, max_server_window_bits: 12, ..Default::default() },
        ];
        let offers = [
            "permessage-deflate",
            "permessage-deflate; client_max_window_bits",
            "permessage-deflate; client_max_window_bits=12; server_max_window_bits=10; client_no_context_takeover",
            "permessage-deflate; server_no_context_takeover",
        ];
        for policy in &policies {
            for offer in offers {
                let p = negotiate([offer.as_bytes()].into_iter(), policy).unwrap();
                let mut v = Vec::new();
                p.write_response_value(&mut v);
                let back = DeflateParams::from_response(&v).unwrap();
                // What the client learns from the header must give it the same two streams
                // (the server may use a smaller server window than it announces, never the reverse).
                assert_eq!(back.receive(Role::Client).context_takeover, p.send(Role::Server).context_takeover);
                assert_eq!(back.send(Role::Client), p.receive(Role::Server), "{offer} under {policy:?}");
                assert!(p.send(Role::Server).window_bits <= back.receive(Role::Client).window_bits);
            }
        }
        assert!(DeflateParams::from_response(b"permessage-deflate; bogus").is_none());
        assert!(DeflateParams::from_response(b"other").is_none());
    }

    #[test]
    fn window_bits_text() {
        let mut v = Vec::new();
        for b in 8..=15u8 {
            v.clear();
            push_bits(&mut v, b);
            assert_eq!(window_bits(&v), Some(b));
        }
        for bad in ["", "7", "16", "1", "100", "08", "-9", "9 ", "0x9"] {
            assert_eq!(window_bits(bad.as_bytes()), None, "{bad:?}");
        }
    }
}
