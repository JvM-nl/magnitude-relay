//! relay-net: HTTP request and response heads, the WebSocket frame decoder in
//! every state (fragments, control frames between them, compression with and
//! without history), the inflater against miniz_oxide, and the handshake's
//! extension negotiation.

use super::{fp, fp_str, linear_cap, Target};
use crate::rng::Rng;
use crate::wsframe::{self, Frame};
use relay_net::http::{self, ExtensionPolicy, Extensions};
use relay_net::ws::{pmd, DeflateParams, Decoder, Event, Role};

const HTTP_DICT: &[&[u8]] = &[
    b"GET ", b" HTTP/1.1\r\n", b"HTTP/1.0", b"\r\n", b"\n", b"\r\n\r\n", b"Upgrade: websocket\r\n", b"Connection: Upgrade\r\n",
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", b"Sec-WebSocket-Version: 13\r\n",
    b"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n", b"server_no_context_takeover",
    b"client_max_window_bits=8", b"server_max_window_bits=\"10\"", b"Accept: application/nostr+json\r\n", b"Content-Length: 5\r\n",
    b"Transfer-Encoding: chunked\r\n", b"X-Real-IP: 1.2.3.4\r\n", b" \t", b":", b",", b";", b"\"",
];

pub fn targets() -> Vec<Target> {
    vec![
        Target { name: "http_request", run: http_request, seeds: http_seeds, generate: gen_http, dict: HTTP_DICT, max_len: 16 << 10, mem_cap: linear_cap },
        Target { name: "http_response", run: http_response, seeds: response_seeds, generate: gen_response, dict: HTTP_DICT, max_len: 16 << 10, mem_cap: linear_cap },
        Target { name: "ws_decode", run: ws_decode, seeds: ws_seeds, generate: gen_ws, dict: &[b"\x81", b"\x01", b"\x80", b"\x88", b"\x89", b"\x8a", b"\xc1", b"\x41", b"\xfe\x00\x00", b"\xff\x7f\xff\xff\xff\xff\xff\xff\xff"], max_len: 256 << 10, mem_cap: ws_cap },
        Target { name: "inflate", run: inflate, seeds: inflate_seeds, generate: gen_inflate, dict: &[b"\x00\x00\xff\xff", b"\x01", b"\x03\x00", b"\xed\xc1"], max_len: 64 << 10, mem_cap: inflate_cap },
        Target { name: "deflate_roundtrip", run: deflate_roundtrip, seeds: roundtrip_seeds, generate: gen_plain, dict: &[], max_len: 256 << 10, mem_cap: roundtrip_cap },
        Target { name: "pmd_negotiate", run: pmd_negotiate, seeds: pmd_seeds, generate: gen_pmd, dict: HTTP_DICT, max_len: 4096, mem_cap: linear_cap },
        Target { name: "base64", run: base64, seeds: || vec![b"dGhlIHNhbXBsZSBub25jZQ==".to_vec()], generate: gen_b64, dict: &[b"=", b"==", b"+/"], max_len: 4096, mem_cap: linear_cap },
    ]
}

/// The decoder's message limits in this target, and what a whole stream may hold.
const MAX_FRAME: usize = 16 << 10;
const MAX_MESSAGE: usize = 64 << 10;

fn ws_cap(len: usize) -> usize {
    // Reassembly and inflate buffers (a message each, with slack), the 32 KiB
    // window, the inflater's scratch, and the target's own copies of the input.
    (4 << 20) + 8 * len
}

fn inflate_cap(_: usize) -> usize {
    // Output is capped at INFLATE_LIMIT, and miniz's output too.
    (8 << 20) + 4 * INFLATE_LIMIT
}

fn roundtrip_cap(len: usize) -> usize {
    (8 << 20) + 16 * len
}

// ---------------------------------------------------------------- HTTP

/// Every accessor on a parsed request, and the prefix property: a slowloris
/// splitting a valid head anywhere must only ever see "need more".
pub fn http_request(data: &[u8]) -> u64 {
    let max = 8 << 10;
    let r = http::parse_request_with(data, max);
    match &r {
        Ok(Some((req, n))) => {
            assert!(*n <= data.len() && *n <= max);
            let _ = (req.wants_upgrade(), req.wants_websocket(), req.accepts("application/nostr+json"), req.header("host"));
            if let Some(k) = req.websocket_key() {
                let _ = http::accept_key(k);
            }
            let policy = ExtensionPolicy::with_deflate(pmd::DeflatePolicy::default());
            let ext = Extensions::negotiate(req, &policy);
            let mut out = Vec::new();
            if let Some(key) = req.websocket_key() {
                http::write_upgrade_response(&mut out, &http::accept_key(key), &ext);
            }
            let _ = http::client_ip("127.0.0.1:1".parse().unwrap(), req, Some("x-real-ip"));
            // Every strict prefix is incomplete, never an error.
            for cut in prefix_cuts(*n) {
                assert!(matches!(http::parse_request_with(&data[..cut], max), Ok(None)), "a prefix ({cut} of {n} bytes) of a valid head is an error");
            }
            fp(&[2, u64::from(req.websocket_key().is_some()), u64::from(ext.deflate.is_some()), req.headers.len() as u64])
        }
        Ok(None) => 3,
        Err(e) => fp(&[4, fp_str(e.message())]),
    }
}

/// A few cut points: every one for short heads, a spread for long ones.
fn prefix_cuts(n: usize) -> Vec<usize> {
    if n <= 64 {
        (0..n).collect()
    } else {
        let mut v: Vec<usize> = (0..32).collect();
        v.extend((n - 32)..n);
        v.extend((0..32).map(|i| i * n / 32));
        v
    }
}

fn http_seeds() -> Vec<Vec<u8>> {
    vec![
        b"GET /nostr HTTP/1.1\r\nHost: r\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n".to_vec(),
        b"GET / HTTP/1.1\nAccept: application/nostr+json\n\n".to_vec(),
        b"OPTIONS /stats HTTP/1.0\r\n\r\n".to_vec(),
    ]
}

fn gen_http(rng: &mut Rng) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(*rng.pick(&[b"GET".as_slice(), b"POST", b"OPTIONS", b"G\x00T", b""]));
    s.push(b' ');
    s.extend_from_slice(*rng.pick(&[b"/".as_slice(), b"/nostr?x=1", b"*", b"", b"/a b"]));
    s.extend_from_slice(*rng.pick(&[b" HTTP/1.1".as_slice(), b" HTTP/1.0", b" HTTP/2", b" HTTP/1.1 "]));
    let nl: &[u8] = if rng.chance(1, 4) { b"\n" } else { b"\r\n" };
    s.extend_from_slice(nl);
    for _ in 0..rng.skewed(70) {
        let h = *rng.pick(HTTP_DICT);
        if h.ends_with(b"\r\n") {
            s.extend_from_slice(&h[..h.len() - 2]);
        } else {
            s.extend_from_slice(b"X-");
            s.extend_from_slice(h);
            s.extend_from_slice(b": v");
        }
        s.extend_from_slice(nl);
    }
    s.extend_from_slice(nl);
    s
}

pub fn http_response(data: &[u8]) -> u64 {
    let r = http::parse_response(data, 8 << 10);
    let head = match &r {
        Ok(Some((resp, n))) => {
            assert!(*n <= data.len());
            let _ = resp.headers.get("sec-websocket-extensions").map(DeflateParams::from_response);
            for cut in prefix_cuts(*n) {
                assert!(matches!(http::parse_response(&data[..cut], 8 << 10), Ok(None)), "a prefix of a valid response head is an error");
            }
            Some(*n)
        }
        _ => None,
    };
    // The ACME client's chunked decoder on whatever follows (or everything).
    let body = &data[head.unwrap_or(0)..];
    let max = 64 << 10;
    match relay_tls::http::decode_chunked(body, max) {
        Ok(Some((out, used))) => {
            assert!(out.len() <= max, "chunked body past its limit");
            assert!(used <= body.len());
            // Read as it arrives, a complete body is only ever "need more" before its end.
            for cut in prefix_cuts(used) {
                assert!(matches!(relay_tls::http::decode_chunked(&body[..cut], max), Ok(None)), "a {cut}-byte prefix of a {used}-byte chunked body is not just incomplete");
            }
            fp(&[2, u64::from(head.is_some())])
        }
        Ok(None) => fp(&[3, u64::from(head.is_some())]),
        Err(e) => fp(&[4, fp_str(&e)]),
    }
}

fn response_seeds() -> Vec<Vec<u8>> {
    vec![
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0;ext=1\r\nTrailer: x\r\n\r\n".to_vec(),
    ]
}

fn gen_response(rng: &mut Rng) -> Vec<u8> {
    let mut s = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    for _ in 0..rng.skewed(20) {
        let n = rng.skewed(300) as usize;
        s.extend_from_slice(format!("{n:x}\r\n").as_bytes());
        s.extend(std::iter::repeat_n(b'x', n));
        s.extend_from_slice(b"\r\n");
    }
    s.extend_from_slice(b"0\r\n\r\n");
    s
}

// ---------------------------------------------------------------- WebSocket decoder

/// An event with its payload copied out of the decoder's buffers.
#[derive(Debug, PartialEq, Eq)]
enum Ev {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<(u16, String)>),
}

fn own(e: Event<'_>) -> Ev {
    match e {
        Event::Text(t) => Ev::Text(t.to_string()),
        Event::Binary(b) => Ev::Binary(b.to_vec()),
        Event::Ping(p) => Ev::Ping(p.to_vec()),
        Event::Pong(p) => Ev::Pong(p.to_vec()),
        Event::Close(c) => Ev::Close(c.map(|(code, r)| (code, r.to_string()))),
    }
}

/// Feeds `stream` in chunks split at `cuts`, as the reactor does: keep what was
/// not consumed, append the next read behind it, decode until no event.
fn feed(dec: &mut Decoder, stream: &[u8], cuts: &[usize]) -> (Vec<Ev>, Option<relay_net::ws::WsError>, usize) {
    let mut buf: Vec<u8> = Vec::new();
    let mut events = Vec::new();
    let mut peak_buf = 0;
    let mut at = 0;
    let mut bounds: Vec<usize> = cuts.iter().copied().filter(|&c| c > 0 && c < stream.len()).collect();
    bounds.sort_unstable();
    bounds.dedup();
    bounds.push(stream.len());
    for end in bounds {
        buf.extend_from_slice(&stream[at..end]);
        at = end;
        peak_buf = peak_buf.max(buf.len());
        let mut off = 0;
        let len = buf.len();
        loop {
            match dec.decode(&mut buf[off..]) {
                Ok(d) => {
                    assert!(off + d.consumed <= len, "consumed past the end of the buffer");
                    off += d.consumed;
                    match d.event {
                        Some(e) => {
                            let ev = own(e);
                            if let Ev::Text(t) | Ev::Close(Some((_, t))) = &ev {
                                assert!(t.len() <= MAX_MESSAGE, "message past the limit");
                            }
                            if let Ev::Binary(b) = &ev {
                                assert!(b.len() <= MAX_MESSAGE, "message past the limit");
                            }
                            events.push(ev);
                        }
                        None => break,
                    }
                }
                Err(e) => {
                    // Errors are sticky.
                    assert_eq!(dec.decode(&mut buf[off..]).err(), Some(e));
                    return (events, Some(e), peak_buf);
                }
            }
        }
        buf.drain(..off);
        // The decoder never needs more than one whole frame buffered.
        assert!(buf.len() <= MAX_FRAME + MAX_MESSAGE / 64 + 64 + 14, "a partial frame larger than any frame may be");
    }
    (events, None, peak_buf)
}

/// Input: one config byte, then the stream. The same stream fed whole and in
/// pieces must decode to the same events and end the same way.
pub fn ws_decode(data: &[u8]) -> u64 {
    let Some((&cfg, stream)) = data.split_first() else { return 1 };
    let make = || {
        let role = if cfg & 1 == 0 { Role::Server } else { Role::Client };
        let mut d = Decoder::new(role, MAX_FRAME, MAX_MESSAGE);
        match (cfg >> 1) % 3 {
            0 => {}
            1 => d.enable_deflate(pmd::StreamConfig { context_takeover: false, window_bits: 15 }),
            _ => d.enable_deflate(pmd::StreamConfig { context_takeover: true, window_bits: 8 + (cfg >> 3) % 8 }),
        }
        d
    };
    let mut whole = make();
    let (ev_a, err_a, _) = feed(&mut whole, stream, &[]);
    assert!(whole.heap_bytes() <= 2 * (MAX_MESSAGE + MAX_MESSAGE / 64 + 64) + (64 << 10), "decoder holds {} bytes", whole.heap_bytes());
    let mut rng = Rng::new(u64::from(cfg) ^ stream.len() as u64);
    let cuts: Vec<usize> = (0..1 + stream.len() / 64).map(|_| rng.usize(stream.len().max(1))).collect();
    let mut pieces = make();
    let (ev_b, err_b, _) = feed(&mut pieces, stream, &cuts);
    assert_eq!(ev_a, ev_b, "events depend on how the stream was split");
    assert_eq!(err_a, err_b, "the outcome depends on how the stream was split");
    // A byte at a time, for short streams (slowloris).
    if stream.len() <= 512 {
        let mut slow = make();
        let all: Vec<usize> = (1..stream.len()).collect();
        let (ev_c, err_c, _) = feed(&mut slow, stream, &all);
        assert_eq!(ev_a, ev_c, "byte-at-a-time decoding differs");
        assert_eq!(err_a, err_c);
    }
    let kinds = ev_a.iter().fold(0u64, |a, e| {
        a | match e {
            Ev::Text(_) => 1,
            Ev::Binary(_) => 2,
            Ev::Ping(_) => 4,
            Ev::Pong(_) => 8,
            Ev::Close(_) => 16,
        }
    });
    fp(&[u64::from(cfg % 6), kinds, err_a.map_or(0, |e| fp_str(e.reason()))])
}

fn ws_seeds() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    // Server role, no compression: text, fragmented binary with a ping between, close.
    let mut s = vec![0u8];
    Frame::text("[\"REQ\",\"a\",{}]").write(&mut s);
    let mut f = Frame::new(2, b"part1");
    f.fin = false;
    f.write(&mut s);
    Frame::new(9, b"ping").write(&mut s);
    Frame::new(0, b"part2").write(&mut s);
    Frame::new(8, &[0x03, 0xE8, b'b', b'y', b'e']).write(&mut s);
    v.push(s);
    // Stateless compression: a compressed text message and a fragmented one.
    let mut s = vec![2u8];
    let z = wsframe::deflate_message("[\"EVENT\",{\"content\":\"hello hello hello\"}]".as_bytes());
    let mut f = Frame::new(1, &z);
    f.rsv = 0x40;
    f.write(&mut s);
    let (a, b) = z.split_at(z.len() / 2);
    let mut f1 = Frame::new(1, a);
    f1.rsv = 0x40;
    f1.fin = false;
    f1.write(&mut s);
    Frame::new(0, b).write(&mut s);
    v.push(s);
    // A bomb: must stop at the message limit.
    let mut s = vec![2u8];
    let mut f = Frame::new(1, &wsframe::deflate_bomb(4 << 20, b'a'));
    f.rsv = 0x40;
    f.write(&mut s);
    v.push(s);
    v
}

fn gen_ws(rng: &mut Rng) -> Vec<u8> {
    let cfg = rng.below(256) as u8;
    let server = cfg & 1 == 0;
    let deflate = !(cfg >> 1).is_multiple_of(3);
    let mut s = vec![cfg];
    let mut in_msg = false;
    for _ in 0..rng.skewed(12) {
        let control = rng.chance(1, 4);
        let op = if control { *rng.pick(&[8u8, 9, 10]) } else if in_msg { 0 } else { *rng.pick(&[1u8, 2]) };
        let mut payload: Vec<u8> = if op == 8 {
            let mut p = (*rng.pick(&[1000u16, 1001, 1005, 1006, 3000, 4999, 999])).to_be_bytes().to_vec();
            p.extend_from_slice(*rng.pick(&[b"".as_slice(), b"bye", b"\xff"]));
            p
        } else {
            let n = if control { rng.skewed(130) } else { rng.skewed(MAX_FRAME as u64 + 10) } as usize;
            let mut p = vec![0u8; n];
            if rng.chance(1, 2) {
                p.iter_mut().for_each(|b| *b = b'a' + rng.below(26) as u8);
            } else {
                rng.fill(&mut p);
            }
            p
        };
        let mut f = Frame::new(op, &[]);
        if deflate && !control && op != 0 && rng.chance(2, 3) {
            payload = wsframe::deflate_message(&payload);
            f.rsv = 0x40;
        }
        f.payload = payload;
        f.mask = if server == rng.chance(15, 16) { Some(wsframe::mask(rng)) } else { None };
        f.fin = control || rng.chance(2, 3);
        if !control {
            in_msg = !f.fin;
        }
        if rng.chance(1, 20) {
            f.wide = Some(*rng.pick(&[126u8, 127]));
        }
        f.write(&mut s);
    }
    s
}

// ---------------------------------------------------------------- inflate

const INFLATE_LIMIT: usize = 256 << 10;

/// Our inflater against miniz_oxide on raw DEFLATE: when both decode, the
/// bytes agree; when miniz decodes a whole stream within the limit, ours does
/// too (ours follows zlib's acceptance rules, which miniz shares).
pub fn inflate(data: &[u8]) -> u64 {
    use miniz_oxide::inflate::{decompress_to_vec_with_limit, TINFLStatus};
    let mut ours = Vec::new();
    let mut inf = relay_net::deflate::Inflater::new(15, false);
    let r = inf.inflate(data, &mut ours, INFLATE_LIMIT);
    assert!(ours.len() <= INFLATE_LIMIT, "output past the limit");
    if r.is_err() {
        assert!(ours.is_empty(), "output kept after an error");
        // Failure is final.
        let mut more = Vec::new();
        assert!(inf.inflate(&[0x03, 0x00], &mut more, 100).is_err());
    }
    let theirs = decompress_to_vec_with_limit(data, INFLATE_LIMIT);
    match (&r, &theirs) {
        (Ok(_), Ok(t)) => {
            // Ours may continue past a final block (more blocks after it); miniz stops there.
            assert!(ours.starts_with(t), "inflated bytes differ from miniz_oxide");
        }
        (Err(relay_net::deflate::InflateError::Malformed(m)), Ok(t)) if t.len() < INFLATE_LIMIT => {
            // Only a stream that miniz read to its end with nothing left over counts.
            let mut d = miniz_oxide::inflate::core::DecompressorOxide::new();
            let mut out = vec![0u8; INFLATE_LIMIT];
            let (st, used, _) = miniz_oxide::inflate::core::decompress(&mut d, data, &mut out, 0, miniz_oxide::inflate::core::inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
            if st == TINFLStatus::Done && used == data.len() {
                panic!("we refuse ({m}) a stream miniz_oxide inflates completely");
            }
        }
        _ => {}
    }
    match r {
        Ok(n) => fp(&[2, (n > 0) as u64]),
        Err(e) => fp(&[3, fp_str(&e.to_string())]),
    }
}

fn inflate_seeds() -> Vec<Vec<u8>> {
    let text = b"hello hello hello world, the quick brown fox jumps over the lazy dog 0123456789";
    vec![
        miniz_oxide::deflate::compress_to_vec(text, 6),
        miniz_oxide::deflate::compress_to_vec(&[0u8; 5000], 1),
        miniz_oxide::deflate::compress_to_vec(&(0..=255u8).cycle().take(70_000).collect::<Vec<_>>(), 9),
        wsframe::deflate_message(text),
    ]
}

fn gen_inflate(rng: &mut Rng) -> Vec<u8> {
    let plain = gen_plain(rng);
    match rng.below(3) {
        0 => miniz_oxide::deflate::compress_to_vec(&plain, rng.below(11) as u8),
        1 => wsframe::deflate_message(&plain),
        _ => {
            let mut z = relay_net::deflate::Deflater::new(8 + rng.below(8) as u8, rng.chance(1, 2));
            let mut out = Vec::new();
            z.deflate(&plain, &mut out, relay_net::deflate::Flush::Finish);
            out
        }
    }
}

fn gen_plain(rng: &mut Rng) -> Vec<u8> {
    let n = rng.skewed(100_000) as usize;
    match rng.below(4) {
        0 => {
            let mut b = vec![0u8; n];
            rng.fill(&mut b);
            b
        }
        1 => (0..n).map(|i| b"abcab"[i % 5]).collect(),
        2 => {
            let words: [&[u8]; 6] = [b"\"content\":", b"\"kind\":1059,", b"[\"p\",\"", b"abcdef0123456789", b"\"]", b" "];
            let mut v = Vec::with_capacity(n);
            while v.len() < n {
                v.extend_from_slice(*rng.pick(&words));
            }
            v
        }
        _ => vec![rng.below(256) as u8; n],
    }
}

/// Our compressor's output decodes, with ours and with miniz_oxide, to the input,
/// message by message with and without history.
pub fn deflate_roundtrip(data: &[u8]) -> u64 {
    let Some((&cfg, rest)) = data.split_first() else { return 1 };
    let bits = 8 + cfg % 8;
    let takeover = cfg & 0x80 != 0;
    let mut z = relay_net::deflate::Deflater::new(bits, takeover);
    let mut inf = relay_net::deflate::Inflater::new(bits, takeover);
    // Split into messages at a few points, as consecutive WebSocket messages.
    let mut rng = Rng::new(u64::from(cfg) ^ rest.len() as u64);
    let mut cuts: Vec<usize> = (0..rng.below(4)).map(|_| rng.usize(rest.len().max(1))).collect();
    cuts.push(rest.len());
    cuts.sort_unstable();
    let mut at = 0;
    let mut stream = Vec::new();
    for c in cuts {
        let msg = &rest[at..c.max(at)];
        at = c.max(at);
        let mut comp = Vec::new();
        z.deflate(msg, &mut comp, relay_net::deflate::Flush::Sync);
        assert!(comp.ends_with(&relay_net::deflate::SYNC_TAIL), "sync flush does not end in 00 00 ff ff");
        stream.extend_from_slice(&comp);
        let body = &comp[..comp.len() - 4];
        let mut out = Vec::new();
        inf.inflate_message(body, &mut out, msg.len() + 1).unwrap_or_else(|e| panic!("our own message does not inflate: {e}"));
        assert_eq!(out, msg, "round trip changed the message");
        if !takeover {
            // miniz wants a stream that ends: close it with an empty final block.
            let mut whole = comp.clone();
            whole.extend_from_slice(&[0x03, 0x00]);
            let theirs = miniz_oxide::inflate::decompress_to_vec(&whole).unwrap_or_else(|e| panic!("miniz cannot read our message: {:?}", e.status));
            assert_eq!(theirs, msg, "miniz reads our message differently");
        }
    }
    if takeover {
        // The whole stream with history, as one decoder sees it.
        let mut st = stream;
        let mut fin = Vec::new();
        z.deflate(&[], &mut fin, relay_net::deflate::Flush::Finish);
        st.extend_from_slice(&fin);
        let theirs = miniz_oxide::inflate::decompress_to_vec(&st).unwrap_or_else(|e| panic!("miniz cannot read our stream: {:?}", e.status));
        assert_eq!(theirs, rest, "miniz reads our stream differently");
    }
    fp(&[u64::from(takeover), u64::from(bits)])
}

fn roundtrip_seeds() -> Vec<Vec<u8>> {
    vec![[&[0x8Fu8][..], b"hello hello hello"].concat(), [&[0x07u8][..], &[0u8; 70_000][..]].concat()]
}

// ---------------------------------------------------------------- negotiation and base64

pub fn pmd_negotiate(data: &[u8]) -> u64 {
    let lines: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    let policy = pmd::DeflatePolicy {
        server_no_context_takeover: data.first().is_some_and(|b| b & 1 != 0),
        client_no_context_takeover: data.first().is_some_and(|b| b & 2 != 0),
        max_server_window_bits: 8 + data.get(1).map_or(7, |b| b % 8),
        max_client_window_bits: 8 + data.get(2).map_or(7, |b| b % 8),
    };
    let r = pmd::negotiate(lines.iter().copied(), &policy);
    if let Some(p) = r {
        // What we answer, a client must read back to the same parameters.
        let mut v = Vec::new();
        p.write_response_value(&mut v);
        let back = DeflateParams::from_response(&v).expect("our response value parses");
        // Each direction's receiver must be able to read what its sender sends:
        // a window at least as large, and history whenever the sender keeps it.
        let readable = |sender: pmd::StreamConfig, receiver: pmd::StreamConfig| {
            receiver.window_bits >= sender.window_bits && (receiver.context_takeover || !sender.context_takeover)
        };
        let text = String::from_utf8_lossy(&v);
        assert!(readable(p.send(Role::Server), back.send(Role::Server)), "a client following {text:?} cannot read the server");
        assert!(readable(back.send(Role::Client), p.send(Role::Client)), "the server cannot read a client following {text:?}");
        for role in [Role::Server, Role::Client] {
            let s = p.send(role);
            assert!((8..=15).contains(&s.window_bits));
        }
        assert!(p.send(Role::Server).window_bits <= policy.max_server_window_bits.clamp(8, 15));
        if policy.server_no_context_takeover {
            assert!(!p.send(Role::Server).context_takeover);
        }
        if policy.client_no_context_takeover {
            assert!(!p.send(Role::Client).context_takeover);
        }
    }
    for l in &lines {
        let _ = DeflateParams::from_response(l);
    }
    fp(&[u64::from(r.is_some())])
}

fn pmd_seeds() -> Vec<Vec<u8>> {
    vec![
        b"\x00\x07\x07permessage-deflate; client_max_window_bits; server_max_window_bits=10".to_vec(),
        b"\x03\x00\x00x-webkit-deflate-frame, permessage-deflate; server_no_context_takeover; client_max_window_bits=\"9\"".to_vec(),
    ]
}

fn gen_pmd(rng: &mut Rng) -> Vec<u8> {
    let mut v = vec![rng.below(4) as u8, rng.below(8) as u8, rng.below(8) as u8];
    let params = [
        "server_no_context_takeover",
        "client_no_context_takeover",
        "client_max_window_bits",
        "client_max_window_bits=8",
        "server_max_window_bits=15",
        "server_max_window_bits=\"9\"",
        "server_max_window_bits=7",
        "server_max_window_bits=16",
        "client_max_window_bits=",
        "x=1",
    ];
    for _ in 0..1 + rng.skewed(3) {
        v.extend_from_slice(b"permessage-deflate");
        for _ in 0..rng.skewed(4) {
            v.extend_from_slice(b"; ");
            v.extend_from_slice(rng.pick(&params).as_bytes());
        }
        v.extend_from_slice(*rng.pick(&[b", ".as_slice(), b"\n"]));
    }
    v
}

pub fn base64(data: &[u8]) -> u64 {
    let mut out = Vec::new();
    let r = relay_net::base64::decode(data, &mut out);
    if r.is_ok() {
        // Re-encoding gives a string that decodes to the same bytes.
        let enc = relay_net::base64::encode_string(&out);
        let mut back = Vec::new();
        relay_net::base64::decode(enc.as_bytes(), &mut back).expect("our own encoding decodes");
        assert_eq!(back, out);
    }
    fp(&[u64::from(r.is_ok())])
}

fn gen_b64(rng: &mut Rng) -> Vec<u8> {
    let mut b = vec![0u8; rng.skewed(40) as usize];
    rng.fill(&mut b);
    let mut s = relay_net::base64::encode_string(&b).into_bytes();
    if rng.chance(1, 3) && !s.is_empty() {
        let i = rng.usize(s.len());
        s[i] = *rng.pick(b"=+/-_ \x00\xff");
    }
    s
}
