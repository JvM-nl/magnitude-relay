//! relay-proto: the JSON scanner, canonical strings, events, filters, client
//! messages, varints, hex and the NIP-77 responder.

use super::{fp, fp_str, linear_cap, Target};
use crate::gen;
use crate::rng::Rng;
use crate::sign::Keys;
use relay_proto::event::{compute_id, parse_event_json};
use relay_proto::json::Scanner;
use relay_proto::message::{ClientMsg, MsgError, MAX_SUB_ID};
use relay_proto::record::{Field, Record, FLAG_RAW_FORM};
use relay_proto::{hex, negentropy, varint, EventParser, Filter};
use std::cell::RefCell;

const JSON_DICT: &[&[u8]] = &[
    b"\\u", b"\\ud800", b"\\udc00", b"\\ud83d\\ude00", b"\\u0000", b"\\\"", b"\\\\", b"\\/", b"null", b"true", b"false", b"[]",
    b"{}", b"\"\":", b"\"id\":", b"\"pubkey\":", b"\"sig\":", b"\"kind\":", b"\"created_at\":", b"\"tags\":", b"\"content\":",
    b"\"ids\":", b"\"authors\":", b"\"kinds\":", b"\"#p\":", b"\"#e\":", b"\"since\":", b"\"until\":", b"\"limit\":", b"\"search\":",
    b"[\"EVENT\",", b"[\"REQ\",", b"[\"COUNT\",", b"[\"CLOSE\",", b"[\"NEG-OPEN\",", b"[\"NEG-MSG\",", b"[\"AUTH\",",
    b"[\"expiration\",\"", b"[\"-\"]", b"[\"d\",\"", b"[\"a\",\"30078:", b"\xc3\xa9", b"\xf0\x9f\x98\x80", b"\xe2\x80\xa8",
];

pub fn targets() -> Vec<Target> {
    vec![
        Target { name: "json", run: json, seeds: json_seeds, generate: gen_json, dict: JSON_DICT, max_len: 64 << 10, mem_cap: linear_cap },
        Target { name: "canonical", run: canonical, seeds: string_seeds, generate: gen_string, dict: JSON_DICT, max_len: 16 << 10, mem_cap: linear_cap },
        Target { name: "event", run: event, seeds: event_seeds, generate: gen_event, dict: JSON_DICT, max_len: 128 << 10, mem_cap: linear_cap },
        Target { name: "filter", run: filter, seeds: filter_seeds, generate: gen_filter, dict: JSON_DICT, max_len: 256 << 10, mem_cap: linear_cap },
        Target { name: "client_msg", run: client_msg, seeds: msg_seeds, generate: gen_msg, dict: JSON_DICT, max_len: 256 << 10, mem_cap: linear_cap },
        Target { name: "varint", run: varints, seeds: varint_seeds, generate: gen_bytes, dict: &[], max_len: 4096, mem_cap: linear_cap },
        Target { name: "hex", run: hexes, seeds: hex_seeds, generate: gen_hex, dict: &[b"0123456789abcdef", b"ABCDEF", b"g"], max_len: 4096, mem_cap: linear_cap },
        Target { name: "negentropy", run: neg, seeds: neg_seeds, generate: gen_neg, dict: &[b"\x61", b"\x00", b"\x01", b"\x02", b"\x80\x80\x80"], max_len: 64 << 10, mem_cap: neg_cap },
        Target { name: "negentropy_sync", run: neg_sync, seeds: neg_seeds, generate: gen_bytes, dict: &[], max_len: 64, mem_cap: neg_cap },
    ]
}

fn neg_cap(len: usize) -> usize {
    // The set itself (up to ~2,000 items, in two implementations) plus the message.
    (8 << 20) + 64 * len
}

thread_local! {
    static PARSER: RefCell<(EventParser, Vec<u8>, Vec<u8>)> = RefCell::new((EventParser::new(), Vec::new(), Vec::new()));
}

// ---------------------------------------------------------------- json

/// Our scanner and serde_json must agree on what is JSON (serde_json skips
/// values without checking surrogate pairing, as ours does; ours nests 65 deep
/// at most, serde_json 128).
pub fn json(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else { return 1 };
    let mut sc = Scanner::new(s);
    let ours = sc.skip().and_then(|()| sc.end());
    let theirs = serde_json::from_str::<serde::de::IgnoredAny>(s);
    match (&ours, &theirs) {
        (Ok(()), Err(e)) => panic!("scanner accepts what serde_json rejects ({e}): {:?}", trunc(s)),
        (Err(e), Ok(_)) if e.msg != "nested too deeply" => panic!("scanner rejects JSON serde_json accepts ({e}): {:?}", trunc(s)),
        _ => {}
    }
    match ours {
        Ok(()) => 2,
        Err(e) => fp(&[3, fp_str(e.msg)]),
    }
}

fn trunc(s: &str) -> &str {
    let mut end = s.len().min(300);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn json_seeds() -> Vec<Vec<u8>> {
    [
        r#"{"a":[1,-2.5e+3,true,false,null,{"b":"c\"d"}],"e":{}}"#,
        r#"["EVENT",{"id":"00","x":[[[[]]]]}]"#,
        "\"\\ud83d\\ude00\\u00e9\\/\"",
        "[0,-0,1e3,1E-3,0.5,123456789012345678901234567890]",
        "  [ 1 , 2 ]  ",
        "{\"\":\"\"}",
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect()
}

fn gen_json(rng: &mut Rng) -> Vec<u8> {
    gen::json_value(rng, 6).into_bytes()
}

// ---------------------------------------------------------------- canonical strings

/// Decodes a JSON string body to UTF-16 code units, lone surrogates and all:
/// the reference for "means the same string".
fn utf16_of(body: &[u8]) -> Option<Vec<u16>> {
    let s = std::str::from_utf8(body).ok()?;
    let mut out = Vec::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\\' {
            let mut b = [0u16; 2];
            out.extend_from_slice(c.encode_utf16(&mut b));
            continue;
        }
        match it.next()? {
            '"' => out.push(0x22),
            '\\' => out.push(0x5C),
            '/' => out.push(0x2F),
            'b' => out.push(8),
            'f' => out.push(12),
            'n' => out.push(10),
            'r' => out.push(13),
            't' => out.push(9),
            'u' => {
                let h: String = (0..4).map(|_| it.next()).collect::<Option<String>>()?;
                out.push(u16::from_str_radix(&h, 16).ok()?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// Every escape a canonical string may contain: the short ones, `\u00xx` for
/// the other control characters, and lowercase `\udxxx` for lone surrogates.
fn assert_canonical_shape(c: &[u8], input: &str) {
    let mut i = 0;
    while i < c.len() {
        assert!(c[i] >= 0x20, "raw control byte in canonical form of {input:?}");
        if c[i] == b'\\' {
            match c.get(i + 1) {
                Some(b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't') => i += 2,
                Some(b'u') => {
                    let h = std::str::from_utf8(&c[i + 2..i + 6]).unwrap();
                    assert_eq!(h, h.to_lowercase(), "uppercase \\u escape in canonical form of {input:?}");
                    let u = u16::from_str_radix(h, 16).unwrap();
                    let short = matches!(u, 8 | 9 | 10 | 12 | 13);
                    assert!((u < 0x20 && !short) || (0xD800..0xE000).contains(&u), "needless \\u{h} in canonical form of {input:?}");
                    i += 6;
                }
                other => panic!("escape {other:?} in canonical form of {input:?}"),
            }
        } else {
            i += 1;
        }
    }
}

pub fn canonical(data: &[u8]) -> u64 {
    let Ok(body) = std::str::from_utf8(data) else { return 1 };
    let quoted = format!("\"{body}\"");
    let mut sc = Scanner::new(&quoted);
    let Ok(raw) = sc.string() else { return 2 };
    if sc.end().is_err() {
        return 3;
    }
    let mut canon = Vec::new();
    raw.write_canonical(&mut canon);
    let canon_s = std::str::from_utf8(&canon).expect("canonical form is UTF-8");
    assert_canonical_shape(&canon, body);
    // Same string, whatever the spelling.
    assert_eq!(utf16_of(raw.bytes), utf16_of(&canon), "canonical form changes the string {body:?}");
    // Idempotent.
    let q2 = format!("\"{canon_s}\"");
    let mut sc2 = Scanner::new(&q2);
    let raw2 = sc2.string().expect("canonical form scans");
    let mut again = Vec::new();
    raw2.write_canonical(&mut again);
    assert_eq!(again, canon, "canonicalisation is not idempotent for {body:?}");
    // serde_json (JSON.stringify's escaping) agrees wherever it can read the string.
    if let Ok(v) = serde_json::from_str::<String>(&quoted) {
        let expect = serde_json::to_string(&v).unwrap();
        assert_eq!(expect.as_bytes(), q2.as_bytes(), "canonical form differs from serde_json for {body:?}");
        let mut esc = Vec::new();
        relay_proto::json::escape_str(&v, &mut esc);
        assert_eq!(esc, canon, "escape_str differs from the canonical form for {body:?}");
        return fp(&[4, raw.escaped as u64]);
    }
    fp(&[5, raw.escaped as u64])
}

fn string_seeds() -> Vec<Vec<u8>> {
    ["plain", "a\\/b", "caf\\u00e9", "\\u00E9\\u0041", "tab\\there\\n\\r\\f\\b", "\\u0001\\u001f\\u007f", "\\ud83d\\ude00", "\\ud800x", "\\udc00", "\\ud800\\ud800\\udc00", "raw é 😀"]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect()
}

fn gen_string(rng: &mut Rng) -> Vec<u8> {
    gen::json_string(rng, 64).into_bytes()
}

// ---------------------------------------------------------------- events

/// What serde_json makes of an event document, for the differential checks.
struct RefEvent {
    id: [u8; 32],
    pubkey: String,
    created_at: u64,
    kind: u64,
    tags: serde_json::Value,
    content: String,
}

fn ref_event(s: &str) -> Option<RefEvent> {
    let v: serde_json::Value = serde_json::from_str(s).ok()?;
    let o = v.as_object()?;
    Some(RefEvent {
        id: hex::decode_32(o.get("id")?.as_str()?.as_bytes())?,
        pubkey: o.get("pubkey")?.as_str()?.to_string(),
        created_at: o.get("created_at")?.as_u64()?,
        kind: o.get("kind")?.as_u64()?,
        tags: o.get("tags")?.clone(),
        content: o.get("content")?.as_str()?.to_string(),
    })
}

/// Walks every accessor of a record and checks they agree with each other.
pub fn check_record(rec: &[u8], tag_count: u32) {
    let r = Record(rec);
    let _ = (r.id(), r.pubkey(), r.sig(), r.created_at(), r.kind(), r.is_protected(), r.expiration(), r.d_tag());
    let mut n = 0u32;
    for t in r.tags() {
        n += 1;
        let fields: Vec<Field<'_>> = t.fields().collect();
        assert_eq!(fields.len(), t.len());
        if let Some((name, value)) = t.indexable() {
            assert!(matches!(fields[0], Field::Str(s) if s == [name]));
            let mut enc = Vec::new();
            fields[1].encode(&mut enc);
            assert_eq!(enc, value, "indexable value is not the second field");
        }
    }
    assert_eq!(n, tag_count, "tag count");
    let mut out = Vec::new();
    r.write_json(&mut out);
    assert_eq!(out.len(), r.json_len(), "json_len disagrees with write_json");
    let mut pre = Vec::new();
    r.write_id_preimage(&mut pre);
    serde_json::from_slice::<serde::de::IgnoredAny>(&out).expect("record JSON is JSON");
    serde_json::from_slice::<serde::de::IgnoredAny>(&pre).expect("id preimage is JSON");
}

pub fn event(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else { return 1 };
    PARSER.with(|p| {
        let (parser, rec, rec2) = &mut *p.borrow_mut();
        let info = match parse_event_json(s, parser, rec, false) {
            Ok(i) => i,
            Err(e) => return fp(&[2, fp_str(&e.to_string())]),
        };
        check_record(rec, info.tag_count);
        // The stored form re-serialises and parses back to the same record.
        let json = Record(rec).to_json();
        let info2 = parse_event_json(&json, parser, rec2, false).expect("a record's own JSON parses");
        assert_eq!(rec, rec2, "record does not survive a round trip through its JSON: {:?}", trunc(s));
        assert_eq!(info.tag_count, info2.tag_count);
        assert_eq!(info.expiration, info2.expiration);
        assert_eq!(info.protected, info2.protected);

        // The id path: accept exactly what hashes. Where serde_json can read the
        // event, its canonical serialisation is the reference.
        let checked = parse_event_json(s, parser, rec2, false).and_then(|i| {
            let sc = Scanner::new(s);
            parser.confirm_id(sc, rec2, i)
        });
        let r = ref_event(s);
        match (&checked, &r) {
            (Ok(_), _) => {
                let mut scratch = Vec::new();
                assert_eq!(compute_id(Record(rec2), &mut scratch), *Record(rec2).id(), "accepted an event whose record does not hash to its id");
                if let Some(r) = &r {
                    if Record(rec2).flags() & FLAG_RAW_FORM == 0 {
                        let want = crate::sign::reference_id(&r.pubkey, r.created_at, r.kind, &r.tags, &r.content);
                        assert_eq!(want, r.id, "canonical id accepted but serde_json's serialisation hashes elsewhere: {:?}", trunc(s));
                    }
                }
            }
            (Err(relay_proto::Reject::IdMismatch), Some(r)) => {
                let want = crate::sign::reference_id(&r.pubkey, r.created_at, r.kind, &r.tags, &r.content);
                assert_ne!(want, r.id, "rejected an event whose serde_json serialisation hashes to its id: {:?}", trunc(s));
            }
            _ => {}
        }
        fp(&[3, info.kind.min(70_000), u64::from(info.any_escaped), u64::from(checked.is_ok())])
    })
}

fn event_seeds() -> Vec<Vec<u8>> {
    let k = Keys::from_seed(7);
    let mut v = Vec::new();
    let (e, _) = k.event(1_700_000_000, 1059, serde_json::json!([["p", "ab".repeat(32)], ["expiration", "1800000000"]]), "hi \u{1} é 😀 \"q\"");
    v.push(e.into_bytes());
    let (e, _) = k.event(1_700_000_001, 30078, serde_json::json!([["d", "vector/pinned"], ["-"]]), "");
    v.push(e.into_bytes());
    if let Some(e) = k.sign_json(5, 1, "[[\"t\",\"caf\\u00e9\"]]", "a\\/b \\ud83d\\ude00") {
        v.push(e.into_bytes());
    }
    v
}

fn gen_event(rng: &mut Rng) -> Vec<u8> {
    thread_local! { static KEYS: Keys = Keys::from_seed(42); }
    if rng.chance(1, 3) {
        KEYS.with(|k| gen::event_json(rng, Some(k))).into_bytes()
    } else {
        gen::event_json(rng, None).into_bytes()
    }
}

// ---------------------------------------------------------------- filters

fn sample_records() -> &'static [Vec<u8>] {
    static R: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    R.get_or_init(|| {
        let mut rng = Rng::new(99);
        let mut out = Vec::new();
        let mut p = EventParser::new();
        while out.len() < 32 {
            let s = gen::event_json(&mut rng, None);
            let mut rec = Vec::new();
            if parse_event_json(&s, &mut p, &mut rec, false).is_ok() {
                out.push(rec);
            }
        }
        out
    })
}

pub fn filter(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else { return 1 };
    let mut sc = Scanner::new(s);
    let f = match Filter::parse(&mut sc).map_err(|e| e.to_string()).and_then(|f| sc.end().map(|()| f).map_err(|e| e.to_string())) {
        Ok(f) => f,
        Err(e) => return fp(&[2, fp_str(&e)]),
    };
    serde_json::from_str::<serde::de::IgnoredAny>(s).expect("accepted filter is JSON");
    // Normalised JSON parses back to the same filter.
    let mut out = Vec::new();
    f.write_json(&mut out);
    let text = String::from_utf8(out).expect("filter JSON is UTF-8");
    let back = Filter::parse(&mut Scanner::new(&text)).unwrap_or_else(|e| panic!("normalised filter {text:?} does not parse: {e}"));
    assert_eq!(back, f, "filter changes through write_json: {text:?}");
    let nm = f.never_matches();
    let mut hits = 0;
    for r in sample_records() {
        let m = f.matches(Record(r));
        assert!(!(nm && m), "a filter that never matches matched");
        hits += u64::from(m);
    }
    fp(&[3, u64::from(nm), hits.min(3), f.tags.len() as u64])
}

fn filter_seeds() -> Vec<Vec<u8>> {
    let a = "ab".repeat(32);
    [
        format!(r##"{{"ids":["{a}"],"authors":["{a}"],"kinds":[1,1059],"#p":["{a}","x"],"since":1,"until":2,"limit":5}}"##),
        "{\"#t\":[\"caf\\u00e9\",\"a\\/b\"],\"kinds\":[]}".to_string(),
        "{}".to_string(),
    ]
    .iter()
    .map(|s| s.as_bytes().to_vec())
    .collect()
}

fn gen_filter(rng: &mut Rng) -> Vec<u8> {
    let big = rng.chance(1, 20);
    gen::filter_json(rng, big).into_bytes()
}

// ---------------------------------------------------------------- client messages

pub fn client_msg(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else { return 1 };
    PARSER.with(|p| {
        let (parser, rec, rec2) = &mut *p.borrow_mut();
        let sub_ok = |id: &str| {
            assert!(!id.is_empty() && id.len() <= MAX_SUB_ID && !id.contains('\\'), "bad sub id accepted: {id:?}");
        };
        match ClientMsg::parse(s, parser, rec) {
            Ok(ClientMsg::Event { info, at }) | Ok(ClientMsg::Auth { info, at }) => {
                check_record(rec, info.tag_count);
                // The position handed back really is where the event starts.
                let mut sc = Scanner::new_at(s, at);
                let again = parser.parse_unchecked(&mut sc, rec2).expect("event re-parses at its reported position");
                assert_eq!(again, info);
                assert_eq!(rec, rec2);
                let _ = parser.confirm_id(Scanner::new_at(s, at), rec, info);
                fp(&[2, info.kind.min(70_000)])
            }
            Ok(ClientMsg::Req { sub_id, filters }) | Ok(ClientMsg::Count { sub_id, filters }) => {
                sub_ok(sub_id);
                fp(&[3, filters.len().min(8) as u64])
            }
            Ok(ClientMsg::Close { sub_id }) | Ok(ClientMsg::NegClose { sub_id }) => {
                sub_ok(sub_id);
                4
            }
            Ok(ClientMsg::NegOpen { sub_id, msg, .. }) | Ok(ClientMsg::NegMsg { sub_id, msg }) => {
                sub_ok(sub_id);
                // Whatever the bytes, the responder answers or refuses; never panics.
                let st = negentropy::VecStorage::new(Vec::new());
                let r = negentropy::reconcile(&st, &msg, 50_000);
                fp(&[5, u64::from(r.is_ok())])
            }
            Err(MsgError::Filter { sub_id, err }) => {
                sub_ok(&sub_id);
                fp(&[6, fp_str(&err.to_string())])
            }
            Err(e) => fp(&[7, fp_str(&e.to_string())]),
        }
    })
}

fn msg_seeds() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = event_seeds().into_iter().map(|e| [b"[\"EVENT\",".as_slice(), &e, b"]"].concat()).collect();
    for f in filter_seeds() {
        v.push([b"[\"REQ\",\"sub\",".as_slice(), &f, b",{}]"].concat());
        v.push([b"[\"COUNT\",\"c\",".as_slice(), &f, b"]"].concat());
        v.push([b"[\"NEG-OPEN\",\"n\",".as_slice(), &f, b",\"6100000200\"]"].concat());
    }
    v.push(b"[\"CLOSE\",\"sub\"]".to_vec());
    v.push(b"[\"NEG-MSG\",\"n\",\"61\"]".to_vec());
    v
}

fn gen_msg(rng: &mut Rng) -> Vec<u8> {
    thread_local! { static KEYS: Keys = Keys::from_seed(43); }
    if rng.chance(1, 4) {
        KEYS.with(|k| gen::client_msg(rng, Some(k))).into_bytes()
    } else {
        gen::client_msg(rng, None).into_bytes()
    }
}

// ---------------------------------------------------------------- varints and hex

/// Big-endian base-128, as negentropy encodes; the reference decoder.
fn neg_varint(q: &mut &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    loop {
        let (&b, rest) = q.split_first()?;
        *q = rest;
        v = v.checked_mul(128)? | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Some(v);
        }
    }
}

pub fn varints(data: &[u8]) -> u64 {
    // LEB128 over arbitrary bytes: never past the end, and every value read
    // re-encodes to something that reads back the same.
    let mut pos = 0;
    let mut n = 0u64;
    while pos < data.len() {
        let before = pos;
        match varint::get(data, &mut pos) {
            Some(v) => {
                assert!(pos > before && pos <= data.len());
                let mut b = Vec::new();
                varint::put(&mut b, v);
                let mut p = 0;
                assert_eq!(varint::get(&b, &mut p), Some(v));
                assert_eq!(p, b.len());
                assert!(b.len() <= pos - before, "canonical encoding longer than one that was read");
                n += 1;
            }
            None => {
                assert!(pos <= data.len());
                break;
            }
        }
    }
    // Negentropy's varints round-trip through put_varint.
    let mut q = data;
    while let Some(v) = neg_varint(&mut q) {
        let mut b = Vec::new();
        negentropy::put_varint(&mut b, v);
        let mut r = b.as_slice();
        assert_eq!(neg_varint(&mut r), Some(v));
        assert!(r.is_empty());
    }
    fp(&[n.min(16)])
}

fn varint_seeds() -> Vec<Vec<u8>> {
    vec![vec![0x80, 0x80, 0x01], vec![0xFF; 10], vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01], vec![0x7F, 0x00]]
}

fn gen_bytes(rng: &mut Rng) -> Vec<u8> {
    let mut b = vec![0u8; rng.skewed(64) as usize];
    rng.fill(&mut b);
    b
}

fn ref_hex(src: &[u8], upper_ok: bool) -> Option<Vec<u8>> {
    if !src.len().is_multiple_of(2) {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' if upper_ok => Some(c - b'A' + 10),
        _ => None,
    };
    src.chunks(2).map(|p| Some(nib(p[0])? << 4 | nib(p[1])?)).collect()
}

pub fn hexes(data: &[u8]) -> u64 {
    let strict = ref_hex(data, false);
    let any = ref_hex(data, true);
    assert_eq!(hex::decode_any_case(data), any);
    if data.len() == 64 {
        assert_eq!(hex::decode_32(data).map(|a| a.to_vec()), strict);
        assert_eq!(hex::is_hex64(data), strict.is_some());
    } else {
        assert!(hex::decode_32(data).is_none());
    }
    if data.len() == 128 {
        assert_eq!(hex::decode_64(data).map(|a| a.to_vec()), strict);
    }
    // Encoding at every offset and length the SIMD paths split on.
    for off in 0..data.len().min(3) {
        let src = &data[off..];
        let mut fast = vec![b'x'; off];
        hex::encode_into(src, &mut fast);
        let slow: Vec<u8> = src.iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect();
        assert_eq!(&fast[off..], &slow[..]);
    }
    fp(&[u64::from(strict.is_some()), u64::from(any.is_some())])
}

fn hex_seeds() -> Vec<Vec<u8>> {
    vec!["ab".repeat(32).into_bytes(), "AB".repeat(32).into_bytes(), "0".repeat(128).into_bytes(), b"abc".to_vec()]
}

fn gen_hex(rng: &mut Rng) -> Vec<u8> {
    let n = *rng.pick(&[64usize, 128, 62, 66, 0, 2, 31, 32, 33]);
    let mut b: Vec<u8> = (0..n).map(|_| *rng.pick(b"0123456789abcdef")).collect();
    if rng.chance(1, 2) && !b.is_empty() {
        let i = rng.usize(b.len());
        b[i] = *rng.pick(b"AFgG/:@`{ \x00\xff");
    }
    b
}

// ---------------------------------------------------------------- negentropy

/// A set of items derived from a few seed bytes: timestamps in a narrow band
/// (so ties and minimal bounds come up), ids from the seed.
fn neg_set(seed: u64, n: usize, ts_span: u64) -> Vec<(u64, [u8; 32])> {
    let mut rng = Rng::new(seed);
    (0..n)
        .map(|_| {
            let t = 1_000 + rng.below(ts_span.max(1));
            let mut id = rng.bytes32();
            if rng.chance(1, 4) {
                id[..6].fill(0x42); // shared prefixes: long minimal bounds
            }
            (t, id)
        })
        .collect()
}

fn ref_storage(items: &[(u64, [u8; 32])]) -> ::negentropy::NegentropyStorageVector {
    let mut st = ::negentropy::NegentropyStorageVector::with_capacity(items.len());
    let mut sorted = items.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    for (t, id) in sorted {
        st.insert(t, ::negentropy::Id::from_byte_array(id)).unwrap();
    }
    st.seal().unwrap();
    st
}

/// Input: `n, span, limit, seed..` then the message. Our responder and the
/// reference must give identical answers whenever ours answers at all.
pub fn neg(data: &[u8]) -> u64 {
    if data.len() < 4 {
        return 1;
    }
    let n = usize::from(data[0]) * 8;
    let span = 1 + u64::from(data[1]) * 3;
    let limit = match data[2] % 4 {
        0 => 0,
        1 => 4096,
        2 => 5000 + usize::from(data[2]) * 100,
        _ => 50_000,
    };
    let items = neg_set(u64::from(data[3]), n, span);
    let msg = &data[4..];
    let ours = negentropy::reconcile(&negentropy::VecStorage::new(items.clone()), msg, limit);
    let st = ref_storage(&items);
    let mut theirs = ::negentropy::Negentropy::borrowed(&st, limit as u64).unwrap();
    let theirs = theirs.reconcile(msg);
    match (&ours, &theirs) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "responder answers differ from the reference (n={n}, limit={limit})"),
        (Ok(_), Err(e)) => panic!("we answer a message the reference refuses ({e:?})"),
        _ => {}
    }
    match ours {
        Ok(o) => fp(&[2, o.len().min(64) as u64 / 8]),
        Err(e) => fp(&[3, fp_str(&e.to_string())]),
    }
}

fn neg_seeds() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    for (n, span, limit, seed, client_n) in [(40u8, 10u8, 0u8, 1u8, 300usize), (200, 200, 1, 2, 10), (10, 1, 3, 3, 2000), (0, 0, 2, 4, 50)] {
        let client = neg_set(u64::from(seed) + 100, client_n, u64::from(span) * 3 + 1);
        let st = ref_storage(&client);
        let mut c = ::negentropy::Negentropy::borrowed(&st, 0).unwrap();
        let mut msg = c.initiate().unwrap();
        let mut input = vec![n, span, limit, seed];
        input.append(&mut msg);
        v.push(input);
    }
    v
}

/// A client message from the reference initiator over a set that overlaps the
/// server's, so every mode and the frame limit come up.
fn gen_neg(rng: &mut Rng) -> Vec<u8> {
    let head = [rng.below(256) as u8, rng.below(64) as u8, rng.below(4) as u8, rng.below(256) as u8];
    let n = usize::from(head[0]) * 8;
    let span = 1 + u64::from(head[1]) * 3;
    let mut client = neg_set(u64::from(head[3]), n, span);
    // Overlap: drop some of the server's items, add some of our own.
    client.retain(|_| rng.chance(3, 4));
    client.extend(neg_set(rng.next_u64(), rng.skewed(500) as usize, span));
    let st = ref_storage(&client);
    let mut c = ::negentropy::Negentropy::borrowed(&st, if rng.chance(1, 2) { 0 } else { 4096 }).unwrap();
    let mut msg = c.initiate().unwrap();
    let mut v = head.to_vec();
    v.append(&mut msg);
    v
}

/// A whole sync between the reference client and our responder: it must
/// converge, and find exactly the set difference.
pub fn neg_sync(data: &[u8]) -> u64 {
    let get = |i: usize| u64::from(data.get(i).copied().unwrap_or(0));
    let span = 1 + get(0) * 5;
    let n_server = (get(1) * 12) as usize;
    let seed = get(2) | get(3) << 8;
    let limit = if get(4) % 2 == 0 { 0 } else { 4096 + (get(5) * 200) as usize };
    let server = neg_set(seed, n_server, span);
    let mut rng = Rng::new(seed ^ 0xABCD);
    let mut client: Vec<(u64, [u8; 32])> = server.iter().copied().filter(|_| rng.chance(get(6) % 4 + 1, 5)).collect();
    client.extend(neg_set(seed ^ 77, (get(7) * 8) as usize, span));
    let ours = negentropy::VecStorage::new(server.clone());
    let st = ref_storage(&client);
    let mut c = ::negentropy::Negentropy::borrowed(&st, limit as u64).unwrap();
    let mut msg = c.initiate().unwrap();
    let (mut have, mut need) = (Vec::new(), Vec::new());
    let mut rounds = 0;
    loop {
        let resp = negentropy::reconcile(&ours, &msg, limit).expect("responder refuses the reference client");
        match c.reconcile_with_ids(&resp, &mut have, &mut need).expect("reference client refuses our answer") {
            Some(next) => msg = next,
            None => break,
        }
        rounds += 1;
        assert!(rounds < 10_000, "sync does not converge");
    }
    let sset: std::collections::HashSet<[u8; 32]> = server.iter().map(|x| x.1).collect();
    let cset: std::collections::HashSet<[u8; 32]> = client.iter().map(|x| x.1).collect();
    let mut want_need: Vec<[u8; 32]> = sset.difference(&cset).copied().collect();
    let mut want_have: Vec<[u8; 32]> = cset.difference(&sset).copied().collect();
    let mut got_need: Vec<[u8; 32]> = need.iter().map(|i| *i.as_bytes()).collect();
    let mut got_have: Vec<[u8; 32]> = have.iter().map(|i| *i.as_bytes()).collect();
    for v in [&mut want_need, &mut want_have, &mut got_need, &mut got_have] {
        v.sort_unstable();
        v.dedup();
    }
    assert_eq!(got_need, want_need, "sync missed or invented events the server has");
    assert_eq!(got_have, want_have, "sync missed or invented events only the client has");
    fp(&[rounds.min(16) as u64])
}
