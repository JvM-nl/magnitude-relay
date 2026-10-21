//! Structure-aware generators: JSON with every awkward string and number the
//! grammar allows (and some it does not), Nostr events (signed or not),
//! filters and client messages. The fuzz targets start from these, and the
//! hostile client sends them.

use crate::rng::Rng;
use crate::sign::Keys;

/// One JSON string body (no quotes): plain text, every short escape, `\u`
/// escapes of control characters, lone and paired surrogates, raw multi-byte
/// UTF-8, and the odd byte JSON forbids raw.
pub fn json_string(rng: &mut Rng, max: usize) -> String {
    let n = rng.skewed(max as u64) as usize;
    let mut s = String::new();
    while s.len() < n {
        match rng.below(20) {
            0 => s.push_str(*rng.pick(&["\\\"", "\\\\", "\\/", "\\b", "\\f", "\\n", "\\r", "\\t"])),
            1 => s.push_str(&format!("\\u{:04x}", rng.below(0x20))),
            2 => s.push_str(&format!("\\u{:04X}", rng.below(0x10000))),
            3 => s.push_str(&format!("\\u{:04x}", 0xD800 + rng.below(0x800))),
            4 => {
                let hi = 0xD800 + rng.below(0x400);
                let lo = 0xDC00 + rng.below(0x400);
                s.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
            }
            5 => s.push(*rng.pick(&['é', 'ß', '中', '😀', '\u{7f}', '\u{2028}', '\u{feff}', '\u{10ffff}'])),
            6 if rng.chance(1, 8) => s.push(char::from(rng.below(0x20) as u8)),
            7 => s.push_str("\\u0000"),
            _ => s.push(char::from(b'a' + rng.below(26) as u8)),
        }
    }
    s
}

/// A number in one of JSON's spellings, or one of the near misses.
pub fn json_number(rng: &mut Rng) -> String {
    match rng.below(12) {
        0 => rng.next_u64().to_string(),
        1 => (rng.next_u64() >> rng.below(64)).to_string(),
        2 => format!("-{}", rng.below(1000)),
        3 => format!("{}.{}", rng.below(100), rng.below(100)),
        4 => format!("{}e{}", rng.below(10), rng.below(400)),
        5 => format!("{}E-{}", rng.below(10), rng.below(20)),
        6 => "18446744073709551616".into(),
        7 => format!("0{}", rng.below(10)),
        8 => "-0".into(),
        9 => "1e309".into(),
        _ => rng.below(100_000).to_string(),
    }
}

/// A JSON value of bounded depth.
pub fn json_value(rng: &mut Rng, depth: u32) -> String {
    match if depth == 0 { rng.below(4) } else { rng.below(7) } {
        0 => format!("\"{}\"", json_string(rng, 40)),
        1 => json_number(rng),
        2 => (*rng.pick(&["true", "false", "null"])).to_string(),
        3 => "[]".into(),
        4 | 5 => {
            let n = rng.skewed(6) as usize;
            let items: Vec<String> = (0..n).map(|_| json_value(rng, depth - 1)).collect();
            format!("[{}]", items.join(","))
        }
        _ => {
            let n = rng.skewed(6) as usize;
            let items: Vec<String> = (0..n).map(|_| format!("\"{}\":{}", json_string(rng, 8), json_value(rng, depth - 1))).collect();
            format!("{{{}}}", items.join(","))
        }
    }
}

pub fn hex(b: &[u8]) -> String {
    relay_proto::hex::encode_string(b)
}

/// Tags: p/e with hex values, d, t, expiration, a, long and escaped values.
pub fn tags(rng: &mut Rng, max: usize) -> String {
    let n = rng.skewed(max as u64) as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = match rng.below(10) {
            0 | 1 => format!("[\"p\",\"{}\"]", hex(&rng.bytes32())),
            2 => format!("[\"e\",\"{}\",\"wss://r.example\",\"reply\"]", hex(&rng.bytes32())),
            3 => format!("[\"d\",\"{}\"]", json_string(rng, 12)),
            4 => format!("[\"expiration\",\"{}\"]", json_number(rng).trim_matches('-')),
            5 => format!("[\"a\",\"{}:{}:{}\"]", rng.below(40_000), hex(&rng.bytes32()), json_string(rng, 8)),
            6 => "[\"-\"]".to_string(),
            7 => "[]".to_string(),
            8 => format!("[\"t\",\"{}\"]", json_string(rng, 300)),
            _ => {
                let k = rng.skewed(5) as usize;
                let parts: Vec<String> = (0..k).map(|_| format!("\"{}\"", json_string(rng, 20))).collect();
                format!("[{}]", parts.join(","))
            }
        };
        out.push(t);
    }
    format!("[{}]", out.join(","))
}

pub fn kind(rng: &mut Rng) -> u64 {
    *rng.pick(&[0, 1, 3, 5, 7, 14, 62, 1059, 10002, 10050, 13303, 21059, 24590, 30078, 33301, 33302, 40000, 65535, u64::MAX >> 1])
}

/// An event document. `signed`: a real id and signature over the canonical
/// form (the content and tags are then valid JSON); otherwise every field is
/// random and the object may be malformed on purpose.
pub fn event_json(rng: &mut Rng, keys: Option<&Keys>) -> String {
    let content = json_string(rng, 200);
    let tags = tags(rng, 8);
    let created_at = if rng.chance(1, 8) { rng.next_u64() >> rng.below(64) } else { 1_700_000_000 + rng.below(100_000_000) };
    let kind = kind(rng);
    if let Some(k) = keys {
        if let Some(ev) = k.sign_json(created_at, kind, &tags, &content) {
            return ev;
        }
    }
    let mut fields = vec![
        format!("\"id\":\"{}\"", hex(&rng.bytes32())),
        format!("\"pubkey\":\"{}\"", hex(&rng.bytes32())),
        format!("\"created_at\":{created_at}"),
        format!("\"kind\":{kind}"),
        format!("\"tags\":{tags}"),
        format!("\"content\":\"{content}\""),
        format!("\"sig\":\"{}{}\"", hex(&rng.bytes32()), hex(&rng.bytes32())),
    ];
    if rng.chance(1, 4) {
        fields.push(format!("\"{}\":{}", json_string(rng, 6), json_value(rng, 2)));
    }
    if rng.chance(1, 6) {
        let i = rng.usize(fields.len());
        fields.remove(i);
    }
    if rng.chance(1, 6) {
        let i = rng.usize(fields.len());
        fields.push(fields[i].clone());
    }
    let mut v = fields;
    if rng.chance(1, 2) {
        let n = v.len();
        for i in 0..n {
            let j = rng.usize(n);
            v.swap(i, j);
        }
    }
    format!("{{{}}}", v.join(","))
}

/// A filter, mostly valid, with lists at and past the relay's limits now and then.
pub fn filter_json(rng: &mut Rng, big: bool) -> String {
    let mut parts = Vec::new();
    let list = |rng: &mut Rng, cap: u64| if big && rng.chance(1, 4) { 1 + rng.below(cap) as usize } else { rng.skewed(8) as usize };
    if rng.chance(1, 4) {
        let n = list(rng, 6000);
        let v: Vec<String> = (0..n).map(|_| format!("\"{}\"", hex(&rng.bytes32()))).collect();
        parts.push(format!("\"ids\":[{}]", v.join(",")));
    }
    if rng.chance(1, 3) {
        let n = list(rng, 6000);
        let v: Vec<String> = (0..n).map(|_| format!("\"{}\"", hex(&rng.bytes32()))).collect();
        parts.push(format!("\"authors\":[{}]", v.join(",")));
    }
    if rng.chance(1, 2) {
        let n = list(rng, 6000);
        let v: Vec<String> = (0..n).map(|_| if rng.chance(1, 10) { json_number(rng) } else { kind(rng).to_string() }).collect();
        parts.push(format!("\"kinds\":[{}]", v.join(",")));
    }
    for _ in 0..rng.skewed(3) {
        let name = if rng.chance(1, 10) { json_string(rng, 3) } else { char::from(*rng.pick(b"peadtkrPZ")).to_string() };
        let n = list(rng, 6000);
        let v: Vec<String> = (0..n)
            .map(|_| if rng.chance(1, 2) { format!("\"{}\"", hex(&rng.bytes32())) } else { format!("\"{}\"", json_string(rng, 30)) })
            .collect();
        parts.push(format!("\"#{name}\":[{}]", v.join(",")));
    }
    for key in ["since", "until", "limit"] {
        if rng.chance(1, 3) {
            parts.push(format!("\"{key}\":{}", json_number(rng)));
        }
    }
    if rng.chance(1, 20) {
        parts.push(format!("\"search\":\"{}\"", json_string(rng, 10)));
    }
    if rng.chance(1, 10) {
        parts.push(format!("\"{}\":{}", json_string(rng, 6), json_value(rng, 2)));
    }
    if rng.chance(1, 10) && !parts.is_empty() {
        let i = rng.usize(parts.len());
        parts.push(parts[i].clone());
    }
    format!("{{{}}}", parts.join(","))
}

pub fn sub_id(rng: &mut Rng) -> String {
    match rng.below(10) {
        0 => String::new(),
        1 => "x".repeat(64),
        2 => "x".repeat(65),
        3 => json_string(rng, 70),
        _ => format!("s{}", rng.below(300)),
    }
}

/// A client message of any command, valid or nearly.
pub fn client_msg(rng: &mut Rng, keys: Option<&Keys>) -> String {
    match rng.below(10) {
        0 | 1 => format!("[\"EVENT\",{}]", event_json(rng, keys)),
        2 | 3 => {
            let n = rng.skewed(4) as usize;
            let fs: Vec<String> = (0..n).map(|_| filter_json(rng, false)).collect();
            format!("[\"REQ\",\"{}\"{}{}]", sub_id(rng), if n > 0 { "," } else { "" }, fs.join(","))
        }
        4 => format!("[\"COUNT\",\"{}\",{}]", sub_id(rng), filter_json(rng, false)),
        5 => format!("[\"CLOSE\",\"{}\"]", sub_id(rng)),
        6 => format!("[\"NEG-OPEN\",\"{}\",{},\"{}\"]", sub_id(rng), filter_json(rng, false), neg_hex(rng)),
        7 => format!("[\"NEG-MSG\",\"{}\",\"{}\"]", sub_id(rng), neg_hex(rng)),
        8 => format!("[\"AUTH\",{}]", event_json(rng, None)),
        _ => json_value(rng, 3),
    }
}

fn neg_hex(rng: &mut Rng) -> String {
    let n = rng.skewed(200) as usize;
    let mut b = vec![0u8; n];
    rng.fill(&mut b);
    if !b.is_empty() && rng.chance(3, 4) {
        b[0] = 0x61;
    }
    let h = hex(&b);
    if rng.chance(1, 10) {
        h.to_uppercase()
    } else {
        h
    }
}
