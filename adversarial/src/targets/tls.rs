//! relay-tls: DER and X.509 (certificates a CA or an operator hands us), PEM
//! files, the JSON of ACME documents, and URLs from the ACME directory.

use super::{fp, fp_str, linear_cap, Target};
use crate::rng::Rng;
use relay_tls::{der, json, pem, x509};

pub fn targets() -> Vec<Target> {
    vec![
        Target { name: "der", run: der_walk, seeds: der_seeds, generate: gen_der, dict: &[b"\x30\x82", b"\x06\x03\x55\x1d\x11", b"\xa0\x03\x02\x01\x02", b"\x17\x0d", b"\x18\x0f", b"\x84\xff\xff\xff\xff"], max_len: 64 << 10, mem_cap: linear_cap },
        Target { name: "pem", run: pem_text, seeds: pem_seeds, generate: gen_pem, dict: &[b"-----BEGIN CERTIFICATE-----\n", b"-----END CERTIFICATE-----\n", b"-----BEGIN PRIVATE KEY-----\n", b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n", b"=="], max_len: 64 << 10, mem_cap: linear_cap },
        Target { name: "tls_json", run: tls_json, seeds: json_seeds, generate: gen_json, dict: &[b"\"status\":\"valid\"", b"\"challenges\":[", b"1e400", b"-0", b"\\u0000", b"\\ud800"], max_len: 64 << 10, mem_cap: linear_cap },
        Target { name: "url", run: url, seeds: || vec![b"https://acme.example:8443/dir?x=1#frag".to_vec(), b"http://[::1]:80/".to_vec()], generate: gen_url, dict: &[b"https://", b"http://", b"[", b"]", b":", b"@", b"#", b"?"], max_len: 4096, mem_cap: linear_cap },
    ]
}

/// Walks every element, recursing into anything that might be constructed, and
/// reads every value type the ACME code reads.
fn walk(r: &mut der::Reader<'_>, depth: u32, n: &mut u64) {
    while !r.is_empty() {
        let Ok(t) = r.next() else { return };
        *n += 1;
        assert!(t.raw.len() >= t.content.len() + 2 && t.raw.ends_with(t.content));
        let _ = der::integer_magnitude(&t);
        let _ = der::oid_to_string(t.content);
        let _ = der::parse_time(&t);
        if depth < 64 && (t.tag & 0x20 != 0 || t.tag == der::OCTET_STRING || t.tag == der::BIT_STRING) {
            walk(&mut t.children(), depth + 1, n);
        }
    }
}

pub fn der_walk(data: &[u8]) -> u64 {
    let mut n = 0;
    walk(&mut der::Reader::new(data), 0, &mut n);
    let cert = x509::parse_certificate(data);
    if let Ok(info) = &cert {
        let _ = info.covers(&["example.com".to_string()]);
    }
    fp(&[n.min(32), u64::from(cert.is_ok()), cert.err().map_or(0, |e| fp_str(e.0))])
}

fn sample_cert() -> Vec<u8> {
    static C: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        let key = x509::EcKey::generate().expect("key");
        x509::acme_challenge_certificate(&key, "relay.example", [7; 32], 1_700_000_000)
    })
    .clone()
}

fn der_seeds() -> Vec<Vec<u8>> {
    let key = x509::EcKey::generate().expect("key");
    vec![sample_cert(), x509::csr(&key, &["a.example".to_string(), "b.example".to_string()]), key.pkcs8().to_vec()]
}

fn gen_der(rng: &mut Rng) -> Vec<u8> {
    // Nested TLVs with random tags and occasionally wrong lengths.
    fn tlv(rng: &mut Rng, depth: u32) -> Vec<u8> {
        let tag = *rng.pick(&[0x30u8, 0x31, 0x02, 0x04, 0x03, 0x06, 0x0c, 0x17, 0x18, 0xa0, 0xa3, 0x82, 0x1f]);
        let content = if depth > 0 && tag & 0x20 != 0 {
            (0..rng.skewed(4)).flat_map(|_| tlv(rng, depth - 1)).collect()
        } else {
            let mut c = vec![0u8; rng.skewed(40) as usize];
            rng.fill(&mut c);
            if tag == 0x17 {
                c = b"250101000000Z".to_vec();
            }
            c
        };
        let mut v = der::tlv(tag, &content);
        if rng.chance(1, 10) && v.len() > 1 {
            v[1] = rng.next_u64() as u8;
        }
        v
    }
    if rng.chance(1, 3) {
        let mut c = sample_cert();
        let i = rng.usize(c.len());
        c[i] ^= 1 << rng.below(8);
        return c;
    }
    tlv(rng, 5)
}

pub fn pem_text(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else { return 1 };
    let r = pem::decode(s);
    if let Ok(blocks) = &r {
        // Every block re-encodes to text that decodes to the same block.
        for b in blocks {
            if b.label.contains('\n') || b.label.contains('\r') {
                continue;
            }
            let again = pem::decode(&pem::encode(&b.label, &b.der)).expect("our own PEM decodes");
            assert_eq!(again.len(), 1);
            assert_eq!(&again[0], b);
        }
    }
    let c = pem::certificates(s);
    let k = pem::private_key(s);
    fp(&[u64::from(r.is_ok()), u64::from(c.is_ok()), u64::from(k.is_ok())])
}

fn pem_seeds() -> Vec<Vec<u8>> {
    let key = x509::EcKey::generate().expect("key");
    let mut s = String::from("# a chain file\n");
    s.push_str(&pem::encode("CERTIFICATE", &sample_cert()));
    s.push_str(&pem::encode("PRIVATE KEY", key.pkcs8()));
    vec![s.into_bytes()]
}

fn gen_pem(rng: &mut Rng) -> Vec<u8> {
    let mut b = vec![0u8; rng.skewed(300) as usize];
    rng.fill(&mut b);
    let label = *rng.pick(&["CERTIFICATE", "PRIVATE KEY", "EC PRIVATE KEY", "X", ""]);
    let mut s = pem::encode(label, &b);
    if rng.chance(1, 3) {
        s = s.replace('\n', "\r\n");
    }
    if rng.chance(1, 4) {
        s.truncate(rng.usize(s.len() + 1));
    }
    s.into_bytes()
}

/// The ACME JSON parser against serde_json, and its own output read back.
pub fn tls_json(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else { return 1 };
    let ours = json::parse(s);
    let theirs = serde_json::from_str::<serde_json::Value>(s);
    match (&ours, &theirs) {
        (Ok(v), Ok(_)) => {
            let text = v.to_string();
            let back = json::parse(&text).unwrap_or_else(|e| panic!("our own JSON {text:?} does not parse: {e}"));
            assert_eq!(&back, v, "value changes through its JSON");
        }
        (Ok(_), Err(e)) if !e.to_string().contains("number out of range") && !e.to_string().contains("surrogate") => {
            panic!("ACME JSON parser accepts what serde_json rejects ({e}): {s:?}")
        }
        (Err(e), Ok(_)) if e.msg != "nested too deeply" => panic!("ACME JSON parser rejects JSON ({e}): {s:?}"),
        _ => {}
    }
    match ours {
        Ok(_) => 2,
        Err(e) => fp(&[3, fp_str(e.msg)]),
    }
}

fn json_seeds() -> Vec<Vec<u8>> {
    vec![
        br#"{"status":"pending","expires":"2026-10-21T00:00:00Z","identifier":{"type":"dns","value":"r.example"},"challenges":[{"type":"tls-alpn-01","url":"https://a/c/1","token":"tok"}]}"#.to_vec(),
        b"[1.5e3,-0,true,null,\"\\u00e9\\ud83d\\ude00\"]".to_vec(),
    ]
}

fn gen_json(rng: &mut Rng) -> Vec<u8> {
    crate::gen::json_value(rng, 5).into_bytes()
}

pub fn url(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else { return 1 };
    match relay_tls::http::Url::parse(s) {
        Ok(u) => {
            assert!(u.target.starts_with('/'), "target without a leading slash: {s:?}");
            assert!(!u.host.is_empty());
            assert!(u.target.bytes().chain(u.host.bytes()).all(|b| b > b' ' && b != 0x7F), "control character survives in {s:?}");
            assert!(!u.target.contains('#'), "fragment survives in {s:?}");
            fp(&[2, u64::from(u.tls)])
        }
        Err(e) => fp(&[3, fp_str(&e[e.find(':').unwrap_or(0)..])]),
    }
}

fn gen_url(rng: &mut Rng) -> Vec<u8> {
    let scheme = *rng.pick(&["https://", "http://", "ftp://", ""]);
    let host = *rng.pick(&["acme.example", "[::1]", "[fe80::1", "a@b", "", "x:y:z", "h"]);
    let port = *rng.pick(&["", ":443", ":0", ":65536", ":-1", ":"]);
    let path = *rng.pick(&["", "/", "/dir", "?q", "/a b", "/#f", "/\x7f"]);
    format!("{scheme}{host}{port}{path}").into_bytes()
}
