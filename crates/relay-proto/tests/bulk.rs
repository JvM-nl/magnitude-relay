//! The bulk verifier against the one-event path: for every line, the same
//! verdict and (when accepted) the same record bytes as
//! `parse_event_json(line, .., true)`, whatever else shares its batch.

use relay_proto::event::{parse_event_json, BulkVerifier, EventInfo, Reject};
use relay_proto::{hex, EventParser};
use secp256k1::{schnorr, Keypair};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Signer(Keypair);

impl Signer {
    fn new(seed: u8) -> Self {
        Signer(Keypair::from_secret_bytes([seed; 32]).unwrap())
    }

    fn pubkey_hex(&self) -> String {
        hex::encode_string(&self.0.x_only_public_key().0.to_byte_array())
    }

    fn sign_preimage(&self, preimage: &str) -> (String, String) {
        let id: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
        let sig = schnorr::sign_no_aux_rand(&id, &self.0);
        (hex::encode_string(&id), hex::encode_string(&sig.to_byte_array()))
    }

    fn event(&self, created_at: u64, kind: u64, tags: Value, content: &str) -> String {
        let pk = self.pubkey_hex();
        let pre = serde_json::to_string(&json!([0, pk, created_at, kind, tags, content])).unwrap();
        let (id, sig) = self.sign_preimage(&pre);
        format!(
            r#"{{"id":"{id}","pubkey":"{pk}","created_at":{created_at},"kind":{kind},"tags":{},"content":{},"sig":"{sig}"}}"#,
            serde_json::to_string(&tags).unwrap(),
            serde_json::to_string(content).unwrap()
        )
    }
}

fn reference(line: &str) -> (Result<EventInfo, Reject>, Vec<u8>) {
    let mut rec = Vec::new();
    let r = parse_event_json(line, &mut EventParser::new(), &mut rec, true);
    (r, rec)
}

fn field(ev: &str, name: &str) -> String {
    let v: Value = serde_json::from_str(ev).unwrap();
    v[name].as_str().unwrap().to_string()
}

/// Every kind of line the one-event path tells apart.
fn corpus() -> Vec<String> {
    let signers: Vec<Signer> = (1..=12).map(Signer::new).collect();
    let mut lines = Vec::new();
    let mut seed = 7u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for i in 0..400u64 {
        let s = &signers[(next() % 12) as usize];
        let len = (next() % 5000) as usize;
        let content: String = (0..len).map(|j| (b'a' + ((j as u64 + i) % 26) as u8) as char).collect();
        let tags = json!([["p", hex::encode_string(&[i as u8; 32])], ["t", format!("tag{i}")]]);
        let ev = s.event(1_700_000_000 + i, [1059, 1, 0, 30078][(i % 4) as usize], tags, &content);
        let sig = field(&ev, "sig");
        let line = match next() % 10 {
            // Content changed after signing: the id no longer matches.
            0 => ev.replacen("\"content\":\"", "\"content\":\"X", 1),
            // One signature bit flipped.
            1 => {
                let mut b = sig.clone().into_bytes();
                b[(next() % 128) as usize] = if b[5] == b'0' { b'1' } else { b'0' };
                ev.replace(&sig, std::str::from_utf8(&b).unwrap())
            }
            // A valid event with trailing bytes: rejected as malformed JSON.
            2 => ev.clone() + " x",
            // A bad signature and trailing bytes: the signature is reported.
            3 => ev.replace(&sig, &"0".repeat(128)) + "]",
            _ => ev,
        };
        lines.push(line);
    }
    // The raw-form fallback (a serialiser that escapes DEL), built without a
    // literal backslash-u in this file.
    let del = format!("x{}u007fy", '\\');
    let s = &signers[0];
    let pk = s.pubkey_hex();
    let pre = format!(r#"[0,"{pk}",1700000002,1,[],"{del}"]"#);
    let (id, sig) = s.sign_preimage(&pre);
    let raw = format!(r#"{{"content":"{del}","created_at":1700000002,"id":"{id}","kind":1,"pubkey":"{pk}","sig":"{sig}","tags":[]}}"#);
    lines.push(raw.clone());
    // Escaped, but matching neither form.
    lines.push(raw.replace("x", "z"));
    // Legal escapes of a canonical event: still valid.
    let e = format!("caf{}u00e9", '\\');
    let ev = s.event(1_700_000_005, 14, json!([]), "café");
    lines.push(ev.replace("café", &e));
    // A pubkey that is not a curve x, with an id over it: the signature fails.
    let bad_pk = "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34";
    let pre = format!(r#"[0,"{bad_pk}",1700000006,1,[],"k"]"#);
    let id = hex::encode_string(&<[u8; 32]>::from(Sha256::digest(pre.as_bytes())));
    lines.push(format!(r#"{{"content":"k","created_at":1700000006,"id":"{id}","kind":1,"pubkey":"{bad_pk}","sig":"{}","tags":[]}}"#, "1".repeat(128)));
    // Malformed lines.
    let ev = s.event(1, 1, json!([]), "x");
    lines.push(ev.replace("\"kind\":1", "\"kind\":-1"));
    lines.push(ev.replace(",\"content\":\"x\"", ""));
    lines.push(ev.replace("\"id\":\"", "\"id\":\"A"));
    lines.push(String::new());
    lines.push("{".into());
    // The same event twice.
    lines.push(ev.clone());
    lines.push(ev);
    lines
}

#[test]
fn bulk_verdicts_match_one_by_one() {
    let mut lines = corpus();
    // Interleave the special lines with the rest.
    let mut seed = 99u64;
    for i in (1..lines.len()).rev() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        lines.swap(i, (seed >> 33) as usize % (i + 1));
    }
    let want: Vec<_> = lines.iter().map(|l| reference(l)).collect();
    assert!(want.iter().any(|(r, _)| r.is_ok()) && want.iter().any(|(r, _)| *r == Err(Reject::SigInvalid)));
    assert!(want.iter().any(|(r, _)| *r == Err(Reject::IdMismatch)));
    // The raw-form fallback is among the accepted lines.
    assert!(want.iter().any(|(r, rec)| r.is_ok() && relay_proto::Record(rec).flags() & relay_proto::record::FLAG_RAW_FORM != 0));
    let mut bulk = BulkVerifier::new();
    for chunk in [1usize, 2, 7, 64, 300, lines.len()] {
        for (c, part) in lines.chunks(chunk).enumerate() {
            let refs: Vec<&str> = part.iter().map(String::as_str).collect();
            bulk.verify(&refs);
            let got = bulk.results().to_vec();
            for (j, g) in got.iter().enumerate() {
                let (w, rec) = &want[c * chunk + j];
                assert_eq!(g, w, "line {}: {}", c * chunk + j, &part[j][..part[j].len().min(120)]);
                if g.is_ok() {
                    assert_eq!(bulk.record(j), rec.as_slice(), "record of line {}", c * chunk + j);
                }
            }
        }
    }
}
