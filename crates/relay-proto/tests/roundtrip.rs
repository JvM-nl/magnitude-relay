//! End-to-end checks of the event path against an independent reference:
//! events are built and signed the way clients do it (serde_json canonical
//! form + libsecp256k1), then pushed through our parser and back out.

use relay_proto::event::{compute_id, parse_event_json, Reject};
use relay_proto::json::Scanner;
use relay_proto::message::ClientMsg;
use relay_proto::{hex, EventParser, Filter, Record};
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

    /// Signs over `preimage` exactly as given (lets tests sign non-canonical forms).
    fn sign_preimage(&self, preimage: &str) -> (String, String) {
        let id: [u8; 32] = Sha256::digest(preimage.as_bytes()).into();
        let sig = schnorr::sign_no_aux_rand(&id, &self.0);
        (hex::encode_string(&id), hex::encode_string(&sig.to_byte_array()))
    }

    /// A client-built event: canonical preimage by serde_json, keys in the
    /// order most clients send them (id first, not alphabetical).
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

fn parse(json: &str) -> Result<Vec<u8>, Reject> {
    let mut p = EventParser::new();
    let mut rec = Vec::new();
    parse_event_json(json, &mut p, &mut rec, true)?;
    Ok(rec)
}

#[test]
fn signed_event_round_trips() {
    let s = Signer::new(7);
    let p_hex = "a".repeat(64);
    let tags = json!([["p", p_hex], ["t", "vector"], ["expiration", "1900000000"], ["e", "ABCD"], []]);
    let ev = s.event(1_700_000_000, 1059, tags.clone(), "hello\n\"world\" é 😀 \u{1}");
    let rec = parse(&ev).expect("valid event");
    let r = Record(&rec);
    assert_eq!(r.kind(), 1059);
    assert_eq!(r.created_at(), 1_700_000_000);
    assert_eq!(r.expiration(), Some(1_900_000_000));
    assert!(!r.is_protected());

    // Our output means the same thing as the input...
    let out = r.to_json();
    let a: Value = serde_json::from_str(&ev).unwrap();
    let b: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(a, b);
    // ...is in strfry's alphabetical key order...
    let keys: Vec<&str> = ["\"content\"", "\"created_at\"", "\"id\"", "\"kind\"", "\"pubkey\"", "\"sig\"", "\"tags\""]
        .into_iter()
        .collect();
    let mut last = 0;
    for k in keys {
        let at = out.find(k).unwrap();
        assert!(at >= last, "{k} out of order in {out}");
        last = at;
    }
    assert_eq!(r.json_len(), out.len());
    // ...and re-parses to the identical record (a fixed point).
    assert_eq!(parse(&out).unwrap(), rec);

    // The 64-hex p value was compacted; the uppercase e value was not.
    let fields: Vec<_> = r.tags().map(|t| t.fields().count()).collect();
    assert_eq!(fields, vec![2, 2, 2, 2, 0]);
    assert!(rec.len() < ev.len() - 64, "compaction saved the hex");
}

#[test]
fn tampering_is_caught() {
    let s = Signer::new(9);
    let ev = s.event(1_700_000_000, 1, json!([]), "original");
    assert_eq!(parse(&ev.replace("original", "tampered")), Err(Reject::IdMismatch));

    let v: Value = serde_json::from_str(&ev).unwrap();
    let sig = v["sig"].as_str().unwrap();
    let mut bad = sig.as_bytes().to_vec();
    bad[0] = if bad[0] == b'0' { b'1' } else { b'0' };
    let forged = ev.replace(sig, std::str::from_utf8(&bad).unwrap());
    assert_eq!(parse(&forged), Err(Reject::SigInvalid));

    // Another key's signature over the same id.
    let other = Signer::new(10);
    let id = v["id"].as_str().unwrap();
    let mut idb = [0u8; 32];
    hex::decode_into(id.as_bytes(), &mut idb);
    let osig = hex::encode_string(&schnorr::sign_no_aux_rand(&idb, &other.0).to_byte_array());
    assert_eq!(parse(&ev.replace(sig, &osig)), Err(Reject::SigInvalid));
}

#[test]
fn wire_escaping_does_not_matter() {
    // The same event, its content escaped in three different (legal) ways:
    // the id commits to the canonical form, so all three must verify and
    // store identically.
    let s = Signer::new(11);
    let ev = s.event(1_700_000_001, 14, json!([["d", "a/b"]]), "café/é");
    let variants = [
        ev.clone(),
        ev.replace("café/é", "caf\\u00e9\\/\\u00E9"),
        ev.replace("\"a/b\"", "\"a\\/b\""),
    ];
    let recs: Vec<_> = variants.iter().map(|v| parse(v).expect(v)).collect();
    assert!(recs.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn raw_form_fallback_for_other_serialisers() {
    // A serialiser that escapes DEL (tao, strfry's) signs over "\u007f". The
    // canonical form keeps DEL raw, so only the as-received form matches.
    let s = Signer::new(12);
    let pk = s.pubkey_hex();
    let pre = format!(r#"[0,"{pk}",1700000002,1,[],"x\u007fy"]"#);
    let (id, sig) = s.sign_preimage(&pre);
    let ev = format!(
        r#"{{"content":"x\u007fy","created_at":1700000002,"id":"{id}","kind":1,"pubkey":"{pk}","sig":"{sig}","tags":[]}}"#
    );
    let rec = parse(&ev).expect("raw form accepted");
    let r = Record(&rec);
    assert_ne!(r.flags() & relay_proto::record::FLAG_RAW_FORM, 0);
    // Re-export is byte-identical to what strfry stored.
    assert_eq!(r.to_json(), ev);
    let mut scratch = Vec::new();
    assert_eq!(&compute_id(r, &mut scratch), r.id());
}

#[test]
fn strfry_export_lines_are_byte_identical() {
    // A strfry export line is tao JSON: alphabetical keys, canonical escapes.
    let s = Signer::new(13);
    let pk = s.pubkey_hex();
    let tags = json!([["p", "b".repeat(64)], ["subject", "Ünïcödé \"q\""], ["-"]]);
    let content = "line1\nline2\ttab \\ back";
    let pre = serde_json::to_string(&json!([0, pk, 1700000003u64, 4, tags, content])).unwrap();
    let (id, sig) = s.sign_preimage(&pre);
    let line = format!(
        r#"{{"content":{},"created_at":1700000003,"id":"{id}","kind":4,"pubkey":"{pk}","sig":"{sig}","tags":{}}}"#,
        serde_json::to_string(content).unwrap(),
        serde_json::to_string(&tags).unwrap()
    );
    let rec = parse(&line).unwrap();
    assert!(Record(&rec).is_protected());
    assert_eq!(Record(&rec).to_json(), line);
}

#[test]
fn malformed_events() {
    let s = Signer::new(14);
    let ev = s.event(1, 1, json!([]), "x");
    let cases = [
        ev.replace("\"kind\":1", "\"kind\":1.0"),
        ev.replace("\"kind\":1", "\"kind\":-1"),
        ev.replace("\"kind\":1", "\"kind\":\"1\""),
        ev.replace("\"tags\":[]", "\"tags\":[[1]]"),
        ev.replace("\"tags\":[]", "\"tags\":{}"),
        ev.replace(",\"content\":\"x\"", ""),
        ev.replace("\"content\":\"x\"", "\"content\":\"x\",\"content\":\"x\""),
        ev.replace("\"id\":\"", "\"id\":\"A"),
        ev.clone() + "x",
    ];
    for c in &cases {
        assert!(parse(c).is_err(), "should reject {c}");
    }
    // Unknown fields are ignored, as strfry does.
    let extra = ev.replacen('{', "{\"relays\":[\"wss://x\"],\"seen\":{\"a\":[1,2]},", 1);
    assert!(parse(&extra).is_ok());
}

fn filter(json: &str) -> Filter {
    Filter::parse(&mut Scanner::new(json)).unwrap()
}

#[test]
fn filters_match() {
    let s = Signer::new(15);
    let me = "c".repeat(64);
    let ev = s.event(1_700_000_100, 1059, json!([["p", me], ["k", "3313"]]), "wrap");
    let rec = parse(&ev).unwrap();
    let r = Record(&rec);
    let pk = s.pubkey_hex();

    let yes = [
        "{}".to_string(),
        format!(r##"{{"kinds":[1059],"#p":["{me}"]}}"##),
        format!(r##"{{"kinds":[1,1059],"#p":["{}","{me}"],"since":1700000100}}"##, "d".repeat(64)),
        format!(r#"{{"authors":["{pk}"],"until":1700000100}}"#),
        r##"{"#k":["3313"]}"##.to_string(),
    ];
    for f in &yes {
        assert!(filter(f).matches(r), "should match {f}");
    }
    let no = [
        r#"{"kinds":[1]}"#.to_string(),
        format!(r##"{{"#p":["{}"]}}"##, "d".repeat(64)),
        r#"{"since":1700000101}"#.to_string(),
        r#"{"until":1700000099}"#.to_string(),
        format!(r#"{{"authors":["{}"]}}"#, "e".repeat(64)),
        r##"{"#k":["3314"]}"##.to_string(),
        r##"{"#e":["x"]}"##.to_string(),
    ];
    for f in &no {
        assert!(!filter(f).matches(r), "should not match {f}");
    }
    assert!(filter(r#"{"kinds":[]}"#).never_matches());
    assert!(filter(r#"{"since":5,"until":4}"#).never_matches());
    assert!(Filter::parse(&mut Scanner::new(r#"{"search":"x"}"#)).is_err());
    assert!(Filter::parse(&mut Scanner::new(r#"{"bogus":1}"#)).is_err());
    assert!(Filter::parse(&mut Scanner::new(r##"{"#pp":["x"]}"##)).is_err());
    assert!(Filter::parse(&mut Scanner::new(r#"{"ids":["abc"]}"#)).is_err());
}

#[test]
fn client_messages() {
    let s = Signer::new(16);
    let ev = s.event(1_700_000_200, 1059, json!([]), "m");
    let mut p = EventParser::new();
    let mut rec = Vec::new();

    let text = format!(r#"["EVENT",{ev}]"#);
    match ClientMsg::parse(&text, &mut p, &mut rec).unwrap() {
        ClientMsg::Event { info, at } => {
            assert_eq!(info.kind, 1059);
            let info = p.confirm_id(Scanner::new_at(&text, at), &mut rec, info).unwrap();
            assert_eq!(info.created_at, 1_700_000_200);
            assert!(relay_proto::event::verify_sig(Record(&rec)));
        }
        _ => panic!("expected EVENT"),
    }

    let text = r##"[ "REQ" , "sub 1", {"kinds":[1059],"limit":0} , {"#d":["vector/pinned"]} ]"##;
    match ClientMsg::parse(text, &mut p, &mut rec).unwrap() {
        ClientMsg::Req { sub_id, filters } => {
            assert_eq!(sub_id, "sub 1");
            assert_eq!(filters.len(), 2);
            assert_eq!(filters[0].limit, Some(0));
        }
        _ => panic!("expected REQ"),
    }

    let text = r#"["NEG-OPEN","n",{"kinds":[1059]},"6100000200"]"#;
    match ClientMsg::parse(text, &mut p, &mut rec).unwrap() {
        ClientMsg::NegOpen { sub_id, msg, .. } => {
            assert_eq!(sub_id, "n");
            assert_eq!(msg, vec![0x61, 0, 0, 2, 0]);
        }
        _ => panic!("expected NEG-OPEN"),
    }

    assert!(matches!(ClientMsg::parse(r#"["CLOSE","x"]"#, &mut p, &mut rec), Ok(ClientMsg::Close { sub_id: "x" })));
    for bad in [r#"["NOPE"]"#, r#"["REQ",""]"#, r#"["REQ","a\"b"]"#, r#"["CLOSE","x"] x"#, r#"{"a":1}"#] {
        assert!(ClientMsg::parse(bad, &mut p, &mut rec).is_err(), "{bad}");
    }
    let long = format!(r#"["CLOSE","{}"]"#, "x".repeat(65));
    assert!(ClientMsg::parse(&long, &mut p, &mut rec).is_err());
}
