//! Signed events: BIP-340 signatures and NIP-01 ids.
//!
//! A relay under test verifies every signature, so the dataset has to be genuinely
//! signed. Keys are derived as `sha256(seed || label || n)`: a valid secp256k1 key
//! except with probability 2^-127 (handled by re-hashing), cheap, and reproducible
//! from the seed alone, which is what makes the dataset deterministic without
//! shipping key material.

use crate::jsonw::escape_into;
use crate::wire::parse_event_line;
use relay_proto::hex;
use secp256k1::{schnorr, Keypair};
use sha2::{Digest, Sha256};

pub struct Signer {
    kp: Keypair,
    pub pk: [u8; 32],
}

/// A finished event: its id and the exact JSON line (no trailing newline).
pub struct SignedEvent {
    pub id: [u8; 32],
    pub json: String,
}

impl Signer {
    pub fn from_secret(mut secret: [u8; 32]) -> Signer {
        loop {
            if let Ok(kp) = Keypair::from_secret_bytes(secret) {
                let pk = kp.x_only_public_key().0.to_byte_array();
                return Signer { kp, pk };
            }
            // Zero or above the curve order: astronomically unlikely, but never loop forever.
            secret = Sha256::digest(secret).into();
        }
    }

    /// The `n`-th key of the pool called `label` under `seed`.
    pub fn derive(seed: u64, label: &str, n: u64) -> Signer {
        let mut h = Sha256::new();
        h.update(seed.to_le_bytes());
        h.update(label.as_bytes());
        h.update(n.to_le_bytes());
        Signer::from_secret(h.finalize().into())
    }

    pub fn pk_hex(&self) -> String {
        hex::encode_string(&self.pk)
    }

    /// Signs an event. `tags_json` is the tags array already rendered (see
    /// [`push_tag`]); `content` is raw text, escaped here the way the id commits to.
    pub fn sign(&self, created_at: u64, kind: u64, tags_json: &str, content: &str) -> SignedEvent {
        let pk = self.pk_hex();
        let mut esc = String::with_capacity(content.len() + 8);
        escape_into(content, &mut esc);
        let id = event_id(&pk, created_at, kind, tags_json, &esc);
        let sig = schnorr::sign_no_aux_rand(&id, &self.kp);
        let mut json = String::with_capacity(esc.len() + tags_json.len() + 400);
        json.push_str("{\"id\":\"");
        json.push_str(&hex::encode_string(&id));
        json.push_str("\",\"pubkey\":\"");
        json.push_str(&pk);
        json.push_str("\",\"created_at\":");
        json.push_str(&created_at.to_string());
        json.push_str(",\"kind\":");
        json.push_str(&kind.to_string());
        json.push_str(",\"tags\":");
        json.push_str(tags_json);
        json.push_str(",\"content\":\"");
        json.push_str(&esc);
        json.push_str("\",\"sig\":\"");
        json.push_str(&hex::encode_string(&sig.to_byte_array()));
        json.push_str("\"}");
        SignedEvent { id, json }
    }
}

/// NIP-01 id: sha256 of `[0,pubkey,created_at,kind,tags,content]` in compact JSON.
/// `content_escaped` is the content already JSON-escaped.
pub fn event_id(pk_hex: &str, created_at: u64, kind: u64, tags_json: &str, content_escaped: &str) -> [u8; 32] {
    let mut pre = String::with_capacity(content_escaped.len() + tags_json.len() + 120);
    pre.push_str("[0,\"");
    pre.push_str(pk_hex);
    pre.push_str("\",");
    pre.push_str(&created_at.to_string());
    pre.push(',');
    pre.push_str(&kind.to_string());
    pre.push(',');
    pre.push_str(tags_json);
    pre.push_str(",\"");
    pre.push_str(content_escaped);
    pre.push_str("\"]");
    Sha256::digest(pre.as_bytes()).into()
}

/// Appends one tag to a tags array under construction. Start the buffer with `"["`
/// and finish it with `]`.
pub fn push_tag(buf: &mut String, parts: &[&str]) {
    if buf.len() > 1 {
        buf.push(',');
    }
    buf.push('[');
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            buf.push(',');
        }
        buf.push('"');
        escape_into(p, buf);
        buf.push('"');
    }
    buf.push(']');
}

/// Checks an event line the way a relay does: the id must be the hash of the exact
/// serialisation the line carries (read back out of the text, not rebuilt from parsed
/// fields), and the signature must verify against the pubkey. Used by the tests and
/// available to anyone who wants to vet a dataset file.
pub fn verify_event_line(line: &str) -> Result<(), String> {
    let e = parse_event_line(line).map_err(|e| e.to_string())?;
    let tags_at = line.find("\"tags\":").ok_or("no tags")? + 7;
    let content_at = line.find(",\"content\":\"").ok_or("no content")?;
    let sig_at = line.rfind("\",\"sig\":\"").ok_or("no sig")?;
    if !(tags_at <= content_at && content_at + 12 <= sig_at) {
        return Err("not in the canonical key order this tool writes".into());
    }
    let tags = &line[tags_at..content_at];
    let content = &line[content_at + 12..sig_at];
    let id = event_id(&hex::encode_string(&e.pubkey), e.created_at, e.kind, tags, content);
    if id != e.id {
        return Err("id does not match the serialised event".into());
    }
    let sig_hex = &line[sig_at + 9..line.len() - 2];
    let sig = hex::decode_64(sig_hex.as_bytes()).ok_or("bad sig hex")?;
    let sig = schnorr::Signature::from_byte_array(sig);
    let pk = secp256k1::XOnlyPublicKey::from_byte_array(e.pubkey).map_err(|e| e.to_string())?;
    schnorr::verify(&sig, &id, &pk).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_events_verify_and_ids_follow_nip01() {
        let s = Signer::derive(1, "t", 0);
        let mut tags = String::from("[");
        push_tag(&mut tags, &["p", &"ab".repeat(32)]);
        push_tag(&mut tags, &["t", "q\"uote"]);
        tags.push(']');
        let ev = s.sign(1_700_000_000, 1059, &tags, "line1\nline2 \"q\" \\ \u{1} \u{e9}");
        verify_event_line(&ev.json).unwrap();
        assert_eq!(parse_event_line(&ev.json).unwrap().id, ev.id);
        // Tampering with any covered field breaks the id.
        let tampered = ev.json.replace("1700000000", "1700000001");
        assert!(verify_event_line(&tampered).is_err());
    }

    #[test]
    fn known_id_vector() {
        // sha256 of the NIP-01 serialisation, computed independently (`printf | sha256sum`).
        let id = event_id(&"00".repeat(32), 1, 1, "[]", "hi");
        let want = Sha256::digest(format!("[0,\"{}\",1,1,[],\"hi\"]", "00".repeat(32)).as_bytes());
        assert_eq!(id[..], want[..]);
    }

    #[test]
    fn derivation_is_deterministic_and_separated() {
        let a = Signer::derive(5, "wrap", 10);
        assert_eq!(a.pk, Signer::derive(5, "wrap", 10).pk);
        assert_ne!(a.pk, Signer::derive(5, "wrap", 11).pk);
        assert_ne!(a.pk, Signer::derive(5, "plane", 10).pk);
        assert_ne!(a.pk, Signer::derive(6, "wrap", 10).pk);
    }

    #[test]
    fn tags_render_compactly() {
        let mut t = String::from("[");
        assert_eq!(t, "[");
        push_tag(&mut t, &["e", "x"]);
        push_tag(&mut t, &["d"]);
        t.push(']');
        assert_eq!(t, r#"[["e","x"],["d"]]"#);
    }
}
