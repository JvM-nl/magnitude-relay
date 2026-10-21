//! Signing real events. The id is computed from serde_json's serialisation of
//! `[0,pubkey,created_at,kind,tags,content]`, a reference that shares no code
//! with the relay, so a relay that hashes differently fails the canary.

use secp256k1::{schnorr, Keypair};
use sha2::{Digest, Sha256};

pub struct Keys {
    pair: Keypair,
    pub pk: [u8; 32],
    pub pk_hex: String,
}

impl Keys {
    pub fn from_seed(seed: u64) -> Keys {
        let mut secret = [0u8; 32];
        let mut n = seed;
        loop {
            for (i, c) in secret.chunks_mut(8).enumerate() {
                c.copy_from_slice(&crate::rng::mix(n ^ (i as u64) << 56).to_le_bytes());
            }
            if let Ok(pair) = Keypair::from_secret_bytes(secret) {
                let pk = pair.x_only_public_key().0.to_byte_array();
                return Keys { pair, pk, pk_hex: relay_proto::hex::encode_string(&pk) };
            }
            n = n.wrapping_add(1);
        }
    }

    /// A signed event as JSON, with `tags_json` and `content_body` (the JSON
    /// string body, escapes and all) exactly as given. `None` when serde_json
    /// cannot read them (a lone surrogate, malformed tags).
    pub fn sign_json(&self, created_at: u64, kind: u64, tags_json: &str, content_body: &str) -> Option<String> {
        let tags: serde_json::Value = serde_json::from_str(tags_json).ok()?;
        let ok = tags.as_array()?.iter().all(|t| t.as_array().is_some_and(|f| f.iter().all(|x| x.is_string())));
        if !ok {
            return None;
        }
        let content: String = serde_json::from_str(&format!("\"{content_body}\"")).ok()?;
        let (id, sig) = self.sign_parts(created_at, kind, &tags, &content);
        Some(format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{}\",\"created_at\":{created_at},\"kind\":{kind},\"tags\":{tags_json},\"content\":\"{content_body}\",\"sig\":\"{}\"}}",
            relay_proto::hex::encode_string(&id),
            self.pk_hex,
            relay_proto::hex::encode_string(&sig)
        ))
    }

    /// Id and signature for already-parsed tags and content.
    pub fn sign_parts(&self, created_at: u64, kind: u64, tags: &serde_json::Value, content: &str) -> ([u8; 32], [u8; 64]) {
        let pre = serde_json::to_string(&serde_json::json!([0, self.pk_hex, created_at, kind, tags, content])).expect("serialisable");
        let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
        let sig = schnorr::sign_no_aux_rand(&id, &self.pair);
        (id, sig.to_byte_array())
    }

    /// A plain signed event from plain text (escaped by serde_json).
    pub fn event(&self, created_at: u64, kind: u64, tags: serde_json::Value, content: &str) -> (String, [u8; 32]) {
        let (id, sig) = self.sign_parts(created_at, kind, &tags, content);
        let v = serde_json::json!({
            "id": relay_proto::hex::encode_string(&id),
            "pubkey": self.pk_hex,
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": content,
            "sig": relay_proto::hex::encode_string(&sig),
        });
        (v.to_string(), id)
    }
}

/// The id serde_json's serialisation gives, for checking the relay's.
pub fn reference_id(pk_hex: &str, created_at: u64, kind: u64, tags: &serde_json::Value, content: &str) -> [u8; 32] {
    let pre = serde_json::to_string(&serde_json::json!([0, pk_hex, created_at, kind, tags, content])).expect("serialisable");
    Sha256::digest(pre.as_bytes()).into()
}
