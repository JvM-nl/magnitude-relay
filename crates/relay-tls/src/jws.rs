//! The JSON Web Signatures ACME wraps every request in (RFC 8555 §6.2), ES256 only.

use crate::b64url;
use crate::json::Value;
use crate::x509::EcKey;
use ring::digest::{digest, SHA256};

/// How the signer is named in the protected header.
#[derive(Debug, Clone, Copy)]
pub enum Signer<'a> {
    /// The public key itself: for `newAccount` (and revocation by certificate key).
    Jwk,
    /// The account URL the CA gave out: for everything after registration.
    Kid(&'a str),
}

/// The account key as a JWK (RFC 7517), members in the order RFC 7638 hashes them.
pub fn jwk(key: &EcKey) -> String {
    let p = key.public_point();
    format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}", b64url::encode(&p[1..33]), b64url::encode(&p[33..65]))
}

/// The JWK thumbprint (RFC 7638): base64url of the SHA-256 of the JWK's canonical
/// form, which is the form [`jwk`] already writes.
pub fn thumbprint(key: &EcKey) -> String {
    b64url::encode(digest(&SHA256, jwk(key).as_bytes()).as_ref())
}

/// The key authorization for a challenge token (RFC 8555 §8.1).
pub fn key_authorization(token: &str, key: &EcKey) -> String {
    format!("{token}.{}", thumbprint(key))
}

/// A signed request body (the flattened JSON serialization). `payload` is `None` for
/// POST-as-GET, which signs an empty payload.
pub fn sign(key: &EcKey, signer: Signer<'_>, nonce: &str, url: &str, payload: Option<&Value>) -> String {
    let mut protected = vec![("alg", Value::str("ES256")), ("nonce", Value::str(nonce)), ("url", Value::str(url))];
    match signer {
        Signer::Jwk => protected.push(("jwk", crate::json::parse(&jwk(key)).expect("our own JWK is JSON"))),
        Signer::Kid(kid) => protected.push(("kid", Value::str(kid))),
    }
    let protected = b64url::encode(Value::obj_vec(protected).to_string().as_bytes());
    let payload = payload.map_or_else(String::new, |p| b64url::encode(p.to_string().as_bytes()));
    let signature = b64url::encode(&key.sign_raw(format!("{protected}.{payload}").as_bytes()));
    Value::obj([("protected", Value::Str(protected)), ("payload", Value::Str(payload)), ("signature", Value::Str(signature))]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

    /// Verifies a body the way a CA does: signature over `protected.payload` with the
    /// key the header names. Returns the decoded protected header and payload.
    pub(crate) fn verify_body(body: &str, public_point: &[u8]) -> Result<(Value, Vec<u8>), String> {
        let v = crate::json::parse(body).map_err(|e| e.to_string())?;
        let (p, pl, s) =
            (v.str_of("protected").ok_or("protected")?, v.str_of("payload").ok_or("payload")?, v.str_of("signature").ok_or("signature")?);
        let sig = b64url::decode(s).ok_or("signature is not base64url")?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_point)
            .verify(format!("{p}.{pl}").as_bytes(), &sig)
            .map_err(|_| "bad signature")?;
        let header =
            crate::json::parse(std::str::from_utf8(&b64url::decode(p).ok_or("protected is not base64url")?).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        Ok((header, b64url::decode(pl).ok_or("payload is not base64url")?))
    }

    /// RFC 7638 §3.1's example key (an RSA key, so only the method is checked here):
    /// the thumbprint is SHA-256 of the canonical JWK, base64url, no padding.
    #[test]
    fn thumbprint_is_the_hash_of_the_canonical_jwk() {
        let k = EcKey::generate().unwrap();
        let j = jwk(&k);
        let parsed = crate::json::parse(&j).unwrap();
        assert_eq!((parsed.str_of("kty"), parsed.str_of("crv")), (Some("EC"), Some("P-256")));
        let (x, y) = (b64url::decode(parsed.str_of("x").unwrap()).unwrap(), b64url::decode(parsed.str_of("y").unwrap()).unwrap());
        assert_eq!([&[4u8][..], &x, &y].concat(), k.public_point());
        assert_eq!((x.len(), y.len()), (32, 32));
        // Required members only, in lexicographic order, no whitespace.
        assert!(j.starts_with("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\""));
        assert_eq!(b64url::decode(&thumbprint(&k)).unwrap(), digest(&SHA256, j.as_bytes()).as_ref());
        assert_eq!(thumbprint(&k).len(), 43);
    }

    #[test]
    fn key_authorization_joins_token_and_thumbprint() {
        let k = EcKey::generate().unwrap();
        assert_eq!(key_authorization("tok-en_1", &k), format!("tok-en_1.{}", thumbprint(&k)));
    }

    #[test]
    fn new_account_request_verifies_with_its_own_jwk() {
        let k = EcKey::generate().unwrap();
        let payload = Value::obj([("termsOfServiceAgreed", Value::Bool(true))]);
        let body = sign(&k, Signer::Jwk, "nonce-1", "https://ca.example/new-acct", Some(&payload));
        let (header, got) = verify_body(&body, k.public_point()).unwrap();
        assert_eq!(header.str_of("alg"), Some("ES256"));
        assert_eq!(header.str_of("nonce"), Some("nonce-1"));
        assert_eq!(header.str_of("url"), Some("https://ca.example/new-acct"));
        assert!(header.get("kid").is_none());
        assert_eq!(header.get("jwk").unwrap().to_string(), jwk(&k));
        assert_eq!(got, payload.to_string().as_bytes());
    }

    #[test]
    fn later_requests_name_the_account_by_url() {
        let k = EcKey::generate().unwrap();
        let body = sign(&k, Signer::Kid("https://ca.example/acct/7"), "n", "https://ca.example/order", Some(&Value::obj([])));
        let (header, _) = verify_body(&body, k.public_point()).unwrap();
        assert_eq!(header.str_of("kid"), Some("https://ca.example/acct/7"));
        assert!(header.get("jwk").is_none());
    }

    #[test]
    fn post_as_get_signs_an_empty_payload() {
        let k = EcKey::generate().unwrap();
        let body = sign(&k, Signer::Kid("kid"), "n", "https://ca.example/authz/1", None);
        let v = crate::json::parse(&body).unwrap();
        assert_eq!(v.str_of("payload"), Some(""));
        let (_, payload) = verify_body(&body, k.public_point()).unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn signature_covers_header_and_payload() {
        let k = EcKey::generate().unwrap();
        let other = EcKey::generate().unwrap();
        let body = sign(&k, Signer::Jwk, "n", "u", Some(&Value::obj([("a", Value::Num(1.0))])));
        assert!(verify_body(&body, other.public_point()).is_err(), "another key");
        let v = crate::json::parse(&body).unwrap();
        // Swapping in a different payload (or header) breaks the signature.
        let swapped = Value::obj([
            ("protected", Value::str(v.str_of("protected").unwrap())),
            ("payload", Value::str(b64url::encode(b"{}"))),
            ("signature", Value::str(v.str_of("signature").unwrap())),
        ]);
        assert!(verify_body(&swapped.to_string(), k.public_point()).is_err());
        let other_header = sign(&k, Signer::Jwk, "n2", "u", Some(&Value::obj([("a", Value::Num(1.0))])));
        let w = crate::json::parse(&other_header).unwrap();
        let mixed = Value::obj([
            ("protected", Value::str(w.str_of("protected").unwrap())),
            ("payload", Value::str(v.str_of("payload").unwrap())),
            ("signature", Value::str(v.str_of("signature").unwrap())),
        ]);
        assert!(verify_body(&mixed.to_string(), k.public_point()).is_err());
    }

    #[test]
    fn signatures_are_fixed_width_and_vary() {
        let k = EcKey::generate().unwrap();
        let a = sign(&k, Signer::Jwk, "n", "u", None);
        let b = sign(&k, Signer::Jwk, "n", "u", None);
        let sig = |s: &str| b64url::decode(crate::json::parse(s).unwrap().str_of("signature").unwrap()).unwrap();
        assert_eq!(sig(&a).len(), 64, "r || s, not DER");
        assert_ne!(sig(&a), sig(&b), "ECDSA signs with fresh randomness");
    }
}
