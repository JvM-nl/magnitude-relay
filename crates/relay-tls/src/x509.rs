//! The X.509 the ACME flow needs, built and read by hand: the certificate request
//! (PKCS#10) sent to finalize an order, the self-signed certificate that answers a
//! TLS-ALPN-01 challenge, and a reader that gets the names and validity out of an
//! issued certificate. Signatures and keys are ring's.

use crate::der::{
    self, bit_string, boolean, context, context_primitive, explicit, integer, integer_u64, octet_string, oid, sequence, set, tlv,
    utf8_string, Reader,
};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING};

const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_PRIME256V1: &str = "1.2.840.10045.3.1.7";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_COMMON_NAME: &str = "2.5.4.3";
const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";
const OID_KEY_USAGE: &str = "2.5.29.15";
const OID_EXT_KEY_USAGE: &str = "2.5.29.37";
const OID_SUBJECT_ALT_NAME: &str = "2.5.29.17";
const OID_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
const OID_EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
/// id-pe-acmeIdentifier (RFC 8737 §6.1).
pub const OID_ACME_IDENTIFIER: &str = "1.3.6.1.5.5.7.1.31";

/// An ECDSA P-256 key pair: the only key type this crate generates. One PKCS#8
/// document, loaded for both signature encodings (X.509 wants DER, JWS wants r || s).
pub struct EcKey {
    pkcs8: Vec<u8>,
    der_signer: EcdsaKeyPair,
    raw_signer: EcdsaKeyPair,
    public: [u8; 65],
}

impl EcKey {
    pub fn generate() -> Result<EcKey, String> {
        let rng = SystemRandom::new();
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).map_err(|_| "the system random number generator failed")?;
        EcKey::from_pkcs8(doc.as_ref())
    }

    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<EcKey, String> {
        let rng = SystemRandom::new();
        let der_signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng).map_err(|e| format!("not a P-256 private key: {e}"))?;
        let raw_signer =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8, &rng).map_err(|e| format!("not a P-256 private key: {e}"))?;
        let public: [u8; 65] = der_signer.public_key().as_ref().try_into().map_err(|_| "unexpected public key length")?;
        Ok(EcKey { pkcs8: pkcs8.to_vec(), der_signer, raw_signer, public })
    }

    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The uncompressed point: `04 || X || Y`.
    pub fn public_point(&self) -> &[u8; 65] {
        &self.public
    }

    /// A DER `ECDSA-Sig-Value`, the encoding X.509 signatures use.
    pub fn sign_der(&self, msg: &[u8]) -> Vec<u8> {
        self.der_signer.sign(&SystemRandom::new(), msg).expect("signing with a loaded key").as_ref().to_vec()
    }

    /// `r || s`, 64 bytes, the encoding JWS ES256 uses.
    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        self.raw_signer
            .sign(&SystemRandom::new(), msg)
            .expect("signing with a loaded key")
            .as_ref()
            .try_into()
            .expect("P-256 signatures are 64 bytes")
    }

    /// The DER `SubjectPublicKeyInfo`.
    pub fn spki(&self) -> Vec<u8> {
        sequence(&[&sequence(&[&oid(OID_EC_PUBLIC_KEY), &oid(OID_PRIME256V1)]), &bit_string(&self.public)])
    }
}

impl std::fmt::Debug for EcKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcKey(P-256)")
    }
}

fn sig_alg() -> Vec<u8> {
    sequence(&[&oid(OID_ECDSA_SHA256)])
}

/// `Name` holding one common name, or no attributes at all when `cn` is empty.
fn name(cn: &str) -> Vec<u8> {
    if cn.is_empty() {
        return sequence(&[]);
    }
    sequence(&[&set(&[&sequence(&[&oid(OID_COMMON_NAME), &utf8_string(cn)])])])
}

/// A common name for a hostname: it must stay within 64 characters (RFC 5280), so
/// a longer name is left to the SAN alone.
fn cn_for(host: &str) -> &str {
    if host.len() <= 64 {
        host
    } else {
        ""
    }
}

fn extension(oid_dotted: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        sequence(&[&oid(oid_dotted), &boolean(true), &octet_string(value)])
    } else {
        sequence(&[&oid(oid_dotted), &octet_string(value)])
    }
}

/// `subjectAltName` listing DNS names (`dNSName` is `[2]` IA5String).
fn san_extension(names: &[String]) -> Vec<u8> {
    let general: Vec<Vec<u8>> = names.iter().map(|n| tlv(context_primitive(2), n.as_bytes())).collect();
    let refs: Vec<&[u8]> = general.iter().map(Vec::as_slice).collect();
    extension(OID_SUBJECT_ALT_NAME, false, &sequence(&refs))
}

/// A PKCS#10 certification request (RFC 2986) for `names`, signed by `key`: the
/// names go in the requested subjectAltName, which is what a CA issues from.
pub fn csr(key: &EcKey, names: &[String]) -> Vec<u8> {
    let exts = sequence(&[&san_extension(names)]);
    let attribute = sequence(&[&oid(OID_EXTENSION_REQUEST), &set(&[&exts])]);
    let info =
        sequence(&[&integer_u64(0), &name(cn_for(names.first().map_or("", String::as_str))), &key.spki(), &tlv(context(0), &attribute)]);
    sequence(&[&info, &sig_alg(), &bit_string(&key.sign_der(&info))])
}

/// What goes into a certificate.
pub struct CertSpec<'a> {
    pub serial: &'a [u8],
    pub issuer_cn: &'a str,
    pub subject_cn: &'a str,
    pub not_before: i64,
    pub not_after: i64,
    /// The subject's `SubjectPublicKeyInfo`, DER.
    pub spki: &'a [u8],
    pub dns_names: &'a [String],
    /// A CA certificate: basicConstraints cA and keyCertSign, no server-auth usage.
    pub ca: bool,
    /// The critical id-pe-acmeIdentifier extension carrying this digest (RFC 8737).
    pub acme_identifier: Option<[u8; 32]>,
}

/// An X.509 v3 certificate signed by `issuer_key` (ecdsa-with-SHA256).
pub fn build_certificate(spec: &CertSpec<'_>, issuer_key: &EcKey) -> Vec<u8> {
    let mut exts: Vec<Vec<u8>> = Vec::new();
    if spec.ca {
        exts.push(extension(OID_BASIC_CONSTRAINTS, true, &sequence(&[&boolean(true)])));
        // keyCertSign is bit 5: 0b0000_0100 with two unused bits.
        exts.push(extension(OID_KEY_USAGE, true, &tlv(der::BIT_STRING, &[2, 0x04])));
    } else {
        // digitalSignature is bit 0.
        exts.push(extension(OID_KEY_USAGE, true, &tlv(der::BIT_STRING, &[7, 0x80])));
        exts.push(extension(OID_EXT_KEY_USAGE, false, &sequence(&[&oid(OID_SERVER_AUTH)])));
    }
    if !spec.dns_names.is_empty() {
        exts.push(san_extension(spec.dns_names));
    }
    if let Some(digest) = &spec.acme_identifier {
        // The extension value is the DER of `Authorization ::= OCTET STRING (SIZE (32))`.
        exts.push(extension(OID_ACME_IDENTIFIER, true, &octet_string(digest)));
    }
    let ext_refs: Vec<&[u8]> = exts.iter().map(Vec::as_slice).collect();
    let tbs = sequence(&[
        &explicit(0, &integer_u64(2)),
        &integer(spec.serial),
        &sig_alg(),
        &name(spec.issuer_cn),
        &sequence(&[&der::time(spec.not_before), &der::time(spec.not_after)]),
        &name(spec.subject_cn),
        spec.spki,
        &explicit(3, &sequence(&ext_refs)),
    ]);
    sequence(&[&tbs, &sig_alg(), &bit_string(&issuer_key.sign_der(&tbs))])
}

/// A positive serial number from 16 random bytes.
pub fn random_serial() -> [u8; 16] {
    let mut s = [0u8; 16];
    SystemRandom::new().fill(&mut s).expect("the system random number generator");
    // Never negative, never zero.
    s[0] = (s[0] & 0x7F) | 0x01;
    s
}

/// The certificate that answers a TLS-ALPN-01 challenge for `domain` (RFC 8737 §3):
/// self-signed with `key`, naming `domain`, carrying the SHA-256 of the key
/// authorization in the critical acmeIdentifier extension. Valid for a day around `now`.
pub fn acme_challenge_certificate(key: &EcKey, domain: &str, digest: [u8; 32], now: i64) -> Vec<u8> {
    let cn = cn_for(domain);
    build_certificate(
        &CertSpec {
            serial: &random_serial(),
            issuer_cn: cn,
            subject_cn: cn,
            not_before: now - 3600,
            not_after: now + 86_400,
            spki: &key.spki(),
            dns_names: &[domain.to_string()],
            ca: false,
            acme_identifier: Some(digest),
        },
        key,
    )
}

/// What a certificate says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    pub serial: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    /// The subjectAltName DNS names, lowercased.
    pub names: Vec<String>,
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    /// The `SubjectPublicKeyInfo`, DER.
    pub spki: Vec<u8>,
    /// The id-pe-acmeIdentifier extension, if present: whether it is critical, and
    /// its contents (the DER of an OCTET STRING).
    pub acme_identifier: Option<(bool, Vec<u8>)>,
}

impl CertInfo {
    /// Whether the certificate is valid for every one of `names` (exact names; a
    /// wildcard in the certificate covers one label, as in RFC 6125).
    pub fn covers(&self, names: &[String]) -> bool {
        names.iter().all(|want| {
            let want = want.to_ascii_lowercase();
            self.names.iter().any(|have| {
                have == &want || have.strip_prefix("*.").is_some_and(|rest| want.split_once('.').is_some_and(|(_, tail)| tail == rest))
            })
        })
    }
}

fn common_name(name: &der::Tlv<'_>) -> Result<Option<String>, der::DerError> {
    let mut rdns = name.children();
    while !rdns.is_empty() {
        let mut atvs = rdns.expect(der::SET)?.children();
        while !atvs.is_empty() {
            let mut atv = atvs.expect(der::SEQUENCE)?.children();
            let id = atv.expect(der::OID)?;
            let value = atv.next()?;
            if der::oid_to_string(id.content)? == OID_COMMON_NAME {
                return Ok(Some(String::from_utf8_lossy(value.content).into_owned()));
            }
        }
    }
    Ok(None)
}

/// Reads the fields of a DER certificate that this crate uses.
pub fn parse_certificate(cert: &[u8]) -> Result<CertInfo, der::DerError> {
    let mut top = Reader::new(cert);
    let certificate = top.expect(der::SEQUENCE)?;
    if !top.is_empty() {
        return Err(der::DerError("data after the certificate"));
    }
    let mut parts = certificate.children();
    let mut tbs = parts.expect(der::SEQUENCE)?.children();
    tbs.take_if(context(0))?;
    let serial = der::integer_magnitude(&tbs.expect(der::INTEGER)?);
    tbs.expect(der::SEQUENCE)?;
    let issuer = tbs.expect(der::SEQUENCE)?;
    let mut validity = tbs.expect(der::SEQUENCE)?.children();
    let not_before = der::parse_time(&validity.next()?)?;
    let not_after = der::parse_time(&validity.next()?)?;
    let subject = tbs.expect(der::SEQUENCE)?;
    let spki = tbs.expect(der::SEQUENCE)?.raw.to_vec();
    // Optional unique IDs, then the extensions.
    tbs.take_if(context_primitive(1))?;
    tbs.take_if(context_primitive(2))?;
    let mut names = Vec::new();
    let mut acme_identifier = None;
    if let Some(exts) = tbs.take_if(context(3))? {
        let mut list = exts.children().expect(der::SEQUENCE)?.children();
        while !list.is_empty() {
            let mut ext = list.expect(der::SEQUENCE)?.children();
            let id = der::oid_to_string(ext.expect(der::OID)?.content)?;
            let critical = ext.take_if(der::BOOLEAN)?.is_some_and(|b| b.content.first().is_some_and(|&v| v != 0));
            let value = ext.expect(der::OCTET_STRING)?.content;
            match id.as_str() {
                OID_SUBJECT_ALT_NAME => {
                    let mut general = Reader::new(value).expect(der::SEQUENCE)?.children();
                    while !general.is_empty() {
                        let g = general.next()?;
                        if g.tag == context_primitive(2) {
                            names.push(String::from_utf8_lossy(g.content).to_ascii_lowercase());
                        }
                    }
                }
                OID_ACME_IDENTIFIER => acme_identifier = Some((critical, value.to_vec())),
                _ => {}
            }
        }
    }
    Ok(CertInfo {
        serial,
        not_before,
        not_after,
        names,
        subject_cn: common_name(&subject)?,
        issuer_cn: common_name(&issuer)?,
        spki,
        acme_identifier,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{pem, time};
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    /// Splits a certificate into the signed part and the signature, as a verifier would.
    fn signed_parts(cert: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut parts = Reader::new(cert).expect(der::SEQUENCE).unwrap().children();
        let tbs = parts.expect(der::SEQUENCE).unwrap().raw.to_vec();
        parts.expect(der::SEQUENCE).unwrap();
        let sig = parts.expect(der::BIT_STRING).unwrap();
        assert_eq!(sig.content[0], 0, "no unused bits");
        (tbs, sig.content[1..].to_vec())
    }

    fn verify(spki_point: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, spki_point).verify(msg, sig).is_ok()
    }

    #[test]
    fn keys_round_trip_through_pkcs8() {
        let k = EcKey::generate().unwrap();
        let again = EcKey::from_pkcs8(k.pkcs8()).unwrap();
        assert_eq!(k.public_point(), again.public_point());
        assert_eq!(k.public_point()[0], 4, "uncompressed point");
        assert!(EcKey::from_pkcs8(b"not a key").is_err());
        assert!(EcKey::from_pkcs8(&[]).is_err());
        assert_ne!(EcKey::generate().unwrap().public_point(), k.public_point());
    }

    #[test]
    fn both_signature_forms_verify() {
        let k = EcKey::generate().unwrap();
        let msg = b"the message";
        assert!(verify(k.public_point(), msg, &k.sign_der(msg)));
        assert!(!verify(k.public_point(), b"another", &k.sign_der(msg)));
        let raw = k.sign_raw(msg);
        let fixed = UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, k.public_point());
        assert!(fixed.verify(msg, &raw).is_ok());
    }

    #[test]
    fn spki_has_the_documented_shape() {
        let k = EcKey::generate().unwrap();
        let spki = k.spki();
        let mut r = Reader::new(&spki).expect(der::SEQUENCE).unwrap().children();
        let mut alg = r.expect(der::SEQUENCE).unwrap().children();
        assert_eq!(der::oid_to_string(alg.expect(der::OID).unwrap().content).unwrap(), OID_EC_PUBLIC_KEY);
        assert_eq!(der::oid_to_string(alg.expect(der::OID).unwrap().content).unwrap(), OID_PRIME256V1);
        let bits = r.expect(der::BIT_STRING).unwrap();
        assert_eq!(&bits.content[1..], k.public_point());
        assert_eq!(spki.len(), 91, "the well-known size of a P-256 SubjectPublicKeyInfo");
    }

    #[test]
    fn csr_is_a_valid_request_for_the_names() {
        let k = EcKey::generate().unwrap();
        let want = names(&["relay.example.com", "www.example.com"]);
        let csr = csr(&k, &want);
        let mut top = Reader::new(&csr).expect(der::SEQUENCE).unwrap().children();
        let info = top.expect(der::SEQUENCE).unwrap();
        assert_eq!(
            der::oid_to_string(top.expect(der::SEQUENCE).unwrap().children().expect(der::OID).unwrap().content).unwrap(),
            OID_ECDSA_SHA256
        );
        let sig = top.expect(der::BIT_STRING).unwrap();
        assert!(verify(k.public_point(), info.raw, &sig.content[1..]), "signed by the key it names");

        let mut f = info.children();
        assert_eq!(f.expect(der::INTEGER).unwrap().content, [0], "version 1 is encoded as 0");
        assert_eq!(common_name(&f.expect(der::SEQUENCE).unwrap()).unwrap().as_deref(), Some("relay.example.com"));
        assert_eq!(f.expect(der::SEQUENCE).unwrap().raw, k.spki());
        let attrs = f.expect(context(0)).unwrap();
        let mut attr = attrs.children().expect(der::SEQUENCE).unwrap().children();
        assert_eq!(der::oid_to_string(attr.expect(der::OID).unwrap().content).unwrap(), OID_EXTENSION_REQUEST);
        let exts = attr.expect(der::SET).unwrap().children().expect(der::SEQUENCE).unwrap();
        let mut ext = exts.children().expect(der::SEQUENCE).unwrap().children();
        assert_eq!(der::oid_to_string(ext.expect(der::OID).unwrap().content).unwrap(), OID_SUBJECT_ALT_NAME);
        let mut general = Reader::new(ext.expect(der::OCTET_STRING).unwrap().content).expect(der::SEQUENCE).unwrap().children();
        let mut got = Vec::new();
        while !general.is_empty() {
            let g = general.next().unwrap();
            assert_eq!(g.tag, 0x82, "dNSName");
            got.push(String::from_utf8(g.content.to_vec()).unwrap());
        }
        assert_eq!(got, want);
    }

    #[test]
    fn csr_with_a_very_long_name_leaves_the_subject_empty() {
        let k = EcKey::generate().unwrap();
        let long = format!("{}.example.com", "a".repeat(60));
        assert!(long.len() > 64);
        let csr = csr(&k, std::slice::from_ref(&long));
        let info = Reader::new(&csr).expect(der::SEQUENCE).unwrap().children().expect(der::SEQUENCE).unwrap();
        let mut f = info.children();
        f.expect(der::INTEGER).unwrap();
        assert_eq!(f.expect(der::SEQUENCE).unwrap().raw, [0x30, 0x00]);
    }

    #[test]
    fn challenge_certificate_carries_the_critical_identifier() {
        let k = EcKey::generate().unwrap();
        let digest = [0xAB; 32];
        let now = 1_792_586_096;
        let der = acme_challenge_certificate(&k, "relay.example.com", digest, now);
        let info = parse_certificate(&der).unwrap();
        assert_eq!(info.names, ["relay.example.com"]);
        assert_eq!((info.not_before, info.not_after), (now - 3600, now + 86_400));
        assert_eq!(info.spki, k.spki());
        let (critical, value) = info.acme_identifier.unwrap();
        assert!(critical, "RFC 8737 requires the extension to be critical");
        assert_eq!(value, [&[0x04, 0x20][..], &digest[..]].concat(), "DER OCTET STRING of 32 bytes");
        let (tbs, sig) = signed_parts(&der);
        assert!(verify(k.public_point(), &tbs, &sig), "self-signed");
    }

    #[test]
    fn certificate_round_trips_through_the_parser() {
        let ca = EcKey::generate().unwrap();
        let leaf = EcKey::generate().unwrap();
        let der = build_certificate(
            &CertSpec {
                serial: &[0x00, 0x80, 0x01],
                issuer_cn: "Test CA",
                subject_cn: "a.example.com",
                not_before: 1_700_000_000,
                not_after: 1_800_000_000,
                spki: &leaf.spki(),
                dns_names: &names(&["a.example.com", "B.Example.com"]),
                ca: false,
                acme_identifier: None,
            },
            &ca,
        );
        let info = parse_certificate(&der).unwrap();
        assert_eq!(info.serial, [0x80, 0x01]);
        assert_eq!((info.not_before, info.not_after), (1_700_000_000, 1_800_000_000));
        assert_eq!(info.names, ["a.example.com", "b.example.com"]);
        assert_eq!((info.subject_cn.as_deref(), info.issuer_cn.as_deref()), (Some("a.example.com"), Some("Test CA")));
        assert!(info.acme_identifier.is_none());
        let (tbs, sig) = signed_parts(&der);
        assert!(verify(ca.public_point(), &tbs, &sig) && !verify(leaf.public_point(), &tbs, &sig));
    }

    #[test]
    fn coverage_rules() {
        let info = CertInfo {
            serial: vec![1],
            not_before: 0,
            not_after: 1,
            names: names(&["example.com", "*.wild.example.com"]),
            subject_cn: None,
            issuer_cn: None,
            spki: vec![],
            acme_identifier: None,
        };
        assert!(info.covers(&names(&["example.com", "EXAMPLE.com"])));
        assert!(info.covers(&names(&["a.wild.example.com"])));
        assert!(!info.covers(&names(&["a.b.wild.example.com"])), "a wildcard is one label");
        assert!(!info.covers(&names(&["wild.example.com"])));
        assert!(!info.covers(&names(&["example.com", "other.com"])));
        assert!(info.covers(&[]));
    }

    #[test]
    fn parser_rejects_garbage() {
        assert!(parse_certificate(b"").is_err());
        assert!(parse_certificate(b"not DER at all").is_err());
        let k = EcKey::generate().unwrap();
        let der = acme_challenge_certificate(&k, "x.example.com", [0; 32], 1_700_000_000);
        assert!(parse_certificate(&der[..der.len() - 1]).is_err(), "truncated");
        let mut extra = der.clone();
        extra.push(0);
        assert!(parse_certificate(&extra).is_err(), "trailing data");
        for cut in (1..der.len()).step_by(7) {
            let _ = parse_certificate(&der[..cut]);
        }
    }

    #[test]
    fn serials_are_positive_and_vary() {
        let a = random_serial();
        let b = random_serial();
        assert_ne!(a, b);
        assert!(a[0] & 0x80 == 0 && a[0] != 0);
    }

    /// Cross-checks against the system `openssl` when there is one: it parses what
    /// we build and verifies the CSR's signature, the check the brief asks for.
    #[test]
    fn openssl_accepts_what_we_build() {
        let Ok(v) = std::process::Command::new("openssl").arg("version").output() else {
            eprintln!("openssl not installed: skipping");
            return;
        };
        assert!(v.status.success());
        let dir = std::env::temp_dir().join(format!("relay-tls-openssl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let k = EcKey::generate().unwrap();
        let csr_pem = dir.join("req.pem");
        std::fs::write(&csr_pem, pem::encode("CERTIFICATE REQUEST", &csr(&k, &names(&["relay.example.com", "www.example.com"])))).unwrap();
        let out = std::process::Command::new("openssl").args(["req", "-verify", "-noout", "-in"]).arg(&csr_pem).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success() && text.contains("verify OK"), "{text}");

        let cert_pem = dir.join("cert.pem");
        let digest = [0x5A; 32];
        std::fs::write(&cert_pem, pem::encode("CERTIFICATE", &acme_challenge_certificate(&k, "relay.example.com", digest, time::now())))
            .unwrap();
        let out = std::process::Command::new("openssl").args(["x509", "-text", "-noout", "-in"]).arg(&cert_pem).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert!(text.contains("DNS:relay.example.com"), "{text}");
        assert!(text.contains("ecdsa-with-SHA256"), "{text}");
        assert!(text.contains("prime256v1") || text.contains("P-256"), "{text}");
        // Whether it names the extension or shows it as an unknown OID, the critical
        // acmeIdentifier extension is there with our digest.
        assert!(text.contains("1.3.6.1.5.5.7.1.31") || text.contains("acmeIdentifier"), "{text}");
        assert!(text.contains("critical"), "{text}");
        // 0x5A is "Z": openssl prints an unknown extension's bytes as text.
        assert!(text.contains(&"Z".repeat(32)), "{text}");

        // A certificate we sign for a leaf chains to our CA certificate, as openssl sees it.
        let (ca, leaf) = (EcKey::generate().unwrap(), EcKey::generate().unwrap());
        let now = time::now();
        let spec = |cn: &str, spki: &[u8], is_ca: bool, names: &[String]| {
            build_certificate(
                &CertSpec {
                    serial: &random_serial(),
                    issuer_cn: "Test Root",
                    subject_cn: cn,
                    not_before: now - 60,
                    not_after: now + 86_400,
                    spki,
                    dns_names: names,
                    ca: is_ca,
                    acme_identifier: None,
                },
                &ca,
            )
        };
        std::fs::write(dir.join("ca.pem"), pem::encode("CERTIFICATE", &spec("Test Root", &ca.spki(), true, &[]))).unwrap();
        std::fs::write(
            dir.join("leaf.pem"),
            pem::encode("CERTIFICATE", &spec("relay.example.com", &leaf.spki(), false, &names(&["relay.example.com"]))),
        )
        .unwrap();
        let out = std::process::Command::new("openssl")
            .args(["verify", "-CAfile"])
            .arg(dir.join("ca.pem"))
            .arg(dir.join("leaf.pem"))
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success() && text.contains(": OK"), "{text}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
