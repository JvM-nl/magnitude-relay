//! PEM (RFC 7468): the text armour around DER that certificate and key files use.
//!
//! Reading is forgiving about what surrounds the blocks (a chain file often carries
//! comments or a trailing newline) and strict about the blocks themselves.

use relay_net::base64;

/// One `-----BEGIN label-----` block's decoded contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub label: String,
    pub der: Vec<u8>,
}

/// Encodes `der` as one block, base64 wrapped at 64 columns, ending in a newline.
pub fn encode(label: &str, der: &[u8]) -> String {
    let b64 = base64::encode_string(der);
    let mut out = String::with_capacity(b64.len() + b64.len() / 64 + 2 * label.len() + 40);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Every block in `text`, in order. Text outside blocks is ignored; a block that is
/// never closed, or whose body is not base64, is an error.
pub fn decode(text: &str) -> Result<Vec<Block>, String> {
    let mut blocks = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(label) = line.trim().strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) else { continue };
        let end = format!("-----END {label}-----");
        let mut body = String::new();
        let mut closed = false;
        for l in lines.by_ref() {
            let l = l.trim();
            if l == end {
                closed = true;
                break;
            }
            if l.starts_with("-----") {
                return Err(format!("the {label} block is cut short by another marker"));
            }
            body.push_str(l);
        }
        if !closed {
            return Err(format!("the {label} block is never closed (no \"{end}\" line)"));
        }
        let mut der = Vec::new();
        base64::decode(body.as_bytes(), &mut der).map_err(|_| format!("the {label} block is not valid base64"))?;
        blocks.push(Block { label: label.to_string(), der });
    }
    Ok(blocks)
}

/// The DER of every `CERTIFICATE` block: a certificate chain, leaf first.
pub fn certificates(text: &str) -> Result<Vec<Vec<u8>>, String> {
    let chain: Vec<Vec<u8>> = decode(text)?.into_iter().filter(|b| b.label == "CERTIFICATE").map(|b| b.der).collect();
    if chain.is_empty() {
        return Err("no certificate found (expected a \"-----BEGIN CERTIFICATE-----\" block)".to_string());
    }
    Ok(chain)
}

/// The first private key block: PKCS#8 (`PRIVATE KEY`), SEC1 (`EC PRIVATE KEY`) or
/// PKCS#1 (`RSA PRIVATE KEY`), as its label and DER.
pub fn private_key(text: &str) -> Result<Block, String> {
    let blocks = decode(text)?;
    if blocks.iter().any(|b| b.label == "ENCRYPTED PRIVATE KEY") {
        return Err("the private key is encrypted; the relay needs it unencrypted (for example `openssl pkcs8 -nocrypt`)".to_string());
    }
    blocks
        .into_iter()
        .find(|b| matches!(b.label.as_str(), "PRIVATE KEY" | "EC PRIVATE KEY" | "RSA PRIVATE KEY"))
        .ok_or_else(|| "no private key found (expected a \"-----BEGIN PRIVATE KEY-----\" block)".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_in_64_column_lines() {
        let der: Vec<u8> = (0..100).collect();
        let pem = encode("CERTIFICATE", &der);
        let lines: Vec<&str> = pem.lines().collect();
        assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(lines.last().unwrap(), &"-----END CERTIFICATE-----");
        assert!(lines[1..lines.len() - 1].iter().all(|l| l.len() <= 64));
        assert_eq!(lines[1].len(), 64);
        assert!(pem.ends_with('\n'));
    }

    #[test]
    fn round_trips_every_length() {
        for n in 0..200 {
            let der: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let blocks = decode(&encode("THING", &der)).unwrap();
            assert_eq!(blocks, [Block { label: "THING".into(), der }], "length {n}");
        }
    }

    #[test]
    fn reads_chains_with_noise_and_crlf() {
        let a = encode("CERTIFICATE", b"first");
        let b = encode("CERTIFICATE", b"second");
        let text = format!("# issued by someone\n{a}\nsome words between\n{b}trailing words").replace('\n', "\r\n");
        assert_eq!(certificates(&text).unwrap(), [b"first".to_vec(), b"second".to_vec()]);
        // Leading and trailing blanks on marker lines are tolerated.
        let padded = format!("  {}  \n", a.lines().next().unwrap());
        assert!(decode(&format!("{padded}{}\n{}\n", a.lines().nth(1).unwrap(), a.lines().last().unwrap())).is_ok());
    }

    #[test]
    fn rejects_broken_blocks() {
        assert!(decode("-----BEGIN CERTIFICATE-----\nQUJD\n").unwrap_err().contains("never closed"));
        assert!(decode("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n").unwrap_err().contains("not valid base64"));
        assert!(decode("-----BEGIN A-----\nQUJD\n-----BEGIN B-----\n-----END B-----\n").unwrap_err().contains("cut short"));
        // A mismatched END is not a close.
        assert!(decode("-----BEGIN A-----\nQUJD\n-----END B-----\n").is_err());
        assert!(certificates("").unwrap_err().contains("no certificate"));
        assert!(certificates(&encode("PRIVATE KEY", b"k")).is_err());
    }

    #[test]
    fn finds_the_private_key_in_any_form() {
        for label in ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"] {
            let text = format!("{}{}", encode("CERTIFICATE", b"c"), encode(label, b"k"));
            let b = private_key(&text).unwrap();
            assert_eq!((b.label.as_str(), b.der.as_slice()), (label, &b"k"[..]));
        }
        assert!(private_key(&encode("CERTIFICATE", b"c")).unwrap_err().contains("no private key"));
        assert!(private_key(&encode("ENCRYPTED PRIVATE KEY", b"k")).unwrap_err().contains("encrypted"));
    }
}
