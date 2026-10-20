//! A strict, allocation-free JSON scanner for the handful of shapes Nostr uses.
//!
//! The scanner never builds a tree. Callers walk the document and take what they
//! need; strings come back as the raw bytes between the quotes plus a flag saying
//! whether they contain escapes, so the common case (no escapes) costs one scan
//! and zero copies.
//!
//! Input is `&str`, so it is valid UTF-8 by construction; the scanner only has to
//! police JSON's own rules.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub msg: &'static str,
    pub pos: usize,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.msg, self.pos)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Nesting allowed when skipping values we do not care about.
const MAX_SKIP_DEPTH: u32 = 64;

/// A JSON string as it appeared on the wire, quotes removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawStr<'a> {
    pub bytes: &'a [u8],
    /// Contains at least one backslash escape.
    pub escaped: bool,
}

impl<'a> RawStr<'a> {
    /// The string's bytes in canonical escaped form, appended to `out`.
    #[inline]
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        if self.escaped {
            canonicalize(self.bytes, out);
        } else {
            // No escapes and JSON forbids raw control characters, so the bytes
            // are already canonical.
            out.extend_from_slice(self.bytes);
        }
    }

    /// True when the string is exactly `s` (with no escapes involved).
    #[inline]
    pub fn is(&self, s: &[u8]) -> bool {
        !self.escaped && self.bytes == s
    }
}

#[derive(Clone)]
pub struct Scanner<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Scanner<'a> {
    pub fn new(s: &'a str) -> Self {
        Scanner { b: s.as_bytes(), p: 0 }
    }

    /// A scanner resuming at byte `pos` of `s` (a position this scanner reported).
    pub fn new_at(s: &'a str, pos: usize) -> Self {
        Scanner { b: s.as_bytes(), p: pos.min(s.len()) }
    }

    #[inline]
    pub fn pos(&self) -> usize {
        self.p
    }

    #[inline]
    fn err<T>(&self, msg: &'static str) -> Result<T> {
        Err(Error { msg, pos: self.p })
    }

    #[inline]
    pub fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.p) {
            if c == b' ' || c == b'\n' || c == b'\r' || c == b'\t' {
                self.p += 1;
            } else {
                break;
            }
        }
    }

    /// Next non-whitespace byte, not consumed.
    #[inline]
    pub fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.p).copied()
    }

    #[inline]
    pub fn expect(&mut self, c: u8) -> Result<()> {
        if self.peek() == Some(c) {
            self.p += 1;
            Ok(())
        } else {
            self.err(match c {
                b'[' => "expected '['",
                b']' => "expected ']'",
                b'{' => "expected '{'",
                b'}' => "expected '}'",
                b':' => "expected ':'",
                b',' => "expected ','",
                _ => "unexpected character",
            })
        }
    }

    /// Consumes `c` if it is next. Used for optional commas and closers.
    #[inline]
    pub fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.p += 1;
            true
        } else {
            false
        }
    }

    /// After the last value: only whitespace may follow.
    pub fn end(&mut self) -> Result<()> {
        self.ws();
        if self.p == self.b.len() {
            Ok(())
        } else {
            self.err("trailing characters")
        }
    }

    pub fn string(&mut self) -> Result<RawStr<'a>> {
        if self.peek() != Some(b'"') {
            return self.err("expected string");
        }
        self.p += 1;
        let start = self.p;
        let mut escaped = false;
        loop {
            let i = find_special(self.b, self.p);
            self.p = i;
            match self.b.get(i) {
                None => return self.err("unterminated string"),
                Some(b'"') => {
                    self.p += 1;
                    return Ok(RawStr { bytes: &self.b[start..i], escaped });
                }
                Some(b'\\') => {
                    escaped = true;
                    match self.b.get(i + 1) {
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => self.p = i + 2,
                        Some(b'u') => {
                            let h = self.b.get(i + 2..i + 6);
                            if h.is_none_or(|h| !h.iter().all(u8::is_ascii_hexdigit)) {
                                return self.err("bad \\u escape");
                            }
                            self.p = i + 6;
                        }
                        _ => return self.err("bad escape"),
                    }
                }
                Some(_) => return self.err("control character in string"),
            }
        }
    }

    /// A non-negative integer in plain decimal: no sign, fraction, exponent or
    /// leading zero. The id hash commits to the decimal form, so anything else
    /// could not round-trip.
    pub fn u64(&mut self) -> Result<u64> {
        self.ws();
        let start = self.p;
        let mut v: u64 = 0;
        while let Some(&c) = self.b.get(self.p) {
            if !c.is_ascii_digit() {
                break;
            }
            v = match v.checked_mul(10).and_then(|v| v.checked_add(u64::from(c - b'0'))) {
                Some(v) => v,
                None => return self.err("number out of range"),
            };
            self.p += 1;
        }
        let len = self.p - start;
        if len == 0 {
            return self.err("expected unsigned integer");
        }
        if len > 1 && self.b[start] == b'0' {
            return self.err("leading zero");
        }
        if matches!(self.b.get(self.p), Some(b'.' | b'e' | b'E')) {
            return self.err("expected integer");
        }
        Ok(v)
    }

    /// Skips one value of any type.
    pub fn skip(&mut self) -> Result<()> {
        self.skip_depth(0)
    }

    fn skip_depth(&mut self, depth: u32) -> Result<()> {
        if depth > MAX_SKIP_DEPTH {
            return self.err("nested too deeply");
        }
        match self.peek() {
            Some(b'"') => self.string().map(|_| ()),
            Some(b'{') => {
                self.p += 1;
                if self.eat(b'}') {
                    return Ok(());
                }
                loop {
                    self.string()?;
                    self.expect(b':')?;
                    self.skip_depth(depth + 1)?;
                    if self.eat(b'}') {
                        return Ok(());
                    }
                    self.expect(b',')?;
                }
            }
            Some(b'[') => {
                self.p += 1;
                if self.eat(b']') {
                    return Ok(());
                }
                loop {
                    self.skip_depth(depth + 1)?;
                    if self.eat(b']') {
                        return Ok(());
                    }
                    self.expect(b',')?;
                }
            }
            Some(b't') => self.literal(b"true"),
            Some(b'f') => self.literal(b"false"),
            Some(b'n') => self.literal(b"null"),
            Some(b'-' | b'0'..=b'9') => self.skip_number(),
            _ => self.err("expected value"),
        }
    }

    fn literal(&mut self, lit: &[u8]) -> Result<()> {
        if self.b[self.p..].starts_with(lit) {
            self.p += lit.len();
            Ok(())
        } else {
            self.err("bad literal")
        }
    }

    fn skip_number(&mut self) -> Result<()> {
        let start = self.p;
        if self.b.get(self.p) == Some(&b'-') {
            self.p += 1;
        }
        let digits = |s: &mut Self| {
            let d = s.p;
            while s.b.get(s.p).is_some_and(u8::is_ascii_digit) {
                s.p += 1;
            }
            s.p - d
        };
        if digits(self) == 0 {
            return self.err("bad number");
        }
        if self.b.get(self.p) == Some(&b'.') {
            self.p += 1;
            if digits(self) == 0 {
                return self.err("bad number");
            }
        }
        if matches!(self.b.get(self.p), Some(b'e' | b'E')) {
            self.p += 1;
            if matches!(self.b.get(self.p), Some(b'+' | b'-')) {
                self.p += 1;
            }
            if digits(self) == 0 {
                return self.err("bad number");
            }
        }
        debug_assert!(self.p > start);
        Ok(())
    }

    /// Iterates `"key": value` pairs of an object, calling `f` with the scanner
    /// positioned at each value. `f` must consume the value.
    pub fn object<E, F>(&mut self, mut f: F) -> std::result::Result<(), E>
    where
        E: From<Error>,
        F: FnMut(&mut Self, RawStr<'a>) -> std::result::Result<(), E>,
    {
        self.expect(b'{')?;
        if self.eat(b'}') {
            return Ok(());
        }
        loop {
            let key = self.string()?;
            self.expect(b':')?;
            f(self, key)?;
            if self.eat(b'}') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    /// Iterates the elements of an array, calling `f` positioned at each one.
    pub fn array<E, F>(&mut self, mut f: F) -> std::result::Result<(), E>
    where
        E: From<Error>,
        F: FnMut(&mut Self) -> std::result::Result<(), E>,
    {
        self.expect(b'[')?;
        if self.eat(b']') {
            return Ok(());
        }
        loop {
            f(self)?;
            if self.eat(b']') {
                return Ok(());
            }
            self.expect(b',')?;
        }
    }

    /// The raw source text of the next value, without interpreting it.
    pub fn raw_value(&mut self) -> Result<&'a [u8]> {
        self.ws();
        let start = self.p;
        self.skip()?;
        Ok(&self.b[start..self.p])
    }
}

const LO: u64 = 0x0101_0101_0101_0101;
const HI: u64 = 0x8080_8080_8080_8080;

/// Index of the first `"`, `\` or control byte at or after `from`, else `b.len()`.
/// Eight bytes at a time; exact for the first match, which is all we use.
#[inline]
fn find_special(b: &[u8], from: usize) -> usize {
    let mut i = from;
    while i + 8 <= b.len() {
        let v = u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let q = v ^ (LO * b'"' as u64);
        let s = v ^ (LO * b'\\' as u64);
        let m = (q.wrapping_sub(LO) & !q) | (s.wrapping_sub(LO) & !s) | (v.wrapping_sub(LO * 0x20) & !v);
        let m = m & HI;
        if m != 0 {
            return i + (m.trailing_zeros() / 8) as usize;
        }
        i += 8;
    }
    while i < b.len() {
        let c = b[i];
        if c == b'"' || c == b'\\' || c < 0x20 {
            return i;
        }
        i += 1;
    }
    b.len()
}

#[inline]
fn hex4(b: &[u8]) -> u32 {
    let mut v = 0u32;
    for &c in &b[..4] {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        };
        v = (v << 4) | u32::from(d);
    }
    v
}

#[inline]
fn push_utf8(out: &mut Vec<u8>, cp: u32) {
    let mut buf = [0u8; 4];
    // Callers never pass a surrogate, so this is a valid scalar value.
    let c = char::from_u32(cp).expect("non-surrogate code point");
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
}

/// The escaped form of one code point that the canonical serialisation uses:
/// what JSON.stringify, serde_json and strfry's tao all emit.
#[inline]
fn push_canonical_char(out: &mut Vec<u8>, cp: u32) {
    match cp {
        0x22 => out.extend_from_slice(b"\\\""),
        0x5C => out.extend_from_slice(b"\\\\"),
        0x08 => out.extend_from_slice(b"\\b"),
        0x0C => out.extend_from_slice(b"\\f"),
        0x0A => out.extend_from_slice(b"\\n"),
        0x0D => out.extend_from_slice(b"\\r"),
        0x09 => out.extend_from_slice(b"\\t"),
        0..=0x1F => push_u_escape(out, cp),
        _ => push_utf8(out, cp),
    }
}

#[inline]
fn push_u_escape(out: &mut Vec<u8>, unit: u32) {
    const D: &[u8; 16] = b"0123456789abcdef";
    out.extend_from_slice(&[
        b'\\',
        b'u',
        D[(unit >> 12) as usize & 15],
        D[(unit >> 8) as usize & 15],
        D[(unit >> 4) as usize & 15],
        D[unit as usize & 15],
    ]);
}

/// Rewrites the escapes of a validated raw JSON string into canonical form.
///
/// Canonical = unescape everything, then escape only `"`, `\` and control
/// characters (`\b \f \n \r \t` short, the rest `\u00xx`). `\/` becomes `/`,
/// `é` becomes `é`, a surrogate pair becomes its UTF-8. A lone surrogate
/// cannot be UTF-8, so it stays a lowercase `\udxxx`, as JSON.stringify writes it.
fn canonicalize(raw: &[u8], out: &mut Vec<u8>) {
    out.reserve(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let j = match raw[i..].iter().position(|&c| c == b'\\') {
            Some(off) => i + off,
            None => {
                out.extend_from_slice(&raw[i..]);
                return;
            }
        };
        out.extend_from_slice(&raw[i..j]);
        let e = raw[j + 1];
        i = j + 2;
        match e {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'/' => out.push(b'/'),
            b'b' => out.extend_from_slice(b"\\b"),
            b'f' => out.extend_from_slice(b"\\f"),
            b'n' => out.extend_from_slice(b"\\n"),
            b'r' => out.extend_from_slice(b"\\r"),
            b't' => out.extend_from_slice(b"\\t"),
            _ => {
                // `u`: the scanner guaranteed four hex digits.
                let unit = hex4(&raw[i..]);
                i += 4;
                if (0xD800..0xDC00).contains(&unit) {
                    if raw.get(i..i + 2) == Some(b"\\u") {
                        let low = hex4(&raw[i + 2..]);
                        if (0xDC00..0xE000).contains(&low) {
                            push_utf8(out, 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00));
                            i += 6;
                            continue;
                        }
                    }
                    push_u_escape(out, unit);
                } else if (0xDC00..0xE000).contains(&unit) {
                    push_u_escape(out, unit);
                } else {
                    push_canonical_char(out, unit);
                }
            }
        }
    }
}

/// Appends the canonical JSON string escaping of arbitrary UTF-8 text (no quotes).
pub fn escape_str(s: &str, out: &mut Vec<u8>) {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let j = find_special(b, i);
        out.extend_from_slice(&b[i..j]);
        if j == b.len() {
            return;
        }
        push_canonical_char(out, u32::from(b[j]));
        i = j + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(json_str: &str) -> String {
        let mut s = Scanner::new(json_str);
        let r = s.string().unwrap();
        let mut out = Vec::new();
        r.write_canonical(&mut out);
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn canonical_matches_serde_json() {
        // serde_json writes the canonical form; whatever escaping the input used,
        // our canonical bytes must equal serde_json's re-serialisation.
        let cases = [
            r#""plain""#,
            r#""a\/b""#,
            "\"caf\\u00e9\"",
            "\"\\u00E9\\u0041\"",
            r#""tab\there\nnl\r\f\b""#,
            r#""\u0001\u001f\u007f""#,
            r#""quote \" back \\ slash""#,
            "\"\\ud83d\\ude00 emoji\"",
            "\"\\u0022\\u005c\"",
            "\"raw é and 😀\"",
        ];
        for c in cases {
            let v: String = serde_json::from_str(c).unwrap();
            let expect = serde_json::to_string(&v).unwrap();
            let expect = &expect[1..expect.len() - 1];
            assert_eq!(canon(c), expect, "case {c}");
        }
    }

    #[test]
    fn lone_surrogates_stay_escaped() {
        assert_eq!(canon(r#""\uD800x""#), r"\ud800x");
        assert_eq!(canon(r#""\udc00""#), r"\udc00");
        assert_eq!(canon(r#""\ud800A""#), r"\ud800A");
    }

    #[test]
    fn strictness() {
        assert!(Scanner::new("\"a\u{1}b\"").string().is_err());
        assert!(Scanner::new(r#""\x""#).string().is_err());
        assert!(Scanner::new(r#""\u12""#).string().is_err());
        assert!(Scanner::new(r#""abc"#).string().is_err());
        assert!(Scanner::new("012").u64().is_err());
        assert!(Scanner::new("1.0").u64().is_err());
        assert!(Scanner::new("1e3").u64().is_err());
        assert!(Scanner::new("-1").u64().is_err());
        assert!(Scanner::new("18446744073709551616").u64().is_err());
        assert_eq!(Scanner::new("18446744073709551615").u64().unwrap(), u64::MAX);
        assert_eq!(Scanner::new("0").u64().unwrap(), 0);
    }

    #[test]
    fn find_special_every_offset() {
        for len in 0..40 {
            for at in 0..len {
                for c in [b'"', b'\\', 0x01, 0x1f] {
                    let mut v = vec![b'x'; len];
                    v[at] = c;
                    assert_eq!(find_special(&v, 0), at);
                }
            }
            let v = vec![0xC3u8; len];
            assert_eq!(find_special(&v, 0), len);
        }
    }

    #[test]
    fn skip_everything() {
        let doc = r#"{"a":[1,-2.5e+3,true,false,null,{"b":"c\"d"}],"e":{}}"#;
        let mut s = Scanner::new(doc);
        s.skip().unwrap();
        s.end().unwrap();
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(Scanner::new(&deep).skip().is_err());
    }

    #[test]
    fn escape_str_canonical() {
        let mut out = Vec::new();
        escape_str("a\"b\\c\nd\u{1}é", &mut out);
        assert_eq!(out, r#"a\"b\\c\nd\u0001é"#.as_bytes());
    }
}
