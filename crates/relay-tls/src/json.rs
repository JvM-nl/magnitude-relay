//! JSON for ACME's few small objects: a reader into a tree and a writer.
//!
//! The relay's own JSON code (relay-proto) scans Nostr events without building
//! anything; a CA's directory, order and problem documents are tiny and read
//! once, so a plain tree is the right shape here. Input is bounded by the HTTP
//! client's body cap, and nesting by [`MAX_DEPTH`].

use std::fmt;

/// Deepest nesting accepted: ACME documents are three or four levels.
pub const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    /// Members in document order; a repeated key is kept (the first one wins on lookup).
    Obj(Vec<(String, Value)>),
}

impl Value {
    pub fn obj<const N: usize>(members: [(&str, Value); N]) -> Value {
        Value::obj_vec(members.into_iter().collect())
    }

    /// [`obj`](Value::obj) for members only known at run time.
    pub fn obj_vec(members: Vec<(&str, Value)>) -> Value {
        Value::Obj(members.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn str(s: impl Into<String>) -> Value {
        Value::Str(s.into())
    }

    /// The member called `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            _ => None,
        }
    }

    /// The string member `key`.
    pub fn str_of(&self, key: &str) -> Option<&str> {
        self.get(key)?.as_str()
    }
}

impl fmt::Display for Value {
    /// Compact JSON.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Num(n) if n.fract() == 0.0 && n.abs() < 1e15 => write!(f, "{}", *n as i64),
            Value::Num(n) if n.is_finite() => write!(f, "{n}"),
            Value::Num(_) => f.write_str("null"),
            Value::Str(s) => write_str(f, s),
            Value::Arr(a) => {
                f.write_str("[")?;
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{v}")?;
                }
                f.write_str("]")
            }
            Value::Obj(m) => {
                f.write_str("{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write_str(f, k)?;
                    write!(f, ":{v}")?;
                }
                f.write_str("}")
            }
        }
    }
}

fn write_str(f: &mut fmt::Formatter<'_>, s: &str) -> fmt::Result {
    f.write_str("\"")?;
    for c in s.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if (c as u32) < 0x20 => write!(f, "\\u{:04x}", c as u32)?,
            c => write!(f, "{c}")?,
        }
    }
    f.write_str("\"")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub msg: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.msg)
    }
}

impl std::error::Error for ParseError {}

/// Parses one JSON document (RFC 8259); anything after it but whitespace is an error.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut p = Parser { b: text.as_bytes(), pos: 0 };
    let v = p.value(0)?;
    p.ws();
    if p.pos != p.b.len() {
        return Err(p.err("trailing characters after the document"));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, msg: &'static str) -> ParseError {
        ParseError { offset: self.pos, msg }
    }

    fn ws(&mut self) {
        while matches!(self.b.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        if self.b.get(self.pos) == Some(&c) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn literal(&mut self, word: &'static [u8], v: Value) -> Result<Value, ParseError> {
        if self.b[self.pos..].starts_with(word) {
            self.pos += word.len();
            Ok(v)
        } else {
            Err(self.err("unexpected character"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nested too deeply"));
        }
        self.ws();
        match self.b.get(self.pos) {
            None => Err(self.err("unexpected end")),
            Some(b'{') => {
                self.pos += 1;
                let mut members = Vec::new();
                self.ws();
                if self.eat(b'}') {
                    return Ok(Value::Obj(members));
                }
                loop {
                    self.ws();
                    if self.b.get(self.pos) != Some(&b'"') {
                        return Err(self.err("expected a member name"));
                    }
                    let k = self.string()?;
                    self.ws();
                    if !self.eat(b':') {
                        return Err(self.err("expected ':'"));
                    }
                    members.push((k, self.value(depth + 1)?));
                    self.ws();
                    if self.eat(b',') {
                        continue;
                    }
                    if self.eat(b'}') {
                        return Ok(Value::Obj(members));
                    }
                    return Err(self.err("expected ',' or '}'"));
                }
            }
            Some(b'[') => {
                self.pos += 1;
                let mut items = Vec::new();
                self.ws();
                if self.eat(b']') {
                    return Ok(Value::Arr(items));
                }
                loop {
                    items.push(self.value(depth + 1)?);
                    self.ws();
                    if self.eat(b',') {
                        continue;
                    }
                    if self.eat(b']') {
                        return Ok(Value::Arr(items));
                    }
                    return Err(self.err("expected ',' or ']'"));
                }
            }
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') => self.literal(b"true", Value::Bool(true)),
            Some(b'f') => self.literal(b"false", Value::Bool(false)),
            Some(b'n') => self.literal(b"null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        self.eat(b'-');
        let digits = |p: &mut Self| {
            let from = p.pos;
            while p.b.get(p.pos).is_some_and(u8::is_ascii_digit) {
                p.pos += 1;
            }
            p.pos - from
        };
        // No leading zeros (RFC 8259 §6).
        if self.b.get(self.pos) == Some(&b'0') && self.b.get(self.pos + 1).is_some_and(u8::is_ascii_digit) {
            return Err(self.err("leading zero in a number"));
        }
        if digits(self) == 0 {
            return Err(self.err("expected digits"));
        }
        if self.eat(b'.') && digits(self) == 0 {
            return Err(self.err("expected digits after '.'"));
        }
        if matches!(self.b.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if !self.eat(b'+') {
                self.eat(b'-');
            }
            if digits(self) == 0 {
                return Err(self.err("expected exponent digits"));
            }
        }
        std::str::from_utf8(&self.b[start..self.pos])
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Value::Num)
            .ok_or_else(|| self.err("bad number"))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self
            .b
            .get(self.pos..self.pos + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
        let v = h.and_then(|h| u32::from_str_radix(h, 16).ok()).ok_or_else(|| self.err("bad \\u escape"))?;
        self.pos += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            // Copy the run up to the next quote, backslash or control character.
            let run = self.b[self.pos..]
                .iter()
                .position(|&c| c == b'"' || c == b'\\' || c < 0x20)
                .ok_or_else(|| self.err("unterminated string"))?;
            out.push_str(std::str::from_utf8(&self.b[self.pos..self.pos + run]).map_err(|_| self.err("invalid UTF-8"))?);
            self.pos += run;
            match self.b[self.pos] {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    let Some(&e) = self.b.get(self.pos) else { return Err(self.err("unterminated string")) };
                    self.pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let c = if (0xD800..0xDC00).contains(&hi) {
                                if !(self.eat(b'\\') && self.eat(b'u')) {
                                    return Err(self.err("lone surrogate"));
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("lone surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            out.push(char::from_u32(c).ok_or_else(|| self.err("lone surrogate"))?);
                        }
                        _ => return Err(self.err("unknown escape")),
                    }
                }
                _ => return Err(self.err("control character in a string")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_an_acme_directory() {
        let v = parse(
            r#"{"newNonce":"https://ca/nonce","newAccount":"https://ca/acct","newOrder":"https://ca/order",
                "meta":{"termsOfService":"https://ca/tos","caaIdentities":["ca.example"],"externalAccountRequired":false},"n":1.5e2}"#,
        )
        .unwrap();
        assert_eq!(v.str_of("newNonce"), Some("https://ca/nonce"));
        assert_eq!(v.get("meta").unwrap().str_of("termsOfService"), Some("https://ca/tos"));
        assert_eq!(v.get("meta").unwrap().get("caaIdentities").unwrap().as_array().unwrap(), [Value::str("ca.example")]);
        assert_eq!(v.get("meta").unwrap().get("externalAccountRequired"), Some(&Value::Bool(false)));
        assert_eq!(v.get("n").unwrap().as_f64(), Some(150.0));
        assert!(v.get("absent").is_none() && v.str_of("meta").is_none());
    }

    #[test]
    fn writes_compact_json() {
        let v = Value::obj([
            ("a", Value::Num(1.0)),
            ("b", Value::Arr(vec![Value::Bool(true), Value::Null, Value::str("x")])),
            ("c", Value::obj([])),
        ]);
        assert_eq!(v.to_string(), r#"{"a":1,"b":[true,null,"x"],"c":{}}"#);
        assert_eq!(Value::Num(-0.5).to_string(), "-0.5");
    }

    /// Strings are built here rather than written as escapes in the source, so the
    /// test file means what it says whatever tool edits it.
    #[test]
    fn strings_escape_and_unescape() {
        let bs = '\\';
        let nasty = format!("q\" b{bs} nl\n tab\t bell\u{7} e\u{e9} \u{1F600} </script>");
        let text = Value::str(nasty.clone()).to_string();
        assert!(!text.contains('\n') && !text.contains('\t') && !text.contains('\u{7}'));
        assert!(text.contains(&format!("{bs}u0007")));
        assert_eq!(parse(&text).unwrap(), Value::Str(nasty));
    }

    #[test]
    fn unicode_escapes_including_surrogate_pairs() {
        let bs = '\\';
        let doc = format!("\"a{bs}u00e9{bs}ud83d{bs}ude00{bs}/{bs}b\"");
        assert_eq!(parse(&doc).unwrap(), Value::str("a\u{e9}\u{1F600}/\u{8}"));
        for bad in [
            format!("\"{bs}ud83d\""),
            format!("\"{bs}ude00\""),
            format!("\"{bs}ud83d{bs}u0041\""),
            format!("\"{bs}u12\""),
            format!("\"{bs}q\""),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rejects_malformed_documents() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":}",
            "{\"a\" 1}",
            "{a:1}",
            "[1 2]",
            "tru",
            "01",
            "1.",
            ".5",
            "-",
            "1e",
            "\"abc",
            "\"a\nb\"",
            "{} x",
            "[1]]",
            "nul",
            "{\"a\":1,}",
            "'a'",
            "[\"a\" \"b\"]",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn accepts_the_edges_of_the_grammar() {
        for good in ["{}", "[]", " null ", "0", "-0", "0.5", "1E+2", "-1e-2", "\"\"", "[[],{}]", "{\"a\":{\"b\":[{}]}}", "\t[ 1 , 2 ]\r\n"]
        {
            assert!(parse(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(&deep(MAX_DEPTH)).is_ok());
        assert!(parse(&deep(MAX_DEPTH + 5)).is_err());
        assert!(parse(&"[".repeat(100_000)).is_err(), "no stack overflow");
    }

    #[test]
    fn first_duplicate_key_wins() {
        let v = parse(r#"{"a":1,"a":2}"#).unwrap();
        assert_eq!(v.get("a"), Some(&Value::Num(1.0)));
    }

    #[test]
    fn problem_document() {
        let v = parse(r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"JWS has an invalid anti-replay nonce","status":400}"#)
            .unwrap();
        assert_eq!(v.str_of("type"), Some("urn:ietf:params:acme:error:badNonce"));
        assert_eq!(v.get("status").unwrap().as_f64(), Some(400.0));
    }
}
