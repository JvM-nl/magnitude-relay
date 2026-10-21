//! A hand-written JSON value and renderer, for the result lines and the filters
//! sent to relays.
//!
//! The output is what a script will `jq` over a whole campaign, so it must be
//! valid JSON no matter what a relay put in an error string: every string is
//! escaped, and a non-finite float (a ratio over zero ops) renders as `null`
//! rather than the invalid `NaN`.

pub enum Json {
    Null,
    Bool(bool),
    U64(u64),
    F64(f64),
    Str(String),
    Arr(Vec<Json>),
    /// Keys keep insertion order, so result lines read the same every run.
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj() -> Json {
        Json::Obj(Vec::new())
    }

    /// Appends a key (builder style). Panics on a non-object: a programming error.
    pub fn with(mut self, key: &str, v: impl Into<Json>) -> Json {
        match &mut self {
            Json::Obj(fields) => fields.push((key.to_owned(), v.into())),
            _ => panic!("Json::with on a non-object"),
        }
        self
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    pub fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::U64(n) => out.push_str(&n.to_string()),
            Json::F64(f) => {
                if f.is_finite() {
                    // Rust's Display never uses an exponent and always round-trips.
                    out.push_str(&f.to_string());
                } else {
                    out.push_str("null");
                }
            }
            Json::Str(s) => {
                out.push('"');
                escape_into(s, out);
                out.push('"');
            }
            Json::Arr(items) => {
                out.push('[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    escape_into(k, out);
                    out.push_str("\":");
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

/// JSON string escaping as `JSON.stringify` does it: the two quotes characters,
/// the five short escapes, and every other control character as a 4-digit hex
/// escape. Everything else, including DEL and non-ASCII, passes through raw. A
/// Nostr event id commits to exactly this form, so the generator uses it too.
pub fn escape_into(s: &str, out: &mut String) {
    // Nearly every string we write (hex, base64 payloads, short words) needs nothing.
    if !s.bytes().any(|b| b < 0x20 || b == b'"' || b == b'\\') {
        out.push_str(s);
        return;
    }
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push('\\');
                out.push('u');
                out.push_str(&format!("{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

impl From<u64> for Json {
    fn from(v: u64) -> Json {
        Json::U64(v)
    }
}
impl From<usize> for Json {
    fn from(v: usize) -> Json {
        Json::U64(v as u64)
    }
}
impl From<u32> for Json {
    fn from(v: u32) -> Json {
        Json::U64(u64::from(v))
    }
}
impl From<f64> for Json {
    fn from(v: f64) -> Json {
        Json::F64(v)
    }
}
impl From<bool> for Json {
    fn from(v: bool) -> Json {
        Json::Bool(v)
    }
}
impl From<&str> for Json {
    fn from(v: &str) -> Json {
        Json::Str(v.to_owned())
    }
}
impl From<String> for Json {
    fn from(v: String) -> Json {
        Json::Str(v)
    }
}
impl<T: Into<Json>> From<Option<T>> for Json {
    fn from(v: Option<T>) -> Json {
        v.map_or(Json::Null, Into::into)
    }
}
impl<T: Into<Json>> From<Vec<T>> for Json {
    fn from(v: Vec<T>) -> Json {
        Json::Arr(v.into_iter().map(Into::into).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backslash followed by `u` and four digits, built here because a source file
    /// that spells the sequence out can be rewritten by tooling before it compiles.
    fn bs_u(hex4: &str) -> String {
        let mut s = String::from("\\");
        s.push('u');
        s.push_str(hex4);
        s
    }

    #[test]
    fn renders_scalars_and_nesting() {
        let j = Json::obj()
            .with("a", 1u64)
            .with("b", "x")
            .with("c", true)
            .with("d", Json::Null)
            .with("e", vec![1u64, 2, 3])
            .with("f", Json::obj().with("g", 0.5));
        assert_eq!(j.render(), r#"{"a":1,"b":"x","c":true,"d":null,"e":[1,2,3],"f":{"g":0.5}}"#);
    }

    #[test]
    fn escapes_like_json_stringify() {
        let mut s = String::new();
        escape_into("a\"b\\c\nd\re\tf\u{8}\u{c}\u{1}\u{1f} ~\u{7f}\u{e9}", &mut s);
        let want = format!("a\\\"b\\\\c\\nd\\re\\tf\\b\\f{}{} ~\u{7f}\u{e9}", bs_u("0001"), bs_u("001f"));
        assert_eq!(s, want);
        // A hostile relay message cannot break out of the string it is embedded in.
        let j = Json::obj().with("msg", "\",\"injected\":1,\"x\":\"");
        assert_eq!(j.render(), r#"{"msg":"\",\"injected\":1,\"x\":\""}"#);
    }

    #[test]
    fn non_finite_floats_are_null_and_floats_have_no_exponent() {
        assert_eq!(Json::F64(f64::NAN).render(), "null");
        assert_eq!(Json::F64(f64::INFINITY).render(), "null");
        assert_eq!(Json::F64(1.5e-7).render(), "0.00000015");
        assert_eq!(Json::F64(12345678.25).render(), "12345678.25");
        assert_eq!(Json::from(None::<u64>).render(), "null");
        assert_eq!(Json::from(Some(7u64)).render(), "7");
    }

    #[test]
    fn keys_are_escaped_and_order_is_kept() {
        let j = Json::obj().with("z", 1u64).with("a\"b", 2u64);
        assert_eq!(j.render(), r#"{"z":1,"a\"b":2}"#);
    }
}
