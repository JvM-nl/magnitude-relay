//! A strict subset of TOML, just big enough for `relay.toml`.
//!
//! The file is written by people who may never have seen TOML, so the parser's
//! job is as much to explain mistakes as to read the file: every error carries a
//! 1-based line number and says what to do about it. Anything outside the subset
//! is rejected with a message rather than half-understood: a lenient parser would
//! let a typo become a silently ignored setting.
//!
//! Supported: comments, blank lines, `[section]` headers (one level, bare names),
//! `[[section]]` headers for a list of tables (each one starts another entry),
//! `key = value` with bare keys, and values that are basic strings with the
//! escapes `\"` `\\` `\n` `\t` `\r` and a four-digit unicode escape, literal
//! `'strings'`, decimal integers (sign and `_` separators allowed), `true` and
//! `false`, and arrays of strings or of integers. Arrays may span lines, carry
//! comments, and end with a trailing comma. Not supported: floats, dates,
//! multi-line strings, inline tables, dotted or quoted keys, nested arrays.

use std::fmt;

/// One parsed value. Arrays are homogeneous, so a list of kinds can never be
/// half strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
    Bool(bool),
    Strs(Vec<String>),
    Ints(Vec<i64>),
    /// `[]` says nothing about what it holds, so it is accepted wherever either
    /// kind of list is.
    Empty,
}

impl Value {
    /// How to name this value in a "expected X, found Y" message.
    pub fn describe(&self) -> &'static str {
        match self {
            Value::Str(_) => "a string",
            Value::Int(_) => "an integer",
            Value::Bool(_) => "true or false",
            Value::Strs(_) => "a list of strings",
            Value::Ints(_) => "a list of integers",
            Value::Empty => "an empty list",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value: Value,
    /// Line the key is on.
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// `""` for keys written before any header.
    pub name: String,
    /// Line of the `[header]`; 0 for the top level.
    pub line: usize,
    /// Written `[[name]]`: one entry of a list, and the name may repeat.
    pub array: bool,
    /// In file order.
    pub entries: Vec<Entry>,
}

/// Sections in file order. The top-level section (`""`) is present only if the
/// file has keys before its first header, and then it is first. A `[[name]]`
/// list has one section per entry, in file order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    pub sections: Vec<Section>,
}

impl Document {
    /// The section called `name` (the first entry, for a list).
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Line on which `key` is set in `section`, if it is set at all.
    pub fn line_of(&self, section: &str, key: &str) -> Option<usize> {
        self.section(section)?.entries.iter().find(|e| e.key == key).map(|e| e.line)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// 1-based.
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

pub fn parse(text: &str) -> Result<Document> {
    // Windows Notepad prepends a byte order mark to UTF-8 files; it is not content.
    let text = if text.as_bytes().starts_with(&[0xEF, 0xBB, 0xBF]) { &text[3..] } else { text };
    let mut p = Parser { s: text, b: text.as_bytes(), p: 0, line: 1 };
    let mut sections = vec![Section { name: String::new(), line: 0, array: false, entries: Vec::new() }];
    let mut cur = 0;
    loop {
        p.skip_trivia();
        let Some(c) = p.peek() else { break };
        let line = p.line;
        if c == b'[' {
            let (name, array) = p.header()?;
            if let Some(first) = sections.iter().find(|s| s.name == name) {
                let msg = match (first.array, array) {
                    (true, true) => None,
                    (false, false) => {
                        Some(format!("section [{name}] appears twice (first on line {}); put all its settings under one header", first.line))
                    }
                    (true, false) => Some(format!("[{name}] is written [[{name}]] on line {}: use [[{name}]] for every entry", first.line)),
                    (false, true) => Some(format!("[[{name}]] is written [{name}] on line {}: use one form", first.line)),
                };
                if let Some(msg) = msg {
                    return p.fail_at(line, msg);
                }
            }
            sections.push(Section { name, line, array, entries: Vec::new() });
            cur = sections.len() - 1;
        } else {
            let (key, value) = p.key_value()?;
            let sec = &mut sections[cur];
            if let Some(first) = sec.entries.iter().find(|e| e.key == key) {
                let at = if sec.name.is_empty() { "at the top of the file".to_string() } else { format!("in [{}]", sec.name) };
                return p.fail_at(line, format!("`{key}` is set twice {at} (first on line {}); remove one", first.line));
            }
            sec.entries.push(Entry { key, value, line });
        }
    }
    if sections[0].entries.is_empty() {
        sections.remove(0);
    }
    Ok(Document { sections })
}

struct Parser<'a> {
    s: &'a str,
    b: &'a [u8],
    p: usize,
    line: usize,
}

impl<'a> Parser<'a> {
    fn fail<T>(&self, msg: impl Into<String>) -> Result<T> {
        self.fail_at(self.line, msg)
    }

    fn fail_at<T>(&self, line: usize, msg: impl Into<String>) -> Result<T> {
        Err(Error { line, msg: msg.into() })
    }

    #[inline]
    fn peek(&self) -> Option<u8> {
        self.b.get(self.p).copied()
    }

    /// The character at the cursor, for messages. The cursor only ever stops on
    /// ASCII bytes or at the start of a character, so slicing is safe.
    fn here(&self) -> char {
        self.s[self.p..].chars().next().unwrap_or(' ')
    }

    /// Consumes one byte (an ASCII structural byte, or a newline).
    fn bump(&mut self) {
        if self.b[self.p] == b'\n' {
            self.line += 1;
        }
        self.p += 1;
    }

    /// Spaces, tabs and the CR of a CRLF.
    fn skip_blanks(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r')) {
            self.p += 1;
        }
    }

    /// Everything between statements: blanks, newlines and comments.
    fn skip_trivia(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.bump(),
                Some(b'#') => self.skip_comment(),
                _ => return,
            }
        }
    }

    /// Up to, not past, the newline.
    fn skip_comment(&mut self) {
        while !matches!(self.peek(), None | Some(b'\n')) {
            self.p += 1;
        }
    }

    /// After a statement only a comment may share its line.
    fn end_of_line(&mut self, after: &str) -> Result<()> {
        self.skip_blanks();
        match self.peek() {
            None => Ok(()),
            Some(b'#') => {
                self.skip_comment();
                Ok(())
            }
            Some(b'\n') => {
                self.bump();
                Ok(())
            }
            Some(_) => self.fail(format!("unexpected `{}` after {after}; each setting goes on its own line", self.here())),
        }
    }

    fn bare_key(&mut self) -> String {
        let start = self.p;
        while matches!(self.peek(), Some(c) if c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
            self.p += 1;
        }
        self.s[start..self.p].to_string()
    }

    /// `[name]` or `[[name]]` (then `true`); the cursor is on the `[`.
    fn header(&mut self) -> Result<(String, bool)> {
        self.p += 1;
        let array = self.peek() == Some(b'[');
        if array {
            self.p += 1;
        }
        self.skip_blanks();
        let name = self.bare_key();
        if name.is_empty() {
            return match self.peek() {
                Some(b']') => self.fail("empty section name: write the name between the brackets, like [relay]"),
                Some(b'"' | b'\'') => self.fail("quoted section names are not supported; use letters, digits, '_' and '-'"),
                _ => self.fail("invalid section name: use letters, digits, '_' and '-'"),
            };
        }
        self.skip_blanks();
        match self.peek() {
            Some(b']') => self.p += 1,
            Some(b'.') => return self.fail("dotted section names like [a.b] are not supported; use a single name"),
            None | Some(b'\n') => return self.fail("section header is missing its closing ']'"),
            Some(_) => return self.fail(format!("unexpected `{}` in section name: use letters, digits, '_' and '-' only", self.here())),
        }
        if array {
            if self.peek() != Some(b']') {
                return self.fail(format!("[[{name}]] is missing its second closing ']'"));
            }
            self.p += 1;
        }
        self.end_of_line("the section header")?;
        Ok((name, array))
    }

    fn key_value(&mut self) -> Result<(String, Value)> {
        let key = self.bare_key();
        if key.is_empty() {
            return match self.peek() {
                Some(b'=') => self.fail("missing key before '='"),
                Some(b'"' | b'\'') => self.fail("quoted keys are not supported; write the key bare, like name = \"...\""),
                _ => self.fail(format!("unexpected `{}`: expected a setting like name = value, or a [section] header", self.here())),
            };
        }
        self.skip_blanks();
        match self.peek() {
            Some(b'=') => self.p += 1,
            Some(b'.') => return self.fail(format!("dotted keys like `{key}.x` are not supported; put the setting under a [section] instead")),
            _ => return self.fail(format!("expected '=' after `{key}`")),
        }
        self.skip_blanks();
        let value = self.value()?;
        self.end_of_line("the value")?;
        Ok((key, value))
    }

    fn value(&mut self) -> Result<Value> {
        match self.peek() {
            None | Some(b'\n' | b'#') => self.fail("missing value after '='"),
            Some(b'"') => {
                if self.b[self.p..].starts_with(b"\"\"\"") {
                    return self.fail("multi-line strings are not supported; keep the string on one line (write \\n for a line break)");
                }
                self.basic_string().map(Value::Str)
            }
            Some(b'\'') => {
                if self.b[self.p..].starts_with(b"'''") {
                    return self.fail("multi-line strings are not supported; keep the string on one line");
                }
                self.literal_string().map(Value::Str)
            }
            Some(b'[') => self.array(),
            Some(b'{') => self.fail("inline tables are not supported; use a [section] with one setting per line"),
            Some(_) => self.scalar(),
        }
    }

    /// `"..."` with escapes; the cursor is on the opening quote.
    fn basic_string(&mut self) -> Result<String> {
        self.p += 1;
        let mut out = String::new();
        let mut seg = self.p;
        loop {
            match self.peek() {
                None | Some(b'\n' | b'\r') => return self.fail("unterminated string: the closing quote must be on the same line"),
                Some(b'"') => {
                    out.push_str(&self.s[seg..self.p]);
                    self.p += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    out.push_str(&self.s[seg..self.p]);
                    self.p += 1;
                    out.push(self.escape()?);
                    seg = self.p;
                }
                Some(c) if (c < 0x20 && c != b'\t') || c == 0x7F => {
                    return self.fail("control character inside a string; write it as an escape such as \\t");
                }
                Some(_) => self.p += 1,
            }
        }
    }

    /// The character after a backslash; the cursor is just past the backslash.
    fn escape(&mut self) -> Result<char> {
        let c = match self.peek() {
            None | Some(b'\n' | b'\r') => return self.fail("unterminated string: the closing quote must be on the same line"),
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'n') => '\n',
            Some(b't') => '\t',
            Some(b'r') => '\r',
            Some(b'u') => {
                let digits = self.s.get(self.p + 1..self.p + 5).filter(|d| d.bytes().all(|b| b.is_ascii_hexdigit()));
                let Some(digits) = digits else {
                    return self.fail("a backslash-u escape needs exactly four hex digits after the u");
                };
                let Some(ch) = u32::from_str_radix(digits, 16).ok().and_then(char::from_u32) else {
                    return self.fail(format!("the escape for {digits} is not a valid character (surrogate halves cannot stand alone)"));
                };
                self.p += 4;
                ch
            }
            Some(_) => {
                return self.fail(format!(
                    "unknown escape `\\{}` in string; allowed: \\\" \\\\ \\n \\t \\r and a backslash-u escape with four hex digits. \
                     To write a backslash (a Windows path, say) double it, or use 'single quotes' where nothing is escaped",
                    self.here()
                ));
            }
        };
        self.p += 1;
        Ok(c)
    }

    /// `'...'`: no escapes at all; the cursor is on the opening quote.
    fn literal_string(&mut self) -> Result<String> {
        self.p += 1;
        let start = self.p;
        loop {
            match self.peek() {
                None | Some(b'\n' | b'\r') => return self.fail("unterminated string: the closing quote must be on the same line"),
                Some(b'\'') => {
                    let out = self.s[start..self.p].to_string();
                    self.p += 1;
                    return Ok(out);
                }
                Some(_) => self.p += 1,
            }
        }
    }

    /// A bare word: `true`, `false` or an integer.
    fn scalar(&mut self) -> Result<Value> {
        let start = self.p;
        while matches!(self.peek(), Some(c) if !matches!(c, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'#')) {
            self.p += 1;
        }
        let tok = &self.s[start..self.p];
        match tok {
            "" => self.fail(format!("expected a value but found `{}`", self.here())),
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            _ if tok.starts_with(|c: char| c.is_ascii_digit() || c == '+' || c == '-') => self.integer(tok),
            _ => self.fail(format!("`{tok}` is not a value: text must be in \"quotes\" (true and false are the only bare words)")),
        }
    }

    fn integer(&self, tok: &str) -> Result<Value> {
        let digits = tok.trim_start_matches(['+', '-']);
        if tok.len() - digits.len() > 1 || digits.is_empty() {
            return self.fail(format!("`{tok}` is not a valid integer"));
        }
        if digits.starts_with("0x") || digits.starts_with("0o") || digits.starts_with("0b") {
            return self.fail(format!("`{tok}`: only decimal integers are supported"));
        }
        if !digits.bytes().all(|b| b.is_ascii_digit() || b == b'_') {
            return if tok.parse::<f64>().is_ok() {
                self.fail(format!("`{tok}`: decimal numbers are not supported; use a whole number"))
            } else {
                self.fail(format!("`{tok}` is not a number; text must be in \"quotes\""))
            };
        }
        if digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
            return self.fail(format!("`{tok}`: an underscore must sit between two digits, like 1_000"));
        }
        let clean: String = digits.chars().filter(|&c| c != '_').collect();
        if clean.len() > 1 && clean.starts_with('0') {
            return self.fail(format!("`{tok}`: leading zeros are not allowed"));
        }
        let signed = if tok.starts_with('-') { format!("-{clean}") } else { clean };
        match signed.parse::<i64>() {
            Ok(n) => Ok(Value::Int(n)),
            Err(_) => self.fail(format!("`{tok}` is too large (integers must fit in 64 bits)")),
        }
    }

    /// `[ ... ]`, possibly over several lines; the cursor is on the `[`.
    fn array(&mut self) -> Result<Value> {
        let open_line = self.line;
        self.p += 1;
        let mut strs: Vec<String> = Vec::new();
        let mut ints: Vec<i64> = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek() {
                None => return self.fail_at(open_line, "this list is missing its closing ']'"),
                Some(b']') => {
                    self.p += 1;
                    break;
                }
                Some(b',') => return self.fail("unexpected ',': a value must come before each comma"),
                Some(b'[') => return self.fail("nested lists are not supported"),
                _ => {}
            }
            match self.value()? {
                Value::Str(s) if ints.is_empty() => strs.push(s),
                Value::Int(n) if strs.is_empty() => ints.push(n),
                Value::Str(_) | Value::Int(_) => return self.fail("a list must hold only strings or only integers, not a mix"),
                _ => return self.fail("lists may only hold strings or integers"),
            }
            self.skip_trivia();
            match self.peek() {
                Some(b',') => self.p += 1,
                Some(b']') => {}
                None => return self.fail_at(open_line, "this list is missing its closing ']'"),
                Some(_) => return self.fail(format!("expected ',' or ']' after a list item, found `{}`", self.here())),
            }
        }
        Ok(match (strs.is_empty(), ints.is_empty()) {
            (true, true) => Value::Empty,
            (false, _) => Value::Strs(strs),
            (_, false) => Value::Ints(ints),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A string containing the one-character backslash, for building escape
    /// sequences in tests without writing them literally.
    const BS: char = '\\';

    fn doc(text: &str) -> Document {
        parse(text).unwrap_or_else(|e| panic!("{e}\n---\n{text}"))
    }

    fn only(text: &str) -> Value {
        let d = doc(text);
        assert_eq!(d.sections.len(), 1);
        assert_eq!(d.sections[0].entries.len(), 1);
        d.sections[0].entries[0].value.clone()
    }

    fn fails(text: &str, line: usize, needle: &str) {
        match parse(text) {
            Ok(d) => panic!("expected an error containing {needle:?}, parsed {d:?} from {text:?}"),
            Err(e) => {
                assert_eq!(e.line, line, "line of {e} for {text:?}");
                assert!(e.msg.contains(needle), "{:?} does not contain {needle:?} (input {text:?})", e.msg);
            }
        }
    }

    #[test]
    fn every_value_type() {
        assert_eq!(only("k = \"hello world\""), Value::Str("hello world".into()));
        assert_eq!(only("k = 'raw \\ text \"q\"'"), Value::Str("raw \\ text \"q\"".into()));
        assert_eq!(only("k = \"\""), Value::Str(String::new()));
        assert_eq!(only("k = 42"), Value::Int(42));
        assert_eq!(only("k = +7"), Value::Int(7));
        assert_eq!(only("k = -7"), Value::Int(-7));
        assert_eq!(only("k = 0"), Value::Int(0));
        assert_eq!(only("k = -0"), Value::Int(0));
        assert_eq!(only("k = 1_000_000"), Value::Int(1_000_000));
        assert_eq!(only("k = 9223372036854775807"), Value::Int(i64::MAX));
        assert_eq!(only("k = -9223372036854775808"), Value::Int(i64::MIN));
        assert_eq!(only("k = true"), Value::Bool(true));
        assert_eq!(only("k = false"), Value::Bool(false));
        assert_eq!(only("k = []"), Value::Empty);
        assert_eq!(only("k = [ ]"), Value::Empty);
        assert_eq!(only("k = [\"a\", 'b', \"\"]"), Value::Strs(vec!["a".into(), "b".into(), String::new()]));
        assert_eq!(only("k = [1, -2, 3_000]"), Value::Ints(vec![1, -2, 3000]));
        assert_eq!(only("k=[1,2]"), Value::Ints(vec![1, 2]));
    }

    #[test]
    fn string_escapes() {
        assert_eq!(only(r#"k = "a\"b\\c\nd\te\rf""#), Value::Str("a\"b\\c\nd\te\rf".into()));
        let uni = format!("k = \"caf{BS}u00e9 {BS}u0041 {BS}u20AC\"");
        assert_eq!(only(&uni), Value::Str("caf\u{e9} A \u{20ac}".into()));
        // Raw non-ASCII passes through untouched, in strings and comments.
        assert_eq!(only("k = \"h\u{e9}llo \u{1f600}\" # \u{e9}\u{e9}"), Value::Str("h\u{e9}llo \u{1f600}".into()));
        // Single quotes keep every backslash, which is what Windows paths want.
        assert_eq!(only(r"k = 'C:\relay\data'"), Value::Str(r"C:\relay\data".into()));
    }

    #[test]
    fn sections_keys_and_lines() {
        let d = doc("# header comment\n\ntop = 1\n\n[a]\nx = 1\ny = \"two\"\n\n[b]  # trailing\nz = true\n");
        let names: Vec<_> = d.sections.iter().map(|s| (s.name.as_str(), s.line)).collect();
        assert_eq!(names, [("", 0), ("a", 5), ("b", 9)]);
        let a = d.section("a").unwrap();
        assert_eq!((a.entries[0].key.as_str(), a.entries[0].line), ("x", 6));
        assert_eq!((a.entries[1].key.as_str(), a.entries[1].line), ("y", 7));
        assert_eq!(d.section("").unwrap().entries[0].line, 3);
        assert_eq!(d.line_of("b", "z"), Some(10));
        assert_eq!(d.line_of("b", "nope"), None);
        assert_eq!(d.line_of("c", "z"), None);
    }

    #[test]
    fn empty_and_header_only_documents() {
        assert!(doc("").sections.is_empty());
        assert!(doc("# nothing\n\n   \n").sections.is_empty());
        let d = doc("[a]\n[b]\n");
        assert_eq!(d.sections.len(), 2);
        assert!(d.sections.iter().all(|s| s.entries.is_empty()));
        // No top-level section unless there are top-level keys.
        assert_eq!(d.sections[0].name, "a");
    }

    #[test]
    fn multi_line_arrays() {
        let t = "[p]\nkinds = [\n  1, 2,   # first two\n  # a comment line\n  3,\n  4, # last, with a trailing comma\n]\nafter = 9\n";
        let d = doc(t);
        let p = d.section("p").unwrap();
        assert_eq!(p.entries[0].value, Value::Ints(vec![1, 2, 3, 4]));
        assert_eq!(p.entries[0].line, 2);
        // Line counting continues correctly past the array.
        assert_eq!(p.entries[1].key, "after");
        assert_eq!(p.entries[1].line, 8);

        let strs = doc("x = [\n  \"a\",\n  \"b\"\n]\n");
        assert_eq!(strs.sections[0].entries[0].value, Value::Strs(vec!["a".into(), "b".into()]));
        assert_eq!(only("x = [1,]"), Value::Ints(vec![1]));
        assert_eq!(only("x = [\n\n# only a comment\n]"), Value::Empty);
    }

    #[test]
    fn comments_at_end_of_lines() {
        let d = doc("[a] # section\nk = \"v # not a comment\" # real\nn = 5# tight\nb = true #\nl = [1, 2] # after list\ns = 'x#y'\n");
        let e = &d.sections[0].entries;
        assert_eq!(e[0].value, Value::Str("v # not a comment".into()));
        assert_eq!(e[1].value, Value::Int(5));
        assert_eq!(e[2].value, Value::Bool(true));
        assert_eq!(e[3].value, Value::Ints(vec![1, 2]));
        assert_eq!(e[4].value, Value::Str("x#y".into()));
    }

    #[test]
    fn crlf_bom_and_last_line_without_newline() {
        let d = doc("[a]\r\nk = 1\r\nl = [1,\r\n 2]\r\nm = \"x\"");
        assert_eq!(d.sections[0].entries.len(), 3);
        assert_eq!(d.sections[0].entries[2].line, 5);
        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(b"[a]\nk = 1\n");
        assert_eq!(doc(std::str::from_utf8(&bom).unwrap()).sections[0].name, "a");
        assert_eq!(doc("[ spaced ]\nk=1").sections[0].name, "spaced");
        assert_eq!(doc("  indented = 1").sections[0].entries[0].key, "indented");
    }

    #[test]
    fn bare_key_characters() {
        let d = doc("[a-b_1]\nmax-limit = 1\nMax_9 = 2\n");
        assert_eq!(d.sections[0].name, "a-b_1");
        assert_eq!(d.sections[0].entries[0].key, "max-limit");
        assert_eq!(d.sections[0].entries[1].key, "Max_9");
    }

    #[test]
    fn string_errors() {
        fails("a = 1\nk = \"abc\n", 2, "unterminated string");
        fails("k = \"abc", 1, "unterminated string");
        fails("k = 'abc\nz = 1", 1, "unterminated string");
        fails("k = \"abc\\", 1, "unterminated string");
        fails("\nk = \"a\u{1}b\"", 2, "control character");
        fails(r#"k = "C:\data""#, 1, "unknown escape");
        fails(r#"k = "C:\data""#, 1, "single quotes");
        // The TOML text C:\relay holds a carriage return (the Rust literal below too):
        // the Windows-path trap.
        assert_eq!(only(r#"k = "C:\relay""#), Value::Str("C:\relay".into()));
        fails(r#"k = "\/""#, 1, "unknown escape");
        fails(&format!("k = \"{BS}u12\""), 1, "four hex digits");
        fails(&format!("k = \"{BS}uzzzz\""), 1, "four hex digits");
        fails(&format!("k = \"{BS}ud800\""), 1, "not a valid character");
        fails("k = \"\"\"multi\nline\"\"\"", 1, "multi-line");
        fails("k = '''multi'''", 1, "multi-line");
    }

    #[test]
    fn number_errors() {
        fails("k = 007", 1, "leading zeros");
        fails("k = 1__0", 1, "underscore");
        fails("k = _1", 1, "is not a value");
        fails("k = 1_", 1, "underscore");
        fails("k = +_1", 1, "underscore");
        fails("k = 1.5", 1, "decimal numbers");
        fails("k = 1e5", 1, "decimal numbers");
        fails("k = 0x1F", 1, "only decimal");
        fails("k = 9223372036854775808", 1, "too large");
        fails("k = -9223372036854775809", 1, "too large");
        fails("k = --1", 1, "not a valid integer");
        fails("k = -", 1, "not a valid integer");
        fails("k = 127.0.0.1:7777", 1, "text must be in \"quotes\"");
        fails("k = 2024-01-01", 1, "text must be in \"quotes\"");
    }

    #[test]
    fn structure_errors() {
        fails("k = vector", 1, "text must be in \"quotes\"");
        fails("\n\nk =\n", 3, "missing value");
        fails("k = # nothing", 1, "missing value");
        fails("k\n", 1, "expected '='");
        fails("k v", 1, "expected '='");
        fails("= 1", 1, "missing key");
        fails("\"k\" = 1", 1, "quoted keys");
        fails("a.b = 1", 1, "dotted keys");
        fails("k = 1 2", 1, "unexpected `2`");
        fails("k = \"a\" \"b\"", 1, "unexpected `\"`");
        fails("k = true x", 1, "unexpected `x`");
        fails("[a]\nk = { x = 1 }", 2, "inline tables");
        fails("$ = 1", 1, "unexpected `$`");
        fails("k = $", 1, "is not a value");
        fails("k = ,", 1, "expected a value");
    }

    #[test]
    fn arrays_of_tables() {
        let d = doc("[a]\nk = 1\n\n[[s]]\nurl = \"x\"\nn = 1\n[[ s ]]\nurl = \"y\"\n[b]\nk = 2\n");
        let names: Vec<_> = d.sections.iter().map(|s| (s.name.as_str(), s.line, s.array)).collect();
        assert_eq!(names, [("a", 1, false), ("s", 4, true), ("s", 7, true), ("b", 9, false)]);
        // The same key in two entries is two settings, not a repeat.
        let urls: Vec<_> = d.sections.iter().filter(|s| s.name == "s").map(|s| s.entries[0].value.clone()).collect();
        assert_eq!(urls, [Value::Str("x".into()), Value::Str("y".into())]);
        assert_eq!(d.section("s").unwrap().line, 4, "the first entry");
        fails("[[s]]\nk = 1\nk = 2", 3, "set twice in [s]");
        fails("[[s]]\n[s]\n", 2, "[s] is written [[s]] on line 1: use [[s]] for every entry");
        fails("[s]\n[[s]]\n", 2, "[[s]] is written [s] on line 1");
        fails("[[s]", 1, "second closing ']'");
        fails("[[s] ]", 1, "second closing ']'");
        fails("[[]]", 1, "empty section name");
    }

    #[test]
    fn header_errors() {
        fails("\n[]", 2, "empty section name");
        fails("[a.b]", 1, "dotted section names");
        fails("[a", 1, "missing its closing");
        fails("[a\nk = 1", 1, "missing its closing");
        fails("[my section]", 1, "unexpected `s` in section name");
        fails("[\"a\"]", 1, "quoted section names");
        fails("[a] x", 1, "unexpected `x`");
        fails("[$]", 1, "invalid section name");
    }

    #[test]
    fn duplicate_errors() {
        fails("k = 1\nj = 2\nk = 3", 3, "set twice at the top of the file (first on line 1)");
        fails("[a]\nk = 1\nj = 2\n[b]\nk = 1\n[a]\n", 6, "section [a] appears twice (first on line 1)");
        fails("[a]\nk = 1\n\nk = 2", 4, "`k` is set twice in [a] (first on line 2)");
        // The same key in different sections is fine.
        assert_eq!(doc("[a]\nk = 1\n[b]\nk = 2\n").sections.len(), 2);
    }

    #[test]
    fn array_errors() {
        fails("k = [1, \"a\"]", 1, "only strings or only integers");
        fails("k = [\"a\", 1]", 1, "only strings or only integers");
        fails("k = [[1]]", 1, "nested lists");
        fails("k = [true]", 1, "strings or integers");
        fails("k = [1,,2]", 1, "unexpected ','");
        fails("k = [,1]", 1, "unexpected ','");
        fails("k = [1 2]", 1, "expected ',' or ']'");
        fails("k = [{}]", 1, "inline tables");
        // An unterminated list is blamed on the line it opened on, not on end of file.
        fails("a = 1\nk = [1,\n 2,\n", 2, "missing its closing");
        fails("k = [\"a\"\n", 1, "missing its closing");
        // Errors inside a multi-line list report the item's own line.
        fails("k = [\n 1,\n 2.5,\n]", 3, "decimal numbers");
        // A list does not end at a comment.
        fails("k = [1, # ]\n", 1, "missing its closing");
    }

    #[test]
    fn error_display_has_line() {
        let e = parse("\n\nk = ?").unwrap_err();
        assert!(e.to_string().starts_with("line 3: "), "{e}");
    }
}
