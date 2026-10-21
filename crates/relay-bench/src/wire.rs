//! Reading JSON: what relays send back, and the event lines of a dataset file.
//!
//! This is deliberately **not** `relay_proto::json`. A benchmark that decoded the
//! relay's output with the relay's own parser could not notice a writer/parser
//! pair that agree on the same mistake, so the checker has its own small scanner.
//! It never builds a tree: it walks the text once, takes the few fields a check
//! needs and skips the rest (a 2 KB `content` costs one `memchr`-speed search for
//! the closing quote, which matters when a REQ returns 500 events and the client
//! shares the box with the relay).
//!
//! Every function returns `None`/`Err` on anything unexpected rather than
//! guessing; the callers count that as an error, loudly.

use relay_proto::hex;
use std::borrow::Cow;

/// A cursor over JSON text. Positions are always on ASCII delimiters, so slicing the
/// `&str` between them is valid UTF-8.
pub struct Cur<'a> {
    s: &'a str,
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    pub fn new(s: &'a str) -> Cur<'a> {
        Cur { s, b: s.as_bytes(), p: 0 }
    }

    #[inline]
    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.p) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.p += 1;
            } else {
                break;
            }
        }
    }

    #[inline]
    pub fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.b.get(self.p).copied()
    }

    #[inline]
    pub fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.p += 1;
            true
        } else {
            false
        }
    }

    #[inline]
    pub fn expect(&mut self, c: u8) -> Option<()> {
        self.eat(c).then_some(())
    }

    /// A string's text between the quotes, as it appeared on the wire (escapes not undone).
    pub fn span(&mut self) -> Option<&'a str> {
        self.expect(b'"')?;
        let start = self.p;
        let mut from = start;
        loop {
            let q = from + self.s.get(from..)?.find('"')?;
            // A quote preceded by an odd run of backslashes is escaped.
            let mut run = 0;
            while q - run > start && self.b[q - run - 1] == b'\\' {
                run += 1;
            }
            if run % 2 == 0 {
                self.p = q + 1;
                return Some(&self.s[start..q]);
            }
            from = q + 1;
        }
    }

    /// A string: its text, and whether it contains any backslash escape.
    pub fn string(&mut self) -> Option<(&'a str, bool)> {
        let inner = self.span()?;
        Some((inner, inner.as_bytes().contains(&b'\\')))
    }

    /// An unsigned integer. A fraction or exponent is refused: the fields read this
    /// way (`created_at`, `kind`, a count) are integers by protocol.
    pub fn u64(&mut self) -> Option<u64> {
        self.ws();
        let start = self.p;
        let mut v: u64 = 0;
        while let Some(&c) = self.b.get(self.p) {
            if !c.is_ascii_digit() {
                break;
            }
            v = v.checked_mul(10)?.checked_add(u64::from(c - b'0'))?;
            self.p += 1;
        }
        if self.p == start || matches!(self.b.get(self.p), Some(b'.' | b'e' | b'E')) {
            return None;
        }
        Some(v)
    }

    /// Skips any value.
    pub fn skip_value(&mut self) -> Option<()> {
        match self.peek()? {
            b'"' => self.span().map(|_| ()),
            b'{' | b'[' => {
                let mut depth = 0usize;
                loop {
                    match self.peek()? {
                        b'"' => {
                            self.span()?;
                        }
                        b'{' | b'[' => {
                            depth += 1;
                            self.p += 1;
                        }
                        b'}' | b']' => {
                            depth -= 1;
                            self.p += 1;
                            if depth == 0 {
                                return Some(());
                            }
                        }
                        _ => self.p += 1,
                    }
                }
            }
            _ => {
                let start = self.p;
                while let Some(&c) = self.b.get(self.p) {
                    if matches!(c, b',' | b']' | b'}' | b' ' | b'\t' | b'\r' | b'\n') {
                        break;
                    }
                    self.p += 1;
                }
                (self.p > start).then_some(())
            }
        }
    }

    /// Walks an object. `f` gets each key (raw) and must consume that key's value.
    pub fn object(&mut self, mut f: impl FnMut(&mut Cur<'a>, &'a str) -> Option<()>) -> Option<()> {
        self.expect(b'{')?;
        if self.eat(b'}') {
            return Some(());
        }
        loop {
            let (key, _) = self.string()?;
            self.expect(b':')?;
            f(self, key)?;
            if self.eat(b',') {
                continue;
            }
            return self.expect(b'}');
        }
    }

    /// Walks an array. `f` must consume one element.
    pub fn array(&mut self, mut f: impl FnMut(&mut Cur<'a>) -> Option<()>) -> Option<()> {
        self.expect(b'[')?;
        if self.eat(b']') {
            return Some(());
        }
        loop {
            f(self)?;
            if self.eat(b',') {
                continue;
            }
            return self.expect(b']');
        }
    }

    /// A `true` or `false` literal.
    pub fn boolean(&mut self) -> Option<bool> {
        let rest = self.s.get(self.peek().map(|_| self.p)?..)?;
        if rest.starts_with("true") {
            self.p += 4;
            Some(true)
        } else if rest.starts_with("false") {
            self.p += 5;
            Some(false)
        } else {
            None
        }
    }

    /// A string value as owned, unescaped text.
    pub fn text(&mut self) -> Option<String> {
        let (raw, esc) = self.string()?;
        Some(if esc { unescape(raw) } else { raw.to_owned() })
    }
}

/// Undoes JSON string escaping (including surrogate pairs). Malformed escapes become
/// U+FFFD instead of failing: this only runs on error text we are about to print.
pub fn unescape(raw: &str) -> String {
    fn hex4(it: &mut std::str::Chars<'_>) -> Option<u32> {
        let mut v = 0;
        for _ in 0..4 {
            v = v * 16 + it.next()?.to_digit(16)?;
        }
        Some(v)
    }
    let mut out = String::with_capacity(raw.len());
    let mut it = raw.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('u') => {
                let Some(hi) = hex4(&mut it) else {
                    out.push('\u{fffd}');
                    continue;
                };
                if (0xD800..0xDC00).contains(&hi) {
                    let mut look = it.clone();
                    if look.next() == Some('\\') && look.next() == Some('u') {
                        if let Some(lo) = hex4(&mut look).filter(|lo| (0xDC00..0xE000).contains(lo)) {
                            it = look;
                            out.push(char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)).unwrap_or('\u{fffd}'));
                            continue;
                        }
                    }
                }
                out.push(char::from_u32(hi).unwrap_or('\u{fffd}'));
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// One message from a relay, with only the fields the checks use.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayMsg<'a> {
    Event { sub: &'a str, id: [u8; 32], created_at: u64, content: &'a str },
    Eose { sub: &'a str },
    Ok { id: [u8; 32], accepted: bool, msg: String },
    Count { sub: &'a str, count: u64 },
    Closed { sub: &'a str, msg: String },
    Notice(String),
    NegMsg { sub: &'a str, hex: &'a str },
    NegErr { sub: &'a str, msg: String },
    /// Valid JSON array with a label we do not act on (AUTH challenge, ...).
    Other(&'a str),
    /// Not a Nostr relay message.
    Malformed,
}

pub fn parse_relay_msg(s: &str) -> RelayMsg<'_> {
    parse_relay_msg_opt(s).unwrap_or(RelayMsg::Malformed)
}

fn parse_relay_msg_opt(s: &str) -> Option<RelayMsg<'_>> {
    let mut c = Cur::new(s);
    c.expect(b'[')?;
    let (label, _) = c.string()?;
    Some(match label {
        "EVENT" => {
            c.expect(b',')?;
            let (sub, _) = c.string()?;
            c.expect(b',')?;
            let (mut id, mut created_at, mut content) = (None, None, "");
            c.object(|c, key| match key {
                "id" => {
                    id = Some(hex::decode_32(c.string()?.0.as_bytes())?);
                    Some(())
                }
                "created_at" => {
                    created_at = Some(c.u64()?);
                    Some(())
                }
                "content" => {
                    content = c.span()?;
                    Some(())
                }
                _ => c.skip_value(),
            })?;
            RelayMsg::Event { sub, id: id?, created_at: created_at?, content }
        }
        "EOSE" => {
            c.expect(b',')?;
            RelayMsg::Eose { sub: c.string()?.0 }
        }
        "OK" => {
            c.expect(b',')?;
            let id = hex::decode_32(c.string()?.0.as_bytes())?;
            c.expect(b',')?;
            let accepted = c.boolean()?;
            let msg = if c.eat(b',') { c.text()? } else { String::new() };
            RelayMsg::Ok { id, accepted, msg }
        }
        "COUNT" => {
            c.expect(b',')?;
            let (sub, _) = c.string()?;
            c.expect(b',')?;
            let mut count = None;
            c.object(|c, key| {
                if key == "count" {
                    count = Some(c.u64()?);
                    Some(())
                } else {
                    c.skip_value()
                }
            })?;
            RelayMsg::Count { sub, count: count? }
        }
        "CLOSED" => {
            c.expect(b',')?;
            let (sub, _) = c.string()?;
            let msg = if c.eat(b',') { c.text()? } else { String::new() };
            RelayMsg::Closed { sub, msg }
        }
        "NOTICE" => {
            c.expect(b',')?;
            RelayMsg::Notice(c.text()?)
        }
        "NEG-MSG" => {
            c.expect(b',')?;
            let (sub, _) = c.string()?;
            c.expect(b',')?;
            RelayMsg::NegMsg { sub, hex: c.string()?.0 }
        }
        "NEG-ERR" => {
            c.expect(b',')?;
            let (sub, _) = c.string()?;
            let msg = if c.eat(b',') { c.text()? } else { String::new() };
            RelayMsg::NegErr { sub, msg }
        }
        other => RelayMsg::Other(other),
    })
}

/// The fields of a stored event the checker keeps.
#[derive(Debug, PartialEq, Eq)]
pub struct EventLine<'a> {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u64,
    /// Every `p` tag value that is 64 lowercase hex, in order, repeats removed.
    pub p: Vec<[u8; 32]>,
    /// Every `t` tag value, in order, repeats removed.
    pub t: Vec<Cow<'a, str>>,
    /// First `d` tag value.
    pub d: Option<Cow<'a, str>>,
}

/// Parses one event (a JSONL line, or the object inside an EVENT message). All `p` and
/// `t` tag values are kept because a filter matches an event if *any* of its tags of
/// that name matches; only the first `d` counts (NIP-01's addressable identifier).
pub fn parse_event_line(line: &str) -> Result<EventLine<'_>, &'static str> {
    let (mut id, mut pubkey, mut created_at, mut kind) = (None, None, None, None);
    let (mut p, mut t, mut d) = (Vec::new(), Vec::<Cow<'_, str>>::new(), None::<Cow<'_, str>>);
    let mut c = Cur::new(line);
    c.object(|c, key| match key {
        "id" => {
            id = Some(hex::decode_32(c.string()?.0.as_bytes())?);
            Some(())
        }
        "pubkey" => {
            pubkey = Some(hex::decode_32(c.string()?.0.as_bytes())?);
            Some(())
        }
        "created_at" => {
            created_at = Some(c.u64()?);
            Some(())
        }
        "kind" => {
            kind = Some(c.u64()?);
            Some(())
        }
        "tags" => c.array(|c| {
            let mut i = 0;
            let (mut name, mut val) = (None, None);
            c.array(|c| {
                if c.peek()? == b'"' && i < 2 {
                    let s = c.string()?;
                    if i == 0 {
                        name = Some(s.0);
                    } else {
                        val = Some(s);
                    }
                } else {
                    c.skip_value()?;
                }
                i += 1;
                Some(())
            })?;
            match (name, val) {
                (Some("p"), Some((v, _))) => {
                    if let Some(k) = hex::decode_32(v.as_bytes()) {
                        if !p.contains(&k) {
                            p.push(k);
                        }
                    }
                }
                (Some("t"), Some((v, esc))) => {
                    let v = if esc { Cow::Owned(unescape(v)) } else { Cow::Borrowed(v) };
                    if !t.contains(&v) {
                        t.push(v);
                    }
                }
                (Some("d"), Some((v, esc))) if d.is_none() => d = Some(if esc { Cow::Owned(unescape(v)) } else { Cow::Borrowed(v) }),
                _ => {}
            }
            Some(())
        }),
        _ => c.skip_value(),
    })
    .ok_or("malformed event JSON")?;
    Ok(EventLine {
        id: id.ok_or("event has no valid id")?,
        pubkey: pubkey.ok_or("event has no valid pubkey")?,
        created_at: created_at.ok_or("event has no created_at")?,
        kind: kind.ok_or("event has no kind")?,
        p,
        t,
        d,
    })
}

/// Just the id of an event line; stops reading at the first `id` key.
pub fn event_id(line: &str) -> Option<[u8; 32]> {
    let mut found = None;
    let mut c = Cur::new(line);
    // `object` has no early exit, so make the walk fail once the id is in hand and
    // treat that failure as success.
    let _ = c.object(|c, key| {
        if key == "id" {
            found = hex::decode_32(c.string()?.0.as_bytes());
            None
        } else {
            c.skip_value()
        }
    });
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Backslash + `u` + 4 hex digits, assembled at run time (see `jsonw` tests).
    fn bs_u(hex4: &str) -> String {
        let mut s = String::from("\\");
        s.push('u');
        s.push_str(hex4);
        s
    }

    fn h(c: char) -> String {
        c.to_string().repeat(64)
    }

    #[test]
    fn event_message_any_key_order_and_whitespace() {
        let a = format!(
            r#"["EVENT","s1",{{"content":"x \" y","created_at":1700000000,"id":"{}","kind":1059,"pubkey":"{}","sig":"{}","tags":[["p","{}"]]}}]"#,
            h('a'),
            h('b'),
            "c".repeat(128),
            h('d')
        );
        let b = format!(
            r#"[ "EVENT" , "s1" , {{ "id" : "{}" , "pubkey":"{}", "created_at" : 1700000000 , "kind":1059 , "tags":[[ "p" , "{}" ]] , "content" : "x \" y" , "sig":"{}" }} ]"#,
            h('a'),
            h('b'),
            h('d'),
            "c".repeat(128)
        );
        for s in [&a, &b] {
            match parse_relay_msg(s) {
                RelayMsg::Event { sub, id, created_at, content } => {
                    assert_eq!((sub, id, created_at), ("s1", [0xaa; 32], 1_700_000_000));
                    assert_eq!(content, "x \\\" y");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn control_messages() {
        assert_eq!(parse_relay_msg(r#"["EOSE","q-1"]"#), RelayMsg::Eose { sub: "q-1" });
        assert_eq!(parse_relay_msg(r#"["COUNT","c",{"count":42}]"#), RelayMsg::Count { sub: "c", count: 42 });
        assert_eq!(parse_relay_msg(r#"["COUNT","c",{"count":7,"approximate":false}]"#), RelayMsg::Count { sub: "c", count: 7 });
        assert_eq!(
            parse_relay_msg(&format!(r#"["OK","{}",false,"blocked: no \"kind\""]"#, h('1'))),
            RelayMsg::Ok { id: [0x11; 32], accepted: false, msg: "blocked: no \"kind\"".into() }
        );
        assert_eq!(
            parse_relay_msg(&format!(r#"["OK","{}",true]"#, h('1'))),
            RelayMsg::Ok { id: [0x11; 32], accepted: true, msg: String::new() }
        );
        assert_eq!(parse_relay_msg(r#"["CLOSED","s","restricted: x"]"#), RelayMsg::Closed { sub: "s", msg: "restricted: x".into() });
        assert_eq!(parse_relay_msg(r#"["NOTICE","hi"]"#), RelayMsg::Notice("hi".into()));
        assert_eq!(parse_relay_msg(r#"["NEG-MSG","n","6100"]"#), RelayMsg::NegMsg { sub: "n", hex: "6100" });
        assert_eq!(parse_relay_msg(r#"["NEG-ERR","n","blocked: big"]"#), RelayMsg::NegErr { sub: "n", msg: "blocked: big".into() });
        assert_eq!(parse_relay_msg(r#"["AUTH","challenge"]"#), RelayMsg::Other("AUTH"));
        for bad in ["", "{}", "[", r#"["EVENT","s"]"#, r#"["OK","zz",true,""]"#, r#"["EOSE"]"#, "[\"EVENT\",\"s\",{\"id\":1}]"] {
            assert_eq!(parse_relay_msg(bad), RelayMsg::Malformed, "{bad}");
        }
    }

    #[test]
    fn strings_with_escaped_quotes_and_backslashes() {
        let mut c = Cur::new(r#""a\\" tail"#);
        assert_eq!(c.string(), Some(("a\\\\", true)));
        let mut c = Cur::new(r#""a\\\"b" "#);
        assert_eq!(c.string(), Some(("a\\\\\\\"b", true)));
        let mut c = Cur::new(r#""plain""#);
        assert_eq!(c.string(), Some(("plain", false)));
        assert_eq!(Cur::new(r#""open"#).string(), None);
    }

    #[test]
    fn skip_value_handles_nesting_and_strings_with_brackets() {
        let mut c = Cur::new(r#"{"a":[1,[2,"]}"],{"b":"\"]"}],"c":null} rest"#);
        assert_eq!(c.skip_value(), Some(()));
        assert_eq!(c.peek(), Some(b'r'));
        let mut c = Cur::new("-12.5e3,");
        assert_eq!(c.skip_value(), Some(()));
        assert_eq!(c.peek(), Some(b','));
    }

    #[test]
    fn integers_are_strict() {
        assert_eq!(Cur::new("  123,").u64(), Some(123));
        assert_eq!(Cur::new("1.5").u64(), None);
        assert_eq!(Cur::new("1e3").u64(), None);
        assert_eq!(Cur::new("-1").u64(), None);
        assert_eq!(Cur::new("99999999999999999999").u64(), None);
        assert_eq!(Cur::new("18446744073709551615").u64(), Some(u64::MAX));
    }

    #[test]
    fn unescape_covers_pairs_and_garbage() {
        assert_eq!(unescape(r"a\nb\t\\\/"), "a\nb\t\\/");
        let pair = format!("{}{}", bs_u("d83d"), bs_u("de00"));
        assert_eq!(unescape(&pair), "\u{1F600}");
        assert_eq!(unescape(&bs_u("00e9")), "\u{e9}");
        // A lone high surrogate and a truncated escape degrade, they do not panic.
        assert_eq!(unescape(&bs_u("d83d")), "\u{fffd}");
        assert_eq!(unescape(&bs_u("12")), "\u{fffd}");
        assert_eq!(unescape("trailing\\"), "trailing\\");
    }

    #[test]
    fn event_line_extracts_the_checked_fields() {
        let line = format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":1700000001,"kind":30023,"tags":[["d","a\"b"],["t","nostr","extra"],["p","{}"],["p","{}"],["e","{}"],["x"]],"content":"hello {{[ ] }} \"q\"","sig":"{}"}}"#,
            h('a'),
            h('b'),
            h('c'),
            h('e'),
            h('f'),
            "9".repeat(128)
        );
        let e = parse_event_line(&line).unwrap();
        assert_eq!(e.id, [0xaa; 32]);
        assert_eq!(e.pubkey, [0xbb; 32]);
        assert_eq!((e.created_at, e.kind), (1_700_000_001, 30023));
        assert_eq!(e.p, vec![[0xcc; 32], [0xee; 32]], "every p tag is kept");
        assert_eq!(e.t, vec!["nostr"]);
        assert_eq!(e.d.as_deref(), Some("a\"b"));
        assert_eq!(event_id(&line), Some([0xaa; 32]));
        // Alphabetical key order (strfry's export) parses the same.
        let alpha = format!(
            r#"{{"content":"c","created_at":5,"id":"{}","kind":1,"pubkey":"{}","sig":"{}","tags":[]}}"#,
            h('1'),
            h('2'),
            "3".repeat(128)
        );
        let e = parse_event_line(&alpha).unwrap();
        assert_eq!((e.id, e.pubkey, e.created_at, e.kind, e.p, e.t, e.d), ([0x11; 32], [0x22; 32], 5, 1, vec![], vec![], None));
        assert_eq!(event_id(&alpha), Some([0x11; 32]));
    }

    #[test]
    fn event_line_rejects_damage() {
        assert!(parse_event_line("{}").is_err());
        assert!(parse_event_line("not json").is_err());
        let no_kind = format!(r#"{{"id":"{}","pubkey":"{}","created_at":1,"tags":[],"content":""}}"#, h('a'), h('b'));
        assert!(parse_event_line(&no_kind).is_err());
        let upper = format!(r#"{{"id":"{}","pubkey":"{}","created_at":1,"kind":1,"tags":[],"content":""}}"#, "A".repeat(64), h('b'));
        assert!(parse_event_line(&upper).is_err(), "uppercase hex is not a Nostr id");
    }
}
