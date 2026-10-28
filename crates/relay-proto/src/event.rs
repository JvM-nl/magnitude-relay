//! Turning wire JSON into a verified record.
//!
//! One pass over the JSON writes the record directly; the id is then the
//! sha256 of a serialisation generated *from the record*. That makes the stored
//! form self-proving: whatever we keep re-serialises to bytes that hash to the id.

use crate::json::{self, RawStr, Scanner};
use crate::record::{self, Record, FLAG_EXPIRATION, FLAG_PROTECTED, FLAG_RAW_FORM, HEADER_LEN};
use crate::secp::{SigRef, Verifier};
use crate::{hex, sha256, varint};
use std::fmt;
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    Json(json::Error),
    MissingField(&'static str),
    DuplicateField(&'static str),
    BadId,
    BadPubkey,
    BadSig,
    TagNotString,
    /// The id does not match the content.
    IdMismatch,
    /// The signature does not verify.
    SigInvalid,
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reject::Json(e) => write!(f, "malformed event: {e}"),
            Reject::MissingField(n) => write!(f, "missing field: {n}"),
            Reject::DuplicateField(n) => write!(f, "duplicate field: {n}"),
            Reject::BadId => f.write_str("id must be 64 lowercase hex"),
            Reject::BadPubkey => f.write_str("pubkey must be 64 lowercase hex"),
            Reject::BadSig => f.write_str("sig must be 128 lowercase hex"),
            Reject::TagNotString => f.write_str("tag values must be strings"),
            Reject::IdMismatch => f.write_str("bad event id"),
            Reject::SigInvalid => f.write_str("bad signature"),
        }
    }
}

impl std::error::Error for Reject {}

impl From<json::Error> for Reject {
    fn from(e: json::Error) -> Self {
        Reject::Json(e)
    }
}

/// What the parse learned that callers decide policy on, without re-reading the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventInfo {
    pub kind: u64,
    pub created_at: u64,
    pub tag_count: u32,
    pub content_len: u32,
    pub expiration: Option<u64>,
    pub protected: bool,
    /// Some string used a backslash escape (only then can canonical and raw differ).
    pub any_escaped: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    Canonical,
    Raw,
}

/// Reusable scratch for parsing. One per thread; nothing allocates after warm-up.
#[derive(Default)]
pub struct EventParser {
    spans: nostr_parse::Parser,
    content: Vec<u8>,
    tags: Vec<u8>,
    field: Vec<u8>,
    preimage: Vec<u8>,
}

/// An event's fixed-size fields and what the parse learned, for `write_record`.
struct Head {
    id: [u8; 32],
    pubkey: [u8; 32],
    sig: [u8; 64],
    created_at: u64,
    kind: u64,
    tag_count: u32,
    expiration: Option<u64>,
    protected: bool,
    any_escaped: bool,
}

impl EventParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses, checks the id, verifies the signature, and leaves the record in
    /// `out` (cleared first).
    pub fn parse_verified(&mut self, s: &mut Scanner<'_>, out: &mut Vec<u8>) -> Result<EventInfo, Reject> {
        let info = self.parse_id_checked(s, out)?;
        if !verify_sig(Record(out)) {
            return Err(Reject::SigInvalid);
        }
        Ok(info)
    }

    /// Parses and checks the id but not the signature, for callers that verify
    /// signatures elsewhere (in parallel, or after a duplicate check).
    pub fn parse_id_checked(&mut self, s: &mut Scanner<'_>, out: &mut Vec<u8>) -> Result<EventInfo, Reject> {
        let again = s.clone();
        let info = self.parse(s, out, Form::Canonical)?;
        self.confirm_id(again, out, info)
    }

    /// Finishes a `parse_unchecked`: checks the id, and when the canonical form
    /// does not hash to it, retries with the strings exactly as they arrived
    /// (an event signed by a serialiser that escapes differently, a raw DEL say).
    /// `again` is a scanner positioned where the event object began.
    pub fn confirm_id(&mut self, mut again: Scanner<'_>, out: &mut Vec<u8>, info: EventInfo) -> Result<EventInfo, Reject> {
        if compute_id(Record(out), &mut self.preimage) == *Record(out).id() {
            return Ok(info);
        }
        if !info.any_escaped {
            return Err(Reject::IdMismatch);
        }
        let info = self.parse(&mut again, out, Form::Raw)?;
        if compute_id(Record(out), &mut self.preimage) == *Record(out).id() {
            out[record::OFF_FLAGS] |= FLAG_RAW_FORM;
            return Ok(info);
        }
        Err(Reject::IdMismatch)
    }

    /// Parses without checking the id or signature, for trusted import.
    pub fn parse_unchecked(&mut self, s: &mut Scanner<'_>, out: &mut Vec<u8>) -> Result<EventInfo, Reject> {
        self.parse(s, out, Form::Canonical)
    }

    fn parse(&mut self, s: &mut Scanner<'_>, out: &mut Vec<u8>, form: Form) -> Result<EventInfo, Reject> {
        if let Some(info) = self.parse_spans(s, out, form) {
            return Ok(info);
        }
        self.parse_scanned(s, out, form)
    }

    /// The common case, read by nostr-parse in place: the same record, the same
    /// answer and the same end as [`Self::parse_scanned`], which takes whatever
    /// this leaves (`None`). That is an event nostr-parse refuses, so the scanner
    /// names the error exactly, or one the two could read differently: a key or
    /// hex field spelled with escapes, a kind past 65535, an empty sig, a deeply
    /// nested extra field.
    fn parse_spans(&mut self, s: &mut Scanner<'_>, out: &mut Vec<u8>, form: Form) -> Option<EventInfo> {
        let mut at = s.clone();
        let text = at.rest()?;
        let Self { spans, content, tags, field, .. } = self;
        let ev = spans.parse_spans(text).ok()?;
        if ev.unusual {
            return None;
        }
        let sig = ev.sig?;

        content.clear();
        tags.clear();
        let mut any_escaped = ev.content.escaped;
        write_str(raw(ev.content), form, content);
        let (mut expiration, mut protected) = (None, false);
        let mut tag_count = 0u32;
        for tag in ev.tags() {
            tag_count += 1;
            let count_at = tags.len();
            tags.push(0);
            for v in tag.iter() {
                any_escaped |= v.escaped;
                field.clear();
                write_str(raw(v), form, field);
                record::encode_field_str(field, tags);
            }
            patch_count(tags, count_at, tag.len() as u64);
            note_tag(tag.get(0).map(raw), tag.get(1).map(raw), tag.len() as u64, &mut protected, &mut expiration);
        }

        let head = Head {
            id: ev.id,
            pubkey: ev.pubkey,
            sig,
            created_at: ev.created_at,
            kind: u64::from(ev.kind),
            tag_count,
            expiration,
            protected,
            any_escaped,
        };
        at.advance(ev.end);
        *s = at;
        Some(write_record(out, &head, content, tags))
    }

    /// Any event JSON can spell, read by this crate's own scanner.
    fn parse_scanned(&mut self, s: &mut Scanner<'_>, out: &mut Vec<u8>, form: Form) -> Result<EventInfo, Reject> {
        self.content.clear();
        self.tags.clear();
        let mut id: Option<[u8; 32]> = None;
        let mut pubkey: Option<[u8; 32]> = None;
        let mut sig: Option<[u8; 64]> = None;
        let mut created_at: Option<u64> = None;
        let mut kind: Option<u64> = None;
        let mut have_content = false;
        let mut tag_count: Option<u32> = None;
        let mut any_escaped = false;
        let mut expiration = None;
        let mut protected = false;

        let Self { content, tags, field, .. } = self;
        s.object(|s, key| -> Result<(), Reject> {
            if key.escaped {
                return Ok(s.skip()?);
            }
            match key.bytes {
                b"id" => id = Some(hex_value(s, &mut id, "id", hex::decode_32, Reject::BadId)?),
                b"pubkey" => pubkey = Some(hex_value(s, &mut pubkey, "pubkey", hex::decode_32, Reject::BadPubkey)?),
                b"sig" => sig = Some(hex_value(s, &mut sig, "sig", hex::decode_64, Reject::BadSig)?),
                b"created_at" => {
                    once(created_at.is_some(), "created_at")?;
                    created_at = Some(s.u64()?);
                }
                b"kind" => {
                    once(kind.is_some(), "kind")?;
                    kind = Some(s.u64()?);
                }
                b"content" => {
                    once(have_content, "content")?;
                    have_content = true;
                    let v = s.string()?;
                    any_escaped |= v.escaped;
                    write_str(v, form, content);
                }
                b"tags" => {
                    once(tag_count.is_some(), "tags")?;
                    let mut n = 0u32;
                    s.array(|s| -> Result<(), Reject> {
                        n += 1;
                        let count_at = tags.len();
                        tags.push(0); // field count, patched once known
                        let mut fields = 0u64;
                        let mut first: Option<RawStr<'_>> = None;
                        let mut second: Option<RawStr<'_>> = None;
                        s.array(|s| -> Result<(), Reject> {
                            if s.peek() != Some(b'"') {
                                return Err(Reject::TagNotString);
                            }
                            let v = s.string()?;
                            any_escaped |= v.escaped;
                            match fields {
                                0 => first = Some(v),
                                1 => second = Some(v),
                                _ => {}
                            }
                            fields += 1;
                            field.clear();
                            write_str(v, form, field);
                            record::encode_field_str(field, tags);
                            Ok(())
                        })?;
                        patch_count(tags, count_at, fields);
                        note_tag(first, second, fields, &mut protected, &mut expiration);
                        Ok(())
                    })?;
                    tag_count = Some(n);
                }
                _ => s.skip()?,
            }
            Ok(())
        })?;

        let id = id.ok_or(Reject::MissingField("id"))?;
        let pubkey = pubkey.ok_or(Reject::MissingField("pubkey"))?;
        let sig = sig.ok_or(Reject::MissingField("sig"))?;
        let created_at = created_at.ok_or(Reject::MissingField("created_at"))?;
        let kind = kind.ok_or(Reject::MissingField("kind"))?;
        if !have_content {
            return Err(Reject::MissingField("content"));
        }
        let tag_count = tag_count.ok_or(Reject::MissingField("tags"))?;

        let head = Head { id, pubkey, sig, created_at, kind, tag_count, expiration, protected, any_escaped };
        Ok(write_record(out, &head, &self.content, &self.tags))
    }
}

/// The record for an event, in `out` (cleared first): the fixed fields, flags,
/// the expiration, then content and tags as already encoded.
fn write_record(out: &mut Vec<u8>, h: &Head, content: &[u8], tags: &[u8]) -> EventInfo {
    out.clear();
    out.reserve(HEADER_LEN + 8 + 20 + content.len() + tags.len());
    out.extend_from_slice(&h.id);
    out.extend_from_slice(&h.pubkey);
    out.extend_from_slice(&h.sig);
    out.extend_from_slice(&h.created_at.to_le_bytes());
    out.extend_from_slice(&h.kind.to_le_bytes());
    let mut flags = 0u8;
    if h.expiration.is_some() {
        flags |= FLAG_EXPIRATION;
    }
    if h.protected {
        flags |= FLAG_PROTECTED;
    }
    out.push(flags);
    if let Some(e) = h.expiration {
        out.extend_from_slice(&e.to_le_bytes());
    }
    varint::put(out, content.len() as u64);
    out.extend_from_slice(content);
    varint::put(out, u64::from(h.tag_count));
    out.extend_from_slice(tags);

    EventInfo {
        kind: h.kind,
        created_at: h.created_at,
        tag_count: h.tag_count,
        content_len: content.len() as u32,
        expiration: h.expiration,
        protected: h.protected,
        any_escaped: h.any_escaped,
    }
}

/// nostr-parse's view of a string as written, as this crate's.
fn raw(v: nostr_parse::RawStr<'_>) -> RawStr<'_> {
    RawStr { bytes: v.bytes, escaped: v.escaped }
}

/// What one tag says about the event: `["-"]` protects it (NIP-70), and the
/// first `expiration` tag's value, in plain decimal, is when it expires.
fn note_tag(first: Option<RawStr<'_>>, second: Option<RawStr<'_>>, fields: u64, protected: &mut bool, expiration: &mut Option<u64>) {
    if let Some(name) = first {
        if fields == 1 && name.is(b"-") {
            *protected = true;
        } else if expiration.is_none() && name.is(b"expiration") {
            *expiration = second.and_then(parse_decimal);
        }
    }
}

/// Parses a whole JSON event document (e.g. one line of an export).
pub fn parse_event_json(text: &str, parser: &mut EventParser, out: &mut Vec<u8>, verify: bool) -> Result<EventInfo, Reject> {
    let mut s = Scanner::new(text);
    let info = if verify {
        parser.parse_verified(&mut s, out)?
    } else {
        parser.parse_unchecked(&mut s, out)?
    };
    s.end()?;
    Ok(info)
}

/// Verifies many JSON events together, giving each line exactly the verdict
/// `parse_event_json(line, .., true)` would: ids are hashed several at a time
/// (`sha256::digest_many`) and signatures checked in batches
/// (`secp::Verifier::verify_batch`). For bulk input such as an import; one
/// per thread.
#[derive(Default)]
pub struct BulkVerifier {
    parser: EventParser,
    sigs: Verifier,
    rec: Vec<u8>,
    /// Records back to back; `spans[i]` is line i's.
    data: Vec<u8>,
    spans: Vec<Range<usize>>,
    results: Vec<Result<EventInfo, Reject>>,
    /// What `Scanner::end` said after each parse: trailing bytes are reported
    /// last, as `parse_event_json` reports them.
    trailing: Vec<Option<Reject>>,
    pre: Vec<u8>,
    pre_spans: Vec<(usize, Range<usize>)>,
    digests: Vec<[u8; 32]>,
    ok: Vec<bool>,
}

impl BulkVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies every line. Afterwards `results()[i]` is line i's verdict and,
    /// for an accepted line, `record(i)` its record (until the next call).
    pub fn verify(&mut self, lines: &[&str]) {
        self.data.clear();
        self.spans.clear();
        self.results.clear();
        self.trailing.clear();
        for line in lines {
            let mut s = Scanner::new(line);
            let r = self.parser.parse_unchecked(&mut s, &mut self.rec);
            let start = self.data.len();
            if r.is_ok() {
                self.data.extend_from_slice(&self.rec);
            }
            self.spans.push(start..self.data.len());
            self.trailing.push(if r.is_ok() { s.end().err().map(Reject::from) } else { None });
            self.results.push(r);
        }

        // Ids, all preimages hashed together.
        self.pre.clear();
        self.pre_spans.clear();
        for (i, r) in self.results.iter().enumerate() {
            if r.is_ok() {
                let start = self.pre.len();
                Record(&self.data[self.spans[i].clone()]).write_id_preimage(&mut self.pre);
                self.pre_spans.push((i, start..self.pre.len()));
            }
        }
        let pres: Vec<&[u8]> = self.pre_spans.iter().map(|(_, r)| &self.pre[r.clone()]).collect();
        self.digests.clear();
        self.digests.resize(pres.len(), [0; 32]);
        sha256::digest_many(&pres, &mut self.digests);
        for (k, (i, _)) in self.pre_spans.iter().enumerate() {
            let i = *i;
            if self.digests[k] == *Record(&self.data[self.spans[i].clone()]).id() {
                continue;
            }
            let Ok(info) = self.results[i] else { unreachable!() };
            self.results[i] = if !info.any_escaped {
                Err(Reject::IdMismatch)
            } else {
                // The canonical form did not hash to the id: the one-event
                // path retries with the strings exactly as received.
                let mut s = Scanner::new(lines[i]);
                let r = self.parser.parse_id_checked(&mut s, &mut self.rec);
                if r.is_ok() {
                    let start = self.data.len();
                    self.data.extend_from_slice(&self.rec);
                    self.spans[i] = start..self.data.len();
                }
                r
            };
        }

        // Signatures, in one batch.
        let idx: Vec<usize> = (0..lines.len()).filter(|&i| self.results[i].is_ok()).collect();
        let refs: Vec<SigRef<'_>> = idx
            .iter()
            .map(|&i| {
                let r = Record(&self.data[self.spans[i].clone()]);
                SigRef { pubkey: r.pubkey(), msg: r.id(), sig: r.sig() }
            })
            .collect();
        self.sigs.verify_batch(&refs, &mut self.ok);
        for (&i, &ok) in idx.iter().zip(&self.ok) {
            if !ok {
                self.results[i] = Err(Reject::SigInvalid);
            } else if let Some(e) = self.trailing[i] {
                self.results[i] = Err(e);
            }
        }
    }

    /// One verdict per line of the last `verify`.
    pub fn results(&self) -> &[Result<EventInfo, Reject>] {
        &self.results
    }

    /// Line i's record, after `verify` accepted it.
    pub fn record(&self, i: usize) -> &[u8] {
        &self.data[self.spans[i].clone()]
    }
}

#[inline]
fn once(seen: bool, name: &'static str) -> Result<(), Reject> {
    if seen {
        Err(Reject::DuplicateField(name))
    } else {
        Ok(())
    }
}

#[inline]
fn hex_value<const N: usize>(
    s: &mut Scanner<'_>,
    slot: &mut Option<[u8; N]>,
    name: &'static str,
    dec: fn(&[u8]) -> Option<[u8; N]>,
    err: Reject,
) -> Result<[u8; N], Reject> {
    once(slot.is_some(), name)?;
    let v = s.string()?;
    if v.escaped {
        return Err(err);
    }
    dec(v.bytes).ok_or(err)
}

#[inline]
fn write_str(v: RawStr<'_>, form: Form, out: &mut Vec<u8>) {
    match form {
        Form::Canonical => v.write_canonical(out),
        Form::Raw => out.extend_from_slice(v.bytes),
    }
}

/// Replaces the one-byte placeholder at `at` with the varint `count`.
#[inline]
fn patch_count(buf: &mut Vec<u8>, at: usize, count: u64) {
    if count < 0x80 {
        buf[at] = count as u8;
    } else {
        let mut v = Vec::with_capacity(4);
        varint::put(&mut v, count);
        buf.splice(at..at + 1, v);
    }
}

fn parse_decimal(v: RawStr<'_>) -> Option<u64> {
    if v.escaped || v.bytes.is_empty() || v.bytes.len() > 20 || !v.bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    v.bytes.iter().try_fold(0u64, |a, &d| a.checked_mul(10)?.checked_add(u64::from(d - b'0')))
}

/// sha256 of the record's NIP-01 serialisation.
pub fn compute_id(rec: Record<'_>, scratch: &mut Vec<u8>) -> [u8; 32] {
    scratch.clear();
    rec.write_id_preimage(scratch);
    sha256::digest(scratch)
}

/// BIP-340 verification of the record's signature over its id.
pub fn verify_sig(rec: Record<'_>) -> bool {
    use secp256k1::{schnorr, XOnlyPublicKey};
    let Ok(pk) = XOnlyPublicKey::from_byte_array(*rec.pubkey()) else {
        return false;
    };
    let sig = schnorr::Signature::from_byte_array(*rec.sig());
    schnorr::verify(&sig, rec.id(), &pk).is_ok()
}

/// nostr-parse's path must agree with the scanner's wherever it answers: the
/// same record, the same answer and the same end, in both forms, for events
/// alone and inside a message.
#[cfg(test)]
mod spans_agree {
    use super::*;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
            items[(self.next() % items.len() as u64) as usize]
        }
    }

    fn hex(r: &mut Rng, n: usize) -> String {
        (0..n).map(|_| char::from(b"0123456789abcdef"[(r.next() % 16) as usize])).collect()
    }

    /// JSON string contents, as written.
    fn text(r: &mut Rng) -> String {
        const PIECES: &[&str] = &[
            "plain", "é😀日本", r"\n", r#"\""#, r"\\", r"\/", r"\u0041", r"\u00e9", r"\ud83d\ude00", r"\ud83d",
            r"\udc00", r"\u007f", "\u{7f}", r"\t\b\f\r", "", "-", "expiration", "1700000000", r"\u0031700", " ",
        ];
        (0..r.next() % 4).map(|_| r.pick(PIECES)).collect()
    }

    fn tag(r: &mut Rng) -> String {
        match r.next() % 10 {
            0 => r#"["-"]"#.into(),
            1 => format!(r#"["expiration","{}"]"#, r.next() % 2_000_000_000),
            2 => r#"["expiration","\u0031700000000"]"#.into(),
            3 => format!(r#"["e","{}"]"#, hex(r, 64)),
            4 => format!(r#"["p","{}","wss://r","mention"]"#, hex(r, 64)),
            5 => "[]".into(),
            6 => format!(r#"["{}","{}","{}"]"#, text(r), text(r), text(r)),
            7 => format!(r#"[ "t" , "{}" ]"#, text(r)),
            8 => r#"["-","x"]"#.into(),
            _ => format!(r#"["{}"]"#, text(r)),
        }
    }

    fn nested(depth: usize) -> String {
        format!("{}1{}", "[".repeat(depth), "]".repeat(depth))
    }

    fn event(r: &mut Rng) -> String {
        let tags: Vec<String> = (0..r.next() % 6).map(|_| tag(r)).collect();
        let kind = r.pick(&["1", "7", "30023", "65535", "65536", "70000", "0"]);
        let sig = if r.next() % 20 == 0 { String::new() } else { hex(r, 128) };
        let mut fields = vec![
            format!(r#""id":"{}""#, hex(r, 64)),
            format!(r#""pubkey":"{}""#, hex(r, 64)),
            format!(r#""created_at":{}"#, r.next() % 2_000_000_000),
            format!(r#""kind":{kind}"#),
            format!(r#""tags":[{}]"#, tags.join(",")),
            format!(r#""content":"{}""#, text(r)),
            format!(r#""sig":"{sig}""#),
        ];
        match r.next() % 12 {
            0 => fields.push(format!(r#""extra":{}"#, nested((r.next() % 70) as usize))),
            1 => fields.push(r#""\u0069d":"x""#.into()),
            2 => fields[0] = fields[0].replacen(r#""id":""#, r#""id":"\u0030"#, 1),
            3 => fields.swap(2, 5),
            4 => fields.reverse(),
            _ => {}
        }
        let sep = r.pick(&[",", " , ", ",\n"]);
        format!("{{{}}}", fields.join(sep))
    }

    fn mutate(r: &mut Rng, s: &str) -> String {
        const ALPHABET: &[u8] = b"{}[]\",:\\ 0123456789abcdefxtnulre-.+/u";
        let mut b = s.as_bytes().to_vec();
        for _ in 0..(1 + r.next() % 3) {
            let at = (r.next() % b.len() as u64) as usize;
            let c = ALPHABET[(r.next() % ALPHABET.len() as u64) as usize];
            match r.next() % 3 {
                0 => b[at] = c,
                1 => b.insert(at, c),
                _ => {
                    b.remove(at);
                }
            }
        }
        String::from_utf8_lossy(&b).into_owned()
    }

    /// Compares the two paths on the event at byte `at` of `text`; returns
    /// whether nostr-parse's answered.
    fn agree(p: &mut EventParser, text: &str, at: usize) -> bool {
        let mut taken = false;
        for form in [Form::Canonical, Form::Raw] {
            let (mut a, mut b) = (Scanner::new_at(text, at), Scanner::new_at(text, at));
            let (mut ra, mut rb) = (Vec::new(), Vec::new());
            let fast = p.parse_spans(&mut a, &mut ra, form);
            let scanned = p.parse_scanned(&mut b, &mut rb, form);
            if let Some(info) = fast {
                assert_eq!(scanned, Ok(info), "{text}");
                assert_eq!(ra, rb, "{text}");
                assert_eq!(a.pos(), b.pos(), "{text}");
                taken = true;
            }
        }
        taken
    }

    fn agree_alone_and_inside(p: &mut EventParser, json: &str) -> bool {
        let msg = format!(r#"["EVENT", {json} ]"#);
        let alone = agree(p, json, 0);
        assert_eq!(agree(p, &msg, 10), alone, "{msg}");
        alone
    }

    #[test]
    fn on_generated_events_and_mutations() {
        let mut r = Rng(0x9E37_79B9_7F4A_7C15);
        let mut p = EventParser::new();
        let (mut events, mut taken, mut mutants, mut mutants_taken) = (0, 0, 0, 0);
        for _ in 0..20_000 {
            let json = event(&mut r);
            events += 1;
            taken += usize::from(agree_alone_and_inside(&mut p, &json));
            for _ in 0..15 {
                mutants += 1;
                mutants_taken += usize::from(agree_alone_and_inside(&mut p, &mutate(&mut r, &json)));
            }
        }
        // Most generated events are plain; the rest are the cases left to the scanner.
        assert!(taken > events / 2, "{taken} of {events} events took the fast path");
        assert!(mutants_taken > 1000, "{mutants_taken} of {mutants} mutants took it");
    }

    /// Every event of a nostrJsonBench corpus (`NOSTR_CORPUS=<dir>`): every one
    /// the scanner accepts must be read by nostr-parse, with the same record.
    #[test]
    #[ignore]
    fn on_a_corpus() {
        let dir = std::env::var("NOSTR_CORPUS").expect("NOSTR_CORPUS");
        let text = std::fs::read_to_string(format!("{dir}/all.ndjson")).unwrap();
        let mut p = EventParser::new();
        let (mut accepted, mut taken) = (0, 0);
        for line in text.lines().filter(|l| !l.is_empty()) {
            let fast = agree_alone_and_inside(&mut p, line);
            let ok = p.parse_scanned(&mut Scanner::new(line), &mut Vec::new(), Form::Canonical).is_ok();
            accepted += usize::from(ok);
            taken += usize::from(fast);
            assert!(fast || !ok, "the scanner reads it, nostr-parse left it: {line}");
        }
        println!("{accepted} events the scanner accepts, {taken} read by nostr-parse, all identical");
    }
}
