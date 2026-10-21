//! The compact binary form every stored event takes.
//!
//! ```text
//!   0  id          32
//!  32  pubkey      32
//!  64  sig         64
//! 128  created_at  u64 LE
//! 136  kind        u64 LE
//! 144  flags       u8
//! 145  [expiration u64 LE, when FLAG_EXPIRATION]
//!      varint content_len, content
//!      varint tag_count, then per tag: varint field_count, fields
//! ```
//!
//! A field is `varint header` then its payload: header `1` is a 32-byte value
//! that was 64 lowercase hex on the wire; header `len << 1` is a string of `len`
//! bytes. Strings (and content) are kept in the escaped form the id commits to,
//! so turning a record back into JSON is copying plus hex.

use crate::hex;
use crate::varint;

pub const OFF_ID: usize = 0;
pub const OFF_PUBKEY: usize = 32;
pub const OFF_SIG: usize = 64;
pub const OFF_CREATED_AT: usize = 128;
pub const OFF_KIND: usize = 136;
pub const OFF_FLAGS: usize = 144;
pub const HEADER_LEN: usize = 145;

/// An `expiration` tag was present and parsed; its value follows the header.
pub const FLAG_EXPIRATION: u8 = 1 << 0;
/// The event carries NIP-70's `["-"]` tag.
pub const FLAG_PROTECTED: u8 = 1 << 1;
/// Strings are stored exactly as received because the canonical form did not
/// hash to the id (an event signed by a serialiser with other escaping rules).
pub const FLAG_RAW_FORM: u8 = 1 << 2;
/// This relay took the event from a client and checked its signature itself
/// (not from another relay, an import or a backup's source). Trusted peers
/// may skip the check for these (see PLAN.md, trusted peers).
pub const FLAG_FIRST_HAND: u8 = 1 << 3;

/// Marks a record [`FLAG_FIRST_HAND`].
pub fn mark_first_hand(rec: &mut [u8]) {
    rec[OFF_FLAGS] |= FLAG_FIRST_HAND;
}

pub const FIELD_HEX32: u64 = 1;

/// A borrowed record. Records come from our own log behind a checksum, so the
/// accessors trust the layout; malformed bytes panic on a bounds check rather
/// than misbehave.
#[derive(Clone, Copy)]
pub struct Record<'a>(pub &'a [u8]);

impl<'a> Record<'a> {
    #[inline]
    pub fn id(&self) -> &'a [u8; 32] {
        self.0[OFF_ID..OFF_ID + 32].try_into().unwrap()
    }

    #[inline]
    pub fn pubkey(&self) -> &'a [u8; 32] {
        self.0[OFF_PUBKEY..OFF_PUBKEY + 32].try_into().unwrap()
    }

    #[inline]
    pub fn sig(&self) -> &'a [u8; 64] {
        self.0[OFF_SIG..OFF_SIG + 64].try_into().unwrap()
    }

    #[inline]
    pub fn created_at(&self) -> u64 {
        u64::from_le_bytes(self.0[OFF_CREATED_AT..OFF_CREATED_AT + 8].try_into().unwrap())
    }

    #[inline]
    pub fn kind(&self) -> u64 {
        u64::from_le_bytes(self.0[OFF_KIND..OFF_KIND + 8].try_into().unwrap())
    }

    #[inline]
    pub fn flags(&self) -> u8 {
        self.0[OFF_FLAGS]
    }

    #[inline]
    pub fn expiration(&self) -> Option<u64> {
        (self.flags() & FLAG_EXPIRATION != 0)
            .then(|| u64::from_le_bytes(self.0[HEADER_LEN..HEADER_LEN + 8].try_into().unwrap()))
    }

    #[inline]
    pub fn is_first_hand(&self) -> bool {
        self.flags() & FLAG_FIRST_HAND != 0
    }

    #[inline]
    pub fn is_protected(&self) -> bool {
        self.flags() & FLAG_PROTECTED != 0
    }

    #[inline]
    fn body_start(&self) -> usize {
        if self.flags() & FLAG_EXPIRATION != 0 {
            HEADER_LEN + 8
        } else {
            HEADER_LEN
        }
    }

    /// Content in its stored (escaped) form, and the offset where tags begin.
    #[inline]
    fn content_and_tags_pos(&self) -> (&'a [u8], usize) {
        let mut p = self.body_start();
        let len = varint::get(self.0, &mut p).expect("record content length") as usize;
        (&self.0[p..p + len], p + len)
    }

    #[inline]
    pub fn content(&self) -> &'a [u8] {
        self.content_and_tags_pos().0
    }

    pub fn tags(&self) -> Tags<'a> {
        let (_, mut p) = self.content_and_tags_pos();
        let n = varint::get(self.0, &mut p).expect("record tag count") as usize;
        Tags { buf: self.0, pos: p, left: n }
    }

    /// The first `d` tag's value, as NIP-01 addresses parameterised replaceable
    /// events. `Some(b"")` for a bare `["d"]`; `None` when there is no `d` tag.
    pub fn d_tag(&self) -> Option<Field<'a>> {
        for tag in self.tags() {
            let mut f = tag.fields();
            if f.next().is_some_and(|n| n.is_str(b"d")) {
                return Some(f.next().unwrap_or(Field::Str(b"")));
            }
        }
        None
    }

    /// Writes the event as wire JSON. Keys are alphabetical, the order strfry
    /// stores and exports, so an imported strfry export re-exports byte for byte.
    pub fn write_json(&self, out: &mut Vec<u8>) {
        let (content, _) = self.content_and_tags_pos();
        out.reserve(self.0.len() * 2 + 64);
        out.extend_from_slice(b"{\"content\":\"");
        out.extend_from_slice(content);
        out.extend_from_slice(b"\",\"created_at\":");
        push_u64(out, self.created_at());
        out.extend_from_slice(b",\"id\":\"");
        hex::encode_into(self.id(), out);
        out.extend_from_slice(b"\",\"kind\":");
        push_u64(out, self.kind());
        out.extend_from_slice(b",\"pubkey\":\"");
        hex::encode_into(self.pubkey(), out);
        out.extend_from_slice(b"\",\"sig\":\"");
        hex::encode_into(self.sig(), out);
        out.extend_from_slice(b"\",\"tags\":");
        self.write_tags_json(out);
        out.push(b'}');
    }

    /// Length of [`write_json`](Self::write_json)'s output, without writing it
    /// (event size limits are measured on the serialised event).
    pub fn json_len(&self) -> usize {
        let (content, _) = self.content_and_tags_pos();
        let digits = |v: u64| if v == 0 { 1 } else { v.ilog10() as usize + 1 };
        let mut n = r#"{"content":"","created_at":,"id":"","kind":,"pubkey":"","sig":"","tags":[]}"#.len();
        n += content.len() + digits(self.created_at()) + digits(self.kind()) + 64 + 64 + 128;
        for (i, tag) in self.tags().enumerate() {
            n += usize::from(i > 0) + 2;
            for (j, f) in tag.fields().enumerate() {
                n += usize::from(j > 0) + 2 + match f {
                    Field::Hex32(_) => 64,
                    Field::Str(s) => s.len(),
                };
            }
        }
        n
    }

    pub fn to_json(&self) -> String {
        let mut out = Vec::new();
        self.write_json(&mut out);
        // Every piece is either ASCII we wrote or a string that was valid UTF-8 on the way in.
        String::from_utf8(out).expect("record JSON is UTF-8")
    }

    fn write_tags_json(&self, out: &mut Vec<u8>) {
        // One pass over the encoded tags: `tags()` would walk each tag twice,
        // once to find where it ends and once for its fields.
        let b = self.0;
        let (_, mut p) = self.content_and_tags_pos();
        let tags = varint::get(b, &mut p).expect("record tag count");
        out.push(b'[');
        for i in 0..tags {
            if i > 0 {
                out.push(b',');
            }
            out.push(b'[');
            let fields = varint::get(b, &mut p).expect("record field count");
            for j in 0..fields {
                if j > 0 {
                    out.push(b',');
                }
                out.push(b'"');
                let h = varint::get(b, &mut p).expect("record field header");
                if h == FIELD_HEX32 {
                    hex::encode_into(&b[p..p + 32], out);
                    p += 32;
                } else {
                    // Stored as it is written: escaped JSON string content.
                    let n = (h >> 1) as usize;
                    out.extend_from_slice(&b[p..p + n]);
                    p += n;
                }
                out.push(b'"');
            }
            out.push(b']');
        }
        out.push(b']');
    }

    /// The NIP-01 serialisation `[0,pubkey,created_at,kind,tags,content]` whose
    /// sha256 is the event id.
    pub fn write_id_preimage(&self, out: &mut Vec<u8>) {
        let (content, _) = self.content_and_tags_pos();
        out.reserve(self.0.len() * 2);
        out.extend_from_slice(b"[0,\"");
        hex::encode_into(self.pubkey(), out);
        out.extend_from_slice(b"\",");
        push_u64(out, self.created_at());
        out.push(b',');
        push_u64(out, self.kind());
        out.push(b',');
        self.write_tags_json(out);
        out.extend_from_slice(b",\"");
        out.extend_from_slice(content);
        out.extend_from_slice(b"\"]");
    }
}

pub struct Tags<'a> {
    buf: &'a [u8],
    pos: usize,
    left: usize,
}

impl<'a> Iterator for Tags<'a> {
    type Item = Tag<'a>;

    #[inline]
    fn next(&mut self) -> Option<Tag<'a>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let n = varint::get(self.buf, &mut self.pos).expect("record field count") as usize;
        let start = self.pos;
        for _ in 0..n {
            skip_field(self.buf, &mut self.pos);
        }
        Some(Tag { buf: &self.buf[start..self.pos], count: n })
    }
}

#[inline]
fn skip_field(buf: &[u8], pos: &mut usize) {
    let h = varint::get(buf, pos).expect("record field header");
    *pos += if h == FIELD_HEX32 { 32 } else { (h >> 1) as usize };
}

#[derive(Clone, Copy)]
pub struct Tag<'a> {
    buf: &'a [u8],
    count: usize,
}

impl<'a> Tag<'a> {
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    #[inline]
    pub fn fields(&self) -> Fields<'a> {
        Fields { buf: self.buf, pos: 0, left: self.count }
    }

    /// For a tag that starts with a one-byte name (`e`, `p`, `t`, ...): the name
    /// and the encoded bytes of its value, the form index keys and filters use.
    #[inline]
    pub fn indexable(&self) -> Option<(u8, &'a [u8])> {
        if self.count < 2 {
            return None;
        }
        // A one-byte string field is the header 0x02 followed by the byte.
        if self.buf.len() < 2 || self.buf[0] != 2 {
            return None;
        }
        let name = self.buf[1];
        let mut p = 2;
        skip_field(self.buf, &mut p);
        Some((name, &self.buf[2..p]))
    }
}

pub struct Fields<'a> {
    buf: &'a [u8],
    pos: usize,
    left: usize,
}

impl<'a> Iterator for Fields<'a> {
    type Item = Field<'a>;

    #[inline]
    fn next(&mut self) -> Option<Field<'a>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let h = varint::get(self.buf, &mut self.pos).expect("record field header");
        let p = self.pos;
        if h == FIELD_HEX32 {
            self.pos += 32;
            Some(Field::Hex32(self.buf[p..p + 32].try_into().unwrap()))
        } else {
            self.pos += (h >> 1) as usize;
            Some(Field::Str(&self.buf[p..self.pos]))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field<'a> {
    /// 64 lowercase hex on the wire.
    Hex32(&'a [u8; 32]),
    /// A string in stored (escaped) form.
    Str(&'a [u8]),
}

impl<'a> Field<'a> {
    #[inline]
    pub fn is_str(&self, s: &[u8]) -> bool {
        matches!(self, Field::Str(b) if *b == s)
    }

    /// The field as it appears between the quotes in JSON.
    #[inline]
    pub fn write_str(&self, out: &mut Vec<u8>) {
        match self {
            Field::Hex32(b) => hex::encode_into(*b, out),
            Field::Str(s) => out.extend_from_slice(s),
        }
    }

    /// Encoded form: header plus payload, as stored in records and index keys.
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Field::Hex32(b) => {
                out.push(FIELD_HEX32 as u8);
                out.extend_from_slice(*b);
            }
            Field::Str(s) => {
                varint::put(out, (s.len() as u64) << 1);
                out.extend_from_slice(s);
            }
        }
    }
}

/// Encodes one tag field from its stored-form string bytes, compacting 64
/// lowercase hex to 32 bytes.
#[inline]
pub fn encode_field_str(stored: &[u8], out: &mut Vec<u8>) {
    if let Some(raw) = (stored.len() == 64).then(|| hex::decode_32(stored)).flatten() {
        out.push(FIELD_HEX32 as u8);
        out.extend_from_slice(&raw);
    } else {
        varint::put(out, (stored.len() as u64) << 1);
        out.extend_from_slice(stored);
    }
}

/// Decimal digits of `v`, appended.
#[inline]
pub fn push_u64(out: &mut Vec<u8>, mut v: u64) {
    // Two digits a step: every event sent writes a ten-digit timestamp.
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while v >= 100 {
        let d = (v % 100) as usize * 2;
        v /= 100;
        i -= 2;
        buf[i..i + 2].copy_from_slice(&DIGIT_PAIRS[d..d + 2]);
    }
    if v >= 10 {
        let d = v as usize * 2;
        i -= 2;
        buf[i..i + 2].copy_from_slice(&DIGIT_PAIRS[d..d + 2]);
    } else {
        i -= 1;
        buf[i] = b'0' + v as u8;
    }
    out.extend_from_slice(&buf[i..]);
}

/// "00", "01", ... "99", back to back.
static DIGIT_PAIRS: [u8; 200] = {
    let mut t = [0u8; 200];
    let mut i = 0;
    while i < 100 {
        t[i * 2] = b'0' + (i / 10) as u8;
        t[i * 2 + 1] = b'0' + (i % 10) as u8;
        i += 1;
    }
    t
};

#[cfg(test)]
mod tests {
    use super::push_u64;

    #[test]
    fn integers_print_as_rust_prints_them() {
        let check = |v: u64| {
            let mut out = b"x".to_vec();
            push_u64(&mut out, v);
            assert_eq!(&out[1..], v.to_string().as_bytes(), "{v}");
        };
        for v in 0..20_000u64 {
            check(v);
        }
        for p in 0..20 {
            let t = 10u64.pow(p);
            for v in [t - 1, t, t + 1, t.saturating_mul(9).saturating_add(9)] {
                check(v);
            }
        }
        for v in [1_792_000_000u64, u64::MAX, u64::MAX - 1, u32::MAX as u64] {
            check(v);
        }
    }
}
