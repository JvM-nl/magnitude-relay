//! The little DER (ITU-T X.690) this crate needs: builders for the CSR and the
//! TLS-ALPN-01 certificate, and a reader to pull a certificate apart.
//!
//! Only definite lengths and single-byte tags: that is all X.509 uses.

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const UTF8_STRING: u8 = 0x0C;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// Context-specific, constructed: `[n] EXPLICIT` and `[n] IMPLICIT` of a constructed type.
pub const fn context(n: u8) -> u8 {
    0xA0 | n
}

/// Context-specific, primitive: `[n] IMPLICIT` of a primitive type (a GeneralName).
pub const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

// ---------------------------------------------------------------------------
// Writing.

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// One tag-length-value.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    push_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// A SEQUENCE of the already-encoded `parts`, in order.
pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// A SET of the already-encoded `parts`. Callers give at most one part, so DER's
/// ordering rule for sets never comes up.
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SET, &parts.concat())
}

/// `[n] EXPLICIT`: the encoded value wrapped in a context tag.
pub fn explicit(n: u8, inner: &[u8]) -> Vec<u8> {
    tlv(context(n), inner)
}

pub fn boolean(v: bool) -> Vec<u8> {
    tlv(BOOLEAN, &[if v { 0xFF } else { 0x00 }])
}

/// A non-negative INTEGER from big-endian magnitude bytes (leading zeros dropped,
/// one added back when the top bit would otherwise read as a sign).
pub fn integer(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude.iter().take_while(|&&b| b == 0).count();
    let m = &magnitude[skip..];
    let mut content = Vec::with_capacity(m.len() + 1);
    if m.first().is_none_or(|&b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(m);
    tlv(INTEGER, &content)
}

pub fn integer_u64(v: u64) -> Vec<u8> {
    integer(&v.to_be_bytes())
}

pub fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, content)
}

/// A BIT STRING of whole bytes (no unused bits).
pub fn bit_string(content: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(content.len() + 1);
    c.push(0);
    c.extend_from_slice(content);
    tlv(BIT_STRING, &c)
}

pub fn utf8_string(s: &str) -> Vec<u8> {
    tlv(UTF8_STRING, s.as_bytes())
}

/// An OBJECT IDENTIFIER from its dotted form, like `"1.2.840.10045.2.1"`.
///
/// Panics on a malformed constant: every caller passes a literal.
pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|a| a.parse().expect("OID arcs are numbers")).collect();
    assert!(arcs.len() >= 2 && arcs[0] <= 2 && (arcs[0] == 2 || arcs[1] < 40), "OID {dotted}");
    let mut content = Vec::new();
    for &arc in std::iter::once(&(arcs[0] * 40 + arcs[1])).chain(&arcs[2..]) {
        let mut groups = vec![(arc & 0x7F) as u8];
        let mut rest = arc >> 7;
        while rest > 0 {
            groups.push(0x80 | (rest & 0x7F) as u8);
            rest >>= 7;
        }
        groups.reverse();
        content.extend_from_slice(&groups);
    }
    tlv(OID, &content)
}

/// A certificate validity time: UTCTime through 2049, GeneralizedTime after (RFC 5280 §4.1.2.5).
pub fn time(unix: i64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = crate::time::civil(unix);
    if (1950..2050).contains(&y) {
        tlv(UTC_TIME, format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100).as_bytes())
    } else {
        tlv(GENERALIZED_TIME, format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z").as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Reading.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerError(pub &'static str);

impl std::fmt::Display for DerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed DER: {}", self.0)
    }
}

impl std::error::Error for DerError {}

/// One element: its tag, its contents, and its whole encoding (header included, which
/// is what a signature covers).
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// The elements inside a constructed value.
    pub fn children(&self) -> Reader<'a> {
        Reader::new(self.content)
    }

    /// This element, checked to have `tag`.
    pub fn expect(self, tag: u8) -> Result<Tlv<'a>, DerError> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(DerError("unexpected element"))
        }
    }
}

/// Walks consecutive elements of a buffer.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The tag of the next element, without consuming it.
    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    // Not an Iterator: each element can fail to parse, and the caller wants to know why.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Tlv<'a>, DerError> {
        let b = self.buf;
        let [tag, first, rest @ ..] = b else { return Err(DerError("truncated header")) };
        if tag & 0x1F == 0x1F {
            return Err(DerError("multi-byte tags are not used here"));
        }
        let (len, header) = if first & 0x80 == 0 {
            (usize::from(*first), 2)
        } else {
            let n = usize::from(first & 0x7F);
            if n == 0 || n > 4 || rest.len() < n {
                return Err(DerError("bad length"));
            }
            (rest[..n].iter().fold(0usize, |a, &x| (a << 8) | usize::from(x)), 2 + n)
        };
        let end = header.checked_add(len).filter(|&e| e <= b.len()).ok_or(DerError("element runs past its parent"))?;
        self.buf = &b[end..];
        Ok(Tlv { tag: *tag, content: &b[header..end], raw: &b[..end] })
    }

    /// The next element, which must have `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, DerError> {
        self.next()?.expect(tag)
    }

    /// The next element if it has `tag`.
    pub fn take_if(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, DerError> {
        if self.peek_tag() == Some(tag) {
            self.next().map(Some)
        } else {
            Ok(None)
        }
    }
}

/// An INTEGER's magnitude with the sign-padding zero removed.
pub fn integer_magnitude(t: &Tlv<'_>) -> Vec<u8> {
    let skip = t.content.iter().take_while(|&&b| b == 0).count();
    t.content[skip..].to_vec()
}

/// The dotted form of an OBJECT IDENTIFIER's contents.
pub fn oid_to_string(content: &[u8]) -> Result<String, DerError> {
    let mut out = String::new();
    let mut arc = 0u64;
    let mut first = true;
    for &b in content {
        arc = arc.checked_mul(128).ok_or(DerError("OID arc too large"))? | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            if first {
                let (a, rest) = if arc < 80 { (arc / 40, arc % 40) } else { (2, arc - 80) };
                out.push_str(&format!("{a}.{rest}"));
                first = false;
            } else {
                out.push_str(&format!(".{arc}"));
            }
            arc = 0;
        }
    }
    if first || content.last().is_some_and(|b| b & 0x80 != 0) {
        return Err(DerError("truncated OID"));
    }
    Ok(out)
}

/// Seconds since the Unix epoch for a UTCTime or GeneralizedTime (`Z` times only,
/// which DER requires).
pub fn parse_time(t: &Tlv<'_>) -> Result<i64, DerError> {
    let s = std::str::from_utf8(t.content).map_err(|_| DerError("time is not ASCII"))?;
    let digits = |r: std::ops::Range<usize>| -> Result<i64, DerError> {
        s.get(r).filter(|d| d.bytes().all(|b| b.is_ascii_digit())).and_then(|d| d.parse().ok()).ok_or(DerError("bad time"))
    };
    let (year, rest) = match t.tag {
        UTC_TIME if s.len() == 13 => {
            let yy = digits(0..2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        GENERALIZED_TIME if s.len() == 15 => (digits(0..4)?, 4),
        _ => return Err(DerError("unsupported time form")),
    };
    if !s.ends_with('Z') {
        return Err(DerError("time is not UTC"));
    }
    let (mo, d, h, mi, sec) = (
        digits(rest..rest + 2)?,
        digits(rest + 2..rest + 4)?,
        digits(rest + 4..rest + 6)?,
        digits(rest + 6..rest + 8)?,
        digits(rest + 8..rest + 10)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return Err(DerError("time out of range"));
    }
    Ok(crate::time::days_from_civil(year, mo, d) * 86_400 + h * 3600 + mi * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_use_the_shortest_form() {
        assert_eq!(tlv(OCTET_STRING, &[]), [0x04, 0x00]);
        assert_eq!(&tlv(OCTET_STRING, &[7; 127])[..2], [0x04, 127]);
        assert_eq!(&tlv(OCTET_STRING, &[7; 128])[..3], [0x04, 0x81, 128]);
        assert_eq!(&tlv(OCTET_STRING, &[7; 255])[..3], [0x04, 0x81, 255]);
        assert_eq!(&tlv(OCTET_STRING, &[7; 256])[..4], [0x04, 0x82, 1, 0]);
        assert_eq!(&tlv(OCTET_STRING, &vec![7; 70_000])[..5], [0x04, 0x83, 1, 0x11, 0x70]);
    }

    #[test]
    fn integers_are_minimal_and_positive() {
        assert_eq!(integer(&[]), [2, 1, 0]);
        assert_eq!(integer(&[0, 0, 0]), [2, 1, 0]);
        assert_eq!(integer(&[1]), [2, 1, 1]);
        assert_eq!(integer(&[0x7F]), [2, 1, 0x7F]);
        assert_eq!(integer(&[0x80]), [2, 2, 0, 0x80]);
        assert_eq!(integer(&[0, 0, 0xFF, 0x01]), [2, 3, 0, 0xFF, 0x01]);
        assert_eq!(integer_u64(256), [2, 2, 1, 0]);
    }

    #[test]
    fn oids_match_known_encodings() {
        // From RFC 5480 and RFC 5280 as they appear in real certificates.
        assert_eq!(oid("1.2.840.10045.2.1"), [6, 7, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 2, 1]);
        assert_eq!(oid("1.2.840.10045.3.1.7"), [6, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 3, 1, 7]);
        assert_eq!(oid("1.2.840.10045.4.3.2"), [6, 8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 4, 3, 2]);
        assert_eq!(oid("2.5.4.3"), [6, 3, 0x55, 4, 3]);
        assert_eq!(oid("2.5.29.17"), [6, 3, 0x55, 0x1D, 0x11]);
        assert_eq!(oid("1.3.6.1.5.5.7.1.31"), [6, 8, 0x2B, 6, 1, 5, 5, 7, 1, 0x1F]);
        assert_eq!(oid("1.2.840.113549.1.9.14"), [6, 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 9, 0x0E]);
        // An arc of 2.x may exceed 39.
        assert_eq!(oid("2.100.3"), [6, 3, 0x81, 0x34, 3]);
    }

    #[test]
    fn oid_round_trips_through_text() {
        for s in ["1.2.840.10045.2.1", "2.5.29.17", "1.3.6.1.5.5.7.1.31", "2.100.3", "1.2.840.113549.1.9.14"] {
            let e = oid(s);
            assert_eq!(oid_to_string(&e[2..]).unwrap(), s);
        }
        assert!(oid_to_string(&[]).is_err());
        assert!(oid_to_string(&[0x2A, 0x86]).is_err());
    }

    #[test]
    fn times() {
        // 2026-10-21 12:34:56 UTC.
        let t = 1_792_586_096;
        assert_eq!(time(t), [UTC_TIME, 13, b'2', b'6', b'1', b'0', b'2', b'1', b'1', b'2', b'3', b'4', b'5', b'6', b'Z']);
        // 2050 and later, and before 1950, use GeneralizedTime.
        let far = time(2_524_608_000);
        assert_eq!(far[0], GENERALIZED_TIME);
        assert_eq!(&far[2..], b"20500101000000Z");
        for t in [0, 1, 946_684_799, 1_792_586_096, 2_524_607_999, 2_524_608_000, 4_102_444_800, -86_400 * 365 * 30] {
            let e = time(t);
            assert_eq!(parse_time(&Reader::new(&e).next().unwrap()).unwrap(), t, "{t}");
        }
    }

    #[test]
    fn parse_time_rejects_junk() {
        for bad in [&b"2610211234Z"[..], b"261021123456", b"261301123456Z", b"2610211234567Z", b"26102112345xZ", b"261021243456Z"] {
            let e = tlv(UTC_TIME, bad);
            assert!(parse_time(&Reader::new(&e).next().unwrap()).is_err(), "{:?}", String::from_utf8_lossy(bad));
        }
        let e = tlv(GENERALIZED_TIME, b"20261021123456+0100");
        assert!(parse_time(&Reader::new(&e).next().unwrap()).is_err());
    }

    #[test]
    fn reader_walks_nested_values() {
        let inner = sequence(&[&integer_u64(5), &utf8_string("hi")]);
        let outer = sequence(&[&inner, &boolean(true), &octet_string(b"xyz")]);
        let mut r = Reader::new(&outer);
        let top = r.expect(SEQUENCE).unwrap();
        assert!(r.is_empty());
        let mut c = top.children();
        let mut i = c.expect(SEQUENCE).unwrap().children();
        assert_eq!(integer_magnitude(&i.expect(INTEGER).unwrap()), [5]);
        assert_eq!(i.expect(UTF8_STRING).unwrap().content, b"hi");
        assert_eq!(c.expect(BOOLEAN).unwrap().content, [0xFF]);
        let last = c.next().unwrap();
        assert_eq!((last.tag, last.content, last.raw), (OCTET_STRING, &b"xyz"[..], &[4, 3, b'x', b'y', b'z'][..]));
        assert!(c.is_empty());
        assert!(c.next().is_err());
    }

    #[test]
    fn reader_rejects_malformed_input() {
        assert!(Reader::new(&[]).next().is_err());
        assert!(Reader::new(&[0x30]).next().is_err());
        assert!(Reader::new(&[0x30, 0x05, 1, 2]).next().is_err(), "length past the end");
        assert!(Reader::new(&[0x30, 0x80, 0, 0]).next().is_err(), "indefinite length");
        assert!(Reader::new(&[0x30, 0x85, 0, 0, 0, 0, 1, 0]).next().is_err(), "length of length");
        assert!(Reader::new(&[0x1F, 0x01, 0x00]).next().is_err(), "multi-byte tag");
        assert!(Reader::new(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]).next().is_err(), "huge length does not overflow");
        assert!(Reader::new(&[0x04, 0x00]).expect(SEQUENCE).is_err());
    }

    #[test]
    fn take_if_only_consumes_a_match() {
        let e = [integer_u64(1), utf8_string("a")].concat();
        let mut r = Reader::new(&e);
        assert!(r.take_if(UTF8_STRING).unwrap().is_none());
        assert!(r.take_if(INTEGER).unwrap().is_some());
        assert!(r.take_if(INTEGER).unwrap().is_none());
        assert_eq!(r.next().unwrap().tag, UTF8_STRING);
    }
}
