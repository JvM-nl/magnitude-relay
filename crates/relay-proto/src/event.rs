//! Turning wire JSON into a verified record.
//!
//! One pass over the JSON writes the record directly; the id is then the
//! sha256 of a serialisation generated *from the record*. That makes the stored
//! form self-proving: whatever we keep re-serialises to bytes that hash to the id.

use crate::json::{self, RawStr, Scanner};
use crate::record::{self, Record, FLAG_EXPIRATION, FLAG_PROTECTED, FLAG_RAW_FORM, HEADER_LEN};
use crate::{hex, sha256, varint};
use std::fmt;

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
    content: Vec<u8>,
    tags: Vec<u8>,
    field: Vec<u8>,
    preimage: Vec<u8>,
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
                        if let Some(name) = first {
                            if fields == 1 && name.is(b"-") {
                                protected = true;
                            } else if expiration.is_none() && name.is(b"expiration") {
                                expiration = second.and_then(parse_decimal);
                            }
                        }
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

        out.clear();
        out.reserve(HEADER_LEN + 8 + 20 + self.content.len() + self.tags.len());
        out.extend_from_slice(&id);
        out.extend_from_slice(&pubkey);
        out.extend_from_slice(&sig);
        out.extend_from_slice(&created_at.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        let mut flags = 0u8;
        if expiration.is_some() {
            flags |= FLAG_EXPIRATION;
        }
        if protected {
            flags |= FLAG_PROTECTED;
        }
        out.push(flags);
        if let Some(e) = expiration {
            out.extend_from_slice(&e.to_le_bytes());
        }
        varint::put(out, self.content.len() as u64);
        out.extend_from_slice(&self.content);
        varint::put(out, u64::from(tag_count));
        out.extend_from_slice(&self.tags);

        Ok(EventInfo {
            kind,
            created_at,
            tag_count,
            content_len: self.content.len() as u32,
            expiration,
            protected,
            any_escaped,
        })
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
