//! NIP-01 filters: parsing and matching against records.

use crate::json::{self, Scanner};
use crate::record::{self, Record};
use crate::hex;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterError {
    Json(json::Error),
    UnknownKey,
    BadId,
    BadAuthor,
    BadTagName,
    Duplicate,
    Unsupported(&'static str),
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterError::Json(e) => write!(f, "bad filter: {e}"),
            FilterError::UnknownKey => f.write_str("bad filter: unknown key"),
            FilterError::BadId => f.write_str("bad filter: ids must be 64 lowercase hex"),
            FilterError::BadAuthor => f.write_str("bad filter: authors must be 64 lowercase hex"),
            FilterError::BadTagName => f.write_str("bad filter: tag filters must be #<single letter>"),
            FilterError::Duplicate => f.write_str("bad filter: duplicate key"),
            FilterError::Unsupported(what) => write!(f, "unsupported filter: {what}"),
        }
    }
}

impl From<json::Error> for FilterError {
    fn from(e: json::Error) -> Self {
        FilterError::Json(e)
    }
}

/// One `#x` condition: the event needs an `x` tag whose value is one of `values`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagFilter {
    pub name: u8,
    /// Encoded field bytes (the record/index form), sorted and deduplicated.
    pub values: Vec<Box<[u8]>>,
}

/// A parsed filter. A list that is present but empty matches nothing, as in strfry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub ids: Option<Vec<[u8; 32]>>,
    pub authors: Option<Vec<[u8; 32]>>,
    pub kinds: Option<Vec<u64>>,
    /// Sorted by tag name.
    pub tags: Vec<TagFilter>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<u64>,
}

impl Filter {
    pub fn parse(s: &mut Scanner<'_>) -> Result<Filter, FilterError> {
        let mut f = Filter::default();
        let mut field = Vec::new();
        s.object(|s, key| -> Result<(), FilterError> {
            if key.escaped {
                return Err(FilterError::UnknownKey);
            }
            match key.bytes {
                b"ids" => {
                    dup(f.ids.is_some())?;
                    f.ids = Some(hex_list(s, FilterError::BadId)?);
                }
                b"authors" => {
                    dup(f.authors.is_some())?;
                    f.authors = Some(hex_list(s, FilterError::BadAuthor)?);
                }
                b"kinds" => {
                    dup(f.kinds.is_some())?;
                    let mut v = Vec::new();
                    s.array(|s| -> Result<(), FilterError> {
                        v.push(s.u64()?);
                        Ok(())
                    })?;
                    v.sort_unstable();
                    v.dedup();
                    f.kinds = Some(v);
                }
                b"since" => {
                    dup(f.since.is_some())?;
                    f.since = Some(s.u64()?);
                }
                b"until" => {
                    dup(f.until.is_some())?;
                    f.until = Some(s.u64()?);
                }
                b"limit" => {
                    dup(f.limit.is_some())?;
                    f.limit = Some(s.u64()?);
                }
                b"search" => return Err(FilterError::Unsupported("search")),
                [b'#', name] if name.is_ascii_alphabetic() => {
                    dup(f.tags.iter().any(|t| t.name == *name))?;
                    let mut values: Vec<Box<[u8]>> = Vec::new();
                    s.array(|s| -> Result<(), FilterError> {
                        let v = s.string()?;
                        field.clear();
                        v.write_canonical(&mut field);
                        let mut enc = Vec::with_capacity(field.len() + 2);
                        record::encode_field_str(&field, &mut enc);
                        values.push(enc.into_boxed_slice());
                        Ok(())
                    })?;
                    values.sort_unstable();
                    values.dedup();
                    f.tags.push(TagFilter { name: *name, values });
                }
                [b'#', ..] => return Err(FilterError::BadTagName),
                _ => return Err(FilterError::UnknownKey),
            }
            Ok(())
        })?;
        f.tags.sort_unstable_by_key(|t| t.name);
        Ok(f)
    }

    /// True when some present list is empty, or the time window is inverted.
    pub fn never_matches(&self) -> bool {
        self.ids.as_ref().is_some_and(Vec::is_empty)
            || self.authors.as_ref().is_some_and(Vec::is_empty)
            || self.kinds.as_ref().is_some_and(Vec::is_empty)
            || self.tags.iter().any(|t| t.values.is_empty())
            || matches!((self.since, self.until), (Some(s), Some(u)) if s > u)
    }

    /// Full match of a stored event against this filter.
    #[inline]
    pub fn matches(&self, rec: Record<'_>) -> bool {
        if let Some(kinds) = &self.kinds {
            if kinds.binary_search(&rec.kind()).is_err() {
                return false;
            }
        }
        let t = rec.created_at();
        if self.since.is_some_and(|s| t < s) || self.until.is_some_and(|u| t > u) {
            return false;
        }
        if let Some(ids) = &self.ids {
            if ids.binary_search(rec.id()).is_err() {
                return false;
            }
        }
        if let Some(authors) = &self.authors {
            if authors.binary_search(rec.pubkey()).is_err() {
                return false;
            }
        }
        self.tags.iter().all(|tf| {
            rec.tags().any(|tag| match tag.indexable() {
                Some((name, value)) => name == tf.name && tf.values.binary_search_by(|v| (**v).cmp(value)).is_ok(),
                None => false,
            })
        })
    }

    /// Writes the filter back as JSON, normalised (used for logs and NIP-77 keys).
    pub fn write_json(&self, out: &mut Vec<u8>) {
        out.push(b'{');
        let mut first = true;
        let mut key = |out: &mut Vec<u8>, k: &[u8]| {
            if !std::mem::take(&mut first) {
                out.push(b',');
            }
            out.push(b'"');
            out.extend_from_slice(k);
            out.extend_from_slice(b"\":");
        };
        let hexes = |out: &mut Vec<u8>, v: &[[u8; 32]]| {
            out.push(b'[');
            for (i, h) in v.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.push(b'"');
                hex::encode_into(h, out);
                out.push(b'"');
            }
            out.push(b']');
        };
        if let Some(ids) = &self.ids {
            key(out, b"ids");
            hexes(out, ids);
        }
        if let Some(a) = &self.authors {
            key(out, b"authors");
            hexes(out, a);
        }
        if let Some(k) = &self.kinds {
            key(out, b"kinds");
            out.push(b'[');
            for (i, n) in k.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                record::push_u64(out, *n);
            }
            out.push(b']');
        }
        for t in &self.tags {
            key(out, &[b'#', t.name]);
            out.push(b'[');
            for (i, v) in t.values.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.push(b'"');
                let mut p = 0;
                // Decode the encoded field back to its JSON string form.
                let h = crate::varint::get(v, &mut p).unwrap_or(0);
                if h == record::FIELD_HEX32 {
                    hex::encode_into(&v[p..], out);
                } else {
                    out.extend_from_slice(&v[p..]);
                }
                out.push(b'"');
            }
            out.push(b']');
        }
        for (k, v) in [(&b"since"[..], self.since), (b"until", self.until), (b"limit", self.limit)] {
            if let Some(v) = v {
                key(out, k);
                record::push_u64(out, v);
            }
        }
        out.push(b'}');
    }
}

#[inline]
fn dup(seen: bool) -> Result<(), FilterError> {
    if seen {
        Err(FilterError::Duplicate)
    } else {
        Ok(())
    }
}

fn hex_list(s: &mut Scanner<'_>, err: FilterError) -> Result<Vec<[u8; 32]>, FilterError> {
    let mut v = Vec::new();
    s.array(|s| -> Result<(), FilterError> {
        let h = s.string()?;
        if h.escaped {
            return Err(err);
        }
        v.push(hex::decode_32(h.bytes).ok_or(err)?);
        Ok(())
    })?;
    v.sort_unstable();
    v.dedup();
    Ok(v)
}
