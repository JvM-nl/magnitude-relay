//! Index keys. Every index lives in one sorted keyspace, told apart by a type byte.
//!
//! Scan keys end in `created_at(8 BE) ‖ seq(8 BE)`, so a prefix's entries sit
//! together, newest last, and a newest-first walk is a backwards range scan.
//! Every variable-length part is self-delimiting (an encoded tag field carries its
//! own length), so no prefix is ever a prefix of another prefix's keys.
//!
//! ```text
//! ID            01 ‖ id(32) ‖ seq
//! CREATED       02 ‖ created_at ‖ seq
//! KIND          03 ‖ kind(8) ‖ created_at ‖ seq
//! AUTHOR        04 ‖ pubkey(32) ‖ created_at ‖ seq
//! AUTHOR_KIND   05 ‖ pubkey ‖ kind ‖ created_at ‖ seq
//! TAG           06 ‖ name(1) ‖ field ‖ created_at ‖ seq
//! TAG_KIND      07 ‖ name ‖ field ‖ kind ‖ created_at ‖ seq
//! ADDR          08 ‖ pubkey ‖ kind ‖ d-field ‖ created_at ‖ seq
//! EXPIRY        09 ‖ expiration ‖ seq
//! DELETED       0A ‖ target id ‖ deleter pubkey          (kind-5 `e` tombstone, permanent)
//! ADDR_DELETED  0B ‖ pubkey ‖ kind ‖ d-field ‖ created_at (kind-5 `a` tombstone, permanent)
//! VANISH        0C ‖ pubkey ‖ created_at                  (NIP-62 tombstone, permanent)
//! NEG           0D ‖ name ‖ field ‖ kind ‖ created_at ‖ id ‖ expiration ‖ seq   (NIP-77 covering)
//! ```
//!
//! NEG keys carry the event id itself, so a negentropy set for Vector's DM sync
//! shape (`kinds:[1059] #p:[me]`) is read from index blocks alone: no event is
//! touched, which is what keeps a large mailbox sync fast on a machine whose
//! log does not fit in RAM. The expiration (0 for none) rides along so an
//! expired wrap is left out exactly, without waiting for the sweep.

use relay_proto::record::{Field, Record};
use relay_proto::{hex, kind, varint};

pub const T_ID: u8 = 0x01;
pub const T_CREATED: u8 = 0x02;
pub const T_KIND: u8 = 0x03;
pub const T_AUTHOR: u8 = 0x04;
pub const T_AUTHOR_KIND: u8 = 0x05;
pub const T_TAG: u8 = 0x06;
pub const T_TAG_KIND: u8 = 0x07;
pub const T_ADDR: u8 = 0x08;
pub const T_EXPIRY: u8 = 0x09;
pub const T_DELETED: u8 = 0x0A;
pub const T_ADDR_DELETED: u8 = 0x0B;
pub const T_VANISH: u8 = 0x0C;
pub const T_NEG: u8 = 0x0D;

/// Kinds whose `p` tags get covering NEG keys: Vector's only NIP-77 shape.
pub const NEG_KINDS: &[u64] = &[1059];

/// Tag values longer than this (stored form) are not indexed, as in strfry.
pub const MAX_INDEXED_VALUE: usize = 256;

/// The encoded empty string: the `d` of a plain replaceable event.
pub const EMPTY_FIELD: [u8; 1] = [0];

/// Key types whose last 8 bytes are the seq of the event they index.
#[inline]
pub fn has_seq(key: &[u8]) -> bool {
    key.first().is_some_and(|&t| t <= T_EXPIRY || t == T_NEG)
}

/// The part of a key that queries name exactly, and so what bloom filters are
/// keyed on: everything but the trailing `created_at ‖ seq` of scan keys; the id
/// of an id key; the whole key of a tombstone (looked up exactly); the address
/// of an address or vanish tombstone (its trailing time is a value, not a name).
/// Every prefix the planner and writer look up is one of these.
#[inline]
pub fn bloom_prefix(key: &[u8]) -> &[u8] {
    let n = key.len();
    match key.first() {
        Some(&T_ID) => &key[..n.min(33)],
        Some(&T_CREATED | &T_EXPIRY) => &key[..n.min(1)],
        Some(&T_KIND | &T_AUTHOR | &T_AUTHOR_KIND | &T_TAG | &T_TAG_KIND | &T_ADDR) => &key[..n.saturating_sub(16)],
        Some(&T_ADDR_DELETED | &T_VANISH) => &key[..n.saturating_sub(8)],
        Some(&T_NEG) => &key[..n.saturating_sub(56)],
        _ => key,
    }
}

#[inline]
pub fn seq_of(key: &[u8]) -> u64 {
    u64::from_be_bytes(key[key.len() - 8..].try_into().unwrap())
}

#[inline]
pub fn created_at_of(key: &[u8]) -> u64 {
    u64::from_be_bytes(key[key.len() - 16..key.len() - 8].try_into().unwrap())
}

/// A batch of keys packed into one buffer.
#[derive(Default)]
pub struct KeyBuf {
    pub data: Vec<u8>,
    pub offs: Vec<u32>,
}

impl KeyBuf {
    #[inline]
    pub fn len(&self) -> usize {
        self.offs.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.offs.is_empty()
    }

    #[inline]
    pub fn key(&self, i: usize) -> &[u8] {
        let s = self.offs[i] as usize;
        let e = self.offs.get(i + 1).map_or(self.data.len(), |&e| e as usize);
        &self.data[s..e]
    }

    #[inline]
    fn begin(&mut self, t: u8) {
        self.offs.push(self.data.len() as u32);
        self.data.push(t);
    }

    #[inline]
    fn put(&mut self, b: &[u8]) {
        self.data.extend_from_slice(b);
    }

    #[inline]
    fn put_u64(&mut self, v: u64) {
        self.data.extend_from_slice(&v.to_be_bytes());
    }

    pub fn push(&mut self, key: &[u8]) {
        self.offs.push(self.data.len() as u32);
        self.data.extend_from_slice(key);
    }
}

/// The `d` field that addresses a replaceable/addressable event, encoded.
pub fn address_d(rec: Record<'_>, out: &mut Vec<u8>) {
    out.clear();
    if kind::is_addressable(rec.kind()) {
        match rec.d_tag() {
            Some(f) => f.encode(out),
            None => out.extend_from_slice(&EMPTY_FIELD),
        }
    } else {
        out.extend_from_slice(&EMPTY_FIELD);
    }
}

/// Appends every index key of `rec` (stored at `seq`) to `kb`.
pub fn index_keys(rec: Record<'_>, seq: u64, kb: &mut KeyBuf, scratch: &mut Vec<u8>, vanish: &crate::VanishCfg) {
    let id = rec.id();
    let pk = rec.pubkey();
    let ca = rec.created_at();
    let k = rec.kind();

    kb.begin(T_ID);
    kb.put(id);
    kb.put_u64(seq);

    kb.begin(T_CREATED);
    kb.put_u64(ca);
    kb.put_u64(seq);

    kb.begin(T_KIND);
    kb.put_u64(k);
    kb.put_u64(ca);
    kb.put_u64(seq);

    kb.begin(T_AUTHOR);
    kb.put(pk);
    kb.put_u64(ca);
    kb.put_u64(seq);

    kb.begin(T_AUTHOR_KIND);
    kb.put(pk);
    kb.put_u64(k);
    kb.put_u64(ca);
    kb.put_u64(seq);

    // Each distinct (name, value) once, even if the event repeats a tag.
    let first_tag_key = kb.len();
    for tag in rec.tags() {
        let Some((name, value)) = tag.indexable() else { continue };
        if !name.is_ascii_alphabetic() || value.len() > MAX_INDEXED_VALUE + 3 {
            continue;
        }
        let dup = (first_tag_key..kb.len()).any(|i| {
            let key = kb.key(i);
            key[0] == T_TAG && key[1] == name && &key[2..key.len() - 16] == value
        });
        if dup {
            continue;
        }
        kb.begin(T_TAG);
        kb.put(&[name]);
        kb.put(value);
        kb.put_u64(ca);
        kb.put_u64(seq);

        kb.begin(T_TAG_KIND);
        kb.put(&[name]);
        kb.put(value);
        kb.put_u64(k);
        kb.put_u64(ca);
        kb.put_u64(seq);

        if name == b'p' && NEG_KINDS.contains(&k) {
            kb.begin(T_NEG);
            kb.put(&[name]);
            kb.put(value);
            kb.put_u64(k);
            kb.put_u64(ca);
            kb.put(id);
            kb.put_u64(rec.expiration().unwrap_or(0));
            kb.put_u64(seq);
        }
    }

    if kind::is_replaceable(k) || kind::is_addressable(k) {
        address_d(rec, scratch);
        kb.begin(T_ADDR);
        kb.put(pk);
        kb.put_u64(k);
        kb.put(scratch);
        kb.put_u64(ca);
        kb.put_u64(seq);
    }

    if let Some(exp) = rec.expiration() {
        kb.begin(T_EXPIRY);
        kb.put_u64(exp);
        kb.put_u64(seq);
    }

    if k == kind::DELETION {
        deletion_keys(rec, kb, scratch);
    }

    if k == kind::VANISH && vanish.targets(rec) {
        kb.begin(T_VANISH);
        kb.put(pk);
        kb.put_u64(ca);
    }
}

/// The permanent tombstones a kind-5 event leaves.
fn deletion_keys(rec: Record<'_>, kb: &mut KeyBuf, scratch: &mut Vec<u8>) {
    let pk = rec.pubkey();
    for tag in rec.tags() {
        let mut f = tag.fields();
        let name = f.next();
        let value = f.next();
        match (name, value) {
            (Some(n), Some(Field::Hex32(target))) if n.is_str(b"e") => {
                kb.begin(T_DELETED);
                kb.put(target);
                kb.put(pk);
            }
            (Some(n), Some(Field::Str(a))) if n.is_str(b"a") => {
                let Some((k, apk, d)) = parse_address(a) else { continue };
                // A deletion only speaks for its own author's events.
                if &apk != pk {
                    continue;
                }
                scratch.clear();
                relay_proto::record::encode_field_str(d, scratch);
                kb.begin(T_ADDR_DELETED);
                kb.put(pk);
                kb.put_u64(k);
                kb.put(scratch);
                kb.put_u64(rec.created_at());
            }
            _ => {}
        }
    }
}

/// `kind:pubkey:d` from an `a` tag value (stored form). `d` may contain colons.
pub fn parse_address(a: &[u8]) -> Option<(u64, [u8; 32], &[u8])> {
    let c1 = a.iter().position(|&b| b == b':')?;
    let rest = &a[c1 + 1..];
    let c2 = rest.iter().position(|&b| b == b':')?;
    let k = std::str::from_utf8(&a[..c1]).ok()?;
    if k.is_empty() || !k.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let k: u64 = k.parse().ok()?;
    let pk = hex::decode_32(&rest[..c2])?;
    Some((k, pk, &rest[c2 + 1..]))
}

// ---- prefixes used by queries and the writer ----

pub fn prefix(t: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + parts.iter().map(|p| p.len()).sum::<usize>());
    v.push(t);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

/// The encoded-field form of an arbitrary value, for building tag prefixes.
pub fn field_bytes(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() + 3);
    varint::put(&mut out, (v.len() as u64) << 1);
    out.extend_from_slice(v);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        let pk = "ab".repeat(32);
        let a = format!("30078:{pk}:vector/pinned:x");
        let (k, p, d) = parse_address(a.as_bytes()).unwrap();
        assert_eq!(k, 30078);
        assert_eq!(p, [0xab; 32]);
        assert_eq!(d, b"vector/pinned:x");
        assert!(parse_address(format!("x:{pk}:d").as_bytes()).is_none());
        assert!(parse_address(b"1:abc:d").is_none());
        let empty = format!("33301:{pk}:");
        let (_, _, d) = parse_address(empty.as_bytes()).unwrap();
        assert_eq!(d, b"");
    }
}
