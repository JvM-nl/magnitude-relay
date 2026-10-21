//! Negentropy (NIP-77) set reconciliation, protocol v1, responder side.
//!
//! The wire format is easy to get subtly wrong, and every client relies on it:
//! varints are **big-endian** base-128 (not LEB128); bound timestamps are
//! delta-encoded against the previous bound in the same message, with 0 meaning
//! infinity; an id prefix in a bound is zero-padded for comparison. The
//! algorithm follows the reference implementation step for step (16 buckets,
//! id lists under 32 items, frame-size cut-off with a fingerprint for the rest)
//! so it interoperates with every client, Vector's included.
//!
//! Storage is a trait: today a sorted vector with prefix sums (fingerprints of
//! any range in O(1)); later the covering index, which never reads an event.

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

pub const PROTOCOL_VERSION: u8 = 0x61;
pub const ID_SIZE: usize = 32;
pub const FINGERPRINT_SIZE: usize = 16;
const BUCKETS: usize = 16;
const DOUBLE_BUCKETS: usize = 2 * BUCKETS;

const MODE_SKIP: u64 = 0;
const MODE_FINGERPRINT: u64 = 1;
const MODE_ID_LIST: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegError {
    Truncated,
    BadMode,
    BadVersion,
    BoundTooLong,
}

impl fmt::Display for NegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            NegError::Truncated => "negentropy message ends prematurely",
            NegError::BadMode => "unknown negentropy mode",
            NegError::BadVersion => "invalid negentropy protocol version",
            NegError::BoundTooLong => "negentropy bound id longer than 32 bytes",
        })
    }
}

impl std::error::Error for NegError {}

/// A position in the `(timestamp, id)` order. `id` is zero-padded past `id_len`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    pub timestamp: u64,
    pub id: [u8; ID_SIZE],
    pub id_len: usize,
}

impl Bound {
    pub const fn ts(timestamp: u64) -> Bound {
        Bound { timestamp, id: [0; ID_SIZE], id_len: 0 }
    }

    pub fn from_item(timestamp: u64, id: &[u8; ID_SIZE]) -> Bound {
        Bound { timestamp, id: *id, id_len: ID_SIZE }
    }
}

/// The items to reconcile, sorted by `(timestamp, id)` ascending.
pub trait NegStorage {
    fn size(&self) -> usize;
    fn item(&self, i: usize) -> (u64, [u8; ID_SIZE]);
    /// First index in `[lo, hi)` whose item is `>= bound`, else `hi`.
    fn lower_bound(&self, lo: usize, hi: usize, bound: &Bound) -> usize {
        let (mut lo, mut hi) = (lo, hi);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let (t, id) = self.item(mid);
            if (t, id) < (bound.timestamp, bound.id) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
    /// Fingerprint of items `[lo, hi)`.
    fn fingerprint(&self, lo: usize, hi: usize) -> [u8; FINGERPRINT_SIZE];
}

/// Sorted items plus running 256-bit sums of their ids.
pub struct VecStorage {
    items: Vec<(u64, [u8; ID_SIZE])>,
    /// `sums[i]` = sum of ids `[0, i)` as little-endian 256-bit integers, mod 2^256.
    sums: Vec<[u64; 4]>,
}

impl VecStorage {
    /// Takes items in any order; sorts and deduplicates them.
    pub fn new(mut items: Vec<(u64, [u8; ID_SIZE])>) -> VecStorage {
        items.sort_unstable();
        items.dedup();
        let mut sums = Vec::with_capacity(items.len() + 1);
        let mut acc = [0u64; 4];
        sums.push(acc);
        for (_, id) in &items {
            add256(&mut acc, &lanes(id));
            sums.push(acc);
        }
        VecStorage { items, sums }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl NegStorage for VecStorage {
    #[inline]
    fn size(&self) -> usize {
        self.items.len()
    }

    #[inline]
    fn item(&self, i: usize) -> (u64, [u8; ID_SIZE]) {
        self.items[i]
    }

    fn fingerprint(&self, lo: usize, hi: usize) -> [u8; FINGERPRINT_SIZE] {
        let mut s = self.sums[hi];
        sub256(&mut s, &self.sums[lo]);
        fingerprint_of(&s, (hi - lo) as u64)
    }
}

#[inline]
fn lanes(id: &[u8; ID_SIZE]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_le_bytes(id[i * 8..i * 8 + 8].try_into().unwrap()))
}

#[inline]
pub fn add256(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut carry = false;
    for i in 0..4 {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(u64::from(carry));
        a[i] = s;
        carry = c1 || c2;
    }
}

#[inline]
pub fn sub256(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = false;
    for i in 0..4 {
        let (s, b1) = a[i].overflowing_sub(b[i]);
        let (s, b2) = s.overflowing_sub(u64::from(borrow));
        a[i] = s;
        borrow = b1 || b2;
    }
}

/// sha256(sum ‖ varint(count)), first 16 bytes.
pub fn fingerprint_of(sum: &[u64; 4], count: u64) -> [u8; FINGERPRINT_SIZE] {
    let mut buf = [0u8; ID_SIZE + 10];
    for (i, l) in sum.iter().enumerate() {
        buf[i * 8..i * 8 + 8].copy_from_slice(&l.to_le_bytes());
    }
    let mut v = Vec::with_capacity(10);
    put_varint(&mut v, count);
    buf[ID_SIZE..ID_SIZE + v.len()].copy_from_slice(&v);
    let h = Sha256::digest(&buf[..ID_SIZE + v.len()]);
    h[..FINGERPRINT_SIZE].try_into().unwrap()
}

/// Big-endian base-128 varint, high bit set on every byte but the last.
pub fn put_varint(out: &mut Vec<u8>, mut n: u64) {
    let mut tmp = [0u8; 10];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            break;
        }
    }
    let last = tmp.len() - 1;
    for b in &mut tmp[i..last] {
        *b |= 0x80;
    }
    out.extend_from_slice(&tmp[i..]);
}

fn get_varint(q: &mut &[u8]) -> Result<u64, NegError> {
    let mut v = 0u64;
    loop {
        let (&b, rest) = q.split_first().ok_or(NegError::Truncated)?;
        *q = rest;
        v = (v << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            return Ok(v);
        }
    }
}

fn get_bytes<'a>(q: &mut &'a [u8], n: usize) -> Result<&'a [u8], NegError> {
    if q.len() < n {
        return Err(NegError::Truncated);
    }
    let (a, b) = q.split_at(n);
    *q = b;
    Ok(a)
}

struct Codec {
    last_in: u64,
    last_out: u64,
}

impl Codec {
    fn bound_in(&mut self, q: &mut &[u8]) -> Result<Bound, NegError> {
        let raw = get_varint(q)?;
        let ts = if raw == 0 { u64::MAX } else { raw - 1 };
        let ts = ts.saturating_add(self.last_in);
        self.last_in = ts;
        let len = get_varint(q)? as usize;
        if len > ID_SIZE {
            return Err(NegError::BoundTooLong);
        }
        let mut id = [0u8; ID_SIZE];
        id[..len].copy_from_slice(get_bytes(q, len)?);
        Ok(Bound { timestamp: ts, id, id_len: len })
    }

    fn bound_out(&mut self, b: &Bound, out: &mut Vec<u8>) {
        if b.timestamp == u64::MAX {
            self.last_out = u64::MAX;
            put_varint(out, 0);
        } else {
            let delta = b.timestamp.saturating_sub(self.last_out);
            self.last_out = b.timestamp;
            put_varint(out, delta.saturating_add(1));
        }
        put_varint(out, b.id_len as u64);
        out.extend_from_slice(&b.id[..b.id_len]);
    }
}

/// The shortest bound that sorts after `prev` and at or before `curr`.
fn minimal_bound(prev: (u64, [u8; ID_SIZE]), curr: (u64, [u8; ID_SIZE])) -> Bound {
    if curr.0 != prev.0 {
        return Bound::ts(curr.0);
    }
    let shared = prev.1.iter().zip(curr.1.iter()).take_while(|(a, b)| a == b).count();
    let len = (shared + 1).min(ID_SIZE);
    let mut id = [0u8; ID_SIZE];
    id[..len].copy_from_slice(&curr.1[..len]);
    Bound { timestamp: curr.0, id, id_len: len }
}

/// Answers one client message. `frame_limit` caps the response size (0 = none);
/// when reached, the remainder is summarised by one fingerprint and the client
/// asks again.
pub fn reconcile(s: &impl NegStorage, mut q: &[u8], frame_limit: usize) -> Result<Vec<u8>, NegError> {
    let mut out = vec![PROTOCOL_VERSION];
    let (&version, rest) = q.split_first().ok_or(NegError::Truncated)?;
    q = rest;
    if !(0x60..=0x6F).contains(&version) {
        return Err(NegError::BadVersion);
    }
    if version != PROTOCOL_VERSION {
        // Tell the client which version we speak.
        return Ok(out);
    }
    let exceeded = |n: usize| frame_limit != 0 && n > frame_limit.saturating_sub(200);
    let mut c = Codec { last_in: 0, last_out: 0 };
    let size = s.size();
    let mut prev_bound = Bound::ts(0);
    let mut prev_index = 0usize;
    let mut skip = false;

    while !q.is_empty() {
        let mut o = Vec::new();
        let curr = c.bound_in(&mut q)?;
        let mode = get_varint(&mut q)?;
        let lower = prev_index;
        let mut upper = s.lower_bound(prev_index, size, &curr);

        match mode {
            MODE_SKIP => skip = true,
            MODE_FINGERPRINT => {
                let theirs = get_bytes(&mut q, FINGERPRINT_SIZE)?;
                if theirs != s.fingerprint(lower, upper) {
                    if std::mem::take(&mut skip) {
                        c.bound_out(&prev_bound, &mut o);
                        put_varint(&mut o, MODE_SKIP);
                    }
                    split_range(s, &mut c, lower, upper, curr, &mut o);
                } else {
                    skip = true;
                }
            }
            MODE_ID_LIST => {
                let n = get_varint(&mut q)? as usize;
                // Their ids are not needed by a responder beyond parsing them:
                // it answers with its own full list for the range.
                let _theirs: HashSet<&[u8]> = (0..n).map(|_| get_bytes(&mut q, ID_SIZE)).collect::<Result<_, _>>()?;
                if std::mem::take(&mut skip) {
                    c.bound_out(&prev_bound, &mut o);
                    put_varint(&mut o, MODE_SKIP);
                }
                let mut ids = Vec::new();
                let mut count = 0u64;
                let mut end = curr;
                for i in lower..upper {
                    if exceeded(out.len() + ids.len()) {
                        let (t, id) = s.item(i);
                        end = Bound::from_item(t, &id);
                        upper = i;
                        break;
                    }
                    ids.extend_from_slice(&s.item(i).1);
                    count += 1;
                }
                c.bound_out(&end, &mut o);
                put_varint(&mut o, MODE_ID_LIST);
                put_varint(&mut o, count);
                o.extend_from_slice(&ids);
                out.extend_from_slice(&o);
                o.clear();
            }
            _ => return Err(NegError::BadMode),
        }

        if exceeded(out.len() + o.len()) {
            let fp = s.fingerprint(upper, size);
            c.bound_out(&Bound::ts(u64::MAX), &mut out);
            put_varint(&mut out, MODE_FINGERPRINT);
            out.extend_from_slice(&fp);
            break;
        }
        out.extend_from_slice(&o);
        prev_index = upper;
        prev_bound = curr;
    }
    Ok(out)
}

fn split_range(s: &impl NegStorage, c: &mut Codec, lower: usize, upper: usize, upper_bound: Bound, o: &mut Vec<u8>) {
    let n = upper - lower;
    if n < DOUBLE_BUCKETS {
        c.bound_out(&upper_bound, o);
        put_varint(o, MODE_ID_LIST);
        put_varint(o, n as u64);
        for i in lower..upper {
            o.extend_from_slice(&s.item(i).1);
        }
        return;
    }
    let per = n / BUCKETS;
    let extra = n % BUCKETS;
    let mut curr = lower;
    for b in 0..BUCKETS {
        let size = per + usize::from(b < extra);
        let fp = s.fingerprint(curr, curr + size);
        curr += size;
        let next = if curr == upper { upper_bound } else { minimal_bound(s.item(curr - 1), s.item(curr)) };
        c.bound_out(&next, o);
        put_varint(o, MODE_FINGERPRINT);
        o.extend_from_slice(&fp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_are_big_endian() {
        let cases: [(u64, &[u8]); 5] = [(0, &[0]), (127, &[0x7F]), (128, &[0x81, 0x00]), (300, &[0x82, 0x2C]), (16384, &[0x81, 0x80, 0x00])];
        for (n, enc) in cases {
            let mut v = Vec::new();
            put_varint(&mut v, n);
            assert_eq!(v, enc, "{n}");
            let mut q = enc;
            assert_eq!(get_varint(&mut q).unwrap(), n);
        }
    }

    #[test]
    fn sums_wrap_and_subtract() {
        let mut a = [u64::MAX; 4];
        add256(&mut a, &[1, 0, 0, 0]);
        assert_eq!(a, [0; 4]);
        sub256(&mut a, &[1, 0, 0, 0]);
        assert_eq!(a, [u64::MAX; 4]);
    }
}
