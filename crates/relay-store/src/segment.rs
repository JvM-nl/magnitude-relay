//! Index segments: immutable sorted key files, the LSM tree's on-disk tier.
//!
//! ```text
//! [block 0] ... [block n-1] [block index] [bloom] [footer]
//! block  = entries ‖ crc32c u32;  entry = varint shared ‖ varint rest ‖ rest bytes
//! index  = n u32 ‖ n × entry offset u32 ‖ entries
//!          entry = off u64 ‖ len u32 ‖ count u32 ‖ before u64 ‖ key_len u16 ‖ first key
//! bloom  = cache-line blocks of 512 bits, k probes inside one block
//! footer = fixed 80 bytes, see `Footer`
//! ```
//!
//! Keys inside a block are prefix-compressed against the previous key (the
//! first is stored whole), which collapses the long shared prefixes of index
//! keys: an author's keys differ only in their last 16 bytes. Nothing is parsed
//! at open: the block index and bloom are read straight from the mapping, so
//! opening is O(1) and the only memory pinned is what the page cache keeps hot.
//! A probe for an absent prefix costs one cache line of bloom.

use crate::crc32c::crc32c;
use crate::keys;
use crate::mmap::{Advice, MappedFile};
use relay_proto::varint;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// Uncompressed block payload target. Fits L1 once decoded.
pub const BLOCK_TARGET: usize = 4096;
const MAGIC: &[u8; 8] = b"RLYSEG01";
const FOOTER_LEN: usize = 80;
const BLOOM_BITS_PER_PREFIX: usize = 10;
const BLOOM_K: u32 = 7;

/// 64-bit hash for bloom probes: multiply-xorshift over 8-byte words. Fast,
/// well mixed, and stable across platforms (it is persisted in segment files).
pub fn hash64(b: &[u8]) -> u64 {
    const M: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut h = (b.len() as u64).wrapping_mul(M) ^ 0x2545_F491_4F6C_DD1D;
    let mut chunks = b.chunks_exact(8);
    for c in &mut chunks {
        let w = u64::from_le_bytes(c.try_into().unwrap());
        h = (h ^ w.wrapping_mul(M)).rotate_left(29).wrapping_mul(M);
    }
    let mut tail = [0u8; 8];
    tail[..chunks.remainder().len()].copy_from_slice(chunks.remainder());
    h = (h ^ u64::from_le_bytes(tail).wrapping_mul(M)).rotate_left(29).wrapping_mul(M);
    h ^= h >> 32;
    h = h.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    h ^ (h >> 32)
}

#[inline]
fn bloom_probe(h: u64, nblocks: u64, mut f: impl FnMut(usize, u32) -> bool) -> bool {
    let block = (((h >> 32) * nblocks) >> 32) as usize;
    let h1 = h as u32;
    let h2 = ((h >> 32) as u32).rotate_left(16) | 1;
    for i in 0..BLOOM_K {
        if !f(block, h1.wrapping_add(i.wrapping_mul(h2)) & 511) {
            return false;
        }
    }
    true
}

struct BlockMeta {
    first: Vec<u8>,
    off: u64,
    len: u32,
    count: u32,
    before: u64,
}

/// Writes a segment from keys supplied in strictly ascending order.
pub struct SegmentWriter {
    path: PathBuf,
    out: BufWriter<File>,
    block: Vec<u8>,
    block_first: Vec<u8>,
    block_count: u32,
    prev: Vec<u8>,
    blocks: Vec<BlockMeta>,
    off: u64,
    keys: u64,
    prefix_hashes: Vec<u64>,
    last_prefix: Vec<u8>,
}

impl SegmentWriter {
    pub fn create(path: &Path) -> io::Result<SegmentWriter> {
        let f = File::create(path)?;
        Ok(SegmentWriter {
            path: path.to_path_buf(),
            out: BufWriter::with_capacity(1 << 20, f),
            block: Vec::with_capacity(BLOCK_TARGET + 512),
            block_first: Vec::new(),
            block_count: 0,
            prev: Vec::new(),
            blocks: Vec::new(),
            off: 0,
            keys: 0,
            prefix_hashes: Vec::new(),
            last_prefix: Vec::new(),
        })
    }

    #[inline]
    pub fn add(&mut self, key: &[u8]) -> io::Result<()> {
        debug_assert!(self.keys == 0 || key > self.prev.as_slice(), "keys must ascend");
        if self.block.len() >= BLOCK_TARGET {
            self.finish_block()?;
        }
        let shared = if self.block_count == 0 {
            self.block_first.clear();
            self.block_first.extend_from_slice(key);
            0
        } else {
            self.prev.iter().zip(key).take_while(|(a, b)| a == b).count()
        };
        varint::put(&mut self.block, shared as u64);
        varint::put(&mut self.block, (key.len() - shared) as u64);
        self.block.extend_from_slice(&key[shared..]);
        self.prev.clear();
        self.prev.extend_from_slice(key);
        self.block_count += 1;
        self.keys += 1;
        // Sorted keys keep equal prefixes adjacent, so each is hashed once.
        let p = keys::bloom_prefix(key);
        if p != self.last_prefix.as_slice() {
            self.prefix_hashes.push(hash64(p));
            self.last_prefix.clear();
            self.last_prefix.extend_from_slice(p);
        }
        Ok(())
    }

    fn finish_block(&mut self) -> io::Result<()> {
        if self.block_count == 0 {
            return Ok(());
        }
        let crc = crc32c(&self.block);
        self.block.extend_from_slice(&crc.to_le_bytes());
        self.out.write_all(&self.block)?;
        let before = self.blocks.last().map_or(0, |b| b.before + u64::from(b.count));
        self.blocks.push(BlockMeta {
            first: std::mem::take(&mut self.block_first),
            off: self.off,
            len: self.block.len() as u32,
            count: self.block_count,
            before,
        });
        self.off += self.block.len() as u64;
        self.block.clear();
        self.block_count = 0;
        Ok(())
    }

    /// Writes index, bloom and footer, syncs, and returns the file size.
    pub fn finish(mut self) -> io::Result<u64> {
        self.finish_block()?;
        let index_off = self.off;
        let mut index = Vec::new();
        index.extend_from_slice(&(self.blocks.len() as u32).to_le_bytes());
        let table_end = 4 + 4 * self.blocks.len();
        let mut entries = Vec::new();
        for b in &self.blocks {
            index.extend_from_slice(&((table_end + entries.len()) as u32).to_le_bytes());
            entries.extend_from_slice(&b.off.to_le_bytes());
            entries.extend_from_slice(&b.len.to_le_bytes());
            entries.extend_from_slice(&b.count.to_le_bytes());
            entries.extend_from_slice(&b.before.to_le_bytes());
            entries.extend_from_slice(&(b.first.len() as u16).to_le_bytes());
            entries.extend_from_slice(&b.first);
        }
        index.extend_from_slice(&entries);
        // Pad to a cache line so the bloom's blocks are aligned in the mapping.
        while (index_off as usize + index.len()) % 64 != 0 {
            index.push(0);
        }

        let nblocks = (self.prefix_hashes.len() * BLOOM_BITS_PER_PREFIX).div_ceil(512).max(1) as u64;
        let mut bloom = vec![0u64; nblocks as usize * 8];
        for &h in &self.prefix_hashes {
            bloom_probe(h, nblocks, |blk, bit| {
                bloom[blk * 8 + (bit / 64) as usize] |= 1 << (bit % 64);
                true
            });
        }
        let bloom_bytes: Vec<u8> = bloom.iter().flat_map(|w| w.to_le_bytes()).collect();
        let bloom_off = index_off + index.len() as u64;

        let mut crc_in = index.clone();
        crc_in.extend_from_slice(&bloom_bytes);
        let mut footer = Vec::with_capacity(FOOTER_LEN);
        footer.extend_from_slice(MAGIC);
        footer.extend_from_slice(&1u32.to_le_bytes()); // version
        footer.extend_from_slice(&BLOOM_K.to_le_bytes());
        footer.extend_from_slice(&(self.blocks.len() as u64).to_le_bytes());
        footer.extend_from_slice(&self.keys.to_le_bytes());
        footer.extend_from_slice(&index_off.to_le_bytes());
        footer.extend_from_slice(&(index.len() as u64).to_le_bytes());
        footer.extend_from_slice(&bloom_off.to_le_bytes());
        footer.extend_from_slice(&nblocks.to_le_bytes());
        footer.extend_from_slice(&crc32c(&crc_in).to_le_bytes());
        footer.resize(FOOTER_LEN, 0);

        self.out.write_all(&index)?;
        self.out.write_all(&bloom_bytes)?;
        self.out.write_all(&footer)?;
        self.out.flush()?;
        let f = self.out.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        Ok(bloom_off + bloom_bytes.len() as u64 + FOOTER_LEN as u64)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// An open segment.
pub struct Segment {
    pub id: u64,
    path: PathBuf,
    map: MappedFile,
    nblocks: usize,
    keys: u64,
    index_off: usize,
    bloom_off: usize,
    bloom_blocks: u64,
    bytes: u64,
    /// Set once a compaction has replaced it: the file goes when the last
    /// snapshot holding it does.
    obsolete: AtomicBool,
}

/// A block's keys, decoded into one buffer.
#[derive(Default)]
pub struct Block {
    data: Vec<u8>,
    offs: Vec<u32>,
}

impl Block {
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
    fn lower_bound(&self, k: &[u8]) -> usize {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.key(mid) < k {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    }
}

impl Segment {
    pub fn open(id: u64, path: &Path) -> io::Result<Segment> {
        let len = std::fs::metadata(path)?.len() as usize;
        if len < FOOTER_LEN {
            return Err(io::Error::other(format!("{}: too short for a segment", path.display())));
        }
        let map = MappedFile::open(path, len)?;
        let f = map.slice(len - FOOTER_LEN, FOOTER_LEN);
        let u64_at = |o: usize| u64::from_le_bytes(f[o..o + 8].try_into().unwrap());
        if &f[..8] != MAGIC {
            return Err(io::Error::other(format!("{}: not a segment file", path.display())));
        }
        let nblocks = u64_at(16) as usize;
        let keys = u64_at(24);
        let index_off = u64_at(32) as usize;
        let index_len = u64_at(40) as usize;
        let bloom_off = u64_at(48) as usize;
        let bloom_blocks = u64_at(56);
        let crc = u32::from_le_bytes(f[64..68].try_into().unwrap());
        let meta_end = bloom_off + bloom_blocks as usize * 64;
        if index_off + index_len != bloom_off || meta_end + FOOTER_LEN != len {
            return Err(io::Error::other(format!("{}: inconsistent footer", path.display())));
        }
        if crc32c(map.slice(index_off, meta_end - index_off)) != crc {
            return Err(io::Error::other(format!("{}: index or bloom checksum mismatch", path.display())));
        }
        map.advise(Advice::Random);
        let seg = Segment { id, path: path.to_path_buf(), map, nblocks, keys, index_off, bloom_off, bloom_blocks, bytes: len as u64, obsolete: AtomicBool::new(false) };
        Ok(seg)
    }

    #[inline]
    pub fn keys(&self) -> u64 {
        self.keys
    }

    #[inline]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn mark_obsolete(&self) {
        self.obsolete.store(true, Ordering::Release);
    }

    /// False means no key with prefix `p` is in this segment. `p` must be a whole
    /// bloom prefix (see `keys::bloom_prefix`).
    #[inline]
    pub fn may_contain(&self, p: &[u8]) -> bool {
        let base = self.bloom_off;
        let h = hash64(p);
        bloom_probe(h, self.bloom_blocks, |blk, bit| {
            let w = self.map.read_u64(base + blk * 64 + (bit / 64) as usize * 8);
            w & (1 << (bit % 64)) != 0
        })
    }

    /// (offset, length, key count, keys before, first key) of block `i`.
    #[inline]
    fn meta(&self, i: usize) -> (usize, usize, usize, u64, &[u8]) {
        let rel = self.map.read_u32(self.index_off + 4 + 4 * i) as usize;
        let e = self.index_off + rel;
        let off = self.map.read_u64(e) as usize;
        let len = self.map.read_u32(e + 8) as usize;
        let count = self.map.read_u32(e + 12) as usize;
        let before = self.map.read_u64(e + 16);
        let klen = u16::from_le_bytes(self.map.slice(e + 24, 2).try_into().unwrap()) as usize;
        (off, len, count, before, self.map.slice(e + 26, klen))
    }

    /// The last block whose first key is `<= k` (0 if `k` sorts first).
    fn block_for(&self, k: &[u8]) -> usize {
        let (mut lo, mut hi) = (0usize, self.nblocks);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.meta(mid).4 <= k {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo.saturating_sub(1)
    }

    /// The block holding global position `pos`.
    fn block_of_pos(&self, pos: u64) -> usize {
        let (mut lo, mut hi) = (0usize, self.nblocks);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.meta(mid).3 <= pos {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo.saturating_sub(1)
    }

    /// Decodes block `i` into `out`, checking its checksum.
    pub fn decode(&self, i: usize, out: &mut Block) {
        let (off, len, count, _, _) = self.meta(i);
        let raw = self.map.slice(off, len);
        let (body, crc) = raw.split_at(len - 4);
        assert_eq!(crc32c(body), u32::from_le_bytes(crc.try_into().unwrap()), "index segment {} block {i} is corrupt", self.path.display());
        out.data.clear();
        out.offs.clear();
        out.data.reserve(count * 64);
        let mut p = 0;
        let mut prev_start = 0usize;
        for _ in 0..count {
            let shared = varint::get(body, &mut p).expect("block entry") as usize;
            let rest = varint::get(body, &mut p).expect("block entry") as usize;
            let start = out.data.len();
            out.data.extend_from_within(prev_start..prev_start + shared);
            out.data.extend_from_slice(&body[p..p + rest]);
            p += rest;
            out.offs.push(start as u32);
            prev_start = start;
        }
    }

    /// Global position of the first key `>= k`, decoding into `blk` (which is
    /// left holding the block that position falls in, as `blk_idx`).
    pub fn lower_bound(&self, k: &[u8], blk: &mut Block, blk_idx: &mut usize) -> u64 {
        if self.nblocks == 0 {
            return 0;
        }
        let b = self.block_for(k);
        if *blk_idx != b || blk.is_empty() {
            self.decode(b, blk);
            *blk_idx = b;
        }
        let before = self.meta(b).3;
        before + blk.lower_bound(k) as u64
    }

    /// Number of keys in `[lo, hi)`.
    pub fn count_range(&self, lo: &[u8], hi: &[u8]) -> u64 {
        let mut blk = Block::default();
        let mut bi = usize::MAX;
        let a = self.lower_bound(lo, &mut blk, &mut bi);
        let b = self.lower_bound(hi, &mut blk, &mut bi);
        b.saturating_sub(a)
    }

    /// True if exactly `k` is present.
    pub fn contains(&self, k: &[u8]) -> bool {
        if !self.may_contain(keys::bloom_prefix(k)) {
            return false;
        }
        let mut blk = Block::default();
        let mut bi = usize::MAX;
        let pos = self.lower_bound(k, &mut blk, &mut bi);
        let start = self.meta(bi).3;
        let i = (pos - start) as usize;
        i < blk.len() && blk.key(i) == k
    }

    /// A cursor over keys in `[lo, hi)`.
    pub fn range(&self, lo: &[u8], hi: &[u8]) -> SegCursor<'_> {
        let mut blk = Block::default();
        let mut bi = usize::MAX;
        let a = self.lower_bound(lo, &mut blk, &mut bi);
        let b = self.lower_bound(hi, &mut blk, &mut bi);
        SegCursor { seg: self, blk, bi, front: a, back: b.max(a) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        if self.obsolete.load(Ordering::Acquire) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Keys of one segment in `[front, back)`, walked from either end.
pub struct SegCursor<'a> {
    seg: &'a Segment,
    blk: Block,
    bi: usize,
    front: u64,
    back: u64,
}

impl SegCursor<'_> {
    #[inline]
    pub fn remaining(&self) -> u64 {
        self.back - self.front
    }

    fn load(&mut self, pos: u64) -> usize {
        let start = if self.bi < self.seg.nblocks { self.seg.meta(self.bi).3 } else { u64::MAX };
        let count = if self.bi < self.seg.nblocks { self.blk.len() as u64 } else { 0 };
        if start == u64::MAX || pos < start || pos >= start + count {
            let b = self.seg.block_of_pos(pos);
            self.seg.decode(b, &mut self.blk);
            self.bi = b;
        }
        (pos - self.seg.meta(self.bi).3) as usize
    }

    /// The last key not yet taken, taken.
    #[inline]
    pub fn next_back(&mut self) -> Option<&[u8]> {
        if self.back == self.front {
            return None;
        }
        self.back -= 1;
        let i = self.load(self.back);
        Some(self.blk.key(i))
    }

    /// The last key not yet taken, left in place.
    #[inline]
    pub fn peek_back(&mut self) -> Option<&[u8]> {
        if self.back == self.front {
            return None;
        }
        let i = self.load(self.back - 1);
        Some(self.blk.key(i))
    }

    /// The first key not yet taken, left in place.
    #[inline]
    pub fn peek_front(&mut self) -> Option<&[u8]> {
        if self.back == self.front {
            return None;
        }
        let i = self.load(self.front);
        Some(self.blk.key(i))
    }

    /// The first key not yet taken, taken.
    #[inline]
    pub fn next_front(&mut self) -> Option<&[u8]> {
        if self.back == self.front {
            return None;
        }
        let i = self.load(self.front);
        self.front += 1;
        Some(self.blk.key(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("seg-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        d
    }

    fn sample_keys(n: usize) -> Vec<Vec<u8>> {
        // Author-shaped keys: long shared prefixes, as in the real index.
        let mut v: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let mut k = vec![keys::T_AUTHOR];
                k.extend_from_slice(&[(i % 97) as u8; 32]);
                k.extend_from_slice(&((i * 7919) as u64).to_be_bytes());
                k.extend_from_slice(&(i as u64).to_be_bytes());
                k
            })
            .collect();
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn round_trip_search_and_bloom() {
        let path = tmp("rt");
        let ks = sample_keys(20_000);
        let mut w = SegmentWriter::create(&path).unwrap();
        for k in &ks {
            w.add(k).unwrap();
        }
        let size = w.finish().unwrap();
        let seg = Segment::open(1, &path).unwrap();
        assert_eq!(seg.keys(), ks.len() as u64);
        assert!(size < (ks.len() * 57) as u64 / 2, "prefix compression works ({size} bytes)");

        // Forward and backward walks see every key in order.
        let mut c = seg.range(&[], &[0xFF]);
        let fwd: Vec<Vec<u8>> = std::iter::from_fn(|| c.next_front().map(|k| k.to_vec())).collect();
        assert_eq!(fwd, ks);
        let mut c = seg.range(&[], &[0xFF]);
        let mut back: Vec<Vec<u8>> = std::iter::from_fn(|| c.next_back().map(|k| k.to_vec())).collect();
        back.reverse();
        assert_eq!(back, ks);

        // Ranges and membership match a sorted vector.
        for probe in [0usize, 1, 77, 5000, 19_999] {
            let k = &ks[probe];
            assert!(seg.contains(k));
            let mut absent = k.clone();
            *absent.last_mut().unwrap() ^= 0x55;
            assert_eq!(seg.contains(&absent), ks.binary_search(&absent).is_ok());
            let lo = &ks[probe / 2];
            let n = seg.count_range(lo, k);
            assert_eq!(n, (probe - probe / 2) as u64);
        }

        // Every present prefix passes the bloom; most absent ones do not.
        for k in ks.iter().step_by(101) {
            assert!(seg.may_contain(keys::bloom_prefix(k)));
        }
        let mut fp = 0;
        for i in 0..10_000u32 {
            let mut k = vec![keys::T_AUTHOR];
            k.extend_from_slice(&[200; 28]);
            k.extend_from_slice(&i.to_be_bytes());
            fp += usize::from(seg.may_contain(&k));
        }
        assert!(fp < 300, "false positive rate {fp}/10000");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corruption_is_detected() {
        let path = tmp("bad");
        let mut w = SegmentWriter::create(&path).unwrap();
        for k in sample_keys(500) {
            w.add(&k).unwrap();
        }
        w.finish().unwrap();
        let mut data = std::fs::read(&path).unwrap();
        let n = data.len();
        data[n - 100] ^= 1; // inside the bloom
        std::fs::write(&path, &data).unwrap();
        assert!(Segment::open(1, &path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_segment() {
        let path = tmp("empty");
        SegmentWriter::create(&path).unwrap().finish().unwrap();
        let seg = Segment::open(1, &path).unwrap();
        assert_eq!(seg.keys(), 0);
        assert!(seg.range(&[], &[0xFF]).next_back().is_none());
        assert!(!seg.contains(b"x"));
        let _ = std::fs::remove_file(&path);
    }
}
