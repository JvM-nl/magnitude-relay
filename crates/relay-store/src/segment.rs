//! Index segments: immutable sorted key files, the LSM tree's on-disk tier.
//!
//! ```text
//! [block 0] ... [block n-1] [block index] [bloom] [footer]
//! block  = entries ‖ restart offsets (u16 each) ‖ restart count u16 ‖ crc32c u32
//! entry  = varint shared ‖ varint rest ‖ rest bytes (shared = 0 at every restart)
//! index  = n u32 ‖ n × entry offset u32 ‖ entries
//!          entry = off u64 ‖ len u32 ‖ count u32 ‖ before u64 ‖ key_len u16 ‖ first key
//! bloom  = cache-line blocks of 512 bits, k probes inside one block
//! footer = fixed 80 bytes, see `Footer`
//! ```
//!
//! Keys inside a block are prefix-compressed against the previous key, which
//! collapses the long shared prefixes of index keys (an author's keys differ only
//! in their last 16 bytes). Every 16th key is stored whole, a restart point: a
//! seek binary-searches the restart keys and decodes at most 16 entries, and a
//! backward walk decodes one 16-key interval at a time. A 4 KiB block of short
//! keys holds ~340 entries; decoding all of them per seek cost ~5 us. Nothing is parsed
//! at open: the block index and bloom are read straight from the mapping, so
//! opening is O(1) and the only memory pinned is what the page cache keeps hot.
//! A probe for an absent prefix costs one cache line of bloom.

use crate::bloom;
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
const MAGIC: &[u8; 8] = b"RLYSEG02";
/// Keys between restart points.
const RESTART: usize = 16;
/// Room for the longest index key (a tag value is capped at 259 bytes).
const SCAN_KEY_MAX: usize = 1024;
const FOOTER_LEN: usize = 80;
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
    restarts: Vec<u16>,
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
            restarts: Vec::with_capacity(BLOCK_TARGET / 64),
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
        if self.block_count == 0 {
            self.block_first.clear();
            self.block_first.extend_from_slice(key);
        }
        let shared = if self.block_count as usize % RESTART == 0 {
            self.restarts.push(self.block.len() as u16);
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
            self.prefix_hashes.push(bloom::hash64(p));
            self.last_prefix.clear();
            self.last_prefix.extend_from_slice(p);
        }
        Ok(())
    }

    fn finish_block(&mut self) -> io::Result<()> {
        if self.block_count == 0 {
            return Ok(());
        }
        for r in &self.restarts {
            self.block.extend_from_slice(&r.to_le_bytes());
        }
        self.block.extend_from_slice(&(self.restarts.len() as u16).to_le_bytes());
        self.restarts.clear();
        let crc = crc32c(&self.block);
        self.block.extend_from_slice(&crc.to_le_bytes());
        #[cfg(any(test, feature = "fault-injection"))]
        crate::fault::check(&self.path, self.block.len())?;
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

        let nblocks = bloom::blocks_for(self.prefix_hashes.len());
        let mut bloom = vec![0u64; nblocks as usize * 8];
        for &h in &self.prefix_hashes {
            bloom::probe(h, nblocks, |blk, bit| {
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
        footer.extend_from_slice(&bloom::K.to_le_bytes());
        footer.extend_from_slice(&(self.blocks.len() as u64).to_le_bytes());
        footer.extend_from_slice(&self.keys.to_le_bytes());
        footer.extend_from_slice(&index_off.to_le_bytes());
        footer.extend_from_slice(&(index.len() as u64).to_le_bytes());
        footer.extend_from_slice(&bloom_off.to_le_bytes());
        footer.extend_from_slice(&nblocks.to_le_bytes());
        footer.extend_from_slice(&crc32c(&crc_in).to_le_bytes());
        footer.resize(FOOTER_LEN, 0);

        #[cfg(any(test, feature = "fault-injection"))]
        crate::fault::check(&self.path, index.len() + bloom_bytes.len() + footer.len())?;
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
    /// One bit per block: its checksum has been verified. Checked on first use
    /// rather than at open, so opening stays O(1) and a block is hashed once.
    verified: Box<[std::sync::atomic::AtomicU64]>,
    /// Set once a compaction has replaced it: the file goes when the last
    /// snapshot holding it does.
    obsolete: AtomicBool,
    /// The first 8 bytes of each block's first key, big-endian: the block
    /// search runs on these in memory and reads the index only among blocks
    /// whose heads tie. Built on first use, so opening stays O(1).
    heads: std::sync::OnceLock<Box<[u64]>>,
}

/// A key's first 8 bytes as a big-endian number, zero-padded: ordered as the
/// keys are (a shorter key that is a prefix of another sorts first or ties).
#[inline]
fn head(k: &[u8]) -> u64 {
    let mut b = [0u8; 8];
    let n = k.len().min(8);
    b[..n].copy_from_slice(&k[..n]);
    u64::from_be_bytes(b)
}

/// Up to `RESTART` decoded keys of one interval of a block.
#[derive(Default)]
pub struct Interval {
    data: Vec<u8>,
    offs: Vec<u32>,
}

impl Interval {
    /// Room for a whole interval of typical keys, so the first decode does not
    /// grow the buffers step by step.
    fn with_capacity() -> Interval {
        Interval { data: Vec::with_capacity(RESTART * 64), offs: Vec::with_capacity(RESTART) }
    }

    #[inline]
    fn len(&self) -> usize {
        self.offs.len()
    }

    #[inline]
    fn key(&self, i: usize) -> &[u8] {
        let s = self.offs[i] as usize;
        let e = self.offs.get(i + 1).map_or(self.data.len(), |&e| e as usize);
        &self.data[s..e]
    }
}

/// A block's layout, borrowed from the mapping.
#[derive(Clone, Copy)]
struct BlockRef<'a> {
    entries: &'a [u8],
    restarts: &'a [u8],
    count: usize,
    before: u64,
}

impl<'a> BlockRef<'a> {
    #[inline]
    fn nrestarts(&self) -> usize {
        self.restarts.len() / 2
    }

    #[inline]
    fn restart_off(&self, r: usize) -> usize {
        u16::from_le_bytes([self.restarts[2 * r], self.restarts[2 * r + 1]]) as usize
    }

    /// The whole key stored at restart `r`.
    #[inline]
    fn restart_key(&self, r: usize) -> &'a [u8] {
        let mut p = self.restart_off(r);
        let _shared = varint::get(self.entries, &mut p).expect("restart entry");
        let len = varint::get(self.entries, &mut p).expect("restart entry") as usize;
        &self.entries[p..p + len]
    }

    /// Decodes interval `r` (keys `r*RESTART ..`) into `out`.
    fn decode(&self, r: usize, out: &mut Interval) {
        out.data.clear();
        out.offs.clear();
        let n = (self.count - r * RESTART).min(RESTART);
        let mut p = self.restart_off(r);
        let mut prev = 0usize;
        for _ in 0..n {
            let shared = varint::get(self.entries, &mut p).expect("block entry") as usize;
            let rest = varint::get(self.entries, &mut p).expect("block entry") as usize;
            let start = out.data.len();
            out.data.extend_from_within(prev..prev + shared);
            out.data.extend_from_slice(&self.entries[p..p + rest]);
            p += rest;
            out.offs.push(start as u32);
            prev = start;
        }
    }

    /// The last restart whose key is `<= k` (0 if none is).
    #[inline]
    fn restart_le(&self, k: &[u8]) -> usize {
        let (mut lo, mut hi) = (0usize, self.nrestarts());
        while lo < hi {
            let mid = (lo + hi) / 2;
            if !keys::key_lt(k, self.restart_key(mid)) {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo.saturating_sub(1)
    }

    /// Position within the block of the first key `>= k`: the restart search,
    /// then at most one interval's keys rebuilt in a stack buffer.
    fn position(&self, k: &[u8]) -> usize {
        let r = self.restart_le(k);
        let mut buf = [0u8; SCAN_KEY_MAX];
        let mut p = self.restart_off(r);
        let end = (r * RESTART + RESTART).min(self.count);
        for i in r * RESTART..end {
            let shared = varint::get(self.entries, &mut p).expect("block entry") as usize;
            let rest = varint::get(self.entries, &mut p).expect("block entry") as usize;
            if shared + rest > SCAN_KEY_MAX {
                return self.position_slow(k, r);
            }
            buf[shared..shared + rest].copy_from_slice(&self.entries[p..p + rest]);
            p += rest;
            if !keys::key_lt(&buf[..shared + rest], k) {
                return i;
            }
        }
        end
    }

    #[cold]
    fn position_slow(&self, k: &[u8], r: usize) -> usize {
        let mut iv = Interval::default();
        self.decode(r, &mut iv);
        let mut i = 0;
        while i < iv.len() && iv.key(i) < k {
            i += 1;
        }
        r * RESTART + i
    }
}

impl Segment {
    pub fn open(id: u64, path: &Path) -> io::Result<Segment> {
        let len = std::fs::metadata(path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?.len() as usize;
        if len < FOOTER_LEN {
            return Err(io::Error::other(format!("{}: too short for a segment", path.display())));
        }
        let map = MappedFile::open(path, len)?;
        let f = map.slice(len - FOOTER_LEN, FOOTER_LEN);
        let u64_at = |o: usize| u64::from_le_bytes(f[o..o + 8].try_into().unwrap());
        if &f[..8] != MAGIC {
            return Err(io::Error::other(format!("{}: not a segment file (or an older format)", path.display())));
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
        let verified = (0..nblocks.div_ceil(64)).map(|_| std::sync::atomic::AtomicU64::new(0)).collect();
        Ok(Segment { id, path: path.to_path_buf(), map, nblocks, keys, index_off, bloom_off, bloom_blocks, bytes: len as u64, verified, obsolete: AtomicBool::new(false), heads: std::sync::OnceLock::new() })
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
        let h = bloom::hash64(p);
        bloom::probe(h, self.bloom_blocks, |blk, bit| {
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

    /// Checks every block's checksum (`Err` names the first damaged one), so
    /// that none is checked again on use.
    pub fn verify_blocks(&self) -> Result<(), usize> {
        for i in 0..self.nblocks {
            let (off, len, ..) = self.meta(i);
            let (body, crc) = self.map.slice(off, len).split_at(len - 4);
            if crc32c(body) != u32::from_le_bytes(crc.try_into().unwrap()) {
                return Err(i);
            }
            self.verified[i / 64].fetch_or(1 << (i % 64), Ordering::Relaxed);
        }
        Ok(())
    }

    /// Block `i`'s layout, its checksum verified on first use.
    fn block(&self, i: usize) -> BlockRef<'_> {
        let (off, len, count, before, _) = self.meta(i);
        let raw = self.map.slice(off, len);
        let (body, crc) = raw.split_at(len - 4);
        let word = &self.verified[i / 64];
        let bit = 1u64 << (i % 64);
        if word.load(Ordering::Relaxed) & bit == 0 {
            // Opening checked every block; this one was damaged since, on disk
            // under the page cache. Nothing it says can be trusted.
            assert_eq!(
                crc32c(body),
                u32::from_le_bytes(crc.try_into().unwrap()),
                "index segment {} block {i} was damaged after the store opened: restarting refuses it and says how to rebuild",
                self.path.display()
            );
            word.fetch_or(bit, Ordering::Relaxed);
        }
        let n = u16::from_le_bytes([body[body.len() - 2], body[body.len() - 1]]) as usize;
        let restarts_at = body.len() - 2 - 2 * n;
        BlockRef { entries: &body[..restarts_at], restarts: &body[restarts_at..body.len() - 2], count, before }
    }

    /// The last block whose first key is `<= k` (0 if `k` sorts first).
    fn block_for(&self, k: &[u8]) -> usize {
        let heads = self.heads.get_or_init(|| (0..self.nblocks).map(|i| head(self.meta(i).4)).collect());
        // A block whose head is below the key's starts below the key; one whose
        // head is above starts above it. Only ties need their first keys read.
        let h = head(k);
        let mut lo = heads.partition_point(|&x| x < h);
        let mut hi = lo + heads[lo..].partition_point(|&x| x == h);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if !keys::key_lt(k, self.meta(mid).4) {
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

    /// Global position of the first key `>= k`.
    pub fn lower_bound(&self, k: &[u8]) -> u64 {
        if self.nblocks == 0 {
            return 0;
        }
        let b = self.block(self.block_for(k));
        b.before + b.position(k) as u64
    }

    /// A cheap estimate of the keys in `[lo, hi)` from the block index alone (no
    /// block is decoded): exact to within two blocks. For planning.
    pub fn estimate_range(&self, lo: &[u8], hi: &[u8]) -> u64 {
        if self.nblocks == 0 {
            return 0;
        }
        let a = self.block_for(lo);
        let b = self.block_for(hi);
        let (ma, mb) = (self.meta(a), self.meta(b));
        if a == b {
            // Both ends in one block: somewhere between 0 and its size.
            return (ma.2 as u64).div_ceil(2);
        }
        (mb.3 - ma.3) + (mb.2 as u64).div_ceil(2) - (ma.2 as u64) / 2
    }

    /// Number of keys in `[lo, hi)`.
    pub fn count_range(&self, lo: &[u8], hi: &[u8]) -> u64 {
        self.lower_bound(hi).saturating_sub(self.lower_bound(lo))
    }

    /// True if exactly `k` is present.
    pub fn contains(&self, k: &[u8]) -> bool {
        if self.nblocks == 0 || !self.may_contain(keys::bloom_prefix(k)) {
            return false;
        }
        // Only the first key at or after `k` matters; every key type byte is below 0xFF.
        let mut found = false;
        self.scan(k, &[0xFF], &mut |x| {
            found = x == k;
            false
        });
        found
    }

    /// Calls `f` with every key in `[lo, hi)`, in order, until it returns false.
    /// One forward walk from the restart point before `lo`: no cursor, and keys
    /// are rebuilt one at a time in a stack buffer, so a point or prefix lookup
    /// decodes a few keys and allocates nothing.
    pub fn scan(&self, lo: &[u8], hi: &[u8], f: &mut dyn FnMut(&[u8]) -> bool) {
        if self.nblocks == 0 {
            return;
        }
        let mut buf = [0u8; SCAN_KEY_MAX];
        let mut bi = self.block_for(lo);
        let mut r = None;
        while bi < self.nblocks {
            let b = self.block(bi);
            let start = *r.get_or_insert_with(|| b.restart_le(lo));
            r = Some(0);
            let mut p = b.restart_off(start);
            for _ in start * RESTART..b.count {
                let shared = varint::get(b.entries, &mut p).expect("block entry") as usize;
                let rest = varint::get(b.entries, &mut p).expect("block entry") as usize;
                let len = shared + rest;
                if len > SCAN_KEY_MAX {
                    // Longer than any key the index writes; take the general path.
                    return self.scan_cursor(lo, hi, f);
                }
                buf[shared..len].copy_from_slice(&b.entries[p..p + rest]);
                p += rest;
                let k = &buf[..len];
                if keys::key_lt(k, lo) {
                    continue;
                }
                if !keys::key_lt(k, hi) || !f(k) {
                    return;
                }
            }
            bi += 1;
        }
    }

    fn scan_cursor(&self, lo: &[u8], hi: &[u8], f: &mut dyn FnMut(&[u8]) -> bool) {
        let mut c = self.range(lo, hi);
        while let Some(k) = c.next_front() {
            if !f(k) {
                return;
            }
        }
    }

    /// A cursor over keys in `[lo, hi)`.
    pub fn range(&self, lo: &[u8], hi: &[u8]) -> SegCursor<'_> {
        let a = self.lower_bound(lo);
        let b = self.lower_bound(hi);
        SegCursor { seg: self, iv: Interval::with_capacity(), cur: None, front: a, back: b.max(a) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Segment {
    fn drop(&mut self) {
        if self.obsolete.load(Ordering::Acquire) {
            crash_point!("segment.retiring");
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Keys of one segment in `[front, back)`, walked from either end, one decoded
/// interval of at most 16 keys at a time.
pub struct SegCursor<'a> {
    seg: &'a Segment,
    iv: Interval,
    /// The decoded interval: (block layout, interval index).
    cur: Option<(BlockRef<'a>, usize)>,
    front: u64,
    back: u64,
}

impl<'a> SegCursor<'a> {
    #[inline]
    pub fn remaining(&self) -> u64 {
        self.back - self.front
    }

    /// Makes sure the interval holding global position `pos` is decoded; returns
    /// the key's index within it.
    #[inline]
    fn load(&mut self, pos: u64) -> usize {
        if let Some((b, r)) = self.cur {
            if pos >= b.before && pos < b.before + b.count as u64 {
                let at = (pos - b.before) as usize;
                if at / RESTART != r {
                    b.decode(at / RESTART, &mut self.iv);
                    self.cur = Some((b, at / RESTART));
                }
                return at % RESTART;
            }
        }
        let b = self.seg.block(self.seg.block_of_pos(pos));
        let at = (pos - b.before) as usize;
        b.decode(at / RESTART, &mut self.iv);
        self.cur = Some((b, at / RESTART));
        at % RESTART
    }

    /// The last key not yet taken, taken.
    #[inline]
    pub fn next_back(&mut self) -> Option<&[u8]> {
        if self.back == self.front {
            return None;
        }
        self.back -= 1;
        let i = self.load(self.back);
        Some(self.iv.key(i))
    }

    /// The last key not yet taken, left in place.
    #[inline]
    pub fn peek_back(&mut self) -> Option<&[u8]> {
        if self.back == self.front {
            return None;
        }
        let i = self.load(self.back - 1);
        Some(self.iv.key(i))
    }

    /// The first key not yet taken, left in place.
    #[inline]
    pub fn peek_front(&mut self) -> Option<&[u8]> {
        if self.back == self.front {
            return None;
        }
        let i = self.load(self.front);
        Some(self.iv.key(i))
    }

    /// The first key not yet taken, taken.
    #[inline]
    pub fn next_front(&mut self) -> Option<&[u8]> {
        if self.back == self.front {
            return None;
        }
        let i = self.load(self.front);
        self.front += 1;
        Some(self.iv.key(i))
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
    fn block_search_with_tied_heads_and_short_keys() {
        // Thousands of keys per 8-byte head, spread over many blocks, and keys
        // shorter than 8 bytes: the searches must match a sorted vector.
        let path = tmp("heads");
        let mut ks: Vec<Vec<u8>> = Vec::new();
        for a in 0..12u8 {
            ks.push(vec![keys::T_AUTHOR, a]);
            ks.push(vec![keys::T_AUTHOR, a, 0]);
            for i in 0..3000u32 {
                let mut k = vec![keys::T_AUTHOR, a, a, a, a, a, a, a];
                k.extend_from_slice(&[a; 24]);
                k.extend_from_slice(&(u64::from(i) * 3).to_be_bytes());
                k.extend_from_slice(&u64::from(i).to_be_bytes());
                ks.push(k);
            }
        }
        ks.sort();
        ks.dedup();
        let mut w = SegmentWriter::create(&path).unwrap();
        for k in &ks {
            w.add(k).unwrap();
        }
        w.finish().unwrap();
        let seg = Segment::open(1, &path).unwrap();
        assert!(seg.nblocks > 50, "{} blocks", seg.nblocks);
        let check = |k: &[u8]| {
            let want = ks.partition_point(|x| x.as_slice() < k) as u64;
            assert_eq!(seg.lower_bound(k), want, "{k:?}");
            assert_eq!(seg.contains(k), ks.binary_search_by(|x| x.as_slice().cmp(k)).is_ok(), "{k:?}");
        };
        for (i, k) in ks.iter().enumerate().step_by(7) {
            check(k);
            let mut changed = k.clone();
            *changed.last_mut().unwrap() ^= 0x01;
            check(&changed);
            check(&k[..(i % k.len()).max(1)]);
            let mut longer = k.clone();
            longer.push(0);
            check(&longer);
        }
        for k in [&[][..], &[0][..], &[keys::T_AUTHOR][..], &[keys::T_AUTHOR, 99][..], &[0xFF; 40][..]] {
            check(k);
        }
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
