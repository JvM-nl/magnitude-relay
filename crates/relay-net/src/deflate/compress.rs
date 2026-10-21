//! DEFLATE encoder, tuned for speed on small and medium JSON messages.
//!
//! **Matching.** One probe per position into a hash table of 4-byte sequences (the
//! shape of zlib level 1 and libdeflate's fast levels): hash the next four bytes,
//! read the candidate position, overwrite it with the current one, and if the four
//! bytes behind the candidate really match (stale and colliding entries are only
//! hints, always verified against the data) extend the match eight bytes at a time.
//! Greedy, no lazy evaluation. Nostr JSON is mostly hex ids, which never repeat
//! except a pubkey seen before (then a 64-byte match), and base64 ciphertext, which
//! never matches at all; a deeper search would burn time for nothing there.
//!
//! **Blocks.** The input is cut into chunks of at most 16 KiB (8 KiB for a stream that
//! keeps history, to bound its buffer) and each chunk becomes one block, so a token
//! buffer of 16k entries can never overflow (every token covers at least one byte) and
//! a 1 MB payload is 64 blocks whose codes adapt as the content changes. For each chunk the encoder knows the exact bit cost of three
//! encodings (dynamic Huffman including its header, fixed Huffman, stored) from the
//! histograms alone, and writes the smallest. That is what keeps tiny messages cheap
//! (fixed Huffman has no header) and incompressible ones from growing past 5 bytes
//! of stored-block framing. Code construction is in [`super::huffman`].
//!
//! **History.** The matcher works on one contiguous buffer, `[history | new data]`,
//! so a match may reach back across message boundaries without any copying in the
//! hot loop. Positions are 16 bits, relative to the buffer start; when appending
//! would overflow `window + chunk` bytes (40 KiB at most) the buffer slides (keep the last `window`
//! bytes, subtract the shift from every table entry), which costs one memmove of
//! the window per chunk of input. That is the *only* per-stream state, and it is
//! only kept when context takeover is on. Without takeover the buffer and table are
//! a thread-wide scratch reused by every history-free stream, so such a stream
//! costs no memory between messages.
//!
//! **Stateless streams are position-independent.** A stale hash entry left by a
//! previous message points at some position of the (reset) buffer; verification
//! compares real bytes, so the worst outcome is a missed match, never a wrong one,
//! and no table clearing is needed per message.
//!
//! **Output.** The encoder emits a sync-flushed stream: data blocks (never BFINAL)
//! and then an empty stored block, `00 00 ff ff` after its three header bits, so the
//! output ends byte-aligned and a receiver can decode it without waiting for more.
//! permessage-deflate strips those four bytes. [`Flush::Finish`] ends the stream with
//! a final empty fixed block instead.

use super::huffman::{build_lengths, canonical_codes, fixed_codes};
use super::tables::*;
use std::cell::RefCell;

/// How a call ends the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flush {
    /// Empty stored block after the data: byte-aligned, more data may follow with the
    /// same history. Ends with the four bytes `00 00 ff ff`.
    Sync,
    /// Final block: the stream is complete and the history is dropped.
    Finish,
}

/// Largest chunk (and so block) in input bytes; also the token buffer's length.
const CHUNK_MAX: usize = 16 * 1024;
const CHUNK_MIN: usize = 4 * 1024;
const CHUNK_HISTORY: usize = 8 * 1024;
/// Hash table size is `1 << hash_bits` entries of `u16`. A stream that keeps history pays for
/// its table per connection, so it gets 8 KiB (12 bits); the thread-wide scratch used by
/// history-free streams is shared by thousands of connections and gets 16 KiB (13 bits),
/// which buys about a point of ratio on large payloads (measured on Nostr-like events; a
/// 32 KiB table buys a few tenths more and runs slower from cache misses).
const MAX_HASH_BITS_HISTORY: u32 = 12;
const MAX_HASH_BITS_SHARED: u32 = 13;
const HASH_MUL: u32 = 0x9E37_79B1;
/// Most positions the match search skips at once through a long run of misses.
const MAX_SKIP: usize = 8;
/// A 4-byte match farther back than this is not taken: its length, distance and extra
/// bits cost about what four literals do (a hex digit costs four bits), so it only
/// costs a token. Measured at a half-point of ratio and some speed on Nostr traffic.
const MAX_FAR_DIST_4: usize = 128;
/// Token flag: bit 24 set means a match; a literal is just the byte value.
const MATCH: u32 = 1 << 24;

/// Chunk (and so block) size. A stream with history holds `window + chunk` bytes per
/// connection, and a single message bigger than a few KiB is rare on one (a Nostr event
/// is at most 64 KiB), so it takes the small chunk; the shared scratch takes the big one.
fn chunk_for(window_bits: u8, history: bool) -> usize {
    let cap = if history { CHUNK_HISTORY } else { CHUNK_MAX };
    (1usize << window_bits).clamp(CHUNK_MIN, cap)
}

fn hash_bits_for(window_bits: u8, history: bool) -> u32 {
    let cap = if history { MAX_HASH_BITS_HISTORY } else { MAX_HASH_BITS_SHARED };
    u32::from(window_bits).clamp(8, cap)
}

/// History buffer plus hash table: what context takeover keeps.
#[derive(Default)]
struct StreamState {
    buf: Vec<u8>,
    table: Vec<u16>,
}

impl StreamState {
    /// Appends `piece`, sliding the window first if it would not fit. Returns where
    /// the piece starts in `buf`. Only the first `used_len` table entries are in use
    /// (a stream may use a prefix of the shared table) and need rebasing.
    fn append(&mut self, piece: &[u8], window: usize, chunk: usize, table_len: usize, used_len: usize) -> usize {
        if self.table.len() != table_len {
            self.table = vec![0; table_len];
        }
        if self.buf.len() + piece.len() > window + chunk {
            let shift = self.buf.len().saturating_sub(window);
            if shift > 0 {
                self.buf.copy_within(shift.., 0);
                self.buf.truncate(self.buf.len() - shift);
                // Entries older than the new start become 0, a position whose bytes are
                // simply verified like any other.
                let s = shift as u16;
                for e in self.table[..used_len].iter_mut() {
                    *e = e.saturating_sub(s);
                }
            }
        }
        // Grow geometrically but never past `window + chunk`: `extend_from_slice` alone would
        // round a 40 KiB history up to a 64 KiB allocation, per connection.
        let need = self.buf.len() + piece.len();
        if need > self.buf.capacity() {
            let target = (self.buf.capacity() * 2).max(need).max(1024).min(window + chunk);
            self.buf.reserve_exact(target - self.buf.len());
        }
        let at = self.buf.len();
        self.buf.extend_from_slice(piece);
        at
    }
}

/// Everything a call needs while it runs, shared by all streams on the thread.
struct Work {
    tokens: Vec<u32>,
    lit_freq: [u32; LITLEN_SYMBOLS],
    dist_freq: [u32; DIST_SYMBOLS],
    lit_len: [u8; LITLEN_SYMBOLS],
    lit_code: [u16; LITLEN_SYMBOLS],
    dist_len: [u8; DIST_SYMBOLS],
    dist_code: [u16; DIST_SYMBOLS],
    cl_freq: [u32; 19],
    cl_len: [u8; 19],
    cl_code: [u16; 19],
    /// Run-length coded code lengths: `symbol << 8 | extra bits value`.
    rle: [u16; 320],
    /// Bits not yet written (fewer than 8) when a block ends.
    acc: u64,
    nbits: u32,
}

struct Scratch {
    work: Work,
    /// Buffer and table for streams without history.
    shared: StreamState,
}

thread_local! {
    static SCRATCH: RefCell<Box<Scratch>> = RefCell::new(Box::new(Scratch {
        work: Work {
            tokens: vec![0; CHUNK_MAX],
            lit_freq: [0; LITLEN_SYMBOLS],
            dist_freq: [0; DIST_SYMBOLS],
            lit_len: [0; LITLEN_SYMBOLS],
            lit_code: [0; LITLEN_SYMBOLS],
            dist_len: [0; DIST_SYMBOLS],
            dist_code: [0; DIST_SYMBOLS],
            cl_freq: [0; 19],
            cl_len: [0; 19],
            cl_code: [0; 19],
            rle: [0; 320],
            acc: 0,
            nbits: 0,
        },
        shared: StreamState::default(),
    }));
}

/// Bits into a pre-sized byte slice. Every size the encoder needs is computed
/// exactly before writing, so the slice is always big enough; indexing is checked
/// regardless.
struct Sink<'a> {
    dst: &'a mut [u8],
    pos: usize,
    acc: u64,
    nbits: u32,
}

impl Sink<'_> {
    /// Adds `n` bits. The caller keeps `nbits + n <= 64` (flush between big puts).
    #[inline(always)]
    fn put(&mut self, v: u64, n: u32) {
        self.acc |= v << self.nbits;
        self.nbits += n;
    }

    /// Writes out every whole byte in the accumulator. Always stores eight bytes
    /// (the extras are overwritten by the next flush) and advances by the whole ones,
    /// so there is no branch on how many are ready.
    #[inline(always)]
    fn flush(&mut self) {
        self.dst[self.pos..self.pos + 8].copy_from_slice(&self.acc.to_le_bytes());
        let whole = self.nbits >> 3;
        self.pos += whole as usize;
        self.acc >>= whole * 8;
        self.nbits &= 7;
    }

    /// `put` for header-style code: flushes first when the accumulator is getting full.
    #[inline(always)]
    fn put_safe(&mut self, v: u64, n: u32) {
        if self.nbits > 32 {
            self.flush();
        }
        self.put(v, n);
    }

    /// Pads with zero bits to a byte boundary and writes everything out.
    fn align(&mut self) {
        self.nbits = (self.nbits + 7) & !7;
        self.flush();
    }

    fn bytes(&mut self, b: &[u8]) {
        debug_assert_eq!(self.nbits, 0);
        self.dst[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }
}

/// How many bytes `a[ai..]` and `b[bi..]` agree on, up to `max` (`ai < bi`).
#[inline(always)]
fn common_prefix(buf: &[u8], ai: usize, bi: usize, max: usize) -> usize {
    let mut n = 0;
    while n + 8 <= max {
        let x = u64::from_le_bytes(buf[ai + n..ai + n + 8].try_into().unwrap_or([0; 8]))
            ^ u64::from_le_bytes(buf[bi + n..bi + n + 8].try_into().unwrap_or([0; 8]));
        if x != 0 {
            return n + (x.trailing_zeros() >> 3) as usize;
        }
        n += 8;
    }
    while n < max && buf[ai + n] == buf[bi + n] {
        n += 1;
    }
    n
}

#[inline(always)]
fn read4(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

impl Work {
    /// Tokenises `buf[from..]` and histograms the symbols. Returns the token count.
    fn find_matches(&mut self, buf: &[u8], from: usize, table: &mut [u16], hbits: u32, window: usize) -> usize {
        self.lit_freq.fill(0);
        self.dist_freq.fill(0);
        let end = buf.len();
        let mask = table.len() - 1;
        let shift = 32 - hbits;
        let tokens = &mut self.tokens[..];
        let (lit_freq, dist_freq) = (&mut self.lit_freq, &mut self.dist_freq);
        let mut nt = 0usize;
        let mut i = from;
        // A position can be hashed only if four bytes remain.
        let hash_end = end.saturating_sub(3);
        // Consecutive probes that found nothing. Long runs of that are ids and base64: past
        // 16 the probe is skipped on every other position, past 32 on two of three, and so
        // on (LZ4's trick). The skipped bytes are still emitted as literals; only the
        // search for a match that starts there is given up, and a repeat of a long string
        // is picked up a byte or two late.
        let mut misses = 0usize;
        while i < hash_end {
            let w = read4(buf, i);
            let h = (w.wrapping_mul(HASH_MUL) >> shift) as usize & mask;
            let cand = table[h] as usize;
            table[h] = i as u16;
            if cand < i && i - cand <= window && read4(buf, cand) == w {
                let len = 4 + common_prefix(buf, cand + 4, i + 4, (end - i).min(MAX_MATCH) - 4);
                let dist = i - cand;
                if len == 4 && dist > MAX_FAR_DIST_4 {
                    // Not worth a token; fall through to the literal path.
                    misses += 1;
                    tokens[nt] = u32::from(buf[i]);
                    nt += 1;
                    lit_freq[buf[i] as usize] += 1;
                    i += 1;
                    continue;
                }
                tokens[nt] = MATCH | (((len - MIN_MATCH) as u32) << 16) | (dist - 1) as u32;
                nt += 1;
                lit_freq[257 + LEN_CODE[len - MIN_MATCH] as usize] += 1;
                dist_freq[dist_code(dist as u32 - 1)] += 1;
                // Index a couple of positions inside the match so a later repeat of this
                // text can start mid-way; more costs time and buys little.
                let stop = (i + len).min(hash_end);
                let mut j = i + 1;
                while j < stop.min(i + 3) {
                    table[(read4(buf, j).wrapping_mul(HASH_MUL) >> shift) as usize & mask] = j as u16;
                    j += 1;
                }
                if dist < len && stop > i + 3 {
                    // The match overlaps itself, so the text is periodic: index its last
                    // position as well, so that the next repeat finds the nearest copy
                    // (distance 1 for a run) instead of one a whole match back.
                    let j = stop - 1;
                    table[(read4(buf, j).wrapping_mul(HASH_MUL) >> shift) as usize & mask] = j as u16;
                }
                i += len;
                misses = 0;
                continue;
            }
            misses += 1;
            let step = (1 + (misses >> 4)).min(MAX_SKIP).min(end - i);
            for &b in &buf[i..i + step] {
                tokens[nt] = u32::from(b);
                nt += 1;
                lit_freq[b as usize] += 1;
            }
            i += step;
        }
        while i < end {
            tokens[nt] = u32::from(buf[i]);
            nt += 1;
            lit_freq[buf[i] as usize] += 1;
            i += 1;
        }
        nt
    }

    /// Chooses and writes the cheapest encoding of the current tokens. `raw` is the
    /// chunk's original bytes (for a stored block).
    fn write_block(&mut self, raw: &[u8], nt: usize, out: &mut Vec<u8>) {
        self.lit_freq[EOB] = 1;
        let fixed = fixed_codes();

        // ---- dynamic code and what it would cost ----
        build_lengths(&self.lit_freq[..286], MAX_CODE_BITS, &mut self.lit_len[..286]);
        self.lit_len[286..].fill(0);
        build_lengths(&self.dist_freq[..30], MAX_CODE_BITS, &mut self.dist_len[..30]);
        self.dist_len[30..].fill(0);
        let hlit = 1 + self.lit_len[..286].iter().rposition(|&l| l != 0).unwrap_or(EOB);
        let hdist = 1 + self.dist_len[..30].iter().rposition(|&l| l != 0).unwrap_or(0);
        let rle_len = self.rle_lengths(hlit, hdist);
        build_lengths(&self.cl_freq, 7, &mut self.cl_len);
        let hclen = (1 + CL_ORDER.iter().rposition(|&s| self.cl_len[s as usize] != 0).unwrap_or(0)).max(4);
        let mut header_bits = 14 + 3 * hclen as u64;
        for &t in &self.rle[..rle_len] {
            let sym = (t >> 8) as usize;
            header_bits += u64::from(self.cl_len[sym]) + [0, 2, 3, 7][sym.saturating_sub(15)];
        }
        let (mut dyn_bits, mut fixed_bits) = (3 + header_bits, 3u64);
        for s in 0..257 {
            let f = u64::from(self.lit_freq[s]);
            dyn_bits += f * u64::from(self.lit_len[s]);
            fixed_bits += f * u64::from(fixed.litlen_len[s]);
        }
        for s in 257..286 {
            let f = u64::from(self.lit_freq[s]);
            let extra = u64::from(LEN_EXTRA[s - 257]);
            dyn_bits += f * (u64::from(self.lit_len[s]) + extra);
            fixed_bits += f * (u64::from(fixed.litlen_len[s]) + extra);
        }
        for (d, &extra) in DIST_EXTRA.iter().enumerate() {
            let f = u64::from(self.dist_freq[d]);
            let extra = u64::from(extra);
            dyn_bits += f * (u64::from(self.dist_len[d]) + extra);
            fixed_bits += f * (5 + extra);
        }
        // ---- stored ----
        let pad = u64::from((8 - (self.nbits + 3) % 8) % 8);
        let stored_bits = 3 + pad + 32 + 8 * raw.len() as u64;

        let before = u64::from(self.nbits);
        let (kind, bits) = if raw.len() <= 65535 && stored_bits <= fixed_bits && stored_bits <= dyn_bits {
            (0, stored_bits)
        } else if fixed_bits <= dyn_bits {
            (1, fixed_bits)
        } else {
            (2, dyn_bits)
        };
        let whole = ((before + bits) / 8) as usize;
        let base = out.len();
        out.resize(base + whole + 16, 0);
        let mut sink = Sink { dst: &mut out[base..], pos: 0, acc: self.acc, nbits: self.nbits };
        match kind {
            0 => {
                sink.put(0, 3);
                sink.align();
                let len = raw.len() as u16;
                sink.bytes(&len.to_le_bytes());
                sink.bytes(&(!len).to_le_bytes());
                sink.bytes(raw);
            }
            1 => {
                sink.put(2, 3); // BFINAL = 0, BTYPE = 01
                emit_tokens(
                    &mut sink,
                    &self.tokens[..nt],
                    &fixed.litlen_code,
                    &fixed.litlen_len,
                    &fixed.dist_code,
                    &fixed.dist_len,
                );
                sink.put(u64::from(fixed.litlen_code[EOB]), u32::from(fixed.litlen_len[EOB]));
                sink.flush();
            }
            _ => {
                canonical_codes(&self.lit_len[..286], &mut self.lit_code[..286]);
                canonical_codes(&self.dist_len[..30], &mut self.dist_code[..30]);
                canonical_codes(&self.cl_len, &mut self.cl_code);
                sink.put(4, 3); // BFINAL = 0, BTYPE = 10
                sink.put((hlit - 257) as u64 | (((hdist - 1) as u64) << 5) | (((hclen - 4) as u64) << 10), 14);
                for &s in &CL_ORDER[..hclen] {
                    sink.put_safe(u64::from(self.cl_len[s as usize]), 3);
                }
                for &t in &self.rle[..rle_len] {
                    let sym = (t >> 8) as usize;
                    sink.put_safe(u64::from(self.cl_code[sym]), u32::from(self.cl_len[sym]));
                    match sym {
                        16 => sink.put_safe(u64::from(t & 0xff), 2),
                        17 => sink.put_safe(u64::from(t & 0xff), 3),
                        18 => sink.put_safe(u64::from(t & 0xff), 7),
                        _ => {}
                    }
                }
                sink.flush();
                emit_tokens(
                    &mut sink,
                    &self.tokens[..nt],
                    &self.lit_code,
                    &self.lit_len,
                    &self.dist_code,
                    &self.dist_len,
                );
                sink.put(u64::from(self.lit_code[EOB]), u32::from(self.lit_len[EOB]));
                sink.flush();
            }
        }
        debug_assert_eq!(sink.pos, whole, "block size accounting (kind {kind})");
        self.acc = sink.acc;
        self.nbits = sink.nbits;
        let used = sink.pos;
        out.truncate(base + used);
    }

    /// Run-length codes `lit_len[..hlit] ++ dist_len[..hdist]` (the two sequences form
    /// one, and a repeat may cross the boundary) into `rle` and counts the code-length
    /// symbols. Returns the number of entries.
    fn rle_lengths(&mut self, hlit: usize, hdist: usize) -> usize {
        self.cl_freq.fill(0);
        let total = hlit + hdist;
        let mut all = [0u8; 320];
        all[..hlit].copy_from_slice(&self.lit_len[..hlit]);
        all[hlit..total].copy_from_slice(&self.dist_len[..hdist]);
        let all = &all[..total];
        let mut n = 0usize;
        macro_rules! push {
            ($sym:expr, $extra:expr) => {{
                let sym: u16 = $sym;
                self.rle[n] = (sym << 8) | ($extra as u16);
                n += 1;
                self.cl_freq[sym as usize] += 1;
            }};
        }
        let mut i = 0usize;
        while i < total {
            let v = all[i];
            let mut run = 1usize;
            if v == 0 {
                // Zero runs are long (most of the alphabet is unused): eight at a time.
                while i + run + 8 <= total && all[i + run..i + run + 8] == [0u8; 8] {
                    run += 8;
                }
                while i + run < total && all[i + run] == 0 {
                    run += 1;
                }
                i += run;
                while run >= 11 {
                    let c = run.min(138);
                    push!(18, c - 11);
                    run -= c;
                }
                if run >= 3 {
                    push!(17, run - 3);
                    run = 0;
                }
                for _ in 0..run {
                    push!(0, 0);
                }
            } else {
                while i + run < total && all[i + run] == v {
                    run += 1;
                }
                i += run;
                push!(u16::from(v), 0);
                run -= 1;
                while run >= 3 {
                    let c = run.min(6);
                    push!(16, c - 3);
                    run -= c;
                }
                for _ in 0..run {
                    push!(u16::from(v), 0);
                }
            }
        }
        n
    }
}

/// Writes every token with the given codes. The accumulator holds fewer than 8 bits on
/// entry (10 after a block header) and is flushed once per token, or once per up to
/// three consecutive literals: a match token is at most 15 + 5 + 15 + 13 = 48 bits and
/// three literals 45, both within the 64 available.
#[inline(always)]
fn emit_tokens(sink: &mut Sink<'_>, tokens: &[u32], lc: &[u16; 288], ll: &[u8; 288], dc: &[u16; 32], dl: &[u8; 32]) {
    let n = tokens.len();
    let mut i = 0;
    while i < n {
        let t = tokens[i];
        i += 1;
        if t < 256 {
            sink.put(u64::from(lc[t as usize]), u32::from(ll[t as usize]));
            if i < n && tokens[i] < 256 {
                let u = tokens[i] as usize;
                sink.put(u64::from(lc[u]), u32::from(ll[u]));
                i += 1;
                if i < n && tokens[i] < 256 {
                    let v = tokens[i] as usize;
                    sink.put(u64::from(lc[v]), u32::from(ll[v]));
                    i += 1;
                }
            }
        } else {
            let l = ((t >> 16) & 0xff) as usize;
            let sym = 257 + LEN_CODE[l] as usize;
            let lbits = u32::from(ll[sym]);
            let lextra = u32::from(LEN_EXTRA_BITS[l]);
            let lx = (l as u64) & ((1u64 << lextra) - 1);
            sink.put(u64::from(lc[sym]) | (lx << lbits), lbits + lextra);
            let d = t & 0x7fff;
            let ds = dist_code(d);
            let dbits = u32::from(dl[ds]);
            let dextra = u32::from(DIST_EXTRA[ds]);
            let dx = u64::from(d) & ((1u64 << dextra) - 1);
            sink.put(u64::from(dc[ds]) | (dx << dbits), dbits + dextra);
        }
        sink.flush();
    }
}

/// A DEFLATE encoder, optionally keeping its history between calls.
pub struct Deflater {
    window_bits: u8,
    takeover: bool,
    state: StreamState,
}

impl Deflater {
    /// `window_bits` (8..=15) bounds match distances to `1 << window_bits`. With
    /// `context_takeover == false` every call is an independent stream (but still
    /// ends with a sync marker unless [`Flush::Finish`]) and nothing is kept.
    pub fn new(window_bits: u8, context_takeover: bool) -> Deflater {
        Deflater {
            window_bits: window_bits.clamp(MIN_WINDOW_BITS, MAX_WINDOW_BITS),
            takeover: context_takeover,
            state: StreamState::default(),
        }
    }

    pub fn window_bits(&self) -> u8 {
        self.window_bits
    }

    pub fn context_takeover(&self) -> bool {
        self.takeover
    }

    /// Heap held between calls (history buffer and hash table); 0 without takeover.
    pub fn heap_bytes(&self) -> usize {
        self.state.buf.capacity() + 2 * self.state.table.capacity()
    }

    /// Forgets the history; the next call starts a fresh stream.
    pub fn reset(&mut self) {
        self.state.buf.clear();
    }

    /// Forgets the history and frees its memory.
    pub fn release(&mut self) {
        self.state = StreamState::default();
    }

    /// Compresses `input`, appending the result to `out`. With [`Flush::Sync`] the
    /// output ends with `00 00 ff ff` and is decodable on its own given the history.
    pub fn deflate(&mut self, input: &[u8], out: &mut Vec<u8>, flush: Flush) {
        let window = 1usize << self.window_bits;
        let takeover = self.takeover;
        let chunk = chunk_for(self.window_bits, takeover);
        let hbits = hash_bits_for(self.window_bits, takeover);
        SCRATCH.with(|cell| {
            let mut guard = cell.borrow_mut();
            let Scratch { work, shared } = &mut **guard;
            let st = if takeover {
                &mut self.state
            } else {
                shared.buf.clear();
                shared
            };
            // The shared table is sized for the largest hash; a stream uses a prefix of it.
            let table_len = if takeover { 1usize << hbits } else { 1usize << MAX_HASH_BITS_SHARED };
            work.acc = 0;
            work.nbits = 0;
            for piece in input.chunks(chunk) {
                let at = st.append(piece, window, chunk, table_len, 1usize << hbits);
                let nt = work.find_matches(&st.buf, at, &mut st.table, hbits, window);
                work.write_block(&st.buf[at..], nt, out);
            }
            // Closing marker.
            let base = out.len();
            out.resize(base + 16, 0);
            let mut sink = Sink { dst: &mut out[base..], pos: 0, acc: work.acc, nbits: work.nbits };
            match flush {
                Flush::Sync => {
                    sink.put(0, 3); // BFINAL = 0, BTYPE = 00
                    sink.align();
                    sink.bytes(&SYNC_TAIL);
                }
                Flush::Finish => {
                    sink.put(3, 3); // BFINAL = 1, BTYPE = 01
                    sink.put(0, 7); // end of block (fixed code 0000000)
                    sink.align();
                }
            }
            let used = sink.pos;
            out.truncate(base + used);
            work.acc = 0;
            work.nbits = 0;
        });
        if flush == Flush::Finish {
            self.reset();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::testutil::{corpora, nostr_corpus, Rng};
    use crate::deflate::Inflater;

    fn compress(data: &[u8], window_bits: u8, takeover: bool) -> Vec<u8> {
        let mut out = Vec::new();
        Deflater::new(window_bits, takeover).deflate(data, &mut out, Flush::Sync);
        out
    }

    fn inflate(packed: &[u8], limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        Inflater::new(15, false).inflate(packed, &mut out, limit).expect("our own output must decode");
        out
    }

    #[test]
    fn empty_input_is_the_bare_marker() {
        assert_eq!(compress(b"", 15, false), [0x00, 0x00, 0x00, 0xff, 0xff]);
        let mut out = Vec::new();
        Deflater::new(15, false).deflate(b"", &mut out, Flush::Finish);
        assert_eq!(out, [0x03, 0x00]);
        assert_eq!(inflate(&out, 10), b"");
    }

    #[test]
    fn round_trip_every_corpus_every_window() {
        for (name, data) in corpora() {
            for wbits in [8u8, 12, 15] {
                for takeover in [false, true] {
                    let packed = compress(&data, wbits, takeover);
                    assert_eq!(packed[packed.len() - 4..], SYNC_TAIL, "{name}");
                    assert_eq!(inflate(&packed, data.len()), data, "{name} wbits {wbits} takeover {takeover}");
                }
            }
        }
    }

    #[test]
    fn round_trip_every_small_length() {
        let mut rng = Rng::new(21);
        let text = crate::deflate::testutil::words(&mut rng, 400);
        let hexes = crate::deflate::testutil::hex(&mut rng, 1200);
        for len in 0..600 {
            for data in [&text.as_bytes()[..len], &hexes[..len]] {
                assert_eq!(inflate(&compress(data, 15, false), len), data, "len {len}");
            }
        }
    }

    #[test]
    fn miniz_decodes_our_output() {
        for (name, data) in corpora() {
            for wbits in [9u8, 15] {
                let packed = compress(&data, wbits, false);
                // miniz wants a final block; ours ends with a sync marker, so decode as a
                // stream and compare what it produced.
                let got = miniz_inflate_stream(&[&packed], data.len() + 64);
                assert_eq!(got, data, "{name} wbits {wbits}");
                let mut fin = Vec::new();
                Deflater::new(wbits, false).deflate(&data, &mut fin, Flush::Finish);
                assert_eq!(miniz_oxide::inflate::decompress_to_vec(&fin).unwrap(), data, "{name} finish");
            }
        }
    }

    /// Decodes sync-flushed chunks with miniz's streaming inflater (raw, so no header),
    /// whose window carries over between calls. `cap` bounds one chunk's output.
    fn miniz_inflate_stream(chunks: &[&[u8]], cap: usize) -> Vec<u8> {
        use miniz_oxide::inflate::stream::{inflate, InflateState};
        use miniz_oxide::{DataFormat, MZError, MZFlush};
        let mut state = InflateState::new_boxed(DataFormat::Raw);
        let mut all = Vec::new();
        for chunk in chunks {
            let mut buf = vec![0u8; cap];
            let r = inflate(&mut state, chunk, &mut buf, MZFlush::Sync);
            assert!(matches!(r.status, Ok(_) | Err(MZError::Buf)), "miniz rejected our stream: {:?}", r.status);
            assert_eq!(r.bytes_consumed, chunk.len(), "miniz stopped early");
            all.extend_from_slice(&buf[..r.bytes_written]);
        }
        all
    }

    #[test]
    fn miniz_decodes_a_takeover_stream_message_by_message() {
        let events = nostr_corpus(9, 300);
        for wbits in [10u8, 15] {
            let mut d = Deflater::new(wbits, true);
            let packed: Vec<Vec<u8>> = events
                .iter()
                .map(|e| {
                    let mut out = Vec::new();
                    d.deflate(e, &mut out, Flush::Sync);
                    out
                })
                .collect();
            let refs: Vec<&[u8]> = packed.iter().map(Vec::as_slice).collect();
            assert_eq!(miniz_inflate_stream(&refs, 1 << 16), events.concat(), "wbits {wbits}");
            // And ours.
            let mut inf = Inflater::new(wbits, true);
            for (p, e) in packed.iter().zip(&events) {
                let mut out = Vec::new();
                inf.inflate(p, &mut out, 1 << 20).unwrap();
                assert_eq!(&out, e);
            }
        }
    }

    #[test]
    fn takeover_beats_independent_messages_on_repetitive_streams() {
        let events = nostr_corpus(2, 200);
        let mut with = Deflater::new(15, true);
        let mut without = Deflater::new(15, false);
        let (mut a, mut b) = (0, 0);
        for e in &events {
            let mut out = Vec::new();
            with.deflate(e, &mut out, Flush::Sync);
            a += out.len();
            let mut out = Vec::new();
            without.deflate(e, &mut out, Flush::Sync);
            b += out.len();
        }
        assert!(a * 10 < b * 9, "history should save at least 10%: {a} vs {b}");
    }

    #[test]
    fn window_bits_bound_the_distance() {
        // Two copies of a random block 3000 bytes apart: reachable with a 4096 window only.
        let mut rng = Rng::new(8);
        let block = rng.bytes(1500);
        let mut data = block.clone();
        data.extend(rng.bytes(1500));
        data.extend_from_slice(&block);
        let wide = compress(&data, 12, false).len();
        let narrow = compress(&data, 11, false).len();
        assert!(wide + 1000 < narrow, "{wide} vs {narrow}");
        // Whatever the window, no distance may exceed it: a decoder with exactly that
        // history must accept the stream.
        for wbits in 8..=15u8 {
            let d = crate::deflate::testutil::nostr_corpus(5, 80).concat();
            let packed = compress(&d, wbits, false);
            let mut out = Vec::new();
            Inflater::new(wbits, false).inflate(&packed, &mut out, 1 << 20).unwrap();
            assert_eq!(out, d);
            // And streaming with history of exactly that size.
            let mut enc = Deflater::new(wbits, true);
            let mut dec = Inflater::new(wbits, true);
            let mut got = Vec::new();
            for piece in d.chunks(700) {
                let mut p = Vec::new();
                enc.deflate(piece, &mut p, Flush::Sync);
                dec.inflate(&p, &mut got, 1 << 20).unwrap_or_else(|e| panic!("wbits {wbits}: {e}"));
            }
            assert_eq!(got, d, "wbits {wbits}");
        }
    }

    #[test]
    fn incompressible_data_grows_by_a_few_bytes_only() {
        let mut rng = Rng::new(77);
        for len in [1usize, 10, 100, 1000, 16_384, 20_000, 200_000] {
            let data = rng.bytes(len);
            let packed = compress(&data, 15, false);
            let blocks = len.div_ceil(CHUNK_MAX);
            // 5 bytes of stored framing per block, plus the 1-byte-ish marker and 4-byte tail.
            assert!(packed.len() <= len + 5 * blocks + 6, "len {len}: {}", packed.len());
            assert_eq!(inflate(&packed, len), data);
        }
    }

    #[test]
    fn block_type_choice_follows_the_cheapest_encoding() {
        let first_block_type = |packed: &[u8]| (packed[0] >> 1) & 3;
        // Random bytes: stored.
        assert_eq!(first_block_type(&compress(&Rng::new(1).bytes(500), 15, false)), 0);
        // A handful of bytes: fixed Huffman (no header to pay for).
        assert_eq!(first_block_type(&compress(b"hello hello hello", 15, false)), 1);
        // A long skewed text: dynamic.
        let text = crate::deflate::testutil::words(&mut Rng::new(2), 500);
        assert_eq!(first_block_type(&compress(text.as_bytes(), 15, false)), 2);
        // Hex digits: dynamic with 4-bit codes, about half the size.
        let hex = crate::deflate::testutil::hex(&mut Rng::new(3), 4000);
        let packed = compress(&hex, 15, false);
        assert_eq!(first_block_type(&packed), 2);
        assert!(packed.len() < 2100 && packed.len() > 2000, "{}", packed.len());
    }

    #[test]
    fn long_runs_use_long_matches() {
        let packed = compress(&vec![b'a'; 100_000], 15, false);
        assert!(packed.len() < 500, "{}", packed.len());
        assert_eq!(inflate(&packed, 100_000), vec![b'a'; 100_000]);
        // Length 258 and 3..=10 byte periods.
        for period in 1..12usize {
            let data: Vec<u8> = (0..5000).map(|i| (i % period) as u8 * 7 + b'a').collect();
            assert_eq!(inflate(&compress(&data, 15, false), data.len()), data, "period {period}");
        }
    }

    #[test]
    fn large_inputs_become_many_blocks_and_stay_correct() {
        let data = nostr_corpus(4, 3000).concat();
        assert!(data.len() > 1_000_000);
        let packed = compress(&data, 15, false);
        assert_eq!(inflate(&packed, data.len()), data);
        assert!(packed.len() < data.len() * 6 / 10, "{} of {}", packed.len(), data.len());
    }

    #[test]
    fn finish_stream_is_final_and_resets_history() {
        let mut d = Deflater::new(15, true);
        let mut a = Vec::new();
        d.deflate(b"abcabcabcabcabc", &mut a, Flush::Sync);
        let mut b = Vec::new();
        d.deflate(b"abcabcabcabcabc", &mut b, Flush::Finish);
        // The finished stream began with the history; a new one must not.
        let mut c = Vec::new();
        d.deflate(b"abcabcabcabcabc", &mut c, Flush::Finish);
        assert_eq!(miniz_oxide::inflate::decompress_to_vec(&c).unwrap(), b"abcabcabcabcabc");
        assert!(b.len() < c.len() + 8, "{} vs {}", b.len(), c.len());
        assert_eq!(c.last(), Some(&0x00));
    }

    #[test]
    fn interleaved_streams_share_the_scratch_without_interference() {
        // Takeover and history-free streams, several of each, taking turns on one thread.
        let events = nostr_corpus(6, 120);
        let mut enc: Vec<Deflater> = (0..4).map(|i| Deflater::new([15u8, 12, 15, 9][i], i % 2 == 0)).collect();
        let mut dec: Vec<Inflater> = (0..4).map(|i| Inflater::new([15u8, 12, 15, 9][i], i % 2 == 0)).collect();
        for (n, e) in events.iter().enumerate() {
            let k = n % 4;
            let mut p = Vec::new();
            enc[k].deflate(e, &mut p, Flush::Sync);
            let mut out = Vec::new();
            dec[k].inflate(&p, &mut out, 1 << 20).unwrap();
            assert_eq!(&out, e, "message {n} on stream {k}");
        }
    }

    #[test]
    fn output_is_appended_and_deterministic() {
        let data = nostr_corpus(1, 5).concat();
        let a = compress(&data, 15, false);
        let b = compress(&data, 15, false);
        assert_eq!(a, b);
        let mut out = b"keep me".to_vec();
        Deflater::new(15, false).deflate(&data, &mut out, Flush::Sync);
        assert_eq!(&out[..7], b"keep me");
        assert_eq!(&out[7..], &a[..]);
    }

    #[test]
    fn sliding_the_window_keeps_matches_valid() {
        // Many messages, so the buffer slides repeatedly; every match is re-verified by
        // the decoder, and the stream must keep compressing (stale entries rebased, not lost).
        let events = nostr_corpus(13, 800);
        let mut enc = Deflater::new(15, true);
        let mut dec = Inflater::new(15, true);
        let mut total_in = 0;
        let mut total_out = 0;
        for e in &events {
            let mut p = Vec::new();
            enc.deflate(e, &mut p, Flush::Sync);
            let mut out = Vec::new();
            dec.inflate(&p, &mut out, 1 << 20).unwrap();
            assert_eq!(&out, e);
            total_in += e.len();
            total_out += p.len();
        }
        assert!(total_out * 100 < total_in * 62, "ratio {total_out}/{total_in}");
        assert!(enc.heap_bytes() <= 64 * 1024, "heap {}", enc.heap_bytes());
    }

    #[test]
    fn history_free_streams_hold_no_memory() {
        let mut d = Deflater::new(15, false);
        let mut out = Vec::new();
        d.deflate(&nostr_corpus(1, 50).concat(), &mut out, Flush::Sync);
        assert_eq!(d.heap_bytes(), 0);
        let mut t = Deflater::new(15, true);
        t.deflate(&nostr_corpus(1, 50).concat(), &mut out, Flush::Sync);
        assert!(t.heap_bytes() > 0 && t.heap_bytes() <= (32 + 16 + 16) * 1024);
        t.release();
        assert_eq!(t.heap_bytes(), 0);
    }

    #[test]
    fn rle_of_code_lengths_round_trips_through_the_decoder() {
        // Histograms with long zero runs, repeated lengths, and a single used symbol
        // exercise every code-length symbol (16, 17, 18).
        let mut rng = Rng::new(55);
        for case in 0..300 {
            let n = 1 + rng.below(2000) as usize;
            let alphabet = [2u64, 3, 16, 60, 200][case % 5];
            let data: Vec<u8> = (0..n)
                .map(|_| if case % 7 == 0 { b'z' } else { (rng.below(alphabet) as u8).wrapping_mul(case as u8 | 1) })
                .collect();
            assert_eq!(inflate(&compress(&data, 15, false), n), data, "case {case}");
        }
    }

    #[test]
    fn random_message_sequences_round_trip_through_both_decoders() {
        use crate::deflate::testutil::{base64, hex, words};
        let mut rng = Rng::new(0x5EED);
        for seq in 0..120 {
            let wbits = 8 + rng.below(8) as u8;
            let takeover = seq % 3 != 0;
            let mut enc = Deflater::new(wbits, takeover);
            let mut ours = Inflater::new(wbits, takeover);
            let mut messages: Vec<Vec<u8>> = Vec::new();
            let mut packed: Vec<Vec<u8>> = Vec::new();
            for _ in 0..1 + rng.below(30) {
                let n = match rng.below(6) {
                    0 => 0,
                    1 => rng.below(8) as usize,
                    2 => rng.below(300) as usize,
                    3 => rng.below(3000) as usize,
                    4 => rng.below(40_000) as usize,
                    _ => rng.below(120_000) as usize,
                };
                let mut m = match rng.below(6) {
                    0 => rng.bytes(n),
                    1 => hex(&mut rng, n),
                    2 => base64(&mut rng, n),
                    3 => words(&mut rng, n / 5 + 1).into_bytes(),
                    4 => vec![b'x'; n],
                    _ => nostr_corpus(rng.below(1000), 1 + n / 600).concat(),
                };
                // Repeat earlier content now and then, so history is actually used.
                if rng.below(3) == 0 && !messages.is_empty() {
                    let from = &messages[rng.below(messages.len() as u64) as usize];
                    m.extend_from_slice(&from[..from.len().min(5000)]);
                }
                let mut p = Vec::new();
                enc.deflate(&m, &mut p, Flush::Sync);
                let mut out = Vec::new();
                ours.inflate(&p, &mut out, m.len()).unwrap_or_else(|e| panic!("seq {seq} ({wbits}, {takeover}): {e}"));
                assert_eq!(out, m, "seq {seq}");
                messages.push(m);
                packed.push(p);
            }
            if takeover {
                // miniz decodes the whole sequence as one stream (its window is always 32 KiB, a
                // superset of ours, so any window size we honoured is fine for it).
                let refs: Vec<&[u8]> = packed.iter().map(Vec::as_slice).collect();
                let cap = messages.iter().map(Vec::len).max().unwrap_or(0) + 64;
                assert_eq!(miniz_inflate_stream(&refs, cap), messages.concat(), "seq {seq}");
            } else {
                for (p, m) in packed.iter().zip(&messages) {
                    assert_eq!(&miniz_inflate_stream(&[p], m.len() + 64), m, "seq {seq}");
                }
            }
        }
    }

    #[test]
    fn corrupted_encoder_output_and_garbage_never_panic() {
        let mut rng = Rng::new(0xBADC0DE);
        // Our own streams, with and without history, as the base for damage.
        let mut streams: Vec<(Vec<u8>, bool)> = Vec::new();
        for (_, data) in corpora().into_iter().filter(|(_, d)| !d.is_empty() && d.len() < 40_000) {
            streams.push((compress(&data, 15, false), false));
        }
        let events = nostr_corpus(77, 40);
        let mut enc = Deflater::new(15, true);
        for e in &events {
            let mut p = Vec::new();
            enc.deflate(e, &mut p, Flush::Sync);
            streams.push((p, true));
        }
        let mut accepted = 0;
        let cases = 12_000;
        for case in 0..cases {
            let (base, _) = &streams[rng.below(streams.len() as u64) as usize];
            let mut s = base.clone();
            match rng.below(5) {
                0 => {
                    let i = rng.below(s.len() as u64) as usize;
                    s[i] ^= 1 << rng.below(8);
                }
                1 => {
                    for _ in 0..1 + rng.below(6) {
                        let i = rng.below(s.len() as u64) as usize;
                        s[i] = rng.next() as u8;
                    }
                }
                2 => {
                    let cut = rng.below(s.len() as u64 + 1) as usize;
                    s.truncate(cut);
                }
                3 => {
                    // Pure garbage of a plausible length, sometimes starting like a real block.
                    let n = rng.below(400) as usize;
                    s = rng.bytes(n);
                    if rng.below(2) == 0 && !s.is_empty() {
                        s[0] = [0x04, 0x05, 0x02, 0x03, 0x01][rng.below(5) as usize] | (s[0] & 0xf8);
                    }
                }
                _ => {
                    let at = rng.below(s.len() as u64 + 1) as usize;
                    let n = 1 + rng.below(6) as usize;
                    let junk = rng.bytes(n);
                    s.splice(at..at, junk);
                }
            }
            for message_mode in [false, true] {
                let mut out = Vec::new();
                let mut inf = Inflater::new(15, true);
                let limit = 1 << 20;
                let r = if message_mode {
                    inf.inflate_message(&s, &mut out, limit)
                } else {
                    inf.inflate(&s, &mut out, limit)
                };
                match r {
                    Ok(n) => {
                        accepted += 1;
                        assert_eq!(n, out.len(), "case {case}");
                        assert!(n <= limit);
                    }
                    Err(_) => assert!(out.is_empty(), "case {case}: output must be rolled back"),
                }
            }
        }
        assert!(accepted < cases, "some damage must be caught");
    }
}
