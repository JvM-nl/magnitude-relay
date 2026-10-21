//! Raw DEFLATE decoder (RFC 1951).
//!
//! **Contract.** [`Inflater::inflate`] takes input made of *complete blocks* and
//! appends the decoded bytes to a caller's `Vec`, producing at most `limit` of them.
//! Anything that ends inside a block is [`InflateError::Truncated`]; there is no
//! mid-block resume, because the only caller (a WebSocket message) always has the
//! whole message in hand, and refusing partial blocks lets the Huffman tables live
//! in a shared scratch instead of in every connection. What *does* persist between
//! calls is the history window, so a sequence of sync-flushed messages decodes as
//! one stream (permessage-deflate "context takeover"). [`Inflater::inflate_message`]
//! is the RFC 7692 form: it behaves as if `00 00 ff ff` were appended to the input
//! (without copying it) and insists the message ends exactly on a block boundary.
//!
//! **Tables.** One lookup decodes a codeword. An 11-bit first-level table (8 for
//! distances) resolves every code that short directly; longer codes go through a
//! sub-table. Entries carry everything the loop needs: codeword length, the extra-bit
//! count, and either the literal, the base length/distance, or an end-of-block /
//! sub-table-pointer / invalid flag, so a length or distance is one lookup plus one
//! mask of the bit buffer. The construction is zlib's `inflate_table` (the sub-table
//! sizing that keeps tables minimal), with zlib's acceptance rules: over-subscribed
//! codes are errors, incomplete ones are errors except the lone one-bit code.
//!
//! **Two loops.** The fast loop runs while there are at least 8 input bytes (so the
//! branch-free 64-bit refill is legal) and at least `SLACK` (400) bytes of output space
//! (so no write needs a bounds decision beyond the slice's own check): one refill
//! guarantees 56 bits, enough for a literal chain, and a full length+distance pair
//! needs at most 48. It decodes runs of literals per refill and copies matches eight
//! bytes at a time. The checked loop takes over for the last few symbols of the
//! input; it re-derives every bound per symbol and is also the reference the fast
//! loop is tested against.
//!
//! **Output and the limit.** Output is written straight into the caller's `Vec`
//! (zero-filled ahead of the write position, trimmed at the end). The buffer never
//! grows past `limit + SLACK`, and the call fails the moment a symbol would cross
//! `limit`, so a bomb allocates what the caller allows and no more.
//!
//! **History.** After a successful call the last `1 << window_bits` bytes produced
//! are kept in a ring that is only as long as the data so far (an idle connection
//! that has received little holds little). A match reaching before this call's
//! output is served from the ring; one reaching before the ring is an error.
//!
//! **Failure is final.** After any error the stream is dead: the history is dropped
//! and every later call fails, so a half-applied message can never be decoded
//! against a wrong window.

use super::huffman::for_each_nonzero;
use super::tables::*;
use std::cell::RefCell;
use std::fmt;
use std::sync::OnceLock;

/// Why a stream was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateError {
    /// The input ended inside a block, or a message did not end on a block boundary.
    Truncated,
    /// Not valid DEFLATE; the text names the construct.
    Malformed(&'static str),
    /// The output would exceed the caller's limit.
    LimitExceeded,
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InflateError::Truncated => f.write_str("deflate stream truncated"),
            InflateError::Malformed(why) => write!(f, "invalid deflate stream: {why}"),
            InflateError::LimitExceeded => f.write_str("decompressed data exceeds the limit"),
        }
    }
}

impl std::error::Error for InflateError {}

/// Output space the fast loop needs ahead of its write position. One refill (56
/// bits) feeds at most 56 literals (1-bit codes) before the loop refills and
/// re-checks, a match writes at most 258 bytes plus up to 7 bytes of word-copy
/// overshoot, and the literal chain may follow it within the same refill's budget.
const SLACK: usize = 400;

// ---- table entries ----
//
// bits 0..8   codeword length (for a sub-table entry: the whole codeword, root bits included)
// bits 8..12  extra-bit count (length/distance); for a sub-table pointer: the sub-table's index bits
// bits 12..16 flags; a literal has none, so `entry & F_ANY == 0` is the literal test
// bits 16..32 literal byte / base length or distance / sub-table offset

const F_LEN: u32 = 1 << 12;
const F_EOB: u32 = 1 << 13;
const F_SUB: u32 = 1 << 14;
const F_BAD: u32 = 1 << 15;
const F_ANY: u32 = 0xF000;

const LIT_ROOT: u32 = 11;
const DIST_ROOT: u32 = 8;
const CL_ROOT: u32 = 7;
/// Room for an 11-bit root plus sub-tables of any complete 288-symbol code (the worst
/// case is a little over 2300 entries); the builder checks it anyway.
const LIT_CAP: usize = 3072;
/// Same for 8-bit distance tables (worst case about 400).
const DIST_CAP: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    LitLen,
    Dist,
    CodeLen,
}

/// Entries (minus their codeword length) for every literal/length symbol, built at
/// compile time so the table builder does one load per symbol.
static LITLEN_TEMPLATE: [u32; LITLEN_SYMBOLS] = {
    let mut t = [F_BAD; LITLEN_SYMBOLS];
    let mut s = 0;
    while s < 256 {
        t[s] = (s as u32) << 16;
        s += 1;
    }
    t[EOB] = F_EOB;
    while s < 286 {
        if s > EOB {
            t[s] = F_LEN | ((LEN_EXTRA[s - 257] as u32) << 8) | ((LEN_BASE[s - 257] as u32) << 16);
        }
        s += 1;
    }
    t
};

static DIST_TEMPLATE: [u32; DIST_SYMBOLS] = {
    let mut t = [F_BAD; DIST_SYMBOLS];
    let mut s = 0;
    while s < 30 {
        t[s] = F_LEN | ((DIST_EXTRA[s] as u32) << 8) | ((DIST_BASE[s] as u32) << 16);
        s += 1;
    }
    t
};

/// The entry for `sym` minus its codeword length.
#[inline(always)]
fn template(kind: Kind, sym: usize) -> u32 {
    match kind {
        Kind::CodeLen => (sym as u32) << 16,
        Kind::LitLen => LITLEN_TEMPLATE[sym],
        Kind::Dist => DIST_TEMPLATE[sym],
    }
}

/// Builds a decode table for `lens` into `table`; see [`build_table_generic`] for the
/// contract. When no codeword is longer than the first-level width (nearly always for
/// the small blocks a relay sees) this takes the doubling path below, which writes each
/// codeword once and fills the rest of the table with block copies instead of one
/// store per slot: for a 10-bit table that is about 60 stores and a 4 KiB `memmove`
/// instead of 1024 checked stores. Both paths produce identical tables (a test builds
/// random codes both ways).
#[inline(never)]
fn build_table(lens: &[u8], root_req: u32, kind: Kind, table: &mut [u32]) -> Result<u32, InflateError> {
    let mut count = [0u16; 16];
    let mut any = 0u8;
    for_each_nonzero(lens, |_, l| {
        count[(l & 15) as usize] += 1;
        any |= l;
    });
    if any > 15 {
        return Err(InflateError::Malformed("code length out of range"));
    }
    let mut max = 15usize;
    while max > 0 && count[max] == 0 {
        max -= 1;
    }
    if max == 0 || max > root_req as usize {
        return build_table_generic(lens, root_req, kind, table);
    }
    // Over-subscribed is an error; incomplete only for the lone one-bit code.
    let mut left = 1i32;
    for &c in &count[1..] {
        left = (left << 1) - i32::from(c);
        if left < 0 {
            return Err(InflateError::Malformed("over-subscribed code lengths"));
        }
    }
    if left > 0 && (kind == Kind::CodeLen || max != 1) {
        return Err(InflateError::Malformed("incomplete code lengths"));
    }
    if table.len() < 1 << max {
        return Err(InflateError::Malformed("decode table overflow"));
    }
    // Symbols sorted by (length, symbol).
    let mut offs = [0u16; 16];
    for len in 1..15 {
        offs[len + 1] = offs[len] + count[len];
    }
    let mut work = [0u16; LITLEN_SYMBOLS];
    for_each_nonzero(lens, |sym, l| {
        work[offs[l as usize] as usize] = sym as u16;
        offs[l as usize] += 1;
    });
    // Canonical codes in order; a codeword of length `len` lands at its bit-reversed value
    // (the bit buffer is LSB-first), and after each length the filled prefix is doubled so
    // every slot whose low `len` bits match the codeword holds its entry.
    let mut code = 0u32;
    let mut next = 0usize;
    for (len, &n) in count.iter().enumerate().take(max + 1).skip(1) {
        for _ in 0..n {
            let rev = (code.reverse_bits() >> (32 - len)) as usize;
            table[rev] = template(kind, work[next] as usize) | len as u32;
            next += 1;
            code += 1;
        }
        if len < max {
            table.copy_within(0..1 << len, 1 << len);
        }
        code <<= 1;
    }
    if left > 0 {
        // The lone one-bit code leaves slot 1 without an entry.
        table[1] = F_BAD | 1;
    }
    Ok(max as u32)
}

/// The general builder: a port of zlib's `inflate_table` (see the module docs).
#[inline(never)]
fn build_table_generic(lens: &[u8], root_req: u32, kind: Kind, table: &mut [u32]) -> Result<u32, InflateError> {
    debug_assert!(lens.len() <= LITLEN_SYMBOLS);
    let mut count = [0u16; 16];
    for &l in lens {
        if l > 15 {
            return Err(InflateError::Malformed("code length out of range"));
        }
        count[l as usize] += 1;
    }
    count[0] = 0;
    let mut max = 15usize;
    while max > 0 && count[max] == 0 {
        max -= 1;
    }
    if max == 0 {
        // No codes at all. For distances that is legal (a block of literals only); any
        // distance symbol then decodes to an invalid entry. It can't be a code-length code.
        if kind == Kind::CodeLen || table.len() < 2 {
            return Err(InflateError::Malformed("empty code"));
        }
        table[0] = F_BAD | 1;
        table[1] = F_BAD | 1;
        return Ok(1);
    }
    let mut min = 1usize;
    while min < max && count[min] == 0 {
        min += 1;
    }
    let root = (root_req as usize).clamp(min, max);

    // Over-subscribed is always an error; incomplete only for the lone one-bit code.
    let mut left = 1i32;
    for &c in &count[1..] {
        left = (left << 1) - i32::from(c);
        if left < 0 {
            return Err(InflateError::Malformed("over-subscribed code lengths"));
        }
    }
    if left > 0 && (kind == Kind::CodeLen || max != 1) {
        return Err(InflateError::Malformed("incomplete code lengths"));
    }

    // Symbols sorted by (length, symbol).
    let mut offs = [0u16; 16];
    for len in 1..15 {
        offs[len + 1] = offs[len] + count[len];
    }
    let mut work = [0u16; LITLEN_SYMBOLS];
    for (sym, &l) in lens.iter().enumerate() {
        if l != 0 {
            work[offs[l as usize] as usize] = sym as u16;
            offs[l as usize] += 1;
        }
    }

    let overflow = InflateError::Malformed("decode table overflow");
    let mut cnt = count;
    let mut huff = 0usize; // the codeword being placed, bit-reversed
    let mut sym = 0usize;
    let mut len = min;
    let mut next = 0usize; // start of the (sub-)table being filled
    let mut curr = root; // index bits of that table
    let mut drop = 0usize; // bits already resolved by the root table
    let mut low = usize::MAX; // root slot of the sub-table in progress
    let mut used = 1usize << root;
    let mask = used - 1;
    if used > table.len() {
        return Err(overflow);
    }
    loop {
        let here = template(kind, work[sym] as usize) | len as u32;
        // Replicate across every slot whose low (len - drop) bits match the code.
        let step = 1usize << (len - drop);
        let size = 1usize << curr;
        let mut fill = size;
        loop {
            fill = fill.checked_sub(step).ok_or(overflow)?;
            table[next + (huff >> drop) + fill] = here;
            if fill == 0 {
                break;
            }
        }
        // Increment the bit-reversed codeword.
        let mut bit = 1usize << (len - 1);
        while huff & bit != 0 {
            bit >>= 1;
        }
        if bit != 0 {
            huff = (huff & (bit - 1)) + bit;
        } else {
            huff = 0;
        }
        sym += 1;
        cnt[len] -= 1;
        if cnt[len] == 0 {
            if len == max {
                break;
            }
            len = lens[work[sym] as usize] as usize;
        }
        if len > root && (huff & mask) != low {
            // First code of a new sub-table.
            if drop == 0 {
                drop = root;
            }
            next += size;
            curr = len - drop;
            let mut room = 1i32 << curr;
            while curr + drop < max {
                room -= i32::from(cnt[curr + drop]);
                if room <= 0 {
                    break;
                }
                curr += 1;
                room <<= 1;
            }
            used += 1usize << curr;
            if used > table.len() {
                return Err(overflow);
            }
            low = huff & mask;
            table[low] = F_SUB | ((curr as u32) << 8) | ((next as u32) << 16) | root as u32;
        }
    }
    if huff != 0 {
        // Incomplete code (the lone one-bit case): the unused slot is invalid.
        table[next + huff] = F_BAD | (len - drop) as u32;
    }
    Ok(root as u32)
}

/// Decode tables for one block, borrowed from the scratch or from the static fixed set.
#[derive(Clone, Copy)]
struct Codes<'t> {
    lit: &'t [u32],
    lit_bits: u32,
    dist: &'t [u32],
    dist_bits: u32,
}

struct Fixed {
    lit: Vec<u32>,
    lit_bits: u32,
    dist: Vec<u32>,
    dist_bits: u32,
}

/// The fixed-Huffman tables, built once for the process.
fn fixed() -> &'static Fixed {
    static FIXED: OnceLock<Fixed> = OnceLock::new();
    FIXED.get_or_init(|| {
        let mut lit = vec![0u32; LIT_CAP];
        let mut dist = vec![0u32; DIST_CAP];
        // Both fixed codes are complete and tiny: cannot fail.
        let lit_bits = build_table(&FIXED_LITLEN_LENS, LIT_ROOT, Kind::LitLen, &mut lit).unwrap_or(1);
        let dist_bits = build_table(&FIXED_DIST_LENS, DIST_ROOT, Kind::Dist, &mut dist).unwrap_or(1);
        Fixed { lit, lit_bits, dist, dist_bits }
    })
}

/// Working tables for dynamic blocks, shared by every stream on the thread.
struct Scratch {
    lit: [u32; LIT_CAP],
    dist: [u32; DIST_CAP],
    cl: [u32; 1 << CL_ROOT],
    lens: [u8; LITLEN_SYMBOLS + DIST_SYMBOLS],
}

thread_local! {
    static SCRATCH: RefCell<Box<Scratch>> = RefCell::new(Box::new(Scratch {
        lit: [0; LIT_CAP],
        dist: [0; DIST_CAP],
        cl: [0; 1 << CL_ROOT],
        lens: [0; LITLEN_SYMBOLS + DIST_SYMBOLS],
    }));
}

#[inline(always)]
fn le64(b: &[u8], i: usize) -> u64 {
    let s = &b[i..i + 8];
    u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
}

/// The history ring, as the loops see it.
#[derive(Clone, Copy)]
struct Win<'a> {
    data: &'a [u8],
    /// Index of the oldest byte once the ring is full, 0 before.
    pos: usize,
}

/// Copies a match whose source starts before this call's output (`dist > o`):
/// first from the history ring, then, if the match is longer than the part of it
/// that lies in history, from the start of this call's output.
fn copy_far(buf: &mut [u8], o: usize, dist: usize, len: usize, w: Win<'_>) -> Result<(), InflateError> {
    let back = dist - o; // how far before this call's first byte the match starts
    let hlen = w.data.len();
    if back > hlen {
        return Err(InflateError::Malformed("distance too far back"));
    }
    let take = len.min(back);
    let mut si = (w.pos + hlen - back) % hlen;
    let mut k = 0;
    while k < take {
        let run = (take - k).min(hlen - si);
        if si + run + 8 <= hlen && o + k + run + 8 <= buf.len() {
            // Room to overshoot on both sides: whole words, no call. Matches into the
            // history are mostly short strings seen before (a pubkey, a tag name), where a
            // `memmove` call costs more than the copy. The overshoot is overwritten or trimmed.
            let mut j = 0;
            while j < run {
                let v = le64(w.data, si + j);
                buf[o + k + j..o + k + j + 8].copy_from_slice(&v.to_le_bytes());
                j += 8;
            }
        } else {
            buf[o + k..o + k + run].copy_from_slice(&w.data[si..si + run]);
        }
        k += run;
        si += run;
        if si == hlen {
            si = 0;
        }
    }
    // Byte k of the match sits `dist` behind position `o + k`, i.e. at `k - back` here.
    for k in take..len {
        buf[o + k] = buf[k - back];
    }
    Ok(())
}

/// Bit input over the message plus its virtual tail. All the slow, simple code uses
/// the methods; the hot loops copy the fields into locals.
struct Ctx<'a> {
    input: &'a [u8],
    tail: &'a [u8],
    n: usize,
    total: usize,
    /// Next unread byte of `input ++ tail`. Bytes sitting in `bb` count as read.
    ip: usize,
    bb: u64,
    bc: u32,
}

impl Ctx<'_> {
    /// Tops the bit buffer up to more than 56 bits, or to the end of the input.
    #[inline]
    fn pull(&mut self) {
        if self.bc > 56 {
            return;
        }
        if self.ip + 8 <= self.n {
            // The fast loop's branch-free refill (see `fast`): whole bytes up to 56..63 bits.
            self.bb |= le64(self.input, self.ip) << self.bc;
            self.ip += ((63 - self.bc) >> 3) as usize;
            self.bc |= 56;
            return;
        }
        while self.bc <= 56 && self.ip < self.total {
            let b = if self.ip < self.n { self.input[self.ip] } else { self.tail[self.ip - self.n] };
            self.bb |= u64::from(b) << self.bc;
            self.ip += 1;
            self.bc += 8;
        }
    }

    #[inline]
    fn get(&mut self, n: u32) -> Result<u32, InflateError> {
        if self.bc < n {
            self.pull();
            if self.bc < n {
                return Err(InflateError::Truncated);
            }
        }
        let v = (self.bb & ((1u64 << n) - 1)) as u32;
        self.bb >>= n;
        self.bc -= n;
        Ok(v)
    }

    /// Drops the unread bits of the current byte.
    #[inline]
    fn align(&mut self) {
        let d = self.bc & 7;
        self.bb >>= d;
        self.bc -= d;
    }
}

/// Makes the output region at least `need` bytes long, growing geometrically but
/// never past `hard_cap`. False if `need` itself exceeds the cap.
fn grow(out: &mut Vec<u8>, start: usize, need: usize, hard_cap: usize) -> bool {
    let region = out.len() - start;
    if region >= need {
        return true;
    }
    if need > hard_cap {
        return false;
    }
    let target = region.saturating_mul(2).min(hard_cap).max(need);
    // `reserve_exact`: `resize` alone would round the capacity up geometrically and
    // let a bomb's allocation overshoot the limit by up to double.
    out.reserve_exact(start + target - out.len());
    out.resize(start + target, 0);
    true
}

/// Checked-loop helper: room for `need` more bytes at `op`, within `limit`.
#[inline]
fn room(
    out: &mut Vec<u8>,
    start: usize,
    op: usize,
    need: usize,
    limit: usize,
    hard_cap: usize,
) -> Result<(), InflateError> {
    if need > limit.saturating_sub(op) {
        return Err(InflateError::LimitExceeded);
    }
    if !grow(out, start, op + need, hard_cap) {
        return Err(InflateError::LimitExceeded);
    }
    Ok(())
}

enum Exit {
    Eob,
    /// Less than [`SLACK`] output bytes left in the buffer.
    Space,
    /// Fewer than 8 input bytes left.
    Input,
}

/// The fast loop. Preconditions: `buf.len() >= SLACK`. It decodes until the end of
/// the block, or until it could no longer prove its next iteration safe.
#[inline(never)]
fn fast(cx: &mut Ctx<'_>, buf: &mut [u8], op: &mut usize, c: &Codes<'_>, w: Win<'_>) -> Result<Exit, InflateError> {
    let input = cx.input;
    let n = cx.n;
    let mut ip = cx.ip;
    let mut bb = cx.bb;
    let mut bc = cx.bc;
    let mut o = *op;
    let lim = buf.len() - SLACK;
    let (lit, dtab) = (c.lit, c.dist);
    let (lroot, droot) = (c.lit_bits, c.dist_bits);
    let (lmask, dmask) = ((1u64 << lroot) - 1, (1u64 << droot) - 1);

    // Branch-free refill: whole bytes up to 56..63 bits. The load is 8 bytes; bits
    // above the ones accounted for in `bc` are the following input bytes, so OR-ing
    // them in again on the next refill is idempotent.
    macro_rules! refill {
        () => {{
            bb |= le64(input, ip) << bc;
            ip += ((63 - bc) >> 3) as usize;
            bc |= 56;
        }};
    }

    let exit = 'main: loop {
        if ip + 8 > n {
            break Exit::Input;
        }
        if o > lim {
            break Exit::Space;
        }
        refill!();
        let mut e = lit[(bb & lmask) as usize];
        // A run of plain literals needs no refill until fewer than 15 bits remain.
        while e & F_ANY == 0 {
            // The shift count is the entry's low byte, always under 16, so masking to six
            // bits is the same value and the mask is free on hardware that ignores the rest.
            let cw = e & 63;
            bb >>= cw;
            bc -= cw;
            buf[o] = (e >> 16) as u8;
            o += 1;
            if bc < 15 {
                continue 'main;
            }
            e = lit[(bb & lmask) as usize];
        }
        // A length and distance pair together need up to 48 bits.
        if bc < 48 {
            if ip + 8 > n {
                break Exit::Input;
            }
            refill!();
        }
        if e & F_SUB != 0 {
            let sb = (e >> 8) & 15;
            e = lit[(e >> 16) as usize + ((bb >> lroot) as usize & ((1usize << sb) - 1))];
        }
        let cw = e & 63;
        bb >>= cw;
        bc -= cw;
        if e & F_LEN != 0 {
            let xb = (e >> 8) & 15;
            let len = (e >> 16) as usize + (bb as usize & ((1usize << xb) - 1));
            bb >>= xb;
            bc -= xb;
            let mut d = dtab[(bb & dmask) as usize];
            if d & F_SUB != 0 {
                let sb = (d >> 8) & 15;
                d = dtab[(d >> 16) as usize + ((bb >> droot) as usize & ((1usize << sb) - 1))];
            }
            let dcw = d & 63;
            bb >>= dcw;
            bc -= dcw;
            if d & F_LEN == 0 {
                return Err(InflateError::Malformed("invalid distance symbol"));
            }
            let dxb = (d >> 8) & 15;
            let dist = (d >> 16) as usize + (bb as usize & ((1usize << dxb) - 1));
            bb >>= dxb;
            bc -= dxb;
            if dist <= o {
                let src = o - dist;
                if dist >= 8 {
                    // Each word read lies wholly below the write position because the
                    // distance is at least the word size.
                    let (mut s, mut d) = (src, o);
                    let end = o + len;
                    while d < end {
                        let v = le64(buf, s);
                        buf[d..d + 8].copy_from_slice(&v.to_le_bytes());
                        s += 8;
                        d += 8;
                    }
                } else if dist == 1 {
                    let b = buf[o - 1];
                    buf[o..o + len].fill(b);
                } else {
                    // Short period: the copied region doubles the readable pattern each step.
                    let mut done = 0;
                    while done < len {
                        let step = (dist + done).min(len - done);
                        buf.copy_within(src..src + step, o + done);
                        done += step;
                    }
                }
            } else {
                copy_far(buf, o, dist, len, w)?;
            }
            o += len;
        } else if e & F_EOB != 0 {
            break Exit::Eob;
        } else if e & F_BAD != 0 {
            return Err(InflateError::Malformed("invalid literal/length symbol"));
        } else {
            // A literal that needed a sub-table.
            buf[o] = (e >> 16) as u8;
            o += 1;
        }
    };
    cx.ip = ip;
    cx.bb = bb & ((1u64 << bc) - 1);
    cx.bc = bc;
    *op = o;
    Ok(exit)
}

/// The checked loop: one symbol at a time, every bound re-derived.
#[allow(clippy::too_many_arguments)]
fn checked(
    cx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
    start: usize,
    op: &mut usize,
    c: &Codes<'_>,
    w: Win<'_>,
    limit: usize,
    hard_cap: usize,
) -> Result<(), InflateError> {
    let (lmask, dmask) = ((1u64 << c.lit_bits) - 1, (1u64 << c.dist_bits) - 1);
    loop {
        cx.pull();
        let mut e = c.lit[(cx.bb & lmask) as usize];
        if e & F_SUB != 0 {
            let sb = (e >> 8) & 15;
            e = c.lit[(e >> 16) as usize + ((cx.bb >> c.lit_bits) as usize & ((1usize << sb) - 1))];
        }
        let cw = e & 0xff;
        if cw > cx.bc {
            return Err(InflateError::Truncated);
        }
        cx.bb >>= cw;
        cx.bc -= cw;
        if e & F_ANY == 0 {
            room(out, start, *op, 1, limit, hard_cap)?;
            out[start + *op] = (e >> 16) as u8;
            *op += 1;
        } else if e & F_LEN != 0 {
            let xb = (e >> 8) & 15;
            let len = (e >> 16) as usize + cx.get(xb)? as usize;
            cx.pull();
            let mut d = c.dist[(cx.bb & dmask) as usize];
            if d & F_SUB != 0 {
                let sb = (d >> 8) & 15;
                d = c.dist[(d >> 16) as usize + ((cx.bb >> c.dist_bits) as usize & ((1usize << sb) - 1))];
            }
            let dcw = d & 0xff;
            if dcw > cx.bc {
                return Err(InflateError::Truncated);
            }
            cx.bb >>= dcw;
            cx.bc -= dcw;
            if d & F_LEN == 0 {
                return Err(InflateError::Malformed("invalid distance symbol"));
            }
            let dist = (d >> 16) as usize + cx.get((d >> 8) & 15)? as usize;
            room(out, start, *op, len, limit, hard_cap)?;
            let o = *op;
            let buf = &mut out[start..];
            if dist <= o {
                for k in 0..len {
                    buf[o + k] = buf[o + k - dist];
                }
            } else {
                copy_far(buf, o, dist, len, w)?;
            }
            *op += len;
        } else if e & F_EOB != 0 {
            return Ok(());
        } else {
            return Err(InflateError::Malformed("invalid literal/length symbol"));
        }
    }
}

/// Reads a dynamic block's code descriptions into the scratch and builds both tables.
fn read_dynamic(cx: &mut Ctx<'_>, s: &mut Scratch) -> Result<(u32, u32), InflateError> {
    let hlit = cx.get(5)? as usize + 257;
    let hdist = cx.get(5)? as usize + 1;
    let hclen = cx.get(4)? as usize + 4;
    if hlit > 286 || hdist > 30 {
        return Err(InflateError::Malformed("too many length or distance symbols"));
    }
    let mut cl = [0u8; 19];
    for &o in &CL_ORDER[..hclen] {
        cl[o as usize] = cx.get(3)? as u8;
    }
    let cl_bits = build_table(&cl, CL_ROOT, Kind::CodeLen, &mut s.cl)?;
    let cl_mask = (1u64 << cl_bits) - 1;
    let total = hlit + hdist;
    let mut i = 0usize;
    while i < total {
        if cx.bc < 14 {
            cx.pull();
        }
        let e = s.cl[(cx.bb & cl_mask) as usize];
        let cw = e & 0xff;
        if cw > cx.bc {
            return Err(InflateError::Truncated);
        }
        cx.bb >>= cw;
        cx.bc -= cw;
        let sym = e >> 16;
        if sym < 16 {
            s.lens[i] = sym as u8;
            i += 1;
            continue;
        }
        let (rep, val) = match sym {
            16 => {
                if i == 0 {
                    return Err(InflateError::Malformed("length repeat with nothing to repeat"));
                }
                (3 + cx.get(2)? as usize, s.lens[i - 1])
            }
            17 => (3 + cx.get(3)? as usize, 0),
            _ => (11 + cx.get(7)? as usize, 0),
        };
        if i + rep > total {
            return Err(InflateError::Malformed("length repeat overruns the code table"));
        }
        s.lens[i..i + rep].fill(val);
        i += rep;
    }
    if s.lens[EOB] == 0 {
        return Err(InflateError::Malformed("no end-of-block code"));
    }
    let lit_bits = build_table(&s.lens[..hlit], LIT_ROOT, Kind::LitLen, &mut s.lit)?;
    let dist_bits = build_table(&s.lens[hlit..total], DIST_ROOT, Kind::Dist, &mut s.dist)?;
    Ok((lit_bits, dist_bits))
}

/// A DEFLATE decoder with optional history. See the module docs for the contract.
pub struct Inflater {
    /// The last `<= wcap` bytes produced, oldest at `wpos` once full (`wpos == 0` before).
    win: Vec<u8>,
    wpos: usize,
    wcap: usize,
    keep: bool,
    /// Bits carried between calls: always fewer than three, from a partly used byte.
    bitbuf: u64,
    bitcnt: u32,
    failed: bool,
    /// Tests only: never use the fast loop, to compare it with the checked one.
    #[cfg(test)]
    pub(crate) force_checked: bool,
}

impl Inflater {
    /// `window_bits` (8..=15) is the largest distance the peer may use; with
    /// `keep_history == false` no history is kept and every call is independent.
    pub fn new(window_bits: u8, keep_history: bool) -> Inflater {
        let bits = window_bits.clamp(MIN_WINDOW_BITS, MAX_WINDOW_BITS);
        Inflater {
            win: Vec::new(),
            wpos: 0,
            wcap: 1 << bits,
            keep: keep_history,
            bitbuf: 0,
            bitcnt: 0,
            failed: false,
            #[cfg(test)]
            force_checked: false,
        }
    }

    /// Bytes of history currently held (0 when history is off).
    pub fn history_len(&self) -> usize {
        self.win.len()
    }

    /// Heap held between calls: the history ring's capacity.
    pub fn heap_bytes(&self) -> usize {
        self.win.capacity()
    }

    /// Forgets the history (and any carried bits); the stream continues as if new.
    pub fn reset(&mut self) {
        self.win.clear();
        self.wpos = 0;
        self.bitbuf = 0;
        self.bitcnt = 0;
        self.failed = false;
    }

    /// Drops the history's allocation along with its contents.
    pub fn release(&mut self) {
        self.win = Vec::new();
        self.wpos = 0;
    }

    /// Decodes `input` (a whole number of blocks), appending at most `limit` bytes to
    /// `out`. Returns the number appended. On error `out` is restored and the stream
    /// is dead.
    pub fn inflate(&mut self, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize, InflateError> {
        self.run(input, &[], false, out, limit)
    }

    /// Decodes one permessage-deflate message (RFC 7692 §7.2.2): `input` is the
    /// payload as received, and the `00 00 ff ff` the sender stripped is supplied
    /// virtually. The message must end on a block boundary with no stray bits.
    pub fn inflate_message(&mut self, input: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize, InflateError> {
        self.run(input, &SYNC_TAIL, true, out, limit)
    }

    fn run(
        &mut self,
        input: &[u8],
        tail: &[u8],
        aligned: bool,
        out: &mut Vec<u8>,
        limit: usize,
    ) -> Result<usize, InflateError> {
        if self.failed {
            return Err(InflateError::Malformed("stream already failed"));
        }
        let start = out.len();
        let result = SCRATCH.with(|s| {
            let mut s = s.borrow_mut();
            self.decode(&mut s, input, tail, out, start, limit)
        });
        let result = result.and_then(|n| {
            if aligned && self.bitcnt != 0 {
                Err(InflateError::Malformed("message ends inside a byte"))
            } else {
                Ok(n)
            }
        });
        match result {
            Ok(n) => {
                out.truncate(start + n);
                if self.keep {
                    self.remember(&out[start..]);
                }
                Ok(n)
            }
            Err(e) => {
                out.truncate(start);
                self.failed = true;
                self.release();
                Err(e)
            }
        }
    }

    fn decode(
        &mut self,
        s: &mut Scratch,
        input: &[u8],
        tail: &[u8],
        out: &mut Vec<u8>,
        start: usize,
        limit: usize,
    ) -> Result<usize, InflateError> {
        let hard_cap = limit.saturating_add(SLACK);
        // A guess at the output size: JSON typically inflates 2-4x. Too small costs one
        // geometric growth step; too big costs zero-fill and memory, so err low.
        let first = input.len().saturating_mul(2).max(1024).saturating_add(SLACK).min(hard_cap);
        out.reserve_exact(start + first - out.len());
        out.resize(start + first, 0);
        let mut cx = Ctx {
            input,
            tail,
            n: input.len(),
            total: input.len() + tail.len(),
            ip: 0,
            bb: self.bitbuf,
            bc: self.bitcnt,
        };
        let mut op = 0usize;
        #[cfg(test)]
        let allow_fast = !self.force_checked;
        #[cfg(not(test))]
        let allow_fast = true;

        loop {
            if cx.ip >= cx.total && cx.bc < 3 {
                break; // clean end at a block boundary
            }
            let header = cx.get(3)?;
            let last = header & 1 != 0;
            match header >> 1 {
                0 => {
                    // Stored: drop the partial byte, hand the whole bytes still in the
                    // bit buffer back to the input, read LEN/NLEN, copy.
                    cx.align();
                    let back = (cx.bc >> 3) as usize;
                    cx.ip = cx.ip.checked_sub(back).ok_or(InflateError::Malformed("internal: bit buffer"))?;
                    cx.bb = 0;
                    cx.bc = 0;
                    if cx.total - cx.ip < 4 {
                        return Err(InflateError::Truncated);
                    }
                    let byte = |p: usize| if p < cx.n { input[p] } else { tail[p - cx.n] };
                    let len = usize::from(byte(cx.ip)) | usize::from(byte(cx.ip + 1)) << 8;
                    let nlen = usize::from(byte(cx.ip + 2)) | usize::from(byte(cx.ip + 3)) << 8;
                    if len ^ nlen != 0xffff {
                        return Err(InflateError::Malformed("stored block length check failed"));
                    }
                    cx.ip += 4;
                    if len > cx.total - cx.ip {
                        return Err(InflateError::Truncated);
                    }
                    room(out, start, op, len, limit, hard_cap)?;
                    // The bytes may straddle the end of the input and the virtual tail, or lie
                    // wholly in the tail (then `cx.ip` is already past `input`).
                    let from_input = len.min(cx.n.saturating_sub(cx.ip));
                    if from_input > 0 {
                        out[start + op..start + op + from_input].copy_from_slice(&input[cx.ip..cx.ip + from_input]);
                    }
                    if from_input < len {
                        let t = cx.ip + from_input - cx.n;
                        out[start + op + from_input..start + op + len].copy_from_slice(&tail[t..t + len - from_input]);
                    }
                    cx.ip += len;
                    op += len;
                }
                kind @ (1 | 2) => {
                    let win = Win { data: &self.win, pos: self.wpos };
                    let codes = if kind == 1 {
                        let f = fixed();
                        Codes { lit: &f.lit, lit_bits: f.lit_bits, dist: &f.dist, dist_bits: f.dist_bits }
                    } else {
                        let (lit_bits, dist_bits) = read_dynamic(&mut cx, s)?;
                        Codes { lit: &s.lit, lit_bits, dist: &s.dist, dist_bits }
                    };
                    huffman_block(&mut cx, out, start, &mut op, &codes, win, limit, hard_cap, allow_fast)?;
                }
                _ => return Err(InflateError::Malformed("invalid block type")),
            }
            if last {
                // The stream's last block: the rest of its final byte is padding, and nothing
                // real may follow it. A sender that ends a message with BFINAL has no sync
                // marker to strip, so the virtual `00 00 ff ff` is simply never read (zlib
                // stops at the end of the stream the same way).
                cx.align();
                let next = cx.ip.checked_sub((cx.bc >> 3) as usize);
                if next.is_none_or(|p| p < cx.n) {
                    return Err(InflateError::Malformed("data after the final block"));
                }
                cx.bb = 0;
                cx.bc = 0;
                break;
            }
        }
        self.bitbuf = cx.bb & ((1u64 << cx.bc) - 1);
        self.bitcnt = cx.bc;
        Ok(op)
    }

    /// Appends freshly produced bytes to the history ring.
    fn remember(&mut self, data: &[u8]) {
        let cap = self.wcap;
        if data.len() >= cap {
            self.win.clear();
            if self.win.capacity() < cap {
                self.win.reserve_exact(cap);
            }
            self.win.extend_from_slice(&data[data.len() - cap..]);
            self.wpos = 0;
            return;
        }
        let room = cap - self.win.len();
        if data.len() <= room {
            // Grow geometrically but never past the window: letting `Vec` double would
            // allocate up to twice the window for every connection that has filled it.
            let need = self.win.len() + data.len();
            if need > self.win.capacity() {
                let target = (self.win.capacity() * 2).max(need).max(512).min(cap);
                self.win.reserve_exact(target - self.win.len());
            }
            self.win.extend_from_slice(data);
            return;
        }
        if self.win.capacity() < cap {
            self.win.reserve_exact(cap - self.win.len());
        }
        // Fill to capacity, then overwrite the oldest bytes.
        let (a, b) = data.split_at(room);
        self.win.extend_from_slice(a);
        let first = b.len().min(cap - self.wpos);
        self.win[self.wpos..self.wpos + first].copy_from_slice(&b[..first]);
        let rest = b.len() - first;
        self.win[..rest].copy_from_slice(&b[first..]);
        self.wpos = (self.wpos + b.len()) % cap;
    }
}

/// Decodes one Huffman block: the fast loop while it can prove its bounds, then the
/// checked loop for the tail of the input.
#[allow(clippy::too_many_arguments)]
fn huffman_block(
    cx: &mut Ctx<'_>,
    out: &mut Vec<u8>,
    start: usize,
    op: &mut usize,
    c: &Codes<'_>,
    win: Win<'_>,
    limit: usize,
    hard_cap: usize,
    allow_fast: bool,
) -> Result<(), InflateError> {
    while allow_fast && cx.ip + 8 <= cx.n {
        if !grow(out, start, *op + SLACK, hard_cap) {
            return Err(InflateError::LimitExceeded);
        }
        let exit = fast(cx, &mut out[start..], op, c, win)?;
        // The fast loop may run a little past the limit inside its slack; catch it here.
        if *op > limit {
            return Err(InflateError::LimitExceeded);
        }
        match exit {
            Exit::Eob => return Ok(()),
            Exit::Space => {}
            Exit::Input => break,
        }
    }
    checked(cx, out, start, op, c, win, limit, hard_cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::testutil::{corpora, Rng};

    /// LSB-first bit writer for hand-built streams.
    #[derive(Default)]
    pub(crate) struct Bits {
        pub bytes: Vec<u8>,
        acc: u64,
        n: u32,
    }

    impl Bits {
        pub fn put(&mut self, v: u32, bits: u32) -> &mut Self {
            self.acc |= u64::from(v) << self.n;
            self.n += bits;
            while self.n >= 8 {
                self.bytes.push(self.acc as u8);
                self.acc >>= 8;
                self.n -= 8;
            }
            self
        }

        /// A Huffman codeword (given MSB-first, as the RFC writes them).
        pub fn code(&mut self, code: u32, len: u32) -> &mut Self {
            let rev = code.reverse_bits() >> (32 - len);
            self.put(rev, len)
        }

        pub fn finish(&mut self) -> Vec<u8> {
            if self.n > 0 {
                self.bytes.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
            std::mem::take(&mut self.bytes)
        }
    }

    fn inflate_all(input: &[u8]) -> Result<Vec<u8>, InflateError> {
        let mut out = Vec::new();
        Inflater::new(15, false).inflate(input, &mut out, 1 << 24).map(|_| out)
    }

    // ---- known streams ----

    #[test]
    fn stored_block() {
        let s = [0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(inflate_all(&s).unwrap(), b"hello");
        // Empty stored block, as a sync flush writes it.
        assert_eq!(inflate_all(&[0x00, 0x00, 0x00, 0xff, 0xff]).unwrap(), b"");
        assert_eq!(inflate_all(&[]).unwrap(), b"");
    }

    #[test]
    fn fixed_huffman_hello() {
        // zlib's raw deflate of "hello".
        assert_eq!(inflate_all(&[0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00]).unwrap(), b"hello");
        // "aaaaaaaaaa": literal a, then a match of length 9 at distance 1.
        assert_eq!(inflate_all(&[0x4b, 0x4c, 0x84, 0x01, 0x00]).unwrap(), b"aaaaaaaaaa");
    }

    #[test]
    fn rfc_7692_empty_message_is_one_zero_byte() {
        let mut inf = Inflater::new(15, true);
        let mut out = Vec::new();
        assert_eq!(inf.inflate_message(&[0x00], &mut out, 100).unwrap(), 0);
        assert!(out.is_empty());
        // An empty payload is not a valid message: the tail alone is cut short.
        let mut inf = Inflater::new(15, true);
        assert_eq!(inf.inflate_message(&[], &mut out, 100), Err(InflateError::Truncated));
    }

    #[test]
    fn rfc_7692_hello_example() {
        // RFC 7692 §7.2.3.1: "Hello" compresses to f2 48 cd c9 c9 07 00 (BFINAL=1 form) or,
        // as a sync-flushed message, f2 48 cd c9 c9 07 00 with the empty block's header bits.
        let mut inf = Inflater::new(15, true);
        let mut out = Vec::new();
        inf.inflate_message(&[0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], &mut out, 100).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn rfc_7692_no_compression_block_example() {
        // §7.2.3.3: a stored block with BFINAL=0 carrying "Hello", then the stripped tail.
        let mut inf = Inflater::new(15, true);
        let mut out = Vec::new();
        inf.inflate_message(&[0x00, 0x05, 0x00, 0xfa, 0xff, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00], &mut out, 100)
            .unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn rfc_7692_two_messages_example() {
        // Section 7.2.3.5: "Hello" sent as two messages, "He" then "llo", each a fixed-Huffman
        // block followed by the sync marker's header byte (the 00 00 ff ff is stripped).
        let mut inf = Inflater::new(15, true);
        let mut out = Vec::new();
        inf.inflate_message(&[0xf2, 0x48, 0x05, 0x00], &mut out, 100).unwrap();
        assert_eq!(out, b"He");
        inf.inflate_message(&[0xca, 0xc9, 0xc9, 0x07, 0x00], &mut out, 100).unwrap();
        assert_eq!(out, b"Hello");
    }

    #[test]
    fn rfc_7692_final_block_example() {
        // §7.2.3.4: the same message ended with a BFINAL=1 block; the receiver still
        // appends the tail, which then decodes as an empty stored block.
        let mut inf = Inflater::new(15, true);
        let mut out = Vec::new();
        inf.inflate_message(&[0xf3, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00], &mut out, 100).unwrap();
        assert_eq!(out, b"Hello");
    }

    // ---- errors, one construct each ----

    fn expect_malformed(stream: &[u8], what: &str) {
        match inflate_all(stream) {
            Err(InflateError::Malformed(m)) => assert!(m.contains(what), "{m:?} should mention {what:?}"),
            other => panic!("expected Malformed({what:?}), got {other:?}"),
        }
    }

    #[test]
    fn invalid_block_type() {
        let mut b = Bits::default();
        b.put(1, 1).put(3, 2);
        expect_malformed(&b.finish(), "block type");
    }

    #[test]
    fn stored_length_complement_is_checked() {
        expect_malformed(&[0x01, 0x05, 0x00, 0xfb, 0xff, 1, 2, 3, 4, 5], "length check");
        assert_eq!(inflate_all(&[0x01, 0x05, 0x00, 0xfa, 0xff, 1, 2, 3, 4]), Err(InflateError::Truncated));
        assert_eq!(inflate_all(&[0x01, 0x05, 0x00]), Err(InflateError::Truncated));
    }

    #[test]
    fn symbols_286_and_287_and_distance_30_are_errors() {
        // Fixed block: literal/length symbol 286 is 8 bits 11000110.
        let mut b = Bits::default();
        b.put(1, 1).put(1, 2).code(0b1100_0110, 8);
        expect_malformed(&b.finish(), "literal/length symbol");
        // 'a' then length 3 (symbol 257 = 0000001) then distance code 30 (11110).
        let mut b = Bits::default();
        b.put(1, 1).put(1, 2).code(0x30 + b'a' as u32, 8).code(1, 7).code(30, 5);
        expect_malformed(&b.finish(), "distance symbol");
    }

    #[test]
    fn distance_before_the_start_of_output_is_an_error() {
        // 'a', then length 3 at distance 2 (code 1): only one byte of output exists.
        let mut b = Bits::default();
        b.put(1, 1).put(1, 2).code(0x30 + b'a' as u32, 8).code(1, 7).code(1, 5).code(0, 7);
        expect_malformed(&b.finish(), "too far back");
    }

    fn dynamic_header(hlit: u32, hdist: u32, cl_lens: &[u32]) -> Bits {
        let mut b = Bits::default();
        b.put(1, 1).put(2, 2).put(hlit - 257, 5).put(hdist - 1, 5).put(cl_lens.len() as u32 - 4, 4);
        for &l in cl_lens {
            b.put(l, 3);
        }
        b
    }

    #[test]
    fn dynamic_header_errors() {
        // HLIT > 286.
        let mut b = Bits::default();
        b.put(1, 1).put(2, 2).put(30, 5).put(0, 5).put(0, 4).put(0, 12);
        expect_malformed(&b.finish(), "too many");
        // HDIST > 30.
        let mut b = Bits::default();
        b.put(1, 1).put(2, 2).put(0, 5).put(31, 5).put(0, 4).put(0, 12);
        expect_malformed(&b.finish(), "too many");
        // Code-length code over-subscribed: three codes of length 1 (order 16,17,18).
        let b = dynamic_header(257, 1, &[1, 1, 1, 0]).finish();
        expect_malformed(&b, "over-subscribed");
        // Code-length code incomplete: a single length-2 code.
        let b = dynamic_header(257, 1, &[2, 0, 0, 0]).finish();
        expect_malformed(&b, "incomplete");
        // No code-length codes at all.
        let b = dynamic_header(257, 1, &[0, 0, 0, 0]).finish();
        expect_malformed(&b, "empty code");
    }

    #[test]
    fn repeat_with_nothing_before_it_and_overrun_are_errors() {
        // Code-length alphabet: symbol 16 and 18 with one-bit codes (16 -> 0, 18 -> 1).
        // Order is 16,17,18,0...: lens [1,0,1,0].
        let mut b = dynamic_header(257, 1, &[1, 0, 1, 0]);
        b.code(0, 1).put(0, 2); // 16 as the very first length
        expect_malformed(&b.finish(), "nothing to repeat");
        // 18 with max repeat, three times: 3 * 138 = 414 > 258 lengths.
        let mut b = dynamic_header(257, 1, &[1, 0, 1, 0]);
        for _ in 0..3 {
            b.code(1, 1).put(127, 7);
        }
        expect_malformed(&b.finish(), "overruns");
    }

    #[test]
    fn missing_end_of_block_code_is_an_error() {
        // Only literals 0 and 1 get codes (length 1 each); symbol 256 has none.
        // Code-length alphabet: symbol 0 -> `0`, symbol 1 -> `10`, symbol 18 -> `11`.
        let mut cl = vec![0u32; 18];
        cl[2] = 2; // symbol 18
        cl[3] = 1; // symbol 0
        cl[17] = 2; // symbol 1
        let mut b = dynamic_header(257, 1, &cl);
        b.code(0b10, 2).code(0b10, 2); // lengths of symbols 0 and 1
        b.code(0b11, 2).put(138 - 11, 7); // 138 zeros
        b.code(0b11, 2).put(118 - 11, 7); // 118 zeros: 2 + 138 + 118 = 258 = HLIT + HDIST
        expect_malformed(&b.finish(), "end-of-block");
    }

    #[test]
    fn stream_without_distance_codes_decodes_literals() {
        // A dynamic block with no distance codes at all (lone EOB + literal 'a').
        let mut cl = vec![0u32; 18];
        cl[2] = 2; // symbol 18
        cl[3] = 1; // symbol 0
        cl[17] = 2; // symbol 1
        let mut b = dynamic_header(257, 1, &cl);
        // lit/len lengths: sym 0..96 zero (97 zeros), sym 97 = 1, sym 98..255 zero (158), sym 256 = 1.
        // 97 zeros = 18 with repeat 97 (extra 86); 158 zeros = 138 + 20 (18 twice).
        b.code(0b11, 2).put(97 - 11, 7);
        b.code(0b10, 2); // length 1 for 'a'
        b.code(0b11, 2).put(127, 7); // 138
        b.code(0b11, 2).put(20 - 11, 7); // 20 more -> symbols 98..=255
        b.code(0b10, 2); // EOB length 1
        b.code(0b0, 1); // the single distance length: 0
                        // Literal 'a' (code 0), 'a' again, then EOB (code 1).
        b.put(0, 1).put(0, 1).put(1, 1);
        assert_eq!(inflate_all(&b.finish()).unwrap(), b"aa");
    }

    // ---- table builder ----

    /// Every codeword, extended by random trailing bits, must resolve to its own symbol
    /// and length through the root table (and the sub-tables).
    fn check_table(lens: &[u8], root: u32, kind: Kind) {
        let mut table = vec![0u32; LIT_CAP];
        let rb = build_table(lens, root, kind, &mut table).unwrap();
        let mut count = [0u32; 16];
        for &l in lens {
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut next = [0u32; 16];
        let mut code = 0u32;
        for bits in 1..16 {
            code = (code + count[bits - 1]) << 1;
            next[bits] = code;
        }
        let mut rng = Rng::new(99);
        for (sym, &l) in lens.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let l = u32::from(l);
            let c = next[l as usize];
            next[l as usize] += 1;
            let rev = c.reverse_bits() >> (32 - l);
            for _ in 0..8 {
                let bits = u64::from(rev) | (rng.next() << l);
                let mut e = table[(bits & ((1 << rb) - 1)) as usize];
                if e & F_SUB != 0 {
                    let sb = (e >> 8) & 15;
                    e = table[(e >> 16) as usize + ((bits >> rb) as usize & ((1 << sb) - 1))];
                }
                assert_eq!(e & 0xff, l, "sym {sym}");
                assert_eq!(e & !0xff, template(kind, sym) & !0xff, "sym {sym}");
            }
        }
    }

    fn random_complete_lengths(rng: &mut Rng, n: usize, max_len: usize) -> Vec<u8> {
        // Start from one code of length 0 and split leaves until n symbols exist.
        let mut leaves: Vec<usize> = vec![0];
        while leaves.len() < n {
            let i = rng.below(leaves.len() as u64) as usize;
            if leaves[i] + 1 > max_len {
                continue;
            }
            leaves[i] += 1;
            let d = leaves[i];
            leaves.push(d);
        }
        let mut lens = vec![0u8; n];
        // Spread the lengths over a random subset of a larger alphabet by shuffling.
        for (i, &d) in leaves.iter().enumerate() {
            lens[i] = d.max(1) as u8;
        }
        for i in (1..n).rev() {
            lens.swap(i, rng.below(i as u64 + 1) as usize);
        }
        lens
    }

    #[test]
    fn tables_resolve_every_codeword_for_random_complete_codes() {
        let mut rng = Rng::new(5);
        for iter in 0..400 {
            let n = 2 + rng.below(285) as usize;
            let max_len = [7usize, 9, 11, 13, 15][iter % 5];
            if n > 1 << max_len {
                continue;
            }
            let mut lens = random_complete_lengths(&mut rng, n, max_len);
            // The generator needs a complete code, which it is by construction.
            let sum: u64 = lens.iter().map(|&l| 1u64 << (15 - l)).sum();
            assert_eq!(sum, 1 << 15);
            lens.resize(286, 0);
            check_table(&lens, 10, Kind::LitLen);
            check_table(&lens, 9, Kind::LitLen);
            let nd = 2 + rng.below(29) as usize;
            let mut dist = random_complete_lengths(&mut rng, nd, 15);
            dist.resize(30, 0);
            check_table(&dist, 8, Kind::Dist);
        }
    }

    #[test]
    fn doubling_fast_path_builds_the_same_tables_as_the_generic_builder() {
        let mut rng = Rng::new(123);
        let mut built = 0;
        for iter in 0..3000 {
            let n = 2 + rng.below(285) as usize;
            let max_len = [3usize, 5, 7, 8, 9, 10, 11, 13][iter % 8];
            if n > 1 << max_len {
                continue;
            }
            let mut lens = random_complete_lengths(&mut rng, n, max_len);
            lens.resize(286, 0);
            for (root, kind) in [(10u32, Kind::LitLen), (9, Kind::LitLen), (15, Kind::LitLen), (8, Kind::Dist)] {
                let l = if kind == Kind::Dist { &lens[..n.min(30)] } else { &lens[..] };
                let (mut a, mut b) = (vec![0u32; LIT_CAP], vec![0u32; LIT_CAP]);
                // Distinct garbage underneath proves every needed slot is written.
                a.fill(0xdead_beef);
                b.fill(0xdead_beef);
                let ra = build_table(l, root, kind, &mut a);
                let rb = build_table_generic(l, root, kind, &mut b);
                assert_eq!(ra, rb, "iter {iter}");
                if let Ok(bits) = ra {
                    let size = 1usize << bits;
                    // The root tables must agree slot for slot (sub-tables only exist on the generic path).
                    assert_eq!(a[..size], b[..size], "iter {iter} root {root}");
                    built += 1;
                }
            }
        }
        assert!(built > 1000);
        // Incomplete single code and the empty code behave alike.
        for lens in [&[1u8][..], &[0, 0, 1], &[0u8; 5]] {
            let (mut a, mut b) = (vec![0u32; 64], vec![0u32; 64]);
            assert_eq!(build_table(lens, 8, Kind::Dist, &mut a), build_table_generic(lens, 8, Kind::Dist, &mut b));
            assert_eq!(a[..2], b[..2]);
        }
    }

    #[test]
    fn table_capacity_holds_for_the_worst_codes() {
        // Codes that maximise sub-table use: as many symbols as possible just past the root.
        let mut rng = Rng::new(17);
        let mut worst = 0usize;
        for _ in 0..3000 {
            let n = 100 + rng.below(186) as usize;
            let lens = random_complete_lengths(&mut rng, n, 15);
            let mut t = vec![0u32; 4096];
            build_table(&lens, 10, Kind::LitLen, &mut t).unwrap();
            // Recompute the table size the builder claimed by walking it.
            let mut used = 1usize << 10;
            for &e in &t[..1 << 10] {
                if e & F_SUB != 0 {
                    used += 1 << ((e >> 8) & 15);
                }
            }
            worst = worst.max(used);
        }
        assert!(worst < LIT_CAP, "worst {worst}");
    }

    #[test]
    fn over_subscribed_and_incomplete_literal_codes_are_rejected() {
        let mut t = vec![0u32; LIT_CAP];
        let mut lens = vec![0u8; 286];
        lens[0] = 1;
        lens[1] = 1;
        lens[2] = 1;
        assert!(build_table(&lens, 10, Kind::LitLen, &mut t).is_err());
        let mut lens = vec![0u8; 286];
        lens[0] = 2;
        lens[1] = 2;
        assert!(build_table(&lens, 10, Kind::LitLen, &mut t).is_err(), "incomplete");
        // The lone one-bit code is the accepted exception, with the other slot invalid.
        let mut lens = vec![0u8; 286];
        lens[256] = 1;
        let rb = build_table(&lens, 10, Kind::LitLen, &mut t).unwrap();
        assert_eq!(rb, 1);
        assert_ne!(t[0] & F_EOB, 0);
        assert_ne!(t[1] & F_BAD, 0);
    }

    // ---- cross-checks against miniz_oxide ----

    fn miniz_deflate(data: &[u8], level: u8) -> Vec<u8> {
        miniz_oxide::deflate::compress_to_vec(data, level)
    }

    #[test]
    fn decodes_miniz_output_at_every_level() {
        for (name, data) in corpora() {
            for level in [0u8, 1, 2, 4, 6, 9] {
                let packed = miniz_deflate(&data, level);
                let mut out = Vec::new();
                let n = Inflater::new(15, false).inflate(&packed, &mut out, data.len()).unwrap_or_else(|e| {
                    panic!("{name} level {level}: {e}");
                });
                assert_eq!(n, data.len(), "{name} level {level}");
                assert_eq!(out, data, "{name} level {level}");
            }
        }
    }

    #[test]
    fn fast_and_checked_loops_agree() {
        for (name, data) in corpora() {
            for level in [1u8, 6] {
                let packed = miniz_deflate(&data, level);
                let mut a = Inflater::new(15, false);
                let mut b = Inflater::new(15, false);
                b.force_checked = true;
                let (mut oa, mut ob) = (Vec::new(), Vec::new());
                a.inflate(&packed, &mut oa, 1 << 24).unwrap();
                b.inflate(&packed, &mut ob, 1 << 24).unwrap();
                assert_eq!(oa, data, "{name}");
                assert_eq!(ob, data, "{name}");
            }
        }
    }

    #[test]
    fn output_is_appended_after_existing_bytes() {
        let packed = miniz_deflate(b"payload payload payload payload", 6);
        let mut out = b"prefix:".to_vec();
        let n = Inflater::new(15, false).inflate(&packed, &mut out, 1000).unwrap();
        assert_eq!(n, 31);
        assert_eq!(out, b"prefix:payload payload payload payload");
        // A match must never reach into the caller's prefix.
        let mut out = b"AAAAAAAAAAAAAAAAAAAA".to_vec();
        let mut b = Bits::default();
        b.put(1, 1).put(1, 2).code(0x30 + b'b' as u32, 8).code(1, 7).code(0, 5).code(0, 7); // 'b', len 3, dist 1, EOB
        let before = out.len();
        let n = Inflater::new(15, false).inflate(&b.finish(), &mut out, 100).unwrap();
        assert_eq!(&out[before..], b"bbbb");
        assert_eq!(n, 4);
        // dist 2 here would reach into the prefix: refused.
        let mut b = Bits::default();
        b.put(1, 1).put(1, 2).code(0x30 + b'b' as u32, 8).code(1, 7).code(1, 5).code(0, 7);
        let mut out = b"AAAA".to_vec();
        assert!(Inflater::new(15, false).inflate(&b.finish(), &mut out, 100).is_err());
        assert_eq!(out, b"AAAA", "output restored on error");
    }

    // ---- limits ----

    #[test]
    fn limit_is_exact() {
        let data = vec![b'q'; 10_000];
        let packed = miniz_deflate(&data, 6);
        for (limit, ok) in [(10_000usize, true), (10_001, true), (9_999, false), (0, false), (1, false), (5_000, false)]
        {
            let mut out = Vec::new();
            let r = Inflater::new(15, false).inflate(&packed, &mut out, limit);
            assert_eq!(r.is_ok(), ok, "limit {limit}");
            if ok {
                assert_eq!(out.len(), 10_000);
            } else {
                assert_eq!(r, Err(InflateError::LimitExceeded));
                assert!(out.is_empty());
            }
        }
        // Stored blocks obey it too.
        let stored = miniz_deflate(&[7u8; 300], 0);
        assert_eq!(Inflater::new(15, false).inflate(&stored, &mut Vec::new(), 299), Err(InflateError::LimitExceeded));
        assert_eq!(Inflater::new(15, false).inflate(&stored, &mut Vec::new(), 300), Ok(300));
    }

    #[test]
    fn decompression_bomb_fails_at_the_limit_without_allocating_past_it() {
        // 1 MiB of zeros deflates to about a kilobyte.
        let packed = miniz_deflate(&vec![0u8; 1 << 20], 9);
        assert!(packed.len() < 1500, "{}", packed.len());
        let limit = 64 * 1024;
        let mut out = Vec::new();
        let r = Inflater::new(15, false).inflate(&packed, &mut out, limit);
        assert_eq!(r, Err(InflateError::LimitExceeded));
        assert!(out.is_empty());
        assert!(out.capacity() <= limit + 2 * SLACK + 4096, "capacity {} for limit {limit}", out.capacity());
        // And with the limit above the true size it all comes out.
        let mut out = Vec::new();
        assert_eq!(Inflater::new(15, false).inflate(&packed, &mut out, 1 << 20), Ok(1 << 20));
    }

    #[test]
    fn many_small_limits_never_overrun() {
        let data: Vec<u8> = (0..3000u32).map(|i| (i % 7) as u8 + b'a').collect();
        let packed = miniz_deflate(&data, 6);
        for limit in 0..data.len() + 3 {
            let mut out = Vec::new();
            let r = Inflater::new(15, false).inflate(&packed, &mut out, limit);
            if limit >= data.len() {
                assert_eq!(r, Ok(data.len()), "limit {limit}");
            } else {
                assert_eq!(r, Err(InflateError::LimitExceeded), "limit {limit}");
                assert!(out.capacity() < limit + 2 * SLACK + 4096);
            }
        }
    }

    // ---- truncation and corruption ----

    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        for (name, data) in corpora().into_iter().filter(|(_, d)| d.len() < 20_000 && !d.is_empty()) {
            for level in [1u8, 6] {
                let packed = miniz_deflate(&data, level);
                for cut in 1..packed.len() {
                    let mut out = Vec::new();
                    let r = Inflater::new(15, false).inflate(&packed[..cut], &mut out, 1 << 24);
                    assert!(r.is_err(), "{name} level {level}: truncation at {cut}/{} decoded", packed.len());
                    assert!(out.is_empty());
                }
            }
        }
    }

    #[test]
    fn random_corruption_never_panics() {
        let mut rng = Rng::new(0xF022);
        let streams: Vec<Vec<u8>> = corpora()
            .into_iter()
            .filter(|(_, d)| !d.is_empty() && d.len() < 30_000)
            .flat_map(|(_, d)| [miniz_deflate(&d, 1), miniz_deflate(&d, 6), miniz_deflate(&d, 0)])
            .collect();
        let mut rejected = 0;
        let cases = 12_000;
        for case in 0..cases {
            let mut s = streams[rng.below(streams.len() as u64) as usize].clone();
            match rng.below(4) {
                0 => {
                    let i = rng.below(s.len() as u64) as usize;
                    s[i] ^= 1 << rng.below(8);
                }
                1 => {
                    for _ in 0..1 + rng.below(8) {
                        let i = rng.below(s.len() as u64) as usize;
                        s[i] = rng.next() as u8;
                    }
                }
                2 => {
                    let cut = rng.below(s.len() as u64) as usize;
                    s.truncate(cut);
                    let extra = rng.below(6) as usize;
                    s.extend(rng.bytes(extra));
                }
                _ => {
                    let at = rng.below(s.len() as u64 + 1) as usize;
                    let n = 1 + rng.below(8) as usize;
                    let junk = rng.bytes(n);
                    s.splice(at..at, junk);
                }
            }
            let mut out = Vec::new();
            let limit = 1 << 20;
            // History on, so far-match paths run; check both loops.
            let mut a = Inflater::new(15, true);
            let ra = a.inflate(&s, &mut out, limit);
            let mut out_b = Vec::new();
            let mut b = Inflater::new(15, true);
            b.force_checked = true;
            let rb = b.inflate(&s, &mut out_b, limit);
            assert_eq!(ra.is_ok(), rb.is_ok(), "case {case}: fast and checked loops disagree on validity");
            if ra.is_ok() {
                assert_eq!(out, out_b, "case {case}");
            } else {
                rejected += 1;
                assert!(out.is_empty() && out_b.is_empty());
            }
        }
        assert!(rejected > cases / 4, "corruption should usually be caught ({rejected}/{cases})");
    }

    #[test]
    fn failed_stream_stays_failed() {
        let mut inf = Inflater::new(15, true);
        let mut out = Vec::new();
        assert!(inf.inflate(&[0x07], &mut out, 100).is_err());
        let good = miniz_deflate(b"fine", 6);
        assert_eq!(inf.inflate(&good, &mut out, 100), Err(InflateError::Malformed("stream already failed")));
        inf.reset();
        assert_eq!(inf.inflate(&good, &mut out, 100), Ok(4));
    }

    // ---- history ----

    /// Splits `data` into messages, compresses each with miniz as one stream with sync
    /// flushes (so each is a standalone chunk but the window carries over).
    pub(crate) fn miniz_sync_stream(messages: &[&[u8]], level: i32) -> Vec<Vec<u8>> {
        use miniz_oxide::deflate::core::{create_comp_flags_from_zip_params, CompressorOxide};
        use miniz_oxide::deflate::stream::deflate;
        use miniz_oxide::MZFlush;
        let flags = create_comp_flags_from_zip_params(level, -15, 0);
        let mut c = CompressorOxide::new(flags);
        messages
            .iter()
            .map(|m| {
                let mut out = vec![0u8; m.len() * 2 + 4096];
                let r = deflate(&mut c, m, &mut out, MZFlush::Sync);
                assert_eq!(r.bytes_consumed, m.len());
                out.truncate(r.bytes_written);
                out
            })
            .collect()
    }

    #[test]
    fn context_takeover_across_messages() {
        let events = crate::deflate::testutil::nostr_corpus(3, 200);
        let msgs: Vec<&[u8]> = events.iter().map(Vec::as_slice).collect();
        for level in [1, 6] {
            let packed = miniz_sync_stream(&msgs, level);
            let mut inf = Inflater::new(15, true);
            for (i, (p, m)) in packed.iter().zip(&msgs).enumerate() {
                let mut out = Vec::new();
                inf.inflate(p, &mut out, 1 << 20).unwrap_or_else(|e| panic!("message {i}: {e}"));
                assert_eq!(&out, m, "message {i} level {level}");
            }
            assert!(inf.history_len() <= 1 << 15);
        }
    }

    #[test]
    fn history_ring_wraps_correctly_with_far_matches() {
        // A 30 KB period of random data repeated: the encoder reaches back ~30 KB, so
        // matches straddle the ring's wrap point as it turns over.
        let mut rng = Rng::new(31);
        let period = rng.bytes(30_000);
        let mut all = Vec::new();
        for _ in 0..8 {
            all.extend_from_slice(&period);
        }
        let msgs: Vec<&[u8]> = all.chunks(7_001).collect();
        for level in [1, 6] {
            let packed = miniz_sync_stream(&msgs, level);
            let mut inf = Inflater::new(15, true);
            let mut got = Vec::new();
            for (i, p) in packed.iter().enumerate() {
                let before = got.len();
                inf.inflate(p, &mut got, 1 << 20).unwrap_or_else(|e| panic!("chunk {i}: {e}"));
                assert_eq!(&got[before..], msgs[i], "chunk {i} level {level}");
            }
            assert_eq!(inf.history_len(), 1 << 15);
            // Checked loop alone must agree.
            let mut inf = Inflater::new(15, true);
            inf.force_checked = true;
            let mut got = Vec::new();
            for p in &packed {
                inf.inflate(p, &mut got, 1 << 20).unwrap();
            }
            assert_eq!(got, all);
        }
    }

    #[test]
    fn small_windows_refuse_distances_beyond_them() {
        let mut rng = Rng::new(4);
        let block = rng.bytes(2000);
        let mut data = block.clone();
        data.extend(rng.bytes(500));
        data.extend_from_slice(&block); // a match ~2500 back
        let packed = miniz_deflate(&data, 6);
        let mut out = Vec::new();
        assert!(Inflater::new(15, false).inflate(&packed, &mut out, 1 << 20).is_ok());
        // Within a single call the window is the output so far, whatever the setting...
        let mut out = Vec::new();
        assert!(Inflater::new(8, false).inflate(&packed, &mut out, 1 << 20).is_ok());
        // ...but a *history* of 256 bytes cannot serve a message that reaches 2500 back.
        let msgs: Vec<&[u8]> = vec![&data[..2500], &data[2500..]];
        let packed = miniz_sync_stream(&msgs, 6);
        let mut inf = Inflater::new(8, true);
        let mut out = Vec::new();
        inf.inflate(&packed[0], &mut out, 1 << 20).unwrap();
        assert_eq!(inf.history_len(), 256);
        assert!(inf.inflate(&packed[1], &mut out, 1 << 20).is_err());
        let mut inf = Inflater::new(12, true);
        let mut out = Vec::new();
        for p in &packed {
            inf.inflate(p, &mut out, 1 << 20).unwrap();
        }
        assert_eq!(out, data);
    }

    #[test]
    fn no_history_mode_keeps_nothing() {
        let msgs: Vec<&[u8]> = vec![b"hello hello hello hello", b"hello hello hello hello"];
        let packed = miniz_sync_stream(&msgs, 6);
        let mut inf = Inflater::new(15, false);
        let mut out = Vec::new();
        inf.inflate(&packed[0], &mut out, 100).unwrap();
        assert_eq!(inf.history_len(), 0);
        assert_eq!(inf.heap_bytes(), 0);
        // The second message was compressed against the first: without history it can't decode.
        assert!(inf.inflate(&packed[1], &mut out, 100).is_err());
    }

    #[test]
    fn message_must_end_on_a_block_boundary() {
        // The sender's sync marker contributes a header byte before the stripped tail.
        let stored = |trailer: &[u8]| {
            let mut m = vec![0x00, 0x05, 0x00, 0xfa, 0xff, b'H', b'e', b'l', b'l', b'o'];
            m.extend_from_slice(trailer);
            m
        };
        let mut out = Vec::new();
        assert_eq!(Inflater::new(15, true).inflate_message(&stored(&[0x00]), &mut out, 100), Ok(5));
        assert_eq!(out, b"Hello");
        // Without the marker's header byte the tail's own bytes are misread.
        let r = Inflater::new(15, true).inflate_message(&stored(&[]), &mut Vec::new(), 100);
        assert_eq!(r, Err(InflateError::Truncated));
        // A complete BFINAL stream followed by the tail is fine (RFC 7692 section 7.2.3.4).
        let packed = miniz_oxide::deflate::compress_to_vec(b"some text some text", 6);
        let mut inf = Inflater::new(15, true);
        let mut out = Vec::new();
        assert_eq!(inf.inflate_message(&packed, &mut out, 1000), Ok(19));
        assert_eq!(out, b"some text some text");
    }

    #[test]
    fn heap_bytes_tracks_the_ring_only() {
        let mut inf = Inflater::new(15, true);
        assert_eq!(inf.heap_bytes(), 0);
        let mut out = Vec::new();
        let msg = vec![b'x'; 1000];
        inf.inflate(&miniz_deflate(&msg, 1), &mut out, 5000).unwrap();
        assert!(inf.heap_bytes() >= 1000 && inf.heap_bytes() < 4096);
        // However much has flowed through, the ring never holds more than its window.
        for bits in [8u8, 12, 15] {
            let mut inf = Inflater::new(bits, true);
            let data = crate::deflate::testutil::nostr_corpus(4, 120).concat();
            for piece in data.chunks(777) {
                let mut out = Vec::new();
                inf.inflate(&miniz_deflate(piece, 1), &mut out, 5000).unwrap();
            }
            assert_eq!(inf.history_len(), 1 << bits);
            assert_eq!(inf.heap_bytes(), 1 << bits, "window {bits} bits");
        }
    }
}
