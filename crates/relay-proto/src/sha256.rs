//! SHA-256 of many messages at once.
//!
//! SHA-256 is a serial chain within one message, so a single hash cannot use
//! wide vectors well: on the production CPU (Skylake, no SHA extensions) the
//! sha2 crate's assembly runs at about 12 cycles per byte. Eight independent
//! messages fill the eight 32-bit lanes of an AVX2 register instead, one round
//! for all of them per instruction sequence. Lanes take the next message as
//! soon as theirs is done, so messages of different lengths share the work
//! without padding each other out; the last few stragglers finish on the
//! scalar code, which beats a mostly empty vector.
//!
//! Without AVX2 (or off x86-64) every message goes through the sha2 crate.
//!
//! Messages can start from a `Midstate`, the state after a shared prefix of
//! whole blocks: BIP-340's tagged hashes all begin with the same 64 bytes.
//!
//! One message alone (`digest`) takes OpenSSL's approach for CPUs with AVX2
//! and BMI2: the message schedule four words at a time in vector registers
//! while the rounds run in scalar ones with flag-free rotates. ring, which
//! carries OpenSSL's code, hashes event preimages about 1.5 times as fast as
//! the sha2 crate's assembly on the production CPU.

use sha2::{Digest, Sha256};

/// The state after hashing some whole 64-byte blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Midstate {
    state: [u32; 8],
    /// Bytes hashed so far (a multiple of 64).
    len: u64,
}

impl Midstate {
    /// Nothing hashed yet.
    pub const EMPTY: Midstate = Midstate { state: IV, len: 0 };

    /// The state after `prefix`, whose length must be a multiple of 64.
    pub fn after(prefix: &[u8]) -> Midstate {
        assert_eq!(prefix.len() % 64, 0, "a midstate covers whole blocks");
        let mut state = IV;
        for b in prefix.chunks_exact(64) {
            let b: [u8; 64] = b.try_into().unwrap();
            sha2::compress256(&mut state, &[b.into()]);
        }
        Midstate { state, len: prefix.len() as u64 }
    }
}

/// SHA-256 of one message.
pub fn digest(msg: &[u8]) -> [u8; 32] {
    #[cfg(target_arch = "x86_64")]
    if x86::has_avx2_bmi2() {
        let mut lane = Lane::idle();
        lane.start(0, msg, &Midstate::EMPTY);
        finish_scalar(&mut lane, msg);
        return lane.digest();
    }
    Sha256::digest(msg).into()
}

/// Hashes each message into the matching slot of `out` (`out.len()` must
/// equal `msgs.len()`).
pub fn digest_many(msgs: &[&[u8]], out: &mut [[u8; 32]]) {
    digest_many_after(&Midstate::EMPTY, msgs, out);
}

/// Hashes `prefix || msg` for each message, where `mid` is the state after
/// the prefix.
pub fn digest_many_after(mid: &Midstate, msgs: &[&[u8]], out: &mut [[u8; 32]]) {
    assert_eq!(msgs.len(), out.len());
    #[cfg(target_arch = "x86_64")]
    if msgs.len() >= MIN_LANES && x86::has_avx2() {
        // SAFETY: AVX2 support was just checked.
        unsafe { x86::digest_many_avx2(mid, msgs, out) };
        return;
    }
    for (m, o) in msgs.iter().zip(out.iter_mut()) {
        *o = if *mid == Midstate::EMPTY {
            Sha256::digest(m).into()
        } else {
            let mut lane = Lane::idle();
            lane.start(0, m, mid);
            finish_scalar(&mut lane, m);
            lane.digest()
        };
    }
}

/// Fewer messages than this go one at a time (a vector step costs the same
/// with one lane busy as with eight).
pub const MIN_LANES: usize = 3;

const IV: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

/// One message's progress in a lane: where its blocks come from, and its
/// final one or two padded blocks.
struct Lane {
    job: usize,
    block: usize,
    /// Whole blocks read straight from the message.
    full: usize,
    /// Blocks in all, padding included.
    total: usize,
    state: [u32; 8],
    tail: [u8; 128],
}

impl Lane {
    const IDLE: usize = usize::MAX;

    fn idle() -> Lane {
        Lane { job: Lane::IDLE, block: 0, full: 0, total: 0, state: IV, tail: [0; 128] }
    }

    fn start(&mut self, job: usize, msg: &[u8], mid: &Midstate) {
        self.job = job;
        self.block = 0;
        self.full = msg.len() / 64;
        let rest = &msg[self.full * 64..];
        let tail_blocks = if rest.len() + 9 <= 64 { 1 } else { 2 };
        self.total = self.full + tail_blocks;
        self.tail = [0; 128];
        self.tail[..rest.len()].copy_from_slice(rest);
        self.tail[rest.len()] = 0x80;
        let end = tail_blocks * 64;
        self.tail[end - 8..end].copy_from_slice(&((mid.len + msg.len() as u64) * 8).to_be_bytes());
        self.state = mid.state;
    }

    fn block<'a>(&'a self, msg: &'a [u8]) -> &'a [u8; 64] {
        let b = if self.block < self.full { &msg[self.block * 64..self.block * 64 + 64] } else { &self.tail[(self.block - self.full) * 64..(self.block - self.full) * 64 + 64] };
        b.try_into().unwrap()
    }

    fn digest(&self) -> [u8; 32] {
        let mut d = [0u8; 32];
        for (i, w) in self.state.iter().enumerate() {
            d[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        d
    }
}

/// Finishes a lane's message one block at a time on one core.
fn finish_scalar(lane: &mut Lane, msg: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    if x86::has_avx2_bmi2() {
        // Whole blocks straight from the message, then the padded tail.
        if lane.block < lane.full {
            // SAFETY: the CPU has AVX2, BMI1 and BMI2 (just checked).
            unsafe { x86::compress_blocks(&mut lane.state, &msg[lane.block * 64..lane.full * 64]) };
            lane.block = lane.full;
        }
        let tail = &lane.tail[(lane.block - lane.full) * 64..(lane.total - lane.full) * 64];
        // SAFETY: as above.
        unsafe { x86::compress_blocks(&mut lane.state, tail) };
        lane.block = lane.total;
        return;
    }
    while lane.block < lane.total {
        let b = *lane.block(msg);
        sha2::compress256(&mut lane.state, &[b.into()]);
        lane.block += 1;
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use super::{finish_scalar, Lane, Midstate};

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    use std::arch::x86_64::*;
    use std::sync::atomic::{AtomicU8, Ordering};

    /// Bit 0: checked; bit 1: AVX2; bit 2: AVX2, BMI1 and BMI2.
    fn features() -> u8 {
        static CACHED: AtomicU8 = AtomicU8::new(0);
        let v = CACHED.load(Ordering::Relaxed);
        if v != 0 {
            return v;
        }
        let avx2 = is_x86_feature_detected!("avx2");
        let bmi = avx2 && is_x86_feature_detected!("bmi1") && is_x86_feature_detected!("bmi2");
        let v = 1 | (u8::from(avx2) << 1) | (u8::from(bmi) << 2);
        CACHED.store(v, Ordering::Relaxed);
        v
    }

    pub fn has_avx2() -> bool {
        features() & 2 != 0
    }

    pub fn has_avx2_bmi2() -> bool {
        features() & 4 != 0
    }

    /// Lanes still running below which the rest finish on scalar code.
    const SCALAR_BELOW: usize = 3;

    #[target_feature(enable = "avx2")]
    pub unsafe fn digest_many_avx2(mid: &Midstate, msgs: &[&[u8]], out: &mut [[u8; 32]]) {
        const IDLE: usize = Lane::IDLE;
        let mut lanes: [Lane; 8] = std::array::from_fn(|_| Lane::idle());
        let mut next = 0;
        for lane in lanes.iter_mut() {
            if next < msgs.len() {
                lane.start(next, msgs[next], mid);
                next += 1;
            }
        }
        let zero = [0u8; 64];
        loop {
            let active = lanes.iter().filter(|l| l.job != IDLE).count();
            if active == 0 {
                break;
            }
            if active < SCALAR_BELOW && next == msgs.len() {
                for lane in lanes.iter_mut().filter(|l| l.job != IDLE) {
                    finish_scalar(lane, msgs[lane.job]);
                    out[lane.job] = lane.digest();
                    lane.job = IDLE;
                }
                break;
            }
            let blocks: [&[u8; 64]; 8] = std::array::from_fn(|i| if lanes[i].job == IDLE { &zero } else { lanes[i].block(msgs[lanes[i].job]) });
            let mut states: [[u32; 8]; 8] = std::array::from_fn(|i| lanes[i].state);
            compress8(&mut states, &blocks);
            for (lane, st) in lanes.iter_mut().zip(states) {
                if lane.job == IDLE {
                    continue;
                }
                lane.state = st;
                lane.block += 1;
                if lane.block == lane.total {
                    out[lane.job] = lane.digest();
                    lane.job = IDLE;
                    if next < msgs.len() {
                        lane.start(next, msgs[next], mid);
                        next += 1;
                    }
                }
            }
        }
    }

    /// Rows (one 8-word vector per lane) to columns (one vector per word).
    #[inline(always)]
    unsafe fn transpose(r: [__m256i; 8]) -> [__m256i; 8] {
        let t0 = _mm256_unpacklo_epi32(r[0], r[1]);
        let t1 = _mm256_unpackhi_epi32(r[0], r[1]);
        let t2 = _mm256_unpacklo_epi32(r[2], r[3]);
        let t3 = _mm256_unpackhi_epi32(r[2], r[3]);
        let t4 = _mm256_unpacklo_epi32(r[4], r[5]);
        let t5 = _mm256_unpackhi_epi32(r[4], r[5]);
        let t6 = _mm256_unpacklo_epi32(r[6], r[7]);
        let t7 = _mm256_unpackhi_epi32(r[6], r[7]);
        let u0 = _mm256_unpacklo_epi64(t0, t2);
        let u1 = _mm256_unpackhi_epi64(t0, t2);
        let u2 = _mm256_unpacklo_epi64(t1, t3);
        let u3 = _mm256_unpackhi_epi64(t1, t3);
        let u4 = _mm256_unpacklo_epi64(t4, t6);
        let u5 = _mm256_unpackhi_epi64(t4, t6);
        let u6 = _mm256_unpacklo_epi64(t5, t7);
        let u7 = _mm256_unpackhi_epi64(t5, t7);
        [
            _mm256_permute2x128_si256(u0, u4, 0x20),
            _mm256_permute2x128_si256(u1, u5, 0x20),
            _mm256_permute2x128_si256(u2, u6, 0x20),
            _mm256_permute2x128_si256(u3, u7, 0x20),
            _mm256_permute2x128_si256(u0, u4, 0x31),
            _mm256_permute2x128_si256(u1, u5, 0x31),
            _mm256_permute2x128_si256(u2, u6, 0x31),
            _mm256_permute2x128_si256(u3, u7, 0x31),
        ]
    }

    macro_rules! rotr {
        ($x:expr, $n:literal) => {
            _mm256_or_si256(_mm256_srli_epi32($x, $n), _mm256_slli_epi32($x, 32 - $n))
        };
    }

    /// One 64-byte block for each of eight lanes.
    #[target_feature(enable = "avx2")]
    unsafe fn compress8(states: &mut [[u32; 8]; 8], blocks: &[&[u8; 64]; 8]) {
        let bswap = _mm256_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12, 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
        // No closures here: they would not inherit this function's AVX2.
        let mut w = [_mm256_setzero_si256(); 16];
        let mut rows = [_mm256_setzero_si256(); 8];
        for half in 0..2 {
            for i in 0..8 {
                rows[i] = _mm256_loadu_si256(blocks[i].as_ptr().add(half * 32).cast());
            }
            let cols = transpose(rows);
            for j in 0..8 {
                w[half * 8 + j] = _mm256_shuffle_epi8(cols[j], bswap);
            }
        }
        for i in 0..8 {
            rows[i] = _mm256_loadu_si256(states[i].as_ptr().cast());
        }
        let init = transpose(rows);
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = init;

        macro_rules! round {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $t:expr) => {{
                let wt = if $t >= 16 {
                    let w15 = w[($t + 1) & 15];
                    let w2 = w[($t + 14) & 15];
                    let s0 = _mm256_xor_si256(_mm256_xor_si256(rotr!(w15, 7), rotr!(w15, 18)), _mm256_srli_epi32(w15, 3));
                    let s1 = _mm256_xor_si256(_mm256_xor_si256(rotr!(w2, 17), rotr!(w2, 19)), _mm256_srli_epi32(w2, 10));
                    let v = _mm256_add_epi32(_mm256_add_epi32(w[$t & 15], s0), _mm256_add_epi32(w[($t + 9) & 15], s1));
                    w[$t & 15] = v;
                    v
                } else {
                    w[$t]
                };
                let s1 = _mm256_xor_si256(_mm256_xor_si256(rotr!($e, 6), rotr!($e, 11)), rotr!($e, 25));
                let ch = _mm256_xor_si256(_mm256_and_si256($e, $f), _mm256_andnot_si256($e, $g));
                let t1 = _mm256_add_epi32(_mm256_add_epi32($h, s1), _mm256_add_epi32(ch, _mm256_add_epi32(wt, _mm256_set1_epi32(K[$t] as i32))));
                let s0 = _mm256_xor_si256(_mm256_xor_si256(rotr!($a, 2), rotr!($a, 13)), rotr!($a, 22));
                let maj = _mm256_xor_si256(_mm256_and_si256($a, $b), _mm256_and_si256($c, _mm256_xor_si256($a, $b)));
                $d = _mm256_add_epi32($d, t1);
                $h = _mm256_add_epi32(t1, _mm256_add_epi32(s0, maj));
            }};
        }
        let mut t = 0;
        while t < 64 {
            round!(a, b, c, d, e, f, g, h, t);
            round!(h, a, b, c, d, e, f, g, t + 1);
            round!(g, h, a, b, c, d, e, f, t + 2);
            round!(f, g, h, a, b, c, d, e, t + 3);
            round!(e, f, g, h, a, b, c, d, t + 4);
            round!(d, e, f, g, h, a, b, c, t + 5);
            round!(c, d, e, f, g, h, a, b, t + 6);
            round!(b, c, d, e, f, g, h, a, t + 7);
            t += 8;
        }

        let sum = [a, b, c, d, e, f, g, h];
        let mut fin = [_mm256_setzero_si256(); 8];
        for i in 0..8 {
            fin[i] = _mm256_add_epi32(sum[i], init[i]);
        }
        let out = transpose(fin);
        for i in 0..8 {
            _mm256_storeu_si256(states[i].as_mut_ptr().cast(), out[i]);
        }
    }

    macro_rules! rotr128 {
        ($x:expr, $n:literal) => {
            _mm_or_si128(_mm_srli_epi32($x, $n), _mm_slli_epi32($x, 32 - $n))
        };
    }

    /// W[t..t+4] from W[t-16..t] (four vectors of four words).
    #[inline(always)]
    unsafe fn schedule(x0: __m128i, x1: __m128i, x2: __m128i, x3: __m128i) -> __m128i {
        let w15 = _mm_alignr_epi8(x1, x0, 4);
        let w7 = _mm_alignr_epi8(x3, x2, 4);
        let s0 = _mm_xor_si128(_mm_xor_si128(rotr128!(w15, 7), rotr128!(w15, 18)), _mm_srli_epi32(w15, 3));
        let tmp = _mm_add_epi32(_mm_add_epi32(x0, s0), w7);
        // W[t] and W[t+1] need sigma1 of W[t-2] and W[t-1]; W[t+2] and W[t+3]
        // need it of W[t] and W[t+1], so the second half waits for the first.
        let w2 = _mm_shuffle_epi32(x3, 0xEE);
        let lo = _mm_add_epi32(tmp, _mm_xor_si128(_mm_xor_si128(rotr128!(w2, 17), rotr128!(w2, 19)), _mm_srli_epi32(w2, 10)));
        let w01 = _mm_shuffle_epi32(lo, 0x44);
        let hi = _mm_add_epi32(tmp, _mm_xor_si128(_mm_xor_si128(rotr128!(w01, 17), rotr128!(w01, 19)), _mm_srli_epi32(w01, 10)));
        _mm_blend_epi32(lo, hi, 0b1100)
    }

    /// The 64-byte blocks of `blocks`, one after another, into `state`.
    #[target_feature(enable = "avx2,bmi1,bmi2")]
    pub unsafe fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 64, 0);
        let bswap = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        // `bc` carries b ^ c: this round's a ^ b is the next round's b ^ c,
        // which makes Maj(a, b, c) = b ^ ((a ^ b) & (b ^ c)) one operation shorter.
        let mut bc;
        macro_rules! round {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $wk:expr) => {{
                $h = $h.wrapping_add($wk);
                let s1 = $e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25);
                let ch = ($e & $f) ^ (!$e & $g);
                $h = $h.wrapping_add(s1).wrapping_add(ch);
                $d = $d.wrapping_add($h);
                let s0 = $a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22);
                let ab = $a ^ $b;
                let maj = $b ^ (ab & bc);
                bc = ab;
                $h = $h.wrapping_add(s0).wrapping_add(maj);
            }};
        }
        for block in blocks.chunks_exact(64) {
            let p = block.as_ptr();
            let mut x0 = _mm_shuffle_epi8(_mm_loadu_si128(p.cast()), bswap);
            let mut x1 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(16).cast()), bswap);
            let mut x2 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(32).cast()), bswap);
            let mut x3 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(48).cast()), bswap);
            let start = [a, b, c, d, e, f, g, h];
            bc = b ^ c;
            let mut wk = [0u32; 8];
            // Eight rounds a turn (the variables' roles come back around),
            // the schedule for the turn after next computed alongside.
            for j in 0..8 {
                _mm_storeu_si128(wk.as_mut_ptr().cast(), _mm_add_epi32(x0, _mm_loadu_si128(K.as_ptr().add(8 * j).cast())));
                _mm_storeu_si128(wk.as_mut_ptr().add(4).cast(), _mm_add_epi32(x1, _mm_loadu_si128(K.as_ptr().add(8 * j + 4).cast())));
                if j < 6 {
                    let n0 = schedule(x0, x1, x2, x3);
                    let n1 = schedule(x1, x2, x3, n0);
                    (x0, x1, x2, x3) = (x2, x3, n0, n1);
                } else {
                    (x0, x1) = (x2, x3);
                }
                round!(a, b, c, d, e, f, g, h, wk[0]);
                round!(h, a, b, c, d, e, f, g, wk[1]);
                round!(g, h, a, b, c, d, e, f, wk[2]);
                round!(f, g, h, a, b, c, d, e, wk[3]);
                round!(e, f, g, h, a, b, c, d, wk[4]);
                round!(d, e, f, g, h, a, b, c, wk[5]);
                round!(c, d, e, f, g, h, a, b, wk[6]);
                round!(b, c, d, e, f, g, h, a, wk[7]);
            }
            a = a.wrapping_add(start[0]);
            b = b.wrapping_add(start[1]);
            c = c.wrapping_add(start[2]);
            d = d.wrapping_add(start[3]);
            e = e.wrapping_add(start[4]);
            f = f.wrapping_add(start[5]);
            g = g.wrapping_add(start[6]);
            h = h.wrapping_add(start[7]);
        }
        *state = [a, b, c, d, e, f, g, h];
    }
}
