//! Encoder-side Huffman code construction: frequencies in, canonical
//! length-limited codes out.
//!
//! **Lengths.** Symbols are sorted by frequency and merged with the two-queue
//! method: leaves wait in sorted order, and the internal nodes the merges create
//! come out in non-decreasing weight order too, so the next two lightest items are
//! always at the front of one of two queues and the whole tree costs O(n) after
//! the sort (no heap). Depths fall out of parent pointers because a parent always
//! has a higher index than its children.
//!
//! **Length limit.** DEFLATE caps codewords at 15 bits (7 for the code-length
//! code). Optimal Huffman lengths exceed that only for very skewed histograms (a
//! Fibonacci-like spread over a block of 16k symbols), so the common case is the
//! O(n) tree above and nothing more. When the tree comes out too deep the block is
//! redone with **package-merge** (Larmore-Hirschberg), which is exact: the lightest
//! `2n - 2` items of the last of `limit` merged lists are the optimal length-limited
//! code, and walking the lists back counts, per level, how many of the (sorted)
//! leaves took part; a leaf's length is the number of levels it appears in. It costs
//! O(n * limit) time and a few KB of heap, on a path that almost never runs, and
//! the tests assert it is *exactly* as cheap as an independent reference
//! implementation, on random and adversarial (Fibonacci) histograms.
//!
//! **Always complete.** A DEFLATE decoder is allowed to reject an incomplete code,
//! and zlib's own `inflate` does except for one corner. So every code built here is
//! complete: with fewer than two used symbols a second, unused one is given a
//! length-1 code, exactly as zlib's `build_tree` does ("force at least two codes").
//!
//! **Canonical codes** are assigned in (length, symbol) order and stored bit-reversed,
//! because DEFLATE packs bits LSB-first but Huffman codes are defined MSB-first:
//! the writer can then OR a code into its accumulator directly.

use super::tables::MAX_CODE_BITS;

/// Calls `f(index, length)` for every non-zero length. Code length arrays are mostly
/// zeros in long runs (a 286-symbol alphabet with 60 used), so whole words of zeros
/// are skipped. Shared by the encoder's code assignment and the decoder's table build.
#[inline(always)]
pub(crate) fn for_each_nonzero(lens: &[u8], mut f: impl FnMut(usize, u8)) {
    let mut base = 0;
    let mut chunks = lens.chunks_exact(8);
    for c in &mut chunks {
        if u64::from_le_bytes([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]) != 0 {
            for (k, &l) in c.iter().enumerate() {
                if l != 0 {
                    f(base + k, l);
                }
            }
        }
        base += 8;
    }
    for (k, &l) in chunks.remainder().iter().enumerate() {
        if l != 0 {
            f(base + k, l);
        }
    }
}

/// Fills `lens` with a complete prefix code's lengths for `freq`, no longer than
/// `max_bits` (at most 15). Unused symbols get 0. See the module docs for the
/// "at least two codes" rule.
pub fn build_lengths(freq: &[u32], max_bits: usize, lens: &mut [u8]) {
    debug_assert_eq!(freq.len(), lens.len());
    debug_assert!(freq.len() <= 288 && (1..=MAX_CODE_BITS).contains(&max_bits));
    // The temporaries below are sized for the alphabet; zeroing four 288-entry arrays
    // for a 19-symbol code-length code would cost more than building the code.
    if freq.len() <= 32 {
        build_lengths_n::<32, 64>(freq, max_bits, lens);
    } else {
        build_lengths_n::<288, 576>(freq, max_bits, lens);
    }
}

/// `N` is the alphabet bound and `M = 2N` the node count of its tree.
fn build_lengths_n<const N: usize, const M: usize>(freq: &[u32], max_bits: usize, lens: &mut [u8]) {
    lens.fill(0);

    // Pack (freq, symbol) into one word so a plain integer sort orders by weight and
    // breaks ties by symbol: deterministic output.
    let mut keys = [0u32; N];
    let mut n = 0usize;
    for (sym, &f) in freq.iter().enumerate() {
        if f != 0 {
            debug_assert!(f < 1 << 22, "frequency overflows the sort key");
            keys[n] = (f << 9) | sym as u32;
            n += 1;
        }
    }

    if n < 2 {
        // Zero or one used symbol: give two symbols a one-bit code each.
        let first = if n == 1 { (keys[0] & 511) as usize } else { 0 };
        let second = if first == 0 { 1 } else { 0 };
        lens[first] = 1;
        if second < lens.len() {
            lens[second] = 1;
        }
        return;
    }
    keys[..n].sort_unstable();

    // Two-queue merge. Nodes 0..n are the sorted leaves, n.. the internal nodes in
    // creation order; `parent` links each node to the internal node that merged it.
    let mut node_freq = [0u32; N];
    let mut parent = [0u16; M];
    let (mut li, mut ni, mut made) = (0usize, 0usize, 0usize);
    // Takes the lighter front item of the two queues.
    macro_rules! take {
        () => {{
            if li < n && (ni >= made || (keys[li] >> 9) <= node_freq[ni]) {
                li += 1;
                (li - 1, keys[li - 1] >> 9)
            } else {
                ni += 1;
                (n + ni - 1, node_freq[ni - 1])
            }
        }};
    }
    for _ in 0..n - 1 {
        let (a, fa) = take!();
        let (b, fb) = take!();
        node_freq[made] = fa + fb;
        parent[a] = (n + made) as u16;
        parent[b] = (n + made) as u16;
        made += 1;
    }

    // Depth of every node, root first (parents have higher indices).
    let root = 2 * n - 2;
    let mut depth = [0u8; M];
    for i in (0..root).rev() {
        depth[i] = depth[parent[i] as usize] + 1;
    }

    if depth[..n].iter().all(|&d| d as usize <= max_bits) {
        // The optimal tree fits: its depths are the lengths (rank order is symbol order
        // by weight, so the rarest symbols already have the deepest leaves).
        for (i, &d) in depth[..n].iter().enumerate() {
            lens[(keys[i] & 511) as usize] = d;
        }
        return;
    }

    // Too deep: exact length-limited lengths by package-merge, in rank order.
    let mut weights = [0u32; 288];
    for i in 0..n {
        weights[i] = keys[i] >> 9;
    }
    let mut by_rank = [0u8; 288];
    if package_merge(&weights[..n], max_bits, &mut by_rank[..n]) {
        for i in 0..n {
            lens[(keys[i] & 511) as usize] = by_rank[i];
        }
    } else {
        // Unreachable for n <= 2^max_bits; stay valid rather than loop or panic.
        flat_lengths(&keys[..n], max_bits, lens);
    }
}

/// Optimal code lengths for ascending `weights` with no length above `max_bits`, by
/// package-merge (see the module docs). `lens[i]` is the length for `weights[i]`.
/// False if `weights.len() > 2^max_bits` (no such code exists) or on a broken
/// invariant, which the verification at the end would catch.
fn package_merge(weights: &[u32], max_bits: usize, lens: &mut [u8]) -> bool {
    let n = weights.len();
    if n < 2 || n > 1 << max_bits {
        return false;
    }
    let w: Vec<u64> = weights.iter().map(|&x| u64::from(x)).collect();
    // pkgs[j]: the packages entering list j, i.e. consecutive pairs of list j-1, which is
    // itself the merge of the leaves and pkgs[j-1] (leaves first on ties). List 0 has none.
    let mut pkgs: Vec<Vec<u64>> = vec![Vec::new(); max_bits];
    for j in 1..max_bits {
        let prev = &pkgs[j - 1];
        let mut out = Vec::with_capacity(n);
        let (mut i, mut k) = (0usize, 0usize);
        let mut pending: Option<u64> = None;
        while i < n || k < prev.len() {
            let item = if i < n && (k >= prev.len() || w[i] <= prev[k]) {
                i += 1;
                w[i - 1]
            } else {
                k += 1;
                prev[k - 1]
            };
            match pending.take() {
                Some(a) => out.push(a + item),
                None => pending = Some(item),
            }
        }
        pkgs[j] = out;
    }
    // Walk back from the cheapest 2n-2 items of the last list: of the `take` items of list
    // j, `i` are leaves (the lightest `i`) and `k` are packages, which are the first 2k
    // items of list j-1.
    let mut take = 2 * n - 2;
    let mut leaves = [0usize; 16];
    for j in (0..max_bits).rev() {
        let p = &pkgs[j];
        let (mut i, mut k) = (0usize, 0usize);
        for _ in 0..take {
            if i < n && (k >= p.len() || w[i] <= p[k]) {
                i += 1;
            } else if k < p.len() {
                k += 1;
            } else {
                return false;
            }
        }
        leaves[j] = i;
        take = 2 * k;
    }
    if take != 0 {
        return false;
    }
    let mut kraft = 0u64;
    for (r, len) in lens.iter_mut().enumerate() {
        let l = leaves[..max_bits].iter().filter(|&&c| r < c).count();
        if l == 0 {
            return false;
        }
        *len = l as u8;
        kraft += 1u64 << (max_bits - l);
    }
    kraft == 1u64 << max_bits
}

/// Last-resort code: every used symbol gets the same length, `ceil(log2 n)`. Only
/// reachable if the limiter's invariant breaks, and valid whenever `n <= 2^max_bits`.
fn flat_lengths(keys: &[u32], max_bits: usize, lens: &mut [u8]) {
    let n = keys.len();
    let mut bits = 1usize;
    while (1usize << bits) < n && bits < max_bits {
        bits += 1;
    }
    for &k in keys {
        lens[(k & 511) as usize] = bits as u8;
    }
}

/// Canonical codes for `lens`, bit-reversed for LSB-first output. Symbols with
/// length 0 are left untouched (they are never emitted).
pub fn canonical_codes(lens: &[u8], codes: &mut [u16]) {
    debug_assert_eq!(lens.len(), codes.len());
    let mut count = [0u16; 16];
    for_each_nonzero(lens, |_, l| count[l as usize & 15] += 1);
    let mut next = [0u16; 16];
    let mut code = 0u16;
    for bits in 1..=MAX_CODE_BITS {
        code = (code + count[bits - 1]) << 1;
        next[bits] = code;
    }
    for_each_nonzero(lens, |sym, l| {
        let c = next[l as usize & 15];
        next[l as usize & 15] = c.wrapping_add(1);
        codes[sym] = c.reverse_bits() >> (16 - u32::from(l));
    });
}

/// A fixed table of codes with lengths, for the fixed-Huffman block type.
pub struct FixedCodes {
    pub litlen_len: [u8; 288],
    pub litlen_code: [u16; 288],
    pub dist_len: [u8; 32],
    pub dist_code: [u16; 32],
}

/// The fixed-Huffman code (§3.2.6), built once.
pub fn fixed_codes() -> &'static FixedCodes {
    use super::tables::{FIXED_DIST_LENS, FIXED_LITLEN_LENS};
    use std::sync::OnceLock;
    static FIXED: OnceLock<FixedCodes> = OnceLock::new();
    FIXED.get_or_init(|| {
        let mut f = FixedCodes {
            litlen_len: FIXED_LITLEN_LENS,
            litlen_code: [0; 288],
            dist_len: FIXED_DIST_LENS,
            dist_code: [0; 32],
        };
        canonical_codes(&f.litlen_len, &mut f.litlen_code);
        canonical_codes(&f.dist_len, &mut f.dist_code);
        f
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deflate::testutil::Rng;

    fn kraft(lens: &[u8]) -> u64 {
        lens.iter().filter(|&&l| l != 0).map(|&l| 1u64 << (15 - l)).sum()
    }

    fn cost(freq: &[u32], lens: &[u8]) -> u64 {
        freq.iter().zip(lens).map(|(&f, &l)| u64::from(f) * u64::from(l)).sum()
    }

    /// Optimal length-limited code length total by package-merge (the reference the
    /// zlib-style limiter is measured against). Items are the used symbols' weights.
    fn package_merge_cost(freq: &[u32], limit: usize) -> u64 {
        let mut w: Vec<u64> = freq.iter().filter(|&&f| f != 0).map(|&f| u64::from(f)).collect();
        w.sort_unstable();
        let n = w.len();
        if n < 2 {
            return w.iter().sum();
        }
        // Each level's list = merge(leaves, packages of the previous level's list).
        let mut prev: Vec<u64> = Vec::new();
        for _ in 0..limit {
            let mut packages: Vec<u64> = prev.chunks_exact(2).map(|p| p[0] + p[1]).collect();
            let mut cur = w.clone();
            cur.append(&mut packages);
            cur.sort_unstable();
            prev = cur;
        }
        // The cheapest 2(n-1) items of the final list; every item contributes its
        // weight once per level it appears in, which is the total code length cost.
        prev.iter().take(2 * (n - 1)).sum()
    }

    fn check_valid(freq: &[u32], limit: usize, lens: &[u8]) {
        let used = freq.iter().filter(|&&f| f != 0).count();
        for (s, (&f, &l)) in freq.iter().zip(lens).enumerate() {
            if f != 0 {
                assert!(l >= 1 && l as usize <= limit, "symbol {s} freq {f} len {l}");
            }
        }
        if used >= 2 {
            assert_eq!(kraft(lens), 1 << 15, "code must be complete");
            assert_eq!(lens.iter().filter(|&&l| l != 0).count(), used);
        } else {
            assert_eq!(lens.iter().filter(|&&l| l != 0).count(), 2, "forced second code");
            assert_eq!(kraft(lens), 1 << 15);
        }
    }

    #[test]
    fn small_cases() {
        let mut lens = [0u8; 4];
        build_lengths(&[5, 5, 5, 5], 15, &mut lens);
        assert_eq!(lens, [2, 2, 2, 2]);
        build_lengths(&[1, 2, 4, 8], 15, &mut lens);
        assert_eq!(lens, [3, 3, 2, 1]);
        build_lengths(&[0, 0, 7, 0], 15, &mut lens);
        assert_eq!(lens, [1, 0, 1, 0], "one used symbol gets a partner");
        check_valid(&[0, 0, 7, 0], 15, &lens);
        build_lengths(&[0, 0, 0, 0], 15, &mut lens);
        assert_eq!(lens, [1, 1, 0, 0]);
        build_lengths(&[3, 0, 0, 0], 15, &mut lens);
        assert_eq!(lens, [1, 1, 0, 0]);
    }

    #[test]
    fn random_histograms_are_complete_and_near_optimal() {
        let mut rng = Rng::new(0xC0DE);
        for iter in 0..3000 {
            let alphabet = [19usize, 30, 100, 286][iter % 4];
            let limit = if alphabet == 19 { 7 } else { 15 };
            let mut freq = vec![0u32; alphabet];
            let used = 1 + rng.below(alphabet as u64) as usize;
            let skew = rng.below(4);
            for _ in 0..used {
                let s = rng.below(alphabet as u64) as usize;
                // Mix flat and heavily skewed weights.
                freq[s] = match skew {
                    0 => 1 + rng.below(4) as u32,
                    1 => 1 + rng.below(1000) as u32,
                    2 => 1 << rng.below(14),
                    _ => 1 + (rng.next() as u32 >> 11) % 60_000,
                };
            }
            let mut lens = vec![0u8; alphabet];
            build_lengths(&freq, limit, &mut lens);
            check_valid(&freq, limit, &lens);
            if freq.iter().filter(|&&f| f != 0).count() >= 2 {
                let opt = package_merge_cost(&freq, limit);
                let got = cost(&freq, &lens);
                assert!(got >= opt, "cannot beat the optimum: {got} < {opt}");
                assert_eq!(got, opt, "iter {iter}: length-limited code must be optimal");
            }
        }
    }

    #[test]
    fn unlimited_depth_equals_plain_huffman() {
        // With a limit that never binds the result is the optimum.
        let mut rng = Rng::new(7);
        for _ in 0..500 {
            let mut freq = vec![0u32; 64];
            for f in freq.iter_mut() {
                *f = rng.below(500) as u32;
            }
            if freq.iter().filter(|&&f| f != 0).count() < 2 {
                continue;
            }
            let mut lens = vec![0u8; 64];
            build_lengths(&freq, 15, &mut lens);
            assert_eq!(cost(&freq, &lens), package_merge_cost(&freq, 15));
        }
    }

    #[test]
    fn fibonacci_histograms_force_the_limiter() {
        // Fibonacci weights give a maximally deep optimal tree: depth n-1 for n symbols.
        let mut fib = vec![1u32, 1];
        while fib.len() < 40 {
            let k = fib.len();
            fib.push(fib[k - 1] + fib[k - 2]);
        }
        for n in [18usize, 20, 25, 30] {
            let freq: Vec<u32> = fib[..n].iter().map(|&f| f.min((1 << 22) - 1)).collect();
            for limit in [15usize, 12, 9, 7] {
                if n > 1 << limit {
                    continue;
                }
                let mut lens = vec![0u8; n];
                build_lengths(&freq, limit, &mut lens);
                check_valid(&freq, limit, &lens);
                let opt = package_merge_cost(&freq, limit);
                let got = cost(&freq, &lens);
                assert_eq!(got, opt, "n {n} limit {limit}");
            }
        }
    }

    #[test]
    fn every_symbol_used_once_at_full_alphabet() {
        let freq = vec![1u32; 286];
        let mut lens = vec![0u8; 286];
        build_lengths(&freq, 15, &mut lens);
        check_valid(&freq, 15, &lens);
        assert!(lens.iter().all(|&l| l == 8 || l == 9));
    }

    #[test]
    fn canonical_codes_are_prefix_free_and_match_rfc_example() {
        // RFC 1951 §3.2.2 example: lengths (3,3,3,3,3,2,4,4) -> 010,011,100,101,110,00,1110,1111.
        let lens = [3u8, 3, 3, 3, 3, 2, 4, 4];
        let mut codes = [0u16; 8];
        canonical_codes(&lens, &mut codes);
        let want_msb = [0b010u16, 0b011, 0b100, 0b101, 0b110, 0b00, 0b1110, 0b1111];
        for i in 0..8 {
            let rev = want_msb[i].reverse_bits() >> (16 - lens[i] as u32);
            assert_eq!(codes[i], rev, "symbol {i}");
        }
        // Prefix-freeness on the MSB-first view for a big random code.
        let mut rng = Rng::new(3);
        let mut freq = vec![0u32; 286];
        for f in freq.iter_mut() {
            *f = 1 + rng.below(1000) as u32;
        }
        let mut lens = vec![0u8; 286];
        build_lengths(&freq, 15, &mut lens);
        let mut codes = vec![0u16; 286];
        canonical_codes(&lens, &mut codes);
        let msb: Vec<(u32, u32)> =
            (0..286).map(|s| ((codes[s].reverse_bits() >> (16 - lens[s] as u32)) as u32, lens[s] as u32)).collect();
        for a in 0..286 {
            for b in 0..286 {
                if a != b && msb[a].1 <= msb[b].1 {
                    assert_ne!(msb[b].0 >> (msb[b].1 - msb[a].1), msb[a].0, "{a} is a prefix of {b}");
                }
            }
        }
    }

    #[test]
    fn fixed_codes_match_the_rfc() {
        let f = fixed_codes();
        // Literal 0 is 00110000 (8 bits), 144 is 110010000 (9), 256 is 0000000 (7), 280 is 11000000 (8).
        let msb = |s: usize| f.litlen_code[s].reverse_bits() >> (16 - f.litlen_len[s] as u32);
        assert_eq!((msb(0), f.litlen_len[0]), (0b0011_0000, 8));
        assert_eq!((msb(144), f.litlen_len[144]), (0b1_1001_0000, 9));
        assert_eq!((msb(256), f.litlen_len[256]), (0, 7));
        assert_eq!((msb(280), f.litlen_len[280]), (0b1100_0000, 8));
        assert_eq!(f.dist_code[1], 0b10000);
    }
}
