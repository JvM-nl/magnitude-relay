//! Multi-scalar multiplication: sum(k_i * P_i) for many points at once, with
//! every scalar below 2^128 (batch verification splits the 256-bit ones with
//! the GLV endomorphism and folds signs into the points).
//!
//! Two methods, picked by size: Strauss (interleaved wNAF over per-point
//! tables) for small sums, where its one shared doubling chain is cheap, and
//! Pippenger (bucket sums per window) for large ones, where it needs no
//! per-point tables at all.

use super::field::Fe;
use super::group::{Affine, Jacobian};

/// One term: `k * point`.
#[derive(Clone, Copy, Debug)]
pub struct Term {
    pub point: Affine,
    pub k: u128,
}

/// Bits a 128-bit scalar can need after signed recoding (one carry bit).
const BITS: usize = 129;

/// Reusable buffers, so a batch allocates nothing once warm.
#[derive(Default)]
pub struct Scratch {
    wnaf: Vec<i8>,
    table: Vec<Jacobian>,
    affine: Vec<Affine>,
    prefix: Vec<Fe>,
    digits: Vec<i16>,
    buckets: Vec<Jacobian>,
}

/// sum(k_i * P_i), by whichever method is faster for this many terms.
pub fn msm(terms: &[Term], s: &mut Scratch) -> Jacobian {
    match window_for(terms.len()) {
        None => strauss(terms, 4, s),
        Some(c) => pippenger(terms, c, s),
    }
}

/// Strauss (`None`) or Pippenger's window width for a number of terms, from
/// a sweep on the production CPU (sigbench `tune`): Strauss with width-4
/// tables wins below 64 terms, then wider windows as the count grows.
pub fn window_for(n: usize) -> Option<u32> {
    match n {
        0..=63 => None,
        64..=111 => Some(5),
        112..=319 => Some(6),
        320..=639 => Some(7),
        640..=1791 => Some(8),
        1792..=2559 => Some(9),
        _ => Some(10),
    }
}

/// wNAF of `k` with width `w` into `out[..BITS]`: digits odd, below 2^(w-1)
/// in absolute value, any two nonzero digits at least w apart.
fn wnaf(k: u128, w: u32, out: &mut [i8]) {
    out[..BITS].fill(0);
    let bit_at = |b: usize| if b < 128 { ((k >> b) & 1) as i32 } else { 0 };
    let bits_at = |b: usize, n: u32| -> i32 {
        if b >= 128 {
            0
        } else {
            ((k >> b) as u32 & ((1u32 << n) - 1)) as i32
        }
    };
    let mut bit = 0usize;
    let mut carry = 0i32;
    while bit < BITS {
        if bit_at(bit) == carry {
            bit += 1;
            continue;
        }
        let now = (w as usize).min(BITS - bit) as u32;
        let mut word = bits_at(bit, now) + carry;
        carry = (word >> (w - 1)) & 1;
        word -= carry << w;
        out[bit] = word as i8;
        bit += now as usize;
    }
    debug_assert_eq!(carry, 0);
}

/// Affine forms of Jacobian points (none at infinity) with one inversion
/// (Montgomery's trick).
fn to_affine_all(pts: &[Jacobian], prefix: &mut Vec<Fe>, out: &mut Vec<Affine>) {
    out.clear();
    if pts.is_empty() {
        return;
    }
    prefix.clear();
    let mut acc = pts[0].z;
    prefix.push(acc);
    for p in &pts[1..] {
        acc = acc.mul(&p.z);
        prefix.push(acc);
    }
    let mut inv = acc.inv();
    out.resize(pts.len(), Affine::G);
    for i in (0..pts.len()).rev() {
        let zi = if i > 0 { inv.mul(&prefix[i - 1]) } else { inv };
        if i > 0 {
            inv = inv.mul(&pts[i].z);
        }
        let zi2 = zi.sqr();
        let mut x = pts[i].x.mul(&zi2);
        let mut y = pts[i].y.mul(&zi2.mul(&zi));
        x.normalize();
        y.normalize();
        out[i] = Affine { x, y };
    }
}

#[inline(always)]
fn neg_lazy(p: &Affine) -> Affine {
    Affine { x: p.x, y: p.y.negate(1) }
}

/// Interleaved wNAF with a table of odd multiples per term.
pub fn strauss(terms: &[Term], w: u32, s: &mut Scratch) -> Jacobian {
    let tsize = 1usize << (w - 2);
    s.wnaf.resize(terms.len() * BITS, 0);
    s.table.clear();
    for (i, t) in terms.iter().enumerate() {
        wnaf(t.k, w, &mut s.wnaf[i * BITS..(i + 1) * BITS]);
        let p = Jacobian::from_affine(&t.point);
        let p2 = p.double();
        s.table.push(p);
        for j in 1..tsize {
            let next = s.table[s.table.len() - 1].add(&p2);
            debug_assert!(!next.infinity, "odd multiples of a point of prime order are never infinity");
            let _ = j;
            s.table.push(next);
        }
    }
    to_affine_all(&s.table, &mut s.prefix, &mut s.affine);

    let mut acc = Jacobian::INFINITY;
    for bit in (0..BITS).rev() {
        acc = acc.double();
        for i in 0..terms.len() {
            let d = s.wnaf[i * BITS + bit];
            if d > 0 {
                acc = acc.add_affine(&s.affine[i * tsize + (d as usize - 1) / 2]);
            } else if d < 0 {
                acc = acc.add_affine(&neg_lazy(&s.affine[i * tsize + ((-d) as usize - 1) / 2]));
            }
        }
    }
    acc
}

/// Signed `c`-bit digits of every scalar, window-major so each window's pass
/// reads contiguously; returns the number of windows.
fn signed_digits(terms: &[Term], c: u32, digits: &mut Vec<i16>) -> usize {
    let windows = (128 / c + 1) as usize;
    let half = 1i32 << (c - 1);
    let mask = (1u128 << c) - 1;
    digits.resize(terms.len() * windows, 0);
    for (i, t) in terms.iter().enumerate() {
        let mut carry = 0i32;
        for w in 0..windows {
            let shift = w as u32 * c;
            let bits = if shift < 128 { ((t.k >> shift) & mask) as i32 } else { 0 };
            let mut d = bits + carry;
            carry = 0;
            if d > half {
                d -= 1 << c;
                carry = 1;
            }
            digits[w * terms.len() + i] = d as i16;
        }
        debug_assert_eq!(carry, 0);
    }
    windows
}

/// Bucket method over signed `c`-bit windows.
pub fn pippenger(terms: &[Term], c: u32, s: &mut Scratch) -> Jacobian {
    let windows = signed_digits(terms, c, &mut s.digits);
    let nb = 1usize << (c - 1);
    let mut acc = Jacobian::INFINITY;
    for w in (0..windows).rev() {
        for _ in 0..c {
            acc = acc.double();
        }
        s.buckets.clear();
        s.buckets.resize(nb, Jacobian::INFINITY);
        let digits = &s.digits[w * terms.len()..(w + 1) * terms.len()];
        for (t, &d) in terms.iter().zip(digits) {
            if d > 0 {
                let b = &mut s.buckets[d as usize - 1];
                *b = b.add_affine(&t.point);
            } else if d < 0 {
                let b = &mut s.buckets[(-d) as usize - 1];
                *b = b.add_affine(&neg_lazy(&t.point));
            }
        }
        // sum(b * bucket[b]) as running sums from the top bucket down.
        let mut running = Jacobian::INFINITY;
        let mut sum = Jacobian::INFINITY;
        for b in s.buckets.iter().rev() {
            running = running.add(b);
            sum = sum.add(&running);
        }
        acc = acc.add(&sum);
    }
    acc
}
