//! Arithmetic modulo p = 2^256 - 2^32 - 977, the secp256k1 base field.
//!
//! Five 52-bit limbs in `u64`s, the representation libsecp256k1 uses: limbs
//! may carry excess bits (the *magnitude*), so additions and negations never
//! propagate carries, and every multiplication brings the result back to
//! magnitude 1. The reduction steps and their bounds follow libsecp256k1's
//! `field_5x52`, which the tests cross-check this module against.
//!
//! Magnitude rules (debug builds assert them):
//! * `mul`, `sqr`: inputs at most 8, result 1.
//! * `add`: magnitudes add (at most 32).
//! * `negate(m)`: input at most `m`, result `m + 1`.
//! * `mul_int(k)`: magnitude times `k`.
//! * `half`: `m / 2 + 1`.
//! * `normalize*`: 1 (and `normalize` makes the value canonical, below p).

const M52: u64 = 0xF_FFFF_FFFF_FFFF;
const M48: u64 = 0xFFFF_FFFF_FFFF;
/// 2^256 mod p, shifted left 4 (the reduction folds 2^260 into the low limb).
const R: u64 = 0x10_0000_3D10;
/// p's lowest limb.
const P0: u64 = 0xF_FFFE_FFFF_FC2F;

#[derive(Clone, Copy)]
pub struct Fe {
    pub(crate) n: [u64; 5],
    #[cfg(debug_assertions)]
    mag: u32,
    #[cfg(debug_assertions)]
    norm: bool,
}

impl std::fmt::Debug for Fe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut t = *self;
        t.normalize();
        write!(f, "Fe({})", crate::hex::encode_string(&t.to_bytes()))
    }
}

impl Fe {
    pub const ZERO: Fe = Fe::from_limbs([0; 5]);
    pub const ONE: Fe = Fe::from_limbs([1, 0, 0, 0, 0]);
    /// A cube root of unity: (beta * x, y) is lambda times (x, y).
    pub const BETA: Fe = Fe::from_be_words([0x7ae96a2b, 0x657c0710, 0x6e64479e, 0xac3434e9, 0x9cf04975, 0x12f58995, 0xc1396c28, 0x719501ee]);
    /// The curve constant b in y^2 = x^3 + 7.
    pub const SEVEN: Fe = Fe::from_limbs([7, 0, 0, 0, 0]);

    /// A normalized element from canonical limbs.
    const fn from_limbs(n: [u64; 5]) -> Fe {
        Fe {
            n,
            #[cfg(debug_assertions)]
            mag: 1,
            #[cfg(debug_assertions)]
            norm: true,
        }
    }

    /// A constant from eight big-endian 32-bit words (the value must be below p).
    pub const fn from_be_words(w: [u32; 8]) -> Fe {
        let d = [
            (w[7] as u64) | ((w[6] as u64) << 32),
            (w[5] as u64) | ((w[4] as u64) << 32),
            (w[3] as u64) | ((w[2] as u64) << 32),
            (w[1] as u64) | ((w[0] as u64) << 32),
        ];
        Fe::from_limbs([
            d[0] & M52,
            (d[0] >> 52) | ((d[1] << 12) & M52),
            (d[1] >> 40) | ((d[2] << 24) & M52),
            (d[2] >> 28) | ((d[3] << 36) & M52),
            d[3] >> 16,
        ])
    }

    #[inline(always)]
    fn with(n: [u64; 5], _mag: u32, _norm: bool) -> Fe {
        Fe {
            n,
            #[cfg(debug_assertions)]
            mag: _mag,
            #[cfg(debug_assertions)]
            norm: _norm,
        }
    }

    #[inline(always)]
    fn check(&self) {
        #[cfg(debug_assertions)]
        {
            let m = if self.norm { 1 } else { 2 * self.mag as u64 };
            assert!(self.mag <= 32, "magnitude {} too large", self.mag);
            for i in 0..4 {
                assert!(self.n[i] <= M52 * m, "limb {i} exceeds magnitude {}", self.mag);
            }
            assert!(self.n[4] <= M48 * m, "top limb exceeds magnitude {}", self.mag);
            if self.norm {
                let max = self.n[4] == M48 && (self.n[3] & self.n[2] & self.n[1]) == M52;
                assert!(!(max && self.n[0] >= P0), "normalized value not below p");
            }
        }
    }

    #[inline(always)]
    fn assert_mag(&self, _max: u32) {
        #[cfg(debug_assertions)]
        {
            self.check();
            assert!(self.mag <= _max, "magnitude {} above {}", self.mag, _max);
        }
    }

    #[inline(always)]
    fn assert_norm(&self) {
        #[cfg(debug_assertions)]
        {
            self.check();
            assert!(self.norm, "field element not normalized");
        }
    }

    /// Parses 32 big-endian bytes; `None` when the value is not below p.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Fe> {
        let w = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().unwrap());
        let (d3, d2, d1, d0) = (w(0), w(8), w(16), w(24));
        let n = [
            d0 & M52,
            (d0 >> 52) | ((d1 << 12) & M52),
            (d1 >> 40) | ((d2 << 24) & M52),
            (d2 >> 28) | ((d3 << 36) & M52),
            d3 >> 16,
        ];
        let over = n[4] == M48 && (n[3] & n[2] & n[1]) == M52 && n[0] >= P0;
        (!over).then(|| Fe::from_limbs(n))
    }

    /// 32 big-endian bytes. Requires a normalized element.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.assert_norm();
        let n = &self.n;
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&((n[4] << 16) | (n[3] >> 36)).to_be_bytes());
        out[8..16].copy_from_slice(&((n[3] << 28) | (n[2] >> 24)).to_be_bytes());
        out[16..24].copy_from_slice(&((n[2] << 40) | (n[1] >> 12)).to_be_bytes());
        out[24..32].copy_from_slice(&((n[1] << 52) | n[0]).to_be_bytes());
        out
    }

    /// Fully reduces to the canonical value below p.
    #[inline]
    pub fn normalize(&mut self) {
        self.check();
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;
        let mut x = t4 >> 48;
        t4 &= M48;
        t0 += x * 0x1_0000_03D1;
        t1 += t0 >> 52;
        t0 &= M52;
        t2 += t1 >> 52;
        t1 &= M52;
        let mut m = t1;
        t3 += t2 >> 52;
        t2 &= M52;
        m &= t2;
        t4 += t3 >> 52;
        t3 &= M52;
        m &= t3;
        x = (t4 >> 48) | u64::from((t4 == M48) & (m == M52) & (t0 >= P0));
        if x != 0 {
            t0 += 0x1_0000_03D1;
            t1 += t0 >> 52;
            t0 &= M52;
            t2 += t1 >> 52;
            t1 &= M52;
            t3 += t2 >> 52;
            t2 &= M52;
            t4 += t3 >> 52;
            t3 &= M52;
            t4 &= M48;
        }
        *self = Fe::with([t0, t1, t2, t3, t4], 1, true);
        self.check();
    }

    /// Reduces to magnitude 1 (the value may still be p or above).
    #[inline]
    pub fn normalize_weak(&mut self) {
        self.check();
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;
        let x = t4 >> 48;
        t4 &= M48;
        t0 += x * 0x1_0000_03D1;
        t1 += t0 >> 52;
        t0 &= M52;
        t2 += t1 >> 52;
        t1 &= M52;
        t3 += t2 >> 52;
        t2 &= M52;
        t4 += t3 >> 52;
        t3 &= M52;
        *self = Fe::with([t0, t1, t2, t3, t4], 1, false);
        self.check();
    }

    /// Whether the value is 0 mod p, without normalizing (any magnitude).
    #[inline]
    pub fn normalizes_to_zero(&self) -> bool {
        self.check();
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;
        let x = t4 >> 48;
        t0 += x * 0x1_0000_03D1;
        // z0 tracks a raw value of 0, z1 a raw value of p.
        let mut z0 = t0 & M52;
        let mut z1 = z0 ^ 0x1_0000_03D0;
        if (z0 != 0) & (z1 != M52) {
            return false;
        }
        t4 &= M48;
        t1 += t0 >> 52;
        t2 += t1 >> 52;
        t1 &= M52;
        z0 |= t1;
        z1 &= t1;
        t3 += t2 >> 52;
        t2 &= M52;
        z0 |= t2;
        z1 &= t2;
        t4 += t3 >> 52;
        t3 &= M52;
        z0 |= t3;
        z1 &= t3;
        z0 |= t4;
        z1 &= t4 ^ 0xF_0000_0000_0000;
        (z0 == 0) | (z1 == M52)
    }

    /// Requires a normalized element.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.assert_norm();
        (self.n[0] | self.n[1] | self.n[2] | self.n[3] | self.n[4]) == 0
    }

    /// Requires a normalized element.
    #[inline]
    pub fn is_odd(&self) -> bool {
        self.assert_norm();
        self.n[0] & 1 == 1
    }

    #[inline(always)]
    pub fn add(&mut self, a: &Fe) {
        self.check();
        a.check();
        for i in 0..5 {
            self.n[i] += a.n[i];
        }
        #[cfg(debug_assertions)]
        {
            self.mag += a.mag;
            self.norm = false;
        }
        self.check();
    }

    /// p * 2 * (m + 1) - self: the negation, at magnitude `m + 1`.
    #[inline(always)]
    pub fn negate(&self, m: u32) -> Fe {
        self.assert_mag(m);
        let k = 2 * (u64::from(m) + 1);
        let r = Fe::with(
            [P0 * k - self.n[0], M52 * k - self.n[1], M52 * k - self.n[2], M52 * k - self.n[3], M48 * k - self.n[4]],
            m + 1,
            false,
        );
        r.check();
        r
    }

    #[inline(always)]
    pub fn mul_int(&mut self, k: u32) {
        self.check();
        for i in 0..5 {
            self.n[i] *= u64::from(k);
        }
        #[cfg(debug_assertions)]
        {
            self.mag *= k;
            self.norm = false;
        }
        self.check();
    }

    /// self / 2.
    #[inline]
    pub fn half(&mut self) {
        self.assert_mag(31);
        let [mut t0, mut t1, mut t2, mut t3, mut t4] = self.n;
        let mask = (t0 & 1).wrapping_neg() >> 12;
        t0 += P0 & mask;
        t1 += mask;
        t2 += mask;
        t3 += mask;
        t4 += mask >> 4;
        let n = [(t0 >> 1) + ((t1 & 1) << 51), (t1 >> 1) + ((t2 & 1) << 51), (t2 >> 1) + ((t3 & 1) << 51), (t3 >> 1) + ((t4 & 1) << 51), t4 >> 1];
        #[cfg(debug_assertions)]
        let mag = self.mag / 2 + 1;
        #[cfg(not(debug_assertions))]
        let mag = 0;
        *self = Fe::with(n, mag, false);
        self.check();
    }

    #[inline(always)]
    pub fn mul(&self, b: &Fe) -> Fe {
        self.assert_mag(8);
        b.assert_mag(8);
        Fe::with(mul_inner(&self.n, &b.n), 1, false)
    }

    #[inline(always)]
    pub fn sqr(&self) -> Fe {
        self.assert_mag(8);
        Fe::with(sqr_inner(&self.n), 1, false)
    }

    /// Whether `self == b` mod p. `self` at most magnitude 1, `b` at most 31.
    #[inline]
    pub fn equal(&self, b: &Fe) -> bool {
        let mut na = self.negate(1);
        na.add(b);
        na.normalizes_to_zero()
    }

    fn sqr_n(&self, n: usize) -> Fe {
        let mut r = *self;
        for _ in 0..n {
            r = r.sqr();
        }
        r
    }

    /// a^(2^223 - 1), with the intermediate powers both exponentiations reuse:
    /// (a^(2^2 - 1), a^(2^22 - 1), a^(2^223 - 1)).
    fn pow_chain(&self) -> (Fe, Fe, Fe) {
        let a = self;
        let x2 = a.sqr().mul(a);
        let x3 = x2.sqr().mul(a);
        let x6 = x3.sqr_n(3).mul(&x3);
        let x9 = x6.sqr_n(3).mul(&x3);
        let x11 = x9.sqr_n(2).mul(&x2);
        let x22 = x11.sqr_n(11).mul(&x11);
        let x44 = x22.sqr_n(22).mul(&x22);
        let x88 = x44.sqr_n(44).mul(&x44);
        let x176 = x88.sqr_n(88).mul(&x88);
        let x220 = x176.sqr_n(44).mul(&x44);
        let x223 = x220.sqr_n(3).mul(&x3);
        (x2, x22, x223)
    }

    /// A square root, when one exists. p = 3 mod 4, so it is a^((p+1)/4);
    /// the result is checked by squaring. Input magnitude at most 8.
    pub fn sqrt(&self) -> Option<Fe> {
        let (x2, x22, x223) = self.pow_chain();
        let t = x223.sqr_n(23).mul(&x22).sqr_n(6).mul(&x2).sqr_n(2);
        let mut back = t.sqr();
        back.normalize_weak();
        let mut a = *self;
        a.normalize_weak();
        back.equal(&a).then_some(t)
    }

    /// The inverse (0 for 0): a^(p-2). Input magnitude at most 8.
    pub fn inv(&self) -> Fe {
        let (x2, x22, x223) = self.pow_chain();
        x223.sqr_n(23).mul(&x22).sqr_n(5).mul(self).sqr_n(3).mul(&x2).sqr_n(2).mul(self)
    }
}

/// The product of two elements, reduced to magnitude 1 (libsecp256k1's
/// `fe_mul_inner`: 25 64x64 multiplies in two 128-bit accumulators, the high
/// half folded back through 2^256 = 0x1000003D1).
#[inline(always)]
fn mul_inner(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let m = |x: u64, y: u64| (x as u128) * (y as u128);
    let [a0, a1, a2, a3, a4] = *a;
    let mut r = [0u64; 5];

    let mut d = m(a0, b[3]) + m(a1, b[2]) + m(a2, b[1]) + m(a3, b[0]);
    let mut c = m(a4, b[4]);
    d += m(R, c as u64);
    c >>= 64;
    let t3 = (d as u64) & M52;
    d >>= 52;

    d += m(a0, b[4]) + m(a1, b[3]) + m(a2, b[2]) + m(a3, b[1]) + m(a4, b[0]);
    d += m(R << 12, c as u64);
    let mut t4 = (d as u64) & M52;
    d >>= 52;
    let tx = t4 >> 48;
    t4 &= M52 >> 4;

    c = m(a0, b[0]);
    d += m(a1, b[4]) + m(a2, b[3]) + m(a3, b[2]) + m(a4, b[1]);
    let mut u0 = (d as u64) & M52;
    d >>= 52;
    u0 = (u0 << 4) | tx;
    c += m(u0, R >> 4);
    r[0] = (c as u64) & M52;
    c >>= 52;

    c += m(a0, b[1]) + m(a1, b[0]);
    d += m(a2, b[4]) + m(a3, b[3]) + m(a4, b[2]);
    c += m((d as u64) & M52, R);
    d >>= 52;
    r[1] = (c as u64) & M52;
    c >>= 52;

    c += m(a0, b[2]) + m(a1, b[1]) + m(a2, b[0]);
    d += m(a3, b[4]) + m(a4, b[3]);
    c += m(R, d as u64);
    d >>= 64;
    r[2] = (c as u64) & M52;
    c >>= 52;

    c += m(R << 12, d as u64) + (t3 as u128);
    r[3] = (c as u64) & M52;
    c >>= 52;
    r[4] = (c as u64) + t4;
    r
}

/// `mul_inner(a, a)` with the symmetric products doubled instead of repeated.
#[inline(always)]
fn sqr_inner(a: &[u64; 5]) -> [u64; 5] {
    let m = |x: u64, y: u64| (x as u128) * (y as u128);
    let [mut a0, a1, a2, a3, mut a4] = *a;
    let mut r = [0u64; 5];

    let mut d = m(a0 * 2, a3) + m(a1 * 2, a2);
    let mut c = m(a4, a4);
    d += m(R, c as u64);
    c >>= 64;
    let t3 = (d as u64) & M52;
    d >>= 52;

    a4 *= 2;
    d += m(a0, a4) + m(a1 * 2, a3) + m(a2, a2);
    d += m(R << 12, c as u64);
    let mut t4 = (d as u64) & M52;
    d >>= 52;
    let tx = t4 >> 48;
    t4 &= M52 >> 4;

    c = m(a0, a0);
    d += m(a1, a4) + m(a2 * 2, a3);
    let mut u0 = (d as u64) & M52;
    d >>= 52;
    u0 = (u0 << 4) | tx;
    c += m(u0, R >> 4);
    r[0] = (c as u64) & M52;
    c >>= 52;

    a0 *= 2;
    c += m(a0, a1);
    d += m(a2, a4) + m(a3, a3);
    c += m((d as u64) & M52, R);
    d >>= 52;
    r[1] = (c as u64) & M52;
    c >>= 52;

    c += m(a0, a2) + m(a1, a1);
    d += m(a3, a4);
    c += m(R, d as u64);
    d >>= 64;
    r[2] = (c as u64) & M52;
    c >>= 52;

    c += m(R << 12, d as u64) + (t3 as u128);
    r[3] = (c as u64) & M52;
    c >>= 52;
    r[4] = (c as u64) + t4;
    r
}
