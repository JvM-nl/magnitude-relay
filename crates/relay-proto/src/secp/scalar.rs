//! Arithmetic modulo n, the order of the secp256k1 group: four 64-bit limbs,
//! always fully reduced. Only what batch verification needs: parsing, add,
//! multiply, negate, and the GLV split into two half-size scalars.

/// n, little-endian limbs.
const N: [u64; 4] = [0xBFD2_5E8C_D036_4141, 0xBAAE_DCE6_AF48_A03B, 0xFFFF_FFFF_FFFF_FFFE, 0xFFFF_FFFF_FFFF_FFFF];
/// 2^256 - n (129 bits).
const NC: [u64; 3] = [!N[0] + 1, !N[1], 1];

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Scalar(pub(crate) [u64; 4]);

impl Scalar {
    pub const ZERO: Scalar = Scalar([0; 4]);
    pub const ONE: Scalar = Scalar([1, 0, 0, 0]);
    /// The cube root of unity matching `Fe::BETA`: lambda * (x, y) = (beta * x, y).
    pub const LAMBDA: Scalar = Scalar::from_be_words([0x5363AD4C, 0xC05C30E0, 0xA5261C02, 0x8812645A, 0x122E22EA, 0x20816678, 0xDF02967C, 0x1B23BD72]);

    pub const fn from_be_words(w: [u32; 8]) -> Scalar {
        Scalar([
            (w[7] as u64) | ((w[6] as u64) << 32),
            (w[5] as u64) | ((w[4] as u64) << 32),
            (w[3] as u64) | ((w[2] as u64) << 32),
            (w[1] as u64) | ((w[0] as u64) << 32),
        ])
    }

    pub fn from_u128(v: u128) -> Scalar {
        Scalar([v as u64, (v >> 64) as u64, 0, 0])
    }

    /// 32 big-endian bytes; `None` when the value is not below n.
    pub fn from_bytes(b: &[u8; 32]) -> Option<Scalar> {
        let s = Scalar::from_bytes_unreduced(b);
        (!s.overflows()).then_some(s)
    }

    /// 32 big-endian bytes reduced mod n (a hash output becomes a challenge).
    pub fn from_bytes_mod(b: &[u8; 32]) -> Scalar {
        let mut s = Scalar::from_bytes_unreduced(b);
        if s.overflows() {
            s = s.add_raw(&Scalar([NC[0], NC[1], NC[2], 0])).0;
        }
        s
    }

    fn from_bytes_unreduced(b: &[u8; 32]) -> Scalar {
        let w = |i: usize| u64::from_be_bytes(b[i..i + 8].try_into().unwrap());
        Scalar([w(24), w(16), w(8), w(0)])
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.0[3 - i].to_be_bytes());
        }
        out
    }

    /// Whether the (unreduced) value is n or more.
    fn overflows(&self) -> bool {
        let d = &self.0;
        for i in (0..4).rev() {
            if d[i] != N[i] {
                return d[i] > N[i];
            }
        }
        true
    }

    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0
    }

    /// Plain 256-bit addition with the carry out.
    fn add_raw(&self, b: &Scalar) -> (Scalar, bool) {
        let mut r = [0u64; 4];
        let mut carry = false;
        for ((r, &x), &y) in r.iter_mut().zip(&self.0).zip(&b.0) {
            let (s, c1) = x.overflowing_add(y);
            let (s, c2) = s.overflowing_add(u64::from(carry));
            *r = s;
            carry = c1 | c2;
        }
        (Scalar(r), carry)
    }

    pub fn add(&self, b: &Scalar) -> Scalar {
        let (mut r, carry) = self.add_raw(b);
        // Both inputs are below n, so one subtraction of n (adding 2^256 - n) suffices.
        if carry || r.overflows() {
            r = r.add_raw(&Scalar([NC[0], NC[1], NC[2], 0])).0;
        }
        r
    }

    pub fn negate(&self) -> Scalar {
        if self.is_zero() {
            return *self;
        }
        let mut r = [0u64; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (d, b1) = N[i].overflowing_sub(self.0[i]);
            let (d, b2) = d.overflowing_sub(u64::from(borrow));
            r[i] = d;
            borrow = b1 | b2;
        }
        Scalar(r)
    }

    /// Whether the value is above n / 2 (its negation is then the smaller one).
    pub fn is_high(&self) -> bool {
        const NH: [u64; 4] = [0xDFE9_2F46_681B_20A0, 0x5D57_6E73_57A4_501D, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF];
        for i in (0..4).rev() {
            if self.0[i] != NH[i] {
                return self.0[i] > NH[i];
            }
        }
        false
    }

    pub fn mul(&self, b: &Scalar) -> Scalar {
        reduce512(&mul_wide(&self.0, &b.0))
    }

    /// The value when it fits 128 bits.
    pub fn as_u128(&self) -> Option<u128> {
        (self.0[2] | self.0[3] == 0).then(|| u128::from(self.0[0]) | (u128::from(self.0[1]) << 64))
    }

    /// Splits k into (k1, k2) with k1 + k2 * lambda = k mod n and both halves
    /// below 2^128 in absolute value (libsecp256k1's `scalar_split_lambda`,
    /// after Gouvea-Oliveira-Lopez). Each half comes back as a magnitude and a
    /// sign: `(m, true)` stands for -m.
    pub fn split_lambda(&self) -> [(u128, bool); 2] {
        const MINUS_B1: Scalar = Scalar::from_be_words([0, 0, 0, 0, 0xE4437ED6, 0x010E8828, 0x6F547FA9, 0x0ABFE4C3]);
        const MINUS_B2: Scalar = Scalar::from_be_words([0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0x8A280AC5, 0x0774346D, 0xD765CDA8, 0x3DB1562C]);
        const G1: Scalar = Scalar::from_be_words([0x3086D221, 0xA7D46BCD, 0xE86C90E4, 0x9284EB15, 0x3DAA8A14, 0x71E8CA7F, 0xE893209A, 0x45DBB031]);
        const G2: Scalar = Scalar::from_be_words([0xE4437ED6, 0x010E8828, 0x6F547FA9, 0x0ABFE4C4, 0x221208AC, 0x9DF506C6, 0x1571B4AE, 0x8AC47F71]);
        let c1 = mul_shift_384(self, &G1).mul(&MINUS_B1);
        let c2 = mul_shift_384(self, &G2).mul(&MINUS_B2);
        let r2 = c1.add(&c2);
        let r1 = self.add(&r2.mul(&Scalar::LAMBDA).negate());
        [r1, r2].map(|r| {
            let (m, neg) = if r.is_high() { (r.negate(), true) } else { (r, false) };
            (m.as_u128().expect("lambda split halves fit 128 bits"), neg)
        })
    }
}

/// The full 512-bit product, little-endian limbs.
#[inline]
fn mul_wide(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let t = (a[i] as u128) * (b[j] as u128) + (r[i + j] as u128) + carry;
            r[i + j] = t as u64;
            carry = t >> 64;
        }
        r[i + 4] = carry as u64;
    }
    r
}

/// x mod n for a 512-bit x, by folding 2^256 = 2^256 - n (mod n) until the
/// value fits, then at most two subtractions.
fn reduce512(x: &[u64; 8]) -> Scalar {
    // x = hi * 2^256 + lo = hi * NC + lo. NC has 129 bits, so each fold takes
    // the excess from 256 bits to 129 more: 512 -> 386 -> 260 -> 256 + a carry.
    let mut v = *x;
    while v[4] | v[5] | v[6] | v[7] != 0 {
        v = fold(&v);
    }
    let mut s = Scalar([v[0], v[1], v[2], v[3]]);
    while s.overflows() {
        s = s.add_raw(&Scalar([NC[0], NC[1], NC[2], 0])).0;
    }
    s
}

/// lo + hi * (2^256 - n), where lo is limbs 0..4 and hi limbs 4..8.
#[inline]
fn fold(x: &[u64; 8]) -> [u64; 8] {
    let mut r = [x[0], x[1], x[2], x[3], 0, 0, 0, 0];
    for i in 0..4 {
        let h = x[4 + i];
        if h == 0 {
            continue;
        }
        let mut carry: u128 = 0;
        for j in 0..3 {
            let t = (h as u128) * (NC[j] as u128) + (r[i + j] as u128) + carry;
            r[i + j] = t as u64;
            carry = t >> 64;
        }
        let mut k = i + 3;
        while carry != 0 {
            let t = (r[k] as u128) + carry;
            r[k] = t as u64;
            carry = t >> 64;
            k += 1;
        }
    }
    r
}

/// round(a * b / 2^384).
fn mul_shift_384(a: &Scalar, b: &Scalar) -> Scalar {
    let w = mul_wide(&a.0, &b.0);
    let mut r = Scalar([w[6], w[7], 0, 0]);
    if w[5] >> 63 == 1 {
        r = r.add_raw(&Scalar::ONE).0;
    }
    r
}
