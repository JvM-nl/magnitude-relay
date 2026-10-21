//! Points on secp256k1 (y^2 = x^3 + 7): affine and Jacobian forms and the
//! variable-time formulas batch verification needs. Verification only touches
//! public data, so nothing here tries to be constant-time.
//!
//! The formulas and magnitude bounds are libsecp256k1's (`group_impl.h`):
//! Jacobian x, y at most magnitude 4 and z at most 1; affine points here are
//! always normalized.

use super::field::Fe;

/// An affine point, normalized coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Affine {
    pub x: Fe,
    pub y: Fe,
}

/// (X, Y, Z) standing for (X / Z^2, Y / Z^3).
#[derive(Clone, Copy, Debug)]
pub struct Jacobian {
    pub x: Fe,
    pub y: Fe,
    pub z: Fe,
    pub infinity: bool,
}

impl Affine {
    /// The generator.
    pub const G: Affine = Affine {
        x: Fe::from_be_words([0x79BE667E, 0xF9DCBBAC, 0x55A06295, 0xCE870B07, 0x029BFCDB, 0x2DCE28D9, 0x59F2815B, 0x16F81798]),
        y: Fe::from_be_words([0x483ADA77, 0x26A3C465, 0x5DA4FBFC, 0x0E1108A8, 0xFD17B448, 0xA6855419, 0x9C47D08F, 0xFB10D4B8]),
    };

    /// BIP-340's lift_x: the point with this x and an even y, when x is below
    /// p and x^3 + 7 is a square.
    pub fn lift_x(x_bytes: &[u8; 32]) -> Option<Affine> {
        let x = Fe::from_bytes(x_bytes)?;
        let mut c = x.sqr().mul(&x);
        c.add(&Fe::SEVEN);
        let mut y = c.sqrt()?;
        y.normalize();
        if y.is_odd() {
            y = y.negate(1);
            y.normalize();
        }
        Some(Affine { x, y })
    }

    /// A point from SEC1 uncompressed bytes (0x04 || x || y), checked to be
    /// on the curve.
    pub fn from_uncompressed(b: &[u8; 65]) -> Option<Affine> {
        if b[0] != 4 {
            return None;
        }
        let x = Fe::from_bytes(b[1..33].try_into().unwrap())?;
        let y = Fe::from_bytes(b[33..65].try_into().unwrap())?;
        let p = Affine { x, y };
        p.on_curve().then_some(p)
    }

    pub fn neg(&self) -> Affine {
        let mut y = self.y.negate(1);
        y.normalize();
        Affine { x: self.x, y }
    }

    /// lambda * self, which is (beta * x, y).
    pub fn mul_lambda(&self) -> Affine {
        let mut x = self.x.mul(&Fe::BETA);
        x.normalize();
        Affine { x, y: self.y }
    }

    /// Whether the coordinates satisfy the curve equation.
    pub fn on_curve(&self) -> bool {
        let mut rhs = self.x.sqr().mul(&self.x);
        rhs.add(&Fe::SEVEN);
        let mut lhs = self.y.sqr();
        lhs.normalize_weak();
        lhs.equal(&rhs)
    }
}

impl Jacobian {
    pub const INFINITY: Jacobian = Jacobian { x: Fe::ZERO, y: Fe::ZERO, z: Fe::ONE, infinity: true };

    pub fn from_affine(a: &Affine) -> Jacobian {
        Jacobian { x: a.x, y: a.y, z: Fe::ONE, infinity: false }
    }

    /// The affine form (one inversion), `None` for infinity.
    pub fn to_affine(&self) -> Option<Affine> {
        if self.infinity {
            return None;
        }
        let zi = self.z.inv();
        let zi2 = zi.sqr();
        let mut x = self.x.mul(&zi2);
        let mut y = self.y.mul(&zi2.mul(&zi));
        x.normalize();
        y.normalize();
        Some(Affine { x, y })
    }

    pub fn neg(&self) -> Jacobian {
        let mut y = self.y;
        y.normalize_weak();
        Jacobian { y: y.negate(1), ..*self }
    }

    /// 2 * self: 3 mul, 4 sqr. Never infinity unless self is (no point of
    /// order 2 exists on the curve).
    #[inline]
    pub fn double(&self) -> Jacobian {
        if self.infinity {
            return *self;
        }
        let a = self;
        let z = a.z.mul(&a.y);
        let mut s = a.y.sqr();
        let mut l = a.x.sqr();
        l.mul_int(3);
        l.half();
        let mut t = s.negate(1);
        t = t.mul(&a.x);
        let mut x = l.sqr();
        x.add(&t);
        x.add(&t);
        s = s.sqr();
        t.add(&x);
        let mut y = t.mul(&l);
        y.add(&s);
        let y = y.negate(2);
        Jacobian { x, y, z, infinity: false }
    }

    /// self + b for an affine b: 8 mul, 3 sqr.
    #[inline]
    pub fn add_affine(&self, b: &Affine) -> Jacobian {
        if self.infinity {
            return Jacobian::from_affine(b);
        }
        let a = self;
        let z12 = a.z.sqr();
        let u1 = a.x;
        let u2 = b.x.mul(&z12);
        let s1 = a.y;
        let s2 = b.y.mul(&z12).mul(&a.z);
        let mut h = u1.negate(4);
        h.add(&u2);
        let mut i = s2.negate(1);
        i.add(&s1);
        if h.normalizes_to_zero() {
            return if i.normalizes_to_zero() { a.double() } else { Jacobian::INFINITY };
        }
        Jacobian::finish_add(&a.z.mul(&h), &h, &i, &u1, &s1)
    }

    /// self + b: 12 mul, 4 sqr.
    #[inline]
    pub fn add(&self, b: &Jacobian) -> Jacobian {
        if self.infinity {
            return *b;
        }
        if b.infinity {
            return *self;
        }
        let a = self;
        let z22 = b.z.sqr();
        let z12 = a.z.sqr();
        let u1 = a.x.mul(&z22);
        let u2 = b.x.mul(&z12);
        let s1 = a.y.mul(&z22).mul(&b.z);
        let s2 = b.y.mul(&z12).mul(&a.z);
        let mut h = u1.negate(1);
        h.add(&u2);
        let mut i = s2.negate(1);
        i.add(&s1);
        if h.normalizes_to_zero() {
            return if i.normalizes_to_zero() { a.double() } else { Jacobian::INFINITY };
        }
        let t = h.mul(&b.z);
        Jacobian::finish_add(&a.z.mul(&t), &h, &i, &u1, &s1)
    }

    /// The shared tail of both additions, given z3, h = u2 - u1, i = s1 - s2.
    #[inline(always)]
    fn finish_add(z: &Fe, h: &Fe, i: &Fe, u1: &Fe, s1: &Fe) -> Jacobian {
        let h2 = h.sqr().negate(1);
        let mut h3 = h2.mul(h);
        let mut t = u1.mul(&h2);
        let mut x = i.sqr();
        x.add(&h3);
        x.add(&t);
        x.add(&t);
        t.add(&x);
        let mut y = t.mul(i);
        h3 = h3.mul(s1);
        y.add(&h3);
        Jacobian { x, y, z: *z, infinity: false }
    }
}
