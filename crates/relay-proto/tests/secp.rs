//! Differential tests of our secp256k1 arithmetic and BIP-340 batch
//! verification: field and scalar operations against big-integer reference
//! arithmetic, points and multi-scalar sums against libsecp256k1, and batch
//! verdicts against libsecp256k1's own verifier, on BIP-340's test vectors and
//! on random valid and corrupted signatures.
//!
//! Iteration counts are modest for `cargo test`; `SECP_DIFF_SCALE=<k>`
//! multiplies them all (the production box runs them by the million in
//! release, ignored test included).

use num_bigint::BigUint;
use relay_proto::hex;
use relay_proto::secp::field::Fe;
use relay_proto::secp::group::{Affine, Jacobian};
use relay_proto::secp::msm::{self, Term};
use relay_proto::secp::scalar::Scalar;
use relay_proto::secp::{verify_one, SigRef, Verifier};
use secp256k1::{schnorr, Keypair, Parity, PublicKey, SecretKey, XOnlyPublicKey};

/// splitmix64: deterministic, so a failure reproduces from its seed.
struct Rng(u64);

impl Rng {
    fn u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.u64() % n
    }

    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for c in b.chunks_mut(8) {
            c.copy_from_slice(&self.u64().to_le_bytes());
        }
        b
    }

    fn u128(&mut self) -> u128 {
        u128::from(self.u64()) | (u128::from(self.u64()) << 64)
    }

    /// 32 bytes biased toward the edges: zero, one, near 2^256, near p and n,
    /// long runs of 0xff and 0x00, and plain random.
    fn edgy32(&mut self) -> [u8; 32] {
        let mut b = self.bytes32();
        match self.below(10) {
            0 => b = [0; 32],
            1 => {
                b = [0; 32];
                b[31] = self.below(4) as u8;
            }
            2 => {
                b = [0xff; 32];
                b[31] = b[31].wrapping_sub(self.below(4) as u8);
            }
            3 => {
                b = big_to_32(&(p() - BigUint::from(self.below(5))));
            }
            4 => {
                b = big_to_32(&(n() - BigUint::from(self.below(5))));
            }
            5 => {
                let k = self.below(32) as usize;
                b[..k].fill(0xff);
            }
            6 => {
                let k = self.below(32) as usize;
                b[..k].fill(0);
            }
            _ => {}
        }
        b
    }
}

fn iters(default: usize) -> usize {
    default * std::env::var("SECP_DIFF_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

fn p() -> BigUint {
    BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16).unwrap()
}

fn n() -> BigUint {
    BigUint::parse_bytes(b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16).unwrap()
}

fn big(b: &[u8; 32]) -> BigUint {
    BigUint::from_bytes_be(b)
}

fn big_to_32(x: &BigUint) -> [u8; 32] {
    let v = x.to_bytes_be();
    assert!(v.len() <= 32);
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

fn fe_bytes(mut f: Fe) -> [u8; 32] {
    f.normalize();
    f.to_bytes()
}

fn fe(b: &[u8; 32]) -> Fe {
    Fe::from_bytes(b).unwrap()
}

#[test]
fn field_matches_big_integers() {
    let mut rng = Rng(1);
    let p = p();
    for _ in 0..iters(20_000) {
        let (ab, bb) = (rng.edgy32(), rng.edgy32());
        assert_eq!(Fe::from_bytes(&ab).is_some(), big(&ab) < p, "parse range of {}", hex::encode_string(&ab));
        let (Some(a), Some(b)) = (Fe::from_bytes(&ab), Fe::from_bytes(&bb)) else { continue };
        let (x, y) = (big(&ab), big(&bb));
        assert_eq!(a.to_bytes(), ab);
        assert_eq!(fe_bytes(a.mul(&b)), big_to_32(&(&x * &y % &p)), "mul");
        assert_eq!(fe_bytes(a.sqr()), big_to_32(&(&x * &x % &p)), "sqr");
        let mut s = a;
        s.add(&b);
        assert_eq!(fe_bytes(s), big_to_32(&((&x + &y) % &p)), "add");
        assert_eq!(fe_bytes(a.negate(1)), big_to_32(&((&p - &x) % &p)), "negate");
        let mut h = a;
        h.half();
        assert_eq!(fe_bytes(h), big_to_32(&(&x * ((&p + 1u32) / 2u32) % &p)), "half");
        assert_eq!(fe_bytes(a.inv()), big_to_32(&x.modpow(&(&p - 2u32), &p)), "inv");
        let root = x.modpow(&((&p + 1u32) / 4u32), &p);
        let is_square = &root * &root % &p == x;
        match a.sqrt() {
            Some(r) => {
                assert!(is_square, "sqrt of a non-square");
                let r = big(&fe_bytes(r));
                assert_eq!(&r * &r % &p, x, "sqrt");
            }
            None => assert!(!is_square, "no sqrt for a square"),
        }
        assert!(a.equal(&a));
        assert_eq!(a.equal(&b), x == y);
        // Zero in disguise: a + (-a) at a raised magnitude.
        let mut z = a.negate(1);
        z.add(&a);
        assert!(z.normalizes_to_zero());
        assert_eq!(s.normalizes_to_zero(), (&x + &y) % &p == BigUint::ZERO);
    }
}

#[test]
fn field_at_maximum_magnitude() {
    // mul and sqr accept magnitude 8: build inputs from 8 added copies and
    // from negations, whose limbs carry the most excess.
    let mut rng = Rng(2);
    let p = p();
    for _ in 0..iters(20_000) {
        let (ab, bb) = (big_to_32(&(big(&rng.edgy32()) % &p)), big_to_32(&(big(&rng.edgy32()) % &p)));
        let (a, b) = (fe(&ab), fe(&bb));
        let mut a8 = a;
        for _ in 0..7 {
            a8.add(&a);
        }
        let b8 = b.negate(7);
        let (x8, y8) = (big(&ab) * 8u32 % &p, (&p - big(&bb)) % &p);
        assert_eq!(fe_bytes(a8.mul(&b8)), big_to_32(&(&x8 * &y8 % &p)));
        assert_eq!(fe_bytes(a8.sqr()), big_to_32(&(&x8 * &x8 % &p)));
        assert_eq!(fe_bytes(b8.sqr()), big_to_32(&(&y8 * &y8 % &p)));
        let mut w = a8;
        w.normalize_weak();
        assert_eq!(fe_bytes(w), big_to_32(&x8));
    }
}

#[test]
fn scalars_match_big_integers() {
    let mut rng = Rng(3);
    let n = n();
    let lambda = BigUint::parse_bytes(b"5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72", 16).unwrap();
    for _ in 0..iters(20_000) {
        let (ab, bb) = (rng.edgy32(), rng.edgy32());
        assert_eq!(Scalar::from_bytes(&ab).is_some(), big(&ab) < n);
        assert_eq!(Scalar::from_bytes_mod(&ab).to_bytes(), big_to_32(&(big(&ab) % &n)));
        let (a, b) = (Scalar::from_bytes_mod(&ab), Scalar::from_bytes_mod(&bb));
        let (x, y) = (big(&ab) % &n, big(&bb) % &n);
        assert_eq!(a.add(&b).to_bytes(), big_to_32(&((&x + &y) % &n)), "add");
        assert_eq!(a.mul(&b).to_bytes(), big_to_32(&(&x * &y % &n)), "mul");
        assert_eq!(a.negate().to_bytes(), big_to_32(&((&n - &x) % &n)), "negate");
        let [(k1, n1), (k2, n2)] = a.split_lambda();
        let signed = |k: u128, neg: bool| {
            let v = BigUint::from(k);
            if neg {
                (&n - v) % &n
            } else {
                v
            }
        };
        assert_eq!((signed(k1, n1) + signed(k2, n2) * &lambda) % &n, x, "split");
        let w = rng.u128();
        assert_eq!(Scalar::from_u128(w).to_bytes(), big_to_32(&BigUint::from(w)));
    }
}

/// A random point and its libsecp256k1 twin.
fn random_point(rng: &mut Rng) -> (Affine, PublicKey) {
    loop {
        if let Ok(sk) = SecretKey::from_secret_bytes(rng.bytes32()) {
            let pk = PublicKey::from_secret_key(&sk);
            return (affine_of(&pk), pk);
        }
    }
}

fn affine_of(pk: &PublicKey) -> Affine {
    let u = pk.serialize_uncompressed();
    Affine { x: fe(u[1..33].try_into().unwrap()), y: fe(u[33..65].try_into().unwrap()) }
}

fn same_point(ours: &Jacobian, theirs: Option<&PublicKey>) -> bool {
    match (ours.to_affine(), theirs) {
        (None, None) => true,
        (Some(a), Some(t)) => {
            let u = t.serialize_uncompressed();
            a.x.to_bytes() == u[1..33] && a.y.to_bytes() == u[33..65]
        }
        _ => false,
    }
}

#[test]
fn lift_x_matches_libsecp() {
    let mut rng = Rng(4);
    for i in 0..iters(20_000) {
        // Every other x is a real pubkey (so lifts succeed often enough).
        let x = if i % 2 == 0 { rng.edgy32() } else { random_point(&mut rng).1.x_only_public_key().0.to_byte_array() };
        let ours = Affine::lift_x(&x);
        let theirs = XOnlyPublicKey::from_byte_array(x).ok().map(|k| k.public_key(Parity::Even));
        assert_eq!(ours.is_some(), theirs.is_some(), "lift_x({}) disagrees", hex::encode_string(&x));
        if let (Some(a), Some(t)) = (ours, theirs) {
            assert!(same_point(&Jacobian::from_affine(&a), Some(&t)));
            assert!(a.on_curve());
        }
    }
}

#[test]
fn point_arithmetic_matches_libsecp() {
    let mut rng = Rng(5);
    for _ in 0..iters(5_000) {
        let (a, ta) = random_point(&mut rng);
        let (b, tb) = random_point(&mut rng);
        let ja = Jacobian::from_affine(&a);
        let jb = Jacobian::from_affine(&b);
        assert!(same_point(&ja.add_affine(&b), ta.combine(&tb).ok().as_ref()), "add_affine");
        assert!(same_point(&ja.add(&jb), ta.combine(&tb).ok().as_ref()), "add");
        assert!(same_point(&ja.double(), ta.combine(&ta).ok().as_ref()), "double");
        assert!(same_point(&ja.add_affine(&a), ta.combine(&ta).ok().as_ref()), "add_affine of itself doubles");
        assert!(ja.add_affine(&a.neg()).infinity, "P + -P");
        assert!(ja.add(&ja.neg()).infinity, "P + -P (jacobian)");
        // Mixed representations: a Jacobian point with z != 1.
        let j2 = ja.double().add(&jb);
        let t2 = ta.combine(&ta).unwrap().combine(&tb).ok();
        assert!(same_point(&j2.add_affine(&b), t2.as_ref().and_then(|t| t.combine(&tb).ok()).as_ref()));
        assert!(same_point(&j2.add(&j2), t2.as_ref().and_then(|t| t.combine(t).ok()).as_ref()));
        assert!(same_point(&Jacobian::from_affine(&a.mul_lambda()), Some(&ta.mul_tweak(&lambda()).unwrap())));
    }
}

fn lambda() -> secp256k1::Scalar {
    secp256k1::Scalar::from_be_bytes(Scalar::LAMBDA.to_bytes()).unwrap()
}

/// sum(k_i P_i) by libsecp256k1, one multiplication per term (None = infinity).
fn reference_sum(terms: &[(PublicKey, u128)]) -> Option<PublicKey> {
    let parts: Vec<PublicKey> = terms
        .iter()
        .filter(|(_, k)| *k != 0)
        .map(|(p, k)| p.mul_tweak(&secp256k1::Scalar::from_be_bytes(big_to_32(&BigUint::from(*k))).unwrap()).unwrap())
        .collect();
    if parts.is_empty() {
        return None;
    }
    let refs: Vec<&PublicKey> = parts.iter().collect();
    PublicKey::combine_keys(&refs).ok()
}

#[test]
fn multi_scalar_sums_match_libsecp() {
    let mut rng = Rng(6);
    let mut s = msm::Scratch::default();
    let rounds = iters(60);
    for round in 0..rounds {
        let len = match round % 4 {
            0 => 1 + rng.below(4) as usize,
            1 => 1 + rng.below(40) as usize,
            _ => 1 + rng.below(400) as usize,
        };
        let mut terms = Vec::new();
        let mut refs = Vec::new();
        for _ in 0..len {
            let (a, t) = random_point(&mut rng);
            let k = match rng.below(8) {
                0 => 0,
                1 => 1,
                2 => u128::MAX,
                3 => rng.u64() as u128,
                _ => rng.u128(),
            };
            terms.push(Term { point: a, k });
            refs.push((t, k));
            // Repeats and opposites exercise the doubling and cancelling paths.
            if rng.below(6) == 0 {
                terms.push(Term { point: a, k });
                refs.push((t, k));
            }
            if rng.below(6) == 0 {
                terms.push(Term { point: a.neg(), k });
                refs.push((t.negate(), k));
            }
        }
        let want = reference_sum(&refs);
        for w in [4, 5, 6] {
            assert!(same_point(&msm::strauss(&terms, w, &mut s), want.as_ref()), "strauss w={w} len={}", terms.len());
        }
        for c in 2..=10 {
            assert!(same_point(&msm::pippenger(&terms, c, &mut s), want.as_ref()), "pippenger c={c} len={}", terms.len());
        }
        assert!(same_point(&msm::msm(&terms, &mut s), want.as_ref()));
    }
    // A sum that cancels exactly.
    let (a, _) = random_point(&mut rng);
    let (b, _) = random_point(&mut rng);
    let k = rng.u128();
    let terms = [Term { point: a, k }, Term { point: b, k: 5 }, Term { point: a.neg(), k }, Term { point: b.neg(), k: 5 }];
    assert!(msm::strauss(&terms, 5, &mut s).infinity);
    assert!(msm::pippenger(&terms, 4, &mut s).infinity);
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode_32(s.as_bytes()).unwrap()
}

fn h64(s: &str) -> [u8; 64] {
    hex::decode_64(s.as_bytes()).unwrap()
}

/// BIP-340's test vectors with 32-byte messages (0-14), as libsecp256k1's
/// tests carry them. 5 and 14 have public keys that do not parse; any
/// signature must fail with them.
const BIP340: &[(&str, &str, &str, bool)] = &[
    ("f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", "0000000000000000000000000000000000000000000000000000000000000000", "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0", true),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a", true),
    ("dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8", "7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c", "5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7", true),
    ("25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3", true),
    ("d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9", "4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703", "00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4", true),
    ("eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", false),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2", false),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd", false),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6", false),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051", false),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197", false),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", false),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", false),
    ("dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", false),
    ("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30", "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89", "6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b", false),
];

struct Owned {
    pk: [u8; 32],
    msg: [u8; 32],
    sig: [u8; 64],
}

impl Owned {
    fn r(&self) -> SigRef<'_> {
        SigRef { pubkey: &self.pk, msg: &self.msg, sig: &self.sig }
    }
}

fn refs(v: &[Owned]) -> Vec<SigRef<'_>> {
    v.iter().map(Owned::r).collect()
}

#[test]
fn bip340_vectors() {
    let vectors: Vec<(Owned, bool)> = BIP340.iter().map(|&(pk, msg, sig, ok)| (Owned { pk: h32(pk), msg: h32(msg), sig: h64(sig) }, ok)).collect();
    let mut v = Verifier::new();
    for (i, (o, ok)) in vectors.iter().enumerate() {
        assert_eq!(verify_one(&o.r()), *ok, "libsecp256k1 on vector {i}");
        assert_eq!(v.verify_all(&[o.r()]), *ok, "batch of one, vector {i}");
        // Paired with each valid vector, in both orders (the first weight is 1).
        for (j, (good, gok)) in vectors.iter().enumerate() {
            if *gok {
                assert_eq!(v.verify_all(&[o.r(), good.r()]), *ok, "vector {i} then {j}");
                assert_eq!(v.verify_all(&[good.r(), o.r()]), *ok, "vector {j} then {i}");
            }
        }
    }
    let valid: Vec<SigRef<'_>> = vectors.iter().filter(|(_, ok)| *ok).map(|(o, _)| o.r()).collect();
    assert!(v.verify_all(&valid));
    let all: Vec<SigRef<'_>> = vectors.iter().map(|(o, _)| o.r()).collect();
    assert!(!v.verify_all(&all));
    let mut verdicts = Vec::new();
    v.verify_batch(&all, &mut verdicts);
    assert_eq!(verdicts, vectors.iter().map(|(_, ok)| *ok).collect::<Vec<_>>());
}

fn signed(rng: &mut Rng, keys: &[Keypair]) -> Owned {
    let kp = &keys[rng.below(keys.len() as u64) as usize];
    let msg = rng.bytes32();
    let sig = schnorr::sign_no_aux_rand(&msg, kp);
    Owned { pk: kp.x_only_public_key().0.to_byte_array(), msg, sig: sig.to_byte_array() }
}

/// Breaks a signature in one of the ways BIP-340 must catch.
fn corrupt(rng: &mut Rng, o: &mut Owned) {
    match rng.below(9) {
        0 => o.sig[rng.below(64) as usize] ^= 1 << rng.below(8),
        1 => o.msg[rng.below(32) as usize] ^= 1 << rng.below(8),
        2 => o.pk[rng.below(32) as usize] ^= 1 << rng.below(8),
        // r not below p.
        3 => o.sig[..32].copy_from_slice(&big_to_32(&(p() + BigUint::from(rng.below(1000))))),
        // s not below n.
        4 => o.sig[32..].copy_from_slice(&big_to_32(&(n() + BigUint::from(rng.below(1000))))),
        // s = s + n would verify if s were reduced: must not.
        5 => {
            let s = big(o.sig[32..].try_into().unwrap()) + n();
            if s.bits() <= 256 {
                o.sig[32..].copy_from_slice(&big_to_32(&s));
            } else {
                o.sig[63] ^= 1;
            }
        }
        // r with odd y: the negated nonce point.
        6 => {
            let s = (n() - big(o.sig[32..].try_into().unwrap()) % n()) % n();
            o.sig[32..].copy_from_slice(&big_to_32(&s));
        }
        7 => o.pk = rng.bytes32(),
        _ => o.sig[..32].copy_from_slice(&rng.bytes32()),
    }
}

#[test]
fn random_batches_match_individual_verification() {
    let mut rng = Rng(7);
    let keys: Vec<Keypair> = (0..64).map(|_| loop {
        if let Ok(k) = Keypair::from_secret_bytes(rng.bytes32()) {
            break k;
        }
    })
    .collect();
    let mut v = Verifier::new();
    let mut verdicts = Vec::new();
    for round in 0..iters(200) {
        let len = match round % 3 {
            0 => 1 + rng.below(8) as usize,
            1 => 1 + rng.below(100) as usize,
            _ => 1 + rng.below(300) as usize,
        };
        let mut batch: Vec<Owned> = (0..len).map(|_| signed(&mut rng, &keys)).collect();
        // Most batches clean, some with one bad signature, some with several.
        match round % 4 {
            0 | 1 => {}
            2 => {
                let i = rng.below(len as u64) as usize;
                corrupt(&mut rng, &mut batch[i]);
            }
            _ => {
                for o in batch.iter_mut() {
                    if rng.below(3) == 0 {
                        corrupt(&mut rng, o);
                    }
                }
            }
        }
        // A repeated signature is still valid; keep some.
        if rng.below(4) == 0 && len > 1 {
            let o = &batch[0];
            let dup = Owned { pk: o.pk, msg: o.msg, sig: o.sig };
            batch.push(dup);
        }
        let r = refs(&batch);
        let want: Vec<bool> = r.iter().map(verify_one).collect();
        assert_eq!(v.verify_all(&r), want.iter().all(|&ok| ok), "round {round}: batch verdict");
        v.verify_batch(&r, &mut verdicts);
        assert_eq!(verdicts, want, "round {round}: per-signature verdicts");
    }
}

/// The million-signature run for the production box (about 256 signatures a
/// round): `SECP_DIFF_SCALE=10 cargo test --release -p relay-proto --test secp -- --include-ignored`
#[test]
#[ignore]
fn many_random_signatures() {
    let mut rng = Rng(8);
    let keys: Vec<Keypair> = (0..4096).map(|_| loop {
        if let Ok(k) = Keypair::from_secret_bytes(rng.bytes32()) {
            break k;
        }
    })
    .collect();
    let mut v = Verifier::new();
    let mut verdicts = Vec::new();
    let (mut sigs, mut bad) = (0u64, 0u64);
    for round in 0..iters(2000) {
        let len = 1 + rng.below(512) as usize;
        let mut batch: Vec<Owned> = (0..len).map(|_| signed(&mut rng, &keys)).collect();
        if round % 2 == 1 {
            for _ in 0..1 + rng.below(3) {
                let i = rng.below(len as u64) as usize;
                corrupt(&mut rng, &mut batch[i]);
            }
        }
        let r = refs(&batch);
        let want: Vec<bool> = r.iter().map(verify_one).collect();
        v.verify_batch(&r, &mut verdicts);
        assert_eq!(verdicts, want, "round {round}");
        sigs += len as u64;
        bad += want.iter().filter(|&&ok| !ok).count() as u64;
    }
    eprintln!("{sigs} signatures, {bad} invalid, all verdicts identical to libsecp256k1");
}
