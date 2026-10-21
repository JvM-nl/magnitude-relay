//! BIP-340 Schnorr verification, one at a time and in batches, on our own
//! secp256k1 arithmetic.
//!
//! One Schnorr verification costs a full double-scalar multiplication, most of
//! it a chain of 128 doublings that every signature pays for again. A batch
//! checks u signatures with one multi-scalar multiplication instead:
//!
//! ```text
//!   (sum a_i s_i) G  -  sum a_i R_i  -  sum (a_i e_i) P_i  ==  infinity
//! ```
//!
//! where R_i = lift_x(r_i), P_i = lift_x(pubkey_i), e_i the BIP-340 challenge,
//! a_1 = 1 and the other weights a_i fresh 128-bit values from a CSPRNG keyed
//! from the OS. If every signature is valid the equation holds. If any is not,
//! it holds only when the weights happen to cancel the error, which for a
//! weight the signer cannot predict has probability at most 2^-128: the same
//! work as breaking a secp256k1 key by brute force. A batch that fails says
//! only that something in it is bad; `verify_batch` then checks each
//! signature on its own with libsecp256k1, so every verdict it gives is the
//! individual verifier's.
//!
//! Signatures by the same key are merged (their P terms add up to one), which
//! on the real traffic leaves about a quarter as many P terms as signatures.
//!
//! Field, scalar and group code follow libsecp256k1's representations and
//! formulas, and the tests check all of it against libsecp256k1 itself.

pub mod field;
pub mod group;
pub mod keys;
pub mod msm;
pub mod rng;
pub mod scalar;

use group::Affine;
use keys::KeyCache;
use msm::Term;
use crate::sha256::{self, Midstate};
use scalar::Scalar;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// One signature to check: BIP-340 over a 32-byte message (an event id).
#[derive(Clone, Copy)]
pub struct SigRef<'a> {
    pub pubkey: &'a [u8; 32],
    pub msg: &'a [u8; 32],
    pub sig: &'a [u8; 64],
}

/// One signature's share of the batch equation.
#[derive(Clone, Copy)]
struct Item {
    s: Scalar,
    e: Scalar,
    /// Index into `Verifier::keys`.
    key: u32,
    r: Affine,
}

/// One distinct public key in a batch, with the sum of its P scalars.
struct KeyTerm {
    bytes: [u8; 32],
    point: Option<Affine>,
    acc: Scalar,
}

/// Below this many signatures a batch costs more than one-at-a-time
/// verification (sigbench `batch` on the production CPU: about even at 2,
/// 1.3x faster at 4).
pub const MIN_BATCH: usize = 3;

/// The smallest part a failed batch is split into before going one by one.
const MIN_SUB: usize = 64;

/// log2 of the key cache's set count (two entries per set).
const CACHE_SET_BITS: u32 = 10;

/// Per-thread verifier: key cache, weight generator and reusable buffers.
pub struct Verifier {
    rng: rng::Weights,
    /// SHA-256 after BIP-340's challenge tag prefix (two tag hashes, one block).
    challenge: Midstate,
    cache: KeyCache,
    items: Vec<Item>,
    /// r || P || m of each signature, hashed together into the challenges.
    challenge_msgs: Vec<[u8; 96]>,
    digests: Vec<[u8; 32]>,
    weights: Vec<u128>,
    keys: Vec<KeyTerm>,
    key_index: HashMap<[u8; 32], u32>,
    lifts: Vec<(u32, bool)>,
    terms: Vec<Term>,
    scratch: msm::Scratch,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Verifier {
    pub fn new() -> Verifier {
        let tag = Sha256::digest(b"BIP0340/challenge");
        let mut prefix = [0u8; 64];
        prefix[..32].copy_from_slice(&tag);
        prefix[32..].copy_from_slice(&tag);
        let mut rng = rng::Weights::new();
        let salt = rng.weight() as u64;
        Verifier {
            rng,
            challenge: Midstate::after(&prefix),
            cache: KeyCache::new(CACHE_SET_BITS, salt),
            items: Vec::new(),
            challenge_msgs: Vec::new(),
            digests: Vec::new(),
            weights: Vec::new(),
            keys: Vec::new(),
            key_index: HashMap::new(),
            lifts: Vec::new(),
            terms: Vec::new(),
            scratch: msm::Scratch::default(),
        }
    }

    /// One signature, checked by libsecp256k1 (the key parse comes from the cache).
    pub fn verify_one(&mut self, c: &SigRef<'_>) -> bool {
        let Some(pk) = self.cache.xonly(c.pubkey) else {
            return false;
        };
        secp256k1::schnorr::verify(&secp256k1::schnorr::Signature::from_byte_array(*c.sig), c.msg, &pk).is_ok()
    }

    /// Verifies each signature, writing one verdict per input into `ok`.
    /// A batch that passes accepts them all. One that fails is narrowed down:
    /// a large batch is retried as eighths (at least `MIN_SUB` each), and any
    /// part that still fails is checked one signature at a time with
    /// libsecp256k1, so every verdict is the individual verifier's. Returns
    /// whether the whole batch passed at once (false below `MIN_BATCH`
    /// signatures, which go one at a time).
    pub fn verify_batch(&mut self, sigs: &[SigRef<'_>], ok: &mut Vec<bool>) -> bool {
        ok.clear();
        if sigs.is_empty() {
            return false;
        }
        if sigs.len() >= MIN_BATCH && self.verify_all(sigs) {
            ok.resize(sigs.len(), true);
            return true;
        }
        let part = if sigs.len() >= 2 * MIN_SUB { (sigs.len() / 8).max(MIN_SUB) } else { sigs.len() };
        for chunk in sigs.chunks(part) {
            if part < sigs.len() && chunk.len() >= MIN_BATCH && self.verify_all(chunk) {
                ok.extend(std::iter::repeat_n(true, chunk.len()));
                continue;
            }
            for c in chunk {
                let v = self.verify_one(c);
                ok.push(v);
            }
        }
        false
    }

    /// True when every signature is valid (see the module doc for the 2^-128).
    /// False says at least one is invalid, not which.
    pub fn verify_all(&mut self, sigs: &[SigRef<'_>]) -> bool {
        if sigs.is_empty() {
            return true;
        }
        self.items.clear();
        self.keys.clear();
        self.key_index.clear();
        self.lifts.clear();
        self.challenge_msgs.clear();
        // Parse and group by key; nothing here touches the curve.
        for c in sigs {
            let Some(s) = Scalar::from_bytes(c.sig[32..].try_into().unwrap()) else {
                return false;
            };
            let next = self.keys.len() as u32;
            let key = *self.key_index.entry(*c.pubkey).or_insert(next);
            if key == next {
                let point = self.cache.point(c.pubkey);
                if point.is_none() {
                    self.lifts.push((key, true));
                }
                self.keys.push(KeyTerm { bytes: *c.pubkey, point, acc: Scalar::ZERO });
            }
            let mut m = [0u8; 96];
            m[..32].copy_from_slice(&c.sig[..32]);
            m[32..64].copy_from_slice(c.pubkey);
            m[64..].copy_from_slice(c.msg);
            self.challenge_msgs.push(m);
            self.lifts.push((self.items.len() as u32, false));
            self.items.push(Item { s, e: Scalar::ZERO, key, r: Affine::G });
        }
        // BIP-340's challenges e = H_tag(r || P || m) mod n, eight at a time.
        let refs: Vec<&[u8]> = self.challenge_msgs.iter().map(|m| &m[..]).collect();
        self.digests.resize(refs.len(), [0; 32]);
        sha256::digest_many_after(&self.challenge, &refs, &mut self.digests);
        for (it, d) in self.items.iter_mut().zip(&self.digests) {
            it.e = Scalar::from_bytes_mod(d);
        }
        // The square roots: each R, and the keys the cache lacked.
        for &(idx, is_key) in &self.lifts {
            if is_key {
                let k = &mut self.keys[idx as usize];
                let Some(p) = Affine::lift_x(&k.bytes) else {
                    return false;
                };
                k.point = Some(p);
                self.cache.put_point(&k.bytes, p);
            } else {
                let Some(p) = Affine::lift_x(sigs[idx as usize].sig[..32].try_into().unwrap()) else {
                    return false;
                };
                self.items[idx as usize].r = p;
            }
        }
        // Weights, and the terms of the equation.
        self.weights.resize(self.items.len(), 1);
        self.rng.fill(&mut self.weights[1..]);
        self.terms.clear();
        let mut z = Scalar::ZERO;
        for (i, it) in self.items.iter().enumerate() {
            let a = if i == 0 { 1u128 } else { self.weights[i] };
            let a_s = Scalar::from_u128(a);
            z = z.add(&a_s.mul(&it.s));
            let k = &mut self.keys[it.key as usize];
            k.acc = k.acc.add(&a_s.mul(&it.e));
            // -a * R: the sign goes on the point.
            self.terms.push(Term { point: it.r.neg(), k: a });
        }
        for k in &self.keys {
            push_split(&mut self.terms, &k.point.expect("every key lifted"), &k.acc.negate());
        }
        push_split(&mut self.terms, &Affine::G, &z);
        msm::msm(&self.terms, &mut self.scratch).infinity
    }
}

/// Pushes k * p as two half-size terms via k = k1 + k2 * lambda.
fn push_split(terms: &mut Vec<Term>, p: &Affine, k: &Scalar) {
    let [(k1, n1), (k2, n2)] = k.split_lambda();
    let pl = p.mul_lambda();
    terms.push(Term { point: if n1 { p.neg() } else { *p }, k: k1 });
    terms.push(Term { point: if n2 { pl.neg() } else { pl }, k: k2 });
}

/// One signature, checked by libsecp256k1 with no cache (the reference the
/// tests compare against).
pub fn verify_one(c: &SigRef<'_>) -> bool {
    use secp256k1::{schnorr, XOnlyPublicKey};
    let Ok(pk) = XOnlyPublicKey::from_byte_array(*c.pubkey) else {
        return false;
    };
    schnorr::verify(&schnorr::Signature::from_byte_array(*c.sig), c.msg, &pk).is_ok()
}
