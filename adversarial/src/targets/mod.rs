//! Fuzz targets: one function per parser of untrusted input. Each takes raw
//! bytes, runs the parser, and panics when an invariant breaks (a panic inside
//! the parser counts too). The same functions run under libFuzzer on the box
//! (`adversarial/fuzz`) and under the stable mutational runner everywhere else.
//!
//! A target returns a small behaviour fingerprint (which error, which branch):
//! the stable runner, which has no coverage feedback, keeps inputs that produce
//! a fingerprint it has not seen, so its corpus still grows toward new paths.

use crate::rng::Rng;

pub mod config;
pub mod net;
pub mod proto;
pub mod tls;

pub struct Target {
    pub name: &'static str,
    /// Runs one input; panics on a broken invariant.
    pub run: fn(&[u8]) -> u64,
    /// Hand-made inputs that reach deep into the parser.
    pub seeds: fn() -> Vec<Vec<u8>>,
    /// Structure-aware random inputs.
    pub generate: fn(&mut Rng) -> Vec<u8>,
    /// Tokens the mutator splices in.
    pub dict: &'static [&'static [u8]],
    pub max_len: usize,
    /// Peak heap allowed while running an input of `len` bytes.
    pub mem_cap: fn(usize) -> usize,
}

/// A fixed overhead plus a multiple of the input: what a parser that copies
/// what it reads a few times over may use, and nothing that a length field
/// alone could inflate.
pub fn linear_cap(len: usize) -> usize {
    (1 << 20) + 64 * len
}

pub fn all() -> Vec<Target> {
    let mut v = proto::targets();
    v.extend(net::targets());
    v.extend(tls::targets());
    v.extend(config::targets());
    v
}

pub fn find(name: &str) -> Option<Target> {
    all().into_iter().find(|t| t.name == name)
}

/// A stable 64-bit fingerprint of a few values.
pub fn fp(parts: &[u64]) -> u64 {
    parts.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &p| crate::rng::mix(h ^ p))
}

/// Fingerprint of a string (an error message, say).
pub fn fp_str(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3))
}
