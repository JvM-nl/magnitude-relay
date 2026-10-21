//! Many-at-once SHA-256 against the sha2 crate, over every padding boundary
//! and every way lanes can start, finish and refill.

use relay_proto::sha256::{digest, digest_many, digest_many_after, Midstate};
use sha2::{Digest, Sha256};

fn check(msgs: &[Vec<u8>]) {
    let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let mut out = vec![[0u8; 32]; msgs.len()];
    digest_many(&refs, &mut out);
    for (m, d) in msgs.iter().zip(&out) {
        assert_eq!(*d, <[u8; 32]>::from(Sha256::digest(m)), "len {}", m.len());
    }
}

fn bytes(seed: &mut u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed as u8
        })
        .collect()
}

#[test]
fn every_length_up_to_three_blocks() {
    let mut seed = 1;
    // One batch per length (all lanes the same length) ...
    for len in 0..=200 {
        let msgs: Vec<Vec<u8>> = (0..11).map(|_| bytes(&mut seed, len)).collect();
        check(&msgs);
    }
    // ... and all lengths together, so lanes finish at different blocks.
    let msgs: Vec<Vec<u8>> = (0..=200).map(|len| bytes(&mut seed, len)).collect();
    check(&msgs);
}

#[test]
fn mixed_batches() {
    let mut seed = 2;
    for round in 0..300u64 {
        let count = (round % 37) as usize;
        let msgs: Vec<Vec<u8>> = (0..count)
            .map(|i| {
                let len = match (round + i as u64) % 5 {
                    0 => (seed % 64) as usize,
                    1 => 1000 + (seed % 3000) as usize,
                    2 => 55 + (seed % 3) as usize,
                    3 => 64 * (1 + (seed % 40) as usize),
                    _ => (seed % 20000) as usize,
                };
                bytes(&mut seed, len)
            })
            .collect();
        check(&msgs);
    }
}

#[test]
fn from_a_midstate() {
    // BIP-340's shape (a 64-byte tag prefix, 96-byte messages) and others,
    // in batches large enough for the lanes and small enough for the scalar path.
    let mut seed = 3;
    for prefix_len in [0usize, 64, 128] {
        let prefix = bytes(&mut seed, prefix_len);
        let mid = Midstate::after(&prefix);
        for count in [1usize, 2, 3, 9, 40] {
            let msgs: Vec<Vec<u8>> = (0..count)
                .map(|i| {
                    let len = if i % 2 == 0 { 96 } else { (seed % 300) as usize };
                    bytes(&mut seed, len)
                })
                .collect();
            let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            let mut out = vec![[0u8; 32]; count];
            digest_many_after(&mid, &refs, &mut out);
            for (m, d) in msgs.iter().zip(&out) {
                let mut h = Sha256::new();
                h.update(&prefix);
                h.update(m);
                assert_eq!(*d, <[u8; 32]>::from(h.finalize()), "prefix {prefix_len}, len {}", m.len());
            }
        }
    }
}

#[test]
fn one_message() {
    let mut seed = 4;
    for len in (0..=300).chain([1000, 2047, 2048, 2049, 4096, 20_000, 65_536]) {
        let m = bytes(&mut seed, len);
        assert_eq!(digest(&m), <[u8; 32]>::from(Sha256::digest(&m)), "len {len}");
    }
}
