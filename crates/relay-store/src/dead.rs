//! The dead set: one bit per seq, set when an event is deleted, replaced or
//! expires. Readers test a bit; only the writer sets them.
//!
//! Chunked so it can grow while readers hold the old chunk list: a chunk never
//! moves once allocated, and a snapshot's list stays valid for every seq it can see.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Seqs per chunk: 4M (512 KiB of bits).
const CHUNK_BITS: u64 = 1 << 22;
const CHUNK_WORDS: usize = (CHUNK_BITS / 64) as usize;

pub type Chunk = Arc<[AtomicU64]>;

#[derive(Clone, Default)]
pub struct DeadSet {
    chunks: Arc<Vec<Chunk>>,
}

impl DeadSet {
    /// Makes room for `seq`, sharing all existing chunks.
    pub fn grow_to(&mut self, seq: u64) {
        let need = (seq / CHUNK_BITS + 1) as usize;
        if need <= self.chunks.len() {
            return;
        }
        let mut v: Vec<Chunk> = (*self.chunks).clone();
        while v.len() < need {
            v.push((0..CHUNK_WORDS).map(|_| AtomicU64::new(0)).collect());
        }
        self.chunks = Arc::new(v);
    }

    #[inline]
    pub fn is_dead(&self, seq: u64) -> bool {
        match self.chunks.get((seq / CHUNK_BITS) as usize) {
            Some(c) => {
                let bit = seq % CHUNK_BITS;
                c[(bit / 64) as usize].load(Ordering::Acquire) & (1 << (bit % 64)) != 0
            }
            None => false,
        }
    }

    /// Writer only. Visible to every snapshot sharing the chunk.
    #[inline]
    pub fn set(&self, seq: u64) {
        let c = &self.chunks[(seq / CHUNK_BITS) as usize];
        let bit = seq % CHUNK_BITS;
        c[(bit / 64) as usize].fetch_or(1 << (bit % 64), Ordering::Release);
    }

    /// The bits for seqs `< upto`, little-endian words (the `dead.bits` file).
    pub fn to_bytes(&self, upto: u64) -> Vec<u8> {
        let words = (upto.div_ceil(64) as usize).min(self.chunks.len() * CHUNK_WORDS);
        let mut out = Vec::with_capacity(words * 8);
        for w in 0..words {
            let c = &self.chunks[w / CHUNK_WORDS];
            out.extend_from_slice(&c[w % CHUNK_WORDS].load(Ordering::Relaxed).to_le_bytes());
        }
        out
    }

    /// Sets every bit recorded in `bytes` (a `to_bytes` image).
    pub fn load(&mut self, bytes: &[u8]) {
        let words = bytes.len() / 8;
        if words == 0 {
            return;
        }
        self.grow_to(words as u64 * 64 - 1);
        for (w, b) in bytes.chunks_exact(8).enumerate() {
            let v = u64::from_le_bytes(b.try_into().unwrap());
            if v != 0 {
                self.chunks[w / CHUNK_WORDS][w % CHUNK_WORDS].fetch_or(v, Ordering::Relaxed);
            }
        }
    }

    pub fn count(&self) -> u64 {
        self.chunks.iter().flat_map(|c| c.iter()).map(|w| u64::from(w.load(Ordering::Relaxed).count_ones())).sum()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn grows_and_shares() {
        let mut d = super::DeadSet::default();
        d.grow_to(10);
        let old = d.clone();
        d.set(3);
        assert!(old.is_dead(3), "chunks are shared");
        d.grow_to(super::CHUNK_BITS * 2 + 5);
        d.set(super::CHUNK_BITS * 2 + 5);
        assert!(d.is_dead(super::CHUNK_BITS * 2 + 5));
        assert!(!old.is_dead(super::CHUNK_BITS * 2 + 5), "old snapshot cannot see new chunks");
        assert!(!d.is_dead(4));
        assert_eq!(d.count(), 2);
        let img = d.to_bytes(super::CHUNK_BITS * 2 + 6);
        let mut e = super::DeadSet::default();
        e.load(&img);
        assert!(e.is_dead(3) && e.is_dead(super::CHUNK_BITS * 2 + 5) && !e.is_dead(4));
        assert_eq!(e.count(), 2);
    }
}
