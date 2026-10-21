//! Weights for batch verification: 128-bit values nobody outside this process
//! can predict. A per-instance key from the OS random source, then SHA-256 of
//! (key, counter) as a PRF, two weights per block. A weight that leaks (say
//! through timing) says nothing about the next one.

use crate::sha256;
use sha2::{Digest, Sha256};

pub struct Weights {
    key: [u8; 32],
    counter: u64,
    spare: Option<u128>,
    msgs: Vec<[u8; 40]>,
    digests: Vec<[u8; 32]>,
}

impl Weights {
    pub fn new() -> Weights {
        Weights { key: os_random(), counter: 0, spare: None, msgs: Vec::new(), digests: Vec::new() }
    }

    /// Fills `out` with weights (never zero), two per hash and the hashes
    /// eight at a time: the same function as `weight`, for a whole batch.
    pub fn fill(&mut self, out: &mut [u128]) {
        let blocks = out.len().div_ceil(2);
        self.msgs.clear();
        for i in 0..blocks as u64 {
            let mut m = [0u8; 40];
            m[..32].copy_from_slice(&self.key);
            m[32..].copy_from_slice(&(self.counter + i).to_le_bytes());
            self.msgs.push(m);
        }
        self.counter += blocks as u64;
        let refs: Vec<&[u8]> = self.msgs.iter().map(|m| &m[..]).collect();
        self.digests.resize(blocks, [0; 32]);
        sha256::digest_many(&refs, &mut self.digests);
        for (i, w) in out.iter_mut().enumerate() {
            let half = &self.digests[i / 2][(i % 2) * 16..(i % 2) * 16 + 16];
            *w = u128::from_le_bytes(half.try_into().unwrap()).max(1);
        }
    }

    /// The next weight, never zero.
    pub fn weight(&mut self) -> u128 {
        if let Some(w) = self.spare.take() {
            return w;
        }
        let mut h = Sha256::new();
        h.update(self.key);
        h.update(self.counter.to_le_bytes());
        self.counter += 1;
        let block: [u8; 32] = h.finalize().into();
        let a = u128::from_le_bytes(block[..16].try_into().unwrap());
        let b = u128::from_le_bytes(block[16..].try_into().unwrap());
        // Zero would drop a signature from the equation; it comes up with
        // probability 2^-128, and 1 is as unpredictable a substitute as any.
        self.spare = Some(b.max(1));
        a.max(1)
    }
}

impl Default for Weights {
    fn default() -> Self {
        Self::new()
    }
}

/// 32 bytes from the kernel's CSPRNG. There is no safe fallback: without
/// randomness the weights could be predicted, so this panics instead.
fn os_random() -> [u8; 32] {
    let mut key = [0u8; 32];
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut got = 0;
        while got < key.len() {
            // SAFETY: the pointer and length describe the unfilled tail of `key`.
            let n = unsafe { libc::getrandom(key[got..].as_mut_ptr().cast(), key.len() - got, 0) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                assert!(e.kind() == std::io::ErrorKind::Interrupted, "getrandom failed: {e}");
                continue;
            }
            got += n as usize;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        // SAFETY: getentropy fills up to 256 bytes of the given buffer.
        let rc = unsafe { libc::getentropy(key.as_mut_ptr().cast(), key.len()) };
        assert!(rc == 0, "getentropy failed: {}", std::io::Error::last_os_error());
    }
    key
}
