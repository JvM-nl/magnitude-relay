//! The checkpoint: which segments make up the index, and where in the log a
//! restart has to start replaying. Replaced atomically (temp file, sync,
//! rename, sync the directory), so a crash leaves either the old one or the new.
//!
//! ```text
//! "RLYCKPT1" ‖ covered u64 ‖ replay_from u64 ‖ next_seg_id u64 ‖ n u32 ‖ n × segment id u64 ‖ crc32c u32
//! ```

use crate::crc32c::crc32c;
use std::io;
use std::path::Path;

const MAGIC: &[u8; 8] = b"RLYCKPT1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Every index key of seqs below this is in `segments`.
    pub covered: u64,
    /// Log offset of the first frame that may not be covered.
    pub replay_from: u64,
    pub next_seg_id: u64,
    pub segments: Vec<u64>,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Checkpoint { covered: 0, replay_from: 0, next_seg_id: 1, segments: Vec::new() }
    }
}

pub fn write(dir: &Path, c: &Checkpoint) -> io::Result<()> {
    let mut b = Vec::with_capacity(40 + c.segments.len() * 8);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&c.covered.to_le_bytes());
    b.extend_from_slice(&c.replay_from.to_le_bytes());
    b.extend_from_slice(&c.next_seg_id.to_le_bytes());
    b.extend_from_slice(&(c.segments.len() as u32).to_le_bytes());
    for id in &c.segments {
        b.extend_from_slice(&id.to_le_bytes());
    }
    let crc = crc32c(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    let tmp = dir.join("checkpoint.tmp");
    std::fs::write(&tmp, &b)?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(&tmp, dir.join("checkpoint"))?;
    crate::bg::sync_dir(dir)
}

pub fn read(dir: &Path) -> io::Result<Option<Checkpoint>> {
    let b = match std::fs::read(dir.join("checkpoint")) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let bad = || io::Error::other("checkpoint file is corrupt");
    if b.len() < 40 || &b[..8] != MAGIC {
        return Err(bad());
    }
    let (body, crc) = b.split_at(b.len() - 4);
    if crc32c(body) != u32::from_le_bytes(crc.try_into().unwrap()) {
        return Err(bad());
    }
    let u64_at = |o: usize| u64::from_le_bytes(body[o..o + 8].try_into().unwrap());
    let n = u32::from_le_bytes(body[32..36].try_into().unwrap()) as usize;
    if body.len() != 36 + n * 8 {
        return Err(bad());
    }
    Ok(Some(Checkpoint {
        covered: u64_at(8),
        replay_from: u64_at(16),
        next_seg_id: u64_at(24),
        segments: (0..n).map(|i| u64_at(36 + i * 8)).collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_corruption() {
        let dir = std::env::temp_dir().join(format!("ckpt-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read(&dir).unwrap(), None);
        let c = Checkpoint { covered: 42, replay_from: 1 << 33, next_seg_id: 9, segments: vec![3, 7, 8] };
        write(&dir, &c).unwrap();
        assert_eq!(read(&dir).unwrap(), Some(c));
        let mut b = std::fs::read(dir.join("checkpoint")).unwrap();
        b[10] ^= 1;
        std::fs::write(dir.join("checkpoint"), b).unwrap();
        assert!(read(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
