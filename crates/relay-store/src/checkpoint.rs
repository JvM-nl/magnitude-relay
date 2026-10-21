//! The checkpoint: which segments make up the index, which log segments are in
//! use, and where in the log a restart has to start replaying. Replaced
//! atomically (temp file, sync, rename, sync the directory), so a crash leaves
//! either the old one or the new.
//!
//! ```text
//! "RLYCKPT3" ‖ covered u64 ‖ replay_from u64 ‖ next_seg_id u64 ‖ next_cold u64
//!            ‖ 7 × (n u32 ‖ n × u64): index segments, cold log segments,
//!              retired hot segments, intent cold, intent retire,
//!              cold run lengths (segments), cold run bytes
//!            ‖ crc32c u32
//! ```
//! Version 1 files (no log compaction yet) read as having empty log lists;
//! version 2 files (no runs recorded) as one run per cold segment, size unknown.

use crate::crc32c::crc32c;
use std::io;
use std::path::Path;

const MAGIC_V1: &[u8; 8] = b"RLYCKPT1";
const MAGIC_V2: &[u8; 8] = b"RLYCKPT2";
const MAGIC: &[u8; 8] = b"RLYCKPT3";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Every index key of seqs below this is in `segments`.
    pub covered: u64,
    /// Log offset of the first frame that may not be covered.
    pub replay_from: u64,
    pub next_seg_id: u64,
    /// Index segments.
    pub segments: Vec<u64>,
    /// Next number for a cold log segment.
    pub next_cold: u64,
    /// Cold log segments in use.
    pub cold: Vec<u64>,
    /// Hot log segments retired by compaction (their numbers may be gaps).
    pub retired: Vec<u64>,
    /// A log compaction in flight: its cold segments are in `cold`, and
    /// `locs` may or may not point into them yet. On open, `locs` is re-derived
    /// from their frames and `intent_retire` joins `retired`. A retired number
    /// of `COLD_BASE` or more is a cold segment (a merge's input).
    pub intent_cold: Vec<u64>,
    pub intent_retire: Vec<u64>,
    /// `cold` cut into sorted runs: how many segments each holds, in order, and
    /// their bytes (0: unknown).
    pub run_lens: Vec<u64>,
    pub run_bytes: Vec<u64>,
}

impl Default for Checkpoint {
    fn default() -> Self {
        Checkpoint {
            covered: 0,
            replay_from: 0,
            next_seg_id: 1,
            segments: Vec::new(),
            next_cold: 0,
            cold: Vec::new(),
            retired: Vec::new(),
            intent_cold: Vec::new(),
            intent_retire: Vec::new(),
            run_lens: Vec::new(),
            run_bytes: Vec::new(),
        }
    }
}

fn put_list(b: &mut Vec<u8>, l: &[u64]) {
    b.extend_from_slice(&(l.len() as u32).to_le_bytes());
    for v in l {
        b.extend_from_slice(&v.to_le_bytes());
    }
}

pub fn write(dir: &Path, c: &Checkpoint) -> io::Result<()> {
    let mut b = Vec::with_capacity(128);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&c.covered.to_le_bytes());
    b.extend_from_slice(&c.replay_from.to_le_bytes());
    b.extend_from_slice(&c.next_seg_id.to_le_bytes());
    b.extend_from_slice(&c.next_cold.to_le_bytes());
    for l in [&c.segments, &c.cold, &c.retired, &c.intent_cold, &c.intent_retire, &c.run_lens, &c.run_bytes] {
        put_list(&mut b, l);
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
    if b.len() < 40 {
        return Err(bad());
    }
    let (body, crc) = b.split_at(b.len() - 4);
    if crc32c(body) != u32::from_le_bytes(crc.try_into().unwrap()) {
        return Err(bad());
    }
    let u64_at = |o: usize| -> io::Result<u64> { Ok(u64::from_le_bytes(body.get(o..o + 8).ok_or_else(bad)?.try_into().unwrap())) };
    let mut p;
    let list = |p: &mut usize| -> io::Result<Vec<u64>> {
        let n = u32::from_le_bytes(body.get(*p..*p + 4).ok_or_else(bad)?.try_into().unwrap()) as usize;
        *p += 4;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(u64_at(*p)?);
            *p += 8;
        }
        Ok(v)
    };
    let mut c = Checkpoint::default();
    if &body[..8] == MAGIC_V1 {
        c.covered = u64_at(8)?;
        c.replay_from = u64_at(16)?;
        c.next_seg_id = u64_at(24)?;
        p = 32;
        c.segments = list(&mut p)?;
    } else if &body[..8] == MAGIC_V2 || &body[..8] == MAGIC {
        c.covered = u64_at(8)?;
        c.replay_from = u64_at(16)?;
        c.next_seg_id = u64_at(24)?;
        c.next_cold = u64_at(32)?;
        p = 40;
        c.segments = list(&mut p)?;
        c.cold = list(&mut p)?;
        c.retired = list(&mut p)?;
        c.intent_cold = list(&mut p)?;
        c.intent_retire = list(&mut p)?;
        if &body[..8] == MAGIC {
            c.run_lens = list(&mut p)?;
            c.run_bytes = list(&mut p)?;
            if c.run_lens.len() != c.run_bytes.len() || c.run_lens.iter().sum::<u64>() != c.cold.len() as u64 {
                return Err(bad());
            }
        } else {
            c.run_lens = vec![1; c.cold.len()];
            c.run_bytes = vec![0; c.cold.len()];
        }
    } else {
        return Err(bad());
    }
    if p != body.len() {
        return Err(bad());
    }
    Ok(Some(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_corruption() {
        let dir = std::env::temp_dir().join(format!("ckpt-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read(&dir).unwrap(), None);
        let c = Checkpoint {
            covered: 42,
            replay_from: 1 << 33,
            next_seg_id: 9,
            segments: vec![3, 7, 8],
            next_cold: 4,
            cold: vec![0, 1, 3],
            retired: vec![0, 1],
            intent_cold: vec![3],
            intent_retire: vec![2],
            run_lens: vec![2, 1],
            run_bytes: vec![1 << 20, 4096],
        };
        write(&dir, &c).unwrap();
        assert_eq!(read(&dir).unwrap(), Some(c));
        let mut b = std::fs::read(dir.join("checkpoint")).unwrap();
        b[10] ^= 1;
        std::fs::write(dir.join("checkpoint"), b).unwrap();
        assert!(read(&dir).is_err());

        // A version 1 file reads with empty log lists.
        let mut v1 = Vec::new();
        v1.extend_from_slice(MAGIC_V1);
        for v in [5u64, 77, 2] {
            v1.extend_from_slice(&v.to_le_bytes());
        }
        put_list(&mut v1, &[9]);
        let crc = crc32c(&v1);
        v1.extend_from_slice(&crc.to_le_bytes());
        std::fs::write(dir.join("checkpoint"), v1).unwrap();
        let r = read(&dir).unwrap().unwrap();
        assert_eq!((r.covered, r.replay_from, r.next_seg_id, r.segments.clone()), (5, 77, 2, vec![9]));
        assert!(r.cold.is_empty() && r.retired.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
