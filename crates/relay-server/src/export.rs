//! `export`: every live event as JSONL, `created_at` ascending, ties in storage
//! order: the same order and bytes strfry's `export` writes.

use relay_store::keys::{created_at_of, seq_of, T_CREATED};
use relay_store::Version;
use std::io::{self, Write};

pub fn run(v: &Version, out: &mut impl Write, since: Option<u64>, until: Option<u64>) -> io::Result<u64> {
    let mut buf = Vec::with_capacity(1 << 20);
    let mut n = 0u64;
    let since = since.unwrap_or(0);
    let until = until.unwrap_or(u64::MAX);
    let mut keys: Vec<(u64, u64)> = Vec::new();
    v.for_prefix(&[T_CREATED], |k| {
        let ca = created_at_of(k);
        if ca >= since && ca <= until {
            keys.push((ca, seq_of(k)));
        }
    });
    // Runs are visited one after another; order across them here.
    keys.sort_unstable();
    for (_, seq) in keys {
        let Some(rec) = v.record(seq) else { continue };
        rec.write_json(&mut buf);
        buf.push(b'\n');
        n += 1;
        if buf.len() >= 1 << 20 {
            out.write_all(&buf)?;
            buf.clear();
        }
    }
    out.write_all(&buf)?;
    out.flush()?;
    Ok(n)
}
