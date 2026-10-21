//! LEB128 unsigned varints, the length framing inside records.

#[inline]
pub fn put(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Reads a varint at `*pos`, advancing it. `None` on truncation or overflow.
#[inline]
pub fn get(buf: &[u8], pos: &mut usize) -> Option<u64> {
    // Lengths, counts and field headers in records are nearly all one byte.
    let b = *buf.get(*pos)?;
    if b < 0x80 {
        *pos += 1;
        return Some(u64::from(b));
    }
    get_long(buf, pos)
}

#[cold]
fn get_long(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        if shift == 63 && b > 1 {
            return None;
        }
        v |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip_edges() {
        for v in [0u64, 1, 127, 128, 300, 16383, 16384, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            super::put(&mut b, v);
            let mut p = 0;
            assert_eq!(super::get(&b, &mut p), Some(v));
            assert_eq!(p, b.len());
        }
        let mut p = 0;
        assert_eq!(super::get(&[0x80, 0x80], &mut p), None);
    }
}
