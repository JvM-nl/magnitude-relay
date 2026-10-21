//! CRC-32C (Castagnoli), the checksum on every log frame.
//!
//! Both production targets compute it in hardware: SSE4.2 `crc32` on x86-64
//! (8 bytes per instruction) and the ARMv8 CRC extension on Apple silicon. The
//! table version only runs on CPUs that have neither.

const POLY: u32 = 0x82F6_3B78;

static TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

fn soft(mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn hw(mut crc: u32, data: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let mut chunks = data.chunks_exact(8);
    let mut c = u64::from(crc);
    for ch in &mut chunks {
        c = _mm_crc32_u64(c, u64::from_le_bytes(ch.try_into().unwrap()));
    }
    crc = c as u32;
    for &b in chunks.remainder() {
        crc = _mm_crc32_u8(crc, b);
    }
    crc
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "crc")]
unsafe fn hw(mut crc: u32, data: &[u8]) -> u32 {
    use std::arch::aarch64::{__crc32cb, __crc32cd};
    let mut chunks = data.chunks_exact(8);
    for ch in &mut chunks {
        crc = __crc32cd(crc, u64::from_le_bytes(ch.try_into().unwrap()));
    }
    for &b in chunks.remainder() {
        crc = __crc32cb(crc, b);
    }
    crc
}

#[inline]
fn has_hw() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("sse4.2")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("crc")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// CRC-32C of `data`.
#[inline]
pub fn crc32c(data: &[u8]) -> u32 {
    let init = !0u32;
    let out = if has_hw() {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        // SAFETY: the required CPU feature was detected at runtime just above.
        unsafe {
            hw(init, data)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        soft(init, data)
    } else {
        soft(init, data)
    };
    !out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
    }

    #[test]
    fn hardware_matches_table() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in 0..data.len() {
            assert_eq!(crc32c(&data[..len]), !soft(!0, &data[..len]), "len {len}");
        }
    }
}
