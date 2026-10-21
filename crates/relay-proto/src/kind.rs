//! Kind classes from NIP-01.

#[inline]
pub fn is_ephemeral(kind: u64) -> bool {
    (20_000..30_000).contains(&kind)
}

/// One event per (pubkey, kind): the newest wins.
#[inline]
pub fn is_replaceable(kind: u64) -> bool {
    kind == 0 || kind == 3 || (10_000..20_000).contains(&kind)
}

/// One event per (pubkey, kind, d tag): the newest wins.
#[inline]
pub fn is_addressable(kind: u64) -> bool {
    (30_000..40_000).contains(&kind)
}

pub const DELETION: u64 = 5;
pub const GIFT_WRAP: u64 = 1059;
pub const VANISH: u64 = 62;
