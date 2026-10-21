//! DEFLATE (RFC 1951) written for a relay that compresses and decompresses many
//! small WebSocket messages on every core.
//!
//! * [`inflate`]: the decoder. Table-driven (an 11-bit first-level table with
//!   sub-tables, 8 for distances), a 64-bit bit buffer refilled eight bytes at a
//!   time, strict about every malformed construct, and bounded: the caller names
//!   the most output one call may produce, so a 1 KB bomb costs one allocation of
//!   that size and an error.
//! * [`compress`]: the encoder. Speed first: a single-probe hash over 4-byte
//!   sequences (zlib level 1 / libdeflate "fast" territory), one dynamic Huffman
//!   block per chunk, with fixed Huffman and stored blocks chosen whenever the exact
//!   bit count says they are smaller, so incompressible input grows by a few bytes.
//! * [`huffman`]: length-limited canonical code construction for the encoder.
//!
//! Both halves keep the 32 KiB sliding window between calls, which is what
//! permessage-deflate's "context takeover" needs (see [`crate::ws::pmd`]); either can
//! also run with no history at all, and then costs no per-stream memory.
//!
//! **Where the working memory lives.** Everything that is only needed *during* a
//! call (Huffman decode tables, the encoder's token buffer, histograms, code
//! tables, and the hash table and window for history-free compression) is in a
//! `thread_local` scratch, ~100-200 KiB per thread, shared by every stream the
//! thread serves. A call never yields in the middle, so two streams cannot
//! interleave on one thread. What a stream owns is only what has to survive between
//! messages, which is why 100k history-free connections cost no codec memory at all.
//!
//! No `unsafe`: bounds are proved by loop shape where that is cheap and checked
//! where it is not, and every size computed for the writer is exact (the tests
//! decode what is written, so an accounting mistake fails loudly).

pub mod compress;
pub mod huffman;
pub mod inflate;
pub mod tables;

pub use compress::{Deflater, Flush};
pub use inflate::{InflateError, Inflater};
pub use tables::SYNC_TAIL;

#[cfg(test)]
#[path = "testdata.rs"]
pub(crate) mod testutil;
