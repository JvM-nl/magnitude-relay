//! HTTP/1.1 upgrade and RFC 6455 WebSocket, written for the relay's hot path.
//!
//! The core is **sans-IO**: [`http`] and [`ws`] are pure functions and small state
//! machines over byte buffers, with no sockets, locks, `Arc`s or per-frame
//! allocation. A connection owner (the relay's reactor) reads into its own buffer,
//! calls in, and flushes one output `Vec<u8>` with a single write. [`conn`] wraps
//! the same code in tokio helpers for tests and the benchmark client.
//!
//! [`connector`] opens a client connection by URL, `wss://` included when the `tls`
//! feature brings in rustls (the relay uses it to sync from other relays).
//!
//! The only other dependencies are `tokio`, which only [`conn`] uses, and `libc` for
//! one socket option ([`conn::unix_buffers`]); SHA-1 and base64 are
//! in-house because the handshake needs nothing more than a correct hash of 60
//! bytes per connection. DEFLATE ([`deflate`]) is in-house too, for the
//! permessage-deflate extension ([`ws::pmd`]): a decoder and a speed-first encoder
//! that keep no per-message allocations and, without context takeover, no
//! per-connection memory. `miniz_oxide` is a dev-dependency only, the reference the
//! codec is cross-checked against in the tests and measured against in the benchmark
//! (`cargo run --release -p relay-net --example deflate_bench`).

pub mod base64;
pub mod conn;
pub mod connector;
pub mod deflate;
pub mod http;
pub mod sha1;
pub mod ws;
