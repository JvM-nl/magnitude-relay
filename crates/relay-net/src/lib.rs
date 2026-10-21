//! HTTP/1.1 upgrade and RFC 6455 WebSocket, written for the relay's hot path.
//!
//! The core is **sans-IO**: [`http`] and [`ws`] are pure functions and small state
//! machines over byte buffers, with no sockets, locks, `Arc`s or per-frame
//! allocation. A connection owner (the relay's reactor) reads into its own buffer,
//! calls in, and flushes one output `Vec<u8>` with a single write. [`conn`] wraps
//! the same code in tokio helpers for tests and the benchmark client.
//!
//! The only dependency is `tokio`, and only [`conn`] uses it; SHA-1 and base64 are
//! in-house because the handshake needs nothing more than a correct hash of 60
//! bytes per connection.

pub mod base64;
pub mod conn;
pub mod http;
pub mod sha1;
pub mod ws;
