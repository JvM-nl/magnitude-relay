//! The Nostr wire protocol, done once and done fast.
//!
//! Nothing here performs IO. Parsing never builds a JSON tree: events go
//! straight from wire bytes to the compact [`record`] form the store keeps, and
//! back out to JSON with a copy and a hex encode.

pub mod base64;
pub mod event;
pub mod filter;
pub mod hex;
pub mod json;
pub mod kind;
pub mod message;
pub mod negentropy;
pub mod nip19;
pub mod record;
pub mod secp;
pub mod sha256;
pub mod varint;

pub use event::{EventInfo, EventParser, Reject};
pub use filter::Filter;
pub use message::ClientMsg;
pub use record::Record;
