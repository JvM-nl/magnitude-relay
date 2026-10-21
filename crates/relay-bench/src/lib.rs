//! A load generator and validating tester for Nostr relays.
//!
//! The same dataset and the same requests go to every relay; what differs between a
//! benchmark and a test is only that here **every answer is checked**. The expected
//! answer to each query is computed from the dataset file by code that shares nothing
//! with any relay (see [`data`], [`check`]), so a relay that is fast because it is
//! wrong fails loudly instead of winning.
//!
//! Commands (see `relay-bench help`): `gen` writes a deterministic signed dataset;
//! `load` ingests it; `query` runs validated read workloads; `neg` runs NIP-77
//! reconciliation against the reference client; `fanout` measures live delivery
//! latency and loss; `idle` holds many quiet connections and samples the relay's memory.

pub mod args;
pub mod check;
pub mod data;
pub mod fanout;
pub mod generate;
pub mod hist;
pub mod idle;
pub mod jsonw;
pub mod load;
#[cfg(test)]
mod mock;
pub mod neg;
pub mod net;
pub mod par;
pub mod query;
pub mod report;
pub mod rng;
pub mod sign;
pub mod wire;
pub mod workload;
