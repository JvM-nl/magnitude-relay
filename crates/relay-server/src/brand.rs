//! The product's name, in one place. Renaming the relay means editing this file,
//! the `[[bin]]` name in Cargo.toml, and the README; nothing else.

/// Human-facing name (NIP-11 `name` default, logs, `--help`).
pub const NAME: &str = "Magnitude Relay";

/// Short lowercase form for paths and service names.
pub const SLUG: &str = "magnitude-relay";

/// NIP-11 `software`.
pub const SOFTWARE_URL: &str = "https://github.com/VectorPrivacy";

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
