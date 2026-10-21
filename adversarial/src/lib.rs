//! The relay's adversarial test suite. Four parts, one binary (`adv`):
//!
//! - **Fuzzing** ([`targets`], [`fuzz`]): every parser of untrusted input, with
//!   invariants (no panic, memory and time budgets, round trips) and
//!   differential checks against reference implementations. The same targets
//!   run under libFuzzer (`adversarial/fuzz`, nightly, on the box).
//! - **Hostile clients** ([`hostile`]): the real binary under malformed,
//!   abusive and resource-exhausting traffic while a well-behaved canary checks
//!   that answers stay right and fast.
//! - **Crash torture** ([`torture`]): a writer in a child process killed at
//!   random moments and at named crash points, the store reopened and checked
//!   against a model of acknowledged writes; plus disk-full and corruption.
//! - **Concurrency stress** ([`stress`]): readers, writers, compactions and
//!   operator deletes at once against the model.
//!
//! See docs/ADVERSARIAL.md for how to run each and what they found.

// `*rng.pick(..)` is needed where the pick's type is inferred from its use.
#![allow(clippy::explicit_auto_deref)]

pub mod alloc;
pub mod corrupt;
pub mod fuzz;
pub mod gen;
pub mod hostile;
pub mod mutate;
pub mod rng;
pub mod sign;
pub mod targets;
pub mod torture;
pub mod wsframe;

/// A switch in the environment: set, and neither empty nor "0".
pub fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.is_empty() && v != "0")
}

// The relay's settings code, compiled here as it is in the relay so the fuzz
// targets can reach it (the relay is a binary crate with no library to link).
#[path = "../../crates/relay-server/src/brand.rs"]
pub mod brand;
#[path = "../../crates/relay-server/src/config.rs"]
pub mod config;
#[path = "../../crates/relay-server/src/toml.rs"]
pub mod toml;

/// What the settings code uses of the relay's operator module (which needs
/// the rest of the binary): its filter parsing, the same rules.
pub mod operator {
    use relay_proto::filter::FilterError;
    use relay_proto::json::Scanner;
    use relay_proto::Filter;

    pub fn parse_filters(text: &str) -> Result<Vec<Filter>, String> {
        let mut s = Scanner::new(text);
        let mut filters = Vec::new();
        if s.peek() == Some(b'[') {
            s.array(|s| -> Result<(), FilterError> {
                filters.push(Filter::parse(s)?);
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        } else {
            filters.push(Filter::parse(&mut s).map_err(|e| e.to_string())?);
        }
        s.end().map_err(|e| e.to_string())?;
        if filters.is_empty() {
            return Err("no filters: an empty list matches nothing".into());
        }
        if filters.iter().any(|f| f.limit.is_some()) {
            return Err("\"limit\" inside a filter is not supported: query takes --limit".into());
        }
        Ok(filters)
    }
}
