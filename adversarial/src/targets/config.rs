//! relay-server's settings file: the TOML subset parser and the settings built
//! from it. A typo in relay.toml must become a message with a line number,
//! never a panic at startup.

use super::{fp, fp_str, linear_cap, Target};
use crate::rng::Rng;

const TOML_DICT: &[&[u8]] = &[
    b"[relay]\n", b"[limits]\n", b"[store]\n", b"[policy]\n", b"[tls]\n", b"[info]\n", b" = ", b"\"", b"'", b"[", b"]", b",", b"#",
    b"\\u00e9", b"\\U0001F600", b"1_000", b"-1", b"9223372036854775808", b"true", b"false", b"bind = \"127.0.0.1:7777\"\n",
    b"kinds = [1, 1059]\n", b"max_limit = 5000\n", b"domains = [\"a.example\"]\n", b"\n", b"\r\n",
];

pub fn targets() -> Vec<Target> {
    vec![Target { name: "config", run: config, seeds, generate: gen, dict: TOML_DICT, max_len: 64 << 10, mem_cap: linear_cap }]
}

pub fn config(data: &[u8]) -> u64 {
    let Ok(s) = std::str::from_utf8(data) else { return 1 };
    let lines = s.lines().count().max(1);
    let doc = crate::toml::parse(s);
    if let Err(e) = &doc {
        assert!(e.line >= 1 && e.line <= lines + 1, "error on line {} of a {lines}-line file", e.line);
    }
    match crate::config::Config::from_toml(s) {
        Ok(cfg) => {
            let _ = cfg.nip11_json();
            let _ = crate::config::store_options(&cfg);
            let kp = cfg.policy.kind_policy();
            for k in [0u64, 1, 1059, 21059, u64::MAX] {
                let _ = kp.allows(k);
            }
            serde_json::from_str::<serde_json::Value>(&cfg.nip11_json()).expect("NIP-11 document is JSON");
            fp(&[2, u64::from(doc.is_ok())])
        }
        Err(e) => {
            if let Some(l) = e.line {
                assert!(l >= 1 && l <= lines + 1, "error on line {l} of a {lines}-line file");
            }
            fp(&[3, fp_str(&e.msg[..e.msg.len().min(24)])])
        }
    }
}

/// `init`'s commented file, and the same with every setting switched on.
fn seeds() -> Vec<Vec<u8>> {
    let text = crate::config::default_config_text();
    let on: String = text.lines().map(|l| l.strip_prefix("# ").filter(|r| r.contains(" = ") || r.starts_with('[')).unwrap_or(l)).collect::<Vec<_>>().join("\n");
    vec![text.into_bytes(), on.into_bytes(), b"[relay]\nbind = \"127.0.0.1:1\"\nthreads = 2\n[limits]\nmax_limit = 10\ndefault_limit = 20\n".to_vec()]
}

fn gen(rng: &mut Rng) -> Vec<u8> {
    let mut s = String::new();
    for _ in 0..rng.skewed(12) {
        match rng.below(5) {
            0 => s.push_str(&format!("[{}]\n", rng.pick(&["relay", "limits", "store", "policy", "tls", "info", "nope", ""]))),
            1 => s.push_str(&format!("{} = {}\n", rng.pick(&["bind", "threads", "max_limit", "kinds", "domains", "data", "x"]), crate::gen::json_value(rng, 1))),
            2 => s.push_str(&format!("# {}\n", crate::gen::json_string(rng, 20))),
            3 => s.push_str(&format!("kinds = [{}]\n", (0..rng.skewed(5)).map(|_| crate::gen::json_number(rng)).collect::<Vec<_>>().join(", "))),
            _ => s.push_str(&format!("name = '{}'\n", crate::gen::json_string(rng, 20))),
        }
    }
    s.into_bytes()
}
