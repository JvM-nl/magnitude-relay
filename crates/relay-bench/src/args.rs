//! Command-line parsing without a dependency.
//!
//! A benchmark campaign is a long shell script, and a typo that silently falls back
//! to a default (`--conn 64` read as nothing, 16 used) produces numbers that look
//! fine and mean something else. So every option is *taken* by the command that
//! uses it, and [`Args::finish`] fails on anything left over.

use std::collections::BTreeMap;
use std::str::FromStr;

#[derive(Debug)]
pub struct Args {
    pub cmd: String,
    opts: BTreeMap<String, String>,
}

impl Args {
    /// `argv` is everything after the program name: `<command> [--name value | --name=value | --flag]...`.
    /// `bool_flags` lists the options that take no value.
    pub fn parse(argv: &[String], bool_flags: &[&str]) -> Result<Args, String> {
        let mut it = argv.iter();
        let cmd = it.next().ok_or("no command given")?.clone();
        if cmd.starts_with("--") {
            return Err(format!("expected a command before '{cmd}'"));
        }
        let mut opts = BTreeMap::new();
        while let Some(a) = it.next() {
            let Some(body) = a.strip_prefix("--") else {
                return Err(format!("unexpected argument '{a}' (options look like --name value)"));
            };
            let (name, value) = match body.split_once('=') {
                Some((n, v)) => (n.to_owned(), v.to_owned()),
                None if bool_flags.contains(&body) => (body.to_owned(), "true".to_owned()),
                None => {
                    let v = it.next().ok_or_else(|| format!("--{body} needs a value"))?;
                    (body.to_owned(), v.clone())
                }
            };
            if opts.insert(name.clone(), value).is_some() {
                return Err(format!("--{name} given twice"));
            }
        }
        Ok(Args { cmd, opts })
    }

    pub fn str(&mut self, name: &str) -> Option<String> {
        self.opts.remove(name)
    }

    pub fn req(&mut self, name: &str) -> Result<String, String> {
        self.str(name).ok_or_else(|| format!("--{name} is required"))
    }

    pub fn str_or(&mut self, name: &str, default: &str) -> String {
        self.str(name).unwrap_or_else(|| default.to_owned())
    }

    pub fn flag(&mut self, name: &str) -> bool {
        self.opts.remove(name).is_some()
    }

    /// A count: plain digits, `_` separators, or a `k`/`m`/`g` suffix (`5M`, `20k`, `1_000`).
    pub fn count(&mut self, name: &str, default: u64) -> Result<u64, String> {
        match self.str(name) {
            None => Ok(default),
            Some(v) => parse_count(&v).ok_or_else(|| format!("--{name}: '{v}' is not a count (try 20000, 20k or 5M)")),
        }
    }

    pub fn opt_count(&mut self, name: &str) -> Result<Option<u64>, String> {
        match self.str(name) {
            None => Ok(None),
            Some(v) => parse_count(&v).map(Some).ok_or_else(|| format!("--{name}: '{v}' is not a count")),
        }
    }

    pub fn num<T: FromStr>(&mut self, name: &str, default: T) -> Result<T, String> {
        match self.str(name) {
            None => Ok(default),
            Some(v) => v.parse().map_err(|_| format!("--{name}: '{v}' is not a valid number")),
        }
    }

    pub fn opt_num<T: FromStr>(&mut self, name: &str) -> Result<Option<T>, String> {
        match self.str(name) {
            None => Ok(None),
            Some(v) => v.parse().map(Some).map_err(|_| format!("--{name}: '{v}' is not a valid number")),
        }
    }

    /// Errors if any option was not taken: a typo, or one this command does not have.
    pub fn finish(self) -> Result<(), String> {
        match self.opts.keys().next() {
            None => Ok(()),
            Some(k) => Err(format!("unknown option --{k} for '{}'", self.cmd)),
        }
    }
}

pub fn parse_count(s: &str) -> Option<u64> {
    let s: String = s.chars().filter(|&c| c != '_').collect();
    let (digits, mult) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1_000),
        'm' | 'M' => (&s[..s.len() - 1], 1_000_000),
        'g' | 'G' => (&s[..s.len() - 1], 1_000_000_000),
        _ => (s.as_str(), 1),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn parses_values_equals_and_flags() {
        let mut a = Args::parse(&v(&["load", "--url", "ws://x", "--conns=8", "--duplicates"]), &["duplicates"]).unwrap();
        assert_eq!(a.cmd, "load");
        assert_eq!(a.req("url").unwrap(), "ws://x");
        assert_eq!(a.num("conns", 1usize).unwrap(), 8);
        assert!(a.flag("duplicates"));
        assert!(!a.flag("duplicates"));
        assert_eq!(a.num("queries", 77u64).unwrap(), 77);
        assert!(a.finish().is_ok());
    }

    #[test]
    fn leftovers_are_errors_not_silently_ignored() {
        let mut a = Args::parse(&v(&["query", "--conn", "64", "--url", "ws://x"]), &[]).unwrap();
        a.req("url").unwrap();
        assert_eq!(a.finish().unwrap_err(), "unknown option --conn for 'query'");
    }

    #[test]
    fn malformed_command_lines() {
        assert!(Args::parse(&[], &[]).is_err());
        assert!(Args::parse(&v(&["--url", "x"]), &[]).is_err());
        assert!(Args::parse(&v(&["gen", "--events"]), &[]).unwrap_err().contains("needs a value"));
        assert!(Args::parse(&v(&["gen", "5"]), &[]).unwrap_err().contains("unexpected argument"));
        assert!(Args::parse(&v(&["gen", "--a", "1", "--a", "2"]), &[]).unwrap_err().contains("twice"));
        let mut a = Args::parse(&v(&["gen"]), &[]).unwrap();
        assert!(a.req("out").unwrap_err().contains("--out is required"));
        let mut a = Args::parse(&v(&["gen", "--events", "lots"]), &[]).unwrap();
        assert!(a.count("events", 1).unwrap_err().contains("not a count"));
        let mut a = Args::parse(&v(&["gen", "--rate", "fast"]), &[]).unwrap();
        assert!(a.num("rate", 1.0f64).is_err());
    }

    #[test]
    fn counts_accept_suffixes() {
        assert_eq!(parse_count("5M"), Some(5_000_000));
        assert_eq!(parse_count("20k"), Some(20_000));
        assert_eq!(parse_count("1_000"), Some(1000));
        assert_eq!(parse_count("2g"), Some(2_000_000_000));
        assert_eq!(parse_count("0"), Some(0));
        assert_eq!(parse_count(""), None);
        assert_eq!(parse_count("k"), None);
        assert_eq!(parse_count("-3"), None);
        assert_eq!(parse_count("1.5k"), None);
        assert_eq!(parse_count("99999999999999999999"), None);
    }
}
