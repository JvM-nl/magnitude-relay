//! The relay's settings: defaults, the optional `relay.toml`, and validation.
//!
//! This is the Selfhosting Kit's front door, so two rules shape it. The relay
//! must run with no file at all (every key is optional and `Config::default()`
//! is the product's out-of-the-box behaviour), and a file written by someone who
//! has never seen TOML must fail loudly and helpfully: unknown keys are errors
//! (a typo must not become a silently ignored setting) with a "did you mean"
//! hint, and every error names its line.
//!
//! Nothing here performs IO except [`Config::load`].

// The server loop that consumes `relay`, `info`, `policy` and `limits` is written
// separately; until it lands the binary only reads `store`. Remove this then.
#![allow(dead_code)]

use crate::toml::{self, Document, Entry, Value};
use crate::brand;
use relay_proto::json::escape_str;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The file looked for when no `--config` is given.
pub const DEFAULT_FILE: &str = "relay.toml";

/// Event kinds the relay accepts out of the box: exactly what Vector produces
/// and reads, per the kinds table in PLAN.md. Public notes are not on the list.
/// Kept sorted and unique.
pub const VECTOR_KINDS: &[u64] = &[
    // Profile.
    0,
    // Deletion (NIP-09).
    5,
    // Badge award.
    8,
    // Request to vanish (NIP-62).
    62,
    // Gift wrap: DM, Concord stream wrap and direct invite.
    1059,
    // Relay list.
    10002,
    // Emoji list.
    10030,
    // DM inbox relays.
    10050,
    // Blossom servers.
    10063,
    // Bot manifest.
    10304,
    // Retired Concord list.
    13302,
    // Concord invite list.
    13303,
    // Ephemeral Concord wrap (typing, voice presence).
    21059,
    // Push request.
    24590,
    // Device transfer.
    24681,
    // Badge definition.
    30009,
    // Emoji set.
    30030,
    // App data.
    30078,
    // User status.
    30315,
    // Concord invite bundle.
    33301,
    // Concord community list fragment.
    33302,
];

/// NIPs the relay speaks, as published in NIP-11. Not 42: this relay never
/// authenticates anyone (PLAN.md, Decisions).
pub const SUPPORTED_NIPS: &[u32] = &[1, 9, 11, 40, 45, 59, 62, 70, 77];

/// Every section and its keys. The single source for "did you mean" hints and
/// for the test that keeps the documented default file complete.
const KEYS: &[(&str, &[&str])] = &[
    ("relay", &["bind", "threads", "real_ip_header"]),
    (
        "info",
        &["name", "description", "pubkey", "contact", "icon", "banner", "privacy_policy", "terms_of_service", "privacy_addresses"],
    ),
    ("policy", &["kinds", "allow_kinds", "deny_kinds", "max_event_bytes", "max_future_seconds", "max_tags"]),
    (
        "limits",
        &[
            "max_message_bytes",
            "max_subscriptions",
            "max_filters",
            "max_filter_values",
            "default_limit",
            "max_limit",
            "max_connections_per_ip",
            "events_per_minute_per_ip",
            "outbound_buffer_bytes",
        ],
    ),
    ("store", &["data", "sync", "segment_mb"]),
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub relay: RelayCfg,
    pub info: InfoCfg,
    pub policy: PolicyCfg,
    pub limits: LimitsCfg,
    pub store: StoreCfg,
}

/// `[relay]`: where and how to listen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCfg {
    pub bind: SocketAddr,
    /// 0 = one reactor per hardware thread.
    pub threads: usize,
    /// Lowercase header naming the real client address, or empty to trust the
    /// socket peer. Only safe when the relay is reachable solely through the
    /// proxy that sets it: otherwise any client can forge it and sidestep every
    /// per-IP limit.
    pub real_ip_header: String,
}

/// `[info]`: the NIP-11 document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoCfg {
    pub name: String,
    pub description: String,
    /// Empty, or 64 lowercase hex characters.
    pub pubkey: String,
    pub contact: String,
    pub icon: String,
    pub banner: String,
    pub privacy_policy: String,
    pub terms_of_service: String,
    /// The relay's own `.onion` / `.b32.i2p` twins, as `ws://` or `wss://` URLs.
    /// Vector reads them from NIP-11 to find a private route to this relay.
    pub privacy_addresses: Vec<String>,
}

/// What the `kinds` setting selects before `allow_kinds` and `deny_kinds` apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KindBase {
    /// [`VECTOR_KINDS`].
    Vector,
    All,
    List(Vec<u64>),
}

/// `[policy]`: what the relay accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCfg {
    pub kinds: KindBase,
    /// Added on top of the base set.
    pub allow_kinds: Vec<u64>,
    /// Removed from it. Wins over everything else.
    pub deny_kinds: Vec<u64>,
    /// Inclusive, measured on the serialised event. Concord designs to 64 KiB.
    pub max_event_bytes: usize,
    /// How far ahead of the relay's clock `created_at` may be. There is no lower
    /// bound: NIP-17 backdates wraps by days and a Concord relay move republishes
    /// old events verbatim.
    pub max_future_seconds: u64,
    pub max_tags: usize,
}

/// `[limits]`: per-connection and per-IP resource caps. Sized for what Vector
/// asks of a relay: a cap below its request silently truncates its history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitsCfg {
    pub max_message_bytes: usize,
    pub max_subscriptions: usize,
    pub max_filters: usize,
    /// Per list inside one filter (`ids`, `authors`, `kinds`, each `#x`).
    pub max_filter_values: usize,
    pub default_limit: usize,
    pub max_limit: usize,
    /// 0 = unlimited.
    pub max_connections_per_ip: u32,
    /// 0 = unlimited.
    pub events_per_minute_per_ip: u32,
    pub outbound_buffer_bytes: usize,
}

/// `[store]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreCfg {
    pub data: PathBuf,
    pub sync: bool,
    pub segment_mb: u32,
}

impl Default for RelayCfg {
    fn default() -> Self {
        // 7777 is strfry's port, so an existing nginx upstream keeps working.
        RelayCfg { bind: SocketAddr::from(([127, 0, 0, 1], 7777)), threads: 0, real_ip_header: String::new() }
    }
}

impl Default for InfoCfg {
    fn default() -> Self {
        InfoCfg {
            name: brand::NAME.to_string(),
            description: "A relay for Vector.".to_string(),
            pubkey: String::new(),
            contact: String::new(),
            icon: String::new(),
            banner: String::new(),
            privacy_policy: String::new(),
            terms_of_service: String::new(),
            privacy_addresses: Vec::new(),
        }
    }
}

impl Default for PolicyCfg {
    fn default() -> Self {
        PolicyCfg {
            kinds: KindBase::Vector,
            allow_kinds: Vec::new(),
            deny_kinds: Vec::new(),
            max_event_bytes: 65_536,
            max_future_seconds: 900,
            max_tags: 2000,
        }
    }
}

impl Default for LimitsCfg {
    fn default() -> Self {
        LimitsCfg {
            max_message_bytes: 262_144,
            max_subscriptions: 200,
            max_filters: 50,
            max_filter_values: 5000,
            default_limit: 500,
            max_limit: 5000,
            max_connections_per_ip: 64,
            events_per_minute_per_ip: 1200,
            outbound_buffer_bytes: 33_554_432,
        }
    }
}

impl Default for StoreCfg {
    fn default() -> Self {
        StoreCfg { data: PathBuf::from("./data"), sync: true, segment_mb: 1024 }
    }
}

impl StoreCfg {
    /// The storage engine's options for this section.
    pub fn options(&self) -> relay_store::Options {
        relay_store::Options { segment_size: u64::from(self.segment_mb) << 20, sync: self.sync }
    }
}

impl PolicyCfg {
    /// The compiled accept/refuse test for event kinds.
    pub fn kind_policy(&self) -> KindPolicy {
        KindPolicy::new(&self.kinds, &self.allow_kinds, &self.deny_kinds)
    }

    /// True unless every kind is accepted. NIP-11 `restricted_writes`.
    pub fn restricts_writes(&self) -> bool {
        !(self.kinds == KindBase::All && self.deny_kinds.is_empty())
    }
}

/// Kinds below this are tested with one bit lookup.
const BITSET_KINDS: u64 = 1 << 16;

/// The compiled kind allowlist. Almost every kind a client sends is below 65536
/// (NIP-01's range), so those hit a flat 8 KiB bitset: one load and a mask, no
/// branches on the data. Larger kinds are rare and go through a sorted list.
#[derive(Clone, PartialEq, Eq)]
pub struct KindPolicy {
    bits: Box<[u64; 1024]>,
    /// Kinds of 65536 and above. When `open`, the kinds that are refused;
    /// otherwise the kinds that are accepted.
    big: Vec<u64>,
    /// Every large kind is accepted unless listed in `big`.
    open: bool,
}

impl KindPolicy {
    /// Builds the set `base` + `allow` - `deny`; a kind in `deny` is refused
    /// whatever else says.
    pub fn new(base: &KindBase, allow: &[u64], deny: &[u64]) -> KindPolicy {
        let open = *base == KindBase::All;
        let mut bits = Box::new([0u64; 1024]);
        let mut big = Vec::new();
        let base_list: &[u64] = match base {
            KindBase::Vector => VECTOR_KINDS,
            KindBase::List(l) => l,
            KindBase::All => {
                bits.fill(u64::MAX);
                &[]
            }
        };
        for &k in base_list.iter().chain(allow) {
            if k < BITSET_KINDS {
                bits[(k >> 6) as usize] |= 1 << (k & 63);
            } else if !open {
                big.push(k);
            }
        }
        for &k in deny {
            if k < BITSET_KINDS {
                bits[(k >> 6) as usize] &= !(1 << (k & 63));
            } else if open {
                big.push(k);
            } else {
                big.retain(|&b| b != k);
            }
        }
        big.sort_unstable();
        big.dedup();
        KindPolicy { bits, big, open }
    }

    #[inline]
    pub fn allows(&self, kind: u64) -> bool {
        if kind < BITSET_KINDS {
            self.bits[(kind >> 6) as usize] >> (kind & 63) & 1 == 1
        } else {
            // In the list means accepted, unless the list is the refusals.
            self.big.binary_search(&kind).is_ok() != self.open
        }
    }
}

impl fmt::Debug for KindPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let small: u32 = self.bits.iter().map(|w| w.count_ones()).sum();
        f.debug_struct("KindPolicy").field("small_kinds_allowed", &small).field("big_kinds", &self.big.len()).field("big_open", &self.open).finish()
    }
}

/// A problem with the settings, located as precisely as it can be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    /// The file, once known (`from_toml` does not know it).
    pub file: Option<String>,
    pub line: Option<usize>,
    pub msg: String,
}

impl ConfigError {
    fn at(line: usize, msg: impl Into<String>) -> Self {
        ConfigError { file: None, line: Some(line), msg: msg.into() }
    }

    fn in_file(path: &Path, line: Option<usize>, msg: impl Into<String>) -> Self {
        ConfigError { file: Some(path.display().to_string()), line, msg: msg.into() }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => write!(f, "{file} line {line}: {}", self.msg),
            (Some(file), None) => write!(f, "{file}: {}", self.msg),
            (None, Some(line)) => write!(f, "line {line}: {}", self.msg),
            (None, None) => f.write_str(&self.msg),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// The settings file at `path`, which must exist; with no path, `./relay.toml`
    /// if there is one and the defaults if there is not. A missing default file
    /// is normal (the relay runs with no configuration); a missing named file is
    /// a mistake the user wants to hear about.
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        match path {
            Some(p) => Config::load_file(p, false),
            None => Config::load_file(Path::new(DEFAULT_FILE), true),
        }
    }

    fn load_file(path: &Path, optional: bool) -> Result<Config, ConfigError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if optional {
                    return Ok(Config::default());
                }
                return Err(ConfigError::in_file(
                    path,
                    None,
                    format!("file not found; `{} init {}` writes a commented starting point", brand::SLUG, path.display()),
                ));
            }
            Err(e) => return Err(ConfigError::in_file(path, None, format!("cannot read it: {e}"))),
        };
        let text = String::from_utf8(bytes).map_err(|e| {
            let line = 1 + e.as_bytes()[..e.utf8_error().valid_up_to()].iter().filter(|&&b| b == b'\n').count();
            ConfigError::in_file(path, Some(line), "this is not valid UTF-8 text; save the file as UTF-8")
        })?;
        Config::from_toml(&text).map_err(|mut e| {
            e.file = Some(path.display().to_string());
            e
        })
    }

    /// Parses settings text. Absent keys keep their defaults; unknown sections and
    /// keys, wrong types and out-of-range values are errors.
    pub fn from_toml(text: &str) -> Result<Config, ConfigError> {
        let doc = toml::parse(text).map_err(|e| ConfigError::at(e.line, e.msg))?;
        let mut cfg = Config::default();
        for sec in &doc.sections {
            if sec.name.is_empty() {
                let e = &sec.entries[0];
                return Err(ConfigError::at(e.line, outside_section(&e.key)));
            }
            if !KEYS.iter().any(|(s, _)| *s == sec.name) {
                return Err(ConfigError::at(sec.line, unknown_section(&sec.name)));
            }
            for e in &sec.entries {
                let applied = match sec.name.as_str() {
                    "relay" => apply_relay(&mut cfg.relay, e),
                    "info" => apply_info(&mut cfg.info, e),
                    "policy" => apply_policy(&mut cfg.policy, e),
                    "limits" => apply_limits(&mut cfg.limits, e),
                    "store" => apply_store(&mut cfg.store, e),
                    _ => Ok(false),
                };
                match applied {
                    Ok(true) => {}
                    Ok(false) => return Err(ConfigError::at(e.line, unknown_key(&sec.name, &e.key))),
                    Err(msg) => return Err(ConfigError::at(e.line, msg)),
                }
            }
        }
        cfg.check_together(&doc)?;
        Ok(cfg)
    }

    /// Rules that relate one setting to another. Each is reported on the line of
    /// whichever of its settings the file actually wrote, and a value the user
    /// never wrote is labelled as the default so the message makes sense.
    fn check_together(&self, doc: &Document) -> Result<(), ConfigError> {
        let shown = |section: &str, key: &str, v: usize| {
            if doc.line_of(section, key).is_some() {
                v.to_string()
            } else {
                format!("{v}, the default")
            }
        };
        let blame = |keys: &[(&str, &str)], msg: String| {
            let line = keys.iter().find_map(|(s, k)| doc.line_of(s, k));
            ConfigError { file: None, line, msg }
        };
        let (p, l) = (&self.policy, &self.limits);
        if l.default_limit > l.max_limit {
            return Err(blame(
                &[("limits", "default_limit"), ("limits", "max_limit")],
                format!(
                    "default_limit ({}) is larger than max_limit ({}): a request without a limit would ask for more than the relay allows; raise max_limit or lower default_limit",
                    shown("limits", "default_limit", l.default_limit),
                    shown("limits", "max_limit", l.max_limit),
                ),
            ));
        }
        if p.max_event_bytes >= l.max_message_bytes {
            return Err(blame(
                &[("policy", "max_event_bytes"), ("limits", "max_message_bytes")],
                format!(
                    "[policy] max_event_bytes ({}) must be smaller than [limits] max_message_bytes ({}): an EVENT message carries the event plus a few more bytes",
                    shown("policy", "max_event_bytes", p.max_event_bytes),
                    shown("limits", "max_message_bytes", l.max_message_bytes),
                ),
            ));
        }
        if l.outbound_buffer_bytes < l.max_message_bytes {
            return Err(blame(
                &[("limits", "outbound_buffer_bytes"), ("limits", "max_message_bytes")],
                format!(
                    "outbound_buffer_bytes ({}) must be at least max_message_bytes ({}): a client's buffer has to hold one full-size message",
                    shown("limits", "outbound_buffer_bytes", l.outbound_buffer_bytes),
                    shown("limits", "max_message_bytes", l.max_message_bytes),
                ),
            ));
        }
        Ok(())
    }

    /// The NIP-11 relay information document, as the HTTP body.
    ///
    /// `created_at_upper_limit` is left out on purpose (it is relative to the
    /// clock, which NIP-11 cannot express) and so is `max_content_length`
    /// (the relay bounds whole events, not their content).
    pub fn nip11_json(&self) -> String {
        let i = &self.info;
        let l = &self.limits;
        let mut o = Obj::default();
        o.text_if("name", &i.name);
        o.text_if("description", &i.description);
        o.text_if("pubkey", &i.pubkey);
        o.text_if("contact", &i.contact);
        o.text_if("icon", &i.icon);
        o.text_if("banner", &i.banner);
        o.text("software", brand::SOFTWARE_URL);
        o.text("version", brand::VERSION);
        o.raw("supported_nips", &json_list(SUPPORTED_NIPS.iter().map(u32::to_string)));
        let mut lim = Obj::default();
        lim.raw("max_message_length", &l.max_message_bytes.to_string());
        lim.raw("max_subscriptions", &l.max_subscriptions.to_string());
        lim.raw("max_limit", &l.max_limit.to_string());
        lim.raw("default_limit", &l.default_limit.to_string());
        lim.raw("max_event_tags", &self.policy.max_tags.to_string());
        lim.raw("auth_required", "false");
        lim.raw("restricted_writes", if self.policy.restricts_writes() { "true" } else { "false" });
        o.raw("limitation", &lim.finish());
        if !i.privacy_addresses.is_empty() {
            o.raw("privacy_addresses", &json_list(i.privacy_addresses.iter().map(|a| json_str(a))));
        }
        o.text_if("privacy_policy", &i.privacy_policy);
        o.text_if("terms_of_service", &i.terms_of_service);
        o.finish()
    }
}

/// A JSON object assembled field by field. Every string goes through the
/// protocol crate's escaper, so operator-written text cannot break the document.
#[derive(Default)]
struct Obj {
    body: String,
}

impl Obj {
    fn raw(&mut self, key: &str, json: &str) {
        if !self.body.is_empty() {
            self.body.push(',');
        }
        self.body.push_str(&json_str(key));
        self.body.push(':');
        self.body.push_str(json);
    }

    fn text(&mut self, key: &str, value: &str) {
        self.raw(key, &json_str(value));
    }

    /// NIP-11 fields are optional; an empty one is noise, so it is omitted.
    fn text_if(&mut self, key: &str, value: &str) {
        if !value.is_empty() {
            self.text(key, value);
        }
    }

    fn finish(self) -> String {
        format!("{{{}}}", self.body)
    }
}

fn json_str(s: &str) -> String {
    let mut v = Vec::with_capacity(s.len() + 2);
    v.push(b'"');
    escape_str(s, &mut v);
    v.push(b'"');
    String::from_utf8(v).expect("escaping valid UTF-8 text yields valid UTF-8")
}

fn json_list(items: impl Iterator<Item = String>) -> String {
    format!("[{}]", items.collect::<Vec<_>>().join(","))
}

// ---------------------------------------------------------------------------
// Reading values. Each helper returns a complete sentence fragment naming the
// key; the caller attaches the line.

const STRING: &str = "a string";
const NUMBER: &str = "a whole number";
const BOOL: &str = "true or false";
const STRINGS: &str = "a list of strings";
const NUMBERS: &str = "a list of whole numbers";

/// "`key` must be X, but this is Y", plus the fix for the usual slip.
fn wrong_type(key: &str, want: &'static str, found: &Value) -> String {
    let hint = match found {
        Value::Str(s) if want == NUMBER && s.trim().parse::<i64>().is_ok() => "; remove the quotes",
        Value::Str(s) if want == BOOL && (s == "true" || s == "false") => "; remove the quotes",
        Value::Str(_) if want == STRINGS => "; put it in a list, like [\"...\"]",
        Value::Str(_) | Value::Int(_) if want == NUMBERS => "; put it in a list, like [1, 2]",
        Value::Int(_) | Value::Bool(_) if want == STRING => "; put it in \"quotes\"",
        Value::Int(_) if want == BOOL => "; write true or false",
        Value::Strs(_) if want == NUMBERS => "; remove the quotes around the numbers",
        Value::Ints(_) if want == STRINGS => "; put each item in \"quotes\"",
        _ => "",
    };
    format!("`{key}` must be {want}, but this is {}{hint}", found.describe())
}

fn string(e: &Entry) -> Result<&str, String> {
    match &e.value {
        Value::Str(s) => Ok(s),
        v => Err(wrong_type(&e.key, STRING, v)),
    }
}

fn boolean(e: &Entry) -> Result<bool, String> {
    match &e.value {
        Value::Bool(b) => Ok(*b),
        v => Err(wrong_type(&e.key, BOOL, v)),
    }
}

/// A whole number in `lo..=hi`.
fn int(e: &Entry, lo: u64, hi: u64) -> Result<u64, String> {
    match &e.value {
        Value::Int(n) => match u64::try_from(*n) {
            Ok(n) if (lo..=hi).contains(&n) => Ok(n),
            _ => Err(format!("`{}` must be between {lo} and {hi}, but this is {n}", e.key)),
        },
        v => Err(wrong_type(&e.key, NUMBER, v)),
    }
}

fn strings(e: &Entry) -> Result<&[String], String> {
    match &e.value {
        Value::Strs(s) => Ok(s),
        Value::Empty => Ok(&[]),
        v => Err(wrong_type(&e.key, STRINGS, v)),
    }
}

/// Event kind numbers.
fn kind_list(e: &Entry) -> Result<Vec<u64>, String> {
    let ints: &[i64] = match &e.value {
        Value::Ints(n) => n,
        Value::Empty => &[],
        v => return Err(wrong_type(&e.key, NUMBERS, v)),
    };
    ints.iter().map(|&n| u64::try_from(n).map_err(|_| format!("`{}` holds {n}, but event kinds are not negative", e.key))).collect()
}

fn apply_relay(c: &mut RelayCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "bind" => {
            let s = string(e)?;
            c.bind = s.parse().map_err(|_| {
                if s.contains(':') {
                    format!("`bind` is not an address and port: \"{s}\". Use an IP address and port, like \"127.0.0.1:7777\", \"0.0.0.0:7777\" or \"[::]:7777\" (host names such as localhost are not accepted)")
                } else {
                    format!("`bind` needs a port as well as an address: write \"{s}:7777\"")
                }
            })?;
        }
        "threads" => c.threads = int(e, 0, 1024)? as usize,
        "real_ip_header" => {
            let s = string(e)?;
            let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
            if !s.bytes().all(token) {
                return Err(format!("`real_ip_header` must be an HTTP header name like \"x-forwarded-for\" or \"x-real-ip\", not \"{s}\""));
            }
            // Header names are case-insensitive; compare them in one case.
            c.real_ip_header = s.to_ascii_lowercase();
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn apply_info(c: &mut InfoCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "name" => c.name = string(e)?.to_string(),
        "description" => c.description = string(e)?.to_string(),
        "pubkey" => {
            let s = string(e)?;
            let valid = s.is_empty() || (s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            if !valid {
                return Err(if s.starts_with("npub1") {
                    "`pubkey` must be the 64-character hex form of your public key, not an npub (convert it in any Nostr client or at nostr.band)".to_string()
                } else if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                    "`pubkey` must be lowercase hex; change the capital letters to lowercase".to_string()
                } else {
                    format!("`pubkey` must be 64 lowercase hex characters (or \"\" for none), but this has {} characters", s.chars().count())
                });
            }
            c.pubkey = s.to_string();
        }
        "contact" => c.contact = string(e)?.to_string(),
        "icon" => c.icon = string(e)?.to_string(),
        "banner" => c.banner = string(e)?.to_string(),
        "privacy_policy" => c.privacy_policy = string(e)?.to_string(),
        "terms_of_service" => c.terms_of_service = string(e)?.to_string(),
        "privacy_addresses" => {
            let list = strings(e)?;
            for a in list {
                let host = a.strip_prefix("wss://").or_else(|| a.strip_prefix("ws://"));
                if host.is_none_or(str::is_empty) {
                    return Err(format!("`privacy_addresses` entries must be websocket URLs starting with ws:// or wss://, but \"{a}\" is not"));
                }
            }
            c.privacy_addresses = list.to_vec();
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn apply_policy(c: &mut PolicyCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "kinds" => {
            c.kinds = match &e.value {
                Value::Str(s) if s.eq_ignore_ascii_case("vector") => KindBase::Vector,
                Value::Str(s) if s.eq_ignore_ascii_case("all") => KindBase::All,
                Value::Str(s) => {
                    let hint = suggest(s, &["vector", "all"]).map(|k| format!(" (did you mean \"{k}\"?)")).unwrap_or_default();
                    return Err(format!("`kinds` must be \"vector\", \"all\", or a list of kind numbers like [0, 1, 7], not \"{s}\"{hint}"));
                }
                Value::Ints(_) | Value::Empty => KindBase::List(kind_list(e)?),
                v => return Err(format!("`kinds` must be \"vector\", \"all\", or a list of kind numbers like [0, 1, 7], but this is {}", v.describe())),
            };
        }
        "allow_kinds" => c.allow_kinds = kind_list(e)?,
        "deny_kinds" => c.deny_kinds = kind_list(e)?,
        "max_event_bytes" => c.max_event_bytes = int(e, 1024, 1 << 24)? as usize,
        "max_future_seconds" => c.max_future_seconds = int(e, 0, 365 * 86_400)?,
        "max_tags" => c.max_tags = int(e, 1, 1_000_000)? as usize,
        _ => return Ok(false),
    }
    Ok(true)
}

fn apply_limits(c: &mut LimitsCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "max_message_bytes" => c.max_message_bytes = int(e, 1024, 1 << 30)? as usize,
        "max_subscriptions" => c.max_subscriptions = int(e, 1, 10_000)? as usize,
        "max_filters" => c.max_filters = int(e, 1, 1000)? as usize,
        "max_filter_values" => c.max_filter_values = int(e, 1, 100_000)? as usize,
        "default_limit" => c.default_limit = int(e, 1, 1_000_000)? as usize,
        "max_limit" => c.max_limit = int(e, 1, 1_000_000)? as usize,
        "max_connections_per_ip" => c.max_connections_per_ip = int(e, 0, 10_000_000)? as u32,
        "events_per_minute_per_ip" => c.events_per_minute_per_ip = int(e, 0, 10_000_000)? as u32,
        "outbound_buffer_bytes" => c.outbound_buffer_bytes = int(e, 64 * 1024, 1 << 31)? as usize,
        _ => return Ok(false),
    }
    Ok(true)
}

fn apply_store(c: &mut StoreCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "data" => {
            let s = string(e)?;
            if s.is_empty() {
                return Err("`data` must name a folder, like \"./data\"".to_string());
            }
            if s.chars().any(char::is_control) {
                return Err("`data` contains a control character such as a tab or line break. In a Windows path, double each backslash (\"C:\\\\relay\\\\data\") or use 'single quotes' (nothing inside them is escaped)".to_string());
            }
            c.data = PathBuf::from(s);
        }
        "sync" => c.sync = boolean(e)?,
        "segment_mb" => {
            let n = int(e, 16, 4096)?;
            if !n.is_power_of_two() {
                return Err(format!("`segment_mb` must be a power of two (16, 32, 64, ... 4096), but this is {n}"));
            }
            c.segment_mb = n as u32;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Messages for names the relay does not know.

fn keys_of(section: &str) -> &'static [&'static str] {
    KEYS.iter().find(|(s, _)| *s == section).map_or(&[], |(_, k)| k)
}

fn unknown_section(name: &str) -> String {
    let sections: Vec<&str> = KEYS.iter().map(|(s, _)| *s).collect();
    match suggest(name, &sections) {
        Some(s) => format!("unknown section [{name}]; did you mean [{s}]?"),
        None => format!("unknown section [{name}]. The sections are {}", sections.iter().map(|s| format!("[{s}]")).collect::<Vec<_>>().join(", ")),
    }
}

fn unknown_key(section: &str, key: &str) -> String {
    let head = format!("unknown setting `{key}` in [{section}]");
    // The exact name under another header is the likeliest slip.
    if let Some((home, _)) = KEYS.iter().find(|(s, ks)| *s != section && ks.contains(&key)) {
        return format!("{head}; `{key}` belongs in [{home}]");
    }
    match suggest(key, keys_of(section)) {
        Some(k) => format!("{head}; did you mean `{k}`?"),
        None => format!("{head}. The settings in [{section}] are {}", keys_of(section).join(", ")),
    }
}

/// A key written before any `[section]` header.
fn outside_section(key: &str) -> String {
    if let Some((home, _)) = KEYS.iter().find(|(_, ks)| ks.contains(&key)) {
        return format!("`{key}` must come after its section header: put it under [{home}]");
    }
    let all: Vec<&str> = KEYS.iter().flat_map(|(_, ks)| ks.iter().copied()).collect();
    match suggest(key, &all) {
        Some(k) => format!("unknown setting `{key}`, and settings must sit under a [section] header; did you mean `{k}`?"),
        None => format!("unknown setting `{key}`, and settings must sit under a [section] header like [relay]"),
    }
}

/// The candidate closest to `name` if it is within edit distance 2 (and the
/// name is longer than the distance, so a two-letter word does not match
/// everything). Case and `-` versus `_` do not count as differences: they are the
/// likeliest typos and the suggestion should say so rather than point at nothing.
fn suggest<'a>(name: &str, candidates: &[&'a str]) -> Option<&'a str> {
    let norm = |s: &str| s.to_ascii_lowercase().replace('-', "_");
    let name = norm(name);
    let len = name.chars().count();
    candidates.iter().map(|&c| (edit_distance(&name, &norm(c)), c)).filter(|&(d, _)| d <= 2 && d < len).min_by_key(|&(d, _)| d).map(|(_, c)| c)
}

/// Levenshtein distance over characters.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diag = row[0];
        row[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let up = row[j + 1];
            row[j + 1] = (diag + usize::from(ca != cb)).min(up + 1).min(row[j] + 1);
            diag = up;
        }
    }
    row[b.len()]
}

// ---------------------------------------------------------------------------

/// A complete `relay.toml` with every setting documented and commented out at its
/// default, so the file parses to exactly the defaults and a user changes a
/// setting by deleting `# ` from one line. The tests keep it honest: they
/// uncomment every setting and require the result to equal `Config::default()`.
pub fn default_config_text() -> String {
    let mut kinds = String::new();
    let mut line = String::new();
    for k in VECTOR_KINDS {
        let item = format!("{k}, ");
        if line.len() + item.len() > 62 {
            kinds.push_str(&format!("#              {}\n", line.trim_end()));
            line.clear();
        }
        line.push_str(&item);
    }
    kinds.push_str(&format!("#              {}", line.trim_end().trim_end_matches(',')));

    TEMPLATE.replace("{name}", brand::NAME).replace("{slug}", brand::SLUG).replace("{vector_kinds}", &kinds)
}

/// Lines of the form `# key = value` are settings; every other comment line is
/// prose and must never look like one (a test enforces it).
const TEMPLATE: &str = r##"# {name} settings
#
# Every setting is optional. With no file at all the relay runs on the values
# below. Each one is listed here commented out and set to its default; to change
# one, delete the "# " in front of its line and edit the value.
#
# The relay reads ./relay.toml (in the folder you start it from) unless you name
# another file with --config. Text after a # is a comment. Words go in "double
# quotes"; numbers, true and false do not. Lists look like [1, 2] or ["a", "b"].
# If something is wrong the relay says which line and does not start.

[relay]
# Where to listen. "127.0.0.1" accepts connections from this computer only, which
# is right when a web server such as nginx or Caddy sits in front of the relay.
# To accept connections from anywhere use "0.0.0.0:7777" ("[::]:7777" adds IPv6).
# bind = "127.0.0.1:7777"

# Worker threads. 0 means one per hardware thread, which is almost always right.
# threads = 0

# Behind a web server every connection arrives from that server, so per-IP limits
# would count all your users as one. Name the header your web server fills in with
# the real address ("x-forwarded-for" or "x-real-ip") and the relay uses it.
# ONLY set this if the relay can be reached solely through that web server:
# anyone who can connect directly could forge the header and dodge every
# per-IP limit. Empty means use the connecting address.
# real_ip_header = ""

[info]
# What the relay tells apps about itself (NIP-11).
# name = "{name}"
# description = "A relay for Vector."

# Your public key as 64 hex characters (apps show it as the operator). An npub is
# not accepted here; Nostr clients can convert it. Empty to leave it out.
# pubkey = ""

# How to reach you, such as "mailto:you@example.com". Empty to leave it out.
# contact = ""

# Web addresses (https://...) of a small icon and a wide banner image. Empty for none.
# icon = ""
# banner = ""

# Web addresses of your privacy policy and terms of service. Empty for none.
# privacy_policy = ""
# terms_of_service = ""

# This relay's own private-network addresses (Tor .onion and I2P .b32.i2p), as
# ws:// or wss:// URLs, for example ["ws://example.onion"]. Vector reads this
# list so users can reach the relay without exposing their IP address.
# privacy_addresses = []

[policy]
# Which kinds of event the relay accepts. One of:
#   "vector"     only what Vector produces and reads. Public notes are refused.
#                Kinds:
{vector_kinds}
#   "all"        every kind
#   [0, 1, 7]    exactly this list of kind numbers
# kinds = "vector"

# Kinds to accept on top of that set, and kinds to refuse. A kind in deny_kinds
# is refused no matter what else says. For example, allow_kinds = [1] lets
# public notes in alongside Vector's own traffic.
# allow_kinds = []
# deny_kinds = []

# Largest event the relay accepts, in bytes of its JSON text. Vector's groups
# (Concord) are designed to fit in 64 KiB (65536); do not go lower or their
# messages will be refused.
# max_event_bytes = 65536

# How many seconds ahead of the relay's clock an event may be dated. Events can
# be dated any time in the past: Vector sends messages backdated by days.
# max_future_seconds = 900

# Most tags one event may carry.
# max_tags = 2000

[limits]
# Vector asks a lot of a relay: thousands of authors in one filter, history pages
# of up to 5000 events, many filters per request. Anything you lower below the
# defaults here can silently cut off part of a user's history, so lower them
# only on a small private relay.

# Largest message a client may send, in bytes. Must be bigger than max_event_bytes.
# max_message_bytes = 262144

# Open subscriptions (REQs) one connection may hold at once.
# max_subscriptions = 200

# Filters in a single subscription request.
# max_filters = 50

# Entries in each list of a filter (ids, authors, kinds, and each #tag).
# max_filter_values = 5000

# How many events a request without a limit gets, and the most a request may ask for.
# default_limit = 500
# max_limit = 5000

# Per IP address: simultaneous connections, and events accepted per minute.
# 0 turns a limit off, for example when testing from a single machine.
# max_connections_per_ip = 64
# events_per_minute_per_ip = 1200

# Memory one connection may use for messages waiting to be sent. A client that
# reads too slowly to stay under this is disconnected. At least max_message_bytes.
# outbound_buffer_bytes = 33554432

[store]
# Folder where events are kept. Created if missing. A relative path is relative
# to the folder you start the relay from, not to this file.
# data = "./data"

# true: an event is acknowledged only once it is safely on disk. false is faster
# but a crash or power cut can lose recently acknowledged events. Leave it true.
# sync = true

# Size of each storage file in MiB: a power of two from 16 to 4096. Fixed when
# the data folder is first created; changing it afterwards makes the data there
# unreadable.
# segment_mb = 1024
"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> Config {
        Config::from_toml(text).unwrap_or_else(|e| panic!("{e}\n---\n{text}"))
    }

    fn fails(text: &str, line: Option<usize>, needle: &str) {
        match Config::from_toml(text) {
            Ok(c) => panic!("expected an error containing {needle:?}, got {c:?} from {text:?}"),
            Err(e) => {
                assert_eq!(e.line, line, "line of {e} for {text:?}");
                assert!(e.msg.contains(needle), "{:?} does not contain {needle:?} (input {text:?})", e.msg);
            }
        }
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        let c = Config::default();
        assert_eq!(c.relay.bind, "127.0.0.1:7777".parse().unwrap());
        assert_eq!((c.relay.threads, c.relay.real_ip_header.as_str()), (0, ""));
        assert_eq!((c.info.name.as_str(), c.info.description.as_str()), (brand::NAME, "A relay for Vector."));
        assert_eq!(c.policy.kinds, KindBase::Vector);
        assert_eq!((c.policy.max_event_bytes, c.policy.max_future_seconds, c.policy.max_tags), (65_536, 900, 2000));
        let l = &c.limits;
        assert_eq!((l.max_message_bytes, l.max_subscriptions, l.max_filters, l.max_filter_values), (262_144, 200, 50, 5000));
        assert_eq!((l.default_limit, l.max_limit), (500, 5000));
        assert_eq!((l.max_connections_per_ip, l.events_per_minute_per_ip, l.outbound_buffer_bytes), (64, 1200, 33_554_432));
        assert_eq!((c.store.data.as_path(), c.store.sync, c.store.segment_mb), (Path::new("./data"), true, 1024));
        assert_eq!(c.store.options().segment_size, 1 << 30);
        assert!(c.store.options().sync);
    }

    #[test]
    fn empty_and_comment_only_files_are_the_defaults() {
        assert_eq!(ok(""), Config::default());
        assert_eq!(ok("# nothing here\n\n"), Config::default());
        assert_eq!(ok("[relay]\n[info]\n[policy]\n[limits]\n[store]\n"), Config::default());
    }

    #[test]
    fn default_text_is_exactly_the_defaults() {
        let text = default_config_text();
        assert_eq!(ok(&text), Config::default(), "the file as shipped");

        // Uncomment every `# key = value` line and the result must still be the
        // defaults: the documented values are the real ones, and every key in the
        // file is a key the parser accepts.
        let mut seen: Vec<String> = Vec::new();
        let uncommented: String = text
            .lines()
            .map(|l| {
                let setting = l.strip_prefix("# ").and_then(|r| r.split_once(" = ")).filter(|(k, _)| KEYS.iter().any(|(_, ks)| ks.contains(k)));
                match setting {
                    Some((k, _)) => {
                        seen.push(k.to_string());
                        format!("{}\n", &l[2..])
                    }
                    None => format!("{l}\n"),
                }
            })
            .collect();
        assert_eq!(ok(&uncommented), Config::default(), "with every setting uncommented");

        // Every key is documented exactly once, under its own header.
        let all: Vec<&str> = KEYS.iter().flat_map(|(_, ks)| ks.iter().copied()).collect();
        let mut documented: Vec<&str> = seen.iter().map(String::as_str).collect();
        documented.sort_unstable();
        let mut expected = all.clone();
        expected.sort_unstable();
        assert_eq!(documented, expected);
        let doc = toml::parse(&uncommented).unwrap();
        for (section, keys) in KEYS {
            let got: Vec<&str> = doc.section(section).unwrap().entries.iter().map(|e| e.key.as_str()).collect();
            assert_eq!(&got, keys, "[{section}] keys, in order");
        }
        assert!(text.lines().all(|l| l.chars().count() <= 90), "keep lines short enough for a terminal");
        assert!(text.contains(brand::NAME) && !text.contains('{'), "placeholders replaced");
    }

    #[test]
    fn full_custom_file() {
        let pk = "ab".repeat(32);
        let text = format!(
            r#"
[relay]
bind = "0.0.0.0:8080"
threads = 4
real_ip_header = "X-Forwarded-For"

[info]
name = "My relay"
description = "Mine, for friends."
pubkey = "{pk}"
contact = "mailto:me@example.com"
icon = "https://example.com/i.png"
banner = 'https://example.com/b.png'
privacy_policy = "https://example.com/privacy"
terms_of_service = "https://example.com/terms"
privacy_addresses = [
    "ws://abcdefghij.onion",   # tor
    "wss://abcdefghij.b32.i2p",
]

[policy]
kinds = [0, 1, 7]
allow_kinds = [30023]
deny_kinds = [7]
max_event_bytes = 100_000
max_future_seconds = 60
max_tags = 100

[limits]
max_message_bytes = 500_000
max_subscriptions = 10
max_filters = 5
max_filter_values = 100
default_limit = 20
max_limit = 100
max_connections_per_ip = 0
events_per_minute_per_ip = 0
outbound_buffer_bytes = 1_000_000

[store]
data = "/var/lib/relay"
sync = false
segment_mb = 64
"#
        );
        let c = ok(&text);
        assert_eq!(c.relay, RelayCfg { bind: "0.0.0.0:8080".parse().unwrap(), threads: 4, real_ip_header: "x-forwarded-for".into() });
        assert_eq!(c.info.name, "My relay");
        assert_eq!(c.info.pubkey, pk);
        assert_eq!(c.info.banner, "https://example.com/b.png");
        assert_eq!(c.info.privacy_addresses, ["ws://abcdefghij.onion", "wss://abcdefghij.b32.i2p"]);
        assert_eq!(c.policy.kinds, KindBase::List(vec![0, 1, 7]));
        assert_eq!((c.policy.allow_kinds.clone(), c.policy.deny_kinds.clone()), (vec![30023], vec![7]));
        assert_eq!((c.policy.max_event_bytes, c.policy.max_future_seconds, c.policy.max_tags), (100_000, 60, 100));
        assert_eq!(c.limits.max_message_bytes, 500_000);
        assert_eq!((c.limits.max_connections_per_ip, c.limits.events_per_minute_per_ip), (0, 0));
        assert_eq!(c.limits.outbound_buffer_bytes, 1_000_000);
        assert_eq!(c.store, StoreCfg { data: PathBuf::from("/var/lib/relay"), sync: false, segment_mb: 64 });
        assert_eq!(c.store.options().segment_size, 64 << 20);
        assert!(!c.store.options().sync);
        let k = c.policy.kind_policy();
        assert!(k.allows(0) && k.allows(1) && k.allows(30023) && !k.allows(7) && !k.allows(5));
    }

    #[test]
    fn kinds_setting_forms() {
        assert_eq!(ok("[policy]\nkinds = \"all\"").policy.kinds, KindBase::All);
        assert_eq!(ok("[policy]\nkinds = \"Vector\"").policy.kinds, KindBase::Vector);
        assert_eq!(ok("[policy]\nkinds = []").policy.kinds, KindBase::List(vec![]));
        assert_eq!(ok("[policy]\nallow_kinds = []\ndeny_kinds = []").policy, PolicyCfg::default());
        fails("[policy]\nkinds = \"vecor\"", Some(2), "did you mean \"vector\"");
        fails("[policy]\nkinds = \"everything\"", Some(2), "\"vector\", \"all\"");
        fails("[policy]\nkinds = 1", Some(2), "\"vector\", \"all\"");
        fails("[policy]\nkinds = [\"1\"]", Some(2), "a list of strings");
        fails("[policy]\nkinds = [1, -2]", Some(2), "not negative");
        fails("[policy]\ndeny_kinds = [\"7\"]", Some(2), "remove the quotes around the numbers");
        fails("[policy]\nallow_kinds = 7", Some(2), "put it in a list");
    }

    #[test]
    fn unknown_names_get_hints() {
        fails("[relay]\nbnid = \"x\"", Some(2), "did you mean `bind`?");
        fails("[limits]\nmax-limit = 5", Some(2), "did you mean `max_limit`?");
        fails("[limits]\nmax_limt = 5", Some(2), "did you mean `max_limit`?");
        fails("[limits]\nMax_Filters = 5", Some(2), "did you mean `max_filters`?");
        fails("[relay]\nname = \"x\"", Some(2), "`name` belongs in [info]");
        fails("[info]\nsync = true", Some(2), "belongs in [store]");
        fails("[store]\nzzzzzzzz = 1", Some(2), "The settings in [store] are data, sync, segment_mb");
        fails("[limit]\nmax_limit = 5", Some(1), "did you mean [limits]?");
        fails("[servers]\n", Some(1), "The sections are [relay], [info], [policy], [limits], [store]");
        // Hints come from the first problem in the file, by line.
        fails("[relay]\nthreads = 1\n\n[info]\nnmae = \"x\"\n[bogus]\n", Some(5), "did you mean `name`?");
        // A very short unknown key does not match every short known key.
        fails("[store]\nx = 1", Some(2), "The settings in [store]");
    }

    #[test]
    fn keys_outside_a_section() {
        fails("bind = \"127.0.0.1:7777\"\n[relay]\n", Some(1), "put it under [relay]");
        fails("\n\nbnid = 1", Some(3), "did you mean `bind`?");
        fails("whatever = 1", Some(1), "must sit under a [section] header");
    }

    #[test]
    fn syntax_errors_come_through_with_their_line() {
        fails("[relay]\nbind = 127.0.0.1:7777", Some(2), "text must be in \"quotes\"");
        fails("[relay]\n\nthreads = ", Some(3), "missing value");
    }

    #[test]
    fn wrong_types_say_what_was_expected() {
        fails("[relay]\nthreads = \"4\"", Some(2), "`threads` must be a whole number, but this is a string; remove the quotes");
        fails("[relay]\nbind = 7777", Some(2), "`bind` must be a string, but this is an integer; put it in \"quotes\"");
        fails("[store]\nsync = \"true\"", Some(2), "must be true or false, but this is a string; remove the quotes");
        fails("[store]\nsync = 1", Some(2), "write true or false");
        fails("[info]\nname = true", Some(2), "must be a string");
        fails("[info]\nprivacy_addresses = \"ws://x.onion\"", Some(2), "must be a list of strings");
        fails("[info]\nprivacy_addresses = [1]", Some(2), "put each item in \"quotes\"");
        fails("[limits]\nmax_limit = [5]", Some(2), "must be a whole number, but this is a list of integers");
        fails("[store]\ndata = []", Some(2), "must be a string, but this is an empty list");
    }

    #[test]
    fn values_are_range_checked() {
        fails("[relay]\nthreads = -1", Some(2), "between 0 and 1024, but this is -1");
        fails("[relay]\nthreads = 5000", Some(2), "between 0 and 1024");
        fails("[limits]\nmax_filters = 0", Some(2), "between 1 and 1000");
        fails("[limits]\nmax_limit = 0", Some(2), "between 1 and");
        fails("[limits]\nmax_subscriptions = 999999", Some(2), "between 1 and 10000");
        fails("[limits]\nmax_message_bytes = 10", Some(2), "between 1024");
        fails("[policy]\nmax_event_bytes = 100", Some(2), "between 1024");
        fails("[policy]\nmax_tags = 0", Some(2), "between 1 and");
        fails("[store]\nsegment_mb = 8", Some(2), "between 16 and 4096");
        fails("[store]\nsegment_mb = 8192", Some(2), "between 16 and 4096");
        fails("[store]\nsegment_mb = 100", Some(2), "power of two");
        assert_eq!(ok("[store]\nsegment_mb = 16").store.segment_mb, 16);
        assert_eq!(ok("[store]\nsegment_mb = 4096").store.segment_mb, 4096);
    }

    #[test]
    fn bind_validation() {
        assert_eq!(ok("[relay]\nbind = \"[::]:7777\"").relay.bind, "[::]:7777".parse().unwrap());
        assert_eq!(ok("[relay]\nbind = \"0.0.0.0:80\"").relay.bind.port(), 80);
        fails("[relay]\nbind = \"0.0.0.0\"", Some(2), "needs a port as well as an address: write \"0.0.0.0:7777\"");
        fails("[relay]\nbind = \"localhost:7777\"", Some(2), "host names such as localhost are not accepted");
        fails("[relay]\nbind = \"1.2.3.4:99999\"", Some(2), "not an address and port");
        fails("[relay]\nbind = \"\"", Some(2), "needs a port");
    }

    #[test]
    fn real_ip_header_validation() {
        assert_eq!(ok("[relay]\nreal_ip_header = \"\"").relay.real_ip_header, "");
        assert_eq!(ok("[relay]\nreal_ip_header = \"X-Real-IP\"").relay.real_ip_header, "x-real-ip");
        fails("[relay]\nreal_ip_header = \"x forwarded\"", Some(2), "HTTP header name");
        fails("[relay]\nreal_ip_header = \"x-real-ip:\"", Some(2), "HTTP header name");
    }

    #[test]
    fn info_validation() {
        let pk = "0123456789abcdef".repeat(4);
        assert_eq!(ok(&format!("[info]\npubkey = \"{pk}\"")).info.pubkey, pk);
        assert_eq!(ok("[info]\npubkey = \"\"").info.pubkey, "");
        fails(&format!("[info]\npubkey = \"{}\"", pk.to_uppercase()), Some(2), "must be lowercase hex");
        fails("[info]\npubkey = \"npub1abcdef\"", Some(2), "not an npub");
        fails("[info]\npubkey = \"abcd\"", Some(2), "this has 4 characters");
        fails(&format!("[info]\npubkey = \"{}zz\"", &pk[..62]), Some(2), "64 lowercase hex");
        fails("[info]\nprivacy_addresses = [\"http://x.onion\"]", Some(2), "ws:// or wss://");
        fails("[info]\nprivacy_addresses = [\"abc.onion\"]", Some(2), "\"abc.onion\" is not");
        fails("[info]\nprivacy_addresses = [\"ws://\"]", Some(2), "ws:// or wss://");
        assert_eq!(ok("[info]\nprivacy_addresses = []").info.privacy_addresses, Vec::<String>::new());
    }

    #[test]
    fn store_data_validation() {
        fails("[store]\ndata = \"\"", Some(2), "must name a folder");
        // A Windows path in double quotes turns \r and \t into control characters.
        fails("[store]\ndata = \"C:\\relay\\data\"", Some(2), "unknown escape");
        fails("[store]\ndata = \"C:\\\\relay\\ttemp\"", Some(2), "control character");
        assert_eq!(ok("[store]\ndata = 'C:\\relay\\data'").store.data, PathBuf::from("C:\\relay\\data"));
        assert_eq!(ok("[store]\ndata = \"C:\\\\relay\\\\data\"").store.data, PathBuf::from("C:\\relay\\data"));
    }

    #[test]
    fn settings_that_depend_on_each_other() {
        // Blame goes to a line the user wrote, and defaults are labelled.
        fails("[limits]\ndefault_limit = 6000", Some(2), "default_limit (6000) is larger than max_limit (5000, the default)");
        fails("[limits]\nmax_limit = 100", Some(2), "default_limit (500, the default) is larger than max_limit (100)");
        fails("[limits]\ndefault_limit = 50\nmax_limit = 10", Some(2), "raise max_limit or lower default_limit");
        assert_eq!(ok("[limits]\ndefault_limit = 100\nmax_limit = 100").limits.max_limit, 100);

        fails("[policy]\nmax_event_bytes = 300000", Some(2), "smaller than [limits] max_message_bytes (262144, the default)");
        fails("[limits]\nmax_message_bytes = 60000", Some(2), "max_event_bytes (65536, the default) must be smaller");
        fails("[policy]\nmax_event_bytes = 5000\n[limits]\nmax_message_bytes = 5000", Some(2), "must be smaller");
        assert!(Config::from_toml("[policy]\nmax_event_bytes = 5000\n[limits]\nmax_message_bytes = 5001").is_ok());

        fails("[limits]\noutbound_buffer_bytes = 100000", Some(2), "at least max_message_bytes (262144, the default)");
        fails("[limits]\nmax_message_bytes = 40_000_000", Some(2), "outbound_buffer_bytes (33554432, the default)");
    }

    #[test]
    fn edit_distance_basics() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("bind", "bind"), 0);
        assert_eq!(edit_distance("bnid", "bind"), 2);
        assert_eq!(edit_distance("bin", "bind"), 1);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
        assert_eq!(edit_distance("", "abc"), 3);
        assert_eq!(suggest("adress", &["address"]), Some("address"));
        assert_eq!(suggest("completely_different", &["bind", "threads"]), None);
    }

    // ----- kind policy -----

    #[test]
    fn vector_kinds_are_sorted_unique_and_cover_the_plan() {
        assert!(VECTOR_KINDS.windows(2).all(|w| w[0] < w[1]));
        // PLAN.md's table of what Vector produces and reads.
        for k in [0, 5, 8, 1059, 10002, 10030, 10050, 10063, 10304, 13303, 21059, 24590, 24681, 30030, 30078, 30315, 33301, 33302] {
            assert!(VECTOR_KINDS.contains(&k), "kind {k}");
        }
        let p = PolicyCfg::default().kind_policy();
        for k in VECTOR_KINDS {
            assert!(p.allows(*k));
        }
        // Public notes, reactions, contact lists and the like are refused.
        for k in [1, 3, 4, 6, 7, 9, 13, 14, 1111, 30023, 20013, 65535, 65536, u64::MAX] {
            assert!(!p.allows(k), "kind {k}");
        }
    }

    /// Reference answer: sets of kinds.
    fn reference(base: &KindBase, allow: &[u64], deny: &[u64], kind: u64) -> bool {
        let in_base = match base {
            KindBase::All => true,
            KindBase::Vector => VECTOR_KINDS.contains(&kind),
            KindBase::List(l) => l.contains(&kind),
        };
        (in_base || allow.contains(&kind)) && !deny.contains(&kind)
    }

    #[test]
    fn kind_policy_matches_a_set_reference() {
        let edge = [0u64, 1, 63, 64, 65, 1058, 1059, 1060, 65534, 65535, 65536, 65537, 70_000, 1 << 40, u64::MAX];
        let bases = [KindBase::Vector, KindBase::All, KindBase::List(vec![]), KindBase::List(vec![1, 7, 65535, 65536, 99_999])];
        let allows: [&[u64]; 3] = [&[], &[1, 30023, 65536, 80_000], &[0, 5, 65535]];
        let denies: [&[u64]; 4] = [&[], &[1059, 1], &[65536, 80_000, 99_999], &[65535, 0, 7, u64::MAX]];
        for base in &bases {
            for allow in allows {
                for deny in denies {
                    let p = KindPolicy::new(base, allow, deny);
                    let probe = edge.iter().copied().chain(VECTOR_KINDS.iter().copied()).chain(allow.iter().copied()).chain(deny.iter().copied());
                    for k in probe.chain(0..2100) {
                        assert_eq!(p.allows(k), reference(base, allow, deny, k), "base {base:?} allow {allow:?} deny {deny:?} kind {k}");
                    }
                }
            }
        }
    }

    #[test]
    fn kind_policy_every_small_kind() {
        let p = KindPolicy::new(&KindBase::Vector, &[1, 30023], &[1059]);
        for k in 0..70_000u64 {
            assert_eq!(p.allows(k), reference(&KindBase::Vector, &[1, 30023], &[1059], k), "kind {k}");
        }
        let all = KindPolicy::new(&KindBase::All, &[], &[7, 70_000]);
        for k in 0..70_000u64 {
            assert_eq!(all.allows(k), k != 7 && k != 70_000, "kind {k}");
        }
    }

    #[test]
    fn kind_policy_is_a_small_bitset() {
        assert_eq!(std::mem::size_of_val(&*KindPolicy::new(&KindBase::Vector, &[], &[]).bits), 8192);
        let p = PolicyCfg { kinds: KindBase::All, ..PolicyCfg::default() };
        assert!(!p.restricts_writes());
        assert!(p.kind_policy().allows(u64::MAX));
        // A deny list means some writes are refused.
        let p = PolicyCfg { kinds: KindBase::All, deny_kinds: vec![1], ..PolicyCfg::default() };
        assert!(p.restricts_writes());
        assert!(PolicyCfg::default().restricts_writes());
    }

    // ----- NIP-11 -----

    fn nip11(c: &Config) -> serde_json::Value {
        let s = c.nip11_json();
        serde_json::from_str(&s).unwrap_or_else(|e| panic!("{e}\n{s}"))
    }

    #[test]
    fn nip11_defaults() {
        let j = nip11(&Config::default());
        assert_eq!(j["name"], brand::NAME);
        assert_eq!(j["description"], "A relay for Vector.");
        assert_eq!(j["software"], brand::SOFTWARE_URL);
        assert_eq!(j["version"], brand::VERSION);
        assert_eq!(j["supported_nips"], serde_json::json!([1, 9, 11, 40, 45, 59, 62, 70, 77]));
        assert!(!j["supported_nips"].as_array().unwrap().contains(&serde_json::json!(42)));
        let l = &j["limitation"];
        assert_eq!(l["max_message_length"], 262_144);
        assert_eq!(l["max_subscriptions"], 200);
        assert_eq!(l["max_limit"], 5000);
        assert_eq!(l["default_limit"], 500);
        assert_eq!(l["max_event_tags"], 2000);
        assert_eq!(l["auth_required"], false);
        assert_eq!(l["restricted_writes"], true);
        assert!(l.get("max_content_length").is_none() && l.get("created_at_upper_limit").is_none());
        for absent in ["pubkey", "contact", "icon", "banner", "privacy_addresses", "privacy_policy", "terms_of_service"] {
            assert!(j.get(absent).is_none(), "{absent} should be omitted when empty");
        }
    }

    #[test]
    fn nip11_reflects_settings() {
        let pk = "cd".repeat(32);
        let c = ok(&format!(
            "[info]\nname = \"N\"\npubkey = \"{pk}\"\ncontact = \"mailto:a@b.c\"\nicon = \"https://i\"\nbanner = \"https://b\"\n\
             privacy_policy = \"https://p\"\nterms_of_service = \"https://t\"\nprivacy_addresses = [\"ws://x.onion\", \"wss://y.b32.i2p\"]\n\
             [policy]\nkinds = \"all\"\nmax_tags = 77\n[limits]\nmax_limit = 600\nmax_subscriptions = 9\n"
        ));
        let j = nip11(&c);
        assert_eq!(j["name"], "N");
        assert_eq!(j["pubkey"], pk.as_str());
        assert_eq!(j["contact"], "mailto:a@b.c");
        assert_eq!(j["icon"], "https://i");
        assert_eq!(j["banner"], "https://b");
        assert_eq!(j["privacy_policy"], "https://p");
        assert_eq!(j["terms_of_service"], "https://t");
        assert_eq!(j["privacy_addresses"], serde_json::json!(["ws://x.onion", "wss://y.b32.i2p"]));
        assert_eq!(j["limitation"]["restricted_writes"], false);
        assert_eq!(j["limitation"]["max_event_tags"], 77);
        assert_eq!(j["limitation"]["max_limit"], 600);
        assert_eq!(j["limitation"]["max_subscriptions"], 9);
    }

    #[test]
    fn nip11_escapes_operator_text() {
        let nasty = "quote \" backslash \\ newline \n tab \t bell \u{7} caf\u{e9} \u{1f600} </script>";
        let mut c = Config::default();
        c.info.name = nasty.to_string();
        c.info.description = nasty.to_string();
        c.info.contact = nasty.to_string();
        c.info.privacy_addresses = vec![format!("ws://{nasty}")];
        let j = nip11(&c);
        assert_eq!(j["name"], nasty);
        assert_eq!(j["description"], nasty);
        assert_eq!(j["contact"], nasty);
        assert_eq!(j["privacy_addresses"][0], format!("ws://{nasty}").as_str());
        // One line, so it can go straight into an HTTP body.
        assert!(!c.nip11_json().contains('\n'));
    }

    // ----- loading -----

    fn temp_file(tag: &str, bytes: &[u8]) -> PathBuf {
        let p = std::env::temp_dir().join(format!("{}-config-test-{}-{tag}.toml", brand::SLUG, std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn load_reads_a_named_file() {
        let p = temp_file("named", b"[limits]\nmax_filters = 7\n");
        let c = Config::load(Some(&p)).unwrap();
        assert_eq!(c.limits.max_filters, 7);
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn load_errors_name_the_file_and_line() {
        let p = temp_file("bad", b"[relay]\n\nbnid = 1\n");
        let e = Config::load(Some(&p)).unwrap_err();
        assert_eq!(e.line, Some(3));
        let text = e.to_string();
        assert!(text.starts_with(&format!("{} line 3: ", p.display())), "{text}");
        assert!(text.contains("did you mean `bind`?"), "{text}");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn load_missing_files() {
        let missing = std::env::temp_dir().join(format!("{}-no-such-{}.toml", brand::SLUG, std::process::id()));
        let e = Config::load(Some(&missing)).unwrap_err();
        assert!(e.msg.contains("file not found") && e.msg.contains(" init "), "{e}");
        // The implicit file may be absent; that is the zero-config case.
        assert_eq!(Config::load_file(&missing, true).unwrap(), Config::default());
        // But an unreadable one is an error either way.
        let dir = std::env::temp_dir();
        assert!(Config::load_file(&dir, true).is_err());
    }

    #[test]
    fn load_rejects_non_utf8_with_a_line() {
        let p = temp_file("latin1", b"[info]\nname = \"caf\xe9\"\n");
        let e = Config::load(Some(&p)).unwrap_err();
        assert_eq!(e.line, Some(2));
        assert!(e.msg.contains("UTF-8"), "{e}");
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn load_accepts_a_byte_order_mark_and_crlf() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"[limits]\r\nmax_filters = 3\r\n");
        let p = temp_file("bom", &bytes);
        assert_eq!(Config::load(Some(&p)).unwrap().limits.max_filters, 3);
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn error_display_forms() {
        let e = ConfigError { file: Some("a.toml".into()), line: Some(3), msg: "m".into() };
        assert_eq!(e.to_string(), "a.toml line 3: m");
        assert_eq!(ConfigError { line: None, ..e.clone() }.to_string(), "a.toml: m");
        assert_eq!(ConfigError { file: None, ..e.clone() }.to_string(), "line 3: m");
        assert_eq!(ConfigError { file: None, line: None, msg: "m".into() }.to_string(), "m");
    }
}
