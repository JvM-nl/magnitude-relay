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
use relay_proto::Filter;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// The file looked for when no `--config` is given.
pub const DEFAULT_FILE: &str = "relay.toml";

/// Event kinds the relay accepts out of the box: exactly what Vector produces
/// and reads, per the kinds table in docs/DESIGN.md. Public notes are not on the list.
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
    // Concord events from before seals, published bare: today's Concord sends
    // these kinds only inside gift wraps, and 3300, 3301, 3304, 3305, 3307 and
    // 3311 are retired outright. Still accepted and stored until November 2026,
    // then removed (owner's call, 2026-10-21); production strfry holds 43k.
    3300, 3301, 3302, 3303, 3304, 3305, 3306, 3307, 3308, 3309, 3310, 3311, 3314,
    // Relay list.
    10002,
    // Profile badges (NIP-58): the awards a person shows.
    10008,
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
    // NIP-46 remote signing (Nostr Connect), for bunker accounts: Vector's
    // nostrconnect:// session runs over its trusted relays, this one first,
    // and the signer app answers there. Ephemeral: relayed, never stored.
    24133,
    // Push request.
    24590,
    // Device transfer.
    24681,
    // Badge set (NIP-58), and profile badges in the form before 10008, which
    // clients still read.
    30008,
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

/// NIPs the relay speaks, as published in NIP-11: the protocol ones (1, 9, 11,
/// 40, 45, 62, 70, 77) and one for each kind of VECTOR_KINDS a NIP defines:
/// 17 (DM inbox relays, 10050) and 59 (gift wraps), 24 (profile fields), 46
/// (remote signing, 24133), 30
/// (emoji lists and sets, 10030/30030), 38 (user status), 58 (badges: 8,
/// 10008, 30008, 30009), 65 (relay lists), 78 (app data). Not 51: of its list kinds only the
/// emoji ones are taken. Not 42: this relay never authenticates anyone
/// (docs/DESIGN.md, Decisions). Blossom server lists (10063) are NIP-B7, which a list
/// of numbers cannot name.
pub const SUPPORTED_NIPS: &[u32] = &[1, 9, 11, 17, 24, 30, 38, 40, 45, 46, 58, 59, 62, 65, 70, 77, 78];

/// Every section and its keys. The single source for "did you mean" hints and
/// for the test that keeps the documented default file complete.
const KEYS: &[(&str, &[&str])] = &[
    ("relay", &["bind", "unix_socket", "unix_socket_mode", "threads", "real_ip_header", "urls", "compression"]),
    (
        "info",
        &["name", "description", "pubkey", "contact", "icon", "banner", "privacy_policy", "terms_of_service", "privacy_addresses"],
    ),
    ("policy", &["kinds", "allow_kinds", "deny_kinds", "max_event_bytes", "max_future_seconds", "max_tags", "banlist"]),
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
            "connections_per_minute_per_ip",
            "connection_burst_per_ip",
            "outbound_buffer_bytes",
        ],
    ),
    ("store", &["data", "sync", "segment_mb", "memory_mb"]),
    ("tls", &["enabled", "domains", "email", "https_bind", "http_bind", "cert", "key", "staging", "directory"]),
    ("sync", &["url", "name", "filter", "direction", "reconcile_seconds", "full_reconcile_seconds", "recent_seconds", "trusted"]),
    ("peer", &["name", "secret", "ips"]),
];

/// Sections written `[[name]]`: there may be any number of each.
const LISTS: &[&str] = &["sync", "peer"];

/// Builds the error for a rule that relates settings, blaming the first of `keys` the file wrote.
type Blame<'a> = dyn Fn(&[(&str, &str)], String) -> ConfigError + 'a;

/// Let's Encrypt's production ACME directory, the default certificate authority.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt's test directory: the same protocol, untrusted certificates, generous limits.
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub relay: RelayCfg,
    pub info: InfoCfg,
    pub policy: PolicyCfg,
    pub limits: LimitsCfg,
    pub store: StoreCfg,
    pub tls: TlsCfg,
    /// One per `[[sync]]` block, in file order.
    pub sync: Vec<SyncCfg>,
    /// One per `[[peer]]` block.
    pub peers: Vec<PeerCfg>,
}

/// `[[peer]]`: another relay of ours, trusted with everything this one holds
/// (gift wraps listed like any event) and to have checked the signatures of
/// events it took from clients itself. Recognised by its private path and its
/// address together.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerCfg {
    /// For people reading the file and the logs.
    pub name: String,
    /// It connects to `/peer/<secret>`.
    pub secret: String,
    /// The addresses it connects from (as `real_ip_header` names them, behind
    /// a web server).
    pub ips: Vec<std::net::IpAddr>,
}

/// `[relay]`: where and how to listen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCfg {
    pub bind: SocketAddr,
    /// A Unix socket to listen on as well, for a web server on the same
    /// machine; empty for none.
    pub unix_socket: String,
    /// Its permission bits.
    pub unix_socket_mode: u32,
    /// 0 = one reactor per hardware thread.
    pub threads: usize,
    /// Lowercase header naming the real client address, or empty to trust the
    /// socket peer. Only safe when the relay is reachable solely through the
    /// proxy that sets it: otherwise any client can forge it and sidestep every
    /// per-IP limit.
    pub real_ip_header: String,
    /// This relay's public addresses; NIP-62 vanish requests naming one are honoured.
    pub urls: Vec<String>,
    /// permessage-deflate for clients that offer it.
    pub compression: Compression,
}

/// How WebSocket messages are compressed (RFC 7692) for clients that ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    Off,
    /// Every message on its own, both ways: no codec memory per connection.
    Stateless,
    /// History carried across messages: better ratio, up to ~80 KB per connection.
    Full,
}

impl RelayCfg {
    /// What the handshake accepts.
    pub fn deflate_policy(&self) -> Option<relay_net::ws::DeflatePolicy> {
        use relay_net::ws::DeflatePolicy;
        match self.compression {
            Compression::Off => None,
            Compression::Stateless => {
                Some(DeflatePolicy { server_no_context_takeover: true, client_no_context_takeover: true, ..DeflatePolicy::default() })
            }
            Compression::Full => Some(DeflatePolicy::default()),
        }
    }
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
    /// A file of banned public keys (see `bans`). Empty means none.
    pub banlist: String,
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
    /// New connections per minute from one address, after a first burst of
    /// `connection_burst_per_ip`. 0 = unlimited.
    pub connections_per_minute_per_ip: u32,
    pub connection_burst_per_ip: u32,
    pub outbound_buffer_bytes: usize,
}

/// `[store]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreCfg {
    pub data: PathBuf,
    pub sync: bool,
    pub segment_mb: u32,
    /// Memory recent index entries may use before they are written to disk.
    pub memory_mb: u32,
}

/// `[tls]`: HTTPS served by the relay itself. Off by default; the relay then speaks
/// plain `ws://` on `[relay] bind`, for a web server in front of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCfg {
    pub enabled: bool,
    /// The certificate's names; empty means the hosts of `[relay] urls`.
    pub domains: Vec<String>,
    /// ACME contact, or empty.
    pub email: String,
    pub https_bind: SocketAddr,
    /// HTTP-01 challenges and the redirect to HTTPS; `None` is no plain-HTTP port.
    pub http_bind: Option<SocketAddr>,
    /// A certificate chain in PEM, or empty to get one from a CA. Both or neither of
    /// `cert` and `key`.
    pub cert: String,
    pub key: String,
    pub staging: bool,
    /// The ACME directory URL, or empty for Let's Encrypt.
    pub directory: String,
}

impl Default for TlsCfg {
    fn default() -> Self {
        TlsCfg {
            enabled: false,
            domains: Vec::new(),
            email: String::new(),
            https_bind: SocketAddr::from(([0, 0, 0, 0], 443)),
            http_bind: Some(SocketAddr::from(([0, 0, 0, 0], 80))),
            cert: String::new(),
            key: String::new(),
            staging: false,
            directory: String::new(),
        }
    }
}

impl TlsCfg {
    /// The ACME directory to ask for certificates.
    pub fn directory_url(&self) -> &str {
        match (self.directory.as_str(), self.staging) {
            ("", false) => LETS_ENCRYPT,
            ("", true) => LETS_ENCRYPT_STAGING,
            (d, _) => d,
        }
    }

    /// Whether the certificate comes from files instead of a CA.
    pub fn uses_files(&self) -> bool {
        !self.cert.is_empty()
    }

    /// The names to get a certificate for: `domains`, or else the hosts of the relay's
    /// public `urls` that a certificate could name (an `.onion` twin or an IP address
    /// in `urls` has none to get).
    pub fn names(&self, relay_urls: &[String]) -> Vec<String> {
        if !self.domains.is_empty() {
            return self.domains.clone();
        }
        let mut out: Vec<String> = Vec::new();
        for url in relay_urls {
            let rest = url.strip_prefix("wss://").or_else(|| url.strip_prefix("ws://")).unwrap_or(url);
            let authority = rest.split(['/', '?']).next().unwrap_or("");
            let host = authority.rsplit_once(':').filter(|(_, port)| port.bytes().all(|b| b.is_ascii_digit())).map_or(authority, |(h, _)| h);
            if let Ok(name) = valid_domain(host) {
                if !out.contains(&name) {
                    out.push(name);
                }
            }
        }
        out
    }
}

/// `[[sync]]`: another relay to copy events from or to, and keep in step with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCfg {
    /// What the dashboard calls the other relay; its host when not set.
    pub name: String,
    /// `ws://` or `wss://`.
    pub url: String,
    /// The events to sync: one filter, or several (their union). `{}` is everything.
    pub filters: Vec<Filter>,
    pub direction: Direction,
    /// Between two comparisons new events stream live; the comparison catches
    /// whatever the stream missed (a disconnect, a restart).
    pub reconcile_seconds: u64,
    /// How often a comparison covers every event. The others cover events
    /// dated in the last `recent_seconds` (0: every comparison is full).
    pub full_reconcile_seconds: u64,
    pub recent_seconds: u64,
    /// The other relay is one of ours ([[peer]] there): the signatures of
    /// events it took from clients itself are not checked again here.
    pub trusted: bool,
}

/// Which way a sync copies events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Theirs to us.
    Down,
    /// Ours to them.
    Up,
    Both,
}

impl Direction {
    pub const NAMES: [&'static str; 3] = ["down", "up", "both"];

    pub fn parse(s: &str) -> Option<Direction> {
        match s {
            "down" => Some(Direction::Down),
            "up" => Some(Direction::Up),
            "both" => Some(Direction::Both),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Direction::Down => "down",
            Direction::Up => "up",
            Direction::Both => "both",
        }
    }

    pub fn down(self) -> bool {
        matches!(self, Direction::Down | Direction::Both)
    }

    pub fn up(self) -> bool {
        matches!(self, Direction::Up | Direction::Both)
    }
}

impl Default for SyncCfg {
    /// Everything, theirs to us, compared hourly. No url: one must be given.
    fn default() -> Self {
        SyncCfg {
            name: String::new(),
            url: String::new(),
            filters: vec![Filter::default()],
            direction: Direction::Down,
            reconcile_seconds: 3600,
            full_reconcile_seconds: 86_400,
            recent_seconds: 3 * 86_400,
            trusted: false,
        }
    }
}

impl Default for RelayCfg {
    fn default() -> Self {
        // 7777 is strfry's port, so an existing nginx upstream keeps working.
        RelayCfg {
            bind: SocketAddr::from(([127, 0, 0, 1], 7777)),
            unix_socket: String::new(),
            unix_socket_mode: 0o666,
            threads: 0,
            real_ip_header: String::new(),
            urls: Vec::new(),
            compression: Compression::Stateless,
        }
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
            banlist: String::new(),
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
            max_connections_per_ip: 256,
            events_per_minute_per_ip: 1200,
            connections_per_minute_per_ip: 60,
            connection_burst_per_ip: 300,
            outbound_buffer_bytes: 33_554_432,
        }
    }
}

impl Default for StoreCfg {
    fn default() -> Self {
        StoreCfg { data: PathBuf::from("./data"), sync: true, segment_mb: 1024, memory_mb: 64 }
    }
}

impl StoreCfg {
    /// The storage engine's options for this section.
    pub fn options(&self) -> relay_store::Options {
        relay_store::Options {
            segment_size: u64::from(self.segment_mb) << 20,
            sync: self.sync,
            flush_bytes: (self.memory_mb as usize) << 20,
            vanish_urls: Vec::new(),
            ..relay_store::Options::default()
        }
    }
}

/// Store options from the whole config (the store also needs the relay's URLs).
pub fn store_options(cfg: &Config) -> relay_store::Options {
    relay_store::Options { vanish_urls: cfg.relay.urls.clone(), ..cfg.store.options() }
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
            KindBase::Vector => {
                // Every ephemeral kind too (owner's call, 2026-10-22): relayed
                // live and never stored, so they cost no disk, and clients'
                // live protocols (Nostr Connect signers, device transfer and
                // the like) work here whatever their kind number.
                for k in 20_000..30_000u64 {
                    bits[(k >> 6) as usize] |= 1 << (k & 63);
                }
                VECTOR_KINDS
            }
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
            let list = LISTS.contains(&sec.name.as_str());
            if sec.array && !list {
                return Err(ConfigError::at(sec.line, format!("write [{0}] with single brackets: there is only one [{0}] section", sec.name)));
            }
            if list && !sec.array {
                return Err(ConfigError::at(sec.line, format!("write [[{0}]] with double brackets: there can be one for each relay", sec.name)));
            }
            let mut sync = SyncCfg::default();
            let mut peer = PeerCfg::default();
            for e in &sec.entries {
                let applied = match sec.name.as_str() {
                    "relay" => apply_relay(&mut cfg.relay, e),
                    "info" => apply_info(&mut cfg.info, e),
                    "policy" => apply_policy(&mut cfg.policy, e),
                    "limits" => apply_limits(&mut cfg.limits, e),
                    "store" => apply_store(&mut cfg.store, e),
                    "tls" => apply_tls(&mut cfg.tls, e),
                    "sync" => apply_sync(&mut sync, e),
                    "peer" => apply_peer(&mut peer, e),
                    _ => Ok(false),
                };
                match applied {
                    Ok(true) => {}
                    Ok(false) => return Err(ConfigError::at(e.line, unknown_key(&sec.name, &e.key))),
                    Err(msg) => return Err(ConfigError::at(e.line, msg)),
                }
            }
            if sec.name == "sync" {
                if sync.url.is_empty() {
                    return Err(ConfigError::at(sec.line, "this [[sync]] has no url: name the relay, like url = \"wss://relay.example.com\""));
                }
                cfg.sync.push(sync);
            }
            if sec.name == "peer" {
                if peer.secret.is_empty() || peer.ips.is_empty() {
                    return Err(ConfigError::at(sec.line, "this [[peer]] needs both a secret and its ips: the relay trusts a peer only on its private path from one of its addresses"));
                }
                if cfg.peers.iter().any(|p| p.secret == peer.secret) {
                    return Err(ConfigError::at(sec.line, "two [[peer]] blocks have the same secret: give each its own"));
                }
                cfg.peers.push(peer);
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
        self.check_tls(&blame)
    }

    /// The `[tls]` rules: a certificate and its key come as a pair, settings that only
    /// matter when asking a CA are not given alongside files, and what is enabled
    /// has addresses to listen on and names to be certified for.
    fn check_tls(&self, blame: &Blame<'_>) -> Result<(), ConfigError> {
        let t = &self.tls;
        if t.cert.is_empty() != t.key.is_empty() {
            let (set, missing) = if t.cert.is_empty() { ("key", "cert") } else { ("cert", "key") };
            return Err(blame(&[("tls", set)], format!("`{set}` is set but `{missing}` is not: a certificate and its private key go together (leave both empty to get a certificate automatically)")));
        }
        if t.staging && !t.directory.is_empty() {
            return Err(blame(&[("tls", "staging"), ("tls", "directory")], "`staging` and `directory` both choose the certificate authority: set one of them".to_string()));
        }
        if t.uses_files() {
            for (key, given) in [("email", !t.email.is_empty()), ("staging", t.staging), ("directory", !t.directory.is_empty())] {
                if given {
                    return Err(blame(&[("tls", key)], format!("`{key}` has no effect with `cert` and `key` set: the relay is not asking a certificate authority for anything then")));
                }
            }
        }
        if !t.enabled {
            return Ok(());
        }
        let others = [("[relay] bind", Some(self.relay.bind), ("relay", "bind")), ("[tls] http_bind", t.http_bind, ("tls", "http_bind"))];
        for (what, addr, at) in others {
            if addr == Some(t.https_bind) {
                return Err(blame(&[("tls", "https_bind"), at], format!("[tls] https_bind and {what} are both {}: two listeners cannot share an address", t.https_bind)));
            }
        }
        if t.http_bind == Some(self.relay.bind) {
            return Err(blame(&[("tls", "http_bind"), ("relay", "bind")], format!("[tls] http_bind and [relay] bind are both {}: two listeners cannot share an address", self.relay.bind)));
        }
        if !t.uses_files() && t.names(&self.relay.urls).is_empty() {
            return Err(blame(
                &[("tls", "enabled"), ("tls", "domains")],
                "[tls] has no names to get a certificate for: list them in `domains`, or give the relay's address in [relay] urls, like \"wss://relay.example.com\"".to_string(),
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

/// `s` as a JSON string literal, quotes included.
pub fn json_str(s: &str) -> String {
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

/// An address to listen on, with the usual slips explained. `port` is the one the
/// examples show.
fn bind_addr(key: &str, s: &str, port: u16) -> Result<SocketAddr, String> {
    s.parse().map_err(|_| {
        if s.contains(':') {
            format!("`{key}` is not an address and port: \"{s}\". Use an IP address and port, like \"127.0.0.1:{port}\", \"0.0.0.0:{port}\" or \"[::]:{port}\" (host names such as localhost are not accepted)")
        } else {
            format!("`{key}` needs a port as well as an address: write \"{s}:{port}\"")
        }
    })
}

fn apply_relay(c: &mut RelayCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "bind" => c.bind = bind_addr("bind", string(e)?, 7777)?,
        "unix_socket" => c.unix_socket = string(e)?.to_string(),
        "unix_socket_mode" => {
            let s = string(e)?;
            c.unix_socket_mode = u32::from_str_radix(s, 8)
                .ok()
                .filter(|m| !s.is_empty() && *m <= 0o777)
                .ok_or_else(|| format!("`unix_socket_mode` is permission bits in octal, like \"666\" or \"660\", not \"{s}\""))?;
        }
        "threads" => c.threads = int(e, 0, 1024)? as usize,
        "compression" => {
            c.compression = match string(e)? {
                "stateless" => Compression::Stateless,
                "full" => Compression::Full,
                "off" => Compression::Off,
                other => return Err(format!("`compression` is \"stateless\", \"full\" or \"off\", not \"{other}\"")),
            }
        }
        "real_ip_header" => {
            let s = string(e)?;
            let token = |b: u8| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b);
            if !s.bytes().all(token) {
                return Err(format!("`real_ip_header` must be an HTTP header name like \"x-forwarded-for\" or \"x-real-ip\", not \"{s}\""));
            }
            // Header names are case-insensitive; compare them in one case.
            c.real_ip_header = s.to_ascii_lowercase();
        }
        "urls" => {
            let list = strings(e)?;
            for a in list {
                let host = a.strip_prefix("wss://").or_else(|| a.strip_prefix("ws://"));
                if host.is_none_or(str::is_empty) {
                    return Err(format!("`urls` entries must be websocket URLs starting with ws:// or wss://, but \"{a}\" is not"));
                }
            }
            c.urls = list.to_vec();
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
        "banlist" => c.banlist = path_setting(e)?,
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
        "connections_per_minute_per_ip" => c.connections_per_minute_per_ip = int(e, 0, 10_000_000)? as u32,
        "connection_burst_per_ip" => c.connection_burst_per_ip = int(e, 1, 10_000_000)? as u32,
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
        "memory_mb" => c.memory_mb = int(e, 1, 65536)? as u32,
        _ => return Ok(false),
    }
    Ok(true)
}

/// A certificate name as `domains` takes it, lowercased, or why it will not do.
fn valid_domain(raw: &str) -> Result<String, String> {
    let d = raw.to_ascii_lowercase();
    if d.is_empty() {
        return Err("is empty".to_string());
    }
    if d.starts_with("*.") {
        return Err("is a wildcard, which needs DNS-based proof of ownership the relay does not do; list each name instead".to_string());
    }
    if d.parse::<std::net::IpAddr>().is_ok() || d.starts_with('[') {
        return Err("is an IP address, but certificates are issued for names such as relay.example.com".to_string());
    }
    if !d.is_ascii() {
        return Err("has characters outside a-z, 0-9 and \"-\"; write international names in their ASCII (xn--) form".to_string());
    }
    if d.ends_with('.') {
        return Err("ends with a dot; leave the last dot off".to_string());
    }
    if d.len() > 253 {
        return Err("is longer than a host name can be".to_string());
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return Err("is not a full name; write it like relay.example.com".to_string());
    }
    for l in &labels {
        let ok = (1..=63).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !l.starts_with('-') && !l.ends_with('-');
        if !ok {
            return Err(format!("has an invalid part \"{l}\": parts are 1 to 63 letters, digits or \"-\", and do not start or end with \"-\""));
        }
    }
    if labels.last().is_some_and(|t| t.bytes().all(|b| b.is_ascii_digit())) {
        return Err("does not end in a top-level domain such as .com".to_string());
    }
    if [".onion", ".i2p", ".local", ".localhost"].iter().any(|private| d.ends_with(private)) {
        return Err("is a private-network name that no public certificate authority will certify".to_string());
    }
    Ok(d)
}

/// An ACME contact address, as far as can be told without sending mail to it.
fn valid_email(s: &str) -> Result<(), String> {
    let bad_char = |b: u8| b <= b' ' || b >= 0x7F || b"<>,;:?#%\"\\".contains(&b);
    match s.split_once('@') {
        Some((local, host)) if !local.is_empty() && host.contains('.') && !host.contains('@') && !host.starts_with('.') && !host.ends_with('.') && !s.bytes().any(bad_char) => Ok(()),
        _ => Err(format!("`email` should be an address like admin@example.com, but this is \"{s}\"")),
    }
}

/// The text of a path setting. Empty is allowed: it means "not set".
fn path_setting(e: &Entry) -> Result<String, String> {
    let s = string(e)?;
    if s.chars().any(char::is_control) {
        return Err(format!("`{}` contains a control character such as a tab or line break. In a Windows path, double each backslash (\"C:\\\\certs\\\\chain.pem\") or use 'single quotes' (nothing inside them is escaped)", e.key));
    }
    Ok(s.to_string())
}

/// A certificate authority's directory address: https, or http for a CA on this machine.
fn valid_directory(s: &str) -> Result<(), String> {
    let url = relay_tls::http::Url::parse(s).map_err(|_| format!("`directory` must be an https:// address, but this is \"{s}\""))?;
    if !url.tls && !matches!(url.host.as_str(), "localhost" | "127.0.0.1" | "::1") {
        return Err(format!("`directory` \"{s}\" is plain http, which is only accepted for a certificate authority on this computer (localhost); use https://"));
    }
    Ok(())
}

fn apply_tls(c: &mut TlsCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "enabled" => c.enabled = boolean(e)?,
        "domains" => {
            let mut names: Vec<String> = Vec::new();
            for d in strings(e)? {
                let name = valid_domain(d).map_err(|why| format!("`domains` entry \"{d}\" {why}"))?;
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            c.domains = names;
        }
        "email" => {
            let s = string(e)?;
            if !s.is_empty() {
                valid_email(s)?;
            }
            c.email = s.to_string();
        }
        "https_bind" => c.https_bind = bind_addr("https_bind", string(e)?, 443)?,
        "http_bind" => {
            let s = string(e)?;
            c.http_bind = if s.is_empty() { None } else { Some(bind_addr("http_bind", s, 80)?) };
        }
        "cert" => c.cert = path_setting(e)?,
        "key" => c.key = path_setting(e)?,
        "staging" => c.staging = boolean(e)?,
        "directory" => {
            let s = string(e)?;
            if !s.is_empty() {
                valid_directory(s)?;
            }
            c.directory = s.to_string();
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn apply_sync(c: &mut SyncCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "url" => {
            let s = string(e)?;
            relay_net::connector::RelayUrl::parse(s)?;
            c.url = s.to_string();
        }
        "filter" => {
            c.filters = crate::operator::parse_filters(string(e)?).map_err(|why| {
                format!("`filter` must be a Nostr filter in JSON, like '{{\"kinds\":[0]}}' (in single quotes), or a list of them: {why}")
            })?;
        }
        "direction" => {
            let s = string(e)?;
            c.direction = Direction::parse(s).ok_or_else(|| {
                let hint = suggest(s, &Direction::NAMES).map(|d| format!(" (did you mean \"{d}\"?)")).unwrap_or_default();
                format!("`direction` is \"down\" (theirs to us), \"up\" (ours to them) or \"both\", not \"{s}\"{hint}")
            })?;
        }
        "name" => c.name = string(e)?.to_string(),
        "reconcile_seconds" => c.reconcile_seconds = int(e, 1, 30 * 86_400)?,
        "full_reconcile_seconds" => c.full_reconcile_seconds = int(e, 1, 365 * 86_400)?,
        "recent_seconds" => c.recent_seconds = int(e, 0, 365 * 86_400)?,
        "trusted" => c.trusted = boolean(e)?,
        _ => return Ok(false),
    }
    Ok(true)
}

fn apply_peer(c: &mut PeerCfg, e: &Entry) -> Result<bool, String> {
    match e.key.as_str() {
        "name" => c.name = string(e)?.to_string(),
        "secret" => {
            let s = string(e)?;
            if s.len() < 32 || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return Err("`secret` must be at least 32 letters, digits, '-' or '_' (for example from `openssl rand -hex 24`)".into());
            }
            c.secret = s.to_string();
        }
        "ips" => {
            c.ips = strings(e)?
                .iter()
                .map(|s| s.parse::<std::net::IpAddr>().map(|ip| ip.to_canonical()).map_err(|_| format!("`ips` takes IP addresses like \"203.0.113.7\" or \"2001:db8::7\", not \"{s}\"")))
                .collect::<Result<_, _>>()?;
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

# A Unix socket to listen on as well, like "/run/relay/relay.sock": a web server
# on the same computer reaches the relay through it more cheaply than over
# 127.0.0.1 (nginx: proxy_pass http://unix:/run/relay/relay.sock;). Its
# directory must exist. Empty means none.
# unix_socket = ""

# Who may connect to that socket, as permission bits: "666" lets every local
# user, as 127.0.0.1 does; "660" only the socket's owner and group (put the web
# server's user in the relay's group).
# unix_socket_mode = "666"

# Worker threads. 0 means one per hardware thread, which is almost always right.
# threads = 0

# Behind a web server every connection arrives from that server, so per-IP limits
# would count all your users as one. Name the header your web server fills in with
# the real address ("x-forwarded-for" or "x-real-ip") and the relay uses it.
# ONLY set this if the relay can be reached solely through that web server:
# anyone who can connect directly could forge the header and dodge every
# per-IP limit. Empty means use the connecting address.
# real_ip_header = ""

# The addresses people use to reach this relay, like "wss://relay.example.com".
# A user's request to vanish (NIP-62) is honoured when it names one of these or
# says ALL_RELAYS: everything they published here is then deleted for good.
# urls = []

# Compression of messages for apps that ask for it (browsers do). One of:
#   "stateless"  each message compressed on its own: no extra memory per connection
#   "full"       compressed with what came before: smaller, but up to about
#                80 KB of memory for every connection that uses it
#   "off"        never compress
# compression = "stateless"

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

# A file of public keys banned from this relay, like "/etc/relay/banlist.txt":
# one npub or 64-character hex key per line, # starts a comment. The relay reads
# it again within seconds of any change, no restart needed; a line it cannot
# read leaves the list as it was. A banned key's events, and gift wraps
# addressed to it, are answered OK and dropped, and the key is left out of every
# filter: its owner sees an ordinary relay with nothing in it, everyone else
# sees no such key. Without AUTH that is as far as a ban can reach: gift wraps
# it sends are signed by one-time keys, and Concord by shared plane keys.
# Removing what the key already stored is a separate step (`delete`).
# Empty means no banlist.
# banlist = ""

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
# 0 turns a limit off. Loopback addresses have no limit: they are services on
# this machine, or everyone who arrives through Tor or I2P (cap those in the
# web server or the onion service instead). 256 connections leaves room for
# many phones behind one carrier address.
# max_connections_per_ip = 256
# events_per_minute_per_ip = 1200

# New connections per minute from one address, after a first burst of
# connection_burst_per_ip. Past that, the relay answers 429 with Retry-After
# before the WebSocket opens, which clients treat as a failed connection and
# back off from. It catches floods: an address opening more than a connection a
# second for minutes on end. The burst is generous because Vector opens a
# connection per Concord plane while it backfills Communities (up to 24 at
# once, replaced as it moves on), and a household or carrier address carries
# several clients. Loopback has no limit, as above. 0 turns it off.
# connections_per_minute_per_ip = 60
# connection_burst_per_ip = 300

# Memory one connection may use for messages waiting to be sent. A client that
# reads too slowly to stay under this is disconnected, and a REQ whose stored
# events add up to more ends with CLOSED (ask for fewer at a time). At least
# max_message_bytes.
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

# Memory (MiB) the newest index entries may use before they are written to disk.
# The relay never needs the whole database in memory; spare RAM simply becomes
# cache. Lower this on a very small machine, raise it on a busy one.
# memory_mb = 64

[tls]
# HTTPS (wss://) served by the relay itself, with a free certificate from Let's
# Encrypt that it gets and renews on its own, so nothing has to sit in front of it.
# Off by default: the relay then speaks plain ws:// on the [relay] bind address,
# meant for a web server such as nginx or Caddy to put HTTPS in front of.
#
# Before turning it on: the names (below) must already point at this computer, and
# the internet must be able to reach it on port 443 and, for the redirect and as a
# second way to prove the names are yours, on port 80. Ports below 1024 need the
# program to run as root, or on Linux to hold the CAP_NET_BIND_SERVICE capability.
#
# Turning it on means you accept the certificate authority's terms of service (for
# Let's Encrypt: https://letsencrypt.org/repository/). The relay prints the address
# the first time it asks. The plain [relay] bind keeps listening as well, so one
# relay can serve both; keep that address on 127.0.0.1 to face only this computer.
# enabled = false

# The names the certificate is for, like ["relay.example.com"]. Empty means the host
# names in [relay] urls. Names only: no IP addresses, no wildcards (*.example.com).
# domains = []

# An address Let's Encrypt can write to when something needs attention. Optional.
# email = ""

# Where to listen for HTTPS, and for plain HTTP on port 80. Port 80 answers the
# certificate authority's checks and sends everyone else to the https:// address.
# "" turns port 80 off; the check on port 443 can still prove the names are yours.
# https_bind = "0.0.0.0:443"
# http_bind = "0.0.0.0:80"

# A certificate and private key of your own, as PEM files (certbot's fullchain.pem
# and privkey.pem, for example). With both set the relay asks no authority for
# anything: it serves these, and picks up new files within a minute of them
# changing, so renewing them needs no restart.
# cert = ""
# key = ""

# true: use Let's Encrypt's test service, to try this out. Apps will not trust its
# certificates, but its limits are generous, so mistakes cost nothing.
# staging = false

# Another ACME certificate authority, as its directory address (an https:// URL).
# Empty means Let's Encrypt.
# directory = ""

# Other relays to copy events from, or to, and keep in step with: one block
# like the one below for each. Nothing is synced unless you add one. The two
# relays first compare what they hold (NIP-77: only the differences travel),
# then new events stream live, and the comparison runs again every
# reconcile_seconds to catch anything the stream missed. Events copied in are
# checked like any app's: signatures, the kinds accepted here, deletions.
# Ephemeral events travel only live, and events expiring within 10 minutes are
# left out of comparisons (and of the catch-up after a dropped stream): they
# would be gone, or nearly, by the time they landed.
#
# [[sync]]
# url = "wss://relay.example.com"

# What the dashboard calls the other relay ("Vector Asia Relay is syncing with
# ..."). Its host when not set.
# name = "relay.example.com"

# Which events: a Nostr filter in JSON, or a list of filters. Put JSON in
# 'single quotes' so its own quotes need no backslashes, as in
# '{"kinds":[0,10002]}'. The default, "{}", means every event.
# filter = "{}"

# "down" copies their events here, "up" copies ours to them, "both" does both.
# direction = "down"

# Seconds between comparisons. New events arrive live in between.
# reconcile_seconds = 3600

# A comparison of every event runs at start and every full_reconcile_seconds;
# the others compare only events dated within the last recent_seconds, which
# is what a stream that dropped can have missed (Vector backdates messages by
# up to two days). A large store compares in a fraction of the time. 0 for
# recent_seconds makes every comparison full.
# full_reconcile_seconds = 86400
# recent_seconds = 259200

# true when the other relay is one of yours and lists this one as a [[peer]]
# (the url is then its private peer address, wss://host/peer/<secret>): events
# it took from apps itself arrive with their signatures already checked, and
# are not checked again. Everything else is, and every other rule applies.
# trusted = false

# Your own relays that copy everything from this one ([[sync]] with trusted =
# true on theirs): one block for each. Such a relay is sent gift wraps like any
# other event, and events this relay took from apps itself carry a mark that
# their signatures were checked here. It is recognised by its private address,
# wss://this-relay/peer/<secret>, AND the address it connects from; both, or
# it is an ordinary client (and a wrong secret is turned away). Behind a web
# server set real_ip_header, and pass /peer/ on to the relay.
#
# The name is what the dashboard shows while the peer syncs with this relay.
#
# [[peer]]
# name = "eu-2"
# secret = "replace-with-your-own-secret-from-openssl-rand"  # `openssl rand -hex 24`
# ips = ["203.0.113.7"]
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
        assert_eq!((l.max_connections_per_ip, l.events_per_minute_per_ip, l.outbound_buffer_bytes), (256, 1200, 33_554_432));
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
        // file is a key the parser accepts. A list section's header is commented
        // out too (there are none by default); uncommented, its block is one
        // entry holding the example url and every other default.
        let mut seen: Vec<String> = Vec::new();
        let uncommented: String = text
            .lines()
            .map(|l| {
                let setting = l.strip_prefix("# ").and_then(|r| r.split_once(" = ")).filter(|(k, _)| KEYS.iter().any(|(_, ks)| ks.contains(k)));
                let list_header = LISTS.iter().any(|s| l == format!("# [[{s}]]"));
                match setting {
                    Some((k, _)) => {
                        seen.push(k.to_string());
                        format!("{}\n", &l[2..])
                    }
                    None if list_header => format!("{}\n", &l[2..]),
                    None => format!("{l}\n"),
                }
            })
            .collect();
        let example = SyncCfg { name: "relay.example.com".into(), url: "wss://relay.example.com".into(), ..SyncCfg::default() };
        let peer = PeerCfg { name: "eu-2".into(), secret: "replace-with-your-own-secret-from-openssl-rand".into(), ips: vec!["203.0.113.7".parse().unwrap()] };
        assert_eq!(ok(&uncommented), Config { sync: vec![example], peers: vec![peer], ..Config::default() }, "with every setting uncommented");

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
        assert!(text.contains(brand::NAME), "the name is filled in");
        for placeholder in ["{name}", "{slug}", "{vector_kinds}"] {
            assert!(!text.contains(placeholder), "{placeholder} replaced");
        }
    }

    #[test]
    fn sync_blocks() {
        let c = ok(r##"
[[sync]]
url = "ws://127.0.0.1:7777"

[[sync]]
url = "wss://relay.example.com/nostr"
filter = '[{"kinds":[0,10002]},{"kinds":[1059],"#p":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}]'
direction = "both"
reconcile_seconds = 60
"##);
        assert_eq!(c.sync.len(), 2);
        assert_eq!(c.sync[0], SyncCfg { url: "ws://127.0.0.1:7777".into(), ..SyncCfg::default() });
        let s = &c.sync[1];
        assert_eq!((s.url.as_str(), s.direction, s.reconcile_seconds, s.filters.len()), ("wss://relay.example.com/nostr", Direction::Both, 60, 2));
        assert_eq!(s.filters[0].kinds, Some(vec![0, 10002]));
        assert!(s.direction.up() && s.direction.down() && !Direction::Down.up() && !Direction::Up.down());
        // Everything else is untouched.
        assert_eq!(Config { sync: Vec::new(), ..c }, Config::default());
    }

    #[test]
    fn sync_mistakes() {
        fails("[sync]\nurl = \"ws://h\"", Some(1), "write [[sync]] with double brackets");
        fails("[[relay]]\nthreads = 1", Some(1), "write [relay] with single brackets");
        fails("[[sync]]\nfilter = \"{}\"\n", Some(1), "has no url");
        fails("[[sync]]\nurl = \"ws://h\"\n[[sync]]\ndirection = \"up\"\n", Some(3), "has no url");
        fails("[[sync]]\nurl = \"http://h\"", Some(2), "must start with ws:// or wss://");
        fails("[[sync]]\nurl = \"ws://h:99999\"", Some(2), "bad port");
        fails("[[sync]]\nurl = \"ws://h\"\nfilter = \"kinds\"", Some(3), "must be a Nostr filter in JSON");
        fails("[[sync]]\nurl = \"ws://h\"\nfilter = '{\"limit\":5}'", Some(3), "limit");
        fails("[[sync]]\nurl = \"ws://h\"\nfilter = '{\"kinds\":[1],\"nope\":1}'", Some(3), "unknown key");
        fails("[[sync]]\nurl = \"ws://h\"\ndirection = \"dwon\"", Some(3), "did you mean \"down\"?");
        fails("[[sync]]\nurl = \"ws://h\"\ndirection = \"sideways\"", Some(3), "\"down\" (theirs to us)");
        fails("[[sync]]\nurl = \"ws://h\"\nreconcile_seconds = 0", Some(3), "between 1 and");
        fails("[[sync]]\nurl = \"ws://h\"\nbind = \"x\"", Some(3), "`bind` belongs in [relay]");
        fails("[relay]\nurl = \"ws://h\"", Some(2), "`url` belongs in [sync]");
    }

    #[test]
    fn peers() {
        let s = "k".repeat(32);
        let c = ok(&format!("[[peer]]\nname = \"eu\"\nsecret = \"{s}\"\nips = [\"203.0.113.7\", \"::ffff:198.51.100.1\"]\n"));
        assert_eq!(c.peers.len(), 1);
        assert_eq!(c.peers[0].ips, vec!["203.0.113.7".parse::<std::net::IpAddr>().unwrap(), "198.51.100.1".parse().unwrap()], "mapped addresses compare as IPv4");
        fails("[[peer]]\nsecret = \"short\"\nips = [\"1.2.3.4\"]", Some(2), "at least 32");
        fails(&format!("[[peer]]\nsecret = \"{}\"\nips = [\"1.2.3.4\"]", "/".repeat(32)), Some(2), "at least 32");
        fails(&format!("[[peer]]\nsecret = \"{s}\""), Some(1), "needs both a secret and its ips");
        fails("[[peer]]\nips = [\"1.2.3.4\"]", Some(1), "needs both a secret and its ips");
        fails(&format!("[[peer]]\nsecret = \"{s}\"\nips = [\"relay.example.com\"]"), Some(3), "IP addresses");
        let twice = format!("[[peer]]\nsecret = \"{s}\"\nips = [\"1.2.3.4\"]\n[[peer]]\nsecret = \"{s}\"\nips = [\"5.6.7.8\"]\n");
        fails(&twice, Some(4), "same secret");
        fails("[peer]\nname = \"x\"", Some(1), "double brackets");
    }

    #[test]
    fn unix_socket_modes() {
        fails("[relay]\nunix_socket_mode = \"rw\"", Some(2), "permission bits in octal");
        fails("[relay]\nunix_socket_mode = \"1777\"", Some(2), "permission bits in octal");
        fails("[relay]\nunix_socket_mode = \"\"", Some(2), "permission bits in octal");
        fails("[relay]\nunix_socket_mode = 660", Some(2), "unix_socket_mode");
        assert_eq!(ok("[relay]\nunix_socket_mode = \"600\"").relay.unix_socket_mode, 0o600);
    }

    #[test]
    fn full_custom_file() {
        let pk = "ab".repeat(32);
        let text = format!(
            r#"
[relay]
bind = "0.0.0.0:8080"
unix_socket = "/run/relay/relay.sock"
unix_socket_mode = "0660"
threads = 4
real_ip_header = "X-Forwarded-For"
compression = "full"

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
        assert_eq!(
            c.relay,
            RelayCfg {
                bind: "0.0.0.0:8080".parse().unwrap(),
                unix_socket: "/run/relay/relay.sock".into(),
                unix_socket_mode: 0o660,
                threads: 4,
                real_ip_header: "x-forwarded-for".into(),
                urls: Vec::new(),
                compression: Compression::Full,
            }
        );
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
        assert_eq!(c.store, StoreCfg { data: PathBuf::from("/var/lib/relay"), sync: false, segment_mb: 64, memory_mb: 64 });
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
        fails("[store]\nzzzzzzzz = 1", Some(2), "The settings in [store] are data, sync, segment_mb, memory_mb");
        fails("[limit]\nmax_limit = 5", Some(1), "did you mean [limits]?");
        fails("[servers]\n", Some(1), "The sections are [relay], [info], [policy], [limits], [store], [tls]");
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

    // ----- [tls] -----

    #[test]
    fn tls_is_off_by_default_and_leaves_the_plain_listener_alone() {
        let c = Config::default();
        assert!(!c.tls.enabled);
        assert_eq!(c.tls.https_bind, "0.0.0.0:443".parse().unwrap());
        assert_eq!(c.tls.http_bind, Some("0.0.0.0:80".parse().unwrap()));
        assert_eq!(c.relay.bind, "127.0.0.1:7777".parse().unwrap());
        assert_eq!((c.tls.directory_url(), c.tls.uses_files()), (LETS_ENCRYPT, false));
        assert!(c.tls.names(&[]).is_empty());
        // Settings given while it is off are checked, but need nothing else.
        assert!(!ok("[tls]\nemail = \"admin@example.com\"\ndomains = [\"relay.example.com\"]").tls.enabled);
        // Turning it on needs only the names (here from the public address).
        let c = ok("[relay]\nurls = [\"wss://relay.example.com\"]\n[tls]\nenabled = true");
        assert_eq!(c.tls.names(&c.relay.urls), ["relay.example.com"]);
    }

    #[test]
    fn tls_full_file() {
        let c = ok("[tls]\nenabled = true\ndomains = [\"Relay.Example.com\", \"www.example.com\", \"relay.example.com\"]\nemail = \"admin@example.com\"\n\
                    https_bind = \"[::]:8443\"\nhttp_bind = \"\"\nstaging = true\n");
        assert_eq!(
            c.tls,
            TlsCfg {
                enabled: true,
                domains: vec!["relay.example.com".into(), "www.example.com".into()],
                email: "admin@example.com".into(),
                https_bind: "[::]:8443".parse().unwrap(),
                http_bind: None,
                staging: true,
                ..TlsCfg::default()
            }
        );
        assert_eq!(c.tls.directory_url(), LETS_ENCRYPT_STAGING);
        let c = ok("[tls]\nenabled = true\ncert = \"/etc/relay/fullchain.pem\"\nkey = \"/etc/relay/privkey.pem\"");
        assert!(c.tls.uses_files());
        assert_eq!((c.tls.cert.as_str(), c.tls.key.as_str()), ("/etc/relay/fullchain.pem", "/etc/relay/privkey.pem"));
        let c = ok("[tls]\ndirectory = \"https://acme.example/dir\"");
        assert_eq!(c.tls.directory_url(), "https://acme.example/dir");
    }

    #[test]
    fn tls_names_come_from_domains_or_the_public_urls() {
        let t = |domains: &[&str]| TlsCfg { domains: domains.iter().map(|d| d.to_string()).collect(), ..TlsCfg::default() };
        let urls = |u: &[&str]| u.iter().map(|d| d.to_string()).collect::<Vec<_>>();
        assert_eq!(t(&["a.example.com"]).names(&urls(&["wss://other.example.com"])), ["a.example.com"], "domains win");
        // Hosts of the urls, without scheme, port or path; names a CA could not certify are skipped.
        let u = urls(&["wss://relay.example.com", "ws://Relay.Example.com:7777/nostr", "wss://www.example.com/", "ws://abcdefghij.onion", "wss://203.0.113.5", "wss://[2001:db8::1]:443", "wss://localhost"]);
        assert_eq!(t(&[]).names(&u), ["relay.example.com", "www.example.com"]);
        assert!(t(&[]).names(&urls(&["ws://abcdefghij.onion"])).is_empty());
    }

    #[test]
    fn tls_domain_validation() {
        for (bad, why) in [
            ("\"*.example.com\"", "wildcard"),
            ("\"203.0.113.5\"", "IP address"),
            ("\"[::1]\"", "IP address"),
            ("\"localhost\"", "not a full name"),
            ("\"\"", "is empty"),
            ("\"example.com.\"", "ends with a dot"),
            ("\"exa mple.com\"", "invalid part"),
            ("\"-a.example.com\"", "invalid part"),
            ("\"a..example.com\"", "invalid part"),
            ("\"caf\u{e9}.example.com\"", "xn--"),
            ("\"relay.example.1\"", "top-level domain"),
            ("\"abc.onion\"", "private-network"),
            ("\"relay.local\"", "private-network"),
        ] {
            fails(&format!("[tls]\ndomains = [{bad}]"), Some(2), why);
        }
        fails("[tls]\ndomains = \"relay.example.com\"", Some(2), "put it in a list");
        fails(&format!("[tls]\ndomains = [\"{}.example.com\"]", "a".repeat(64)), Some(2), "invalid part");
        // The message names the entry.
        fails("[tls]\ndomains = [\"ok.example.com\", \"*.example.com\"]", Some(2), "`domains` entry \"*.example.com\"");
        assert_eq!(ok("[tls]\ndomains = [\"xn--caf-dma.example.com\", \"a-b.c-d.example.org\"]").tls.domains.len(), 2);
    }

    #[test]
    fn tls_email_validation() {
        assert_eq!(ok("[tls]\nemail = \"ops+relay@mail.example.com\"").tls.email, "ops+relay@mail.example.com");
        assert_eq!(ok("[tls]\nemail = \"\"").tls.email, "");
        for bad in ["admin", "admin@", "@example.com", "admin@example", "a b@example.com", "a@b@example.com", "admin@example.com?cc=x", "mailto:admin@example.com", "admin@.example.com"] {
            fails(&format!("[tls]\nemail = \"{bad}\""), Some(2), "address like admin@example.com");
        }
    }

    #[test]
    fn tls_bind_validation() {
        assert_eq!(ok("[tls]\nhttps_bind = \"127.0.0.1:8443\"").tls.https_bind.port(), 8443);
        assert_eq!(ok("[tls]\nhttp_bind = \"0.0.0.0:8080\"").tls.http_bind.unwrap().port(), 8080);
        assert_eq!(ok("[tls]\nhttp_bind = \"\"").tls.http_bind, None);
        fails("[tls]\nhttps_bind = \"0.0.0.0\"", Some(2), "`https_bind` needs a port as well as an address: write \"0.0.0.0:443\"");
        fails("[tls]\nhttp_bind = \"example.com:80\"", Some(2), "`http_bind` is not an address and port");
        fails("[tls]\nhttps_bind = \"\"", Some(2), "needs a port");
        fails("[tls]\nhttps_bind = 443", Some(2), "must be a string");
    }

    #[test]
    fn tls_certificate_and_key_go_together() {
        fails("[tls]\ncert = \"chain.pem\"", Some(2), "`cert` is set but `key` is not");
        fails("[tls]\nkey = \"key.pem\"", Some(2), "`key` is set but `cert` is not");
        // Even with TLS off: a half-written pair is a mistake worth hearing about.
        fails("[tls]\nenabled = false\nkey = \"key.pem\"", Some(3), "`cert`");
        assert!(Config::from_toml("[tls]\ncert = \"a\"\nkey = \"b\"").is_ok());
        fails("[tls]\ncert = \"a\\tb\"\nkey = \"k\"", Some(2), "control character");
        // A CA's settings mean nothing when files are given.
        fails("[tls]\ncert = \"a\"\nkey = \"b\"\nemail = \"x@example.com\"", Some(4), "`email` has no effect");
        fails("[tls]\ncert = \"a\"\nkey = \"b\"\nstaging = true", Some(4), "`staging` has no effect");
        fails("[tls]\ncert = \"a\"\nkey = \"b\"\ndirectory = \"https://x.example/d\"", Some(4), "`directory` has no effect");
    }

    #[test]
    fn tls_directory_choice() {
        fails("[tls]\nstaging = true\ndirectory = \"https://x.example/d\"", Some(2), "both choose the certificate authority");
        fails("[tls]\ndirectory = \"ftp://x.example/d\"", Some(2), "https:// address");
        fails("[tls]\ndirectory = \"acme.example.com\"", Some(2), "https:// address");
        fails("[tls]\ndirectory = \"http://acme.example.com/dir\"", Some(2), "only accepted for a certificate authority on this computer");
        // Plain http is fine for a CA on this machine (a test CA, for instance).
        for ok_dir in ["http://127.0.0.1:14000/dir", "http://localhost:14000/dir", "http://[::1]:14000/dir", "https://acme.example.com/directory"] {
            assert_eq!(ok(&format!("[tls]\ndirectory = \"{ok_dir}\"")).tls.directory, ok_dir);
        }
    }

    #[test]
    fn tls_needs_names_and_distinct_addresses_once_enabled() {
        fails("[tls]\nenabled = true", Some(2), "no names to get a certificate for");
        fails("[relay]\nurls = [\"ws://abcdefghij.onion\"]\n[tls]\nenabled = true", Some(4), "no names");
        // Files need no names.
        assert!(Config::from_toml("[tls]\nenabled = true\ncert = \"a\"\nkey = \"b\"").is_ok());
        let named = "[tls]\nenabled = true\ndomains = [\"relay.example.com\"]\n";
        fails(&format!("[relay]\nbind = \"0.0.0.0:443\"\n{named}"), Some(2), "https_bind and [relay] bind are both 0.0.0.0:443");
        fails(&format!("{named}http_bind = \"0.0.0.0:443\""), Some(4), "https_bind and [tls] http_bind are both");
        fails(&format!("[relay]\nbind = \"0.0.0.0:80\"\n{named}"), Some(2), "http_bind and [relay] bind are both 0.0.0.0:80");
        // A disabled section is not held to any of this.
        assert!(Config::from_toml("[relay]\nbind = \"0.0.0.0:443\"\n[tls]\nenabled = false").is_ok());
        assert!(Config::from_toml(&format!("[relay]\nbind = \"127.0.0.1:7777\"\n{named}")).is_ok());
    }

    #[test]
    fn tls_unknown_names_get_hints() {
        fails("[tls]\ndomain = [\"a.example.com\"]", Some(2), "did you mean `domains`?");
        fails("[tls]\nenable = true", Some(2), "did you mean `enabled`?");
        fails("[tls]\nstagging = true", Some(2), "did you mean `staging`?");
        fails("[relay]\nhttps_bind = \"0.0.0.0:443\"", Some(2), "belongs in [tls]");
        fails("[ssl]\n", Some(1), "unknown section [ssl]");
        fails("[tls]\nenabled = \"true\"", Some(2), "remove the quotes");
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
        // docs/DESIGN.md's table of what Vector produces and reads.
        for k in [0, 5, 8, 1059, 10002, 10008, 10030, 10050, 10063, 10304, 13303, 21059, 24133, 24590, 24681, 30008, 30009, 30030, 30078, 30315, 33301, 33302] {
            assert!(VECTOR_KINDS.contains(&k), "kind {k}");
        }
        let p = PolicyCfg::default().kind_policy();
        for k in VECTOR_KINDS {
            assert!(p.allows(*k));
        }
        // Every ephemeral kind is relayed, Vector's or not; nothing around it is.
        for k in [20_000, 20_013, 22_242, 24_133, 29_999] {
            assert!(p.allows(k), "ephemeral {k}");
        }
        // Public notes, reactions, contact lists and the like are refused.
        for k in [1, 3, 4, 6, 7, 9, 13, 14, 1111, 19_999, 30_000, 30023, 65535, 65536, u64::MAX] {
            assert!(!p.allows(k), "kind {k}");
        }
    }

    /// Reference answer: sets of kinds.
    fn reference(base: &KindBase, allow: &[u64], deny: &[u64], kind: u64) -> bool {
        let in_base = match base {
            KindBase::All => true,
            KindBase::Vector => VECTOR_KINDS.contains(&kind) || (20_000..30_000).contains(&kind),
            KindBase::List(l) => l.contains(&kind),
        };
        (in_base || allow.contains(&kind)) && !deny.contains(&kind)
    }

    #[test]
    fn kind_policy_matches_a_set_reference() {
        let edge = [0u64, 1, 63, 64, 65, 1058, 1059, 1060, 19_999, 20_000, 24_133, 29_999, 30_000, 65534, 65535, 65536, 65537, 70_000, 1 << 40, u64::MAX];
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
        assert_eq!(j["supported_nips"], serde_json::json!([1, 9, 11, 17, 24, 30, 38, 40, 45, 46, 58, 59, 62, 65, 70, 77, 78]));
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
