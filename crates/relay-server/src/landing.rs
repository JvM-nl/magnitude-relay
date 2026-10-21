//! The page a browser gets at the relay's address: its name and live status,
//! four live numbers, how to connect over clearnet, Tor and I2P, what it
//! carries and who runs it, in Vector's colours. `live` is the small JSON the
//! page refreshes those numbers from (cheaper than `/stats`, which also reads
//! the host's health).

use crate::config::{KindBase, SUPPORTED_NIPS};
use crate::reactor::Shared;
use std::fmt::Write;
use std::sync::atomic::Ordering;

const TEMPLATE: &str = include_str!("web/landing.html");
const MARK: &str = include_str!("web/mark.svg");
const WORD: &str = include_str!("web/word.svg");
/// Rubik (SIL Open Font License), served by the relay itself: no font CDN.
pub const FONT: &[u8] = include_bytes!("web/rubik.woff2");

/// What each NIP in `SUPPORTED_NIPS` means to a person, for the chips.
fn nip_name(n: u32) -> &'static str {
    match n {
        1 => "Core protocol",
        9 => "Deletions",
        11 => "Relay information",
        17 => "Private DMs",
        24 => "Profile fields",
        30 => "Custom emoji",
        38 => "User statuses",
        40 => "Expiring events",
        45 => "Event counts",
        58 => "Badges",
        59 => "Gift wraps",
        62 => "Request to vanish",
        65 => "Relay lists",
        70 => "Protected events",
        77 => "Negentropy sync",
        78 => "App data",
        _ => "",
    }
}

struct Live {
    events: u64,
    connections: u64,
    answer_ms: f64,
    events_out: u64,
    uptime_secs: u64,
}

fn live(shared: &Shared) -> Live {
    let t = shared.metrics.totals();
    Live {
        events: shared.store.snapshot().count,
        connections: shared.metrics.open.load(Ordering::Relaxed),
        answer_ms: if t.reqs == 0 { 0.0 } else { t.req_micros as f64 / t.reqs as f64 / 1000.0 },
        events_out: t.events_out,
        uptime_secs: shared.metrics.uptime_secs(),
    }
}

/// `live`: the page's four numbers and the uptime.
pub fn live_json(shared: &Shared) -> String {
    let l = live(shared);
    format!(
        "{{\"events\":{},\"connections\":{},\"answer_ms\":{:.3},\"events_out\":{},\"uptime_secs\":{}}}",
        l.events, l.connections, l.answer_ms, l.events_out, l.uptime_secs
    )
}

/// The page for a request to `path`. Links and fetches on it are relative to
/// `<base>`, the path itself as a directory, so it works at `/` and behind a
/// web server at `/nostr` alike.
pub fn page(shared: &Shared, path: &str) -> String {
    let cfg = &shared.cfg;
    let info = &cfg.info;
    let l = live(shared);
    let base = if path.ends_with('/') { path.to_string() } else { format!("{path}/") };
    let name = if info.name.is_empty() { crate::brand::NAME } else { &info.name };
    let desc = if info.description.is_empty() { "A Nostr relay." } else { &info.description };

    let (mut tor, mut i2p) = (Vec::new(), Vec::new());
    for a in &info.privacy_addresses {
        if a.contains(".onion") {
            tor.push(a.as_str());
        } else if a.contains(".i2p") {
            i2p.push(a.as_str());
        }
    }
    let clearnet: Vec<&str> = cfg.relay.urls.iter().map(String::as_str).collect();

    let mut nips = String::new();
    for &n in SUPPORTED_NIPS {
        let _ = write!(
            nips,
            "<a class=\"chip\" href=\"https://github.com/nostr-protocol/nips/blob/master/{n:02}.md\" target=\"_blank\" rel=\"noopener\"><i>{n:02}</i>{}</a>",
            nip_name(n)
        );
    }
    let policy = match cfg.policy.kinds {
        KindBase::Vector if cfg.policy.restricts_writes() => {
            "Built for Vector: it keeps the kinds of events Vector uses (messages, Concord communities, profiles, badges, emoji) and turns other kinds away."
        }
        _ if cfg.policy.restricts_writes() => "Accepts a chosen set of event kinds.",
        _ => "Open to every kind of event.",
    };
    let mut limits = String::new();
    for (k, v) in [
        ("Largest event", bytes(cfg.policy.max_event_bytes as u64)),
        ("Largest message", bytes(cfg.limits.max_message_bytes as u64)),
        ("Events per request", group(cfg.limits.max_limit as u64)),
        ("Subscriptions per connection", group(cfg.limits.max_subscriptions as u64)),
        ("Sign-in (AUTH)", "not needed".to_string()),
    ] {
        let _ = write!(limits, "<li><span>{k}</span><b>{v}</b></li>");
    }

    let operator = if info.pubkey.is_empty() && info.contact.is_empty() {
        String::new()
    } else {
        let mut who = String::new();
        if !info.pubkey.is_empty() {
            let npub = npub(&info.pubkey);
            who.push_str(&addresses(&[npub.as_deref().unwrap_or(&info.pubkey)], ""));
        }
        if !info.contact.is_empty() {
            let href = if info.contact.contains("://") || info.contact.starts_with("mailto:") { info.contact.clone() } else { format!("mailto:{}", info.contact) };
            let _ = write!(who, "<a href=\"{}\" rel=\"noopener\">{}</a>", esc(&href), esc(&info.contact));
        }
        let img = if info.icon.is_empty() { String::new() } else { format!("<img src=\"{}\" alt=\"\" loading=\"lazy\" referrerpolicy=\"no-referrer\">", esc(&info.icon)) };
        let cols = if img.is_empty() { " style=\"grid-template-columns: minmax(0, 1fr)\"" } else { "" };
        format!(
            "<section aria-labelledby=\"op-h\"><div class=\"sec-head\"><span class=\"eyebrow\">Operator</span><h2 id=\"op-h\">Who runs it</h2></div><div class=\"panel op\"{cols}>{img}<div class=\"who\">{who}</div></div></section>"
        )
    };

    // Tor and I2P cards only where the settings name such an address; the
    // line inviting a choice only when there is one.
    let mut html = TEMPLATE.to_string();
    for (marker, list) in [("TOR", &tor), ("I2P", &i2p)] {
        if list.is_empty() {
            let (open, close) = (format!("<!--{marker}-->"), format!("<!--/{marker}-->"));
            if let (Some(a), Some(b)) = (html.find(&open), html.find(&close)) {
                html.replace_range(a..b + close.len(), "");
            }
        }
    }
    let note = if tor.is_empty() && i2p.is_empty() { "" } else { "      <p>Choose your preferred network.</p>\n" };
    html.replace("{{CONNECT_NOTE}}", note)
        .replace("{{BASE}}", &esc(&base))
        .replace("{{NAME}}", &esc(name))
        .replace("{{DESC}}", &esc(desc))
        .replace("{{MARK_SVG}}", MARK.trim())
        .replace("{{WORD_SVG}}", WORD.trim())
        .replace("{{UPTIME}}", &uptime(l.uptime_secs))
        .replace("{{EVENTS}}", &group(l.events))
        .replace("{{OPEN}}", &group(l.connections))
        .replace("{{ANSWER}}", &format!("{:.2}", l.answer_ms))
        .replace("{{SERVED}}", &short(l.events_out))
        .replace("{{CLEARNET}}", &addresses(&clearnet, ""))
        .replace("{{TOR}}", &addresses(&tor, ""))
        .replace("{{I2P}}", &addresses(&i2p, ""))
        .replace("{{NIPS}}", &nips)
        .replace("{{POLICY}}", policy)
        .replace("{{LIMITS}}", &limits)
        .replace("{{OPERATOR}}", &operator)
        .replace("{{SOFTWARE}}", crate::brand::NAME)
        .replace("{{VERSION}}", crate::brand::VERSION)
}

/// One copyable line per address; `none` when there are none (empty: left for
/// the page's script, which fills in its own address).
fn addresses(list: &[&str], none: &str) -> String {
    if list.is_empty() {
        return if none.is_empty() { String::new() } else { format!("<span class=\"none\">{none}</span>") };
    }
    let mut o = String::new();
    for a in list {
        let a = esc(a);
        let _ = write!(o, "<div class=\"addr\"><code>{a}</code><button class=\"copy\" type=\"button\" data-copy=\"{a}\">Copy</button></div>");
    }
    o
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

/// 4881407 -> "4,881,407".
fn group(n: u64) -> String {
    let s = n.to_string();
    let mut o = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            o.push(',');
        }
        o.push(c);
    }
    o
}

/// The page script's short form: 1.2M, 34K, 980.
fn short(n: u64) -> String {
    match n {
        1_000_000_000.. => format!("{:.1}B", n as f64 / 1e9),
        1_000_000.. => format!("{:.1}M", n as f64 / 1e6),
        10_000.. => format!("{}K", (n as f64 / 1e3).round() as u64),
        _ => group(n),
    }
}

fn bytes(n: u64) -> String {
    if n >= 1024 && n % 1024 == 0 {
        format!("{} KiB", n / 1024)
    } else {
        format!("{} bytes", group(n))
    }
}

fn uptime(s: u64) -> String {
    let (d, h, m) = (s / 86400, s % 86400 / 3600, s % 3600 / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

/// A hex public key as `npub1…` (NIP-19, bech32), or None if it is not 64 hex characters.
fn npub(hex: &str) -> Option<String> {
    let bytes = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok()).collect::<Option<Vec<u8>>>()?;
    if bytes.len() != 32 {
        return None;
    }
    // 8-bit bytes to 5-bit groups.
    let mut data = Vec::with_capacity(52);
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let polymod = |values: &[u8]| {
        let gen = [0x3b6a57b2u32, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let mut chk = 1u32;
        for &v in values {
            let top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ u32::from(v);
            for (i, g) in gen.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    chk ^= g;
                }
            }
        }
        chk
    };
    let hrp = b"npub";
    let mut values: Vec<u8> = hrp.iter().map(|c| c >> 5).collect();
    values.push(0);
    values.extend(hrp.iter().map(|c| c & 31));
    values.extend(&data);
    values.extend([0u8; 6]);
    let pm = polymod(&values) ^ 1;
    let mut out = String::from("npub1");
    for &d in &data {
        out.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npub_matches_nip19() {
        // NIP-19's own example.
        assert_eq!(
            npub("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d").as_deref(),
            Some("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6")
        );
        assert_eq!(npub("zz"), None);
    }

    #[test]
    fn numbers_read_well() {
        assert_eq!(group(4_881_407), "4,881,407");
        assert_eq!(group(999), "999");
        assert_eq!(short(1_234_567), "1.2M");
        assert_eq!(short(34_400), "34K");
        assert_eq!(bytes(131_072), "128 KiB");
        assert_eq!(uptime(3 * 3600 + 12 * 60), "3h 12m");
        assert_eq!(esc("<a href=\"x\">&'"), "&lt;a href=&quot;x&quot;&gt;&amp;&#39;");
    }

    #[test]
    fn every_supported_nip_has_a_name() {
        for &n in SUPPORTED_NIPS {
            assert!(!nip_name(n).is_empty(), "NIP-{n}");
        }
    }
}
