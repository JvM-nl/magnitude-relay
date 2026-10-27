//! Who is using the relay, for the operator only: per address, what its
//! connections asked for and took over the last hour. Read through the admin
//! socket (`top`), never served over HTTP.
//!
//! Cheap by construction. A connection counts into cells only its own reactor
//! touches; when it closes, the counts are added to that reactor's table for
//! the current ten minutes. Nothing is shared or locked until the operator
//! asks, and then each reactor answers for itself.

use crate::subs::FxMap;
use relay_proto::Filter;
use std::cell::Cell;
use std::fmt;
use std::net::IpAddr;

/// Seconds one slot of the table covers, and how many are kept: an hour.
pub const SLOT_SECS: u64 = 600;
pub const SLOTS: usize = 6;

/// What a REQ asked for, without its values: its kinds, how many authors,
/// ids and tag values, the window and the limit. Never a key or an id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Shape {
    filters: u8,
    /// `None`: any kind. Otherwise the first four, and how many in all.
    kinds: Option<([u32; 4], u8)>,
    authors: u16,
    ids: u16,
    p: u16,
    other_tags: u16,
    since: bool,
    until: bool,
    limit: Option<u32>,
}

impl Shape {
    /// The first filter's shape, with how many filters came with it.
    pub fn of(filters: &[Filter]) -> Shape {
        let Some(f) = filters.first() else { return Shape::default() };
        let n = |len: usize| len.min(u16::MAX as usize) as u16;
        let kinds = f.kinds.as_ref().map(|k| {
            let mut first = [0u32; 4];
            for (slot, k) in first.iter_mut().zip(k) {
                *slot = (*k).min(u32::MAX as u64) as u32;
            }
            (first, k.len().min(u8::MAX as usize) as u8)
        });
        let tag_values = |p: bool| n(f.tags.iter().filter(|t| (t.name == b'p') == p).map(|t| t.values.len()).sum());
        Shape {
            filters: filters.len().min(u8::MAX as usize) as u8,
            kinds,
            authors: f.authors.as_ref().map_or(0, |a| n(a.len())),
            ids: f.ids.as_ref().map_or(0, |a| n(a.len())),
            p: tag_values(true),
            other_tags: tag_values(false),
            since: f.since.is_some(),
            until: f.until.is_some(),
            limit: f.limit.map(|l| l.min(u32::MAX as u64) as u32),
        }
    }
}

impl fmt::Display for Shape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.filters == 0 {
            return f.write_str("-");
        }
        match self.kinds {
            None => f.write_str("any kind")?,
            Some((first, n)) => {
                let shown: Vec<String> = first.iter().take(n.min(4) as usize).map(u32::to_string).collect();
                write!(f, "kinds {}{}", shown.join(","), if n > 4 { format!(" +{}", n - 4) } else { String::new() })?;
            }
        }
        for (n, what) in [(self.authors, "authors"), (self.ids, "ids"), (self.p, "#p"), (self.other_tags, "tags")] {
            if n > 0 {
                write!(f, " · {what}×{n}")?;
            }
        }
        if self.since {
            f.write_str(" · since")?;
        }
        if self.until {
            f.write_str(" · until")?;
        }
        if let Some(l) = self.limit {
            write!(f, " · limit {l}")?;
        }
        if self.filters > 1 {
            write!(f, " · +{} filters", self.filters - 1)?;
        }
        Ok(())
    }
}

/// One connection's counts, written only by its own reactor.
#[derive(Default)]
pub struct Talk {
    pub reqs: Cell<u32>,
    pub counts: Cell<u32>,
    pub negs: Cell<u32>,
    /// EVENTs received, and those refused.
    pub events: Cell<u32>,
    pub refused: Cell<u32>,
    /// REQs refused for asking for gift wraps wholesale.
    pub wraps: Cell<u32>,
    /// Events answered OK and dropped (see `bans`).
    pub silenced: Cell<u32>,
    pub bytes_out: Cell<u64>,
    /// The last REQ's shape.
    pub shape: Cell<Shape>,
}

#[inline]
pub fn bump(c: &Cell<u32>) {
    c.set(c.get().saturating_add(1));
}

/// An address's totals over some stretch of time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Agg {
    /// Connections opened (closed ones, plus `live`), and of them still open.
    pub conns: u64,
    pub live: u64,
    /// Seconds connected, summed.
    pub secs: u64,
    pub reqs: u64,
    pub counts: u64,
    pub negs: u64,
    pub events: u64,
    pub refused: u64,
    pub wraps: u64,
    pub silenced: u64,
    pub bytes_out: u64,
    /// The latest connection's user agent and REQ shape.
    pub ua: Box<str>,
    pub shape: Shape,
}

impl Agg {
    pub fn add(&mut self, t: &Talk, ua: &str, secs: u64, live: bool) {
        self.conns += 1;
        // An open connection's time is not over, so it stays out of the average.
        if live {
            self.live += 1;
        } else {
            self.secs += secs;
        }
        self.reqs += u64::from(t.reqs.get());
        self.counts += u64::from(t.counts.get());
        self.negs += u64::from(t.negs.get());
        self.events += u64::from(t.events.get());
        self.refused += u64::from(t.refused.get());
        self.wraps += u64::from(t.wraps.get());
        self.silenced += u64::from(t.silenced.get());
        self.bytes_out += t.bytes_out.get();
        if &*self.ua != ua {
            self.ua = ua.into();
        }
        if t.shape.get() != Shape::default() {
            self.shape = t.shape.get();
        }
    }

    pub fn merge(&mut self, o: &Agg) {
        self.conns += o.conns;
        self.live += o.live;
        self.secs += o.secs;
        self.reqs += o.reqs;
        self.counts += o.counts;
        self.negs += o.negs;
        self.events += o.events;
        self.refused += o.refused;
        self.wraps += o.wraps;
        self.silenced += o.silenced;
        self.bytes_out += o.bytes_out;
        if self.ua.is_empty() {
            self.ua = o.ua.clone();
        }
        if self.shape == Shape::default() {
            self.shape = o.shape;
        }
    }
}

/// A reactor's closed connections, by address, in ten-minute slots.
#[derive(Default)]
pub struct TalkLog {
    slots: [(u64, FxMap<IpAddr, Agg>); SLOTS],
}

impl TalkLog {
    /// Adds a closed connection's counts to the slot for `now` (Unix seconds).
    pub fn fold(&mut self, now: u64, ip: IpAddr, ua: &str, t: &Talk, secs: u64) {
        let slot = now / SLOT_SECS;
        let at = &mut self.slots[(slot % SLOTS as u64) as usize];
        if at.0 != slot {
            *at = (slot, FxMap::default());
        }
        at.1.entry(ip).or_default().add(t, ua, secs, false);
    }

    /// Every address's totals in the slots from `from` (a slot number) on.
    pub fn since(&self, from: u64, into: &mut FxMap<IpAddr, Agg>) {
        for (slot, table) in &self.slots {
            if *slot >= from && !table.is_empty() {
                for (ip, a) in table {
                    into.entry(*ip).or_default().merge(a);
                }
            }
        }
    }
}

/// What `top` sorts by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum By {
    Bytes,
    Conns,
    Reqs,
    Events,
    Refused,
}

impl By {
    pub const NAMES: [(By, &'static str); 5] = [(By::Bytes, "bytes"), (By::Conns, "conns"), (By::Reqs, "reqs"), (By::Events, "events"), (By::Refused, "refused")];

    pub fn parse(s: &str) -> Option<By> {
        By::NAMES.iter().find(|(_, n)| *n == s).map(|(b, _)| *b)
    }

    pub fn name(self) -> &'static str {
        By::NAMES.iter().find(|(b, _)| *b == self).map(|(_, n)| *n).expect("every order is named")
    }

    fn key(self, a: &Agg) -> u64 {
        match self {
            By::Bytes => a.bytes_out,
            By::Conns => a.conns,
            By::Reqs => a.reqs + a.counts + a.negs,
            By::Events => a.events,
            By::Refused => a.refused + a.wraps,
        }
    }
}

/// The table `top` prints: a summary line, a header, then the busiest
/// addresses first.
pub fn render(rows: FxMap<IpAddr, Agg>, minutes: u64, by: By, limit: usize) -> Vec<String> {
    let mut all = Agg::default();
    for a in rows.values() {
        all.merge(a);
    }
    let mut rows: Vec<(IpAddr, Agg)> = rows.into_iter().collect();
    rows.sort_by(|a, b| by.key(&b.1).cmp(&by.key(&a.1)).then(a.0.cmp(&b.0)));
    let mb = |b: u64| format!("{:.1}", b as f64 / 1e6);
    let mut out = vec![
        format!(
            "last {minutes} min: {} addresses, {} connections ({} open), {} REQs, {} EVENTs ({} refused, {} silenced), {} gift-wrap scrapes refused, {} MB out; by {}",
            rows.len(),
            all.conns,
            all.live,
            all.reqs,
            all.events,
            all.refused,
            all.silenced,
            all.wraps,
            mb(all.bytes_out),
            by.name()
        ),
        format!("{:<40} {:>7} {:>5} {:>7} {:>8} {:>7} {:>6} {:>6} {:>9}  {:<28} last request", "address", "conns", "open", "avg s", "reqs", "events", "refus", "scrape", "MB out", "app"),
    ];
    for (ip, a) in rows.into_iter().take(limit) {
        let avg = if a.conns > a.live { a.secs / (a.conns - a.live) } else { 0 };
        let ua: String = if a.ua.is_empty() { "-".into() } else { a.ua.chars().take(28).collect() };
        out.push(format!(
            "{:<40} {:>7} {:>5} {:>7} {:>8} {:>7} {:>6} {:>6} {:>9}  {:<28} {}",
            ip.to_string(),
            a.conns,
            a.live,
            avg,
            a.reqs + a.counts + a.negs,
            a.events,
            a.refused + a.silenced,
            a.wraps,
            mb(a.bytes_out),
            ua,
            a.shape
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_proto::json::Scanner;

    fn shape(json: &str) -> String {
        let fs: Vec<Filter> = vec![Filter::parse(&mut Scanner::new(json)).unwrap()];
        Shape::of(&fs).to_string()
    }

    #[test]
    fn a_shape_names_kinds_and_counts_never_values() {
        let pk = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";
        let s = shape(&format!("{{\"kinds\":[1059,21059],\"authors\":[\"{pk}\"],\"#p\":[\"{pk}\"],\"since\":1,\"limit\":500}}"));
        assert_eq!(s, "kinds 1059,21059 · authors×1 · #p×1 · since · limit 500");
        assert!(!s.contains(pk));
        assert_eq!(shape("{\"kinds\":[0,1,3,5,7,30078]}"), "kinds 0,1,3,5 +2");
        assert_eq!(shape("{}"), "any kind");
        assert_eq!(Shape::default().to_string(), "-");
    }

    #[test]
    fn closed_connections_fold_into_the_hour_and_old_slots_fall_away() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let t = Talk::default();
        t.reqs.set(3);
        t.bytes_out.set(1000);
        let mut log = TalkLog::default();
        log.fold(10 * SLOT_SECS, ip, "bot/1", &t, 4);
        log.fold(10 * SLOT_SECS + 5, ip, "bot/1", &t, 6);
        log.fold(13 * SLOT_SECS, ip, "bot/2", &t, 2);
        let mut m = FxMap::default();
        log.since(10, &mut m);
        assert_eq!((m[&ip].conns, m[&ip].reqs, m[&ip].bytes_out, m[&ip].secs), (3, 9, 3000, 12));
        let mut m = FxMap::default();
        log.since(11, &mut m);
        assert_eq!(m[&ip].conns, 1);
        // Six slots on, slot 10's place is reused.
        log.fold(16 * SLOT_SECS, ip, "bot/3", &t, 1);
        let mut m = FxMap::default();
        log.since(0, &mut m);
        assert_eq!(m[&ip].conns, 2);
    }

    #[test]
    fn the_table_puts_the_busiest_first() {
        let mut rows = FxMap::default();
        let a: IpAddr = "203.0.113.1".parse().unwrap();
        let b: IpAddr = "2001:db8::1".parse().unwrap();
        rows.insert(a, Agg { conns: 5, bytes_out: 10, ua: "small".into(), ..Agg::default() });
        rows.insert(b, Agg { conns: 2, live: 1, secs: 30, bytes_out: 9_000_000, ua: "big".into(), ..Agg::default() });
        let lines = render(rows, 60, By::Bytes, 10);
        assert!(lines[0].starts_with("last 60 min: 2 addresses, 7 connections (1 open)"), "{}", lines[0]);
        assert!(lines[2].starts_with("2001:db8::1"), "{lines:?}");
        assert!(lines[2].contains(" 30 ") && lines[2].contains("9.0"), "{lines:?}");
    }
}
