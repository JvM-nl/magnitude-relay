//! Syncing with another relay: this relay as a NIP-77 (negentropy) client of
//! another, copying events down (theirs to us), up (ours to them), or both.
//!
//! One filter at a time, newest first, in time windows. For each window both
//! sides' sets are compared by negentropy with us initiating, so only ids
//! cross the wire until the differences are known; then what we lack is asked
//! for by id (REQ, in chunks, several at once) and checked and stored like a
//! client's EVENT, and what they lack is published (EVENT, reading each OK,
//! backing off when they say we are going too fast).
//!
//! Windows exist because a set has to fit somewhere. A relay refuses to
//! compare more than it is willing to hold (strfry: a million events unless the
//! filter is its prepared `{}`; us: two million), and our side holds the set in
//! memory while comparing. Each window is sized from what the last one held,
//! aiming at [`WINDOW_TARGET`] events on whichever side has more; one that we
//! hold too much of is cut at exactly [`WINDOW_CAP`]; one the other relay calls
//! too large is retried at a quarter of the length.
//!
//! The `sync` command runs this once (`run_command`); a running relay runs it
//! for each `[[sync]]` entry on start and every `reconcile_seconds`, and
//! streams new events live in between (`live.rs`).

#[cfg(test)]
mod fake_tests;
pub mod live;
pub mod local;
pub mod remote;

use crate::config::{store_options, Config, Direction};
use crate::inbound::{Tally, Verdict};
use crate::ingest;
use crate::session::{self, SessionCfg};
use local::{Inbound, Local};
use relay_net::connector::{Connector, RelayUrl};
use relay_proto::message::RelayMsg;
use relay_proto::{hex, EventParser, Filter, Record};
use relay_store::Store;
use remote::{NegFail, Remote};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Events per window to aim for, on whichever side holds more.
pub const WINDOW_TARGET: usize = 100_000;
/// The most of a window we hold in memory at once (about 72 bytes each).
pub const WINDOW_CAP: usize = 500_000;
/// The first window reaches back this far from now.
const FIRST_SPAN: u64 = 86_400;
/// Ids per REQ: strfry caps a filter at 500 results, and 500 ids make a
/// 34 KB message, inside every relay's limit.
const FETCH_CHUNK: usize = 500;
/// REQs in flight at once. strfry allows 20 subscriptions per connection.
const FETCH_PARALLEL: usize = 8;
/// Events checked and stored together.
const INGEST_BATCH: usize = 1000;
const INGEST_BATCH_BYTES: usize = 4 << 20;
/// EVENTs awaiting their OK at once.
const PUSH_WINDOW: usize = 256;
/// Events read from our store at a time to publish.
const PUSH_CHUNK: usize = 500;
/// Silence that ends a fetch or a push.
const IDLE: Duration = Duration::from_secs(60);
/// The longest a push waits after the other relay says to slow down.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Events expiring sooner than this are left to the live link. A bulk pass
/// (a reconcile, or the backlog the live link sends after a reconnect) does not
/// copy them: they would be gone, or nearly, by the time they landed. Ephemeral
/// events never travel in bulk at all, since they are never stored.
pub const SHORT_LIVED: u64 = 600;

/// What a bulk pass treats as already expired: everything expiring within
/// [`SHORT_LIVED`] of now.
pub fn bulk_horizon() -> u64 {
    ingest::now().saturating_add(SHORT_LIVED)
}

/// A `[[peer]]`'s passes against this relay, as seen from here. A peer runs a
/// pass on a connection of its own: negentropy messages to find what differs,
/// then REQs by id for what it lacks and EVENTs for what we lack. (How far back
/// the pass reaches only the peer knows: it compares in time windows, and each
/// window's filter says only that window.)
#[derive(Debug, Default)]
pub struct PeerLink {
    pub name: String,
    /// Unix seconds: when the current (or last) pass began, and its last sign of life.
    pub since: AtomicU64,
    pub last: AtomicU64,
    /// Events it sent here or asked for by id during the current (or last) pass.
    pub moved: AtomicU64,
}

impl PeerLink {
    /// Silence after which a pass is over.
    pub const QUIET: u64 = 20;

    pub fn new(name: &str) -> PeerLink {
        PeerLink { name: name.to_string(), ..PeerLink::default() }
    }

    /// A negentropy message of a pass: one after a quiet spell begins a new pass.
    pub fn touch(&self, now: u64) {
        if now.saturating_sub(self.last.load(Relaxed)) > Self::QUIET {
            self.since.store(now, Relaxed);
            self.moved.store(0, Relaxed);
        }
        self.last.store(now, Relaxed);
    }

    /// Events of the pass fetched or sent: the pass is still going, though
    /// copying a large difference can be a long time between negentropy messages.
    pub fn moved(&self, now: u64, n: u64) {
        self.moved.fetch_add(n, Relaxed);
        self.last.store(now, Relaxed);
    }

    pub fn active(&self, now: u64) -> bool {
        let last = self.last.load(Relaxed);
        last > 0 && now.saturating_sub(last) <= Self::QUIET
    }
}

/// What a sync of one filter did.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub windows: u64,
    /// Events compared on each side.
    pub ours: u64,
    pub theirs: u64,
    /// Events only we held / only they held.
    pub have: u64,
    pub need: u64,
    pub rounds: u64,
    /// Not asked for: turned away on an earlier pass of the same sync.
    pub refused_before: u64,
    /// Events received for what we asked.
    pub fetched: u64,
    /// Asked for and never sent: deleted there in the meantime, or hidden from us.
    pub not_returned: u64,
    /// Sent though nobody asked; ignored.
    pub unrequested: u64,
    /// Fetched but expiring within [`SHORT_LIVED`], so not stored: a relay
    /// that is not one of ours leaves them in its set.
    pub short_lived: u64,
    /// Messages from the other relay that could not be read.
    pub unreadable: u64,
    /// What became of what we fetched.
    pub down: Tally,
    /// What the other relay said to what we published.
    pub up: Tally,
    /// Published but never answered.
    pub up_unanswered: u64,
    /// Times the other relay told us to slow down.
    pub up_slowed: u64,
    pub secs: f64,
}

impl Report {
    pub fn merge(&mut self, o: &Report) {
        self.windows += o.windows;
        self.ours += o.ours;
        self.theirs += o.theirs;
        self.have += o.have;
        self.need += o.need;
        self.rounds += o.rounds;
        self.refused_before += o.refused_before;
        self.fetched += o.fetched;
        self.not_returned += o.not_returned;
        self.unrequested += o.unrequested;
        self.short_lived += o.short_lived;
        self.unreadable += o.unreadable;
        self.down.merge(&o.down);
        self.up.merge(&o.up);
        self.up_unanswered += o.up_unanswered;
        self.up_slowed += o.up_slowed;
        self.secs += o.secs;
    }
}

/// How a sync runs.
pub struct Opts {
    pub dir: Direction,
    /// Compare only: fetch nothing, publish nothing.
    pub dry_run: bool,
    /// Leave gift wraps out of broad filters (the other relay does; see `Remote::hides_wraps`).
    pub hide_wraps: bool,
    /// The other relay is a trusted peer: the signatures of events it marks
    /// first-hand are not checked again.
    pub trusted: bool,
    /// Print a line per window to stderr.
    pub verbose: bool,
    /// [`WINDOW_TARGET`] and [`WINDOW_CAP`], smaller in tests.
    pub target: usize,
    pub cap: usize,
}

impl Opts {
    pub fn new(dir: Direction) -> Opts {
        Opts { dir, dry_run: false, hide_wraps: false, trusted: false, verbose: false, target: WINDOW_TARGET, cap: WINDOW_CAP }
    }
}

/// Syncs the events `f` matches, window by window, newest first.
pub async fn sync_filter(remote: &mut Remote, local: &mut impl Local, f: &Filter, opts: &Opts, report: &mut Report) -> Result<(), String> {
    let started = Instant::now();
    let result = windows(remote, local, f, opts, report).await;
    report.secs += started.elapsed().as_secs_f64();
    result
}

async fn windows(remote: &mut Remote, local: &mut impl Local, f: &Filter, opts: &Opts, report: &mut Report) -> Result<(), String> {
    if f.never_matches() {
        return Ok(());
    }
    let lo = f.since.unwrap_or(0);
    // Inclusive; MAX while the window is open-ended (the filter has no until).
    let mut upper = f.until.unwrap_or(u64::MAX);
    let mut span = FIRST_SPAN;
    loop {
        // An open-ended window reaches back from now and forward without end.
        let top = if upper == u64::MAX { ingest::now().max(lo) } else { upper };
        let mut since = top.saturating_sub(span - 1).max(lo);
        let window = |since: u64| Filter {
            since: (since > 0 || f.since.is_some()).then_some(since),
            until: (upper != u64::MAX).then_some(upper),
            ..f.clone()
        };
        let mut wf = window(since);
        let mut items = local.items(&wf, opts.hide_wraps, opts.cap)?;
        if items.len() > opts.cap {
            // Newest first: start the window just after the second that overflowed.
            let cut = items[opts.cap].0;
            if cut < top {
                since = cut + 1;
            } else {
                // One second holds more than the cap: it cannot be split by time.
                since = top;
            }
            wf = window(since);
            items = local.items(&wf, opts.hide_wraps, usize::MAX)?;
        }
        let ours = items.len() as u64;
        let diff = match remote.reconcile(&wf, items).await {
            Ok(d) => d,
            Err(NegFail::TooBig(why)) => {
                if since >= top {
                    return Err(format!("{} will not compare even one second of {}: {why}", remote.url, filter_text(&wf)));
                }
                span = ((top - since + 1) / 4).max(1);
                if opts.verbose {
                    eprintln!("  {} says the window from {since} is too large ({why}); trying a quarter of it", remote.url);
                }
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        let theirs = ours - diff.have.len() as u64 + diff.need.len() as u64;
        report.windows += 1;
        report.ours += ours;
        report.theirs += theirs;
        report.have += diff.have.len() as u64;
        report.need += diff.need.len() as u64;
        report.rounds += diff.rounds as u64;
        if opts.verbose {
            let until = if upper == u64::MAX { "now".to_string() } else { upper.to_string() };
            eprintln!("  {since}..{until}: ours {ours}, theirs {theirs}; only theirs {}, only ours {} ({} rounds)", diff.need.len(), diff.have.len(), diff.rounds);
        }
        if !opts.dry_run {
            if opts.dir.down() && !diff.need.is_empty() {
                fetch(remote, local, &diff.need, opts.trusted, report).await?;
            }
            if opts.dir.up() && !diff.have.is_empty() {
                push(remote, local, &diff.have, report).await?;
            }
        }
        if since <= lo {
            return Ok(());
        }
        // Size the next window from this one's density.
        let len = (top - since + 1) as u128;
        let held = ours.max(theirs).max(1) as u128;
        span = (len * opts.target as u128 / held).clamp((len / 4).max(1), len.saturating_mul(16)).min(u64::MAX as u128) as u64;
        upper = since - 1;
    }
}

/// `text` fit to show where others can read it (/stats, /metrics, the log):
/// the secret of a peer address (`/peer/<secret>`) is left out.
pub fn shown(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("/peer/") {
        out.push_str(&rest[..i + "/peer/".len()]);
        rest = &rest[i + "/peer/".len()..];
        let end = rest.find(|c: char| matches!(c, '/' | '?' | '#' | ':' | '"') || c.is_whitespace()).unwrap_or(rest.len());
        if end > 0 {
            out.push('…');
        }
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

pub fn filter_text(f: &Filter) -> String {
    let mut b = Vec::new();
    f.write_json(&mut b);
    String::from_utf8_lossy(&b).into_owned()
}

/// Asks for `need` by id and stores what comes back.
async fn fetch(remote: &mut Remote, local: &mut impl Local, need: &[[u8; 32]], trusted: bool, report: &mut Report) -> Result<(), String> {
    // Turned away on an earlier pass and still there: not asked for again.
    let asking: Vec<[u8; 32]> = need.iter().filter(|id| !local.refused_before(id)).copied().collect();
    report.refused_before += (need.len() - asking.len()) as u64;
    let mut chunks = asking.chunks(FETCH_CHUNK);
    let mut asked: HashMap<String, HashSet<[u8; 32]>> = HashMap::new();
    let mut batch: Vec<Inbound> = Vec::new();
    let mut ids: Vec<[u8; 32]> = Vec::new();
    let mut batch_bytes = 0;
    let mut parser = EventParser::new();
    let mut rec = Vec::new();
    let horizon = bulk_horizon();
    loop {
        while asked.len() < FETCH_PARALLEL {
            let Some(chunk) = chunks.next() else { break };
            let sub = remote.sub("get");
            let f = Filter { ids: Some(chunk.to_vec()), limit: Some(chunk.len() as u64), ..Filter::default() };
            remote.queue(&format!("[\"REQ\",\"{sub}\",{}]", filter_text(&f)));
            asked.insert(sub, chunk.iter().copied().collect());
        }
        remote.flush().await?;
        if asked.is_empty() {
            break;
        }
        let text = remote.next_within(IDLE).await?;
        let mut closed = None;
        match RelayMsg::parse(&text) {
            Ok(RelayMsg::Event { sub_id, at, first_hand }) => {
                let Some(want) = asked.get_mut(sub_id) else { continue };
                let id = match parser.parse_unchecked(&mut relay_proto::json::Scanner::new_at(&text, at), &mut rec) {
                    Ok(_) => *Record(&rec).id(),
                    Err(_) => {
                        report.down.add(&Verdict::Invalid("invalid: malformed event".into()));
                        continue;
                    }
                };
                if !want.remove(&id) {
                    report.unrequested += 1;
                    continue;
                }
                report.fetched += 1;
                if Record(&rec).expiration().is_some_and(|x| x <= horizon) {
                    report.short_lived += 1;
                    continue;
                }
                batch_bytes += text.len();
                batch.push(Inbound { text, at, vouched: trusted && first_hand });
                ids.push(id);
            }
            Ok(RelayMsg::Eose { sub_id }) | Ok(RelayMsg::Closed { sub_id, .. }) => closed = Some(sub_id.to_string()),
            Ok(_) => {}
            Err(_) => report.unreadable += 1,
        }
        if let Some(sub) = closed {
            if let Some(left) = asked.remove(&sub) {
                report.not_returned += left.len() as u64;
                // strfry keeps a subscription open after EOSE.
                remote.queue(&format!("[\"CLOSE\",\"{sub}\"]"));
            }
        }
        if batch.len() >= INGEST_BATCH || batch_bytes >= INGEST_BATCH_BYTES || (asked.is_empty() && !batch.is_empty()) {
            store(local, std::mem::take(&mut batch), std::mem::take(&mut ids), &mut report.down).await?;
            batch_bytes = 0;
        }
    }
    if !batch.is_empty() {
        store(local, batch, ids, &mut report.down).await?;
    }
    Ok(())
}

/// Stores a batch and remembers what was turned away for good (a failed
/// write may succeed another time; everything else will be refused again).
async fn store(local: &mut impl Local, batch: Vec<Inbound>, ids: Vec<[u8; 32]>, tally: &mut Tally) -> Result<(), String> {
    for (v, id) in local.ingest(&batch).await?.into_iter().zip(ids) {
        if !matches!(v, Verdict::Stored | Verdict::Duplicate | Verdict::Failed) {
            local.remember_refused(id);
        }
        tally.add(&v);
    }
    Ok(())
}

/// How an OK answers a published event.
pub fn verdict_of_ok(accepted: bool, message: &str) -> Verdict {
    match (accepted, message) {
        (true, m) if m.starts_with("duplicate") => Verdict::Duplicate,
        (true, _) => Verdict::Stored,
        // Ours, for a replaceable event a newer version of which it holds.
        (false, m) if m.starts_with("duplicate") => Verdict::Superseded,
        (false, m) => Verdict::Refused(m.to_string()),
    }
}

/// True for an OK that asks us to send again later.
pub fn slow_down(accepted: bool, message: &str) -> bool {
    !accepted && message.starts_with("rate-limited")
}

/// When to publish again after being told to slow down. Every EVENT already
/// in flight is likely to be told the same, so only the first answer of a
/// burst lengthens the pause: it doubles from a second up to a minute, and
/// resets once something is accepted.
#[derive(Debug, Default)]
pub struct Backoff {
    pause: Duration,
    until: Option<Instant>,
}

impl Backoff {
    pub fn slowed(&mut self, now: Instant) {
        if self.until.is_some_and(|u| now < u) {
            return;
        }
        self.pause = (self.pause * 2).clamp(Duration::from_secs(1), MAX_BACKOFF);
        self.until = Some(now + self.pause);
    }

    pub fn accepted(&mut self) {
        self.pause = Duration::ZERO;
    }

    /// The pause still to wait, if any.
    pub fn waiting(&self, now: Instant) -> Option<Instant> {
        self.until.filter(|&u| now < u)
    }
}

/// Publishes `have` to the other relay and reads every OK.
async fn push(remote: &mut Remote, local: &mut impl Local, have: &[[u8; 32]], report: &mut Report) -> Result<(), String> {
    let mut ids = have.chunks(PUSH_CHUNK);
    let mut queue: VecDeque<([u8; 32], String)> = VecDeque::new();
    let mut waiting: HashMap<[u8; 32], String> = HashMap::new();
    let mut backoff = Backoff::default();
    loop {
        if queue.len() < PUSH_WINDOW {
            if let Some(chunk) = ids.next() {
                for json in local.events(chunk)? {
                    if let Some(id) = event_id(&json) {
                        queue.push_back((id, json));
                    }
                }
            }
        }
        let paused = backoff.waiting(Instant::now());
        if paused.is_none() {
            while waiting.len() < PUSH_WINDOW {
                let Some((id, json)) = queue.pop_front() else { break };
                remote.queue(&format!("[\"EVENT\",{json}]"));
                waiting.insert(id, json);
            }
            remote.flush().await?;
        }
        if waiting.is_empty() {
            if queue.is_empty() && ids.len() == 0 {
                return Ok(());
            }
            if let Some(until) = paused {
                tokio::time::sleep_until(until.into()).await;
            }
            continue;
        }
        let text = match remote.next_within(IDLE).await {
            Ok(t) => t,
            Err(_) => {
                report.up_unanswered += waiting.len() as u64;
                return Err(format!("{} stopped answering what we published", remote.url));
            }
        };
        let Ok(RelayMsg::Ok { id, accepted, message }) = RelayMsg::parse(&text) else { continue };
        let Some(json) = waiting.remove(&id) else { continue };
        if slow_down(accepted, &message) {
            report.up_slowed += 1;
            backoff.slowed(Instant::now());
            queue.push_front((id, json));
        } else {
            backoff.accepted();
            report.up.add(&verdict_of_ok(accepted, &message));
        }
    }
}

/// The id of an event's JSON.
fn event_id(json: &str) -> Option<[u8; 32]> {
    let mut id = None;
    let mut s = relay_proto::json::Scanner::new(json);
    s.object(|s, key| -> Result<(), relay_proto::json::Error> {
        if key.is(b"id") {
            id = hex::decode_32(s.string()?.bytes);
        } else {
            s.skip()?;
        }
        Ok(())
    })
    .ok()?;
    id
}

/// Where the `sync` command's events go.
enum Target {
    Direct(Box<local::Direct>),
    Socket(local::ViaSocket),
}

/// `sync <url>`: one pass over each filter, with the relay running or not.
pub fn run_command(cfg: &Config, url: &str, filters: Vec<Filter>, dir: Direction, dry_run: bool, trusted: bool) -> Result<(), String> {
    let url = RelayUrl::parse(url)?;
    crate::operator::check_filters(&filters)?;
    let mut target = match Store::open(&cfg.store.data, store_options(cfg)) {
        Ok((store, w)) => Target::Direct(Box::new(local::Direct::new(store, w, SessionCfg::from_config(cfg)?))),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Target::Socket(local::ViaSocket::new(crate::admin::socket_path(&cfg.store.data), e.to_string())),
        Err(e) => return Err(e.to_string()),
    };
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    let result = rt.block_on(async {
        let connector = Connector::new().map_err(|e| e.to_string())?;
        let mut remote = Remote::connect(&connector, &url).await?;
        let hide_wraps = if filters.iter().any(session::broad) { remote.hides_wraps().await? } else { false };
        let mut total = Report::default();
        let how = if dry_run { "comparing with" } else { "syncing with" };
        eprintln!("{how} {url} ({}{})", dir.name(), if hide_wraps { "; it lists gift wraps only by author, recipient or id, so they are left out here too" } else { "" });
        for f in &filters {
            println!("filter {}", filter_text(f));
            let opts = Opts { dry_run, hide_wraps, trusted, verbose: true, ..Opts::new(dir) };
            let mut report = Report::default();
            let r = match &mut target {
                Target::Direct(l) => sync_filter(&mut remote, l.as_mut(), f, &opts, &mut report).await,
                Target::Socket(l) => sync_filter(&mut remote, l, f, &opts, &mut report).await,
            };
            print_report(&report, dir, dry_run);
            total.merge(&report);
            r?;
        }
        if filters.len() > 1 {
            println!("all filters:");
            print_report(&total, dir, dry_run);
        }
        remote.close().await;
        Ok::<(), String>(())
    });
    if let Target::Direct(d) = target {
        d.finish()?;
    }
    result
}

fn print_report(r: &Report, dir: Direction, dry_run: bool) {
    println!(
        "  compared {} window(s) in {:.1}s ({} rounds): ours {}, theirs {}; only theirs {}, only ours {}",
        r.windows, r.secs, r.rounds, r.ours, r.theirs, r.need, r.have
    );
    if dry_run {
        println!("  dry run: nothing was fetched or published");
        return;
    }
    if dir.down() {
        println!(
            "  fetched {} of {} (not returned {}, unrequested {}, unreadable {}, expiring too soon to keep {})",
            r.fetched, r.need, r.not_returned, r.unrequested, r.unreadable, r.short_lived
        );
        println!("  here: {}", r.down);
    }
    if dir.up() {
        println!("  published {} (unanswered {}, told to slow down {} times)", r.up.total() + r.up_unanswered, r.up_unanswered, r.up_slowed);
        println!("  there: {}", r.up);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_secret_is_never_shown() {
        let url = "wss://relay.example.com/nostr/peer/149b308886368b3c";
        assert_eq!(shown(url), "wss://relay.example.com/nostr/peer/…");
        assert_eq!(
            shown(&format!("sync with {url}: {url}: unexpected end of file")),
            "sync with wss://relay.example.com/nostr/peer/…: wss://relay.example.com/nostr/peer/…: unexpected end of file"
        );
        assert_eq!(shown("wss://h/peer/s3cret?x=1"), "wss://h/peer/…?x=1");
        for plain in ["wss://relay.ditto.pub", "ws://127.0.0.1:7777/nostr", "wss://h/peer/"] {
            assert_eq!(shown(plain), plain);
        }
    }

    #[test]
    fn ok_messages() {
        assert_eq!(verdict_of_ok(true, ""), Verdict::Stored);
        assert_eq!(verdict_of_ok(true, "duplicate: already have this event"), Verdict::Duplicate);
        assert_eq!(verdict_of_ok(false, "duplicate: a newer version of this event is already stored"), Verdict::Superseded);
        assert_eq!(verdict_of_ok(false, "blocked: this event was deleted"), Verdict::Refused("blocked: this event was deleted".into()));
        assert!(slow_down(false, "rate-limited: slow down, too many events from your address"));
        assert!(!slow_down(true, "rate-limited: fine"));
        assert!(!slow_down(false, "blocked: no"));
    }

    #[test]
    fn ids_of_stored_json() {
        let id = "ab".repeat(32);
        assert_eq!(event_id(&format!(r#"{{"content":"","created_at":1,"id":"{id}","kind":1}}"#)), Some([0xab; 32]));
        // Not fooled by text that looks like a key.
        assert_eq!(event_id(&format!(r#"{{"content":"\"id\":\"{id}\"","id":"{}"}}"#, "cd".repeat(32))), Some([0xcd; 32]));
        assert_eq!(event_id(r#"{"content":""}"#), None);
    }
}
