//! The dataset generator: fully signed events, deterministic from a seed, shaped
//! like Vector's traffic so every workload has a known answer.
//!
//! # Shape
//!
//! Events are interleaved in a fixed 20-event cycle, so the proportions are exact
//! rather than statistical (event `n` is of class `n % 20`):
//!
//! | `n % 20` | share | what |
//! |---|---|---|
//! | 0..=13  | 70% | **gift wraps** (kind 1059): a fresh single-use author key per event, one `p` tag to a recipient from a pool (Zipf, exponent 0.75: a few mailboxes of 50k+ wraps at 5M events), 1-2 KB of base64-looking content, `created_at` backdated up to 2 days (NIP-17) |
//! | 14..=16 | 15% | **Concord plane traffic** (kind 1059): the author is one of a pool of plane keys (Zipf, so a few planes are deep enough to page through), a random `p` tag, 0.5-1.5 KB content |
//! | 17..=18 | 10% | **generic** events for the classic workloads: kinds 1, 7 and 30023 from a pool of authors, `t` tags from a word list, `e` tags pointing at events that exist in the file |
//! | 19      | 5%  | **replaceable / addressable**: kinds 0, 10050 and 30078 (`d` = `vector/pinned`, ...) from the same author pool, many versions per key so most are superseded |
//!
//! # Determinism
//!
//! Event `n` is a pure function of `(seed, n)`: its randomness comes from a private
//! stream ([`Rng::for_item`]), its keys are `sha256(seed || label || index)`, and
//! nothing reads the clock. So chunks are signed on every core and written in
//! order, and the file is byte-identical for any thread count. `created_at` is laid
//! on a timeline that **ends** at `--end` (a fixed constant by default, not "now",
//! otherwise two runs a second apart would differ), at `--rate` events per second.
//!
//! # Ties
//!
//! About 9% of wraps and plane events copy the `created_at` (and recipient, or
//! plane) of the first event of their group of four, so a mailbox or plane has
//! many same-second events with different ids. Without them the tie-break rules of
//! NIP-01 (lowest id first) would never be exercised, and a `limit` cutting through
//! a same-second group is exactly the case where relays differ.
//!
//! # Replaceables
//!
//! Versions of one key (author, kind, `d`) get distinct `created_at` (no jitter, and
//! the rate is capped at 20 events/s so consecutive replaceables are always at least
//! a second apart). Relays differ on which of two same-second versions wins; the
//! generator never makes them tie, so the expected live set is unambiguous.

use crate::jsonw::escape_into;
use crate::par::{cpus, par_map};
use crate::rng::{Rng, Zipf};
use crate::sign::{event_id, push_tag, SignedEvent, Signer};
use relay_proto::hex;
use std::collections::BTreeMap;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::{Condvar, Mutex};
use std::time::Instant;

/// Last `created_at` of the dataset unless `--end` says otherwise. A fixed past
/// instant (2026-10-14): reproducible, and old enough that no relay's "event from the
/// future" check can fire.
pub const DEFAULT_END: u64 = 1_792_000_000;

pub const GIFT_WRAP: u64 = 1059;

const STREAM_ATTR: u64 = 1;
const STREAM_CLONE: u64 = 2;
const STREAM_BODY: u64 = 3;

/// NIP-17 backdates a wrap's `created_at` by up to two days.
const WRAP_BACKDATE: u64 = 172_800;
/// Percent of non-leader wraps / plane events that copy their group leader's timing.
const CLONE_PERCENT: u64 = 12;
/// Events generated and rendered per work item.
const CHUNK: u64 = 1024;

const WORDS: [&str; 64] = [
    "bitcoin", "nostr", "vector", "privacy", "music", "art", "food", "travel", "news", "dev", "rust", "linux", "coffee", "games", "books",
    "film", "space", "science", "sports", "weather", "photo", "memes", "cats", "dogs", "garden", "cycling", "running", "chess", "poker",
    "design", "crypto", "monero", "pivx", "tor", "i2p", "radio", "retro", "lofi", "anime", "history", "math", "physics", "biology", "diy",
    "maker", "3dprint", "solar", "wind", "ocean", "mountain", "forest", "city", "night", "morning", "gm", "gn", "zap", "meetup", "podcast",
    "writing", "poetry", "jazz", "metal", "synth",
];

const D_VALUES: [&str; 3] = ["vector/pinned", "vector/settings", "vector/drafts"];

#[derive(Clone, Debug)]
pub struct GenParams {
    pub events: u64,
    pub seed: u64,
    /// Dataset timeline density in events per second, times 1000 (integer, so the
    /// timeline is exact on every platform).
    pub rate_milli: u64,
    /// `created_at` of the newest possible event.
    pub end: u64,
    pub recipients: usize,
    pub planes: usize,
    pub authors: usize,
    pub threads: usize,
}

impl GenParams {
    pub fn new(events: u64, seed: u64) -> GenParams {
        GenParams { events, seed, rate_milli: 2000, end: DEFAULT_END, recipients: 10_000, planes: 2_000, authors: 5_000, threads: cpus() }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.events == 0 {
            return Err("--events must be at least 1".into());
        }
        if !(1..=20_000).contains(&self.rate_milli) {
            return Err("--rate must be between 0.001 and 20 events per second".into());
        }
        if self.recipients == 0 || self.planes == 0 || self.authors == 0 {
            return Err("--recipients, --planes and --authors must be at least 1".into());
        }
        let span = (self.events - 1) * 1000 / self.rate_milli;
        if self.end < span + WRAP_BACKDATE {
            return Err(format!("the timeline ({span} s) does not fit before --end {}", self.end));
        }
        Ok(())
    }
}

/// How many events of each class `events` produces.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct ClassCounts {
    pub wraps: u64,
    pub planes: u64,
    pub generic: u64,
    pub replaceable: u64,
}

pub fn class_counts(events: u64) -> ClassCounts {
    let mut c = ClassCounts::default();
    let (full, rem) = (events / 20, events % 20);
    c.wraps = full * 14;
    c.planes = full * 3;
    c.generic = full * 2;
    c.replaceable = full;
    for m in 0..rem {
        match m {
            0..=13 => c.wraps += 1,
            14..=16 => c.planes += 1,
            17..=18 => c.generic += 1,
            _ => c.replaceable += 1,
        }
    }
    c
}

pub struct Generator {
    p: GenParams,
    /// `created_at` of event 0.
    base: u64,
    recipients: Vec<String>,
    planes: Vec<Signer>,
    authors: Vec<Signer>,
    author_hex: Vec<String>,
    zipf_recipient: Zipf,
    zipf_plane: Zipf,
    zipf_author: Zipf,
    zipf_word: Zipf,
}

/// A generic event before signing; split out so a root event's id can be computed
/// without paying for a signature (other events reference it from `e` tags).
struct Generic {
    kind: u64,
    author: usize,
    created_at: u64,
    tags: String,
    content: String,
}

impl Generator {
    pub fn new(p: GenParams) -> Result<Generator, String> {
        p.validate()?;
        let (seed, threads) = (p.seed, p.threads);
        let recipients = par_map(p.recipients, threads, |k| Signer::derive(seed, "recipient", k as u64).pk_hex());
        let planes = par_map(p.planes, threads, |k| Signer::derive(seed, "plane", k as u64));
        let authors = par_map(p.authors, threads, |k| Signer::derive(seed, "author", k as u64));
        let author_hex = authors.iter().map(Signer::pk_hex).collect();
        let base = p.end - (p.events - 1) * 1000 / p.rate_milli;
        Ok(Generator {
            zipf_recipient: Zipf::new(p.recipients),
            zipf_plane: Zipf::new(p.planes),
            zipf_author: Zipf::new(p.authors),
            zipf_word: Zipf::new(WORDS.len()),
            p,
            base,
            recipients,
            planes,
            authors,
            author_hex,
        })
    }

    /// `created_at` of the n-th event before any per-class jitter.
    fn timeline(&self, n: u64) -> u64 {
        self.base + n * 1000 / self.p.rate_milli
    }

    /// (recipient index, created_at) of the wrap with ordinal `w`, ignoring cloning.
    fn wrap_attrs(&self, w: u64) -> (usize, u64) {
        let n = (w / 14) * 20 + w % 14;
        let mut r = Rng::for_item(self.p.seed, n, STREAM_ATTR);
        let recipient = self.zipf_recipient.sample(&mut r);
        (recipient, self.timeline(n).saturating_sub(r.below(WRAP_BACKDATE)))
    }

    fn wrap(&self, n: u64) -> SignedEvent {
        let w = (n / 20) * 14 + n % 20;
        let leader = w - w % 4;
        let cloned = w != leader && Rng::for_item(self.p.seed, n, STREAM_CLONE).chance(CLONE_PERCENT, 100);
        let (recipient, created_at) = self.wrap_attrs(if cloned { leader } else { w });
        let mut r = Rng::for_item(self.p.seed, n, STREAM_BODY);
        let len = 1024 + r.below(1025) as usize;
        let content = payload(&mut r, len);
        let mut tags = String::from("[");
        push_tag(&mut tags, &["p", &self.recipients[recipient]]);
        tags.push(']');
        Signer::derive(self.p.seed, "wrap", n).sign(created_at, GIFT_WRAP, &tags, &content)
    }

    /// (plane index, created_at) of the plane event with ordinal `u`, ignoring cloning.
    fn plane_attrs(&self, u: u64) -> (usize, u64) {
        let n = (u / 3) * 20 + 14 + u % 3;
        let mut r = Rng::for_item(self.p.seed, n, STREAM_ATTR);
        let plane = self.zipf_plane.sample(&mut r);
        (plane, self.timeline(n).saturating_sub(r.below(3600)))
    }

    fn plane_event(&self, n: u64) -> SignedEvent {
        let u = (n / 20) * 3 + (n % 20 - 14);
        let leader = u - u % 4;
        let cloned = u != leader && Rng::for_item(self.p.seed, n, STREAM_CLONE).chance(CLONE_PERCENT, 100);
        let (plane, created_at) = self.plane_attrs(if cloned { leader } else { u });
        let mut r = Rng::for_item(self.p.seed, n, STREAM_BODY);
        let len = 512 + r.below(1025) as usize;
        let content = payload(&mut r, len);
        let recipient = hex::encode_string(&r.bytes32());
        let mut tags = String::from("[");
        push_tag(&mut tags, &["p", &recipient]);
        tags.push(']');
        self.planes[plane].sign(created_at, GIFT_WRAP, &tags, &content)
    }

    fn generic_fields(&self, n: u64) -> Generic {
        let g = (n / 20) * 2 + (n % 20 - 17);
        // Every 8th generic event is a plain note with no `e` tag; later events reference
        // these, so a referenced id always exists in the file and never needs recursion.
        let root = g % 8 == 0;
        let mut r = Rng::for_item(self.p.seed, n, STREAM_BODY);
        let kind_roll = r.below(100);
        let author = self.zipf_author.sample(&mut r);
        let jitter = r.below(3600);
        let second_tag = r.chance(1, 2);
        let (w1, w2) = (self.zipf_word.sample(&mut r), self.zipf_word.sample(&mut r));
        let e_roll = r.below(10);
        let e_pick = r.next_u64();
        let kind = match kind_roll {
            _ if root => 1,
            0..=59 => 1,
            60..=84 => 7,
            _ => 30023,
        };
        let mut tags = String::from("[");
        push_tag(&mut tags, &["t", WORDS[w1]]);
        if second_tag && w2 != w1 {
            push_tag(&mut tags, &["t", WORDS[w2]]);
        }
        if !root && g >= 8 && (kind == 7 || (kind == 1 && e_roll < 3)) {
            let target = self.root_id(8 * (e_pick % (g / 8)));
            push_tag(&mut tags, &["e", &hex::encode_string(&target)]);
        }
        let content = match kind {
            7 => "+".to_owned(),
            30023 => {
                push_tag(&mut tags, &["d", &format!("article-{n}")]);
                push_tag(&mut tags, &["title", &format!("On {} and {}", WORDS[w1], WORDS[w2])]);
                format!("# Article {n}\n\nA few words about {} and {}.", WORDS[w1], WORDS[w2])
            }
            _ => format!("note {n}: {} {}", WORDS[w1], WORDS[w2]),
        };
        tags.push(']');
        Generic { kind, author, created_at: self.timeline(n).saturating_sub(jitter), tags, content }
    }

    /// Id of the root generic event with ordinal `j` (a multiple of 8): the hash of its
    /// serialisation, no signature needed.
    fn root_id(&self, j: u64) -> [u8; 32] {
        let n = (j / 2) * 20 + 17 + j % 2;
        let ev = self.generic_fields(n);
        let mut esc = String::new();
        escape_into(&ev.content, &mut esc);
        event_id(&self.author_hex[ev.author], ev.created_at, ev.kind, &ev.tags, &esc)
    }

    fn generic(&self, n: u64) -> SignedEvent {
        let ev = self.generic_fields(n);
        self.authors[ev.author].sign(ev.created_at, ev.kind, &ev.tags, &ev.content)
    }

    fn replaceable(&self, n: u64) -> SignedEvent {
        let mut r = Rng::for_item(self.p.seed, n, STREAM_BODY);
        let roll = r.below(10);
        let author = r.below(self.p.authors as u64) as usize;
        let d = D_VALUES[r.below(3) as usize];
        let mut tags = String::from("[");
        let (kind, content) = match roll {
            0..=2 => (0, format!("{{\"name\":\"user{author}\",\"about\":\"bench profile, version {n}\"}}")),
            3..=5 => {
                push_tag(&mut tags, &["relay", "wss://dm.example.com"]);
                (10050, String::new())
            }
            _ => {
                push_tag(&mut tags, &["d", d]);
                (30078, format!("{{\"v\":{n}}}"))
            }
        };
        tags.push(']');
        self.authors[author].sign(self.timeline(n), kind, &tags, &content)
    }

    /// Event number `n`, signed.
    pub fn event(&self, n: u64) -> SignedEvent {
        match n % 20 {
            0..=13 => self.wrap(n),
            14..=16 => self.plane_event(n),
            17 | 18 => self.generic(n),
            _ => self.replaceable(n),
        }
    }
}

/// 6 bits of entropy per character from the base64 alphabet, 10 characters per RNG
/// word. What a NIP-44 payload looks like to a relay: opaque, incompressible text.
fn payload(rng: &mut Rng, len: usize) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(len);
    let (mut word, mut left) = (0u64, 0);
    for _ in 0..len {
        if left == 0 {
            word = rng.next_u64();
            left = 10;
        }
        s.push(B64[(word & 63) as usize] as char);
        word >>= 6;
        left -= 1;
    }
    s
}

#[derive(Debug, PartialEq, Eq)]
pub struct GenStats {
    pub classes: ClassCounts,
    pub bytes: u64,
}

struct State {
    next_chunk: u64,
    written: u64,
    ready: BTreeMap<u64, Vec<u8>>,
    failed: bool,
}

/// Marks the run failed if a worker panics, so the writer does not wait forever.
struct PanicFlag<'a>(&'a Mutex<State>, &'a Condvar);

impl Drop for PanicFlag<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Ok(mut st) = self.0.lock() {
                st.failed = true;
            }
            self.1.notify_all();
        }
    }
}

/// Writes the dataset to `out` as JSONL, signing on `p.threads` threads. Output is
/// in event order and independent of the thread count.
pub fn generate_to<W: Write>(p: &GenParams, mut out: W, progress: bool) -> io::Result<GenStats> {
    let generator = Generator::new(p.clone()).map_err(io::Error::other)?;
    let total_chunks = p.events.div_ceil(CHUNK);
    // Workers may run this many chunks ahead of the writer: bounds buffered output.
    let window = (p.threads.max(1) as u64) * 4;
    let state = Mutex::new(State { next_chunk: 0, written: 0, ready: BTreeMap::new(), failed: false });
    let cv = Condvar::new();
    let started = Instant::now();
    let mut bytes = 0u64;
    let mut last_report = Instant::now();

    std::thread::scope(|s| {
        for _ in 0..p.threads.max(1) {
            s.spawn(|| {
                let _flag = PanicFlag(&state, &cv);
                loop {
                    let chunk = {
                        let mut st = state.lock().unwrap();
                        loop {
                            if st.failed || st.next_chunk >= total_chunks {
                                return;
                            }
                            if st.next_chunk < st.written + window {
                                break;
                            }
                            st = cv.wait(st).unwrap();
                        }
                        st.next_chunk += 1;
                        st.next_chunk - 1
                    };
                    let (lo, hi) = (chunk * CHUNK, ((chunk + 1) * CHUNK).min(p.events));
                    let mut buf = Vec::with_capacity(((hi - lo) as usize) * 2200);
                    for n in lo..hi {
                        buf.extend_from_slice(generator.event(n).json.as_bytes());
                        buf.push(b'\n');
                    }
                    state.lock().unwrap().ready.insert(chunk, buf);
                    cv.notify_all();
                }
            });
        }
        // The calling thread writes chunks in order as they complete. On any early exit the
        // workers are told to stop, or they would wait for window space that never opens.
        let result = (|| -> io::Result<()> {
            for chunk in 0..total_chunks {
                let buf = {
                    let mut st = state.lock().unwrap();
                    loop {
                        if st.failed {
                            return Err(io::Error::other("a generator thread panicked"));
                        }
                        if let Some(b) = st.ready.remove(&chunk) {
                            st.written += 1;
                            break b;
                        }
                        st = cv.wait(st).unwrap();
                    }
                };
                cv.notify_all();
                bytes += buf.len() as u64;
                out.write_all(&buf)?;
                if progress && last_report.elapsed().as_secs() >= 5 {
                    last_report = Instant::now();
                    let done = ((chunk + 1) * CHUNK).min(p.events);
                    eprintln!("  {done}/{} events, {:.1} GB, {:.0} ev/s", p.events, bytes as f64 / 1e9, done as f64 / started.elapsed().as_secs_f64());
                }
            }
            Ok(())
        })();
        if result.is_err() {
            state.lock().unwrap().failed = true;
            cv.notify_all();
        }
        result
    })?;
    out.flush()?;
    Ok(GenStats { classes: class_counts(p.events), bytes })
}

pub fn generate(p: &GenParams, path: &Path) -> io::Result<GenStats> {
    let file = std::fs::File::create(path)?;
    generate_to(p, BufWriter::with_capacity(1 << 20, file), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::verify_event_line;
    use crate::wire::parse_event_line;
    use std::collections::{HashMap, HashSet};

    /// Small pools keep key derivation cheap in unit tests.
    fn small(events: u64, seed: u64) -> GenParams {
        GenParams { recipients: 40, planes: 12, authors: 30, threads: 2, rate_milli: 500, ..GenParams::new(events, seed) }
    }

    fn lines(p: &GenParams) -> Vec<String> {
        let mut buf = Vec::new();
        generate_to(p, &mut buf, false).unwrap();
        String::from_utf8(buf).unwrap().lines().map(str::to_owned).collect()
    }

    #[test]
    fn same_seed_same_bytes_whatever_the_thread_count() {
        let a = lines(&GenParams { threads: 1, ..small(2500, 77) });
        let b = lines(&GenParams { threads: 5, ..small(2500, 77) });
        assert_eq!(a.len(), 2500);
        assert_eq!(a, b);
        assert_eq!(a[..100], b[..100]);
        let other = lines(&small(200, 78));
        assert_ne!(a[..100], other[..100]);
        for (x, y) in a.iter().zip(&other) {
            assert_ne!(x, y);
        }
    }

    #[test]
    fn every_class_is_validly_signed_and_proportions_are_exact() {
        let ls = lines(&small(200, 5));
        let mut kinds: HashMap<u64, u32> = HashMap::new();
        for l in &ls {
            verify_event_line(l).unwrap_or_else(|e| panic!("{e}: {l}"));
            *kinds.entry(parse_event_line(l).unwrap().kind).or_default() += 1;
        }
        let wraps = kinds[&1059];
        assert_eq!(wraps, 140 + 30, "70% wraps + 15% plane traffic are both kind 1059");
        assert_eq!(kinds.get(&1).unwrap_or(&0) + kinds.get(&7).unwrap_or(&0) + kinds.get(&30023).unwrap_or(&0), 20);
        assert_eq!(kinds.get(&0).unwrap_or(&0) + kinds.get(&10050).unwrap_or(&0) + kinds.get(&30078).unwrap_or(&0), 10);
        assert_eq!(class_counts(200), ClassCounts { wraps: 140, planes: 30, generic: 20, replaceable: 10 });
        assert_eq!(class_counts(7), ClassCounts { wraps: 7, ..Default::default() });
        assert_eq!(class_counts(19), ClassCounts { wraps: 14, planes: 3, generic: 2, replaceable: 0 });
    }

    #[test]
    fn wraps_have_single_use_authors_pooled_recipients_and_backdating() {
        let p = small(2000, 9);
        let ls = lines(&p);
        let mut authors = HashSet::new();
        let mut recipients: HashMap<[u8; 32], u32> = HashMap::new();
        let mut max_backdate = 0;
        let mut wrap_count = 0;
        for (n, l) in ls.iter().enumerate() {
            if n % 20 > 13 {
                continue;
            }
            wrap_count += 1;
            let e = parse_event_line(l).unwrap();
            assert_eq!(e.kind, 1059);
            assert!(authors.insert(e.pubkey), "wrap authors are single-use");
            assert_eq!(e.p.len(), 1, "a wrap has exactly one p tag");
            *recipients.entry(e.p[0]).or_default() += 1;
            assert!(e.created_at <= p.end);
            let on_timeline = p.end - (p.events - 1) * 1000 / p.rate_milli + n as u64 * 1000 / p.rate_milli;
            max_backdate = max_backdate.max(on_timeline.saturating_sub(e.created_at));
            let len = l.len();
            assert!((1100..2700).contains(&len), "1-2 KB of content, got a {len} byte line");
        }
        assert_eq!(wrap_count, 1400);
        assert!(recipients.len() <= 40);
        let mut sizes: Vec<u32> = recipients.values().copied().collect();
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        assert!(sizes[0] > 3 * sizes[sizes.len() / 2], "mailboxes are skewed: {sizes:?}");
        // A cloned wrap copies its group leader's (earlier) timing, so allow a few cycles on top.
        assert!(max_backdate > 100_000 && max_backdate < 172_800 + 400, "{max_backdate}");
    }

    #[test]
    fn same_second_groups_exist_for_a_recipient() {
        let ls = lines(&small(6000, 3));
        let mut by_key: HashMap<([u8; 32], u64), u32> = HashMap::new();
        for l in &ls {
            let e = parse_event_line(l).unwrap();
            if e.kind == 1059 {
                if let Some(&p) = e.p.first() {
                    *by_key.entry((p, e.created_at)).or_default() += 1;
                }
            }
        }
        let ties = by_key.values().filter(|&&c| c >= 2).count();
        assert!(ties > 100, "only {ties} same-recipient same-second groups");
    }

    #[test]
    fn plane_events_share_authors_and_e_tags_point_at_real_events() {
        let ls = lines(&small(4000, 4));
        let mut ids = HashSet::new();
        let mut plane_authors: HashMap<[u8; 32], u32> = HashMap::new();
        for (n, l) in ls.iter().enumerate() {
            let e = parse_event_line(l).unwrap();
            ids.insert(e.id);
            if (14..17).contains(&(n % 20)) {
                *plane_authors.entry(e.pubkey).or_default() += 1;
            }
        }
        assert!(plane_authors.len() <= 12);
        assert!(plane_authors.values().any(|&c| c > 20), "planes are deep enough to page");
        let mut e_tags = 0;
        for l in &ls {
            let mut rest = l.as_str();
            while let Some(i) = rest.find("[\"e\",\"") {
                let id = hex::decode_32(&rest.as_bytes()[i + 6..i + 70]).expect("e tag value is an id");
                assert!(ids.contains(&id), "e tag references an event that is not in the file");
                e_tags += 1;
                rest = &rest[i + 70..];
            }
        }
        assert!(e_tags > 50, "{e_tags}");
    }

    #[test]
    fn replaceable_versions_never_tie() {
        let ls = lines(&small(8000, 6));
        let mut seen: HashSet<(Vec<u8>, u64, String, u64)> = HashSet::new();
        let mut keys: HashMap<(Vec<u8>, u64, String), u32> = HashMap::new();
        for (n, l) in ls.iter().enumerate() {
            if n % 20 != 19 {
                continue;
            }
            let e = parse_event_line(l).unwrap();
            let d = e.d.as_deref().unwrap_or("").to_owned();
            assert!(seen.insert((e.pubkey.to_vec(), e.kind, d.clone(), e.created_at)), "two versions of one key share a second");
            *keys.entry((e.pubkey.to_vec(), e.kind, d)).or_default() += 1;
        }
        assert!(keys.values().any(|&c| c >= 3), "keys have several versions, most get superseded");
    }

    #[test]
    fn timestamps_end_at_end_and_params_are_checked() {
        let p = small(1000, 1);
        let ls = lines(&p);
        let max = ls.iter().map(|l| parse_event_line(l).unwrap().created_at).max().unwrap();
        assert!(max <= p.end && max > p.end - 4000, "{max} vs {}", p.end);
        assert!(GenParams { events: 0, ..small(1, 1) }.validate().is_err());
        assert!(GenParams { rate_milli: 20_001, ..small(1, 1) }.validate().is_err());
        assert!(GenParams { end: 1000, ..small(1000, 1) }.validate().is_err());
        assert!(small(1000, 1).validate().is_ok());
    }
}
