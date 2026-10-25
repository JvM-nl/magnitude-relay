//! Banned public keys: one npub or hex key per line of the `[policy] banlist`
//! file, read again whenever it changes.
//!
//! Without AUTH a connection has no identity, so a ban covers what names the
//! key: events it signs, gift wraps addressed to it, and filters asking for
//! it. Those events are answered `OK` like any other and dropped, and the key
//! is taken out of every filter, so to its owner the relay looks ordinary and
//! empty, and to everyone else the key is simply not here.

use relay_proto::filter::Filter;
use relay_proto::record::{Record, FIELD_HEX32};
use relay_proto::{hex, kind, nip19, varint};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// How often the file is looked at for a change.
const POLL: Duration = Duration::from_secs(5);

/// One version of the list, sorted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BanSet(Vec<[u8; 32]>);

impl BanSet {
    /// The file's text: a key per line, `#` to the end of a line is a comment.
    pub fn parse(text: &str) -> Result<BanSet, String> {
        let mut keys = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let key = line.split('#').next().unwrap_or_default().trim();
            if key.is_empty() {
                continue;
            }
            keys.push(parse_key(key).ok_or_else(|| format!("line {}: \"{key}\" is not an npub or a 64-character hex public key", n + 1))?);
        }
        keys.sort_unstable();
        keys.dedup();
        Ok(BanSet(keys))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        !self.0.is_empty() && self.0.binary_search(key).is_ok()
    }

    /// Whether `rec` is from a banned key, or a gift wrap addressed to one.
    #[inline]
    pub fn silences(&self, rec: Record<'_>) -> bool {
        if self.0.is_empty() {
            return false;
        }
        self.contains(rec.pubkey())
            || (rec.kind() == kind::GIFT_WRAP && rec.tags().any(|t| matches!(t.indexable(), Some((b'p', v)) if self.names(v))))
    }

    /// Takes banned keys out of every filter's `authors` and `#p`. A list left
    /// empty matches nothing, so a filter for only a banned key finds nothing.
    pub fn strip(&self, filters: &mut [Filter]) {
        if self.0.is_empty() {
            return;
        }
        for f in filters {
            if let Some(authors) = &mut f.authors {
                authors.retain(|k| !self.contains(k));
            }
            for t in f.tags.iter_mut().filter(|t| t.name == b'p') {
                t.values.retain(|v| !self.names(v));
            }
        }
    }

    /// Whether an encoded tag value is a banned key: compacted hex, or the 64
    /// digits of one in upper or mixed case, which are kept as a string.
    fn names(&self, v: &[u8]) -> bool {
        let mut p = 0;
        let Some(h) = varint::get(v, &mut p) else { return false };
        let s = &v[p..];
        if h == FIELD_HEX32 {
            s.try_into().is_ok_and(|k| self.contains(k))
        } else {
            s.len() == 64 && hex::decode_32(&s.to_ascii_lowercase()).is_some_and(|k| self.contains(&k))
        }
    }
}

fn parse_key(s: &str) -> Option<[u8; 32]> {
    if s.len() == 64 {
        hex::decode_32(s.to_ascii_lowercase().as_bytes())
    } else {
        nip19::decode_npub(s)
    }
}

/// The list in force, and the file it comes from.
pub struct Bans {
    path: PathBuf,
    current: Mutex<Arc<BanSet>>,
    /// Moves on every change; each thread keeps its own copy until it does.
    generation: AtomicU64,
    id: u64,
}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// This thread's copy of each list: (list id, generation, set).
    static SEEN: RefCell<Vec<(u64, u64, Arc<BanSet>)>> = const { RefCell::new(Vec::new()) };
}

impl Bans {
    /// The list `[policy] banlist` names, if it names one.
    pub fn from_config(cfg: &crate::config::Config) -> Result<Option<Arc<Bans>>, String> {
        match cfg.policy.banlist.as_str() {
            "" => Ok(None),
            path => Bans::load(Path::new(path)).map(Some).map_err(|e| format!("banlist: {e}")),
        }
    }

    pub fn load(path: &Path) -> Result<Arc<Bans>, String> {
        Ok(Arc::new(Bans {
            path: path.to_owned(),
            current: Mutex::new(Arc::new(read(path)?)),
            generation: AtomicU64::new(0),
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        }))
    }

    pub fn len(&self) -> usize {
        self.current.lock().unwrap().len()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs `f` on the list in force. While the list is unchanged this is a
    /// load of the generation and this thread's own copy: no lock, and no
    /// write to memory the reactors share.
    #[inline]
    pub fn with<R>(&self, f: impl FnOnce(&BanSet) -> R) -> R {
        let generation = self.generation.load(Ordering::Acquire);
        SEEN.with(|seen| {
            let mut seen = seen.borrow_mut();
            let i = match seen.iter().position(|e| e.0 == self.id) {
                Some(i) => i,
                None => {
                    seen.push((self.id, u64::MAX, Arc::default()));
                    seen.len() - 1
                }
            };
            if seen[i].1 != generation {
                seen[i].2 = Arc::clone(&self.current.lock().unwrap());
                seen[i].1 = generation;
            }
            f(&seen[i].2)
        })
    }

    /// Reads the file again whenever it changes, for as long as the relay
    /// runs. A file that cannot be read, or has a bad line, leaves the list as
    /// it was: a slip while editing never lifts a ban.
    pub fn watch(self: &Arc<Self>) {
        self.watch_every(POLL);
    }

    fn watch_every(self: &Arc<Self>, every: Duration) {
        let bans = Arc::clone(self);
        let mut applied = stamp_of(&bans.path);
        let mut settling = None;
        std::thread::Builder::new()
            .name("banlist".into())
            .spawn(move || loop {
                std::thread::sleep(every);
                let now = stamp_of(&bans.path);
                if now == applied {
                    settling = None;
                    continue;
                }
                // Read once the file has held still for a whole interval: one
                // caught between being emptied and rewritten would otherwise
                // read as an empty list and lift every ban.
                if settling != Some(now) {
                    settling = Some(now);
                    continue;
                }
                settling = None;
                applied = now;
                match read(&bans.path) {
                    Ok(set) => bans.replace(set),
                    Err(e) => eprintln!("banlist: {e}; keeping the {} keys already in force", bans.len()),
                }
            })
            .expect("banlist thread");
    }

    fn replace(&self, set: BanSet) {
        let mut current = self.current.lock().unwrap();
        if **current == set {
            return;
        }
        eprintln!("banlist: {} keys (was {})", set.len(), current.len());
        *current = Arc::new(set);
        self.generation.fetch_add(1, Ordering::Release);
    }
}

fn stamp_of(path: &Path) -> Option<(SystemTime, u64)> {
    let m = std::fs::metadata(path).ok()?;
    Some((m.modified().unwrap_or(SystemTime::UNIX_EPOCH), m.len()))
}

fn read(path: &Path) -> Result<BanSet, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    BanSet::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_proto::event::parse_event_json;
    use relay_proto::json::Scanner;
    use secp256k1::{schnorr, Keypair};
    use sha2::{Digest, Sha256};

    const NPUB: &str = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";
    const HEX: &str = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e";

    fn key(seed: u8) -> Keypair {
        Keypair::from_secret_bytes([seed; 32]).unwrap()
    }

    fn pk(k: &Keypair) -> String {
        hex::encode_string(&k.x_only_public_key().0.to_byte_array())
    }

    fn record(k: &Keypair, kind: u64, tags: &str) -> Vec<u8> {
        let pk = pk(k);
        let pre = format!("[0,\"{pk}\",1700000000,{kind},{tags},\"\"]");
        let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
        let sig = hex::encode_string(&schnorr::sign_no_aux_rand(&id, k).to_byte_array());
        let json = format!(
            "{{\"id\":\"{}\",\"pubkey\":\"{pk}\",\"created_at\":1700000000,\"kind\":{kind},\"tags\":{tags},\"content\":\"\",\"sig\":\"{sig}\"}}",
            hex::encode_string(&id)
        );
        let mut rec = Vec::new();
        parse_event_json(&json, &mut relay_proto::EventParser::default(), &mut rec, false).unwrap();
        rec
    }

    fn filters(json: &str) -> Vec<Filter> {
        vec![Filter::parse(&mut Scanner::new(json)).unwrap()]
    }

    #[test]
    fn the_file_takes_npubs_hex_in_any_case_and_comments() {
        let text = format!("# banned\n\n{NPUB}  # spam\n{}\n   {HEX}\n", HEX.to_ascii_uppercase());
        let set = BanSet::parse(&text).unwrap();
        assert_eq!(set.len(), 1);
        assert!(set.contains(&hex::decode_32(HEX.as_bytes()).unwrap()));
        assert_eq!(BanSet::parse("# nothing yet\n").unwrap().len(), 0);
    }

    #[test]
    fn a_bad_line_is_named() {
        let e = BanSet::parse(&format!("{HEX}\nnpub1nope\n")).unwrap_err();
        assert!(e.starts_with("line 2: \"npub1nope\""), "{e}");
    }

    #[test]
    fn silences_the_keys_events_and_wraps_addressed_to_it() {
        let (banned, other) = (key(1), key(2));
        let set = BanSet::parse(&pk(&banned)).unwrap();
        let to = |p: &str| format!("[[\"p\",\"{p}\"]]");
        assert!(set.silences(Record(&record(&banned, 0, "[]"))));
        assert!(set.silences(Record(&record(&other, 1059, &to(&pk(&banned))))));
        assert!(set.silences(Record(&record(&other, 1059, &to(&pk(&banned).to_ascii_uppercase())))));
        // Everyone else, and anything else that merely mentions the key.
        assert!(!set.silences(Record(&record(&other, 1059, &to(&pk(&other))))));
        assert!(!set.silences(Record(&record(&other, 0, "[]"))));
        assert!(!set.silences(Record(&record(&other, 8, &to(&pk(&banned))))));
        assert!(!BanSet::default().silences(Record(&record(&banned, 0, "[]"))));
    }

    #[test]
    fn filters_lose_the_key_and_a_list_of_only_it_matches_nothing() {
        let (banned, other) = (key(1), key(2));
        let set = BanSet::parse(&pk(&banned)).unwrap();
        let (b, o) = (pk(&banned), pk(&other));

        let mut fs = filters(&format!("{{\"authors\":[\"{b}\",\"{o}\"],\"#p\":[\"{b}\",\"{}\",\"{o}\"]}}", b.to_ascii_uppercase()));
        set.strip(&mut fs);
        assert_eq!(fs[0].authors.as_deref(), Some(&[hex::decode_32(o.as_bytes()).unwrap()][..]));
        assert_eq!(fs[0].tags[0].values.len(), 1);
        assert!(!fs[0].never_matches());

        for f in [format!("{{\"authors\":[\"{b}\"]}}"), format!("{{\"kinds\":[1059],\"#p\":[\"{b}\"]}}")] {
            let mut fs = filters(&f);
            set.strip(&mut fs);
            assert!(fs[0].never_matches(), "{f}");
        }
    }

    #[test]
    fn every_thread_sees_a_change_and_a_broken_file_keeps_the_old_list() {
        let dir = std::env::temp_dir().join(format!("bans-{}-{}", std::process::id(), NEXT_ID.load(Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("banlist");
        std::fs::write(&path, "").unwrap();
        let bans = Bans::load(&path).unwrap();
        let k = hex::decode_32(HEX.as_bytes()).unwrap();
        assert!(!bans.with(|s| s.contains(&k)));

        bans.watch_every(Duration::from_millis(10));
        std::fs::write(&path, format!("{NPUB}\n")).unwrap();
        let banned_here = || bans.with(|s| s.contains(&k));
        let t = std::time::Instant::now();
        while !banned_here() {
            assert!(t.elapsed() < Duration::from_secs(5), "change not picked up");
            std::thread::sleep(Duration::from_millis(5));
        }
        let b = Arc::clone(&bans);
        assert!(std::thread::spawn(move || b.with(|s| s.contains(&k))).join().unwrap());

        std::fs::write(&path, format!("{NPUB}\nnot a key\n")).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(banned_here(), "a bad edit lifted the ban");
        std::fs::remove_file(&path).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert!(banned_here(), "a missing file lifted the ban");

        std::fs::write(&path, "").unwrap();
        let t = std::time::Instant::now();
        while banned_here() {
            assert!(t.elapsed() < Duration::from_secs(5), "unban not picked up");
            std::thread::sleep(Duration::from_millis(5));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
