//! The torture workload: every event and every operation is a pure function of
//! (seed, number), so the parent and any number of child processes agree on
//! what operation N is without talking about it. Events are crafted to hit
//! every storage rule: replaceable and addressable slots with same-second ties,
//! kind-5 deletions by `e` and `a` tag (by the author, by a gift wrap's
//! recipient, by strangers), NIP-62 vanish, NIP-40 expiry, duplicates and
//! re-sends of deleted events.

use crate::rng::{mix, Rng};
use relay_proto::event::parse_event_json;
use relay_proto::{hex, EventParser};

/// Event numbers of operation `i` are `i * MAX_BATCH ..`: unique, and ordered
/// like the operations.
pub const MAX_BATCH: u64 = 64;
/// Authors who write notes, profiles and deletions; the first `RECIPIENTS` of
/// them also receive gift wraps.
pub const AUTHORS: u64 = 8;
pub const RECIPIENTS: u64 = 6;
/// Concord plane keys: authors of many gift wraps (they can never vanish).
pub const PLANES: u64 = 3;
/// Expirations at or below this are in the past for any clock after 1970-01-24.
pub const PAST: u64 = 2_000_000;
/// And these are far in the future.
pub const FUTURE: u64 = 4_000_000_000;
pub const URL: &str = "wss://relay.example/nostr";

pub fn key(seed: u64, who: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, c) in k.chunks_mut(8).enumerate() {
        c.copy_from_slice(&mix(seed ^ mix(who.wrapping_mul(31).wrapping_add(i as u64 + 1))).to_le_bytes());
    }
    k
}

/// Author numbers: `0..AUTHORS` people, then planes, then one-off wrap keys.
pub fn author_key(seed: u64, a: u64) -> [u8; 32] {
    key(seed ^ 0xA0A0, a)
}

pub fn id_of(seed: u64, n: u64) -> [u8; 32] {
    key(seed ^ 0x1D1D, n)
}

/// Who wrote event `n` and what kind it is: cheap, so deletions can aim at an
/// event's author without building the whole event.
pub fn head(seed: u64, n: u64) -> (u64, u64) {
    let mut r = Rng::derive(seed ^ 0x4EAD, n);
    let pick = r.below(100);
    let kind = match pick {
        0..=27 => *r.pick(&[1u64, 1, 1, 14, 7]),
        28..=40 => *r.pick(&[0u64, 0, 10002, 13303]),
        41..=55 => *r.pick(&[30078u64, 30078, 33301, 33302]),
        56..=83 => 1059,
        84..=95 => 5,
        _ => 62,
    };
    let author = if kind == 1059 {
        if r.chance(2, 3) {
            AUTHORS + r.below(PLANES)
        } else {
            1000 + n // a one-off DM wrap key
        }
    } else if kind == 62 {
        // Vanish is rare and mostly by the last authors, so most history survives.
        AUTHORS - 1 - r.below(3)
    } else {
        r.below(AUTHORS)
    };
    (author, kind)
}

#[derive(Clone, Debug)]
pub struct Ev {
    pub n: u64,
    pub id: [u8; 32],
    pub author: u64,
    pub pubkey: [u8; 32],
    pub kind: u64,
    pub created_at: u64,
    /// Tags as strings, exactly as written to the JSON.
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl Ev {
    pub fn json(&self) -> String {
        let tags = serde_json::to_string(&self.tags).unwrap();
        format!(
            r#"{{"id":"{}","pubkey":"{}","created_at":{},"kind":{},"tags":{},"content":{},"sig":"{}"}}"#,
            hex::encode_string(&self.id),
            hex::encode_string(&self.pubkey),
            self.created_at,
            self.kind,
            tags,
            serde_json::to_string(&self.content).unwrap(),
            "00".repeat(64)
        )
    }

    /// The record the store keeps for it.
    pub fn record(&self) -> Vec<u8> {
        let mut p = EventParser::new();
        let mut rec = Vec::new();
        parse_event_json(&self.json(), &mut p, &mut rec, false).expect("workload events parse");
        rec
    }

    pub fn tag<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.tags.iter().filter(move |t| t.first().is_some_and(|x| x == name)).filter_map(|t| t.get(1).map(String::as_str))
    }

    pub fn expiration(&self) -> Option<u64> {
        // As the parser reads it: the first `expiration` tag, if its value is decimal.
        let v = self.tags.iter().find(|t| t.first().is_some_and(|x| x == "expiration"))?.get(1)?;
        if v.is_empty() || v.len() > 20 || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    }
}

/// A recent event number before `n` (deletions and re-sends aim mostly at recent history).
pub fn recent(r: &mut Rng, n: u64) -> Option<u64> {
    if n == 0 {
        return None;
    }
    let back = 1 + r.skewed(n.min(4000) - 1 + 1);
    Some(n.saturating_sub(back.min(n)))
}

pub fn event(seed: u64, n: u64) -> Ev {
    let (author, kind) = head(seed, n);
    let mut r = Rng::derive(seed ^ 0xE7E7, n);
    // Time moves forward slowly, with jitter and many exact ties.
    let base = 1_000_000 + n / 8;
    let created_at = match r.below(4) {
        0 => base,
        1 => base - base % 16,
        _ => base.saturating_sub(r.below(300)) + r.below(30),
    };
    let mut tags: Vec<Vec<String>> = Vec::new();
    let s = |v: &str| v.to_string();
    let hexk = |k: [u8; 32]| hex::encode_string(&k);
    match kind {
        1 | 14 | 7 => {
            if r.chance(1, 3) {
                tags.push(vec![s("t"), s(*r.pick(&["nostr", "vector", "x"]))]);
            }
            if r.chance(1, 4) {
                tags.push(vec![s("p"), hexk(author_key(seed, r.below(RECIPIENTS)))]);
            }
            if let Some(t) = recent(&mut r, n).filter(|_| r.chance(1, 4)) {
                tags.push(vec![s("e"), hexk(id_of(seed, t))]);
            }
            match r.below(12) {
                0 => tags.push(vec![s("expiration"), (PAST - r.below(1000)).to_string()]),
                1 => tags.push(vec![s("expiration"), (FUTURE + r.below(1000)).to_string()]),
                2 => tags.push(vec![s("expiration"), s("soon-ish")]),
                _ => {}
            }
        }
        0 | 10002 | 13303 => {}
        30078 | 33301 | 33302 => match r.below(6) {
            0 => {}
            1 => tags.push(vec![s("d")]),
            2 => tags.push(vec![s("d"), s("")]),
            _ => tags.push(vec![s("d"), s(*r.pick(&["a", "b", "vector/pinned"]))]),
        },
        1059 => {
            for _ in 0..1 + r.below(2) {
                tags.push(vec![s("p"), hexk(author_key(seed, r.below(RECIPIENTS)))]);
            }
            if r.chance(1, 10) {
                tags.push(vec![s("expiration"), (if r.chance(1, 2) { PAST } else { FUTURE }).to_string()]);
            }
        }
        5 => {
            for _ in 0..1 + r.below(4) {
                if let Some(t) = recent(&mut r, n) {
                    tags.push(vec![s("e"), hexk(id_of(seed, t))]);
                }
            }
            if r.chance(1, 4) {
                let ak = *r.pick(&[30078u64, 33301, 0, 10002, 1]);
                let apk = if r.chance(3, 4) { author } else { r.below(AUTHORS) };
                let d = *r.pick(&["", "a", "b", "vector/pinned"]);
                tags.push(vec![s("a"), format!("{ak}:{}:{d}", hexk(author_key(seed, apk)))]);
            }
            tags.push(vec![s("k"), s("1")]);
        }
        62 => tags.push(vec![s("relay"), s(if r.chance(4, 5) { "ALL_RELAYS" } else { "wss://elsewhere.example" })]),
        _ => {}
    }
    let len = r.skewed(400) as usize;
    let content: String = (0..len).map(|i| char::from(b'a' + ((n as usize + i) % 26) as u8)).collect();
    Ev { n, id: id_of(seed, n), author, pubkey: author_key(seed, author), kind, created_at, tags, content }
}

/// A deletion aimed at a specific earlier event, by its author or its
/// recipient (so deletions often land, which random targets rarely would).
pub fn targeted_delete(seed: u64, n: u64, target: u64) -> Ev {
    let (t_author, t_kind) = head(seed, target);
    let mut r = Rng::derive(seed ^ 0xDE1E, n);
    let author = if t_kind == 1059 {
        // A recipient (Concord), or now and then the wrap's author (refused).
        let t = event(seed, target);
        let ps: Vec<u64> = (0..RECIPIENTS).filter(|&a| t.tag("p").any(|p| p == hex::encode_string(&author_key(seed, a)))).collect();
        if !ps.is_empty() && r.chance(4, 5) {
            *r.pick(&ps)
        } else {
            t_author
        }
    } else if r.chance(5, 6) {
        t_author
    } else {
        r.below(AUTHORS)
    };
    let base = 1_000_000 + n / 8;
    Ev {
        n,
        id: id_of(seed, n),
        author,
        pubkey: author_key(seed, author),
        kind: 5,
        created_at: base,
        tags: vec![vec!["e".into(), hex::encode_string(&id_of(seed, target))]],
        content: String::new(),
    }
}

/// One operation of the workload.
#[derive(Clone, Debug)]
pub enum Op {
    /// Events in order: fresh ones and re-sends of earlier ones.
    Batch(Vec<Ev>),
    /// Operator removal: filters (JSON) and an optional age cutoff.
    Delete { filters: Vec<String>, older_than: Option<u64> },
    /// The way the server's admin socket deletes: matches found on a snapshot,
    /// then killed a few at a time with client batches in between, then a checkpoint.
    AdminDelete { filters: Vec<String>, between: Vec<Vec<Ev>> },
    /// NIP-40 sweep at this (fake) time.
    Sweep(u64),
    FlushAll,
    CompactAll,
    CompactLog,
    MergeLog,
    Checkpoint,
    /// Clean shutdown (flush, sync) and reopen, as SIGTERM and a restart do.
    Restart,
}

pub fn filter_json(seed: u64, r: &mut Rng) -> String {
    let hexk = |k: [u8; 32]| hex::encode_string(&k);
    let mut parts = Vec::new();
    match r.below(5) {
        0 => parts.push(format!("\"authors\":[\"{}\"]", hexk(author_key(seed, r.below(AUTHORS + PLANES))))),
        1 => parts.push(format!("\"kinds\":[{}]", r.pick(&[1u64, 0, 30078, 1059, 5, 14]))),
        2 => parts.push(format!("\"#p\":[\"{}\"]", hexk(author_key(seed, r.below(RECIPIENTS))))),
        3 => {
            parts.push(format!("\"authors\":[\"{}\"]", hexk(author_key(seed, r.below(AUTHORS)))));
            parts.push(format!("\"kinds\":[{}]", r.pick(&[1u64, 0, 30078, 5])));
        }
        _ => parts.push(format!("\"#t\":[\"{}\"]", r.pick(&["nostr", "vector", "x"]))),
    }
    if r.chance(1, 2) {
        let t = 1_000_000 + r.below(20_000);
        parts.push(format!("\"until\":{t}"));
        if r.chance(1, 2) {
            parts.push(format!("\"since\":{}", t.saturating_sub(r.below(5000))));
        }
    }
    format!("{{{}}}", parts.join(","))
}

pub fn op(seed: u64, i: u64) -> Op {
    let mut r = Rng::derive(seed ^ 0x0909, i);
    let first = i * MAX_BATCH;
    let batch = |r: &mut Rng, first: u64, max: u64| -> Vec<Ev> {
        let len = 1 + r.skewed(max - 1);
        let mut v = Vec::new();
        for j in 0..len {
            let n = first + j;
            match r.below(20) {
                // Re-send something earlier: a duplicate, or a deleted/replaced/vanished one.
                0 | 1 => {
                    if let Some(old) = recent(r, first) {
                        v.push(event(seed, old));
                    }
                }
                2 | 3 => {
                    if let Some(t) = recent(r, first) {
                        v.push(targeted_delete(seed, n, t));
                    }
                }
                _ => v.push(event(seed, n)),
            }
        }
        v
    };
    match r.below(100) {
        0..=79 => Op::Batch(batch(&mut r, first, 40)),
        80..=82 => Op::Delete { filters: (0..1 + r.below(2)).map(|_| filter_json(seed, &mut r)).collect(), older_than: r.chance(1, 3).then(|| 1_000_000 + r.below(20_000)) },
        83..=85 => {
            let filters = vec![filter_json(seed, &mut r)];
            let between = (0..1 + r.below(4)).map(|k| batch(&mut r, first + k * 16, 16)).collect();
            Op::AdminDelete { filters, between }
        }
        86..=88 => Op::Sweep(1_000_000 + r.below(3_000_000)),
        89..=90 => Op::FlushAll,
        91 => Op::CompactAll,
        92..=93 => Op::CompactLog,
        94 => Op::MergeLog,
        95..=97 => Op::Checkpoint,
        _ => Op::Restart,
    }
}
