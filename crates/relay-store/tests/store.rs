//! Store behaviour: NIP-01 rules, Concord's deletion rule, durability and
//! recovery, and a randomized check of the query engine against brute force.

use relay_proto::event::parse_event_json;
use relay_proto::json::Scanner;
use relay_proto::{hex, EventParser, Filter, Record};
use relay_store::writer::DELETE_BATCH;
use relay_store::{Options, Outcome, Store, Writer};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmpdir(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!("relay-store-test-{}-{}-{}", std::process::id(), name, N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn opts() -> Options {
    // Small log segments so tests cross segment boundaries, and a tiny flush
    // threshold so every test runs through segment files, background flushes,
    // compactions and checkpoints, not just memory runs.
    Options { segment_size: 64 * 1024, sync: true, flush_bytes: 4096, vanish_urls: vec!["wss://relay.example/nostr".into()], ..Options::default() }
}

fn hex32(b: u8, n: u64) -> String {
    let mut v = [b; 32];
    v[24..].copy_from_slice(&n.to_be_bytes());
    hex::encode_string(&v)
}

/// An event record. The store does not verify, so ids are synthetic; `n` makes them unique.
fn ev(n: u64, author: u8, created_at: u64, kind: u64, tags: &str, content: &str) -> Vec<u8> {
    let json = format!(
        r#"{{"id":"{}","pubkey":"{}","created_at":{created_at},"kind":{kind},"tags":{tags},"content":"{content}","sig":"{}"}}"#,
        hex32(0xEE, n),
        hex32(author, 0),
        "00".repeat(64)
    );
    let mut p = EventParser::new();
    let mut rec = Vec::new();
    parse_event_json(&json, &mut p, &mut rec, false).unwrap();
    rec
}

fn id_of(n: u64) -> [u8; 32] {
    hex::decode_32(hex32(0xEE, n).as_bytes()).unwrap()
}

fn pk(author: u8) -> String {
    hex32(author, 0)
}

fn write(w: &mut Writer, recs: &[Vec<u8>]) -> Vec<Outcome> {
    let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
    w.write(&refs).unwrap()
}

fn filter(json: &str) -> Filter {
    Filter::parse(&mut Scanner::new(json)).unwrap()
}

fn ids(store: &Store, f: &str, limit: usize) -> Vec<[u8; 32]> {
    store.snapshot().query(&filter(f), limit, 1_000).iter().map(|h| h.id).collect()
}

#[test]
fn store_query_reopen() {
    let dir = tmpdir("reopen");
    {
        let (store, mut w) = Store::open(&dir, opts()).unwrap();
        let recs: Vec<_> = (0..300).map(|i| ev(i, (i % 3) as u8 + 1, 100 + i, if i % 2 == 0 { 1059 } else { 14 }, "[]", "x")).collect();
        for chunk in recs.chunks(37) {
            assert!(write(&mut w, chunk).iter().all(|o| matches!(o, Outcome::Stored(_))));
        }
        assert_eq!(ids(&store, r#"{"kinds":[1059]}"#, 1000).len(), 150);
        assert_eq!(ids(&store, &format!(r#"{{"authors":["{}"],"kinds":[14]}}"#, pk(1)), 1000).len(), 50);
    }
    let (store, w) = Store::open(&dir, opts()).unwrap();
    assert_eq!(w.next_seq(), 300);
    let got = ids(&store, r#"{"kinds":[1059],"limit":3}"#, 3);
    assert_eq!(got, vec![id_of(298), id_of(296), id_of(294)]);
    assert_eq!(store.snapshot().count(&filter(r#"{"kinds":[14]}"#), 1_000), 150);
}

#[test]
fn duplicates() {
    let dir = tmpdir("dup");
    let (_store, mut w) = Store::open(&dir, opts()).unwrap();
    let a = ev(1, 1, 100, 1059, "[]", "a");
    assert_eq!(write(&mut w, &[a.clone(), a.clone()]), vec![Outcome::Stored(0), Outcome::Duplicate]);
    assert_eq!(write(&mut w, &[a]), vec![Outcome::Duplicate]);
}

#[test]
fn replaceable_and_addressable() {
    let dir = tmpdir("replace");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    // kind 0: newest wins.
    assert_eq!(write(&mut w, &[ev(1, 1, 100, 0, "[]", "old")]), vec![Outcome::Stored(0)]);
    assert_eq!(write(&mut w, &[ev(2, 1, 200, 0, "[]", "new")]), vec![Outcome::Stored(1)]);
    assert_eq!(write(&mut w, &[ev(3, 1, 150, 0, "[]", "late")]), vec![Outcome::Superseded]);
    assert_eq!(ids(&store, &format!(r#"{{"kinds":[0],"authors":["{}"]}}"#, pk(1)), 10), vec![id_of(2)]);
    // Same second: the lowest id wins, whichever arrives first.
    assert_eq!(write(&mut w, &[ev(9, 1, 200, 0, "[]", "tie-high")]), vec![Outcome::Superseded]);
    assert!(matches!(write(&mut w, &[ev(0, 1, 200, 0, "[]", "tie-low")])[0], Outcome::Stored(_)));
    assert_eq!(ids(&store, r#"{"kinds":[0]}"#, 10), vec![id_of(0)]);

    // 30078: addressed by d; two d values coexist.
    let a = r#"[["d","vector/pinned"]]"#;
    let b = r#"[["d","vector/mutes"]]"#;
    write(&mut w, &[ev(10, 2, 100, 30078, a, "1"), ev(11, 2, 100, 30078, b, "1"), ev(12, 2, 101, 30078, a, "2")]);
    let got = ids(&store, &format!(r##"{{"kinds":[30078],"authors":["{}"],"#d":["vector/pinned"]}}"##, pk(2)), 10);
    assert_eq!(got, vec![id_of(12)]);
    assert_eq!(ids(&store, r#"{"kinds":[30078]}"#, 10).len(), 2);

    // 33301 with an empty d, and with no d at all: the same address.
    write(&mut w, &[ev(20, 3, 100, 33301, r#"[["d",""]]"#, "x")]);
    write(&mut w, &[ev(21, 3, 101, 33301, "[]", "y")]);
    assert_eq!(ids(&store, r#"{"kinds":[33301]}"#, 10), vec![id_of(21)]);

    // The replaced events are gone after reopen too.
    drop(store);
    drop(w);
    let (store, _w) = Store::open(&dir, opts()).unwrap();
    assert_eq!(ids(&store, r#"{"kinds":[0]}"#, 10), vec![id_of(0)]);
    assert_eq!(ids(&store, r#"{"kinds":[33301]}"#, 10), vec![id_of(21)]);
}

#[test]
fn deletions_follow_concord() {
    let dir = tmpdir("delete");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    let recipient = pk(7);
    let wrap = ev(1, 5, 100, 1059, &format!(r#"[["p","{recipient}"]]"#), "wrap");
    let note = ev(2, 5, 100, 14, "[]", "regular");
    write(&mut w, &[wrap.clone(), note.clone()]);

    // The wrap's author asks to delete both: the regular event goes, the wrap stays.
    let del = ev(3, 5, 110, 5, &format!(r#"[["e","{}"],["e","{}"]]"#, hex32(0xEE, 1), hex32(0xEE, 2)), "");
    assert!(matches!(write(&mut w, &[del])[0], Outcome::Stored(_)));
    let both = format!(r#"{{"ids":["{}","{}"]}}"#, hex32(0xEE, 1), hex32(0xEE, 2));
    assert_eq!(ids(&store, &both, 10), vec![id_of(1)]);
    // Re-publishing the deleted regular event is refused.
    assert_eq!(write(&mut w, &[note]), vec![Outcome::Deleted]);

    // The recipient (the wrap's p key) can delete it, and it stays deleted.
    let del2 = ev(4, 7, 120, 5, &format!(r#"[["e","{}"]]"#, hex32(0xEE, 1)), "");
    write(&mut w, &[del2]);
    assert!(ids(&store, &format!(r#"{{"ids":["{}"]}}"#, hex32(0xEE, 1)), 10).is_empty());
    assert_eq!(write(&mut w, &[wrap]), vec![Outcome::Deleted]);

    // A deletion that arrives before its target blocks it too.
    let del3 = ev(5, 6, 130, 5, &format!(r#"[["e","{}"]]"#, hex32(0xEE, 6)), "");
    write(&mut w, &[del3]);
    assert_eq!(write(&mut w, &[ev(6, 6, 125, 14, "[]", "late")]), vec![Outcome::Deleted]);

    // `a` deletion: everything at the address up to its time, and older re-publishes.
    write(&mut w, &[ev(10, 8, 100, 30078, r#"[["d","x"]]"#, "v1")]);
    let a = format!("30078:{}:x", pk(8));
    write(&mut w, &[ev(11, 8, 150, 5, &format!(r#"[["a","{a}"]]"#), "")]);
    assert!(ids(&store, r#"{"kinds":[30078]}"#, 10).is_empty());
    assert_eq!(write(&mut w, &[ev(12, 8, 140, 30078, r#"[["d","x"]]"#, "v0")]), vec![Outcome::Deleted]);
    assert!(matches!(write(&mut w, &[ev(13, 8, 160, 30078, r#"[["d","x"]]"#, "v2")])[0], Outcome::Stored(_)));

    // Kind-5 events themselves cannot be deleted.
    write(&mut w, &[ev(14, 5, 200, 5, &format!(r#"[["e","{}"]]"#, hex32(0xEE, 3)), "")]);
    assert_eq!(ids(&store, &format!(r#"{{"ids":["{}"]}}"#, hex32(0xEE, 3)), 10), vec![id_of(3)]);

    // All of it survives a reopen.
    drop(store);
    drop(w);
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    assert!(ids(&store, &format!(r#"{{"ids":["{}","{}"]}}"#, hex32(0xEE, 1), hex32(0xEE, 2)), 10).is_empty());
    assert_eq!(write(&mut w, &[ev(1, 5, 100, 1059, &format!(r#"[["p","{recipient}"]]"#), "wrap")]), vec![Outcome::Deleted]);
}

#[test]
fn ordering_ties_and_limits() {
    let dir = tmpdir("ties");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    // Ten events in the same second, written in descending id order, across batches.
    let recs: Vec<_> = (0..10).rev().map(|i| ev(i, 1, 500, 1059, "[]", "t")).collect();
    for r in &recs {
        write(&mut w, std::slice::from_ref(r));
    }
    write(&mut w, &[ev(100, 1, 501, 1059, "[]", "newer"), ev(101, 1, 499, 1059, "[]", "older")]);
    // newest first; inside the tied second, lowest ids first.
    let got = ids(&store, r#"{"kinds":[1059]}"#, 4);
    assert_eq!(got, vec![id_of(100), id_of(0), id_of(1), id_of(2)]);
    let got = ids(&store, r#"{"kinds":[1059],"until":500,"since":500}"#, 100);
    assert_eq!(got, (0..10).map(id_of).collect::<Vec<_>>());
    assert!(ids(&store, r#"{"kinds":[1059]}"#, 0).is_empty());
}

#[test]
fn expiration() {
    let dir = tmpdir("expire");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    write(&mut w, &[ev(1, 1, 100, 1059, r#"[["expiration","500"]]"#, "typing"), ev(2, 1, 100, 1059, "[]", "msg")]);
    let snap = store.snapshot();
    assert_eq!(snap.query(&filter("{}"), 10, 499).len(), 2);
    assert_eq!(snap.query(&filter("{}"), 10, 500).len(), 1);
    drop(snap);
    assert_eq!(w.sweep_expired(400).unwrap(), 0);
    assert_eq!(w.sweep_expired(600).unwrap(), 1);
    assert_eq!(store.snapshot().query(&filter("{}"), 10, 0).len(), 1);
}

#[test]
fn torn_tail_is_cut() {
    let dir = tmpdir("torn");
    {
        let (_s, mut w) = Store::open(&dir, opts()).unwrap();
        write(&mut w, &[ev(1, 1, 100, 1059, "[]", "a"), ev(2, 1, 101, 1059, "[]", "b")]);
    }
    // Simulate a crash mid-write: garbage that looks like the start of a frame.
    let seg = dir.join("log").join("00000000.log");
    let data = std::fs::read(&seg).unwrap();
    let mut end = 0usize;
    loop {
        let len = u32::from_le_bytes(data[end..end + 4].try_into().unwrap()) as usize;
        if len == 0 {
            break;
        }
        end += 20 + len;
    }
    let f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
    use std::os::unix::fs::FileExt;
    f.write_all_at(&[200, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 9, 9, 9], end as u64).unwrap();
    drop(f);
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    assert_eq!(w.next_seq(), 2);
    assert_eq!(ids(&store, "{}", 10).len(), 2);
    // And writing after recovery continues cleanly.
    assert!(matches!(write(&mut w, &[ev(3, 1, 102, 1059, "[]", "c")])[0], Outcome::Stored(2)));
    drop((store, w));
    let (store, _w) = Store::open(&dir, opts()).unwrap();
    assert_eq!(ids(&store, "{}", 10).len(), 3);
}

#[test]
fn deleted_content_is_zeroed_on_disk() {
    let dir = tmpdir("zero");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    let secret = "SECRET-CONTENT-ZZZZ";
    write(&mut w, &[ev(1, 1, 100, 14, "[]", secret)]);
    let held = store.snapshot();
    write(&mut w, &[ev(2, 1, 101, 5, &format!(r#"[["e","{}"]]"#, hex32(0xEE, 1)), "")]);
    let seg = dir.join("log").join("00000000.log");
    let on_disk = |s: &str| std::fs::read(&seg).unwrap().windows(s.len()).any(|w| w == s.as_bytes());
    // Dead bits are shared, so even the old snapshot stops returning it at once;
    // but a reader of that snapshot may be mid-read, so the bytes must stay...
    assert!(held.record(0).is_none());
    assert!(on_disk(secret));
    drop(held);
    // ...and gone once the next batch finds no reader holding it.
    write(&mut w, &[ev(3, 1, 102, 14, "[]", "later")]);
    assert!(!on_disk(secret));
}

/// Deterministic xorshift for reproducible random tests.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn queries_match_brute_force() {
    let dir = tmpdir("random");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let kinds = [1059u64, 14, 7, 1111];
    let mut all: Vec<Vec<u8>> = Vec::new();
    let mut n = 0u64;
    // Many small batches, so the query runs over many runs at once.
    for _ in 0..120 {
        let batch: Vec<Vec<u8>> = (0..rng.below(30) + 1)
            .map(|_| {
                n += 1;
                let author = rng.below(6) as u8 + 1;
                let kind = kinds[rng.below(4) as usize];
                let p = pk(rng.below(5) as u8 + 20);
                let t = ["a", "b", "c"][rng.below(3) as usize];
                let tags = format!(r#"[["p","{p}"],["t","{t}"]]"#);
                ev(n, author, 1000 + rng.below(200), kind, &tags, "r")
            })
            .collect();
        write(&mut w, &batch);
        all.extend(batch);
    }
    let snap = store.snapshot();
    let mut prev: Option<Filter> = None;
    for q in 0..400 {
        let mut parts = Vec::new();
        if rng.below(2) == 0 {
            parts.push(format!(r#""authors":["{}","{}"]"#, pk(rng.below(6) as u8 + 1), pk(rng.below(6) as u8 + 1)));
        }
        if rng.below(2) == 0 {
            parts.push(format!(r#""kinds":[{},{}]"#, kinds[rng.below(4) as usize], kinds[rng.below(4) as usize]));
        }
        if rng.below(2) == 0 {
            parts.push(format!(r##""#p":["{}"]"##, pk(rng.below(5) as u8 + 20)));
        }
        if rng.below(3) == 0 {
            parts.push(format!(r##""#t":["{}"]"##, ["a", "b", "c"][rng.below(3) as usize]));
        }
        if rng.below(3) == 0 {
            parts.push(format!(r#""since":{}"#, 1000 + rng.below(100)));
        }
        if rng.below(3) == 0 {
            parts.push(format!(r#""until":{}"#, 1100 + rng.below(100)));
        }
        let fjson = format!("{{{}}}", parts.join(","));
        let f = filter(&fjson);
        let limit = [1usize, 5, 20, 100, 10_000][rng.below(5) as usize];

        let mut expect: Vec<(u64, [u8; 32])> =
            all.iter().map(|r| Record(r)).filter(|r| f.matches(*r)).map(|r| (r.created_at(), *r.id())).collect();
        expect.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        expect.truncate(limit);
        let got: Vec<(u64, [u8; 32])> = snap.query(&f, limit, 0).iter().map(|h| (h.created_at, h.id)).collect();
        assert_eq!(got, expect, "query {q}: {fjson} limit {limit}");

        let total = all.iter().filter(|r| f.matches(Record(r))).count() as u64;
        assert_eq!(snap.count(&f, 0), total, "count {q}: {fjson}");

        // The lazy walk yields every match, newest first, with no limit; and over
        // two filters, each event of the union once.
        let seqs_of = |fs: &[Filter]| -> Vec<(u64, u64)> { snap.matching(fs, None, 0).map(|h| (h.created_at, h.seq)).collect() };
        let walk = seqs_of(std::slice::from_ref(&f));
        assert!(walk.windows(2).all(|w| w[0] > w[1]), "walk order {q}: {fjson}");
        assert_eq!(walk.len() as u64, total, "walk {q}: {fjson}");
        if let Some(p) = &prev {
            let walk = seqs_of(&[f.clone(), p.clone()]);
            assert!(walk.windows(2).all(|w| w[0] > w[1]), "union order {q}: {fjson}");
            let union = all.iter().filter(|r| f.matches(Record(r)) || p.matches(Record(r))).count();
            assert_eq!(walk.len(), union, "union {q}: {fjson}");
        }
        prev = Some(f);
    }
}

#[test]
fn segment_size_cannot_change() {
    let dir = tmpdir("meta");
    drop(Store::open(&dir, opts()).unwrap());
    let other = Options { segment_size: 128 * 1024, ..opts() };
    let err = Store::open(&dir, other).err().expect("must refuse");
    assert!(err.to_string().contains("segment size"), "{err}");
    assert!(Store::open(&dir, opts()).is_ok());
}

#[test]
fn restart_uses_checkpoint_and_compacts() {
    let dir = tmpdir("ckpt");
    let mut all = Vec::new();
    {
        let (store, mut w) = Store::open(&dir, opts()).unwrap();
        for i in 0..2000u64 {
            let r = ev(i, (i % 5) as u8 + 1, 1000 + i, 1059, &format!(r#"[["p","{}"]]"#, pk((i % 7) as u8 + 30)), "x");
            write(&mut w, std::slice::from_ref(&r));
            all.push(r);
        }
        w.compact_all().unwrap();
        assert_eq!(w.segment_count(), 1, "everything merged into one segment");
        let v = store.snapshot();
        assert_eq!(v.index_bytes(), 0, "no index left in memory after a full flush");
        assert_eq!(ids(&store, "{}", 5000).len(), 2000);
        // A little more after the checkpoint: the tail a restart must replay.
        write(&mut w, &[ev(5000, 1, 9000, 1059, "[]", "tail")]);
    }
    let t = std::time::Instant::now();
    let (store, w) = Store::open(&dir, opts()).unwrap();
    let opened = t.elapsed();
    assert_eq!(w.next_seq(), 2001);
    let v = store.snapshot();
    assert!(v.index_keys() > 2000 * 5);
    assert!(v.index_bytes() < 10_000, "only the tail is in memory ({} bytes)", v.index_bytes());
    assert_eq!(ids(&store, "{}", 5000).len(), 2001);
    let me = pk(30);
    let got = ids(&store, &format!(r##"{{"kinds":[1059],"#p":["{me}"],"limit":10}}"##), 10);
    let mut expect: Vec<_> = all.iter().map(|r| Record(r)).filter(|r| r.tags().any(|t| t.indexable().is_some())).filter(|r| {
        let f = filter(&format!(r##"{{"#p":["{me}"]}}"##));
        f.matches(*r)
    }).map(|r| (r.created_at(), *r.id())).collect();
    expect.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    assert_eq!(got, expect.iter().take(10).map(|e| e.1).collect::<Vec<_>>());
    eprintln!("reopen with checkpoint: {opened:?}");
}

#[test]
fn crash_leftovers_are_removed() {
    let dir = tmpdir("leftover");
    {
        let (_s, mut w) = Store::open(&dir, opts()).unwrap();
        for i in 0..300u64 {
            write(&mut w, &[ev(i, 1, 100 + i, 1059, "[]", "x")]);
        }
        w.flush_all().unwrap();
    }
    // A flush and a compaction that died before their checkpoint.
    std::fs::write(dir.join("idx").join("0000000000009999.seg"), b"partial").unwrap();
    std::fs::write(dir.join("idx").join("0000000000009998.seg.tmp"), b"partial").unwrap();
    let (store, _w) = Store::open(&dir, opts()).unwrap();
    assert!(!dir.join("idx").join("0000000000009999.seg").exists());
    assert!(!dir.join("idx").join("0000000000009998.seg.tmp").exists());
    assert_eq!(ids(&store, "{}", 1000).len(), 300);
}

#[test]
fn vanish_nip62() {
    let dir = tmpdir("vanish");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    let me = pk(40);
    write(&mut w, &[
        ev(1, 40, 100, 0, "[]", "profile"),
        ev(2, 40, 110, 30078, r#"[["d","vector/pinned"]]"#, "prefs"),
        ev(3, 41, 120, 1059, &format!(r#"[["p","{me}"]]"#), "dm to me"),
        ev(4, 42, 130, 0, "[]", "someone else"),
        // Key 41 is also a Concord-style plane key: a wrap to someone else.
        ev(12, 41, 125, 1059, &format!(r#"[["p","{}"]]"#, pk(44)), "plane traffic"),
    ]);
    // A request naming another relay does nothing here.
    let elsewhere = ev(5, 40, 200, 62, r#"[["relay","wss://other.example"]]"#, "");
    assert!(matches!(write(&mut w, &[elsewhere])[0], Outcome::Stored(_)));
    assert_eq!(ids(&store, &format!(r#"{{"authors":["{}"],"kinds":[0]}}"#, pk(40)), 10).len(), 1);
    // ALL_RELAYS (and our own URL) do: my events and wraps to me go.
    let v = ev(6, 40, 200, 62, r#"[["relay","ALL_RELAYS"]]"#, "");
    assert!(matches!(write(&mut w, &[v])[0], Outcome::Stored(_)));
    assert!(ids(&store, &format!(r#"{{"authors":["{}"],"kinds":[0,30078]}}"#, pk(40)), 10).is_empty());
    assert!(ids(&store, &format!(r##"{{"kinds":[1059],"#p":["{me}"]}}"##), 10).is_empty());
    assert_eq!(ids(&store, r#"{"kinds":[0]}"#, 10), vec![id_of(4)]);
    // Older events from me, or wraps to me, cannot come back; newer ones can.
    assert_eq!(write(&mut w, &[ev(7, 40, 150, 0, "[]", "old")]), vec![Outcome::Deleted]);
    assert_eq!(write(&mut w, &[ev(8, 43, 150, 1059, &format!(r#"[["p","{me}"]]"#), "old wrap")]), vec![Outcome::Deleted]);
    assert!(matches!(write(&mut w, &[ev(9, 40, 300, 0, "[]", "new me")])[0], Outcome::Stored(_)));
    // A Concord plane key (it authored wraps) cannot vanish.
    let r = write(&mut w, &[ev(10, 41, 400, 62, r#"[["relay","wss://relay.example/nostr/"]]"#, "")]);
    assert!(matches!(r[0], Outcome::Rejected(_)), "{r:?}");
    drop((store, w));
    // All of it holds after a restart.
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    assert!(ids(&store, &format!(r##"{{"kinds":[1059],"#p":["{me}"]}}"##), 10).is_empty());
    assert_eq!(write(&mut w, &[ev(11, 40, 199, 30078, r#"[["d","x"]]"#, "old")]), vec![Outcome::Deleted]);
}

#[test]
fn negentropy_covering_set_matches_query() {
    let dir = tmpdir("neg");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    let me = pk(50);
    let other = pk(51);
    let mut n = 0u64;
    for i in 0..600u64 {
        n += 1;
        let to = if i % 3 == 0 { &other } else { &me };
        let tags = if i % 10 == 0 {
            // Some already expired, some expiring later.
            format!(r#"[["p","{to}"],["expiration","{}"]]"#, if i % 20 == 0 { 500 } else { 5000 })
        } else {
            format!(r#"[["p","{to}"]]"#)
        };
        write(&mut w, &[ev(n, (i % 4) as u8 + 60, 100 + i % 50, 1059, &tags, "w")]);
    }
    // The recipient deletes a few of their wraps.
    let dels: Vec<String> = (1..40u64).filter(|i| i % 3 != 1).map(|i| format!(r#"["e","{}"]"#, hex32(0xEE, i))).collect();
    write(&mut w, &[ev(9000, 50, 1000, 5, &format!("[{}]", dels.join(",")), "")]);
    let snap = store.snapshot();
    for (fj, now) in [
        (format!(r##"{{"kinds":[1059],"#p":["{me}"]}}"##), 1000u64),
        (format!(r##"{{"kinds":[1059],"#p":["{me}","{other}"],"since":120,"until":140}}"##), 1000),
        (format!(r##"{{"kinds":[1059],"#p":["{me}"]}}"##), 6000),
    ] {
        let f = filter(&fj);
        let mut covered = snap.neg_items(&f, now).expect("covered shape");
        covered.sort();
        let mut queried: Vec<(u64, [u8; 32])> = snap.query(&f, usize::MAX, now).iter().map(|h| (h.created_at, h.id)).collect();
        queried.sort();
        assert!(!queried.is_empty());
        assert_eq!(covered, queried, "{fj} at {now}");
    }
    assert!(snap.neg_items(&filter(r#"{"kinds":[1059],"authors":["00"]}"#.replace("00", &pk(1)).as_str()), 0).is_none());
}

#[test]
fn torn_tail_with_precreated_next_segment() {
    let dir = tmpdir("torn2");
    {
        let (_s, mut w) = Store::open(&dir, opts()).unwrap();
        write(&mut w, &[ev(1, 1, 100, 1059, "[]", "a"), ev(2, 1, 101, 1059, "[]", "b")]);
        // Zero-filling ahead pre-creates the next segment files.
        w.prepare().unwrap();
        w.prepare().unwrap();
    }
    assert!(dir.join("log").join("00000001.log").exists(), "next segment pre-created");
    let seg = dir.join("log").join("00000000.log");
    let data = std::fs::read(&seg).unwrap();
    let mut end = 0usize;
    loop {
        let len = u32::from_le_bytes(data[end..end + 4].try_into().unwrap()) as usize;
        if len == 0 {
            break;
        }
        end += 20 + len;
    }
    let f = std::fs::OpenOptions::new().write(true).open(&seg).unwrap();
    use std::os::unix::fs::FileExt;
    f.write_all_at(&[200, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 9], end as u64).unwrap();
    drop(f);
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    assert_eq!(ids(&store, "{}", 10).len(), 2);
    assert!(matches!(write(&mut w, &[ev(3, 1, 102, 1059, "[]", "c")])[0], Outcome::Stored(2)));
    drop((store, w));
    let (store, _w) = Store::open(&dir, opts()).unwrap();
    assert_eq!(ids(&store, "{}", 10).len(), 3);
}

/// Like `ev`, with any pubkey (gift wraps are signed by one-off keys).
fn ev_by(n: u64, pubkey: &str, created_at: u64, kind: u64, tags: &str, content: &str) -> Vec<u8> {
    let json = format!(
        r#"{{"id":"{}","pubkey":"{pubkey}","created_at":{created_at},"kind":{kind},"tags":{tags},"content":"{content}","sig":"{}"}}"#,
        hex32(0xEE, n),
        "00".repeat(64)
    );
    let mut p = EventParser::new();
    let mut rec = Vec::new();
    parse_event_json(&json, &mut p, &mut rec, false).unwrap();
    rec
}

fn log_opts(compact_after: usize) -> Options {
    // Tiny clustering chunks, so a compaction streams through many of them.
    Options { log_compact_segments: compact_after, log_chunk_bytes: 24 * 1024, ..opts() }
}

/// Every file under `dir`, recursively.
fn files_under(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(files_under(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            copy_dir(&p, &to.join(e.file_name()));
        } else {
            std::fs::copy(&p, to.join(e.file_name())).unwrap();
        }
    }
}

/// The live frames of a log segment file: (flags, record).
fn frames(path: &std::path::Path) -> Vec<(u32, Vec<u8>)> {
    let data = std::fs::read(path).unwrap();
    let mut out = Vec::new();
    let mut o = 0usize;
    while o + 20 <= data.len() {
        let len = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
        if len == 0 {
            break;
        }
        let flags = u32::from_le_bytes(data[o + 4..o + 8].try_into().unwrap());
        out.push((flags, data[o + 20..o + 20 + len].to_vec()));
        o += 20 + len;
    }
    out
}

/// A mixed Vector-like workload: DM gift wraps (one-off keys), Concord plane
/// wraps (one key, many wraps), chat messages and profiles; with deletions by
/// authors and by wrap recipients, and replaced profiles. Returns the records
/// that must be live at the end. Every record that dies carries "SECRET".
struct Workload {
    rng: Rng,
    n: u64,
    live: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Records that will be deleted later: (n, deleter author byte).
    doomed: Vec<(u64, u8)>,
    profile: std::collections::HashMap<u8, u64>,
}

const PLANE: u8 = 0xA0;

impl Workload {
    fn new() -> Self {
        Workload { rng: Rng(0xD1B5_4A32_D192_ED03), n: 0, live: Default::default(), doomed: Vec::new(), profile: Default::default() }
    }

    fn batch(&mut self, size: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for _ in 0..size {
            self.n += 1;
            let n = self.n;
            let ca = 10_000 + n;
            let doom = self.rng.below(4) == 0;
            let content = if doom { format!("SECRET{n}") } else { format!("keep{n}") };
            let body = format!("{content}-{}", "x".repeat(200 + self.rng.below(300) as usize));
            let to = self.rng.below(12) as u8 + 1;
            let rec = match self.rng.below(5) {
                0 | 1 => {
                    // A DM wrap from a one-off key; the recipient may delete it.
                    let tags = format!(r#"[["p","{}"]]"#, pk(to));
                    if doom {
                        self.doomed.push((n, to));
                    }
                    ev_by(n, &hex32(0xC0, n), ca, 1059, &tags, &body)
                }
                2 => {
                    let tags = format!(r#"[["p","{}"]]"#, pk(to));
                    if doom {
                        self.doomed.push((n, to));
                    }
                    ev_by(n, &pk(PLANE), ca, 1059, &tags, &body)
                }
                3 => {
                    if doom {
                        self.doomed.push((n, to));
                    }
                    ev(n, to, ca, 14, "[]", &body)
                }
                _ => {
                    // A new profile replaces the author's last one.
                    if let Some(old) = self.profile.insert(to, n) {
                        self.live.remove(&old);
                    }
                    ev(n, to, ca, 0, "[]", &format!("SECRET-profile-{n}"))
                }
            };
            self.live.insert(n, rec.clone());
            out.push(rec);
        }
        // Deletions of some earlier doomed records, each signed by who may delete it.
        let k = (self.doomed.len() / 3).min(8);
        for (target, by) in self.doomed.drain(..k).collect::<Vec<_>>() {
            self.n += 1;
            let tags = format!(r#"[["e","{}"]]"#, hex32(0xEE, target));
            out.push(ev(self.n, by, 10_000 + self.n, 5, &tags, ""));
            self.live.remove(&target);
            // The deletion itself stays (it is live too).
            self.live.insert(self.n, out.last().unwrap().clone());
        }
        out
    }

    fn finish(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for (target, by) in std::mem::take(&mut self.doomed) {
            self.n += 1;
            let tags = format!(r#"[["e","{}"]]"#, hex32(0xEE, target));
            out.push(ev(self.n, by, 10_000 + self.n, 5, &tags, ""));
            self.live.remove(&target);
            self.live.insert(self.n, out.last().unwrap().clone());
        }
        // The last profiles are live and must not count as secrets: rewrite them.
        for (&author, &old) in self.profile.clone().iter() {
            self.n += 1;
            let r = ev(self.n, author, 10_000 + self.n, 0, "[]", "final");
            self.live.remove(&old);
            self.live.insert(self.n, r.clone());
            self.profile.insert(author, self.n);
            out.push(r);
        }
        out
    }

    /// Checks a store against the model with a spread of filters.
    fn check(&self, store: &Store, what: &str) {
        let snap = store.snapshot();
        let mut filters = vec![
            "{}".to_string(),
            r#"{"kinds":[1059]}"#.to_string(),
            r#"{"kinds":[0,14]}"#.to_string(),
            format!(r#"{{"authors":["{}"],"kinds":[1059]}}"#, pk(PLANE)),
        ];
        for to in 1..=12u8 {
            filters.push(format!(r##"{{"kinds":[1059],"#p":["{}"]}}"##, pk(to)));
            filters.push(format!(r#"{{"authors":["{}"]}}"#, pk(to)));
        }
        for fj in &filters {
            let f = filter(fj);
            let mut expect: Vec<(u64, [u8; 32])> =
                self.live.values().map(|r| Record(r)).filter(|r| f.matches(*r)).map(|r| (r.created_at(), *r.id())).collect();
            expect.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            let got: Vec<(u64, [u8; 32])> = snap.query(&f, usize::MAX, 0).iter().map(|h| (h.created_at, h.id)).collect();
            assert_eq!(got.len(), expect.len(), "{what}: {fj}");
            assert_eq!(got, expect, "{what}: {fj}");
            // Every answer's record reads back intact from wherever it now lives.
            for h in snap.query(&f, 50, 0) {
                let r = snap.record(h.seq).expect("live");
                assert_eq!(r.id(), &h.id);
                assert_eq!(r.0, self.live.values().find(|x| Record(x).id() == &h.id).unwrap().as_slice(), "{what}: bytes of {fj}");
            }
        }
    }
}

fn cluster_class(r: Record<'_>) -> (u8, [u8; 32], u64) {
    use relay_proto::record::Field;
    if r.kind() == 1059 {
        if r.pubkey() == &hex::decode_32(pk(PLANE).as_bytes()).unwrap() {
            return (0, *r.pubkey(), r.created_at());
        }
        let p = r.tags().find_map(|t| {
            let mut f = t.fields();
            match (f.next(), f.next()) {
                (Some(n), Some(Field::Hex32(p))) if n.is_str(b"p") => Some(*p),
                _ => None,
            }
        });
        return (1, p.unwrap(), r.created_at());
    }
    (2, *r.pubkey(), r.created_at())
}

#[test]
fn log_compaction_keeps_every_answer() {
    let dir = tmpdir("logc");
    let mut wl = Workload::new();
    {
        let (store, mut w) = Store::open(&dir, log_opts(2)).unwrap();
        // Compactions run in the background while writes and deletions go on.
        for round in 0..150 {
            let b = wl.batch(12);
            write(&mut w, &b);
            if round % 50 == 49 {
                wl.check(&store, &format!("round {round}"));
            }
        }
        assert!(!files_under(&dir.join("log").join("cold")).is_empty(), "compactions ran in the background");
        let b = wl.finish();
        write(&mut w, &b);
        w.compact_log_all().unwrap();
        // A few more batches let the last dead records be zeroed.
        for _ in 0..3 {
            let b = wl.batch(2);
            write(&mut w, &b);
            w.maintain().unwrap();
        }
        let b = wl.finish();
        write(&mut w, &b);
        w.compact_log_all().unwrap();
        write(&mut w, &[]);
        w.maintain().unwrap();
        wl.check(&store, "after compaction");

        let log = dir.join("log");
        let cold: Vec<PathBuf> = files_under(&log.join("cold"));
        let hot: Vec<PathBuf> = std::fs::read_dir(&log).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "log")).collect();
        let highest = hot.iter().filter_map(|p| p.file_stem()?.to_str()?.parse::<u64>().ok()).max().unwrap();
        assert!(!cold.is_empty(), "cold segments written");
        assert!((hot.len() as u64) < highest / 2, "retired hot segments removed: {} of {}", hot.len(), highest + 1);

        // Cold segments hold runs in cluster order (plane traffic by author, DM
        // wraps by recipient, the rest by author; then by time), one per chunk of
        // log clustered together. Arrival order would give runs of about two.
        let (mut checked, mut runs) = (0usize, 0usize);
        for c in &cold {
            let keys: Vec<_> = frames(c).into_iter().filter(|f| f.0 == 0).map(|f| cluster_class(Record(&f.1))).collect();
            runs += 1 + keys.windows(2).filter(|w| w[0] > w[1]).count();
            checked += keys.len();
        }
        assert!(checked > 500, "most records live in cold segments ({checked})");
        assert!(checked >= runs * 10, "{checked} records in {runs} sorted runs: not clustered");

        // After compact_log_all the whole cold log is one run, sorted end to end
        // (read in the run's order, which the checkpoint records).
        assert_eq!(w.cold_runs(), 1);
        let ck = relay_store::checkpoint::read(&dir).unwrap().unwrap();
        assert_eq!(ck.run_lens, vec![ck.cold.len() as u64]);
        let keys: Vec<_> = ck
            .cold
            .iter()
            .flat_map(|n| frames(&log.join("cold").join(format!("{n:08}.log"))))
            .filter(|f| f.0 == 0)
            .map(|f| cluster_class(Record(&f.1)))
            .collect();
        assert!(keys.windows(2).all(|w| w[0] <= w[1]), "the merged run is out of cluster order");

        // Nothing that died is left readable on disk, hot or cold.
        for f in files_under(&log) {
            let data = std::fs::read(&f).unwrap();
            assert!(!data.windows(6).any(|w| w == b"SECRET"), "deleted content left in {}", f.display());
        }
    }
    let (store, mut w) = Store::open(&dir, log_opts(2)).unwrap();
    wl.check(&store, "after reopen");
    // And it keeps working: more writes, more compactions.
    for _ in 0..40 {
        let b = wl.batch(12);
        write(&mut w, &b);
    }
    let b = wl.finish();
    write(&mut w, &b);
    w.compact_log_all().unwrap();
    wl.check(&store, "after more compaction");
    drop((store, w));
    let (store, _w) = Store::open(&dir, log_opts(2)).unwrap();
    wl.check(&store, "after second reopen");
}

#[test]
fn interrupted_log_compaction_finishes_at_open() {
    let dir = tmpdir("logc-crash");
    let mut wl = Workload::new();
    {
        let (_s, mut w) = Store::open(&dir, log_opts(0)).unwrap();
        for _ in 0..60 {
            let b = wl.batch(12);
            write(&mut w, &b);
        }
        let b = wl.finish();
        write(&mut w, &b);
        w.flush_all().unwrap();
    }
    // The state just before a compaction.
    let before = tmpdir("logc-before");
    copy_dir(&dir, &before);
    let ck_before = relay_store::checkpoint::read(&dir).unwrap().unwrap();
    {
        let (_s, mut w) = Store::open(&dir, log_opts(0)).unwrap();
        w.compact_log_all().unwrap();
    }
    let ck_after = relay_store::checkpoint::read(&dir).unwrap().unwrap();
    let new_cold: Vec<u64> = ck_after.cold.iter().copied().filter(|n| !ck_before.cold.contains(n)).collect();
    let retired: Vec<u64> = ck_after.retired.iter().copied().filter(|n| !ck_before.retired.contains(n)).collect();
    assert!(!new_cold.is_empty() && !retired.is_empty());
    assert!(ck_after.intent_cold.is_empty() && ck_after.intent_retire.is_empty());

    // 1. Died while the cold segments were being written: they are leftovers.
    let crash1 = tmpdir("logc-crash1");
    copy_dir(&before, &crash1);
    copy_dir(&dir.join("log").join("cold"), &crash1.join("log").join("cold"));
    {
        let (store, _w) = Store::open(&crash1, log_opts(0)).unwrap();
        wl.check(&store, "crash while writing");
        assert!(files_under(&crash1.join("log").join("cold")).is_empty(), "unregistered cold segments removed");
    }

    // 2. Died after the intent was recorded, before `locs` pointed at the cold
    //    copies (and with the old hot segments gone or not): open finishes it.
    for keep_hot in [true, false] {
        let crash2 = tmpdir("logc-crash2");
        copy_dir(&before, &crash2);
        copy_dir(&dir.join("log").join("cold"), &crash2.join("log").join("cold"));
        if !keep_hot {
            for n in &retired {
                std::fs::remove_file(crash2.join("log").join(format!("{n:08}.log"))).unwrap();
            }
        }
        let mut ck = ck_before.clone();
        ck.next_cold = ck_after.next_cold;
        ck.cold = ck_after.cold.clone();
        ck.run_lens = ck_after.run_lens.clone();
        ck.run_bytes = ck_after.run_bytes.clone();
        ck.intent_cold = new_cold.clone();
        ck.intent_retire = retired.clone();
        relay_store::checkpoint::write(&crash2, &ck).unwrap();
        {
            let (store, _w) = Store::open(&crash2, log_opts(0)).unwrap();
            wl.check(&store, &format!("crash before relink (hot kept: {keep_hot})"));
        }
        let ck = relay_store::checkpoint::read(&crash2).unwrap().unwrap();
        assert!(ck.intent_cold.is_empty() && ck.intent_retire.is_empty(), "intent finished");
        for n in &retired {
            assert!(ck.retired.contains(n));
            assert!(!crash2.join("log").join(format!("{n:08}.log")).exists());
        }
        let (store, _w) = Store::open(&crash2, log_opts(0)).unwrap();
        wl.check(&store, "reopen after finishing");
    }
}

#[test]
fn one_process_per_directory() {
    let dir = tmpdir("lock");
    let (store, w) = Store::open(&dir, opts()).unwrap();
    let err = Store::open(&dir, opts()).err().expect("a second open must be refused");
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    assert!(err.to_string().contains(&format!("pid {}", std::process::id())), "{err}");
    drop((store, w));
    // Released with the store.
    assert!(Store::open(&dir, opts()).is_ok());
}

/// On Linux a deleted record's whole blocks go back to the filesystem.
#[cfg(target_os = "linux")]
#[test]
fn deleted_large_records_give_their_blocks_back() {
    use std::os::unix::fs::MetadataExt;
    let dir = tmpdir("punch");
    let big = Options { segment_size: 4 << 20, ..opts() };
    let (_store, mut w) = Store::open(&dir, big.clone()).unwrap();
    let content = "y".repeat(1 << 20);
    write(&mut w, &[ev(1, 1, 100, 14, "[]", &content)]);
    w.sync().unwrap();
    let seg = dir.join("log").join("00000000.log");
    let before = std::fs::metadata(&seg).unwrap().blocks();
    write(&mut w, &[ev(2, 1, 101, 5, &format!(r#"[["e","{}"]]"#, hex32(0xEE, 1)), "")]);
    // The next batch finds no reader of the old version and zeroes the record.
    write(&mut w, &[ev(3, 1, 102, 14, "[]", "later")]);
    w.sync().unwrap();
    let after = std::fs::metadata(&seg).unwrap().blocks();
    assert!(before - after >= 1900, "1 MiB deleted, only {} KiB given back", (before - after) / 2);
    assert!(!std::fs::read(&seg).unwrap().windows(64).any(|w| w == content[..64].as_bytes()));
}

#[test]
fn interrupted_log_merge_finishes_at_open() {
    let dir = tmpdir("merge-crash");
    let mut wl = Workload::new();
    {
        let (_s, mut w) = Store::open(&dir, log_opts(0)).unwrap();
        for _ in 0..60 {
            let b = wl.batch(12);
            write(&mut w, &b);
        }
        let b = wl.finish();
        write(&mut w, &b);
        w.compact_log_hot().unwrap();
        assert!(w.cold_runs() > 4, "tiny chunks give many runs ({})", w.cold_runs());
    }
    // Several runs, before the merge.
    let before = tmpdir("merge-before");
    copy_dir(&dir, &before);
    let ck_before = relay_store::checkpoint::read(&dir).unwrap().unwrap();
    {
        let (store, mut w) = Store::open(&dir, log_opts(0)).unwrap();
        w.merge_log_runs().unwrap();
        assert_eq!(w.cold_runs(), 1);
        wl.check(&store, "after the merge");
    }
    let ck_after = relay_store::checkpoint::read(&dir).unwrap().unwrap();
    let merged: Vec<u64> = ck_after.cold.clone();
    assert!(merged.iter().all(|n| !ck_before.cold.contains(n)));
    for n in &ck_before.cold {
        assert!(!dir.join("log").join("cold").join(format!("{n:08}.log")).exists(), "merged input {n} removed");
    }

    // Died after the merge's intent was recorded, before `locs` moved: the old
    // runs are still there and listed, the new one is too, and open finishes it.
    let crash = tmpdir("merge-crash2");
    copy_dir(&before, &crash);
    copy_dir(&dir.join("log").join("cold"), &crash.join("log").join("cold"));
    let mut ck = ck_before.clone();
    ck.next_cold = ck_after.next_cold;
    ck.cold.extend(&merged);
    ck.run_lens.push(merged.len() as u64);
    ck.run_bytes.push(ck_after.run_bytes[0]);
    ck.intent_cold = merged.clone();
    ck.intent_retire = ck_before.cold.iter().map(|n| relay_store::log::COLD_BASE + n).collect();
    relay_store::checkpoint::write(&crash, &ck).unwrap();
    {
        let (store, w) = Store::open(&crash, log_opts(0)).unwrap();
        assert_eq!(w.cold_runs(), 1);
        wl.check(&store, "merge finished at open");
    }
    let ck = relay_store::checkpoint::read(&crash).unwrap().unwrap();
    assert!(ck.intent_cold.is_empty() && ck.intent_retire.is_empty());
    assert_eq!(ck.cold, merged);
    for n in &ck_before.cold {
        assert!(!crash.join("log").join("cold").join(format!("{n:08}.log")).exists(), "input {n} removed at open");
    }
    let (store, _w) = Store::open(&crash, log_opts(0)).unwrap();
    wl.check(&store, "reopen after the merge");
}

/// `n` events: event `i` is by author `i % 3 + 1`, of kind 1059 when `i` is even
/// and 14 when odd, created at `1000 + i`.
fn fill(w: &mut Writer, n: u64) {
    let recs: Vec<_> = (0..n).map(|i| ev(i, (i % 3) as u8 + 1, 1000 + i, if i % 2 == 0 { 1059 } else { 14 }, "[]", "x")).collect();
    for chunk in recs.chunks(97) {
        write(w, chunk);
    }
}

/// What a delete should have done, tracked by hand: marks the events `pred`
/// accepts as gone and says how many that newly was.
fn forget(alive: &mut [bool], pred: impl Fn(u64) -> bool) -> usize {
    let mut n = 0;
    for (i, a) in alive.iter_mut().enumerate() {
        if *a && pred(i as u64) {
            *a = false;
            n += 1;
        }
    }
    n
}

/// Asserts the store holds exactly the events `alive` says, to the query, the count and the walk.
fn assert_alive(store: &Store, alive: &[bool], what: &str) {
    let want: BTreeSet<[u8; 32]> = (0..alive.len() as u64).filter(|&i| alive[i as usize]).map(id_of).collect();
    let snap = store.snapshot();
    let walked: Vec<_> = snap.matching(&[filter("{}")], None, 2_000).collect();
    assert_eq!(walked.iter().map(|h| h.id).collect::<BTreeSet<_>>(), want, "{what}: walk");
    assert_eq!(walked.len(), want.len(), "{what}: walk repeats an event");
    assert_eq!(snap.count(&filter("{}"), 2_000), want.len() as u64, "{what}: count");
    let queried: BTreeSet<[u8; 32]> = snap.query(&filter("{}"), usize::MAX, 2_000).iter().map(|h| h.id).collect();
    assert_eq!(queried, want, "{what}: query");
}

#[test]
fn delete_matching_removes_only_what_matches() {
    let dir = tmpdir("delete");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    fill(&mut w, 600);
    let mut alive = vec![true; 600];
    let (author, kind, at) = (|i: u64| i % 3 + 1, |i: u64| if i % 2 == 0 { 1059 } else { 14 }, |i: u64| 1000 + i);
    assert_alive(&store, &alive, "before");

    // One filter: its events go from query and count, nothing else does.
    let mine = filter(&format!(r#"{{"kinds":[14],"authors":["{}"]}}"#, pk(1)));
    assert_eq!(w.delete_matching(std::slice::from_ref(&mine), None, 2_000).unwrap(), forget(&mut alive, |i| kind(i) == 14 && author(i) == 1));
    assert_eq!(store.snapshot().count(&mine, 2_000), 0);
    assert!(store.snapshot().query(&mine, 1_000, 2_000).is_empty());
    assert_alive(&store, &alive, "one filter");
    assert_eq!(w.delete_matching(std::slice::from_ref(&mine), None, 2_000).unwrap(), 0, "nothing left to delete");

    // A restart does not bring them back: the kills leave no rule key in the
    // log for the replay to re-derive them from.
    drop((store, w));
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    assert_alive(&store, &alive, "after reopen");

    // `older_than` is exclusive: the wrap created at exactly 1300 stays.
    let wraps = filter(r#"{"kinds":[1059]}"#);
    assert_eq!(w.delete_matching(std::slice::from_ref(&wraps), Some(1300), 2_000).unwrap(), forget(&mut alive, |i| kind(i) == 1059 && at(i) < 1300));
    assert!(store.snapshot().lookup_id(&id_of(300)).is_some());
    assert!(store.snapshot().lookup_id(&id_of(298)).is_none());
    assert_alive(&store, &alive, "older_than");

    // It narrows a filter's own `until`, and never widens it.
    let early = filter(r#"{"kinds":[14],"until":1100}"#);
    assert_eq!(w.delete_matching(std::slice::from_ref(&early), Some(1500), 2_000).unwrap(), forget(&mut alive, |i| kind(i) == 14 && at(i) <= 1100));
    let narrow = filter(r#"{"kinds":[14],"until":1400}"#);
    assert_eq!(w.delete_matching(std::slice::from_ref(&narrow), Some(1200), 2_000).unwrap(), forget(&mut alive, |i| kind(i) == 14 && at(i) < 1200));
    assert_alive(&store, &alive, "until");

    // Nothing is older than the epoch, and no filters match nothing.
    assert_eq!(w.delete_matching(&[filter("{}")], Some(0), 2_000).unwrap(), 0);
    assert_eq!(w.delete_matching(&[], None, 2_000).unwrap(), 0);

    // A union counts an event matched by both filters once.
    let by_two = filter(&format!(r#"{{"authors":["{}"]}}"#, pk(2)));
    let late = filter(r#"{"kinds":[1059],"since":1500}"#);
    let want = forget(&mut alive, |i| author(i) == 2 || (kind(i) == 1059 && at(i) >= 1500));
    assert_eq!(w.delete_matching(&[by_two, late], None, 2_000).unwrap(), want);
    assert_alive(&store, &alive, "union");

    // And all of it holds after another restart.
    drop((store, w));
    let (store, _w) = Store::open(&dir, opts()).unwrap();
    assert_alive(&store, &alive, "after second reopen");
}

#[test]
fn delete_matching_runs_in_batches() {
    let dir = tmpdir("delete-batches");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    let n = DELETE_BATCH as u64 * 2 + 100;
    fill(&mut w, n);
    // Whole batches and a partial one.
    assert_eq!(w.delete_matching(&[filter(r#"{"kinds":[1059]}"#)], None, 2_000).unwrap() as u64, n / 2);
    assert_eq!(store.snapshot().count(&filter("{}"), 1_000_000), n / 2);
    drop((store, w));
    let (store, _w) = Store::open(&dir, opts()).unwrap();
    assert_eq!(store.snapshot().count(&filter("{}"), 1_000_000), n / 2);
    assert_eq!(store.snapshot().count(&filter(r#"{"kinds":[1059]}"#), 1_000_000), 0);
}

#[test]
fn operator_deleted_content_is_zeroed_on_disk() {
    let dir = tmpdir("delete-zero");
    let (_store, mut w) = Store::open(&dir, opts()).unwrap();
    let secret = "SECRET-CONTENT-YYYY";
    write(&mut w, &[ev(1, 1, 100, 14, "[]", secret), ev(2, 1, 101, 14, "[]", "kept-content")]);
    let seg = dir.join("log").join("00000000.log");
    let on_disk = |s: &str| std::fs::read(&seg).unwrap().windows(s.len()).any(|w| w == s.as_bytes());
    assert!(on_disk(secret));
    // By id, which takes the other plan.
    assert_eq!(w.delete_matching(&[filter(&format!(r#"{{"ids":["{}"]}}"#, hex32(0xEE, 1)))], None, 1_000).unwrap(), 1);
    assert!(!on_disk(secret), "the deleted event's bytes are zeroed once the delete is over");
    assert!(on_disk("kept-content"));
}

#[test]
fn matching_skips_expired_and_dead() {
    let dir = tmpdir("matching");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    write(&mut w, &[ev(1, 1, 100, 1059, r#"[["expiration","500"]]"#, "typing"), ev(2, 1, 100, 1059, "[]", "msg"), ev(3, 1, 101, 1059, "[]", "gone")]);
    let walk = |f: &str, older: Option<u64>, now: u64| {
        let v = store.snapshot();
        let ids: Vec<_> = v.matching(&[filter(f)], older, now).map(|h| h.id).collect();
        // The keys-only walk finds the same events (its hits carry seqs only).
        let by_keys: Vec<_> = v.matching_seqs(&[filter(f)], older, now).map(|h| *v.record(h.seq).unwrap().id()).collect();
        assert_eq!(by_keys, ids, "keys-only walk of {f} at {now}");
        ids
    };
    assert_eq!(walk("{}", None, 499).len(), 3);
    assert_eq!(walk("{}", None, 500), vec![id_of(3), id_of(2)], "expired at 500, newest first");
    // The same by id.
    let one = format!(r#"{{"ids":["{}"]}}"#, hex32(0xEE, 1));
    assert_eq!(walk(&one, None, 499), vec![id_of(1)]);
    assert!(walk(&one, None, 500).is_empty());
    assert_eq!(w.delete_matching(&[filter(&format!(r#"{{"ids":["{}"]}}"#, hex32(0xEE, 3)))], None, 500).unwrap(), 1);
    assert_eq!(walk("{}", None, 500), vec![id_of(2)]);
    assert!(walk("{}", Some(100), 500).is_empty(), "created at 100 is not older than 100");
    assert_eq!(walk("{}", Some(101), 500), vec![id_of(2)]);
}
