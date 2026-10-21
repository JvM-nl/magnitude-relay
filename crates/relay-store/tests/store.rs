//! Store behaviour: NIP-01 rules, Concord's deletion rule, durability and
//! recovery, and a randomized check of the query engine against brute force.

use relay_proto::event::parse_event_json;
use relay_proto::json::Scanner;
use relay_proto::{hex, EventParser, Filter, Record};
use relay_store::{Options, Outcome, Store, Writer};
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
    Options { segment_size: 64 * 1024, sync: true, flush_bytes: 4096, vanish_urls: vec!["wss://relay.example/nostr".into()] }
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
