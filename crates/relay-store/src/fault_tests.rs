//! Writes that fail part way (a full disk, see `fault.rs`): whatever failed
//! must leave nothing that a later write, a reader or a restart could misread.

use crate::fault;
use crate::{Options, Outcome, Store, Writer};
use relay_proto::event::parse_event_json;
use relay_proto::{hex, EventParser};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) fn tmpdir(name: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let d = std::env::temp_dir().join(format!("relay-store-fault-{}-{}-{}", std::process::id(), name, N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    d
}

pub(crate) fn opts() -> Options {
    Options { segment_size: 64 * 1024, sync: true, flush_bytes: 1 << 20, ..Options::default() }
}

fn hex32(b: u8, n: u64) -> String {
    let mut v = [b; 32];
    v[24..].copy_from_slice(&n.to_be_bytes());
    hex::encode_string(&v)
}

pub(crate) fn id_of(n: u64) -> [u8; 32] {
    hex::decode_32(hex32(0xEE, n).as_bytes()).unwrap()
}

/// A kind-1 event record by author `author`, `pad` bytes of content.
pub(crate) fn ev(n: u64, author: u8, pad: usize) -> Vec<u8> {
    ev_kind(n, author, 1, pad)
}

fn ev_kind(n: u64, author: u8, kind: u64, pad: usize) -> Vec<u8> {
    let json = format!(
        r#"{{"id":"{}","pubkey":"{}","created_at":{},"kind":{kind},"tags":[],"content":"{}","sig":"{}"}}"#,
        hex32(0xEE, n),
        hex32(author, 0),
        1000 + n,
        "x".repeat(pad),
        "00".repeat(64)
    );
    let mut p = EventParser::new();
    let mut rec = Vec::new();
    parse_event_json(&json, &mut p, &mut rec, false).unwrap();
    rec
}

pub(crate) fn write(w: &mut Writer, recs: &[Vec<u8>]) -> std::io::Result<Vec<Outcome>> {
    let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
    w.write(&refs)
}

/// Every live seq's record looks itself up by id at that seq, and the ids
/// found are exactly `want`.
fn check(store: &Store, want: &[u64]) {
    let v = store.snapshot();
    let mut got = Vec::new();
    for seq in 0..v.count {
        let Some(r) = v.record(seq) else { continue };
        assert_eq!(v.lookup_id(r.id()), Some(seq), "seq {seq} is not where its id points");
        got.push(u64::from_be_bytes(r.id()[24..].try_into().unwrap()));
    }
    assert_eq!(got, want, "the live events, in seq order");
    for n in 0..64 {
        if let Some(seq) = v.lookup_id(&id_of(n)) {
            let r = v.record(seq).unwrap_or_else(|| panic!("event {n}'s id points at dead seq {seq}"));
            assert_eq!(r.id(), &id_of(n), "event {n}'s id points at another event's record");
        }
    }
}

fn reopen(dir: &Path, store: Store, w: Writer) -> (Store, Writer) {
    w.close();
    drop(store);
    Store::open(dir, opts()).unwrap()
}

/// Found by the adversarial suite's disk-fault torture: a log write that
/// failed left its frames queued, and the next batch wrote them out ahead of
/// its own under the same seqs. After a restart one event's index entries
/// pointed at the other's record.
#[test]
fn a_failed_append_leaves_nothing_for_the_next_one_to_write() {
    let dir = tmpdir("failed-append");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    write(&mut w, &[ev(1, 1, 10)]).unwrap();
    fault::fail_writes(&dir, 0);
    assert!(write(&mut w, &[ev(2, 2, 10)]).is_err());
    fault::clear(&dir);
    assert_eq!(write(&mut w, &[ev(3, 3, 10)]).unwrap(), vec![Outcome::Stored(1)]);
    check(&store, &[1, 3]);
    let (store, w) = reopen(&dir, store, w);
    assert_eq!(w.next_seq(), 2);
    check(&store, &[1, 3]);
    let _ = std::fs::remove_dir_all(dir);
}

/// The failed batch's frames went to a new log segment, the next batch's fit
/// in the old one: the failed frames must not be replayed from the new
/// segment under seqs given out again.
#[test]
fn a_failed_append_into_a_new_segment_is_not_replayed() {
    let dir = tmpdir("failed-roll");
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    // Fill the first segment to within about 3 KB of its end.
    let mut n = 1;
    let mut stored = Vec::new();
    while w.log.head() < 60 * 1024 {
        write(&mut w, &[ev(n, 1, 900)]).unwrap();
        stored.push(n);
        n += 1;
    }
    // Too big for what is left of segment 0: goes to segment 1, and fails
    // there after its first frame is written.
    fault::fail_writes(&dir, 6000);
    assert!(write(&mut w, &[ev(100, 2, 5000), ev(101, 2, 5000)]).is_err());
    fault::clear(&dir);
    // Small enough for segment 0.
    write(&mut w, &[ev(102, 3, 10)]).unwrap();
    stored.push(102);
    check(&store, &stored);
    let (store, _w) = reopen(&dir, store, w);
    check(&store, &stored);
    let _ = std::fs::remove_dir_all(dir);
}

/// Two profiles, then a batch replacing both whose second kill cannot be
/// flagged on disk (the disk fills up right after the first flag).
fn replace_both_with_the_second_flag_failing(name: &str) -> (PathBuf, Store, Writer, std::io::Result<Vec<Outcome>>) {
    let first = [ev_kind(1, 1, 0, 10), ev_kind(2, 2, 0, 10)];
    let batch = [ev_kind(3, 1, 0, 10), ev_kind(4, 2, 0, 10)];
    let refs: Vec<&[u8]> = batch.iter().map(|r| r.as_slice()).collect();
    // What the batch's frames and locations take, measured on a twin.
    let twin = tmpdir(&format!("{name}-twin"));
    let appended = {
        let (_s, mut w) = Store::open(&twin, opts()).unwrap();
        write(&mut w, &first).unwrap();
        fault::fail_writes(&twin, 1 << 40);
        let _ = w.stage(&refs).unwrap();
        let n = (1 << 40) - fault::remaining(&twin).unwrap();
        fault::clear(&twin);
        w.close();
        n
    };
    let _ = std::fs::remove_dir_all(twin);
    let dir = tmpdir(name);
    let (store, mut w) = Store::open(&dir, opts()).unwrap();
    write(&mut w, &first).unwrap();
    fault::fail_writes(&dir, appended + 4);
    let r = write(&mut w, &batch);
    fault::clear(&dir);
    (dir, store, w, r)
}

/// Found by the adversarial suite's disk-fault torture: a batch whose second
/// kill could not be flagged failed after its first kill had been queued for
/// zeroing. That kill never happened, yet the next flush zeroed the record:
/// a live event served as zeros. Now the kills happen (a kill without its flag
/// keeps its bytes until a checkpoint records it) and the batch succeeds.
#[test]
fn a_kill_whose_flag_cannot_be_written_never_zeroes_a_live_record() {
    let (dir, store, mut w, r) = replace_both_with_the_second_flag_failing("flag-fails");
    w.flush_all().unwrap();
    write(&mut w, &[ev(5, 3, 10)]).unwrap();
    // Whatever the batch's fate, every live record is itself, not zeros...
    let live = if r.is_ok() { [3, 4, 5] } else { [1, 2, 5] };
    check(&store, &live);
    let (store, w) = reopen(&dir, store, w);
    check(&store, &live);
    // ...and the batch went through.
    assert_eq!(r.unwrap(), vec![Outcome::Stored(2), Outcome::Stored(3)]);
    drop((store, w));
    let _ = std::fs::remove_dir_all(dir);
}

/// The same, with a crash before any checkpoint: the kill that has no flag is
/// re-derived from the log.
#[test]
fn a_kill_whose_flag_cannot_be_written_survives_a_crash() {
    let (dir, store, w, r) = replace_both_with_the_second_flag_failing("flag-fails-crash");
    r.unwrap();
    let (store, _w) = reopen(&dir, store, w);
    check(&store, &[3, 4]);
    let _ = std::fs::remove_dir_all(dir);
}
