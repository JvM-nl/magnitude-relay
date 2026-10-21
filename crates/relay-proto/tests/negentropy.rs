//! Our negentropy against the reference implementation (the `negentropy` crate
//! Vector uses through nostr-sdk), both ways round, and against itself: every
//! sync must find exactly the set difference, whoever initiates.
//!
//! Three pairings per case: the reference client with our responder (how Vector
//! syncs from us), our initiator with the reference responder (how we sync from
//! strfry, whose responder is the same algorithm), and ours with ours (how our
//! relays sync from each other). Our initiator also runs in lockstep with the
//! reference one and must send byte-identical messages.

use negentropy::{Id, Negentropy, NegentropyStorageVector};
use relay_proto::negentropy::{reconcile, Initiator, NegError, VecStorage, MIN_FRAME_LIMIT};
use std::collections::BTreeSet;

type Item = (u64, [u8; 32]);
type Ids = BTreeSet<[u8; 32]>;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn id(&mut self) -> [u8; 32] {
        let mut id = [0u8; 32];
        for c in id.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        id
    }
}

fn reference_storage(items: &[Item]) -> NegentropyStorageVector {
    let mut st = NegentropyStorageVector::with_capacity(items.len());
    for (t, id) in items {
        st.insert(*t, Id::from_byte_array(*id)).unwrap();
    }
    st.seal().unwrap();
    st
}

fn ids(v: Vec<Id>) -> Ids {
    v.into_iter().map(|i| *i.as_bytes()).collect()
}

/// A responder's messages must fit its own limit.
fn fits(msg: &[u8], limit: usize, who: &str) {
    if limit != 0 {
        assert!(msg.len() <= limit, "{who} sent {} bytes over its frame limit {limit}", msg.len());
    }
}

/// The reference client against our responder: (client has, client needs, rounds).
fn reference_to_ours(client: &[Item], server: &VecStorage, client_limit: usize, server_limit: usize) -> (Ids, Ids, usize) {
    let mut neg = Negentropy::owned(reference_storage(client), client_limit as u64).unwrap();
    let mut msg = neg.initiate().unwrap();
    let (mut have, mut need) = (Vec::new(), Vec::new());
    let mut rounds = 0;
    loop {
        rounds += 1;
        assert!(rounds < 1000, "sync does not converge");
        let resp = reconcile(server, &msg, server_limit).unwrap();
        fits(&resp, server_limit, "our responder");
        match neg.reconcile_with_ids(&resp, &mut have, &mut need).unwrap() {
            Some(next) => {
                fits(&next, client_limit, "the reference client");
                msg = next;
            }
            None => break,
        }
    }
    (ids(have), ids(need), rounds)
}

/// Our initiator against any responder: (we have, we need, rounds). An id can
/// be reported more than once, by ours as by the reference: when a message is
/// cut at the frame limit, ranges already settled in it are covered again by
/// the fingerprint of the rest (the lockstep test proves the reference does the
/// same). Callers deduplicate.
fn ours_to(client: &[Item], client_limit: usize, mut respond: impl FnMut(&[u8]) -> Vec<u8>) -> (Ids, Ids, usize) {
    let init = Initiator::new(VecStorage::new(client.to_vec()), client_limit).unwrap();
    let mut msg = init.initiate();
    let (mut have, mut need) = (Vec::new(), Vec::new());
    let mut rounds = 0;
    loop {
        rounds += 1;
        assert!(rounds < 1000, "sync does not converge");
        fits(&msg, client_limit, "our initiator");
        let resp = respond(&msg);
        match init.reconcile(&resp, &mut have, &mut need).unwrap() {
            Some(next) => msg = next,
            None => break,
        }
    }
    (have.into_iter().collect(), need.into_iter().collect(), rounds)
}

/// Our initiator and the reference initiator, same set, same responder (ours):
/// every message they send must be the same bytes.
fn lockstep(client: &[Item], server: &VecStorage, client_limit: usize, server_limit: usize) {
    let ours = Initiator::new(VecStorage::new(client.to_vec()), client_limit).unwrap();
    let mut theirs = Negentropy::owned(reference_storage(client), client_limit as u64).unwrap();
    let mut msg = ours.initiate();
    assert_eq!(msg, theirs.initiate().unwrap(), "first message");
    let (mut h1, mut n1, mut h2, mut n2) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for round in 0.. {
        assert!(round < 1000, "sync does not converge");
        let resp = reconcile(server, &msg, server_limit).unwrap();
        let a = ours.reconcile(&resp, &mut h1, &mut n1).unwrap();
        let b = theirs.reconcile_with_ids(&resp, &mut h2, &mut n2).unwrap();
        assert_eq!(a, b, "round {round}");
        match a {
            Some(next) => msg = next,
            None => break,
        }
    }
}

fn sets(seed: u64, n_shared: usize, n_client: usize, n_server: usize, same_second: bool) -> (Vec<Item>, Vec<Item>, Ids, Ids) {
    let mut r = Rng(seed);
    let ts = |r: &mut Rng| if same_second { 1_700_000_000 } else { 1_700_000_000 + r.next() % 1_000_000 };
    let shared: Vec<Item> = (0..n_shared).map(|_| (ts(&mut r), r.id())).collect();
    let only_c: Vec<Item> = (0..n_client).map(|_| (ts(&mut r), r.id())).collect();
    let only_s: Vec<Item> = (0..n_server).map(|_| (ts(&mut r), r.id())).collect();
    let client = shared.iter().chain(&only_c).copied().collect();
    let server = shared.iter().chain(&only_s).copied().collect();
    (client, server, only_c.iter().map(|x| x.1).collect(), only_s.iter().map(|x| x.1).collect())
}

/// Every pairing must find exactly the difference. `limits` are (initiator, responder).
fn check(seed: u64, n_shared: usize, n_client: usize, n_server: usize, same_second: bool, limits: (usize, usize)) {
    let (client, server, only_c, only_s) = sets(seed, n_shared, n_client, n_server, same_second);
    let (cl, sl) = limits;
    let ours = VecStorage::new(server.clone());

    let (have, need, _) = reference_to_ours(&client, &ours, cl, sl);
    assert_eq!((&have, &need), (&only_c, &only_s), "reference client, our responder, seed {seed}");

    let (have, need, _) = ours_to(&client, cl, |m| reconcile(&ours, m, sl).unwrap());
    assert_eq!((&have, &need), (&only_c, &only_s), "our initiator, our responder, seed {seed}");

    let mut theirs = Negentropy::owned(reference_storage(&server), sl as u64).unwrap();
    let (have, need, _) = ours_to(&client, cl, |m| {
        let resp = theirs.reconcile(m).unwrap();
        fits(&resp, sl, "the reference responder");
        resp
    });
    assert_eq!((&have, &need), (&only_c, &only_s), "our initiator, reference responder, seed {seed}");

    lockstep(&client, &ours, cl, sl);
}

#[test]
fn small_and_empty_sets() {
    check(1, 0, 0, 0, false, (0, 0));
    check(2, 0, 5, 0, false, (0, 0));
    check(3, 0, 0, 5, false, (0, 0));
    check(4, 10, 3, 4, false, (0, 0));
    check(5, 31, 1, 1, false, (0, 0));
    check(6, 32, 0, 1, false, (0, 0));
}

#[test]
fn identical_and_disjoint_sets() {
    // Identical: settled by the first answer, whatever the size.
    let (client, server, _, _) = sets(7, 50_000, 0, 0, false);
    let ours = VecStorage::new(server);
    let (have, need, rounds) = ours_to(&client, 60_000, |m| reconcile(&ours, m, 60_000).unwrap());
    assert!(have.is_empty() && need.is_empty());
    assert_eq!(rounds, 1, "one answer of matching fingerprints ends it");
    // Nothing in common, each side large, both limited.
    check(8, 0, 20_000, 20_000, false, (60_000, 60_000));
    check(9, 0, 5_000, 5_000, true, (MIN_FRAME_LIMIT, MIN_FRAME_LIMIT));
    // One side empty.
    check(10, 0, 30_000, 0, false, (60_000, 60_000));
    check(11, 0, 0, 30_000, false, (60_000, 500_000));
}

#[test]
fn large_sets_no_limit() {
    for seed in 12..16 {
        check(seed, 20_000, 500, 700, false, (0, 0));
    }
}

#[test]
fn identical_timestamps_need_id_bounds() {
    // Every item in one second: bounds must split on id prefixes.
    check(20, 5_000, 300, 200, true, (0, 0));
    check(21, 5_000, 300, 200, true, (60_000, 60_000));
}

#[test]
fn frame_limits_like_vector() {
    // Vector syncs with a 60 000-byte client frame limit; a mailbox that is
    // mostly missing makes the server answer with long id lists.
    check(30, 1_000, 0, 50_000, false, (60_000, 60_000));
    check(31, 30_000, 20_000, 2_000, false, (60_000, 60_000));
    check(32, 10_000, 100, 100, false, (60_000, 4_096 + 200));
}

#[test]
fn frame_limits_like_strfry() {
    // Syncing from strfry: our 60 000-byte initiator against its 500 000-byte
    // responder, with lots missing on our side (a first copy) and on theirs.
    check(33, 20_000, 0, 100_000, false, (60_000, 500_000));
    check(34, 20_000, 100_000, 0, false, (60_000, 500_000));
    // And the smallest limits the protocol allows.
    check(35, 3_000, 2_000, 2_000, false, (MIN_FRAME_LIMIT, MIN_FRAME_LIMIT));
}

#[test]
fn mailbox_scale() {
    // A heavy account: 100k wraps held, relay has 2k new ones.
    check(40, 100_000, 0, 2_000, false, (60_000, 60_000));
}

#[test]
fn a_million_items_every_pairing() {
    check(52, 1_000_000, 2_000, 2_000, false, (60_000, 500_000));
}

#[test]
fn a_million_items() {
    // A relay's worth: a million in common, a few thousand different each way.
    let (client, server, only_c, only_s) = sets(50, 1_000_000, 3_000, 4_000, false);
    let ours = VecStorage::new(server);
    let (have, need, rounds) = ours_to(&client, 60_000, |m| reconcile(&ours, m, 500_000).unwrap());
    assert_eq!((have, need), (only_c, only_s));
    // 7 000 differences sit in ~7 000 buckets of under 32, each settled by an
    // id list of about a kilobyte: a 60 000-byte message carries ~60 of them.
    assert!(rounds < 150, "{rounds} rounds");
    // And a million missing outright: a first copy of a whole relay, ~15 600
    // ids per 500 000-byte answer.
    let (client, server, only_c, only_s) = sets(51, 0, 0, 1_000_000, false);
    let ours = VecStorage::new(server);
    let (have, need, rounds) = ours_to(&client, 60_000, |m| reconcile(&ours, m, 500_000).unwrap());
    assert_eq!((have.len(), need.len()), (0, 1_000_000));
    assert_eq!((have, need), (only_c, only_s));
    assert!(rounds <= 1_000_000 / 15_000 + 2, "{rounds} rounds");
}

#[test]
fn unsupported_version_answers_with_ours() {
    let server = VecStorage::new(vec![]);
    assert_eq!(reconcile(&server, &[0x62], 0).unwrap(), vec![0x61]);
    assert!(reconcile(&server, &[0x10], 0).is_err());
    assert!(reconcile(&server, &[0x61, 0x00, 0x00, 0x01], 0).is_err(), "truncated fingerprint");
}

#[test]
fn initiator_refuses_what_it_cannot_use() {
    assert_eq!(Initiator::new(VecStorage::new(vec![]), 100).err(), Some(NegError::FrameLimitTooSmall));
    let init = Initiator::new(VecStorage::new(vec![]), 0).unwrap();
    let (mut h, mut n) = (Vec::new(), Vec::new());
    // A responder that only speaks another version says so with a lone byte.
    assert_eq!(init.reconcile(&[0x62], &mut h, &mut n), Err(NegError::UnsupportedVersion(0x62)));
    assert_eq!(init.reconcile(&[0x10], &mut h, &mut n), Err(NegError::BadVersion));
    assert_eq!(init.reconcile(&[], &mut h, &mut n), Err(NegError::Truncated));
    // An id list claiming more ids than the message holds.
    assert_eq!(init.reconcile(&[0x61, 0x00, 0x00, 0x02, 0x05], &mut h, &mut n), Err(NegError::Truncated));
    assert_eq!(init.reconcile(&[0x61, 0x00, 0x00, 0x07], &mut h, &mut n), Err(NegError::BadMode));
    // An empty answer (just the version) means done.
    assert_eq!(init.reconcile(&[0x61], &mut h, &mut n), Ok(None));
}
