//! Our responder against the reference client (the `negentropy` crate Vector
//! uses through nostr-sdk): every sync must find exactly the set difference.

use negentropy::{Id, Negentropy, NegentropyStorageVector};
use relay_proto::negentropy::{reconcile, VecStorage};
use std::collections::BTreeSet;

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

/// Runs a full reconciliation; returns (client has, client needs) and rounds.
fn sync(client: &[(u64, [u8; 32])], server: &VecStorage, client_limit: u64, server_limit: usize) -> (BTreeSet<[u8; 32]>, BTreeSet<[u8; 32]>, usize) {
    let mut st = NegentropyStorageVector::with_capacity(client.len());
    for (t, id) in client {
        st.insert(*t, Id::from_byte_array(*id)).unwrap();
    }
    st.seal().unwrap();
    let mut neg = Negentropy::owned(st, client_limit).unwrap();
    let mut msg = neg.initiate().unwrap();
    let (mut have, mut need) = (Vec::new(), Vec::new());
    let mut rounds = 0;
    loop {
        rounds += 1;
        assert!(rounds < 1000, "sync does not converge");
        let resp = reconcile(server, &msg, server_limit).unwrap();
        if server_limit != 0 {
            assert!(resp.len() <= server_limit, "response {} over frame limit {server_limit}", resp.len());
        }
        match neg.reconcile_with_ids(&resp, &mut have, &mut need).unwrap() {
            Some(next) => msg = next,
            None => break,
        }
    }
    let have = have.into_iter().map(|i| *i.as_bytes()).collect();
    let need = need.into_iter().map(|i| *i.as_bytes()).collect();
    (have, need, rounds)
}

fn check(seed: u64, n_shared: usize, n_client: usize, n_server: usize, same_second: bool, limits: (u64, usize)) {
    let mut r = Rng(seed);
    let ts = |r: &mut Rng| if same_second { 1_700_000_000 } else { 1_700_000_000 + r.next() % 1_000_000 };
    let shared: Vec<_> = (0..n_shared).map(|_| (ts(&mut r), r.id())).collect();
    let only_c: Vec<_> = (0..n_client).map(|_| (ts(&mut r), r.id())).collect();
    let only_s: Vec<_> = (0..n_server).map(|_| (ts(&mut r), r.id())).collect();
    let client: Vec<_> = shared.iter().chain(&only_c).copied().collect();
    let server = VecStorage::new(shared.iter().chain(&only_s).copied().collect());
    let (have, need, rounds) = sync(&client, &server, limits.0, limits.1);
    assert_eq!(have, only_c.iter().map(|x| x.1).collect(), "have, seed {seed}");
    assert_eq!(need, only_s.iter().map(|x| x.1).collect(), "need, seed {seed}");
    let _ = rounds;
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
fn large_sets_no_limit() {
    for seed in 10..14 {
        check(seed, 20_000, 500, 700, false, (0, 0));
    }
}

#[test]
fn identical_timestamps_need_id_bounds() {
    // Every item in one second: bounds must split on id prefixes.
    check(20, 5_000, 300, 200, true, (0, 0));
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
fn mailbox_scale() {
    // A heavy account: 100k wraps held, relay has 2k new ones.
    check(40, 100_000, 0, 2_000, false, (60_000, 60_000));
}

#[test]
fn unsupported_version_answers_with_ours() {
    let server = VecStorage::new(vec![]);
    assert_eq!(reconcile(&server, &[0x62], 0).unwrap(), vec![0x61]);
    assert!(reconcile(&server, &[0x10], 0).is_err());
    assert!(reconcile(&server, &[0x61, 0x00, 0x00, 0x01], 0).is_err(), "truncated fingerprint");
}
