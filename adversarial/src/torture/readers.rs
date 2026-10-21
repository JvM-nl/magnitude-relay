//! Readers beside the writer: snapshots taken and held for a while (as a slow
//! client or an operator's walk would), queried, and every answer checked for
//! what must hold in any snapshot whatever the writer is doing: results match
//! the filter, are ordered, are live and unexpired, look themselves up by id,
//! and are well-formed events; COUNT agrees with the query and with the walk.
//! A broken invariant panics, which the child reports and the parent fails on.
//!
//! A snapshot never sees events published after it, but it does see kills: the
//! dead set is shared, so an event can die between two calls on one snapshot
//! (by design: deleted events stop being served at once). Checks that a kill
//! in between could explain are only enforced when the dead set did not
//! change while they ran.

use super::child::NOW;
use super::work;
use crate::rng::Rng;
use relay_proto::event::parse_event_json;
use relay_proto::{EventParser, Filter};
use relay_store::{Store, Version};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub fn check_snapshot(v: &Version, f: &Filter, rng: &mut Rng) {
    let before = v.dead_count();
    let mut soft: Vec<String> = Vec::new();
    let limit = 1 + rng.skewed(300) as usize;
    let hits = v.query(f, limit, NOW);
    assert!(hits.len() <= limit, "query returned {} for limit {limit}", hits.len());
    let mut parser = EventParser::new();
    let mut back = Vec::new();
    for w in hits.windows(2) {
        assert!(
            (w[0].created_at, std::cmp::Reverse(w[0].id)) > (w[1].created_at, std::cmp::Reverse(w[1].id)),
            "results out of order or repeated"
        );
    }
    for h in &hits {
        let Some(r) = v.record(h.seq) else {
            soft.push(format!("hit seq {} is not live in its own snapshot", h.seq));
            continue;
        };
        assert_eq!(r.id(), &h.id, "hit id does not match its record (seq {})", h.seq);
        assert_eq!(r.created_at(), h.created_at, "hit time does not match its record");
        assert!(f.matches(r), "record does not match the filter that found it");
        assert!(r.expiration().is_none_or(|e| e > NOW), "expired event returned");
        if v.lookup_id(r.id()) != Some(h.seq) {
            soft.push(format!("id lookup of seq {} disagrees with the scan", h.seq));
        }
        let json = r.to_json();
        parse_event_json(&json, &mut parser, &mut back, false).unwrap_or_else(|e| panic!("stored record is not an event ({e}): {json}"));
        // The store keeps base64 content decoded (`record::compact_into`).
        let mut kept = Vec::new();
        relay_proto::record::compact_into(&back, &mut kept);
        assert_eq!(kept.as_slice(), r.0, "record does not survive its own JSON");
    }
    if rng.chance(1, 3) {
        let all = v.query(f, usize::MAX, NOW);
        let n = v.count(f, NOW);
        let walk = v.matching(std::slice::from_ref(f), None, NOW).count();
        // Kills only ever remove: each later answer is at most the earlier one.
        assert!(n as usize <= all.len(), "COUNT {n} is more than the query found ({})", all.len());
        assert!(walk as u64 <= n, "operator walk finds {walk}, more than COUNT {n}");
        if n as usize != all.len() || walk as u64 != n {
            soft.push(format!("query {}, COUNT {n}, walk {walk}", all.len()));
        }
    }
    if !soft.is_empty() && v.dead_count() == before {
        panic!("with no kill in between: {}", soft.join("; "));
    }
}

/// Runs reader threads until the process ends.
pub fn spawn(slot: Arc<RwLock<Option<Store>>>, seed: u64) {
    for t in 0..2u64 {
        let slot = slot.clone();
        std::thread::spawn(move || {
            let mut rng = Rng::derive(seed ^ 0x5EAD, t);
            loop {
                let store = slot.read().unwrap().clone();
                let Some(store) = store else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                let v = store.snapshot();
                drop(store);
                for _ in 0..1 + rng.below(8) {
                    let f = super::model::parse_filter(&work::filter_json(seed, &mut rng));
                    check_snapshot(&v, &f, &mut rng);
                }
                // Hold it: reclaim and log relinking must wait for us.
                std::thread::sleep(Duration::from_millis(rng.skewed(40)));
                drop(v);
            }
        });
    }
}
