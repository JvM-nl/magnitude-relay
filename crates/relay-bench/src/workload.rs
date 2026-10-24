//! The workloads: which filters to send, and, computed from the dataset before a
//! single request goes out, what each answer must be.
//!
//! A workload is a pool of distinct queries (`--distinct`, default 256) that the
//! connections cycle through in a seeded pseudo-random order. A pool rather than one
//! query because a single repeated query measures one hot cache line; 256 different
//! authors, mailboxes or windows measure the index. Parameters are drawn from the
//! dataset itself, so every query has a known, non-trivial answer, and the draw is
//! seeded, so two relays face the identical request stream.
//!
//! Two deliberate choices keep the relays comparable:
//! * Filters that would otherwise match gift wraps always name an author, a `#p`
//!   or ids, because the relay under development refuses (and others may hide) wraps
//!   in broad scans, per docs/DESIGN.md.
//! * Every filter carries an explicit `limit` (relays differ on the default: strfry
//!   500, ours 500, others unlimited).

use crate::data::{fnv64, Dataset, FilterSpec, Expected, GIFT_WRAP};
use crate::rng::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// fastr's names, in its order.
pub const CLASSIC: [&str; 12] =
    ["latest_1", "latest_100", "latest_500", "author", "kind", "author_kind", "tag", "time_window", "exact_id", "exact_ids_100", "miss", "multi_filter"];
/// Vector's real shapes.
pub const VECTOR: [&str; 5] = ["dm_inbox", "dm_catchup", "concord_page", "concord_paging", "dm_ids"];
pub const COUNT: &str = "count";

/// The kinds of the "generic" part of the dataset: the notes, reactions and articles
/// the classic workloads ask for.
pub const GENERIC_KINDS: [u32; 3] = [1, 7, 30023];
/// Pages walked back through a plane by `concord_paging`.
pub const PAGES: usize = 5;
const TWO_DAYS: u32 = 172_800;

/// Workload names from a `--workload` value: a name, a comma list, or the groups
/// `classic`, `vector` and `all`.
pub fn expand(spec: &str) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let names: Vec<&str> = match part {
            "classic" => CLASSIC.to_vec(),
            "vector" => VECTOR.to_vec(),
            "all" => CLASSIC.iter().chain(VECTOR.iter()).copied().chain([COUNT]).collect(),
            one if CLASSIC.contains(&one) || VECTOR.contains(&one) || one == COUNT => vec![one],
            other => return Err(format!("unknown workload '{other}' (classic: {}; vector: {}; count; or classic|vector|all)", CLASSIC.join(" "), VECTOR.join(" "))),
        };
        for n in names {
            if !out.iter().any(|o| o == n) {
                out.push(n.to_owned());
            }
        }
    }
    if out.is_empty() {
        return Err("--workload is empty".into());
    }
    Ok(out)
}

/// One request and its known answer.
pub enum Step {
    Req { json: String, exp: Expected },
    Count { json: String, expect: u64 },
}

impl Step {
    pub fn json(&self) -> &str {
        match self {
            Step::Req { json, .. } | Step::Count { json, .. } => json,
        }
    }
}

/// One unit of work for a connection: usually a single request; for `concord_paging`
/// a whole walk, whose requests must go out in order.
pub struct Op {
    pub steps: Vec<Step>,
}

pub struct Pool {
    pub ops: Vec<Op>,
}

pub struct PoolOpts {
    /// Overrides the page size of the workloads that have a configurable one.
    pub limit: Option<usize>,
    pub distinct: usize,
    pub seed: u64,
}

fn req_op(ds: &Dataset, filters: Vec<FilterSpec>) -> Op {
    let exp = ds.expected(&filters);
    let json = filters.iter().map(FilterSpec::to_json).collect::<Vec<_>>().join(",");
    Op { steps: vec![Step::Req { json, exp }] }
}

/// Random live events satisfying `pred`, by rejection sampling.
fn sample_events(ds: &Dataset, rng: &mut Rng, n: usize, pred: impl Fn(&crate::data::Meta) -> bool) -> Vec<u32> {
    let mut out = Vec::new();
    for _ in 0..n.saturating_mul(40) {
        let i = rng.below(ds.len() as u64) as u32;
        if pred(&ds.events[i as usize]) {
            out.push(i);
            if out.len() == n {
                break;
            }
        }
    }
    out
}

/// Picks up to `n` distinct groups, a quarter from the heaviest ~1% (at most 20) and
/// the rest from the remainder: "a mix of light and heavy mailboxes". Groups smaller
/// than `min` are ignored (a plane-traffic wrap's random `p` is a mailbox of one).
fn pick_mixed<T: Clone>(groups: &[(T, u32)], rng: &mut Rng, n: usize, min: u32) -> Vec<T> {
    let usable: Vec<&(T, u32)> = groups.iter().filter(|g| g.1 >= min).collect();
    if usable.len() <= n {
        return usable.into_iter().map(|g| g.0.clone()).collect();
    }
    let heavy_n = (usable.len() / 100).clamp(1, 20);
    let (heavy, light) = usable.split_at(heavy_n);
    let mut picked = HashSet::new();
    let mut out = Vec::new();
    for i in 0..n * 40 {
        let (pool, base) = if i % 4 == 0 { (heavy, 0) } else { (light, heavy_n) };
        let k = base + rng.below(pool.len() as u64) as usize;
        if picked.insert(k) {
            out.push(usable[k].0.clone());
            if out.len() == n {
                break;
            }
        }
    }
    out
}

fn limit_or(o: &PoolOpts, default: usize) -> usize {
    o.limit.unwrap_or(default)
}

fn need(ok: bool, what: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("the dataset has no {what}"))
    }
}

pub fn build(name: &str, ds: &Dataset, o: &PoolOpts) -> Result<Pool, String> {
    let mut rng = Rng::for_item(o.seed, fnv64(name), 0x57);
    let generic = || FilterSpec { kinds: GENERIC_KINDS.to_vec(), ..Default::default() };
    let non_wrap = |m: &crate::data::Meta| m.kind != GIFT_WRAP;
    let mut ops = Vec::new();
    match name {
        "latest_1" | "latest_100" | "latest_500" => {
            let n: usize = name.rsplit('_').next().unwrap().parse().unwrap();
            ops.push(req_op(ds, vec![FilterSpec { limit: Some(n), ..generic() }]));
        }
        "author" => {
            let mut seen = HashSet::new();
            for i in sample_events(ds, &mut rng, o.distinct * 4, non_wrap) {
                let pk = ds.events[i as usize].pk;
                if seen.insert(pk) && ops.len() < o.distinct {
                    ops.push(req_op(ds, vec![FilterSpec { authors: vec![pk], limit: Some(limit_or(o, 100)), ..Default::default() }]));
                }
            }
        }
        "kind" => {
            let present: HashSet<u32> = ds.kind_counts().into_iter().map(|k| k.0).collect();
            for k in [0u32, 1, 7, 10050, 30023, 30078] {
                if present.contains(&k) {
                    ops.push(req_op(ds, vec![FilterSpec { kinds: vec![k], limit: Some(limit_or(o, 100)), ..Default::default() }]));
                }
            }
        }
        "author_kind" => {
            let mut seen = HashSet::new();
            for i in sample_events(ds, &mut rng, o.distinct * 4, non_wrap) {
                let m = &ds.events[i as usize];
                if seen.insert((m.pk, m.kind)) && ops.len() < o.distinct {
                    ops.push(req_op(ds, vec![FilterSpec { authors: vec![m.pk], kinds: vec![m.kind], limit: Some(limit_or(o, 100)), ..Default::default() }]));
                }
            }
        }
        "tag" => {
            for w in ds.sample_words(&mut rng, o.distinct) {
                ops.push(req_op(ds, vec![FilterSpec { t: vec![w], limit: Some(limit_or(o, 100)), ..Default::default() }]));
            }
        }
        "time_window" => {
            // Windows start at the time of a real generic event, so none is empty.
            let mut seen = HashSet::new();
            for i in sample_events(ds, &mut rng, o.distinct * 4, |m| GENERIC_KINDS.contains(&m.kind)) {
                let since = ds.events[i as usize].ts;
                if seen.insert(since) && ops.len() < o.distinct {
                    ops.push(req_op(ds, vec![FilterSpec { since: Some(since), until: Some(since + 3599), limit: Some(limit_or(o, 500)), ..generic() }]));
                }
            }
        }
        "exact_id" => {
            let mut seen = HashSet::new();
            for i in sample_events(ds, &mut rng, o.distinct * 2, |_| true) {
                if seen.insert(i) && ops.len() < o.distinct {
                    ops.push(req_op(ds, vec![FilterSpec { ids: vec![ds.events[i as usize].id], limit: Some(1), ..Default::default() }]));
                }
            }
        }
        "exact_ids_100" => {
            for _ in 0..o.distinct {
                let mut seen = HashSet::new();
                let ids: Vec<[u8; 32]> =
                    sample_events(ds, &mut rng, 200, |_| true).into_iter().filter(|i| seen.insert(*i)).take(100).map(|i| ds.events[i as usize].id).collect();
                ops.push(req_op(ds, vec![FilterSpec { limit: Some(ids.len()), ids, ..Default::default() }]));
            }
        }
        "miss" => {
            for i in 0..o.distinct as u64 {
                let mut salt = 0u64;
                let id = loop {
                    let mut h = Sha256::new();
                    h.update(b"miss");
                    h.update(o.seed.to_le_bytes());
                    h.update(i.to_le_bytes());
                    h.update(salt.to_le_bytes());
                    let id: [u8; 32] = h.finalize().into();
                    if ds.lookup_id(&id).is_none() {
                        break id;
                    }
                    salt += 1;
                };
                ops.push(req_op(ds, vec![FilterSpec { ids: vec![id], limit: Some(1), ..Default::default() }]));
            }
        }
        "multi_filter" => {
            let lim = limit_or(o, 50);
            let authors = sample_events(ds, &mut rng, o.distinct, non_wrap);
            let words = ds.sample_words(&mut rng, o.distinct);
            need(!authors.is_empty() && !words.is_empty(), "authors with tagged events")?;
            for (j, a) in authors.iter().enumerate() {
                let k = GENERIC_KINDS[j % GENERIC_KINDS.len()];
                ops.push(req_op(
                    ds,
                    vec![
                        FilterSpec { authors: vec![ds.events[*a as usize].pk], limit: Some(lim), ..Default::default() },
                        FilterSpec { t: vec![words[j % words.len()].clone()], limit: Some(lim), ..Default::default() },
                        FilterSpec { kinds: vec![k], limit: Some(lim), ..Default::default() },
                    ],
                ));
            }
        }
        "dm_inbox" | "dm_catchup" => {
            let boxes = pick_mixed(&ds.wrap_mailboxes(), &mut rng, o.distinct, 2);
            let since = (name == "dm_catchup").then(|| ds.max_ts.saturating_sub(TWO_DAYS));
            for r in boxes {
                ops.push(req_op(ds, vec![FilterSpec { kinds: vec![GIFT_WRAP], p: vec![r], since, limit: Some(limit_or(o, 500)), ..Default::default() }]));
            }
        }
        "concord_page" => {
            for plane in pick_mixed(&ds.pure_authors(GIFT_WRAP, 2), &mut rng, o.distinct, 2) {
                ops.push(req_op(ds, vec![FilterSpec { kinds: vec![GIFT_WRAP], authors: vec![plane], limit: Some(limit_or(o, 500)), ..Default::default() }]));
            }
        }
        "concord_paging" => {
            // Heavy planes: that is where paging happens. Each walk follows the *expected*
            // cursor, so the request stream does not depend on what the relay answered.
            let planes = ds.pure_authors(GIFT_WRAP, 2);
            let take = planes.len().min(o.distinct.min(32));
            for (plane, _) in planes.into_iter().take(take) {
                let limit = limit_or(o, 500);
                let mut steps = Vec::new();
                let mut until: Option<u32> = None;
                for _ in 0..PAGES {
                    let f = FilterSpec { kinds: vec![GIFT_WRAP], authors: vec![plane], until, limit: Some(limit), ..Default::default() };
                    let exp = ds.expected(std::slice::from_ref(&f));
                    let Some(last) = exp.order.last() else { break };
                    let cursor = exp.want[last];
                    steps.push(Step::Req { json: f.to_json(), exp });
                    // `until` is inclusive: the boundary second is fetched again, which is how
                    // a same-second wall is crossed. If a whole page sits in one second the
                    // cursor cannot advance, so step past it rather than loop forever.
                    until = Some(if Some(cursor) == until { cursor.saturating_sub(1) } else { cursor });
                }
                if !steps.is_empty() {
                    ops.push(Op { steps });
                }
            }
        }
        "dm_ids" => {
            for r in pick_mixed(&ds.wrap_mailboxes(), &mut rng, o.distinct, 2) {
                let mut members = ds.matching(&FilterSpec { kinds: vec![GIFT_WRAP], p: vec![r], ..Default::default() });
                rng.shuffle(&mut members);
                members.truncate(500);
                let ids: Vec<[u8; 32]> = members.iter().map(|&i| ds.events[i as usize].id).collect();
                ops.push(req_op(ds, vec![FilterSpec { limit: Some(ids.len()), ids, kinds: vec![GIFT_WRAP], p: vec![r], ..Default::default() }]));
            }
        }
        "count" => {
            for r in pick_mixed(&ds.wrap_mailboxes(), &mut rng, o.distinct, 1) {
                let f = FilterSpec { kinds: vec![GIFT_WRAP], p: vec![r], ..Default::default() };
                ops.push(Op { steps: vec![Step::Count { json: f.to_json(), expect: ds.count(&f) }] });
            }
        }
        other => return Err(format!("unknown workload '{other}'")),
    }
    need(!ops.is_empty(), &format!("data to build workload '{name}' from"))?;
    // A pool where nothing is expected to match would "pass" against a relay that
    // returns nothing. (`miss` is the exception: empty is its answer.)
    if name != "miss" {
        let any_data = ops.iter().any(|op| {
            op.steps.iter().any(|s| match s {
                Step::Req { exp, .. } => !exp.want.is_empty(),
                Step::Count { expect, .. } => *expect > 0,
            })
        });
        need(any_data, &format!("events matching the '{name}' queries"))?;
    }
    Ok(Pool { ops })
}

/// A small generated dataset for other modules' tests.
#[cfg(test)]
pub fn tests_synthetic(events: u64) -> Dataset {
    tests::synthetic(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate::{generate_to, GenParams};
    use std::io::Cursor;

    pub fn synthetic(events: u64) -> Dataset {
        let p = GenParams { recipients: 20, planes: 8, authors: 30, threads: 4, rate_milli: 100, ..GenParams::new(events, 11) };
        let mut buf = Vec::new();
        generate_to(&p, &mut buf, false).unwrap();
        Dataset::from_reader(Cursor::new(buf), false).unwrap()
    }

    #[test]
    fn expand_names_and_groups() {
        assert_eq!(expand("classic").unwrap().len(), 12);
        assert_eq!(expand("vector").unwrap(), VECTOR.to_vec());
        assert_eq!(expand("all").unwrap().len(), 18);
        assert_eq!(expand("author, miss ,author").unwrap(), vec!["author", "miss"]);
        assert_eq!(expand("dm_inbox,count").unwrap(), vec!["dm_inbox", "count"]);
        assert!(expand("nope").unwrap_err().contains("unknown workload"));
        assert!(expand(",").is_err());
    }

    #[test]
    fn every_workload_builds_a_pool_with_nonempty_expectations() {
        let ds = synthetic(2000);
        let o = PoolOpts { limit: Some(10), distinct: 12, seed: 3 };
        for name in expand("all").unwrap() {
            let pool = build(&name, &ds, &o).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!pool.ops.is_empty(), "{name}");
            assert!(pool.ops.len() <= 32, "{name}");
            for op in &pool.ops {
                for s in &op.steps {
                    // Every request is valid JSON for the relay: filters in an array body.
                    let mut c = crate::wire::Cur::new(s.json());
                    assert!(c.skip_value().is_some(), "{name}: {}", s.json());
                    if let Step::Req { exp, json } = s {
                        if name != "miss" && name != "concord_paging" {
                            assert!(exp.total > 0 || name == "dm_catchup", "{name}: nothing expected for {json}");
                        }
                        assert!(exp.want.len() <= 3 * 100, "{name}");
                    }
                }
            }
        }
    }

    #[test]
    fn pools_are_deterministic_per_seed() {
        let ds = synthetic(1500);
        let json = |seed| {
            let o = PoolOpts { limit: Some(10), distinct: 8, seed };
            build("dm_inbox", &ds, &o).unwrap().ops.iter().map(|op| op.steps[0].json().to_owned()).collect::<Vec<_>>()
        };
        assert_eq!(json(1), json(1));
        assert_ne!(json(1), json(2));
    }

    #[test]
    fn paging_walks_back_through_a_heavy_plane_without_gaps() {
        let ds = synthetic(6000);
        let o = PoolOpts { limit: Some(15), distinct: 4, seed: 1 };
        let pool = build("concord_paging", &ds, &o).unwrap();
        let op = &pool.ops[0];
        assert!(op.steps.len() >= 3, "{} pages", op.steps.len());
        // Following the cursor with an inclusive `until` repeats at most the boundary second
        // and never skips: the union of the pages is the newest events, contiguously.
        let mut union: HashSet<[u8; 32]> = HashSet::new();
        let mut oldest = u32::MAX;
        for s in &op.steps {
            let Step::Req { exp, .. } = s else { panic!() };
            assert!(!exp.want.is_empty());
            assert!(exp.want.values().all(|&t| t <= oldest), "page reaches newer than the previous page's boundary");
            oldest = *exp.want.values().min().unwrap();
            union.extend(exp.want.keys());
        }
        assert!(union.len() > 15, "the walk went past the first page");
    }

    #[test]
    fn dm_ids_asks_for_ids_that_are_in_the_mailbox() {
        let ds = synthetic(3000);
        let o = PoolOpts { limit: None, distinct: 6, seed: 5 };
        let pool = build("dm_ids", &ds, &o).unwrap();
        for op in &pool.ops {
            let Step::Req { exp, json } = &op.steps[0] else { panic!() };
            let ids = json.matches("\"ids\"").count();
            assert_eq!(ids, 1);
            assert!(exp.total >= 1 && exp.total <= 500);
            assert_eq!(exp.total as usize, exp.order.len());
            assert!(exp.extra.is_empty(), "an ids query is never cut by its limit");
        }
    }

    #[test]
    fn miss_ids_do_not_exist_and_count_matches_matching() {
        let ds = synthetic(1000);
        let o = PoolOpts { limit: None, distinct: 5, seed: 8 };
        let pool = build("miss", &ds, &o).unwrap();
        for op in &pool.ops {
            let Step::Req { exp, .. } = &op.steps[0] else { panic!() };
            assert_eq!(exp.total, 0);
        }
        let pool = build("count", &ds, &o).unwrap();
        for op in &pool.ops {
            let Step::Count { expect, .. } = &op.steps[0] else { panic!() };
            assert!(*expect >= 1);
        }
    }

    #[test]
    fn a_dataset_without_the_data_is_an_error_not_an_empty_pass() {
        // Generic events only: no gift wraps, so the Vector workloads cannot be built.
        let line = |n: u16| crate::data::tests::line(n, 1, 1000 + u64::from(n), 1, &[&["t", "x"]]);
        let ds = crate::data::tests::dataset(&[line(1), line(2), line(3)]);
        let o = PoolOpts { limit: None, distinct: 4, seed: 1 };
        for name in ["dm_inbox", "concord_page", "concord_paging", "dm_ids", "count"] {
            assert!(build(name, &ds, &o).is_err(), "{name}");
        }
        assert!(build("author", &ds, &o).is_ok());
    }
}
