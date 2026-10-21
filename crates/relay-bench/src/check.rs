//! Judging a relay's answer against the expected one.
//!
//! The rules, in order of severity:
//!
//! * **Set mismatch (fatal).** The relay returned an event it should not have, left
//!   out one it should have, repeated one, or reported a different `created_at` for
//!   one. The only slack is a `limit` that cuts through a same-second group: NIP-01
//!   says "lowest id first", strfry serves insertion order, and both are defensible,
//!   so a *different member of the boundary second* is not a set mismatch (it is
//!   counted as a tie pick). Anything beyond the boundary second is.
//! * **Order mismatch (fatal).** `created_at` not non-increasing: newest-first is the
//!   one ordering rule every relay agrees on.
//! * **Tie order / tie pick (informational).** Equal `created_at` but ids not
//!   ascending, or a different boundary-second member than NIP-01's. Fatal only with
//!   `--strict-ties`, which our own relay must pass.
//!
//! Order is only checked for single-filter requests: with several filters relays
//! legitimately emit filter by filter or merged.

use crate::data::Expected;
use relay_proto::hex;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub set_mismatch: bool,
    pub order_mismatch: bool,
    pub tie_order: bool,
    pub tie_pick: bool,
    /// Why, for the first few failures of a run. Empty when everything matched.
    pub detail: String,
}

impl Verdict {
    pub fn ok(&self, strict_ties: bool) -> bool {
        !self.set_mismatch && !self.order_mismatch && !(strict_ties && (self.tie_order || self.tie_pick))
    }
}

fn short(id: &[u8; 32]) -> String {
    hex::encode_string(&id[..6])
}

/// Checks `got` (id and `created_at` in arrival order) against `exp`.
pub fn validate(exp: &Expected, got: &[([u8; 32], u64)]) -> Verdict {
    let mut v = Verdict::default();
    let mut seen = std::collections::HashSet::with_capacity(got.len());
    let (mut dups, mut unexpected, mut wrong_ts, mut substituted) = (0usize, Vec::new(), 0usize, 0usize);
    for (id, ts) in got {
        if !seen.insert(*id) {
            dups += 1;
        } else if let Some(&want_ts) = exp.want.get(id) {
            if u64::from(want_ts) != *ts {
                wrong_ts += 1;
            }
        } else if exp.extra.contains(id) {
            substituted += 1;
        } else {
            unexpected.push(*id);
        }
    }
    let missing: Vec<&[u8; 32]> = exp.want.keys().filter(|id| !seen.contains(*id)).collect();
    // A missing event is excusable only if a same-second event stood in at a cut.
    let hard_missing: Vec<&&[u8; 32]> = missing.iter().filter(|id| !exp.subst_secs.contains(&exp.want[**id])).collect();
    let count_off = exp.single && got.len() != exp.want.len();
    v.set_mismatch = dups > 0 || !unexpected.is_empty() || wrong_ts > 0 || !hard_missing.is_empty() || count_off;
    v.tie_pick = !v.set_mismatch && (substituted > 0 || !missing.is_empty());

    if exp.single {
        for w in got.windows(2) {
            if w[0].1 < w[1].1 {
                v.order_mismatch = true;
            } else if w[0].1 == w[1].1 && w[0].0 > w[1].0 {
                v.tie_order = true;
            }
        }
    }

    if v.set_mismatch || v.order_mismatch || v.tie_order || v.tie_pick {
        let mut d = format!("got {} events, expected {}", got.len(), exp.want.len());
        if dups > 0 {
            d.push_str(&format!("; {dups} repeated"));
        }
        if wrong_ts > 0 {
            d.push_str(&format!("; {wrong_ts} with a different created_at"));
        }
        if !unexpected.is_empty() {
            d.push_str(&format!("; {} unexpected (first {})", unexpected.len(), short(&unexpected[0])));
        }
        if !hard_missing.is_empty() {
            d.push_str(&format!("; {} missing (first {})", hard_missing.len(), short(hard_missing[0])));
        }
        if v.order_mismatch {
            d.push_str("; not newest-first");
        }
        if v.tie_order {
            d.push_str("; same-second events not in id order");
        }
        if v.tie_pick {
            d.push_str("; different members of the boundary second than NIP-01's");
        }
        v.detail = d;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::tests::{dataset, id, line};
    use crate::data::FilterSpec;

    fn got(items: &[(u16, u64)]) -> Vec<([u8; 32], u64)> {
        items.iter().map(|&(n, ts)| (id(n), ts)).collect()
    }

    /// Ten events: ts 100 down to 10 by tens, plus a tied trio at 200.
    fn fixture() -> crate::data::Dataset {
        let mut l = vec![line(1, 1, 200, 1, &[]), line(2, 1, 200, 1, &[]), line(3, 1, 200, 1, &[])];
        for i in 0..7u16 {
            l.push(line(10 + i, 1, 100 - u64::from(i) * 10, 1, &[]));
        }
        dataset(&l)
    }

    #[test]
    fn exact_answer_passes_everything() {
        let ds = fixture();
        let ex = ds.expected(&[FilterSpec { kinds: vec![1], limit: Some(5), ..Default::default() }]);
        let v = validate(&ex, &got(&[(1, 200), (2, 200), (3, 200), (10, 100), (11, 90)]));
        assert_eq!(v, Verdict::default());
        assert!(v.ok(true));
    }

    #[test]
    fn missing_unexpected_repeated_and_wrong_timestamps_are_set_mismatches() {
        let ds = fixture();
        let ex = ds.expected(&[FilterSpec { kinds: vec![1], limit: Some(5), ..Default::default() }]);
        let base = [(1, 200), (2, 200), (3, 200), (10, 100), (11, 90)];
        // Missing one (and so the wrong count), with an extra one beyond the cut.
        let v = validate(&ex, &got(&[(1, 200), (2, 200), (3, 200), (10, 100), (12, 80)]));
        assert!(v.set_mismatch && v.detail.contains("unexpected") && v.detail.contains("missing"), "{}", v.detail);
        // Too few.
        let v = validate(&ex, &got(&base[..4]));
        assert!(v.set_mismatch && v.detail.contains("missing"));
        // Too many.
        let mut more = base.to_vec();
        more.push((12, 80));
        let v = validate(&ex, &got(&more));
        assert!(v.set_mismatch);
        // Repeats hide missing events from a plain count.
        let v = validate(&ex, &got(&[(1, 200), (2, 200), (3, 200), (10, 100), (10, 100)]));
        assert!(v.set_mismatch && v.detail.contains("repeated"));
        // Right id, wrong created_at.
        let v = validate(&ex, &got(&[(1, 200), (2, 200), (3, 200), (10, 100), (11, 91)]));
        assert!(v.set_mismatch && v.detail.contains("created_at"));
        // Nothing at all.
        assert!(validate(&ex, &[]).set_mismatch);
    }

    #[test]
    fn order_rules() {
        let ds = fixture();
        let ex = ds.expected(&[FilterSpec { kinds: vec![1], limit: Some(5), ..Default::default() }]);
        // Oldest first is fatal even though the set is right.
        let v = validate(&ex, &got(&[(11, 90), (10, 100), (3, 200), (2, 200), (1, 200)]));
        assert!(v.order_mismatch && !v.set_mismatch);
        assert!(!v.ok(false));
        // Same-second events in the wrong id order: informational, fatal only when strict.
        let v = validate(&ex, &got(&[(3, 200), (1, 200), (2, 200), (10, 100), (11, 90)]));
        assert!(v.tie_order && !v.order_mismatch && !v.set_mismatch);
        assert!(v.ok(false) && !v.ok(true));
        // Several filters: no order promised.
        let ex2 = ds.expected(&[FilterSpec { kinds: vec![1], limit: Some(5), ..Default::default() }, FilterSpec { ids: vec![id(15)], ..Default::default() }]);
        let v = validate(&ex2, &got(&[(15, 50), (11, 90), (10, 100), (3, 200), (2, 200), (1, 200)]));
        assert!(!v.order_mismatch && !v.tie_order && !v.set_mismatch, "{}", v.detail);
    }

    #[test]
    fn a_limit_cutting_a_same_second_group_allows_another_member_of_that_second() {
        let ds = fixture();
        // limit 2 cuts the tied trio at 200: NIP-01 answer is ids 1 and 2.
        let ex = ds.expected(&[FilterSpec { kinds: vec![1], limit: Some(2), ..Default::default() }]);
        assert_eq!(ex.order, vec![id(1), id(2)]);
        let v = validate(&ex, &got(&[(1, 200), (2, 200)]));
        assert_eq!(v, Verdict::default());
        // strfry-style: a different pair of the same second.
        let v = validate(&ex, &got(&[(3, 200), (2, 200)]));
        assert!(v.tie_pick && v.tie_order && !v.set_mismatch && !v.order_mismatch, "{v:?}");
        assert!(v.ok(false) && !v.ok(true));
        // But an event from another second is wrong, not a tie pick.
        let v = validate(&ex, &got(&[(1, 200), (10, 100)]));
        assert!(v.set_mismatch);
        // And so is a short answer.
        let v = validate(&ex, &got(&[(1, 200)]));
        assert!(v.set_mismatch);
    }

    #[test]
    fn empty_answers() {
        let ds = fixture();
        let ex = ds.expected(&[FilterSpec { ids: vec![id(999)], ..Default::default() }]);
        assert_eq!(validate(&ex, &[]), Verdict::default());
        assert!(validate(&ex, &got(&[(1, 200)])).set_mismatch, "an answer to a query that must be empty");
    }
}
