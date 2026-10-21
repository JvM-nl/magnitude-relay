//! Comparing a reopened store with the model.

use super::child::NOW;
use super::model::{parse_filter, Model};
use super::work;
use crate::rng::Rng;
use relay_proto::Record;
use relay_store::{Store, Writer};

/// For seqs an interrupted removal may or may not have killed, the store's
/// word decides (both are allowed; the record must still be intact if alive,
/// which `check_state` then checks).
pub fn adopt(m: &mut Model, store: &Store, maybe: &[u64]) {
    let v = store.snapshot();
    let mut revived = Vec::new();
    for &seq in maybe {
        if (seq as usize) < m.slots.len() {
            let live = v.is_live(seq);
            if live && !m.slots[seq as usize].alive {
                m.revive_seq(seq);
                revived.push(seq);
            } else if !live && m.slots[seq as usize].alive {
                m.kill_seq(seq);
            }
        }
    }
    // What came back is then subject to every rule of what was stored since.
    m.settle_revived(&revived);
}

/// Every seq dead or alive exactly as the model says, every live record byte
/// for byte, every live id found at its seq.
pub fn check_state(m: &Model, store: &Store, w: &Writer) -> Result<(), String> {
    if w.next_seq() != m.next_seq() {
        return Err(format!("next_seq is {}, model has {}", w.next_seq(), m.next_seq()));
    }
    let v = store.snapshot();
    let mut errs = Vec::new();
    for s in &m.slots {
        let live = v.is_live(s.seq);
        if live != s.alive {
            // Who could have decided it: events at its address, by its author
            // (a vanish), naming its id, or other copies of it.
            let id_hex = relay_proto::hex::encode_string(&s.ev.id);
            let addr = super::model::address_d(&s.ev);
            let related: Vec<String> = m
                .slots
                .iter()
                .filter(|o| o.seq != s.seq)
                .filter(|o| {
                    (o.ev.pubkey == s.ev.pubkey && o.ev.kind == s.ev.kind && super::model::address_d(&o.ev) == addr && (relay_proto::kind::is_replaceable(o.ev.kind) || relay_proto::kind::is_addressable(o.ev.kind)))
                        || (o.ev.kind == 62 && o.ev.pubkey == s.ev.pubkey)
                        || o.ev.tags.iter().any(|t| t.get(1).is_some_and(|v| *v == id_hex))
                        || o.ev.id == s.ev.id
                })
                .map(|o| format!("seq {} n{} kind {} ca {} {}/{} [{} by {}]", o.seq, o.ev.n, o.ev.kind, o.ev.created_at, if v.is_live(o.seq) { "live" } else { "dead" }, if o.alive { "live" } else { "dead" }, o.why.0, o.why.1 as i64))
                .collect();
            let killed = if s.alive {
                String::new()
            } else {
                let (w, by) = s.why;
                match m.slots.get(by as usize) {
                    Some(k) => format!("{w} by seq {by}, n{} kind {}; ", k.ev.n, k.ev.kind),
                    None => format!("{w}; "),
                }
            };
            let why = format!(" ({killed}ca {}; id looks up to {:?}; related, store/model: {})", s.ev.created_at, v.lookup_id(&s.ev.id), related.join(", "));
            errs.push(format!(
                "seq {} (event n{} kind {} {}) is {} in the store, {} in the model{why}",
                s.seq,
                s.ev.n,
                s.ev.kind,
                relay_proto::hex::encode_string(&s.ev.id[..4]),
                if live { "live" } else { "dead" },
                if s.alive { "live" } else { "dead" }
            ));
            continue;
        }
        if !s.alive {
            continue;
        }
        let r = v.record(s.seq).expect("live");
        if r.0 != s.rec.as_slice() {
            let what = if r.0.iter().all(|&b| b == 0) { "zeroed" } else { "different bytes" };
            errs.push(format!("seq {} (event n{} kind {}): record is {what} ({} bytes, want {})", s.seq, s.ev.n, s.ev.kind, r.0.len(), s.rec.len()));
            continue;
        }
        match v.lookup_id(&s.ev.id) {
            Some(q) if q == s.seq => {}
            other => errs.push(format!("id of seq {} (n{}) looks up to {other:?}", s.seq, s.ev.n)),
        }
        if errs.len() > 8 {
            break;
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(format!("{} mismatches: {}", errs.len(), errs.join("; ")))
    }
}

/// Every live record's frame on disk too: not flagged dead, checksum intact.
/// A live record whose frame says otherwise is served now but lost at the next
/// log compaction (the copy skips it) or crash (replay kills it).
pub fn check_frames(m: &Model, dir: &std::path::Path, seg_size: u64) -> Result<(), String> {
    use relay_store::log::{cold_path, hot_path, COLD_BASE, FLAG_DEAD, FRAME_HEADER};
    use std::os::unix::fs::FileExt;
    let locs = std::fs::File::open(dir.join("locs")).map_err(|e| format!("locs: {e}"))?;
    let mut files: std::collections::HashMap<u64, std::fs::File> = std::collections::HashMap::new();
    let mut errs = Vec::new();
    for s in m.live_seqs() {
        let mut b = [0u8; 8];
        locs.read_exact_at(&mut b, s.seq * 8).map_err(|e| format!("locs of seq {}: {e}", s.seq))?;
        let off = u64::from_le_bytes(b);
        let idx = off / seg_size;
        if let std::collections::hash_map::Entry::Vacant(e) = files.entry(idx) {
            let path = if idx >= COLD_BASE { cold_path(&dir.join("log"), idx - COLD_BASE) } else { hot_path(&dir.join("log"), idx) };
            e.insert(std::fs::File::open(&path).map_err(|e| format!("seq {}: {}: {e}", s.seq, path.display()))?);
        }
        let f = &files[&idx];
        let mut h = [0u8; FRAME_HEADER];
        f.read_exact_at(&mut h, off % seg_size).map_err(|e| format!("frame of seq {}: {e}", s.seq))?;
        let len = u32::from_le_bytes(h[0..4].try_into().unwrap()) as usize;
        let flags = u32::from_le_bytes(h[4..8].try_into().unwrap());
        let seq = u64::from_le_bytes(h[8..16].try_into().unwrap());
        let crc = u32::from_le_bytes(h[16..20].try_into().unwrap());
        let mut rec = vec![0u8; len.min(1 << 20)];
        f.read_exact_at(&mut rec, off % seg_size + FRAME_HEADER as u64).map_err(|e| format!("record of seq {}: {e}", s.seq))?;
        let what = if seq != s.seq {
            format!("holds seq {seq}")
        } else if flags & FLAG_DEAD != 0 {
            "is flagged dead".to_string()
        } else if relay_store::crc32c::crc32c(&rec) != crc {
            "fails its checksum".to_string()
        } else {
            continue;
        };
        errs.push(format!("live seq {} (n{} kind {}): its frame at {off} {what}", s.seq, s.ev.n, s.ev.kind));
        if errs.len() > 8 {
            break;
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(format!("{} frames: {}", errs.len(), errs.join("; ")))
    }
}

/// Random queries against brute force over the model. Returns how many ran.
pub fn check_queries(m: &Model, store: &Store, n: usize, rng: &mut Rng) -> Result<u64, String> {
    let v = store.snapshot();
    let seed = m.seed;
    let hexk = |k: [u8; 32]| relay_proto::hex::encode_string(&k);
    for q in 0..n {
        let json = match q % 6 {
            0 => format!("{{\"kinds\":[1059],\"#p\":[\"{}\"]}}", hexk(work::author_key(seed, rng.below(work::RECIPIENTS)))),
            1 => format!(
                "{{\"authors\":[\"{}\",\"{}\"],\"kinds\":[0,1,5,30078,1059,62]}}",
                hexk(work::author_key(seed, rng.below(work::AUTHORS + work::PLANES))),
                hexk(work::author_key(seed, rng.below(work::AUTHORS)))
            ),
            2 => {
                // A handful of ids, some live, some not.
                let ids: Vec<String> = (0..1 + rng.below(6))
                    .map(|_| {
                        let n = if m.slots.is_empty() || rng.chance(1, 4) { rng.below(1 << 20) } else { m.slots[rng.usize(m.slots.len())].ev.n };
                        format!("\"{}\"", hexk(work::id_of(seed, n)))
                    })
                    .collect();
                format!("{{\"ids\":[{}]}}", ids.join(","))
            }
            3 => "{}".to_string(),
            _ => work::filter_json(seed, rng),
        };
        let f = parse_filter(&json);
        let limit = if rng.chance(1, 3) { usize::MAX } else { 1 + rng.skewed(200) as usize };
        let got: Vec<[u8; 32]> = v.query(&f, limit, NOW).iter().map(|h| h.id).collect();
        let want = m.query(&f, limit, NOW);
        if got != want {
            let missing: Vec<String> = want.iter().filter(|x| !got.contains(x)).take(4).map(|x| hexk(*x)[..8].to_string()).collect();
            let extra: Vec<String> = got.iter().filter(|x| !want.contains(x)).take(4).map(|x| hexk(*x)[..8].to_string()).collect();
            return Err(format!("query {json} limit {limit}: store {} results, model {}; missing {missing:?}, extra {extra:?}", got.len(), want.len()));
        }
        let all = m.query(&f, usize::MAX, NOW).len() as u64;
        let c = v.count(&f, NOW);
        if c != all {
            return Err(format!("COUNT {json}: store {c}, model {all}"));
        }
        let walk: Vec<u64> = v.matching(std::slice::from_ref(&f), None, NOW).map(|h| h.seq).collect();
        let mwalk = m.matching(std::slice::from_ref(&f), None, NOW);
        if walk != mwalk {
            return Err(format!("operator walk {json}: store {} events, model {}", walk.len(), mwalk.len()));
        }
        if let Some(mut items) = v.neg_items(&f, NOW) {
            items.sort_unstable();
            let mut want: Vec<(u64, [u8; 32])> =
                m.live_seqs().map(|s| Record(&s.rec)).filter(|r| f.matches(*r) && r.expiration().is_none_or(|e| e > NOW)).map(|r| (r.created_at(), *r.id())).collect();
            want.sort_unstable();
            if items != want {
                return Err(format!("NIP-77 set {json}: store {} items, model {}", items.len(), want.len()));
            }
        }
    }
    Ok(n as u64)
}
