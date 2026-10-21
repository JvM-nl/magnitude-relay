//! Events that reach the store without a client connection: copied from
//! another relay by a sync, or handed to the admin socket. Another relay is
//! not trusted any more than a client is, so each event is checked exactly as
//! a client's EVENT is (`Session::on_event`): this relay's policy, then the id,
//! then the signature. Only the per-IP rate limit is left out; it is there to
//! share the relay fairly between clients, and a sync is the operator's own.

use crate::session::SessionCfg;
use relay_proto::json::Scanner;
use relay_proto::secp::{SigRef, Verifier};
use relay_proto::{kind, EventParser, Record};
use relay_store::{Outcome, Version};
use std::collections::BTreeMap;
use std::fmt;

/// What became of one event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Stored,
    /// Already here.
    Duplicate,
    /// A newer version of its replaceable or addressable slot is stored.
    Superseded,
    /// A deletion (kind 5) holds: by its author, or for a gift wrap by a recipient.
    Deleted,
    /// Its author, or a gift wrap's recipient, asked this relay to vanish (NIP-62).
    Vanished,
    /// Ephemeral: a relay passes these on and never keeps them, so a copy is pointless.
    Ephemeral,
    /// This relay's policy or a storage rule says no; the message says which.
    Refused(String),
    /// Malformed, or its id or signature does not check out.
    Invalid(String),
    /// The store could not write it; it may succeed another time.
    Failed,
}

impl Verdict {
    pub fn of(o: Option<Outcome>) -> Verdict {
        match o {
            Some(Outcome::Stored(_)) => Verdict::Stored,
            Some(Outcome::Duplicate) => Verdict::Duplicate,
            Some(Outcome::Superseded) => Verdict::Superseded,
            Some(Outcome::Deleted) => Verdict::Deleted,
            Some(Outcome::Vanished) => Verdict::Vanished,
            Some(Outcome::Rejected(m)) => Verdict::Refused(m.to_string()),
            None => Verdict::Failed,
        }
    }

    /// One short string per verdict, for the admin socket. Round-trips through `parse`.
    pub fn code(&self) -> String {
        match self {
            Verdict::Stored => "stored".into(),
            Verdict::Duplicate => "duplicate".into(),
            Verdict::Superseded => "superseded".into(),
            Verdict::Deleted => "deleted".into(),
            Verdict::Vanished => "vanished".into(),
            Verdict::Ephemeral => "ephemeral".into(),
            Verdict::Refused(m) => format!("refused {m}"),
            Verdict::Invalid(m) => format!("invalid {m}"),
            Verdict::Failed => "failed".into(),
        }
    }

    pub fn parse(code: &str) -> Option<Verdict> {
        Some(match code {
            "stored" => Verdict::Stored,
            "duplicate" => Verdict::Duplicate,
            "superseded" => Verdict::Superseded,
            "deleted" => Verdict::Deleted,
            "vanished" => Verdict::Vanished,
            "ephemeral" => Verdict::Ephemeral,
            "failed" => Verdict::Failed,
            c => {
                if let Some(m) = c.strip_prefix("refused ") {
                    Verdict::Refused(m.to_string())
                } else if let Some(m) = c.strip_prefix("invalid ") {
                    Verdict::Invalid(m.to_string())
                } else {
                    return None;
                }
            }
        })
    }
}

/// Parses and checks the event object at byte `at` of `text`, all but its
/// signature, leaving its record in `rec` when only the signature is left to
/// check. Policy first and the duplicate check before any hashing, as for a
/// client: a refusal or an event already here costs no signature check.
fn check_unsigned(text: &str, at: usize, cfg: &SessionCfg, v: &Version, now: u64, parser: &mut EventParser, rec: &mut Vec<u8>) -> Result<(), Verdict> {
    let info = parser.parse_unchecked(&mut Scanner::new_at(text, at), rec).map_err(|e| Verdict::Invalid(format!("invalid: {e}")))?;
    if let Some(msg) = cfg.refusal(&info, Record(rec), now) {
        return Err(Verdict::Refused(msg));
    }
    if kind::is_ephemeral(info.kind) {
        return Err(Verdict::Ephemeral);
    }
    if v.lookup_id(Record(rec).id()).is_some() {
        return Err(Verdict::Duplicate);
    }
    if parser.confirm_id(Scanner::new_at(text, at), rec, info).is_err() {
        return Err(Verdict::Invalid("invalid: bad event id".into()));
    }
    Ok(())
}

fn bad_signature() -> Verdict {
    Verdict::Invalid("invalid: bad signature".into())
}

/// Checks a batch of events, spread over up to `threads` threads (signature
/// checks are the cost). Per event: its record to store, or what settled it.
/// Each thread checks its share's signatures together (`secp::Verifier`),
/// several times cheaper per event than one at a time and with the same
/// verdicts.
pub fn check_all(events: &[(&str, usize)], cfg: &SessionCfg, v: &Version, now: u64, threads: usize) -> Vec<Result<Vec<u8>, Verdict>> {
    let one = |part: &[(&str, usize)]| -> Vec<Result<Vec<u8>, Verdict>> {
        let mut parser = EventParser::new();
        let mut out: Vec<Result<Vec<u8>, Verdict>> = part
            .iter()
            .map(|&(text, at)| {
                let mut rec = Vec::new();
                check_unsigned(text, at, cfg, v, now, &mut parser, &mut rec).map(|()| rec)
            })
            .collect();
        let waiting: Vec<usize> = (0..out.len()).filter(|&i| out[i].is_ok()).collect();
        let refs: Vec<SigRef<'_>> = waiting
            .iter()
            .map(|&i| {
                let r = Record(out[i].as_ref().expect("waiting for its signature"));
                SigRef { pubkey: r.pubkey(), msg: r.id(), sig: r.sig() }
            })
            .collect();
        let mut ok = Vec::new();
        Verifier::new().verify_batch(&refs, &mut ok);
        drop(refs);
        for (&i, &good) in waiting.iter().zip(&ok) {
            if !good {
                out[i] = Err(bad_signature());
            }
        }
        out
    };
    // Below this a thread costs more than it saves.
    const PER_THREAD: usize = 64;
    let threads = threads.clamp(1, events.len().div_ceil(PER_THREAD).max(1));
    if threads == 1 {
        return one(events);
    }
    let per = events.len().div_ceil(threads);
    std::thread::scope(|s| {
        let parts: Vec<_> = events.chunks(per).map(|part| s.spawn(move || one(part))).collect();
        parts.into_iter().flat_map(|h| h.join().expect("event check thread")).collect()
    })
}

/// How many events met each fate, with refusals counted by their reason.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    pub stored: u64,
    pub duplicate: u64,
    pub superseded: u64,
    pub deleted: u64,
    pub vanished: u64,
    pub ephemeral: u64,
    pub failed: u64,
    pub refused: BTreeMap<String, u64>,
    pub invalid: BTreeMap<String, u64>,
}

impl Tally {
    pub fn add(&mut self, v: &Verdict) {
        match v {
            Verdict::Stored => self.stored += 1,
            Verdict::Duplicate => self.duplicate += 1,
            Verdict::Superseded => self.superseded += 1,
            Verdict::Deleted => self.deleted += 1,
            Verdict::Vanished => self.vanished += 1,
            Verdict::Ephemeral => self.ephemeral += 1,
            Verdict::Failed => self.failed += 1,
            Verdict::Refused(m) => *self.refused.entry(m.clone()).or_default() += 1,
            Verdict::Invalid(m) => *self.invalid.entry(m.clone()).or_default() += 1,
        }
    }

    pub fn merge(&mut self, o: &Tally) {
        self.stored += o.stored;
        self.duplicate += o.duplicate;
        self.superseded += o.superseded;
        self.deleted += o.deleted;
        self.vanished += o.vanished;
        self.ephemeral += o.ephemeral;
        self.failed += o.failed;
        for (k, n) in &o.refused {
            *self.refused.entry(k.clone()).or_default() += n;
        }
        for (k, n) in &o.invalid {
            *self.invalid.entry(k.clone()).or_default() += n;
        }
    }

    pub fn total(&self) -> u64 {
        self.stored + self.duplicate + self.superseded + self.deleted + self.vanished + self.ephemeral + self.failed + self.refused.values().sum::<u64>() + self.invalid.values().sum::<u64>()
    }

    /// Everything that was not stored and not already here.
    pub fn turned_away(&self) -> u64 {
        self.total() - self.stored - self.duplicate
    }
}

impl fmt::Display for Tally {
    /// `stored 5, duplicate 1, deleted 2`, then one line per refusal reason.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = [
            ("stored", self.stored),
            ("already here", self.duplicate),
            ("superseded by a newer version", self.superseded),
            ("deleted (kind 5)", self.deleted),
            ("vanished (NIP-62)", self.vanished),
            ("ephemeral, not kept", self.ephemeral),
            ("write failed", self.failed),
        ]
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(what, n)| format!("{what} {n}"))
        .collect();
        f.write_str(if parts.is_empty() { "nothing" } else { "" })?;
        f.write_str(&parts.join(", "))?;
        for (what, map) in [("refused", &self.refused), ("invalid", &self.invalid)] {
            let mut v: Vec<_> = map.iter().collect();
            v.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
            for (reason, n) in v {
                write!(f, "\n    {what} {n}: {reason}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_codes_round_trip() {
        for v in [
            Verdict::Stored,
            Verdict::Duplicate,
            Verdict::Superseded,
            Verdict::Deleted,
            Verdict::Vanished,
            Verdict::Ephemeral,
            Verdict::Failed,
            Verdict::Refused("blocked: kind 1 is not accepted by this relay".into()),
            Verdict::Invalid("invalid: bad signature".into()),
        ] {
            assert_eq!(Verdict::parse(&v.code()), Some(v.clone()), "{v:?}");
        }
        assert_eq!(Verdict::parse("sideways"), None);
    }

    #[test]
    fn tallies_add_up() {
        let mut t = Tally::default();
        for v in [Verdict::Stored, Verdict::Stored, Verdict::Deleted, Verdict::Refused("blocked: x".into()), Verdict::Refused("blocked: x".into())] {
            t.add(&v);
        }
        let mut u = Tally::default();
        u.add(&Verdict::Duplicate);
        u.add(&Verdict::Invalid("invalid: bad id".into()));
        t.merge(&u);
        assert_eq!((t.total(), t.turned_away(), t.stored, t.refused["blocked: x"]), (7, 4, 2, 2));
        let text = t.to_string();
        assert!(text.starts_with("stored 2, already here 1, deleted (kind 5) 1"), "{text}");
        assert!(text.contains("\n    refused 2: blocked: x") && text.contains("\n    invalid 1: invalid: bad id"), "{text}");
        assert_eq!(Tally::default().to_string(), "nothing");
    }

    /// One event at a time, signature by libsecp256k1 alone: the reference.
    fn check(text: &str, at: usize, cfg: &SessionCfg, v: &Version, now: u64, parser: &mut EventParser, rec: &mut Vec<u8>) -> Result<(), Verdict> {
        check_unsigned(text, at, cfg, v, now, parser, rec)?;
        if !relay_proto::event::verify_sig(Record(rec)) {
            return Err(bad_signature());
        }
        Ok(())
    }

    /// A batch gets exactly the verdicts its events get one at a time, bad
    /// signatures, bad ids, refusals and duplicates among good events.
    #[test]
    fn checking_together_agrees_with_one_at_a_time() {
        use secp256k1::{schnorr, Keypair};
        use sha2::{Digest, Sha256};
        let dir = std::env::temp_dir().join(format!("relay-inbound-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (store, mut w) = relay_store::Store::open(&dir, relay_store::Options::default()).unwrap();
        let keys: Vec<Keypair> = (1..=5u8).map(|i| Keypair::from_secret_bytes([i; 32]).unwrap()).collect();
        let now = 1_700_000_000;
        let event = |k: &Keypair, i: u64, kind: u64| -> String {
            let pk = relay_proto::hex::encode_string(&k.x_only_public_key().0.to_byte_array());
            let content = format!("event {i}");
            let pre = format!("[0,\"{pk}\",{},{kind},[],\"{content}\"]", now - i);
            let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
            let sig = relay_proto::hex::encode_string(&schnorr::sign_no_aux_rand(&id, k).to_byte_array());
            let id = relay_proto::hex::encode_string(&id);
            format!("{{\"id\":\"{id}\",\"pubkey\":\"{pk}\",\"created_at\":{},\"kind\":{kind},\"tags\":[],\"content\":\"{content}\",\"sig\":\"{sig}\"}}", now - i)
        };
        let mut texts = Vec::new();
        for i in 0..300u64 {
            let mut e = event(&keys[(i % 5) as usize], i, 1);
            match i % 23 {
                // A signature digit changed.
                3 => {
                    let at = e.find("\"sig\":\"").unwrap() + 7 + (i as usize % 100);
                    let c = if e.as_bytes()[at] == b'0' { "1" } else { "0" };
                    e.replace_range(at..at + 1, c);
                }
                // The content changed: a bad id.
                7 => e = e.replace("\"event ", "\"evenT "),
                // A kind this policy refuses.
                11 => e = event(&keys[0], i, 7),
                _ => {}
            }
            texts.push(e);
        }
        // One already stored.
        let mut rec = Vec::new();
        relay_proto::event::parse_event_json(&texts[1], &mut EventParser::new(), &mut rec, true).unwrap();
        w.write(&[&rec[..]]).unwrap();
        let v = store.snapshot();
        let cfg = SessionCfg {
            max_subscriptions: 10,
            max_filters: 10,
            max_filter_values: 10,
            default_limit: 10,
            max_limit: 10,
            max_event_bytes: 65_536,
            max_future_seconds: 900,
            max_tags: 100,
            kind_allowed: Box::new(|k| k == 1),
        };
        let refs: Vec<(&str, usize)> = texts.iter().map(|t| (t.as_str(), 0)).collect();
        let mut parser = EventParser::new();
        let want: Vec<Result<Vec<u8>, Verdict>> = refs
            .iter()
            .map(|&(t, at)| {
                let mut rec = Vec::new();
                check(t, at, &cfg, &v, now, &mut parser, &mut rec).map(|()| rec)
            })
            .collect();
        assert!(want.contains(&Err(bad_signature())) && want.contains(&Err(Verdict::Duplicate)));
        for threads in [1, 3] {
            assert_eq!(check_all(&refs, &cfg, &v, now, threads), want, "{threads} threads");
        }
        drop((v, w, store));
        let _ = std::fs::remove_dir_all(dir);
    }
}
