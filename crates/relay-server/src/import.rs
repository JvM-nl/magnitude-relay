//! `import`: load a JSONL export (strfry's format, one event per line) into the store.
//!
//! Parsing and signature verification fan out over every core; the writer
//! applies chunks strictly in file order, so seqs follow the file and strfry's
//! tie order (levId ascending within a second) is preserved.

use relay_proto::event::{parse_event_json, BulkVerifier, EventInfo, Reject};
use relay_proto::{kind, EventParser};
use relay_store::{Outcome, Writer};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, BufReader, Read};
use std::sync::mpsc;
use std::time::Instant;

/// Lines per work unit: big enough to amortise channel traffic, small enough to
/// keep every core busy to the end.
const CHUNK_LINES: usize = 2048;

/// Whether an event of this kind, by this author, is left out of an import.
pub type SkipKind = Box<dyn Fn(u64, &[u8; 32]) -> bool + Send + Sync>;

pub struct ImportOptions {
    pub verify: bool,
    /// Events this skips, by kind and author, are left out (ephemeral kinds
    /// are always left out).
    pub skip_kind: Option<SkipKind>,
    /// Events a client could not store here are left out as well (see `bans`).
    pub bans: Option<std::sync::Arc<crate::lists::KeyList>>,
    pub threads: usize,
}

#[derive(Default, Debug)]
pub struct ImportStats {
    pub lines: u64,
    pub stored: u64,
    pub duplicate: u64,
    pub superseded: u64,
    pub deleted: u64,
    /// Refused because their author (or a gift wrap's recipient) vanished (NIP-62).
    pub vanished: u64,
    pub ephemeral: u64,
    pub skipped_kind: u64,
    pub skipped_banned: u64,
    pub invalid: HashMap<String, u64>,
    pub bytes: u64,
}

struct Chunk {
    idx: u64,
    lines: Vec<String>,
}

struct Parsed {
    idx: u64,
    /// Records back to back, with end offsets.
    data: Vec<u8>,
    ends: Vec<usize>,
    lines: u64,
    ephemeral: u64,
    skipped_kind: u64,
    skipped_banned: u64,
    invalid: Vec<String>,
}

pub fn run(input: impl Read + Send, w: &mut Writer, opts: ImportOptions, mut progress: impl FnMut(&ImportStats)) -> io::Result<ImportStats> {
    let started = Instant::now();
    let threads = opts.threads.max(1);
    let (work_tx, work_rx) = mpsc::sync_channel::<Chunk>(threads * 4);
    let work_rx = std::sync::Mutex::new(work_rx);
    let (done_tx, done_rx) = mpsc::sync_channel::<Parsed>(threads * 4);
    let mut stats = ImportStats::default();

    std::thread::scope(|scope| -> io::Result<()> {
        // Reader.
        let reader = scope.spawn(move || -> io::Result<u64> {
            let mut r = BufReader::with_capacity(8 << 20, input);
            let mut idx = 0u64;
            let mut bytes = 0u64;
            loop {
                let mut lines = Vec::with_capacity(CHUNK_LINES);
                for _ in 0..CHUNK_LINES {
                    let mut line = String::new();
                    // Invalid UTF-8 surfaces as an error here; count the line as invalid
                    // rather than abort the import.
                    let mut raw = Vec::new();
                    let n = r.read_until(b'\n', &mut raw)?;
                    if n == 0 {
                        break;
                    }
                    bytes += n as u64;
                    match String::from_utf8(raw) {
                        Ok(s) => line.push_str(s.trim_end_matches(['\n', '\r'])),
                        Err(_) => line.push('\u{FFFD}'),
                    }
                    lines.push(line);
                }
                if lines.is_empty() {
                    break;
                }
                if work_tx.send(Chunk { idx, lines }).is_err() {
                    break;
                }
                idx += 1;
            }
            Ok(bytes)
        });

        // Parsers.
        let work_rx = &work_rx;
        let skip_kind = &opts.skip_kind;
        let bans = &opts.bans;
        for _ in 0..threads {
            let done_tx = done_tx.clone();
            let verify = opts.verify;
            scope.spawn(move || {
                let mut parser = EventParser::new();
                let mut bulk = BulkVerifier::new();
                let mut rec = Vec::new();
                loop {
                    let chunk = match work_rx.lock().unwrap().recv() {
                        Ok(c) => c,
                        Err(_) => break,
                    };
                    let mut out = Parsed {
                        idx: chunk.idx,
                        data: Vec::with_capacity(chunk.lines.iter().map(|l| l.len()).sum::<usize>()),
                        ends: Vec::with_capacity(chunk.lines.len()),
                        lines: chunk.lines.len() as u64,
                        ephemeral: 0,
                        skipped_kind: 0,
                        skipped_banned: 0,
                        invalid: Vec::new(),
                    };
                    let lines: Vec<&str> = chunk.lines.iter().map(String::as_str).filter(|l| !l.trim().is_empty()).collect();
                    out.lines = lines.len() as u64;
                    let take = |r: &Result<EventInfo, Reject>, rec: &[u8], out: &mut Parsed| match r {
                        Ok(info) if kind::is_ephemeral(info.kind) => out.ephemeral += 1,
                        Ok(info) if skip_kind.as_ref().is_some_and(|f| f(info.kind, relay_proto::Record(rec).pubkey())) => out.skipped_kind += 1,
                        Ok(_) if bans.as_ref().is_some_and(|b| b.with(|s| s.silences(relay_proto::Record(rec)))) => out.skipped_banned += 1,
                        Ok(_) => {
                            out.data.extend_from_slice(rec);
                            out.ends.push(out.data.len());
                        }
                        Err(e) => out.invalid.push(reason(e)),
                    };
                    if verify {
                        // Ids hashed several at a time, signatures in one batch.
                        bulk.verify(&lines);
                        for (i, r) in bulk.results().iter().enumerate() {
                            take(r, bulk.record(i), &mut out);
                        }
                    } else {
                        for line in &lines {
                            let r = parse_event_json(line, &mut parser, &mut rec, false);
                            take(&r, &rec, &mut out);
                        }
                    }
                    if done_tx.send(out).is_err() {
                        break;
                    }
                }
            });
        }
        drop(done_tx);

        // Writer: strictly in file order.
        let mut pending: BTreeMap<u64, Parsed> = BTreeMap::new();
        let mut next = 0u64;
        let mut last_report = Instant::now();
        for p in done_rx.iter() {
            pending.insert(p.idx, p);
            while let Some(p) = pending.remove(&next) {
                next += 1;
                stats.lines += p.lines;
                stats.ephemeral += p.ephemeral;
                stats.skipped_kind += p.skipped_kind;
                stats.skipped_banned += p.skipped_banned;
                for r in p.invalid {
                    *stats.invalid.entry(r).or_default() += 1;
                }
                let mut start = 0;
                let recs: Vec<&[u8]> = p
                    .ends
                    .iter()
                    .map(|&e| {
                        let r = &p.data[start..e];
                        start = e;
                        r
                    })
                    .collect();
                for o in w.write(&recs)? {
                    match o {
                        Outcome::Stored(_) => stats.stored += 1,
                        Outcome::Duplicate => stats.duplicate += 1,
                        Outcome::Superseded => stats.superseded += 1,
                        Outcome::Deleted => stats.deleted += 1,
                        Outcome::Vanished => stats.vanished += 1,
                        Outcome::Rejected(m) => *stats.invalid.entry(m.to_string()).or_default() += 1,
                    }
                }
                if last_report.elapsed().as_secs() >= 2 {
                    progress(&stats);
                    last_report = Instant::now();
                }
            }
        }
        stats.bytes = reader.join().expect("reader thread")?;
        Ok(())
    })?;
    w.sync()?;
    let _ = started;
    Ok(stats)
}

fn reason(e: &Reject) -> String {
    match e {
        Reject::Json(_) => "malformed json".into(),
        other => other.to_string(),
    }
}
