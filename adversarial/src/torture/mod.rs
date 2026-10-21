//! Crash torture for the store. A child process runs the workload and is
//! killed (SIGKILL) at random moments or at named crash points: inside
//! flushes, compactions, log compaction exchanges, cold merges, deletes,
//! checkpoints and its own recovery. After every kill the parent reopens the
//! store and checks it against a model of what was acknowledged:
//!
//! - every acknowledged event is present, byte for byte, at its seq;
//! - nothing deleted, replaced, vanished, expired or removed comes back, and
//!   the dead set matches the model exactly;
//! - the operation in flight landed as some prefix of itself (an operator
//!   removal: any subset of its targets, each intact if alive, and what came
//!   back then subject to the rules of everything stored since);
//! - every live record's frame on disk is intact and not flagged dead (else
//!   the next log compaction drops it);
//! - queries, COUNT, the operator walk and NIP-77 sets match brute force.
//!
//! With `--faults`, half the children also run on a disk that fills up (see
//! `child::Faults`): a failed operation is reported and the child carries on,
//! as the relay does, saying what the store then holds. The parent keeps one
//! model per outcome the failure may have had, prunes them with what follows,
//! and after the kill also allows what a crash may make of a failure (a
//! failed batch's frames still at the end of the log, an unacknowledged
//! removal undone).

pub mod child;
pub mod model;
pub mod readers;
pub mod verify;
pub mod work;

use crate::rng::{mix, Rng};
use child::{Shape, NOW};
use model::{Model, Out, ADMIN_CHUNK};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use work::Op;

/// Named crash points (see relay-store's `fault.rs`), for targeted kills.
pub const CRASH_POINTS: &[&str] = &[
    "writer.appended",
    "writer.marked_dead",
    "writer.published",
    "ticket.synced",
    "writer.killed",
    "writer.flagged",
    "reclaim.zeroing",
    "log.flushing",
    "log.zeroing",
    "log.scrubbing",
    "log.preparing",
    "checkpoint.dead_bits",
    "checkpoint.tmp_written",
    "checkpoint.renamed",
    "bg.segment_written",
    "bg.segment_renamed",
    "flush.done",
    "compact.done",
    "compact.checkpointed",
    "cold.writing",
    "cold.sealing",
    "cold.sealed",
    "logcompact.registered",
    "logcompact.intent_recorded",
    "relink.writing",
    "relink.done",
    "relink.retired",
    "relink.checkpointed",
    "file.retiring",
    "segment.retiring",
    "open.replayed",
    "open.intent_finished",
    "open.repaired",
];

pub struct Cfg {
    pub root: PathBuf,
    pub seed: u64,
    pub iterations: u64,
    /// Kills land up to this long after the child starts (skewed short).
    pub max_kill_ms: u64,
    /// Half the kills aim at a named crash point instead of a moment.
    pub crash_points: bool,
    /// Reader threads in the child hold snapshots and check invariants.
    pub readers: bool,
    /// Operations per store before a fresh one is started.
    pub epoch_ops: u64,
    /// Queries per verification.
    pub queries: usize,
    /// Half the children run with a disk that fills up (see `child::Faults`).
    pub faults: bool,
    /// Kills at crash points are power cuts: writes not yet synced may be
    /// lost, page by page (see relay-store's `fault.rs`).
    pub power: bool,
    pub verbose: bool,
}

#[derive(Default, Debug)]
pub struct Stats {
    pub iterations: u64,
    pub epochs: u64,
    pub ops_acked: u64,
    pub events_acked: u64,
    pub timer_kills: u64,
    pub clean_exits: u64,
    /// Crash point name -> times a child died there.
    pub points: BTreeMap<String, u64>,
    /// In-flight batches found landed, by how much: (none, part, all).
    pub landed: (u64, u64, u64),
    pub queries_checked: u64,
    pub max_events: u64,
    /// Children run with write faults, operations that failed, and children
    /// that could not open on a full disk.
    pub fault_children: u64,
    pub ops_failed: u64,
    pub opens_refused: u64,
    /// Children whose crash point was a power cut.
    pub power_cuts: u64,
    /// Failed operations by what the store held afterwards: (nothing, part, all).
    pub failed_landed: (u64, u64, u64),
}

/// The files of a store and its checkpoint, for failure reports.
pub fn describe_dir(dir: &Path) -> String {
    fn walk(d: &Path, root: &Path, out: &mut Vec<String>) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let mut es: Vec<_> = rd.flatten().collect();
        es.sort_by_key(|e| e.path());
        for e in es {
            let p = e.path();
            if p.is_dir() {
                walk(&p, root, out);
            } else {
                let len = e.metadata().map(|m| m.len()).unwrap_or(0);
                out.push(format!("{} ({len})", p.strip_prefix(root).unwrap_or(&p).display()));
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, dir, &mut files);
    let ck = match relay_store::checkpoint::read(dir) {
        Ok(Some(c)) => format!("{c:?}"),
        Ok(None) => "none".into(),
        Err(e) => format!("unreadable: {e}"),
    };
    format!("files [{}]; checkpoint {ck}", files.join(", "))
}

/// A copy of a store directory (copy-on-write where the filesystem has it:
/// `locs` is large and sparse).
fn keep_copy(dir: &Path, to: &Path) {
    let _ = std::fs::remove_dir_all(to);
    let flags: &[&str] = if cfg!(target_os = "macos") { &["-cR"] } else { &["-R", "--reflink=auto", "--sparse=always"] };
    let _ = Command::new("cp").args(flags).arg(dir).arg(to).status();
}

fn panic_text(p: &Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
}

/// A child's run, as its stdout told it.
struct Run {
    lines: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
fn spawn_child(dir: &Path, seed: u64, start: u64, shape: &Shape, crash: Option<(String, u64)>, power: Option<u64>, faults: Option<child::Faults>, readers: bool, log: &Path) -> std::io::Result<(std::process::Child, mpsc::Receiver<String>)> {
    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("torture-child").arg("--dir").arg(dir).arg("--seed").arg(seed.to_string()).arg("--start").arg(start.to_string()).arg("--shape").arg(shape.encode());
    if readers {
        cmd.arg("--readers");
    }
    if let Some(f) = faults {
        cmd.arg("--faults").arg(f.encode());
    }
    cmd.env_remove("RELAY_CRASH_AT");
    if let Some((p, n)) = &crash {
        cmd.env("RELAY_CRASH_AT", format!("{p}:{n}")).env("RELAY_CRASH_LOG", log);
    }
    cmd.env_remove("RELAY_POWER_CUT");
    if let Some(seed) = power {
        cmd.env("RELAY_POWER_CUT", seed.to_string());
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null());
    let mut child = cmd.spawn()?;
    let out = child.stdout.take().expect("piped stdout");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines() {
            let Ok(l) = line else { break };
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    Ok((child, rx))
}

fn kill(child: &std::process::Child) {
    // SAFETY: signalling a child we spawned and have not yet reaped.
    unsafe {
        libc::kill(child.id() as i32, libc::SIGKILL);
    }
}

/// The shape of an epoch's store: small enough that every background path
/// runs constantly, varied so checkpoints are sometimes frequent, sometimes rare.
fn shape_for(rng: &mut Rng) -> Shape {
    Shape {
        segment_size: *rng.pick(&[64u64 << 10, 128 << 10, 1 << 20]),
        flush_bytes: *rng.pick(&[2048usize, 4096, 16 << 10, 256 << 10, 4 << 20]),
        log_compact_segments: *rng.pick(&[0usize, 2, 2, 3]),
        log_chunk_bytes: *rng.pick(&[16u64 << 10, 64 << 10, 1 << 20]),
    }
}

/// Where an admin delete stands in the model while its steps are acknowledged.
#[derive(Clone)]
struct AdminRun {
    targets: Vec<u64>,
    /// Steps fully applied (kill chunk then client batch).
    done: usize,
    killed: u64,
    /// Seqs the operator killed (their kills are not durable until the op is acknowledged).
    op_killed: Vec<u64>,
}

fn admin_step(m: &mut Model, run: &mut AdminRun, between: &[Vec<work::Ev>], s: usize, batch_prefix: Option<usize>) -> Vec<Out> {
    for &seq in run.targets.chunks(ADMIN_CHUNK).nth(s).unwrap_or(&[]) {
        if m.slots[seq as usize].alive {
            run.killed += 1;
            run.op_killed.push(seq);
            m.kill_seq(seq);
        }
    }
    let mut outs = Vec::new();
    if let Some(b) = between.get(s) {
        let n = batch_prefix.unwrap_or(b.len()).min(b.len());
        outs.extend(b[..n].iter().map(|e| m.apply_event(e)));
    }
    outs
}

fn steps_of(run: &AdminRun, between: &[Vec<work::Ev>]) -> usize {
    run.targets.chunks(ADMIN_CHUNK).count().max(between.len())
}

fn parse_tokens(t: &str) -> Result<Vec<Out>, String> {
    t.split_whitespace().map(|x| Out::parse(x).ok_or(format!("bad token {x:?}"))).collect()
}

/// An operation in full: each event of a batch as kind and id prefix.
pub fn describe_op(op: &Op) -> String {
    match op {
        Op::Batch(v) => format!("batch: {}", v.iter().map(|e| format!("n{} kind {}", e.n, e.kind)).collect::<Vec<_>>().join(", ")),
        other => op_name(other),
    }
}

fn op_name(op: &Op) -> String {
    match op {
        Op::Batch(v) => format!("batch of {}", v.len()),
        Op::Delete { filters, older_than } => format!("delete {filters:?} older_than {older_than:?}"),
        Op::AdminDelete { filters, between } => format!("admin delete {filters:?} with {} client batches", between.len()),
        other => format!("{other:?}").chars().take(40).collect(),
    }
}

/// Candidate states for an operation the crash interrupted.
fn candidates(base: &Model, op: &Op, admin: Option<&AdminRun>) -> Vec<(String, Model, Vec<u64>)> {
    let mut out = Vec::new();
    match op {
        Op::Batch(evs) => {
            let mut m = base.clone();
            out.push(("prefix 0".to_string(), m.clone(), Vec::new()));
            for (k, e) in evs.iter().enumerate() {
                m.apply_event(e);
                out.push((format!("prefix {}", k + 1), m.clone(), Vec::new()));
            }
        }
        Op::Delete { filters, older_than } => {
            // Any subset of the targets may be gone: the store's word decides each.
            let fs: Vec<_> = filters.iter().map(|f| model::parse_filter(f)).collect();
            let targets = base.matching(&fs, *older_than, NOW);
            let mut m = base.clone();
            for &s in &targets {
                m.kill_seq(s);
            }
            out.push(("removal (store decides each)".to_string(), m, targets));
        }
        Op::AdminDelete { filters, between } => {
            let fs: Vec<_> = filters.iter().map(|f| model::parse_filter(f)).collect();
            let m = base.clone();
            let run = match admin {
                Some(a) => AdminRun { targets: a.targets.clone(), done: a.done, killed: a.killed, op_killed: a.op_killed.clone() },
                None => AdminRun { targets: m.matching(&fs, None, NOW), done: 0, killed: 0, op_killed: Vec::new() },
            };
            let total = steps_of(&run, between);
            if run.done < total {
                // Steps without a client batch are not acknowledged one by one, so
                // the child may have gone on killing up to the next client batch
                // (then landed some prefix of it), or to the end. Operator kills
                // are not durable before the op is acknowledged: the store's word
                // decides each one.
                let s0 = run.done;
                let j = (s0..total).find(|&s| between.get(s).is_some());
                let blen = j.map_or(0, |j| between[j].len());
                for k in 0..=blen {
                    let mut mk = m.clone();
                    let mut rk = AdminRun { targets: run.targets.clone(), done: run.done, killed: run.killed, op_killed: run.op_killed.clone() };
                    for s in s0..j.unwrap_or(total) {
                        admin_step(&mut mk, &mut rk, between, s, None);
                    }
                    if let Some(j) = j {
                        admin_step(&mut mk, &mut rk, between, j, Some(k));
                    }
                    out.push((format!("admin from step {s0}, batch {j:?} prefix {k}"), mk, rk.op_killed.clone()));
                }
            } else {
                let maybe = run.op_killed.clone();
                out.push(("admin, all steps".to_string(), m.clone(), maybe));
            }
        }
        _ => out.push(("no effect".to_string(), base.clone(), Vec::new())),
    }
    out
}

/// One state the store may be in, as far as the child's lines tell. Without
/// write faults there is always exactly one; a failed operation forks one per
/// outcome it may have had, and the next lines prune them.
#[derive(Clone)]
struct World {
    label: String,
    m: Model,
    admin: Option<AdminRun>,
    admin_op: Option<u64>,
    /// Failed batches whose frames may still lie at the end of the log, with
    /// the model's next seq when each failed: while nothing has been stored
    /// since, a restart may find a prefix of one of them there (as for a
    /// crash). Which one: the last whose frames got written before it failed.
    trailing: Vec<(Vec<work::Ev>, u64)>,
    /// Seqs a failed removal killed: the kill was never acknowledged, so it may
    /// not survive a crash (an operator's kill is durable only once its
    /// checkpoint is written). The store's word decides them at the reopen.
    unsure: Vec<u64>,
}

impl World {
    fn new(m: Model) -> World {
        World { label: String::new(), m, admin: None, admin_op: None, trailing: Vec::new(), unsure: Vec::new() }
    }

    /// Applies one acknowledgement line ("P" or "A") and checks its outcomes.
    fn ack(&mut self, eseed: u64, tag: &str, i: u64, step: usize, got: &[Out]) -> Result<(), String> {
        let op = work::op(eseed, i);
        if tag == "P" {
            let Op::AdminDelete { filters, between } = &op else { return Err("progress line for a non-admin op".into()) };
            let fs: Vec<_> = filters.iter().map(|f| model::parse_filter(f)).collect();
            if self.admin_op != Some(i) {
                self.admin = Some(AdminRun { targets: self.m.matching(&fs, None, NOW), done: 0, killed: 0, op_killed: Vec::new() });
                self.admin_op = Some(i);
            }
            let a = self.admin.as_mut().expect("admin run");
            let mut outs = Vec::new();
            while a.done <= step {
                let d = a.done;
                outs = admin_step(&mut self.m, a, between, d, None);
                a.done += 1;
            }
            if outs != got {
                return Err(format!("admin step {step} outcomes: store said {got:?}, model expects {outs:?}"));
            }
            return Ok(());
        }
        let want = match &op {
            Op::AdminDelete { filters, between } => {
                let fs: Vec<_> = filters.iter().map(|f| model::parse_filter(f)).collect();
                if self.admin_op != Some(i) {
                    self.admin = Some(AdminRun { targets: self.m.matching(&fs, None, NOW), done: 0, killed: 0, op_killed: Vec::new() });
                }
                let a = self.admin.as_mut().expect("admin run");
                let total = steps_of(a, between);
                while a.done < total {
                    let d = a.done;
                    admin_step(&mut self.m, a, between, d, None);
                    a.done += 1;
                }
                let k = a.killed;
                self.admin = None;
                self.admin_op = None;
                vec![Out::Stored(k)]
            }
            other => self.m.apply_op(other, NOW),
        };
        if want != got {
            return Err(format!("{}: store said {got:?}, model expects {want:?}", op_name(&op)));
        }
        if want.iter().any(|o| matches!(o, Out::Stored(_))) && matches!(op, Op::Batch(_)) {
            self.trailing.clear();
        }
        Ok(())
    }
}

/// The outcomes a failed operation may have had, each with the seqs whose
/// fate the child's view of the store decides.
type Forks = Vec<(World, Vec<u64>)>;

/// Keeps the worlds `f` accepts; when none does, the error of the first.
fn prune(worlds: Vec<World>, mut f: impl FnMut(&mut World) -> Result<(), String>) -> Result<Vec<World>, String> {
    let mut kept = Vec::new();
    let mut first_err = None;
    for mut w in worlds {
        match f(&mut w) {
            Ok(()) => kept.push(w),
            Err(e) => {
                first_err.get_or_insert(if w.label.is_empty() { e } else { format!("[{}] {e}", w.label) });
            }
        }
    }
    if kept.is_empty() {
        return Err(first_err.unwrap_or_else(|| "no state left".into()));
    }
    Ok(kept)
}

/// Whether a world holds what the child said it holds after a failure.
fn matches_view(w: &World, next_seq: u64, published: u64, live: &[u64]) -> Result<(), String> {
    if published != next_seq {
        return Err(format!("the store took seqs up to {next_seq} but published only {published}"));
    }
    if w.m.next_seq() != next_seq {
        return Err(format!("next_seq {next_seq}, model has {}", w.m.next_seq()));
    }
    let model_live: Vec<u64> = w.m.live_seqs().map(|s| s.seq).collect();
    if model_live != live {
        let a: std::collections::BTreeSet<u64> = model_live.iter().copied().collect();
        let b: std::collections::BTreeSet<u64> = live.iter().copied().collect();
        let only_model: Vec<_> = a.difference(&b).take(8).collect();
        let only_store: Vec<_> = b.difference(&a).take(8).collect();
        return Err(format!("live sets differ: model only {only_model:?}, store only {only_store:?}"));
    }
    Ok(())
}

pub fn run(cfg: &Cfg) -> Result<Stats, String> {
    let mut st = Stats::default();
    let mut rng = Rng::new(cfg.seed);
    std::fs::create_dir_all(&cfg.root).map_err(|e| e.to_string())?;
    let crash_log = cfg.root.join("crash-points.log");
    let mut epoch = 0u64;
    let mut it = 0u64;
    while it < cfg.iterations {
        let eseed = mix(cfg.seed ^ mix(epoch + 1));
        let dir = cfg.root.join(format!("epoch-{epoch}"));
        let _ = std::fs::remove_dir_all(&dir);
        let shape = shape_for(&mut Rng::new(eseed));
        if cfg.verbose {
            eprintln!("epoch {epoch}: seed {eseed:#x}, shape {shape:?}");
        }
        let mut m = Model::new(eseed);
        let mut next_op = 0u64;
        st.epochs += 1;
        while next_op < cfg.epoch_ops && it < cfg.iterations {
            it += 1;
            st.iterations += 1;
            let crash = (cfg.crash_points && rng.chance(1, 2)).then(|| (rng.pick(CRASH_POINTS).to_string(), 1 + rng.skewed(30)));
            let _ = std::fs::remove_file(&crash_log);
            let faults = (cfg.faults && rng.chance(1, 2)).then(|| child::Faults { budget: rng.skewed(1 << 21), hold: rng.below(4), at_open: rng.chance(1, 8) });
            if faults.is_some() {
                st.fault_children += 1;
            }
            // A power cut instead of a crash: what was not synced may be lost.
            let power = (cfg.power && crash.is_some()).then(|| rng.next_u64());
            if power.is_some() {
                st.power_cuts += 1;
            }
            let (mut child, rx) = spawn_child(&dir, eseed, next_op, &shape, crash.clone(), power, faults, cfg.readers, &crash_log).map_err(|e| e.to_string())?;
            let delay = Duration::from_millis(1 + rng.skewed(cfg.max_kill_ms));
            let deadline = Instant::now() + if crash.is_some() { delay * 4 } else { delay };
            let mut lines = Vec::new();
            let mut exited = false;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                match rx.recv_timeout(left) {
                    Ok(l) => lines.push(l),
                    Err(mpsc::RecvTimeoutError::Timeout) => break,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        exited = true;
                        break;
                    }
                }
            }
            if !exited {
                kill(&child);
                st.timer_kills += 1;
            }
            lines.extend(rx.iter());
            let status = child.wait().map_err(|e| e.to_string())?;
            if let Ok(p) = std::fs::read_to_string(&crash_log) {
                for l in p.lines() {
                    *st.points.entry(l.to_string()).or_default() += 1;
                }
            }
            if exited && status.success() {
                st.clean_exits += 1;
            }
            if crate::env_flag("ADV_TRACE") {
                eprintln!("child {it} from op {next_op} (crash {crash:?}, faults {faults:?}, {status}):");
                for l in &lines {
                    eprintln!("  {}", l.chars().take(300).collect::<String>());
                }
            }
            let run = Run { lines };
            let first_op = next_op;
            let mut pending: Option<(u64, Forks)> = None;
            let ctx = |msg: String| format!("epoch {epoch} (seed {eseed:#x}, shape {shape:?}) iteration {it}, child from op {first_op}: {msg}");

            // Replay the child's lines into the model: one world, unless a
            // write failed.
            let mut worlds = vec![World::new(m)];
            for l in &run.lines {
                let (tag, rest) = l.split_once(' ').unwrap_or((l.as_str(), ""));
                match tag {
                    "O" => {
                        let n: u64 = rest.trim().parse().map_err(|_| ctx(format!("bad line {l:?}")))?;
                        worlds = prune(worlds, |w| if w.m.next_seq() == n { Ok(()) } else { Err(format!("child opened with next_seq {n}, model has {}", w.m.next_seq())) }).map_err(&ctx)?;
                    }
                    "P" | "A" => {
                        let (i, step, toks) = if tag == "P" {
                            let mut parts = rest.splitn(3, ' ');
                            let i: u64 = parts.next().and_then(|x| x.parse().ok()).ok_or(ctx(format!("bad line {l:?}")))?;
                            let s: usize = parts.next().and_then(|x| x.parse().ok()).ok_or(ctx(format!("bad line {l:?}")))?;
                            (i, s, parts.next().unwrap_or(""))
                        } else {
                            let (i, toks) = rest.split_once(' ').unwrap_or((rest, ""));
                            (i.parse().map_err(|_| ctx(format!("bad line {l:?}")))?, 0, toks)
                        };
                        if i != next_op {
                            return Err(ctx(format!("line for op {i}, expected op {next_op}")));
                        }
                        let got = parse_tokens(toks).map_err(&ctx)?;
                        let many = worlds.len() > 1;
                        worlds = prune(worlds, |w| w.ack(eseed, tag, i, step, &got)).map_err(|e| ctx(if many { format!("after a failed write, no outcome it may have had explains op {i}: {e}") } else { e }))?;
                        if tag == "A" {
                            let op = work::op(eseed, i);
                            st.ops_acked += 1;
                            if let Op::Batch(v) = &op {
                                st.events_acked += v.len() as u64;
                            }
                            next_op += 1;
                        }
                    }
                    "E" if faults.is_some() => {
                        let (i, _) = rest.split_once(' ').unwrap_or((rest, ""));
                        let i: u64 = i.parse().map_err(|_| ctx(format!("bad line {l:?}")))?;
                        if i != next_op {
                            return Err(ctx(format!("failure of op {i}, expected op {next_op}")));
                        }
                        st.ops_failed += 1;
                        // Every outcome the failed operation may have had; the child's
                        // next line says which it was.
                        let op = work::op(eseed, i);
                        let mut forks = Vec::new();
                        for w in &worlds {
                            for (label, c, maybe) in candidates(&w.m, &op, w.admin.as_ref()) {
                                let mut trailing = w.trailing.clone();
                                if let Op::Batch(evs) = &op {
                                    trailing.push((evs.clone(), w.m.next_seq()));
                                }
                                forks.push((World { label: format!("op {i} failed: {label}"), m: c, admin: None, admin_op: None, trailing, unsure: w.unsure.clone() }, maybe));
                            }
                        }
                        // The view decides removals in flight, so keep them with their world.
                        pending = Some((i, forks));
                        next_op += 1;
                    }
                    "V" if faults.is_some() => {
                        let mut parts = rest.splitn(4, ' ');
                        let mut num = || parts.next().and_then(|x| x.parse::<u64>().ok());
                        let (Some(i), Some(ns), Some(published)) = (num(), num(), num()) else { return Err(ctx(format!("bad line {l:?}"))) };
                        let live = child::parse_ranges(rest.splitn(4, ' ').nth(3).unwrap_or("")).ok_or(ctx(format!("bad line {l:?}")))?;
                        let Some((fi, forks)) = pending.take() else { return Err(ctx(format!("view without a failure: {l:?}"))) };
                        if fi != i {
                            return Err(ctx(format!("view of op {i} after the failure of op {fi}")));
                        }
                        let live_set: std::collections::HashSet<u64> = live.iter().copied().collect();
                        let mut kept = Vec::new();
                        let mut first_err = None;
                        for (mut w, maybe) in forks {
                            // A removal in flight: the store's word decides each target.
                            for &seq in &maybe {
                                if (seq as usize) < w.m.slots.len() {
                                    let alive = live_set.contains(&seq);
                                    if alive && !w.m.slots[seq as usize].alive {
                                        w.m.revive_seq(seq);
                                    } else if !alive && w.m.slots[seq as usize].alive {
                                        w.m.kill_seq(seq);
                                    }
                                    if !alive {
                                        w.unsure.push(seq);
                                    }
                                }
                            }
                            match matches_view(&w, ns, published, &live) {
                                Ok(()) => kept.push(w),
                                Err(e) => {
                                    first_err.get_or_insert(format!("[{}] {e}", w.label));
                                }
                            }
                        }
                        if kept.is_empty() {
                            return Err(ctx(format!("after op {i} ({}) failed, the store holds no state the model allows: {}", op_name(&work::op(eseed, i)), first_err.unwrap_or_default())));
                        }
                        let before = worlds.first().map_or(0, |w| w.m.next_seq());
                        let after = kept[0].m.next_seq();
                        let n = match work::op(eseed, i) {
                            Op::Batch(evs) => evs.len() as u64,
                            _ => 0,
                        };
                        if after == before {
                            st.failed_landed.0 += 1;
                        } else if after - before < n {
                            st.failed_landed.1 += 1;
                        } else {
                            st.failed_landed.2 += 1;
                        }
                        worlds = kept;
                    }
                    "N" if faults.is_some_and(|f| f.at_open) => st.opens_refused += 1,
                    "E" => return Err(ctx(format!("operation failed without injected faults: {rest}"))),
                    "R" => return Err(ctx(format!("panic in the child: {rest}"))),
                    "F" => return Err(ctx(format!("the store refused to open: {rest}; {}", describe_dir(&dir)))),
                    _ => return Err(ctx(format!("unexpected line {l:?}"))),
                }
            }
            if let Some((i, _)) = pending {
                // Killed between a failure and its view: the failed op is the one in flight.
                next_op = i;
                st.ops_failed -= 1;
            }

            // The operation in flight, and what the store may hold because of it.
            let op = work::op(eseed, next_op);
            let mut cands = Vec::new();
            for w in &worlds {
                cands.extend(candidates(&w.m, &op, w.admin.as_ref()).into_iter().map(|(l, c, mut maybe)| {
                    maybe.extend(&w.unsure);
                    (l, c, maybe)
                }));
            }
            // A failed batch still at the end of the log may land on restart.
            for w in &worlds {
                for (evs, ns) in &w.trailing {
                    if w.m.next_seq() == *ns {
                        let mut t = w.m.clone();
                        for (k, e) in evs.iter().enumerate() {
                            t.apply_event(e);
                            for (label, c, mut maybe) in candidates(&t, &op, w.admin.as_ref()) {
                                maybe.extend(&w.unsure);
                                cands.push((format!("failed batch prefix {}, then {label}", k + 1), c, maybe));
                            }
                        }
                    }
                }
            }
            if crate::env_flag("ADV_KEEP_PREOPEN") {
                // The store as the crash left it, before this open changes it.
                // The last few iterations, to replay their children by hand.
                keep_copy(&dir, &cfg.root.join(format!("pre-open-{it}")));
                let _ = std::fs::remove_dir_all(cfg.root.join(format!("pre-open-{}", it.saturating_sub(8))));
            }
            let (store, w) = relay_store::Store::open(&dir, shape.options()).map_err(|e| ctx(format!("reopen after the crash failed: {e}; {}", describe_dir(&dir))))?;
            let mut chosen = None;
            let mut best_err = String::new();
            for (label, mut c, maybe) in cands {
                // The parent's open swept what had expired.
                c.sweep(work::PAST);
                // Removals in flight: the store's word decides each target.
                verify::adopt(&mut c, &store, &maybe);
                let checked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verify::check_state(&c, &store, &w)));
                match checked.unwrap_or_else(|p| Err(format!("reading the store panicked: {}", panic_text(&p)))) {
                    Ok(()) => {
                        if let Op::Batch(evs) = &op {
                            let k: usize = label.trim_start_matches("prefix ").parse().unwrap_or(0);
                            if k == 0 {
                                st.landed.0 += 1;
                            } else if k == evs.len() {
                                st.landed.2 += 1;
                            } else {
                                st.landed.1 += 1;
                            }
                        }
                        if crate::env_flag("ADV_TRACE") {
                            eprintln!("reopened as [{label}], next op {next_op}");
                        }
                        chosen = Some(c);
                        break;
                    }
                    Err(e) => {
                        // The candidate with the store's seq count is the prefix that
                        // landed: its error is the one that explains the failure.
                        let landed = c.next_seq() == w.next_seq();
                        if best_err.is_empty() || landed || (e.len() < best_err.len() && !best_err.starts_with('*')) {
                            best_err = format!("{}[{label}] {e}", if landed { "*" } else { "" });
                        }
                    }
                }
            }
            let Some(c) = chosen else {
                return Err(ctx(format!("after the crash in {} the store matches no state the model allows; closest: {best_err}", op_name(&op))));
            };
            m = c;
            verify::check_frames(&m, &dir, shape.segment_size).map_err(|e| ctx(format!("after the reopen: {e}")))?;
            st.queries_checked += verify::check_queries(&m, &store, cfg.queries, &mut rng).map_err(|e| ctx(format!("query check after reopen: {e}")))?;
            st.max_events = st.max_events.max(m.next_seq());
            // Let any background job the open started finish before the next child opens.
            w.close();
            drop(store);
            if cfg.verbose && it.is_multiple_of(50) {
                eprintln!("  it {it}: op {next_op}, {} events stored, {} live; {:?}", m.next_seq(), m.live_seqs().count(), st.landed);
            }
        }
        if cfg.verbose {
            eprintln!("epoch {epoch} done: {} ops, {} events", next_op, m.next_seq());
        }
        let _ = std::fs::remove_dir_all(&dir);
        epoch += 1;
    }
    Ok(st)
}

/// Every shape `shape_for` can choose (with the smallest chunk), for replays.
pub fn all_shapes() -> Vec<Shape> {
    let mut v = Vec::new();
    for &segment_size in &[64u64 << 10, 1 << 20] {
        for &flush_bytes in &[2048usize, 256 << 10] {
            for &log_compact_segments in &[0usize, 2] {
                v.push(Shape { segment_size, flush_bytes, log_compact_segments, log_chunk_bytes: 16 << 10 });
            }
        }
    }
    v
}

fn write_batch(w: &mut relay_store::Writer, evs: &[work::Ev]) -> std::io::Result<Vec<Out>> {
    let recs: Vec<Vec<u8>> = evs.iter().map(|e| e.record()).collect();
    let refs: Vec<&[u8]> = recs.iter().map(|r| r.as_slice()).collect();
    Ok(w.write(&refs)?.iter().map(Out::of).collect())
}

/// The workload in one process with no crashes: every acknowledgement checked
/// against the model as it happens, and the whole store against the model and
/// brute force every `check_every` operations. Deterministic: a failure here
/// reproduces exactly from (seed, shape).
pub fn replay(dir: &Path, eseed: u64, shape: Shape, ops: u64, check_every: u64, queries: usize) -> Result<u64, String> {
    replay_model(dir, eseed, shape, ops, check_every, queries).map(|(q, _)| q)
}

/// `replay`, also returning the model of what the store then holds (before
/// the expiry sweep its next open makes).
pub fn replay_model(dir: &Path, eseed: u64, shape: Shape, ops: u64, check_every: u64, queries: usize) -> Result<(u64, Model), String> {
    let _ = std::fs::remove_dir_all(dir);
    let (store, mut w) = relay_store::Store::open(dir, shape.options()).map_err(|e| e.to_string())?;
    let mut m = Model::new(eseed);
    let mut rng = Rng::new(eseed ^ 0xC4EC);
    let mut checked = 0;
    for i in 0..ops {
        let op = work::op(eseed, i);
        if matches!(op, Op::Restart) {
            continue;
        }
        let ctx = |msg: String| format!("seed {eseed:#x} shape {} op {i} ({}): {msg}", shape.encode(), op_name(&op));
        let io = |e: std::io::Error| ctx(e.to_string());
        let got: Vec<Out> = match &op {
            Op::Batch(evs) => write_batch(&mut w, evs).map_err(io)?,
            Op::Delete { filters, older_than } => {
                let fs: Vec<_> = filters.iter().map(|f| model::parse_filter(f)).collect();
                vec![Out::Stored(w.delete_matching(&fs, *older_than, NOW).map_err(io)? as u64)]
            }
            Op::AdminDelete { filters, between } => {
                let fs: Vec<_> = filters.iter().map(|f| model::parse_filter(f)).collect();
                let v = store.snapshot();
                let seqs: Vec<u64> = v.matching_seqs(&fs, None, NOW).map(|h| h.seq).collect();
                let chunks: Vec<&[u64]> = seqs.chunks(ADMIN_CHUNK).collect();
                let mut out = Vec::new();
                let mut killed = 0u64;
                for s in 0..chunks.len().max(between.len()) {
                    if let Some(c) = chunks.get(s) {
                        killed += w.kill_live(c).map_err(io)? as u64;
                    }
                    if let Some(b) = between.get(s) {
                        out.extend(write_batch(&mut w, b).map_err(io)?);
                    }
                }
                w.write_checkpoint().map_err(io)?;
                drop(v);
                out.push(Out::Stored(killed));
                out
            }
            Op::Sweep(t) => w.sweep_expired(*t).map(|_| Vec::new()).map_err(io)?,
            Op::FlushAll => w.flush_all().map(|_| Vec::new()).map_err(io)?,
            Op::CompactAll => w.compact_all().map(|_| Vec::new()).map_err(io)?,
            Op::CompactLog => w.compact_log_hot().map(|_| Vec::new()).map_err(io)?,
            Op::MergeLog => w.merge_log_runs().map(|_| Vec::new()).map_err(io)?,
            Op::Checkpoint => w.write_checkpoint().map(|_| Vec::new()).map_err(io)?,
            Op::Restart => unreachable!("skipped above"),
        };
        let want = m.apply_op(&op, NOW);
        if got != want {
            return Err(ctx(format!("store said {got:?}, model expects {want:?}")));
        }
        if check_every > 0 && (i + 1) % check_every == 0 {
            verify::check_state(&m, &store, &w).map_err(&ctx)?;
            checked += verify::check_queries(&m, &store, queries, &mut rng).map_err(&ctx)?;
            let v = store.snapshot();
            for _ in 0..queries {
                let f = model::parse_filter(&work::filter_json(eseed, &mut rng));
                let mut r2 = rng.clone();
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| readers::check_snapshot(&v, &f, &mut r2)));
                if r.is_err() {
                    let mut j = Vec::new();
                    f.write_json(&mut j);
                    return Err(ctx(format!("snapshot invariant broken for filter {}", String::from_utf8_lossy(&j))));
                }
            }
        }
    }
    Ok((checked, m))
}
