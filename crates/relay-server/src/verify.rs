//! Signature checks for the reactors, batched across connections.
//!
//! A read brings a connection's EVENTs a dozen at a time at most, and a batch
//! that small saves little: 25 µs a signature at 12, against 16 at 128 and 14
//! at 256 (docs/SIG_PERF.md). Reactors hand their queued signatures here as
//! one `Job` per read and wait for the verdicts; a verifier takes every job
//! waiting, up to `MAX_BATCH` signatures, and checks them as one batch. Nothing
//! waits for more to arrive: one verifier works while it has jobs, and the
//! batch it takes next is whatever came in meanwhile, so batches grow with the
//! load. Another verifier wakes only when `WAKE_AT` signatures are still
//! waiting.
//! Reactors never stall their other connections behind a long batch.

use relay_proto::secp::{self, SigRef, Verifier};
use relay_proto::{sha256, Record};
use std::collections::VecDeque;
use std::ops::Range;
use std::sync::{Arc, Condvar, Mutex};
use tokio::sync::oneshot;

/// Most signatures checked as one batch: ~2 ms of work at 16 µs each.
const MAX_BATCH: usize = 128;
/// Signatures waiting that wake another verifier while one is busy. At 128
/// one verifier ran flat out before a second woke, and ingest lost 6-8%; at
/// 1 batches stayed small (CPU -8% instead of -17%). 48 kept both.
const WAKE_AT: usize = 48;

/// One read's queued EVENTs: their records end to end, and back from the
/// verifier with a verdict each.
#[derive(Default)]
pub struct Job {
    pub recs: Vec<u8>,
    pub ends: Vec<usize>,
    pub kinds: Vec<u64>,
    /// Whether the id is still to be checked (the reactor checks those it
    /// cannot leave to a verifier).
    pub check_id: Vec<bool>,
    pub verdicts: Vec<Verdict>,
    pub checked: Checked,
    /// The first job of a batch that passed: the one that counts the batch.
    pub head: bool,
}

impl Job {
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    pub fn push(&mut self, rec: &[u8], kind: u64, check_id: bool) {
        self.recs.extend_from_slice(rec);
        self.ends.push(self.recs.len());
        self.kinds.push(kind);
        self.check_id.push(check_id);
    }

    pub fn clear(&mut self) {
        self.recs.clear();
        self.ends.clear();
        self.kinds.clear();
        self.check_id.clear();
        self.verdicts.clear();
        self.checked = Checked::OneByOne;
        self.head = false;
    }

    pub fn record(&self, i: usize) -> &[u8] {
        let start = if i == 0 { 0 } else { self.ends[i - 1] };
        &self.recs[start..self.ends[i]]
    }

    /// Each record, in order.
    pub fn records(&self) -> impl Iterator<Item = &[u8]> {
        (0..self.len()).map(|i| self.record(i))
    }
}

/// What a check found for one event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Valid,
    BadId,
    BadSig,
}

/// How a job's signatures were checked.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Checked {
    #[default]
    OneByOne,
    /// In a batch that passed.
    Batch,
    /// In a batch that failed because of this job's own signatures: they were
    /// then checked alone, and the connection checks the rest the same way.
    BatchFailed,
}

/// Checks jobs: one per thread that does (each reactor, each verifier).
#[derive(Default)]
pub struct Checker {
    sigs: Verifier,
    pre: Vec<u8>,
    spans: Vec<Range<usize>>,
    digests: Vec<[u8; 32]>,
    ok: Vec<bool>,
    /// (job, event) of each preimage, then of each signature.
    at: Vec<(usize, usize)>,
}

impl Checker {
    /// Gives every event of `jobs` a verdict: ids left to us hashed eight at
    /// a time (`sha256::digest_many`), then the signatures of every event
    /// whose id holds, as one batch when `batch` (else one at a time). An
    /// event with a bad id stays out of the batch, so it cannot fail it.
    pub fn check(&mut self, jobs: &mut [&mut Job], batch: bool) {
        self.pre.clear();
        self.spans.clear();
        self.at.clear();
        for (j, job) in jobs.iter_mut().enumerate() {
            job.verdicts.clear();
            job.verdicts.resize(job.len(), Verdict::Valid);
            for i in 0..job.len() {
                if job.check_id[i] {
                    let start = self.pre.len();
                    Record(job.record(i)).write_id_preimage(&mut self.pre);
                    self.spans.push(start..self.pre.len());
                    self.at.push((j, i));
                }
            }
        }
        if !self.at.is_empty() {
            let pres: Vec<&[u8]> = self.spans.iter().map(|r| &self.pre[r.clone()]).collect();
            self.digests.clear();
            self.digests.resize(pres.len(), [0; 32]);
            sha256::digest_many(&pres, &mut self.digests);
            for (k, &(j, i)) in self.at.iter().enumerate() {
                if self.digests[k] != *Record(jobs[j].record(i)).id() {
                    jobs[j].verdicts[i] = Verdict::BadId;
                }
            }
        }

        self.at.clear();
        let mut refs: Vec<SigRef<'_>> = Vec::new();
        for (j, job) in jobs.iter().enumerate() {
            for i in 0..job.len() {
                if job.verdicts[i] == Verdict::Valid {
                    let r = Record(job.record(i));
                    refs.push(SigRef { pubkey: r.pubkey(), msg: r.id(), sig: r.sig() });
                    self.at.push((j, i));
                }
            }
        }
        let tried = batch && refs.len() >= secp::MIN_BATCH;
        let passed = if tried {
            self.sigs.verify_batch(&refs, &mut self.ok)
        } else {
            self.ok.clear();
            self.ok.extend(refs.iter().map(|r| self.sigs.verify_one(r)));
            false
        };
        drop(refs);
        let mut in_batch = vec![false; jobs.len()];
        for (k, &(j, i)) in self.at.iter().enumerate() {
            in_batch[j] = true;
            if !self.ok[k] {
                jobs[j].verdicts[i] = Verdict::BadSig;
            }
        }
        let mut counted = false;
        for (j, job) in jobs.iter_mut().enumerate() {
            job.checked = if tried && passed && in_batch[j] {
                Checked::Batch
            } else if tried && job.verdicts.contains(&Verdict::BadSig) {
                Checked::BatchFailed
            } else {
                Checked::OneByOne
            };
            job.head = job.checked == Checked::Batch && !counted;
            counted |= job.head;
        }
    }
}

struct Queue {
    jobs: VecDeque<(Job, oneshot::Sender<Job>)>,
    /// Signatures waiting in `jobs`.
    sigs: usize,
    /// Verifiers at work.
    busy: usize,
    stop: bool,
}

struct Inner {
    q: Mutex<Queue>,
    ready: Condvar,
    threads: usize,
}

/// The verifier threads. Dropped, they finish what they hold and exit.
pub struct Pool {
    inner: Arc<Inner>,
}

impl Pool {
    pub fn new(threads: usize) -> Pool {
        let inner = Arc::new(Inner {
            q: Mutex::new(Queue { jobs: VecDeque::new(), sigs: 0, busy: 0, stop: false }),
            ready: Condvar::new(),
            threads: threads.max(1),
        });
        for i in 0..inner.threads {
            let inner = inner.clone();
            std::thread::Builder::new().name(format!("verify-{i}")).spawn(move || work(&inner)).expect("verifier thread");
        }
        Pool { inner }
    }

    /// Whether `n` signatures should come here rather than be checked on the
    /// spot: a batch's worth, or any number while a batch is being checked
    /// (they join the next one). One or two at a quiet moment go faster on
    /// the reactor than through another thread.
    pub fn wants(&self, n: usize) -> bool {
        n >= secp::MIN_BATCH || self.inner.q.lock().unwrap().busy > 0
    }

    /// Queues a job; its verdicts come back on the receiver.
    pub fn submit(&self, job: Job) -> oneshot::Receiver<Job> {
        let (tx, rx) = oneshot::channel();
        let mut q = self.inner.q.lock().unwrap();
        q.sigs += job.len();
        q.jobs.push_back((job, tx));
        // An idle pool gets one verifier; a busy one another, only once enough
        // is waiting beyond what the working ones will take.
        if q.busy == 0 || (q.sigs >= WAKE_AT && q.busy < self.inner.threads) {
            self.inner.ready.notify_one();
        }
        rx
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.inner.q.lock().unwrap().stop = true;
        self.inner.ready.notify_all();
    }
}

fn work(inner: &Inner) {
    let mut checker = Checker::default();
    let mut taken: Vec<(Job, oneshot::Sender<Job>)> = Vec::new();
    loop {
        {
            let mut q = inner.q.lock().unwrap();
            while q.jobs.is_empty() && !q.stop {
                q = inner.ready.wait(q).unwrap();
            }
            if q.jobs.is_empty() {
                return;
            }
            // Whole jobs, at least one, up to a batch's worth of signatures.
            let mut n = 0;
            while let Some((job, _)) = q.jobs.front() {
                if n > 0 && n + job.len() > MAX_BATCH {
                    break;
                }
                n += job.len();
                taken.push(q.jobs.pop_front().unwrap());
            }
            q.sigs -= n;
            q.busy += 1;
            if q.sigs >= WAKE_AT && q.busy < inner.threads {
                inner.ready.notify_one();
            }
        }
        let mut jobs: Vec<&mut Job> = taken.iter_mut().map(|(j, _)| j).collect();
        checker.check(&mut jobs, true);
        for (job, tx) in taken.drain(..) {
            // A connection that went away no longer wants its verdicts.
            let _ = tx.send(job);
        }
        inner.q.lock().unwrap().busy -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use relay_proto::event::parse_event_json;

    /// `n` signed kind-1 events as records, from five keys.
    fn signed(n: u64) -> Vec<Vec<u8>> {
        use secp256k1::{schnorr, Keypair};
        use sha2::{Digest, Sha256};
        let keys: Vec<Keypair> = (1..=5u8).map(|i| Keypair::from_secret_bytes([i; 32]).unwrap()).collect();
        (0..n)
            .map(|i| {
                let k = &keys[(i % 5) as usize];
                let pk = relay_proto::hex::encode_string(&k.x_only_public_key().0.to_byte_array());
                let pre = format!("[0,\"{pk}\",{},1,[],\"event {i}\"]", 1_700_000_000 - i);
                let id: [u8; 32] = Sha256::digest(pre.as_bytes()).into();
                let sig = relay_proto::hex::encode_string(&schnorr::sign_no_aux_rand(&id, k).to_byte_array());
                let id = relay_proto::hex::encode_string(&id);
                let json = format!(
                    "{{\"id\":\"{id}\",\"pubkey\":\"{pk}\",\"created_at\":{},\"kind\":1,\"tags\":[],\"content\":\"event {i}\",\"sig\":\"{sig}\"}}",
                    1_700_000_000 - i
                );
                let mut rec = Vec::new();
                parse_event_json(&json, &mut relay_proto::EventParser::default(), &mut rec, false).unwrap();
                rec
            })
            .collect()
    }

    /// Any number of jobs, valid or not, come back whole and in their own
    /// order, with libsecp256k1's verdict for every signature.
    #[test]
    fn jobs_come_back_with_their_own_verdicts() {
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let pool = Pool::new(2);
        let good = signed(40);
        // One of them with a byte of its signature changed.
        let mut bad = good[7].clone();
        let sig = *Record(&bad).sig();
        let at = bad.windows(64).position(|w| w == sig).unwrap() + 10;
        bad[at] ^= 1;
        // And one whose content no longer hashes to its id.
        let mut forged = good[12].clone();
        let at = forged.windows(8).position(|w| w == b"event 12").unwrap();
        forged[at + 4] = b'T';
        let mut rxs = Vec::new();
        let mut want = Vec::new();
        for (i, chunk) in good.chunks(5).enumerate() {
            let mut job = Job::default();
            let mut w = Vec::new();
            for (k, r) in chunk.iter().enumerate() {
                // Job 3 carries a bad signature in its second place, job 5 a
                // bad id in its first.
                let r = match (i, k) {
                    (3, 1) => &bad,
                    (5, 0) => &forged,
                    _ => r,
                };
                job.push(r, 1, true);
                w.push(match (i, k) {
                    (3, 1) => Verdict::BadSig,
                    (5, 0) => Verdict::BadId,
                    _ => Verdict::Valid,
                });
            }
            rxs.push(pool.submit(job));
            want.push(w);
        }
        for (i, rx) in rxs.into_iter().enumerate() {
            let job = rt.block_on(rx).unwrap();
            assert_eq!(job.verdicts, want[i], "job {i}");
            if i == 3 {
                assert_eq!(job.checked, Checked::BatchFailed);
            } else {
                assert_ne!(job.checked, Checked::BatchFailed, "job {i}");
            }
        }
    }
}
