//! Signature checks for the reactors, batched across connections.
//!
//! A read brings a connection's EVENTs a dozen at a time at most, and a batch
//! that small saves little: 25 µs a signature at 12, against 16 at 128 and 14
//! at 256 (docs/SIG_PERF.md). Reactors hand their queued signatures here as
//! one `Job` per read and wait for the verdicts; a verifier takes every job
//! waiting, up to `MAX_BATCH` signatures, and checks them as one batch. Nothing
//! waits for more to arrive: one verifier works while it has jobs, and the
//! batch it takes next is whatever came in meanwhile, so batches grow with the
//! load. Another verifier wakes only when a full batch is still waiting.
//! Reactors never stall their other connections behind a long batch.

use relay_proto::secp::{self, SigRef, Verifier};
use relay_proto::Record;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use tokio::sync::oneshot;

/// Most signatures checked as one batch: ~2 ms of work at 16 µs each.
const MAX_BATCH: usize = 128;

/// One read's queued EVENTs: their records end to end, and back from the
/// verifier with a verdict each.
#[derive(Default)]
pub struct Job {
    pub recs: Vec<u8>,
    pub ends: Vec<usize>,
    pub kinds: Vec<u64>,
    pub ok: Vec<bool>,
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

    pub fn push(&mut self, rec: &[u8], kind: u64) {
        self.recs.extend_from_slice(rec);
        self.ends.push(self.recs.len());
        self.kinds.push(kind);
    }

    pub fn clear(&mut self) {
        self.recs.clear();
        self.ends.clear();
        self.kinds.clear();
        self.ok.clear();
        self.checked = Checked::OneByOne;
        self.head = false;
    }

    /// Each record, in order.
    pub fn records(&self) -> impl Iterator<Item = &[u8]> {
        let mut start = 0;
        self.ends.iter().map(move |&end| {
            let r = &self.recs[start..end];
            start = end;
            r
        })
    }

    fn refs(&self) -> impl Iterator<Item = SigRef<'_>> {
        self.records().map(|r| {
            let r = Record(r);
            SigRef { pubkey: r.pubkey(), msg: r.id(), sig: r.sig() }
        })
    }

    /// Checks this job's signatures alone: as a batch when `batch`, else one at
    /// a time.
    pub fn verify(&mut self, v: &mut Verifier, batch: bool) {
        let mut ok = std::mem::take(&mut self.ok);
        ok.clear();
        let refs: Vec<SigRef<'_>> = self.refs().collect();
        let checked = if batch && refs.len() >= secp::MIN_BATCH {
            if v.verify_batch(&refs, &mut ok) {
                Checked::Batch
            } else {
                Checked::BatchFailed
            }
        } else {
            ok.extend(refs.iter().map(|r| v.verify_one(r)));
            Checked::OneByOne
        };
        drop(refs);
        self.ok = ok;
        self.checked = checked;
        self.head = checked == Checked::Batch;
    }
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
        // An idle pool gets one verifier; a busy one another, only once a full
        // batch is waiting beyond what the working ones will take.
        if q.busy == 0 || (q.sigs >= MAX_BATCH && q.busy < self.inner.threads) {
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
    let mut v = Verifier::default();
    let mut taken: Vec<(Job, oneshot::Sender<Job>)> = Vec::new();
    let mut ok = Vec::new();
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
            if q.sigs >= MAX_BATCH && q.busy < inner.threads {
                inner.ready.notify_one();
            }
        }
        check(&mut v, &mut taken, &mut ok);
        for (job, tx) in taken.drain(..) {
            // A connection that went away no longer wants its verdicts.
            let _ = tx.send(job);
        }
        inner.q.lock().unwrap().busy -= 1;
    }
}

/// Checks every signature in `jobs` as one batch and hands each job its verdicts.
fn check(v: &mut Verifier, jobs: &mut [(Job, oneshot::Sender<Job>)], ok: &mut Vec<bool>) {
    if let [(job, _)] = jobs {
        return job.verify(v, true);
    }
    let refs: Vec<SigRef<'_>> = jobs.iter().flat_map(|(j, _)| j.refs()).collect();
    let passed = refs.len() >= secp::MIN_BATCH && v.verify_batch(&refs, ok);
    if refs.len() < secp::MIN_BATCH {
        ok.clear();
        ok.extend(refs.iter().map(|r| v.verify_one(r)));
    }
    drop(refs);
    let mut at = 0;
    for (i, (job, _)) in jobs.iter_mut().enumerate() {
        job.head = passed && i == 0;
        let n = job.len();
        job.ok.clear();
        job.ok.extend_from_slice(&ok[at..at + n]);
        at += n;
        job.checked = if passed {
            Checked::Batch
        } else if job.ok.contains(&false) {
            Checked::BatchFailed
        } else {
            Checked::OneByOne
        };
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
        let mut rxs = Vec::new();
        let mut want = Vec::new();
        for (i, chunk) in good.chunks(5).enumerate() {
            let mut job = Job::default();
            let mut w = Vec::new();
            for (k, r) in chunk.iter().enumerate() {
                // Job 3 carries a bad signature in its second place.
                let r = if i == 3 && k == 1 { &bad } else { r };
                job.push(r, 1);
                w.push(!(i == 3 && k == 1));
            }
            rxs.push(pool.submit(job));
            want.push(w);
        }
        for (i, rx) in rxs.into_iter().enumerate() {
            let job = rt.block_on(rx).unwrap();
            assert_eq!(job.ok, want[i], "job {i}");
            if i == 3 {
                assert_eq!(job.checked, Checked::BatchFailed);
            } else {
                assert_ne!(job.checked, Checked::BatchFailed, "job {i}");
            }
        }
    }
}
