# Signature and id verification on the production CPU

Measured 2026-10-21 on the jskitty box (Intel i7-6700, Skylake, 4 cores / 8
threads, AVX2 + BMI2, no SHA extensions, Ubuntu 24.04, Rust 1.98), beside the
live services, which were never touched. Builds and runs were capped to CPUs 0-5
at nice 10; single-thread measurements are pinned to CPU 0. The box is never
idle (production blockbook uses one to three and a half cores, nginx and strfry
some more), so every comparison below is made inside one process, alternating
the methods round by round and keeping the best of each, or alternating whole
runs; absolute numbers drift by up to ~10% between hours, ratios much less.
Runs taken while another benchmark shared the cores (12:30-14:00) were
re-taken; the numbers here are from before or after that window.

The tool is `crates/relay-proto/examples/sigbench.rs` (modes `steps`, `sha`,
`batch`, `tune`, `ingest`, `diff`, described at its top). Data: 100k events each
from `/root/relay-test/all.jsonl` (the real 4.8M-event export): `recent` (the
last 100k lines, today's traffic) and `sample` (every 48th line, the whole
history).

## Summary

| per core, JSON to accepted record | before | after | |
|---|---|---|---|
| bulk (import, sync, admin ingest), recent traffic | 20.2k ev/s (49.5 µs) | **73.2k ev/s** (13.7 µs) | **3.6x** |
| bulk, whole-history sample | 19.5k ev/s (51.2 µs) | 63.8k ev/s (15.7 µs) | 3.3x |
| reactor, one EVENT per read (the common case) | 20.2k ev/s | 22.9k ev/s (43.6 µs) | 1.13x |
| reactor, a read bringing 16 EVENTs | 20.2k ev/s | 40.5k ev/s (24.7 µs) | 2.0x |
| reactor, 64 EVENTs in a read | 20.2k ev/s | 51.0k ev/s | 2.5x |

Import end to end, 962k real lines (every fifth line of the export), the
binary from master against this branch, same flags:

| CPUs | master (bfd9166) | this branch | | CPU time per line |
|---|---|---|---|---|
| 1 | 14.9k / 14.7k lines/s | **27.8k / 27.8k** | **1.88x** | 72 → 39 µs |
| 2 | 27.3k / 23.2k | 42.5k / 43.2k | 1.6-1.9x | 78-91 → 40 µs |
| 4 | 33.2k / 46.0k | 37.0k / 35.1k | (writer-bound) | 75-103 → 53 µs |

Two alternating runs each, `relay import` with default settings (fsync per
batch). On one or two cores verification was the limit and the import now runs
1.9x faster; on four cores both builds stop at the single writer thread and the
disk (35-46k lines/s, varying with the box's IO load), and this branch gets
there on half the CPU.

Every verdict is unchanged: on the whole 4.8M-line export, with and without
deliberately corrupted lines, bulk and one-at-a-time verification agree on every
verdict and every stored record; 5.1M random signatures (19.9k invalid of every
kind) get libsecp256k1's verdict; BIP-340's test vectors pass alone and in every
pairing. See [Correctness](#correctness).

## Where the time went

`sigbench steps` on `recent`, one event at a time exactly as the relay did it
(sha2 crate, libsecp256k1's `XOnlyPublicKey::from_byte_array` and
`schnorr::verify`), ns per event:

| line size | events | parse | preimage | SHA-256 | lift_x | verify | total |
|---|---|---|---|---|---|---|---|
| <1 KB | 4 671 | 1 152 | 188 | 1 522 | 4 600 | 40 962 | 48 424 |
| 1-2 KB | 20 204 | 919 | 130 | 6 371 | 4 477 | 39 634 | 51 532 |
| 2-4 KB | 72 262 | 980 | 139 | 9 114 | 4 601 | 40 847 | 55 682 |
| 4-16 KB | 2 653 | 1 746 | 301 | 28 082 | 4 640 | 40 815 | 75 585 |
| >=16 KB | 210 | 7 182 | 1 710 | 141 671 | 4 747 | 41 630 | 196 939 |
| all | 100 000 | 1 009 | 147 | 8 987 | 4 577 | 40 608 | 55 329 |

The signature is 82% of an event (pubkey parse 8%, verify 73%) and the id hash
16%; parsing and the preimage are 2%. The whole-history sample is the same
shape (all: parse 1.1 µs, SHA-256 10.9, lift_x 4.7, verify 40.8).

What the traffic looks like (`recent` / `sample`): 93% / 90% kind 1059 gift
wraps; lines mostly 2-4 KB (mean 2.3 / 2.8 KB). Authors repeat far more than
"gift wraps use one-off keys" suggests: Concord plane keys and a few bots sign
most wraps, so a 2048-entry pubkey cache hits for **81% / 66%** of events, and
a batch of 2048 consecutive events has only **0.22 / 0.36 distinct keys per
event** (0.30 / 0.42 in batches of 64).

## Experiments

### Build flags: dropped

libsecp256k1 is compiled by secp256k1-sys with `cc` at `-O3`. It honours
`CFLAGS`. On this Ubuntu gcc its first attempt fails (the crate's
`-Dprintf(...)=` clashes with glibc's fortified `stdio2.h`) and it silently
retries against its own wasm stub headers; the library works the same either
way, `-U_FORTIFY_SOURCE` would avoid the detour. Field asm no longer exists
upstream; `USE_ASM_X86_64` only switches the scalar code. Measured (30k
events, µs, before the contended window):

| | lift_x | verify |
|---|---|---|
| default | 4.23 | 36.45 |
| `CFLAGS=-march=native` | 4.82 (+14%) | 35.21 (-3.4%) |
| `-DUSE_ASM_X86_64=1` | 4.18 | 36.01 (-1.2%) |
| both | 4.78 | 34.94 (-4%) |
| `RUSTFLAGS=-C target-cpu=native` (our code) | parse 0.86 vs 0.92 µs | |

At best 2% net, inside the noise of a second round, and a box-only build
setting to keep alive: not taken.

### Batch verification: kept

`relay_proto::secp`. One verification is a double-scalar multiplication whose
128 doublings every signature pays again. A batch checks the BIP-340 equation
for all at once:

```
(sum a_i s_i) G  -  sum a_i R_i  -  sum (a_i e_i) P_i  ==  infinity
```

with a_1 = 1 and the other weights 128-bit values from a CSPRNG (SHA-256 of a
per-verifier key read from the OS, `getrandom`/`getentropy`, and a counter). If
any signature is bad the equation holds only when the weights cancel its error,
probability at most 2^-128 for weights the signer cannot predict: the work of
breaking a secp256k1 key. A failed batch is retried in eighths (at least 64
each), and any part that fails again is checked one signature at a time by
libsecp256k1, so every rejection is libsecp256k1's own verdict; only the
acceptance of a whole batch rests on our arithmetic (with the 2^-128 above).

**In-house or not.** libsecp256k1 has no batch API. Its internal multi-scalar
code (`bench_ecmult`, compiled from the vendored sources on the box) costs
8.2 µs per full-width point at 1023 points (13.7 at 63, 10.3 at 255, 7.3 at
2047); a batch through it would pay two full-width points per signature,
~16 µs, before R's square root, and would mean compiling a second copy of the
library from secp256k1-sys's vendored internals. Our own code can do what that
API cannot: a 128-bit weight needs no GLV split, so each R is one half-width
term, and signatures by one key share one P term. On real traffic that is ~1.4
half-width terms per signature instead of 4. The pieces follow libsecp256k1's
representations and formulas (5x52 field with magnitudes, 4x64 scalars, its GLV
constants and group formulas), which is also what makes them testable against
it, and they run at its speed:

| | ours (Rust) | libsecp256k1 (C, gcc -O3) |
|---|---|---|
| field mul / sqr | 18.0 / 14.4 ns | 17.1 / 15.0 ns |
| point double / mixed add / full add | 126 / 211 / 312 ns | 120 / 208 / 281 ns |
| lift_x (a square root) | 4.11 µs | 4.27 µs |
| field inverse | 3.9 µs (exponentiation; one per batch) | 1.24 µs (safegcd) |

**Multi-scalar method** (`sigbench tune`, ns per 128-bit term, a clean run
before the contended window):

| terms | Strauss w4 | w5 | Pippenger c=4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 |
|---|---|---|---|---|---|---|---|---|---|---|
| 8 | **10 366** | 11 077 | 17 223 | 21 119 | | | | | | |
| 32 | **8 328** | 9 124 | 9 493 | 10 105 | 11 996 | 16 123 | | | | |
| 64 | 8 177 | 8 903 | 8 058 | **7 966** | 8 511 | 10 626 | 14 359 | | | |
| 128 | 8 079 | 8 784 | 7 393 | 6 573 | **6 575** | 7 350 | 9 452 | 12 775 | | |
| 256 | 7 959 | 8 768 | 6 885 | 5 922 | **5 582** | 5 654 | 6 489 | 8 201 | 11 423 | |
| 512 | 8 001 | 8 849 | 6 732 | 5 647 | 5 096 | **4 810** | 5 020 | 5 769 | 7 268 | 10 188 |
| 1024 | 8 082 | 8 823 | 6 638 | 5 477 | 4 802 | 4 399 | **4 250** | 4 489 | 5 108 | 6 650 |
| 2048 | 8 107 | 8 909 | 6 534 | 5 418 | 4 697 | 4 188 | 3 900 | **3 836** | 3 990 | 4 704 |
| 4096 | 8 164 | 9 153 | 6 504 | 5 369 | 4 669 | 4 091 | 3 682 | 3 501 | **3 397** | 3 685 |
| 8192 | 8 327 | 9 753 | 6 495 | 5 353 | 4 608 | 4 018 | 3 607 | 3 330 | **3 095** | 3 125 |

Strauss with width-4 tables below 64 terms, then Pippenger with c from 5 to 10
(`msm::window_for`).

**Per signature** (`sigbench batch`, all 100k signatures valid, against
libsecp256k1 one at a time with the pubkey parse, 39.8 µs on `recent`):

| batch | 2 | 4 | 8 | 16 | 32 | 64 | 128 | 256 | 512 | 1024 | 2048 | 4096 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| µs/sig, recent | | | | | 19.6 | 16.9 | 14.8 | 13.2 | 12.1 | 11.2 | **10.6** | 10.0 |
| µs/sig, sample | 42.3 | 31.8 | 26.3 | 23.4 | 20.8 | 18.3 | 16.3 | 14.7 | 13.6 | 12.7 | 11.9 | 11.3 |
| speedup | 1.04x | 1.38x | 1.68x | 1.89x | 2.04x | 2.35x | 2.70x | 3.01x | 3.29x | 3.56x | **3.77x** | 4.00x |

The speedup row is against the same run's one-at-a-time figure: the sample run
(44.1 µs) up to 16, the recent run (39.8 µs) from 32; the recent run's small
sizes were hit by a burst of production load and are left out. Batches below 3
signatures go one at a time (`secp::MIN_BATCH`). At 2048 the remaining cost
per signature is about 4.1 µs for R's square root, 5 µs of multi-scalar work
(1.43 half-width terms at ~3.6 µs), 0.8 µs of key square roots on cache misses
and ~0.5 µs of bookkeeping.

### Pubkey cache: kept

`secp::keys::KeyCache`, 1024 sets of two (2048 keys), per thread, salted. It
keeps our lifted point for batches and libsecp256k1's own parse for one-at-a-
time verification, so that path stays entirely libsecp256k1's. Simulated hit
rates on the real traffic: 78% (256 entries, direct-mapped) to 82% (16k) on
`recent`, 63-66% on `sample`; 2048 two-way gets 81% / 66%. One at a time:
39.8 → 36.4 µs (1.09x).

### Merging signatures by key: kept

Inside a batch the P terms of one key add up to one (`KeyTerm::acc`), before the
GLV split. With 0.22 distinct keys per event at 2048, that halves the
multi-scalar work; together with the cache it took a batch of 2048 from 20.1 to
10.9 µs per signature, 64 from 27.1 to 17.5.

### Interleaved square roots: dropped

The idea: square roots are long chains of dependent squarings; stepping 2-4
independent chains together might fill the multiplier. Measured 1 lane
3.86 µs, 2 lanes 3.82, 4 lanes 3.94 per root: no gain. Skylake's 64x64-bit
multiplies and the 128-bit shifts all issue on port 1, which a single chain
already keeps busy.

### Affine buckets in Pippenger: not taken (yet)

Additions into different buckets are independent, so a round of them can share
one inversion and run as affine additions (~6 multiplications instead of a
mixed addition's 11). Built and differentially tested (commit-local, not on
this branch), then measured as an interleaved A/B on the box, ns per term,
best of five alternating rounds (the second, quieter of two runs):

| terms | Jacobian c=9 | c=10 | affine c=9 | c=10 | c=11 |
|---|---|---|---|---|---|
| 1024 | **4 543** | 5 162 | 6 015 | 4 751 | 6 131 |
| 2048 | 3 869 | 3 999 | 6 070 | **3 636** | 4 208 |
| 3072 | 3 605 | 3 579 | 6 416 | **3 218** | 3 557 |
| 4096 | 3 531 | 3 404 | 6 987 | **3 036** | 3 264 |
| 8192 | 3 341 | 3 092 | 9 438 | **2 754** | 2 842 |

A real win from about 2048 terms: 6% there, ~11% from 3072 up. An import chunk
of 2048 events is ~2 900 terms, so it would save ~10% of the multi-scalar work,
~0.5 µs of 10.6 per signature, ~3% of the bulk path, and nothing on the
reactor's small batches. Small windows lose because our inversion is an
exponentiation (3.9 µs), which a round has to amortise. Left out of this round
for its complexity against that gain; worth taking together with a safegcd
inversion, which would also widen where it pays.

### SHA-256, eight messages at a time: kept

`relay_proto::sha256::digest_many`. Eight preimages in the eight 32-bit lanes of
AVX2, a lane taking the next message as its own finishes, stragglers finished
on scalar code (`sigbench sha`, 100k real preimages, mean 2 091 bytes):

| | ns/event | ns/byte | |
|---|---|---|---|
| sha2 crate (asm), one at a time | 8 322 | 3.98 | 1.00x |
| ours, one at a time | 6 382 | 3.05 | 1.30x |
| ours, groups of 8 | 2 619 | 1.25 | 3.18x |
| groups of 64 | 2 183 | 1.04 | 3.81x |
| groups of 2048 | 2 002 | 0.96 | **4.16x** |

The same lanes, started from a midstate, hash the batch verifier's BIP-340
challenges (64-byte tag prefix + 96 bytes): 613 → 119 ns per signature; the
weights come out of lanes too: 137 → 34 ns.

### SHA-256, one message: kept

For the reactor, where an EVENT is hashed alone. Alternatives, each against
ring (OpenSSL's AVX2/BMI2 code) in the same process on 100k real event lines
(two runs each): the sha2 crate's assembly 1.62-1.68x slower than ring, its
pure-Rust code 1.83-1.88x slower, that with `-C target-cpu=native` 1.46-1.48x.
Ours follows OpenSSL's approach (message schedule four words at a time in
vector registers, rounds in scalar registers with BMI2's `rorx`, Maj from the
previous round's a^b): 1.30x faster than the sha2 crate's assembly, so ring is
still ~1.25x faster than ours; OpenSSL also schedules two blocks at once in
256-bit registers, which ours does not. ring is now in the workspace (for TLS)
but by PLAN.md runs only in `relay-tls`; using its SHA-256 here would save
another ~1.3 µs per event on the reactor (3%).

### Other costs

Parsing (1.0 µs) and the preimage (0.15 µs) are 2% of an event; nothing there
was worth changing. The bulk path's bookkeeping per signature, measured: key
map 0.09 µs, scalar multiplication 0.04 µs, GLV split 0.11 µs per key.

## After

`sigbench ingest`, per core, JSON to accepted record, rounds alternating
between the methods (best of three), two runs each:

| | recent | | sample | |
|---|---|---|---|---|
| before: sha2 + libsecp256k1, one at a time | 49 334 ns | 20.3k/s | 51 091 ns | 19.6k/s |
| `parse_event_json`, one at a time (our SHA-256) | 47 401 | 1.04x | 48 195 | 1.06x |
| reactor: id check, cached libsecp256k1 | 43 380 | 1.14x | 45 487 | 1.12x |
| bulk, chunks of 16 | 24 602 | 2.01x | 27 320 | 1.87x |
| bulk, chunks of 64 | 19 580 | 2.53x | 21 642 | 2.36x |
| bulk, chunks of 256 | 15 818 | 3.12x | 17 916 | 2.85x |
| bulk, chunks of 2048 | **13 644** | **3.62x** | **15 617** | **3.27x** |

### Import

Pinned with `systemd-run -p AllowedCPUs=...`, so `import` starts one parser
thread per allowed CPU beside its reader and writer; every fifth line of the
export (962 001 lines, 2.68 GB), a fresh data directory each run, fsync per
batch as by default. Wall-clock rate as `import` reports it (ingest phase,
before the final compaction), CPU time from the shell's rusage for the whole
process, compaction included:

| CPUs | build | run 1 | run 2 | CPU (user + sys) |
|---|---|---|---|---|
| 1 | master | 14 892 lines/s | 14 685 | 68.9 s / 69.8 s |
| 1 | branch | 27 772 | 27 825 | 37.9 s / 37.3 s |
| 2 | master | 27 262 | 23 210 | 74.8 s / 87.1 s |
| 2 | branch | 42 506 | 43 166 | 39.2 s / 38.9 s |
| 4 | master | 33 200 | 45 959 | 98.8 s / 72.4 s |
| 4 | branch | 36 970 | 35 066 | 51.0 s / 51.8 s |

An earlier run of the same comparison (pre-rebase builds against their own
base, 14:03-14:13) agrees: 1 CPU 14.4k → 25.9-27.5k, 2 CPUs 23.0-27.4k →
29.8-35.7k, 4 CPUs 31.7-34.3k → 37.4-45.7k. A thread profile of a 4-CPU import
shows the four parser threads ~17% busy each and the writer ~60%, the rest of
its time waiting on IO: the next import limit is the writer (log append, index
keys, sync), not verification.

## Where it is used

- **Import** (`relay import`): each worker hands its chunk of 2048 lines to an
  `event::BulkVerifier`.
- **Sync and admin ingest** (`inbound::check_all`): each thread runs every
  check up to the signature for its share, then verifies the share's
  signatures as one batch.
- **Reactor**: an EVENT that passes every check but the signature is queued
  (`session::SigQueue`); when the frames of the current read are done, or
  before any frame that is not an EVENT, or at 16 queued, the queue is
  verified as a batch (3 or more) or one by one, and each event is finished in
  arrival order: refusals, ephemeral relaying and writer hand-off happen
  exactly as before, in the same order relative to other messages. Nothing
  ever waits for more input. A connection whose batch fails once is checked
  one by one from then on, so mixing bad signatures into bursts cannot make
  the relay pay twice. `/stats` and `/metrics` count `sigs_batched` and
  `sig_batches_failed`.
- One-at-a-time paths (`parse_event_json`, `confirm_id`) use the faster
  single-message SHA-256.

## Correctness

- `crates/relay-proto/tests/secp.rs`: field operations against `num-bigint`
  (also at the maximum magnitude mul and sqr accept), scalars and the GLV split
  against big integers, `lift_x` against libsecp256k1 (random and edge x,
  values at and above p), point addition, doubling, negation and the
  endomorphism against libsecp256k1, multi-scalar sums of up to 400 terms
  (repeats, opposites, zero and 2^128-1 scalars, exact cancellation) for
  Strauss at w = 4, 5, 6 and Pippenger at c = 2..10 against libsecp256k1,
  BIP-340's test vectors 0-14 (from libsecp256k1's own tests) alone and paired
  with every valid vector in both orders, and random batches of 1-300
  signatures with every kind of corruption (bit flips in r, s, message or
  key, r >= p, s >= n, s + n, negated s, random key, random r) compared with
  libsecp256k1's verdict per signature. `SECP_DIFF_SCALE=10` on the box in
  release: 200k field and scalar rounds, 600 multi-scalar rounds, and
  **5 130 499 random signatures, 19 859 invalid, every verdict identical**.
- `tests/sha256.rs`: every length up to 200 bytes, mixed batches up to 20 KB
  messages, midstates, one message at every length to 300 and beyond 64 KB,
  against the sha2 crate (AVX2 paths on the box).
- `tests/bulk.rs`: `BulkVerifier` against `parse_event_json` line by line, in
  chunks of 1 to 400, over valid events, bad ids, bad signatures, the raw-form
  fallback, legal re-escaping, unparseable keys, malformed JSON, trailing
  bytes after valid and invalid events, and duplicates.
- `sigbench diff` on the whole export (4 810 009 lines) on the box: clean,
  with one line in 5000 corrupted, and one in 50 corrupted five ways (a
  signature digit, s >= n, r off the curve, another key under a recomputed id,
  changed content): every verdict and every record identical to
  `parse_event_json`.
- `crates/relay-server/src/inbound.rs`: `check_all` against the one-at-a-time
  check over valid events, bad signatures, bad ids, refusals and a duplicate,
  on one and three threads.
- `crates/relay-server/tests/e2e.rs` `bursts_of_events_are_verified_together`:
  42 EVENTs and a REQ in one write, three rounds, two with bad signatures
  mixed in: one OK per event with the right verdict and message, refusals
  before the REQ's EOSE, the ephemeral event delivered, exactly the good
  events stored, and `/stats` showing the batch path taken and the fallback
  used. All existing tests pass (workspace, Mac and box).

## APIs

- `relay_proto::secp::Verifier` (one per thread): `verify_one`
  (libsecp256k1, cached key parse), `verify_batch` (verdict per signature),
  `verify_all` (one yes/no); `SigRef`, `MIN_BATCH`, and the free
  `verify_one` (uncached reference). Modules `field`, `scalar`, `group`, `msm`,
  `keys`, `rng` are public for the tests and sigbench.
- `relay_proto::sha256`: `digest`, `digest_many`, `digest_many_after`,
  `Midstate`.
- `relay_proto::event::BulkVerifier`: `verify(&[&str])`, `results()`,
  `record(i)`. `compute_id` now uses `sha256::digest`.
- Server: `session::SigQueue` in the reactor, `Session::flush_events`; the
  metrics `sigs_batched` and `sig_batches_failed`.
- Dependencies: relay-proto now uses `libc` (for `getrandom`/`getentropy`) and
  sha2's `compress` feature; `num-bigint` is a dev-dependency.

## Open points

- **The in-house line.** While this was being built, master's PLAN.md gained
  "TLS and cryptography are the one thing never written in-house". This branch
  writes secp256k1 field, scalar and group arithmetic and SHA-256 itself. Their
  scope: verification of public data only (no secret ever touches them, so
  nothing needs to be constant-time); every rejection is still libsecp256k1's
  verdict, single events on the reactor are still verified by libsecp256k1, and
  only the acceptance of a whole batch rests on our multi-scalar code (with the
  2^-128 bound), all differentially tested against libsecp256k1 and big-integer
  arithmetic. If the line stands as written, the options and their price: drop
  batching (bulk falls from 3.6x to about 1.3x: lanes for the id hash and the key
  cache stay); or batch through libsecp256k1's own internal multi-scalar code
  via a C shim compiled from secp256k1-sys's vendored sources (about 16 µs per
  signature against 10.6, and a second build of the library to maintain); and
  ring's SHA-256 for single messages instead of ours (faster, see above, but
  ring outside `relay-tls`). PLAN.md's Hashing bullet is out of date either way.
- **Import** is now limited by its single writer thread and the disk, not by
  verification.
- **Affine buckets with a safegcd inversion**: ~0.5 µs per signature in bulk.
- **libsecp256k1's build** on Ubuntu goes through its wasm stub headers (see
  Build flags); harmless, and `-U_FORTIFY_SOURCE` in `CFLAGS` would avoid it.

## Reproduce

```sh
bench/box/push-ours-src.sh            # or: git archive HEAD | ssh jskitty 'tar -x -C <dir>'
cargo build --release -p relay-proto --example sigbench
sigbench steps|sha|batch|tune|ingest <events.jsonl>
sigbench diff /root/relay-test/all.jsonl 4 50
SECP_DIFF_SCALE=10 cargo test --release -p relay-proto --test secp -- --include-ignored
```
