# Adversarial testing

The relay's adversarial suite: what it attacks, how to run it, what it found
and what it still does not cover. It lives in `adversarial/`, a cargo workspace
of its own (the store is built there with fault injection, which must never be
unified into a relay build), with one command line, `adv`.

## Short version

- **Five parts.** Fuzzing of every parser of untrusted input (21 targets, a
  stable mutational runner everywhere and libFuzzer on the box); hostile
  clients against the real relay binary while a canary checks its answers;
  crash torture of the store against a model of acknowledged writes, in four
  modes (plain SIGKILL, a disk that fills up, power cuts, both); damage to a
  store's files; and a soak that runs the hostile scenarios for hours.
- **26 findings** (the table below), 25 fixed here and one independently on
  master, each with a regression test that fails without its fix; what was found and left for a decision is under
  *Open*. The worst: acknowledged events lost or brought back after a crash
  or power cut, live events served as zeros or as another event, a reader
  panic (with `panic = "abort"`, the relay) after an interrupted operator
  removal, and memory held forever by clients that stop reading.
- **Hot-path changes** (each listed under *For review*): a seq and length
  check on every record read, a write-stall guard around client writes, a cap
  on a REQ's buffered answer, and dead flags written one batch later.
- **Open:** a flipped bit inside a record is still served (records are not
  checksummed on read), a damaged index block still aborts the relay on the
  query that reads it, expensive REQs run on the reactor threads (four
  clients pushed the canary's p99 to 672 ms on a 50k store), and NIP-77
  sessions hold about 90 bytes per item.

## Running it

Everything below runs from `adversarial/` on the stable toolchain unless it
says box.

| What | Command | Time |
|---|---|---|
| CI-sized run of every part | `scripts/ci.sh` | ~15 min on 8 cores |
| Store fault tests only | `cargo test -p relay-store` (repo root) | 30 s |
| Parser fuzzing | `target/release/adv fuzz --target all --secs 60` | per target |
| Crash torture, many seeds | `scripts/torture-many.sh FIRST COUNT ITERS PAR [--faults] [--power]` | ~5 min per 8 seeds x 400 |
| Damage | `target/release/adv corrupt --dir DIR --cases 400` | ~4 min |
| Hostile clients | `target/release/adv hostile --dir DIR` (needs `cargo build --release -p relay-server`) | ~3 min |
| Box: build | `scripts/box-push.sh` (Mac), then `scripts/box-build.sh` (box) | |
| Box: libFuzzer | `scripts/box-fuzz.sh SECS [PAR]` | SECS per target |
| Box: long torture | `scripts/box-torture.sh MODE FIRST COUNT ITERS [PAR]` | |
| Box: real full disk | `scripts/box-diskfull.sh` (a tmpfs, unmounted after) | 1 min |
| Box: soak | `scripts/box-soak.sh HOURS` | |

`adv help` lists every command and option. Useful switches for digging into a
failure: `ADV_TRACE=1` prints every torture child's lines and how each reopen
was matched; `ADV_KEEP_PREOPEN=1` keeps the last 8 stores as each crash left
them (`pre-open-N`); `adv torture-ops --seed EPOCH_SEED` prints an epoch's
operations; `adv torture-child` with `ADV_CHILD_STOP_AT=N` replays one child
by hand on a kept store; `adv open --dir D --shape S` opens a kept store and
lists unreadable live records.

The box rules the scripts follow: everything under `/root/bench/adv`, relays
on 127.0.0.1 only (on a free port the kernel picks), every heavy process on CPUs 0-5 at nice 10 with
4 cargo jobs and a memory ceiling, a nightly toolchain only in
`/root/bench/adv/rustup` (the box's own is never changed), a tmpfs mounted
only for the disk-full run and unmounted on exit.

## The parts

### 1. Parsers

`adv fuzz` runs each target on hand-made seeds, structure-aware generated
inputs and mutations (havoc, splicing, dictionary tokens), keeping inputs that
produce a new behaviour fingerprint (an error class, a branch) since a stable
build has no coverage feedback. Every input is held to:

- no panic (overflow checks and debug assertions on);
- a memory budget, measured by a counting global allocator (1 MiB plus 64
  bytes per input byte by default): a length field that makes a parser
  allocate a gigabyte fails even when the machine could afford it;
- a time budget (2 s, and a watchdog for hangs);
- round trips and differential checks where there is a reference: the JSON
  scanner against serde_json, event ids against a from-scratch NIP-01
  serialisation and sha256, signatures against secp256k1, negentropy
  against the reference `negentropy` crate (both directions, full sync),
  the inflater against miniz_oxide, deflate then inflate, permessage-deflate
  negotiation (the receiver can always read what the sender sends).

Targets: `json`, `canonical`, `event`, `filter`, `client_msg`, `varint`,
`hex`, `negentropy`, `negentropy_sync` (relay-proto); `http_request`,
`http_response`, `ws_decode` (every decoder state, fragmentation, control
frames), `inflate`, `deflate_roundtrip`, `pmd_negotiate` (relay-net);
`base64`, `der`, `pem`, `tls_json`, `url` (relay-tls); `config` (the TOML
settings, relay-server). A finding is saved with its input; `adv minimize`
shrinks it and `adv replay` reruns it.

On the box the same target functions run under libFuzzer with
AddressSanitizer (`adversarial/fuzz`, one binary per target, the counting
allocator installed in each), seeded from the stable runner's seeds and
dictionaries (`adv export-seeds`). Corpora persist in
`/root/bench/adv/fuzz/corpus`.

### 2. Hostile clients

`adv hostile` starts the real relay binary on a loopback port with a store
prefilled through its own `import`, trusting `X-Real-IP` so one machine can
play many clients. A canary (and, with `--load N`, N more checked clients)
keeps publishing, receiving live, fetching by id and counting throughout.
Scenarios: `garbage` (random and malformed messages), `subscriptions`
(limits, churn, duplicate ids), `filters` (at and past every limit, planner
product explosions, giant id lists, `since > until`, odd numbers, duplicate
keys, wrong types, deep nesting), `events` (bad signatures, invalid UTF-8,
hundreds of tags, floods), `frames` (oversized, fragmentation abuse, control
floods, compression bombs, bad close codes), `slowloris`, `expensive`
(planner-heavy REQs), `noread` (subscribers that never read), `bigreq` (huge
unread REQ answers), `neg` (NIP-77 sessions), `churn`. Each is judged on the
relay staying up, the canary's answers and p99 latency, peak and retained
memory (private memory, not mapped files), and descriptors.

`adv diskfull` (box: `scripts/box-diskfull.sh`) puts the relay's data on a
small tmpfs, fills it with a client until the relay refuses, and checks that
it keeps serving, takes writes again once space is freed (no restart), and
after a restart still has every event it acknowledged.

The soak (`scripts/box-soak.sh`) repeats every scenario for hours against one
relay with normal traffic beside it, writing a CSV line per run (memory,
descriptors, canary latency) to see drift.

### 3. Crash torture

`adv torture` runs a deterministic workload (batches of events of every kind
the store has rules for: replaceable, addressable, deletions by id and by
address, vanish requests, gift wraps, expirations, duplicates; operator
removals, admin deletes interleaved with client batches, sweeps, flushes,
compactions, log compactions and merges, checkpoints, restarts) in a child
process. The child acknowledges each operation on stdout once it is durable
and is killed with SIGKILL at a random moment or at one of 33 named crash
points (inside flushes, compactions, log compaction exchanges, cold merges,
checkpoints, kills, zeroing, its own recovery). Reader threads in the child
hold snapshots and check every answer meanwhile. After every kill the parent
reopens the store and checks it against a model of what was acknowledged:

- every acknowledged event present, byte for byte, at its seq;
- nothing deleted, replaced, vanished, expired or removed back, and the dead
  set exactly the model's;
- the operation in flight landed as some prefix of itself (an unacknowledged
  operator removal: any subset of its targets, and what came back then
  subject to the rules of everything stored since);
- every live record's frame on disk intact and not flagged dead (else the
  next log compaction drops it);
- queries, COUNT, the operator walk and NIP-77 sets equal brute force.

Modes:

- `--faults`: half the children run on a disk that fills up after a random
  number of bytes, stays full for a few operations, then has room again
  (injected in the store's write calls, `fault::fail_writes`). The child
  carries on after a failure, as the relay does, and says what the store
  then holds; the parent keeps one model per outcome the failure may have
  had and prunes them as acknowledgements come.
- `--power`: kills at crash points are power cuts: every page of the log and
  `locs` written since its file's last sync goes back to a random one of the
  states it went through (`RELAY_POWER_CUT`). SIGKILL alone keeps the page
  cache, so it cannot tell a missed sync from a made one.
- `torture-replay`: the workload in one process, checked after every few
  operations (deterministic; for bisecting).

`adv corrupt` builds stores with the same workload and damages one file of
each (a flipped bit, a zeroed run, a garbled page, a cut; weighted toward the
log and `locs`), then opens it in a fresh process and reads everything:
allowed are a refusal that names the damage, or opening without what the
damage destroyed; a panic, hang or wrong answer is a finding.

### 4. Concurrency

The torture child's readers run queries, COUNT, id lookups and NIP-77 sets on
held snapshots while the writer writes, flushes, compacts, exchanges log
segments and zeroes dead records, and check what must hold in any snapshot
(results match, ordered, live, unexpired, well-formed; COUNT agrees). Admin
deletes hold a snapshot across many kill chunks and client batches. Loom was
not used: the store's primitives (the shared dead set, version publication
and reclamation, sync epochs gating zeroing) use std atomics and locks
directly, and model-checking them would first need a `sync` facade in
relay-store that loom can replace.

## Findings

Severity: **high** loses or corrupts acknowledged data, serves wrong data, or
takes the relay down; **medium** wastes memory or availability under attack,
or needs an unusual failure; **low** is cosmetic or tool-only. Each fix has a
regression test that fails without it.

| # | Sev. | Area | What happened | Found by | Fix | Regression test |
|---|---|---|---|---|---|---|
| 1 | low | proto JSON | A skipped value could be a number with a leading zero (`01`, `-00`), which JSON forbids | fuzz, differential vs serde_json | `2b3736a` | `json` unit test `skipped_numbers_are_json_numbers` |
| 2 | high | store, crash | A deleted or replaced event came back as an all-zero record after a crash between its zeroing and the next checkpoint (repair re-decided it from the zeroed bytes) | crash torture | `4ca0b70` | `zeroed_records_stay_dead_after_a_crash_before_the_checkpoint`, `zeroed_replaced_records_do_not_win_their_slot_back_after_a_crash` |
| 3 | high | store, crash | An event replaced or deleted by a tail event that was itself removed before a crash came back; a removed kind-5 lost its tombstone | crash torture | `4ca0b70`, `d76f276` | `a_replaced_event_stays_dead_when_its_replacement_is_removed_before_a_crash`, `a_removed_deletion_still_blocks_a_republish_after_a_crash` |
| 4 | high | store, crash | A kill made during an interrupted log compaction was lost when open finished the exchange | crash torture | `4ca0b70` | `a_kill_during_an_interrupted_log_compaction_survives` |
| 5 | medium | store, crash | Two live copies of one event (operator removal, re-publish, crash) | crash torture | `4ca0b70` | `a_crash_never_leaves_two_live_copies_of_one_event` |
| 6 | medium | store, crash | Kills re-derived at open were lost by a second crash | crash torture | `4ca0b70` | `kills_re_derived_at_open_survive_the_next_crash` |
| 7 | high | store | A frame filling its log segment exactly put the next one past the segment's end: reading it panicked (relay abort), a restart lost it and the rest of the segment; reopening at a boundary panicked on the first append | crash torture (64 KiB segments) | `84830ce` | `a_frame_that_fills_its_segment_exactly`, `reopening_with_the_head_at_a_segment_boundary` |
| 8 | medium | store, crash | A kill during the store's very first open left an empty `meta`: the folder was refused from then on | crash torture | `6d6f872` | `a_crash_while_creating_the_store_does_not_brick_it` |
| 9 | medium | store | Removed rule-bearing records (a deleted kind 30078, say) kept their content on disk for up to five minutes (introduced by fix 3) | e2e tests | `d76f276` | e2e `deleted_content_leaves_the_disk_*` |
| 10 | medium | server | A subscriber that stops reading kept its connection and buffers forever (eight of them under a live flood: 18 MB each, 32 MB with deflate or TLS) | hostile `noread` | `e102e1a`, `5c59fcf` | e2e `a_subscriber_that_never_reads_is_dropped` |
| 11 | medium | server | A REQ's stored answer was encoded whole before any of it was sent: 7.7 MB pinned per unread REQ on a 20k-event store, unbounded in general | hostile `bigreq` | `caddcb0` | e2e `an_answer_past_the_outbound_limit_ends_in_closed` |
| 12 | high | server | Fix 10 at first swallowed the wakeup for live events queued during a write: slow subscribers got events late or not at all | e2e `large_live_events_reach_every_subscriber_intact` | `5c59fcf` | that test |
| 13 | high | store, disk full | A failed log write left its frames queued; the next batch wrote them out under the same seqs: after a restart one event's index entries pointed at another's record | torture `--faults` | `5ba78fd` | `a_failed_append_leaves_nothing_for_the_next_one_to_write`, `a_failed_append_into_a_new_segment_is_not_replayed` |
| 14 | high | store, disk full | A batch whose second kill could not be flagged failed after queueing its first kill for zeroing: a live event zeroed | torture `--faults` | `5ba78fd` | `a_kill_whose_flag_cannot_be_written_never_zeroes_a_live_record`, `a_kill_whose_flag_cannot_be_written_survives_a_crash` |
| 15 | high | store, disk full | A failed index compaction reset a flush in flight: the writer panicked (relay abort) after indexing keys twice | torture `--faults` | `5ba78fd` | `writer::tests::a_failed_compaction_leaves_a_flush_in_flight_alone` |
| 16 | low | store, disk full | Housekeeping after a published batch (zeroing, starting a flush) turned a durable, visible batch into a reported failure | torture `--faults` | `5ba78fd` | covered by the torture |
| 17 | high | store, crash | An operator removal interrupted by a crash brought older victims back live with dead-flagged frames; the next log compaction dropped their bytes and reading them panicked (relay abort). No disk fault needed | torture, frame check | `b4fc91f` | `an_interrupted_removal_leaves_no_live_event_with_a_dead_frame` |
| 18 | low | store | A dropped writer's background job raced a reopen in the same process (`store_query_reopen` failed about one run in five) | flaky test | master `f65584c` (the same fix, made independently) | `store_query_reopen` |
| 19 | high | store, disk full | A failed log compaction's cold files were reused by the next one without clearing: stale frames read back by merges, and a restart panicked on a garbage seq | torture `--faults` | `a64845a` | `a_failed_log_compaction_leaves_nothing_in_the_next_ones_segments` |
| 20 | high | store, power loss | Dead flags went to disk in the same unsynced stretch as their killer: a power cut keeping the flag and losing the killer killed an acknowledged event at the next replay (on an older frame, it set up fix 17's drop) | torture `--power` | `8a5a34e` | `a_dead_flag_never_reaches_the_disk_before_its_killer` |
| 21 | medium | store, power loss | A replacement deleted in its own batch, and a power cut keeping only its flag: the replaced event came back | torture `--power` | `0e1e757` | `a_replacement_deleted_in_its_own_batch_still_replaced` |
| 22 | high | store, crash | A batch storing a profile, deleting it, then storing an older one into the emptied slot: after a crash before its flags were down, repair killed the older (acknowledged) one too | torture, after fix 20 | `3a25ffb` | `an_event_stored_into_a_slot_its_deletion_emptied_survives_a_crash` |
| 23 | medium | store, damage | A damaged `locs` entry served another event under the first one's id; a zeroed or cut frame panicked readers and `repair` (relay abort) | `adv corrupt` | `91a2518` | `a_damaged_location_reads_as_missing_not_as_another_event`, `a_zeroed_frame_is_missing_not_a_panic` |
| 24 | medium | store, damage | `dead.bits` had no checksum (a flipped bit brought a deleted event back), and an unreadable one was taken as empty (every removal undone) | `adv corrupt` | `91a2518` | `a_damaged_dead_set_is_refused` |
| 25 | medium | store, damage | Damage that left `dead.bits` whole words long (a garbled page padding it to 4 KiB, a cut) passed for the older form without a checksum | `adv corrupt` | `be84800`, `7df2fad` | `a_damaged_dead_set_is_refused` |
| 26 | high | store, power loss | A batch spanning two log segments, torn in the first and whole in the second: the store refused to open, or replayed seqs whose frames were gone (live events that could not be read, seqs reused) | torture `--power`, after the rebase onto master | `4a6be22` | `a_batch_torn_across_two_segments_is_dropped_whole` |

Tests named without a crate are in `crates/relay-store` (`tests/store.rs`, or
`src/fault_tests.rs` for those that need the fault hooks); "e2e" ones in
`crates/relay-server/tests/e2e.rs`.

## Open: every finding's verdict (2026-10-21, night)

Each is fixed, mitigated, accepted with its reason, or not a defect.

- **A flipped bit inside a record is served**: fixed (5766a68). A record's
  frame CRC is checked the first time a process reads it (one bit per seq,
  `relay_store::verified`), a damaged one is skipped and counted
  (`store.damaged_reads` in /stats). A dead record (zeroed under its old
  checksum) is skipped without being reported. Cost on the box: read CPU
  +2-3% on a fresh store, where every read is a first read; once per record
  per process after.
- **A damaged index block aborts the relay**: fixed (5766a68, d865cb1).
  Opening checks every block of every listed segment (8 MB reads, threads
  side by side: a cold 1.46 GB index in 0.52-0.58 s, warm 0.27-0.30 s, against
  0.04-0.19 s before) and refuses a damaged one, naming the file and how to
  rebuild (`export`, which reads by seq without the index, then `import`).
  A damaged segment written after the last checkpoint is not listed: opening
  deletes it and replays the log, so it is harmless.
- **Expensive REQs run on the reactor threads**: fixed (5766a68). A REQ over
  256 index ranges or ~20 000 entries to read goes to the query workers; its
  subscription is held (live events buffered, sent after the stored ones and
  EOSE). The same attack: canary p99 672 ms -> 0.8 ms.
- **fsync errors are not fatal**: fixed. The first failed sync stops writes
  for the rest of the process (reads go on) with a critical warning on
  /stats, /metrics and the dashboard: on Linux a failed fsync may drop the
  pages it could not write, so a later successful sync proves nothing. A
  restart replays the log from what really reached the disk.
- **NIP-77 sessions** (memory): mitigated. Open sessions share a budget of
  12M items (about 1 GB at ~90 bytes each); a NEG-OPEN past it is refused
  with `rate-limited` and may retry. `neg_items_held` in /stats and /metrics.
  Vector's syncs hold a mailbox each, thousands of items.
- **Write cost per tag** (low): mitigated, not changed. 880 distinct `p` tags
  cost ~2.5 ms of writer time, and every tag must be indexed to be found.
  Per-IP event limits (1200 a minute) bound one client to ~5% of the writer,
  and Concord member lists legitimately carry many `p` tags, so a lower tag
  limit would break them.
- **A cut log segment undoes recent deletions** (damage, accepted). After a
  log segment is cut short in the middle, the log ends there and the store is
  what it was at that point: consistent, but a deletion recorded after the
  cut, whose target was not yet zeroed on disk, is undone with everything else
  after the cut. 24 of 600 damaged stores (all cut log segments; the rest of
  the 600: refused 205, loss 155, unharmed 216, panics 0, other wrong answers
  0). It needs a truncated log file, it reaches only deletions not yet zeroed,
  and refusing to open instead would mean downtime. A persistent "synced up
  to" marker would let recovery tell a torn tail from damage further back.
- **A flipped dead flag in a frame header is unseen** (damage, accepted for
  now). The header (length, flags, seq) is not covered by the CRC; length and
  seq damage is caught (`record_of` checks both, the record CRC catches a wrong
  length), the flag is not: on, log compaction drops a live record; off, a
  dead record not yet zeroed comes back. The fix (compaction trusting only the
  checksummed dead set, relink zeroing cold copies of records that died
  meanwhile) changes the crash-safe exchange, and is not for a night before a
  deploy.
- **Damage in the unflushed log tail truncates** (design, not a defect): a
  torn or out-of-sequence frame ends the log, because a power cut produces
  exactly that and nothing after it was acknowledged.
- **`panic = "abort"`** (mitigated): every panic the suite reached is fixed
  (index blocks were the last; 0 panics in 600 damaged stores), and the
  cut-over's systemd unit restarts the relay, which opens in under a second.
- Not run: loom on the store's primitives (see Concurrency), and a power
  model for the files written whole (segments, checkpoints: they are synced
  and renamed before use, which the crash torture exercises). Future work.

## For review (hot paths)

Each was kept to what the fix needs; measured effects are in the commit
messages.

- `crates/relay-server/src/reactor.rs`, `serve` (`e102e1a`, `5c59fcf`):
  every client write goes through `finish_write`, a biased `select!` of the
  write, an overflow watch and a stall timer (a write that completes at once
  polls nothing else; no timer is armed); after a write, a non-empty output
  buffer re-arms the notify.
- `crates/relay-server/src/session.rs`, REQ answers (`caddcb0`): one
  length compare per stored event sent.
- `crates/relay-store/src/writer.rs`, `append` (`5ba78fd`): keeps the head
  to roll back to; `log.rs` `append` checks one `Option` per frame.
- `writer.rs`, `publish_staged` (`5ba78fd`, `b4fc91f`, `8a5a34e`): kills of
  a batch with new frames are queued instead of flagged; `maintain` writes
  them once their batch is synced (one atomic load when nothing is queued)
  and checks an `Instant` for the idle sync. A removed record's bytes leave
  the disk one batch later than before.
- `log.rs` `append` at a segment boundary (`84830ce`): one modulo and
  compare, already computed.
- `version.rs`, every record read (`91a2518`): the frame's seq and length
  are compared from the header next to the record.
- Checkpoints checksum `dead.bits` (`91a2518`): one hardware CRC over it.

## Campaigns run

All on the Mac (Apple silicon, stable toolchain). The box campaigns
(libFuzzer, the real full disk, the long torture and the soak) are scripted
but were not run: the box was taken by benchmarks for the rest of the
session. They are the next thing to run (`scripts/box-*.sh`).

- **Crash torture**, one iteration = one child killed (or cut) and the store
  reopened and fully checked:
  - on the code rebased onto master: seeds 600-623 x 400 iterations in each
    of the four modes. The first run found finding 26 (three seeds, power
    and faults+power); after its fix the rerun (38,400 iterations) passed
    with no failure;
  - on the final code before the rebase: seeds 400-415 and 500-523 x 400
    iterations in each of the four modes (64,000 iterations), no failure;
  - while finding and fixing: about 200 seeds x 400 iterations plain, and
    some 150 seed runs with faults or power cuts.
- **Damage**: 1,200 damaged stores on the final code before the rebase and
  1,000 after it (the first 500 found finding 25's cut `dead.bits`). Of the
  last 500, on the final code: refused 88 (every damaged checkpoint,
  `meta` and `dead.bits`, and a quarter of the damaged index segments),
  loss 98, unharmed 126; panics 61, all from damaged index blocks; wrong
  answers 127, all from damaged bytes inside log records (open findings)
  but one: a cut `locs` left seq 0 reading a stale copy at offset 0, where
  every zeroed location entry points.
- **Parser fuzzing** (stable runner), runs per target: base64 137M, tls_json
  64M, json 58M, pmd_negotiate 58M, canonical 50M, pem 40M, http_response
  23M, config 11M, inflate 4.7M, event 4.1M, ws_decode 4.1M, client_msg
  3.1M, http_request 2.7M, filter 2.5M, der 1.7M, url 0.4M, varint 0.2M,
  negentropy 0.56M, negentropy_sync 67k (each a full reconciliation against
  the reference), deflate_roundtrip 32k, hex 38k. No finding but the one
  JSON fix (and one bug in the harness's own config target).
- **Hostile clients**: every scenario on stores of 5k, 20k and 50k events,
  with 2-3 checked clients beside the canary; the 50k run is where the
  expensive-REQ and NIP-77 numbers under *Open* come from.
- `scripts/ci.sh` passes end to end (about 15 minutes).
