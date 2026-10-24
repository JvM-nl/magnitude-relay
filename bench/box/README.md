# Benchmark box setup

Four relays, built and configured identically-fairly on the production host `ssh jskitty`
(i7-6700, 4C/8T, Ubuntu 24.04), everything under `/root/bench/`, nothing running when idle.
Set up 2026-10-21.

| relay | port | version | binary | data dir |
|---|---|---|---|---|
| fastr | 7801 | `9341e53` (Raise filter limits so ngit fetches fit) | `/root/bench/bin/fastr` | `/root/bench/fastr-data` |
| ditto-relay | 7802 | `da4ec6c`, v2.5.0 | `/root/bench/bin/ditto-relay` | `/root/bench/ditto-data` |
| strfry | 7803 | 1.1.2-148-g4cd3cf6 (the production binary, read-only) | `/root/strfry/strfry` | `/root/bench/strfry-db` |
| ours | 7804 | `da8b2f1` (`git archive` of the committed tree; uncommitted work is not included) | `/root/bench/bin/magnitude-relay` | `/root/bench/ours-data` |

All bind 127.0.0.1 only, inside 7801-7809 (`start.sh` checks every listener the process owns
and stops it if there is another).

## Use

```sh
# on the Mac
bench/box/push.sh                       # scripts -> /root/bench/box, configs -> /root/bench
bench/box/push-ours-src.sh [rev]        # ship a COMMITTED snapshot of this repo, then:
ssh jskitty /root/bench/box/build-cargo.sh ours

# on the box (/root/bench/box)
./start.sh <ours|strfry|fastr|ditto>    # capped, pinned, niced, nohup, waits for the port
./stop.sh  <name|all>                   # by pid file, verifies gone; `all` also sweeps strays
./wipe.sh  <name>                       # deletes that relay's data dir only (must be stopped)
python3 -I ./smoke.py <port>            # publish + read-back + NEG-OPEN smoke test
```

`env.sh` holds ports, paths and pinning, and `assert_in_bench`, which every script runs on
every path it writes, deletes or signals (refuses anything not strictly inside `/root/bench`,
`..` or symlinks included). The only thing used from outside is the production strfry
*binary*, executed with our own config. `stop.sh` identifies processes by
`/proc/PID/exe` (and strfry's `--config=/root/bench/strfry-bench.conf`), never by name, so the
production strfry (same binary, different config) cannot be matched.

## CPU topology and pinning

`lscpu -e`: 4 cores x 2 threads. Hyperthread siblings are **(0,4) (1,5) (2,6) (3,7)**.

Default (the proposal, kept): relay under test `AllowedCPUs=0-3`, load generator CPUs 4-5,
production's CPUs 6-7 left alone, everything at `nice 10`, nothing of ours outside CPUs 0-5.
`cgroup v2 cpuset` works (`systemd-run --scope -p AllowedCPUs=...` verified; the process sees
`Cpus_allowed_list` and `available_parallelism()` honour it: ours started 4 reactors, ditto
sizes its semaphores from it).

Caveat to know about: 0-3 gives the relay four *physical* cores, but its CPUs 0 and 1 are siblings
of the load generator's 4 and 5, and 2 and 3 are siblings of production's 6 and 7. Every relay
core has a busy neighbour thread, equally for all four relays, so comparisons stay fair but
absolute numbers are lower than a quiet box. If you want the relay isolated from the load
generator at the core level, use `RELAY_CPUS=0,1,4,5 LOADGEN_CPUS=2,3 ./start.sh <name>`
(relay owns two whole cores, loadgen shares with production's 6-7 instead); the cost is a
2-core relay. Also: production's own processes are not pinned and float over all eight CPUs
(baseline 10-30% busy per CPU, blockbook ~1 core), and the governor is `powersave` (intel_pstate,
turbo on), so warm up and record `/proc/stat` around each run.

Run the load generator with
`systemd-run --scope --quiet -p AllowedCPUs=4-5 nice -n 10 <cmd>`.

## Builds (exact commands)

All builds ran as `systemd-run --scope --quiet -p AllowedCPUs=0-5 nice -n 10 ...`, one at a time.

* **fastr**: `build-fastr.sh`, 29 s. Needs Odin `dev-2026-09` (`dev-2026-09-nightly:a2fb372`, the
  version `tests/bench/Dockerfile` and `docs/BENCHMARKS.md` use; CI/Dockerfile pin the older
  `dev-2026-05`) in `/root/bench/tools/odin`. The box has no `cmake` and no `clang`, and we do not
  apt-install on production, so: libsecp256k1 v0.7.0 (`a660a49`) is compiled by hand with gcc
  13.3 using the flags the project's CMake would (schnorrsig+extrakeys, `ECMULT_WINDOW_SIZE=15`,
  `COMB_BLOCKS=43 COMB_TEETH=6`, `USE_ASM_X86_64`, `-std=c90 -O2`), and Odin's link step calls
  `clang`, so `/root/bench/tools/bin/clang` is `#!/bin/sh` + `exec gcc "$@"`. Then
  `odin build cmd/fastr -out:fastr -o:speed` (= `just build`). Links the system libssl for
  `wss://` sync peers (unused).
* **ditto-relay**: `build-cargo.sh ditto`, 8 m 54 s (single-threaded fat-LTO tail), rustc 1.98.0.
  The repo's `rust-toolchain.toml` pins 1.99.0, which rustup would have downloaded; that was not
  authorised, so `RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu` overrides it. It built
  cleanly. `CARGO_HOME=/root/bench/cargo-home` keeps crate downloads out of `/root/.cargo`.
  `Cargo.toml` patches Arti to Soapbox's fork at `git.shakespeare.diy` (plus its
  `arti-corpora` submodule on gitlab.torproject.org); cargo fetched both.
* **ours**: `push-ours-src.sh` then `build-cargo.sh ours` (`cargo build --release -p relay-server`),
  54 s from scratch (21 s incremental). Built from a snapshot in `/root/bench/src/ours`, NOT in
  `/root/relay-src`: when I started, that tree had no `serve` command (it predated `serve.rs`), and
  while I worked it was re-synced and rebuilt by someone else (its binary is in use by an `import`),
  so I left it alone. Rebuild the bench binary whenever the code moves: both commands above.
* **strfry**: not built, the production binary is used as is.

## Configs and deviations from defaults

Config files (copies here, installed by `push.sh`): `strfry-bench.conf`, `ours.toml`,
`ditto.toml`, `fastr.env` (fastr takes `FASTR_*` environment variables only; `start.sh` sources it).

| setting | fastr | ditto | strfry | ours |
|---|---|---|---|---|
| max `limit` | 5000 (was 500) | 5000 (was 1000) | 5000 (was 500) | 5000 (default) |
| subs / connection | 200 (was 20) | 200 (was 20) | 200 (was 20) | 200 (default) |
| values per filter list | 5000 (was 4096) | 20000 (default) | not configurable | 5000 (default) |
| filters per REQ | 50 (was 32) | 100 (default) | 50 (was 20) | 50 (default) |
| message size | 262144 (was 2 MiB) | 4,000,000 (default) | 262144 (was 131072) | 262144 (default) |
| connections | 20000 (was 1024) | no cap found in source | `nofiles` 524288 | no global cap found; per-IP limit 0 = off |
| event size | content <= 50 KiB, 1059: 1.5 MiB (default) | message cap | 65536 (default) | 65536 (default) |
| per-IP rate limits | none exist | none exist | none exist | 0 = off |
| kinds | all | all | `rejectedKinds = ""` (live refuses 13 kinds) | `kinds = "all"` (default "vector") |
| AUTH needed to read 1059/4 | **always, hard-wired** | no (`auth_kinds = []`, the default) | no (`restrictedReadKinds = ""`) | no |
| compression | none | none | **off** (live: on) | none |
| negentropy | on, max 1,000,000 recs (was 500k) | on, max 1,000,000 | on, max 1,000,000 | on |
| other | | `metrics_bind = ""` | `realIpHeader = ""` | |

Why these: the numbers are the ones Vector/Concord ask for (docs/DESIGN.md): limit 5000, >= 2000 authors
per filter, 200 subs, 256 KiB frames. `metrics_bind = ""` because ditto's default
`127.0.0.1:13133` is outside 7801-7809. strfry's `auth.enabled` stays `true`: the live config
documents that `enabled = false` alone leaves gift wraps unreadable (the kinds list is the
control), so `restrictedReadKinds = ""` is what opens them, exactly as in production. Not
verified separately.

Left on, because they are part of each design: **ditto**: NIP-50 search (Tantivy, commit every
1000 ms), NLP (vader/whatlang) on every write, NIP-85 assertions and trend labels (every 900 s),
version history for replaceables, ranking (WoT has no seeds because `pubkey` is unset, so it does
nothing). Tor, TLS and Prometheus are off. No external services are contacted.

Fairness notes (not changed, but they colour results):
* **Durability differs.** strfry and ours (`sync = true`) fsync before acknowledging; fastr has
  no fsync/msync anywhere in `src/`; ditto runs LMDB `MDB_NOSYNC` with a periodic forced flush.
* strfry still has `rejectEventsOlderThanSeconds = 94608000` (3 years, the live value). Ours,
  ditto and fastr accept any past timestamp. Seed benchmark data newer than that or raise it.
* Unspecified `limit`: strfry returns up to 5000, fastr 5000 (its default limit equals max),
  ditto 100, ours 500.
* strfry runs `--verbosity=WARNING` like production; the others log at their defaults to
  `/root/bench/logs/<name>.log`.

## fastr and NIP-17 (kind 1059)

Cannot be turned off by any setting. It is hard-wired in the core: a connection that has not
completed NIP-42 AUTH as a p-tag recipient **silently gets nothing** for kind 1059 (no `CLOSED`,
just `EOSE`), whatever the filter:

* stored REQ: `#p`, `authors`, `ids`, kindless `#p`/`authors` (`src/store/query.odin:394`);
* COUNT (scan path, `query.odin:713`), NEG-OPEN inventory (`query.odin:855`): 1059 events are
  excluded from the set, so a sync against fastr reports nothing to fetch;
* live subscriptions (`src/ws/handler.odin:205`): wraps are only fanned out to a connection
  authenticated as a p-tagged pubkey.

Publishing works (`OK true`). Authors cannot read their own wraps either, only recipients. The
policy hooks in `cmd/fastr/plugins.odin` do not help ("core visibility rules remain mandatory").
Making fastr comparable on gift-wrap workloads needs a source patch at those four sites, or a
benchmark client that does NIP-42 AUTH as the recipient. I have **not** patched it.

## Smoke test (fresh data, `smoke.py`, no AUTH)

One signed kind-1059, ephemeral author, one `p` tag; read back unauthenticated.

| relay | accepted | by `#p` | by `authors` | by `ids` | NEG-OPEN `{kinds:[1059]}` | NEG-OPEN `{kinds:[1059],authors:[a]}` |
|---|---|---|---|---|---|---|
| fastr | yes | **no** (EOSE, 0) | **no** | **no** | NEG-MSG, event absent | NEG-MSG, event absent |
| ditto | yes | yes | yes | yes | NEG-MSG, event present | NEG-MSG, event present |
| strfry | yes | yes | yes | yes | NEG-MSG, event present | NEG-MSG, event present |
| ours | yes | yes | yes | yes | **NEG-ERR** `restricted: gift wraps are requested by author, recipient or id` | NEG-MSG, event present |

NEG message used: `6100000200` (version 0x61, bound infinity, mode IdList, 0 ids). fastr also
greets every connection with an `AUTH` challenge; ours' NEG-ERR for an unbounded gift-wrap
filter is its own policy, deliberate or not, and a benchmark that syncs "all 1059" by kind alone
will hit it.
