# Benchmarks

Magnitude Relay against strfry, the relay Vector ran before it. Both were
measured on the same machine by the same load generator (`relay-bench`, in this
repository), one relay at a time, with every answer checked against the right
one: a relay could not win by skipping work.

- **Machine:** 4-core Skylake server (i7-6700, AVX2), NVMe RAID 1. Each relay
  pinned to the same two physical cores, the load generator to the other two.
- **Data:** 1,000,000 Vector-shaped events (gift-wrapped DMs, Concord channel
  wraps, profiles, lists), the same file for both.
- **Durability:** both relays answer `OK` only once an event is on disk.
- **Runs:** best of three passes per relay, 21 October 2026.
- **Reproduce:** `bench/box/suite.sh` runs the whole suite against any relay;
  `bench/box/README.md` explains each workload.

Bold marks the better result. `q/s` is requests answered per second; `p50` and
`p99` are the median and the slowest 1 in 100.

| workload | metric | Magnitude Relay | strfry |
|---|---|---|---|
| ingest | ev/s | **29,618** | 5,228 |
| ingest | p50 (ms) | **14.55** | 99.61 |
| ingest | p99 (ms) | **70.25** | 138.41 |
| after_ingest | disk | **2.52 GB** | 3.55 GB |
| after_ingest | RSS | **1217 MB** | 3093 MB |
| after_ingest | RSS private | 141 MB | **21 MB** |
| ingest_dup | ev/s | **260,132** | 10,911 |
| ingest_dup | p50 (ms) | **2.03** | 50.86 |
| ingest_dup | p99 (ms) | **3.70** | 84.93 |
| latest_1 | q/s | **64,880** | 20,912 |
| latest_1 | p50 (ms) | **0.11** | 0.34 |
| latest_1 | p99 (ms) | **0.16** | 1.03 |
| latest_100 | q/s | **17,909** | 1,658 |
| latest_100 | p50 (ms) | **0.36** | 4.72 |
| latest_100 | p99 (ms) | **0.73** | 6.75 |
| latest_500 | q/s | **4,045** | 435 |
| latest_500 | p50 (ms) | **1.61** | 17.56 |
| latest_500 | p99 (ms) | **3.05** | 26.74 |
| author | q/s | **36,102** | 3,772 |
| author | p50 (ms) | **0.18** | 2.03 |
| author | p99 (ms) | **0.43** | 3.87 |
| kind | q/s | **17,921** | 1,671 |
| kind | p50 (ms) | **0.37** | 4.65 |
| kind | p99 (ms) | **0.69** | 6.95 |
| author_kind | q/s | **47,770** | 5,306 |
| author_kind | p50 (ms) | **0.14** | 1.43 |
| author_kind | p99 (ms) | **0.33** | 3.24 |
| tag | q/s | **17,626** | 1,630 |
| tag | p50 (ms) | **0.38** | 4.78 |
| tag | p99 (ms) | **0.70** | 6.42 |
| time_window | q/s | **3,956** | 433 |
| time_window | p50 (ms) | **1.64** | 17.83 |
| time_window | p99 (ms) | **3.08** | 27.53 |
| exact_id | q/s | **116,931** | 22,026 |
| exact_id | p50 (ms) | **0.06** | 0.32 |
| exact_id | p99 (ms) | **0.09** | 0.99 |
| exact_ids_100 | q/s | **9,459** | 1,233 |
| exact_ids_100 | p50 (ms) | **0.72** | 6.23 |
| exact_ids_100 | p99 (ms) | **1.18** | 10.09 |
| miss | q/s | **127,178** | 24,586 |
| miss | p50 (ms) | **0.05** | 0.30 |
| miss | p99 (ms) | **0.09** | 0.70 |
| multi_filter | q/s | **13,441** | 1,323 |
| multi_filter | p50 (ms) | **0.50** | 5.83 |
| multi_filter | p99 (ms) | **0.94** | 8.39 |
| dm_inbox | q/s | **11,267** | 1,603 |
| dm_inbox | p50 (ms) | **0.50** | 4.39 |
| dm_inbox | p99 (ms) | **2.42** | 12.71 |
| dm_catchup | q/s | **19,226** | 2,886 |
| dm_catchup | p50 (ms) | **0.17** | 1.77 |
| dm_catchup | p99 (ms) | **1.93** | 10.09 |
| concord_page | q/s | **13,213** | 1,653 |
| concord_page | p50 (ms) | **0.41** | 4.26 |
| concord_page | p99 (ms) | **1.67** | 12.45 |
| concord_paging | q/s | **3,901** | 581 |
| concord_paging | p50 (ms) | **1.75** | 13.11 |
| concord_paging | p99 (ms) | **3.87** | 26.21 |
| dm_ids | q/s | **7,520** | 1,297 |
| dm_ids | p50 (ms) | **0.58** | 4.65 |
| dm_ids | p99 (ms) | **4.06** | 18.61 |
| count | q/s | **102,641** | 3,263 |
| count | p50 (ms) | **0.05** | 0.32 |
| count | p99 (ms) | **0.47** | 21.23 |
| neg_light_90 | q/s | **48,085** | 12,365 |
| neg_light_90 | p50 (ms) | **0.14** | 0.57 |
| neg_light_90 | p99 (ms) | **0.26** | 1.21 |
| neg_heavy_90 | q/s | **512** | 112 |
| neg_heavy_90 | p50 (ms) | **4.46** | 29.88 |
| neg_heavy_90 | p99 (ms) | **20.03** | 61.13 |
| fanout | deliv/s | 20,936 | 20,936 |
| fanout | p50 (ms) | **0.58** | 41.94 |
| fanout | p99 (ms) | **6.09** | 111.15 |
| fanout | missed | 0.0 | 0.0 |
| idle | conn/s | **23,145** | 17,115 |
| idle | bytes/conn | 1,656 | **1.2** |

## What the workloads are

- **ingest / ingest_dup:** publishing the whole dataset, then 100,000 events the
  relay already has.
- **latest_N, author, kind, tag, time_window, exact_id(s), miss, multi_filter:**
  the classic query shapes every relay serves.
- **dm_inbox, dm_catchup, dm_ids:** opening a DM inbox (500 messages), catching up
  on two days of DMs, and fetching messages by id.
- **concord_page, concord_paging:** opening a Community channel and scrolling back
  five pages.
- **count:** an exact count of matching events.
- **neg_light_90 / neg_heavy_90:** NIP-77 sync where the app already has 90% of a
  quiet or a busy inbox.
- **fanout:** live delivery of 2,000 messages a second to 1,000 subscribers.
- **idle:** how many connections a second it accepts, and memory per idle
  connection.
- **after_ingest:** disk and memory once the dataset is loaded. `RSS` includes the
  database files the operating system caches in memory; `RSS private` is the
  relay's own memory.

## On real data

The full jskitty.com dataset (4.9 million real events) was copied into a hidden
Magnitude Relay fed every new event live, and 951 requests built from that data
(DM inboxes, Community channels, profiles, settings, lists, lookups by id) were
answered by it and by the production strfry side by side. The answers matched,
except for events their authors or recipients had asked to delete (NIP-09,
NIP-62), which strfry still served. Mean time to a complete answer: **0.45 ms**
against strfry's **17.4 ms**. On disk the same data takes **11 GB** against
strfry's **27 GB**.
