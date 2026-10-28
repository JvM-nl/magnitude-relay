# Design

How Magnitude Relay is built, and why: what it accepts and the rules it takes
from Vector and Concord, the storage engine and network design, and the
decisions that shaped them. For running it, see the [README](../README.md).

## Who it serves

Out of the box it accepts **only what Vector produces and reads**. Public notes are
refused. Config can open it to all kinds or to a chosen list. The kinds below come
from reading Vector's source and the Concord spec.

| kind | what | class | how Vector reads it |
|---|---|---|---|
| 0 | profile | replaceable | `authors`, `limit:1` |
| 5 | deletion | regular | `authors`, `#a` |
| 8 | badge award | regular | issuer + `#p` |
| 10008, 30008, 30009 | profile badges, badge set (and pre-10008 profile badges), badge definition | replaceable / addressable | NIP-58, for any client; Vector reads 30009 by `a` coordinate |
| 1059 | DM gift wrap / Concord stream wrap / Direct Invite | regular | DMs `#p:[me]` (+`#k`); Concord `authors:[hundreds of plane keys]`; `ids` |
| 10002 | relay list | replaceable | emoji-pack outbox lookup |
| 10030, 10050, 10063, 10304 | emoji list, DM inbox relays, Blossom servers, bot manifest | replaceable | `authors`, `limit:1` |
| 13303 | Concord invite list | replaceable | `authors` |
| 21059 | ephemeral Concord wrap (typing, voice presence) | **ephemeral** | live, `authors` |
| 24590 | push request | **ephemeral** | pusher `#p` |
| 24681 | device transfer | **ephemeral** | `#p:[room]` |
| 30030, 30078, 30315 | emoji set, app data, status | addressable | `authors` + `#d`; 30078 also `#d`+`#r`, `#t:["miniapp"]` |
| 33301, 33302 | Concord invite bundle (empty `d`), community list fragment | addressable | `authors` |

Inner kinds (13, 14, 15, 16, 7, 9, 1111, 33xx, 20013, 20014) are inside seals and
never reach a relay bare. Vector does not use MLS, kind 1 or kind 3.

### Rules that come out of Vector and Concord
- **Ephemeral** (21059, 24590, 24681, 24133 Nostr Connect, and every kind
  20000-29999): fanned out live, never stored, never replayed
  (NIP-59 says MUST NOT store; strfry keeps them 5 min). `OK true` even with no
  listener: Vector's relay check fails on `mute:`.
- **No lower age bound** on regular events. NIP-17 backdates wraps up to 2 days and a
  Concord relay move republishes old events verbatim. Future bound 900 s.
- **Event size** ≤ 65,536 bytes inclusive, measured on the serialised event (Concord
  calls 64 KiB the ceiling and designs to ~55 KB). Messages up to 128 KiB+ (Vector's
  negentropy assumes a 128 KiB frame).
- **Limits sized for Concord**: `limit` up to 5000 (same-second walls during a move),
  ≥ 2000 authors per filter, ≥ 20 filters per REQ, live filters with hundreds of
  authors. Any cap below what Vector asks for silently truncates history.
- **Ordering**: `created_at` descending, ties **lowest id first** (NIP-01, Concord
  01.md:151). Not strfry's levId order; differential tests compare modulo ties.
- **Deletion**: kind 5 deletes a 1059 when signed by its **p-tagged key** (strfry and
  NIP-59 do this; Concord relies on it). Author-signed deletes of a 1059 are refused
  (Concord; see Decisions). Kind-5 events are kept forever so a re-publish stays blocked.
- **NIP-40**: expired events are never served (checked at read time, swept later) and
  refused on publish if already expired.
- **NIP-62**: honoured for real users; refused from any pubkey that has authored a
  1059/21059 (a stream key could otherwise wipe a whole Concord plane, permanently).
- **No AUTH** (see Decisions). Vector only authenticates when challenged, so it
  simply never does here.
- **Write policy**: no per-pubkey reputation, WoT or "must have a profile" rules
  (gift-wrap authors are single-use keys). Rate limits are per IP / connection.
- NIP-11 publishes `privacy_addresses` (Vector reads it to find onion/I2P twins).
- Negentropy errors answer with `NEG-ERR`, never silence: Vector otherwise waits out
  its full timeout.

## Design

Runtime dependencies: `tokio` (reactor only), `secp256k1` (libsecp256k1), `sha2`,
`libc`, and our own `nostr-parse` (VectorPrivacy/nostr-parse). Events are read with
its spans mode, in place, and the record is written from the strings as they arrived;
an event it refuses or flags as unusual (escaped keys or hex, a kind past 65535, deep
nesting) is read by our scanner instead, so every verdict is the scanner's. TLS and
cryptography are otherwise never written in-house. The two
exceptions are speed-only and checked against those crates: batch Schnorr
verification (our own field, group and multi-scalar arithmetic decides that a
whole batch is valid; any doubt goes back to libsecp256k1 one signature at a
time) and multi-lane SHA-256 (see `docs/SIG_PERF.md`). The
built-in HTTPS adds `rustls` (ring provider, no aws-lc), `tokio-rustls`, `ring` and
`webpki-roots`, used by `relay-tls` and nowhere else. Everything else is ours.
Dev-only crates cross-check our implementations.

### Crates
- `relay-proto`: allocation-free JSON scanner (events go through nostr-parse first), canonical events, id + sig
  verification, compact records, filters, client messages.
- `relay-store`: the storage engine.
- `relay-net`: HTTP/1.1 + RFC 6455 WebSocket (server and client).
- `relay-tls`: built-in HTTPS. Our ACME client (RFC 8555, TLS-ALPN-01 and HTTP-01),
  JWS, DER/X.509 and PEM, a small HTTP client for the CA, the certificate store and
  renewal loop, and the TLS connection type the reactors drive. rustls does the
  TLS; nothing cryptographic is ours. Ships an in-process ACME server for tests.
- `relay-server`: the binary: config, reactors, subscriptions, NIP-11/45/77,
  metrics, dashboard, import/export.
- `relay-bench`: load generator + differential tester against any relay URL.

### Events
Strings are stored **in the escaped form the event id commits to**, so output is a
copy plus hex and every stored event re-serialises to bytes that hash to its id.
Canonical escaping = JSON.stringify / serde_json / tao for everything a client can
sign. If canonical does not match the id, the bytes as received are tried (a raw
DEL, lone surrogates); neither → invalid. 64-hex tag values are stored as 32 bytes.
Output keys are alphabetical like strfry, so re-exporting an imported strfry export
is **byte-identical** (proved in tests on hand-built tao-form lines).

### Storage engine: built to not need the database in RAM
The working set of a relay is "recent events + whichever user is syncing right
now", not the whole DB. Every structure is shaped so a query touches a small,
contiguous set of pages, and spare RAM becomes cache rather than a requirement.

- **Event log**: source of truth and WAL. Append-only segment files, records framed
  `len | crc32c | record`. `pwrite` in, `mmap` out.
- **`locs`**: dense seq → log offset (8 B/event), so records can move.
- **Clustered compaction**: cold log segments are rewritten ordered by the key their
  readers use: 1059 by `p` (a DM sync becomes one sequential read), plane-key wraps
  by author (a Concord history page is contiguous), everything else by author. Hot
  data stays in arrival order. `locs` absorbs the move; indexes never change.
- **Index**: one LSM tree, keys `type ‖ prefix ‖ created_at(BE) ‖ seq(BE)`: `id`,
  `created`, `kind`, `pubkey`, `pubkey+kind`, `tag(name,value)`,
  `tag(name,value)+kind`, `address(pubkey,kind,d)`, `expiry`. Disk segments:
  prefix-compressed 4 KiB blocks, a block index (first key, count, min/max
  created_at), a bloom filter on prefixes, a crc. Size-tiered compaction. Readers
  take an `Arc<Version>` snapshot: no locks on the read path.
- **NIP-77 covering index** for `(p, kind)`: keys carry the full id, and each block
  stores the 256-bit sum and count of its ids. A fingerprint over any range is block
  sums plus two partial blocks. `kinds:[1059] #p:[me]`, Vector's only NIP-77 shape,
  never touches the event log. Answers come in O(log n) block reads whatever the
  mailbox size.
- **COUNT** is index-only: per-block counts for interior blocks, decoding only the
  two boundary blocks, minus dead seqs. No event is read.
- **Dead set**: a seq bitset (atomic words). Deletion/replacement/expiry set a bit
  and zero the record body in place (deleted content does not linger); compaction
  drops the keys.
- **Caches sized to the box**: bloom filters and block indexes pinned in RAM (small:
  ~1-2 bytes/event), a block cache and the page cache take whatever else is free;
  `madvise` keeps index segments hot and marks log scans sequential. A 2 GB VPS
  still answers from disk in a few reads per query; a 64 GB box serves from memory.
- **Crash recovery**: everything but the log is derivable. A checkpoint records the
  log high-water mark after fsyncing the rest; boot replays the tail.
- **Durability**: group commit. The writer takes everything queued, appends,
  `fdatasync`s once, publishes, then sends OK. OK means on disk (strfry's guarantee,
  which not every relay gives). `relaxed` mode exists only for like-for-like
  benchmarks.
- **Bulk import**: verify on all cores, append to the log, external-sort the keys,
  write one disk segment per index. No per-event index inserts.

### Hardware: every level
Tuned and measured on a 4-core Skylake server (AVX2 + BMI2, no SHA-NI, 32 KiB L1d,
256 KiB L2/core, 8 MiB L3), with runtime detection choosing the fastest path elsewhere.
- **SIMD where bytes are scanned**: JSON string scanning, hex encode/decode,
  WebSocket unmasking, UTF-8 validation, key comparison in blocks. AVX2 on x86 with
  runtime detection, NEON on ARM, SWAR fallback (what is in `relay-proto` today).
- **Cache-line discipline**: per-core state padded to 128 B (Magnitude, our media
  server, measured 142 → 81 ns from this alone), hot fields first, counters per reactor and summed on
  read, no shared atomics on the request path.
- **Data layout**: index blocks sized to fit L1, block index and blooms laid out as
  flat arrays (binary search without pointer chasing), subscription index in
  struct-of-arrays form so one event's fan-out check walks contiguous memory.
- **Prefetching**: software prefetch of the next block / next record while the
  current one is matched; `MADV_SEQUENTIAL` / `MADV_WILLNEED` on scans; huge pages
  for the big in-memory tables.
- **No allocation on hot paths**: per-reactor arenas and reused buffers; one encoded
  copy of an event shared (`Arc`) by every subscriber.
- **Hashing and signatures**: SHA-256 eight messages at a time in AVX2 lanes, one
  message with OpenSSL's AVX2+BMI2 schedule; Schnorr signatures verified as a
  batch (BIP-340 with random 128-bit weights, GLV + Strauss/Pippenger) for bulk
  input and for the EVENTs that arrive in one read, with a pubkey cache (Concord
  plane keys sign many events). See `docs/SIG_PERF.md`.
- **Thread layout**: one reactor per hardware thread, pinned, `SO_REUSEPORT`; the
  writer on its own core; background compaction niced.

### Network and threads
- A connection lives on one reactor for life: parse, verify, query and send all
  happen there, so work spreads over cores without handoffs.
- EVENT: parse → cheap checks → **id lookup before any hashing** (a resend costs one
  bloom probe) → sha256 + schnorr → writer → OK after fsync.
- REQ: inline with a work budget; over budget it yields and resumes, so one huge REQ
  cannot starve a reactor.
- Live fan-out: the writer broadcasts each committed event (encoded once) to every
  reactor, which matches it against its own inverted index (ids / authors / tags /
  kinds). No inotify, no polling: target well under 1 ms from commit to send.
  Ephemeral events take the same path without touching the writer.
- Backpressure: bounded outbound bytes per connection; slow readers are dropped and
  never block the writer.

### Query planning
One index per filter, chosen by estimated size (block-index range widths are a
cheap cardinality estimate). Cursors walk newest-first from `until` to `since`,
merged by `(created_at desc)`; when `limit` cuts inside a same-second group, the
whole group is read and the lowest ids kept. Index-only when the index covers the
filter. Multi-filter REQs are a deduplicated union.


## Decisions
1. **Author-signed deletes of a 1059 are refused; p-tag deletes are honoured**
   (following Concord). A plane key is shared, so an author delete
   would let any keyholder wipe a plane. The tombstone check for a re-published 1059
   looks only at its p tags. Vector's DM delete-from-network needs another mechanism
   (expiration at send time, or a cooperative delete that makes the recipient's own
   client issue the p-tag delete); that is a Vector-side change.
2. **No NIP-42 AUTH**: authenticating users is a privacy
   reduction, so the relay never sends a challenge and does not advertise NIP-42.
   An `AUTH` message gets `OK false "restricted: auth is not used on this relay"`.
   Reads are open. One rule survives that needs no identity: a 1059 filter with none
   of `authors`, `#p`, `ids` is refused (no bulk scraping of the gift-wrap store;
   Vector never sends that shape).
3. **HTTPS is optional and additive.** Plain `ws://` on `[relay] bind`
   stays the default and keeps working beside it. Connections accepted on the HTTPS
   listener ignore `real_ip_header`: that header is for a proxy that overwrites it,
   and the HTTPS port faces clients directly. TLS 1.2 and 1.3; the only application
   protocol offered is `http/1.1` (plus `acme-tls/1` for validation), so an h2-only
   client is refused. The socket the reactor holds is an enum of plain TCP and TLS;
   the plain variant is the bare `TcpStream`, so plain connections cost what they did.
   A TLS connection reads through rustls into the same per-reactor scratch buffer.
4. **Trusted peers**: our own relays replicate with each other
   without redoing each other's work, but only for what came in from outside. A
   relay recognises a peer by its private path (`/peer/<secret>`) AND one of its
   listed addresses, both or neither. To a peer, gift wraps are listed like any
   event (so a full replica carries DMs). A receiving relay with `trusted = true`
   skips only the signature check, and only for events the sending relay took from
   an app and checked itself (marked `"first-hand"` after the event object; records
   carry it as a flag set only for EVENTs from ordinary connections). Imports,
   synced events and anything a peer sends are re-verified at the next hop; ids
   and every storage rule are always checked.
5. **Concord's bare pre-seal events** (kinds 3300-3311, 3314) stay in the Vector preset until November 2026, then come out.
