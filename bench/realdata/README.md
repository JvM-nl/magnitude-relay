# Real-data checks (run on the box, read-only against the live strfry)

- `mkfilters.py`: ~950 REQ filters drawn from the real export (heaviest and typical DM
  mailboxes, plane-like gift-wrap authors, profiles, inbox relay lists, synced settings,
  Concord lists, id batches), all bounded by `until` = the sync time.
- `cargo run --release -p relay-bench --example diff -- --a ws://127.0.0.1:7777 --b ws://127.0.0.1:7805 --filters filters.jsonl`
  sends each to both relays and compares id sets.
- `explain.py`: for every event only one side returned, finds the reason in the exports
  (NIP-62 vanish, NIP-09 deletion, arrived after the sync).
- `vanish_check.py`: verifies an export of our store against strfry's, line by line.
- `relay-bench --example mirror`: keeps a hidden instance fed with live traffic.

Result on 2026-10-21 (4.81M events + 3-day delta): 951 requests, 945 identical, 6 differing;
every differing event was one a user had asked to delete (NIP-62 vanish honoured by us,
never by strfry) or arrived after the sync. Mean time to EOSE: strfry 17.6 ms, ours 7.6 ms.
