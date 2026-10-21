#!/bin/bash
# cluster_ab.sh  (run on the box)  What clustering the log buys when the database is
# not in memory. The same export is imported twice: by OLD_BIN (a build from before log
# compaction: arrival-order log) into $AB/db-u, and by NEW_BIN (clusters after import)
# into $AB/db-c. Both are exported and compared (they must be byte-identical), then the
# engine benchmark (relay-store `real` example) runs on each inside a 1 GiB memory cap,
# after that database's own pages are dropped from the page cache. Nothing else on the
# box is evicted: posix_fadvise(DONTNEED) on our files only.
#
# Env: EXPORT (strfry export, jsonl), OLD_BIN, NEW_BIN, REAL (the `real` example), AB.
set -euo pipefail
EXPORT=${EXPORT:-/root/relay-test/all.jsonl}
OLD_BIN=${OLD_BIN:-/root/relay-test/magnitude-relay-prev}
NEW_BIN=${NEW_BIN:-/root/bench/bin/magnitude-relay}
REAL=${REAL:-/root/bench/src/ours/target/release/examples/real}
AB=${AB:-/root/relay-test/ab}
# CPUs 0-5 and nice 10, as every benchmark on the box; extra systemd-run options first.
scope() { systemd-run --scope --quiet -p AllowedCPUs=0-5 "$@"; }

mkdir -p "$AB"
for v in u c; do
    cat > "$AB/$v.toml" <<EOF
[policy]
kinds = "all"
[store]
data = "$AB/db-$v"
EOF
done

evict() {
    python3 -I - "$1" <<'EOF'
import os, sys
n = 0
for root, _, files in os.walk(sys.argv[1]):
    for f in files:
        fd = os.open(os.path.join(root, f), os.O_RDONLY)
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        os.close(fd)
        n += 1
print(f"evicted {n} files under {sys.argv[1]}")
EOF
}

if [ ! -e "$AB/db-u/checkpoint" ]; then
    echo "== import, arrival order ($OLD_BIN)"
    scope /usr/bin/time -f "%e s, %M KB max RSS" nice -n 10 "$OLD_BIN" --config "$AB/u.toml" import "$EXPORT" 2>&1 | tail -4
fi
if [ ! -e "$AB/db-c/checkpoint" ]; then
    echo "== import, clustered ($NEW_BIN)"
    scope /usr/bin/time -f "%e s, %M KB max RSS" nice -n 10 "$NEW_BIN" --config "$AB/c.toml" import "$EXPORT" 2>&1 | tail -5
fi
du -sh "$AB/db-u" "$AB/db-c"
ls "$AB/db-c/log" "$AB/db-c/log/cold" | tr '\n' ' '; echo

echo "== exports must match"
for v in u c; do
    "$NEW_BIN" --config "$AB/$v.toml" export | sha256sum | sed "s/-\$/db-$v/"
done

for v in u c; do
    echo "== engine benchmark, db-$v, 1 GiB cap, cold"
    evict "$AB/db-$v"
    scope -p MemoryMax=1G nice -n 10 "$REAL" "$AB/db-$v" 4 2>&1
done
