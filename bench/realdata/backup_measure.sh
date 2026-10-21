#!/bin/bash
# backup_measure.sh  (run on the box)  An online backup of the hidden instance, and what
# it costs the relay while and after it runs: time to EOSE over the 951 real-data REQs
# (replay.py, one connection) before, during and after, and how much of the store is in
# the page cache before and after (fincore). The backup goes to $DEST, which must not
# exist; remove it afterwards yourself.
set -euo pipefail
RT=/root/relay-test
BIN=${BIN:-$RT/bin/magnitude-relay}
CFG=${CFG:-$RT/hidden.toml}
DB=${DB:-$RT/db}
DEST=${DEST:-$RT/backup-measure}
ADDR=${ADDR:-127.0.0.1:7805}
replay() { python3 -I "$RT/replay.py" "$ADDR" "$RT/filters.jsonl" "$@"; }
cached() {
    # How much of the store is in the page cache (mincore over a read-only mapping).
    python3 -I - "$DB" <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
page, cached, total = os.sysconf("SC_PAGE_SIZE"), 0, 0
for root, _, files in os.walk(sys.argv[1]):
    for f in files:
        path = os.path.join(root, f)
        size = os.path.getsize(path)
        if size == 0 or not os.path.isfile(path):
            continue
        fd = os.open(path, os.O_RDONLY)
        addr = libc.mmap(None, size, 1, 1, fd, 0)
        os.close(fd)
        if addr in (None, ctypes.c_void_p(-1).value):
            continue
        pages = (size + page - 1) // page
        vec = (ctypes.c_ubyte * pages)()
        if libc.mincore(addr, size, vec) == 0:
            cached += sum(b & 1 for b in vec) * page
        libc.munmap(addr, size)
        total += size
print(f"{cached / 1e9:.2f} GB of the store cached")
PY
}

echo "== store: $(du -sh "$DB" | cut -f1); $(cached)"
echo "== before"
replay --loops 3 --label "before "

echo "== backup to $DEST (CLI on CPUs 0-5, nice 10; the copy itself runs inside the relay)"
out=$(mktemp)
systemd-run --scope --quiet -p AllowedCPUs=0-5 nice -n 10 /usr/bin/time -f "%e s wall, CLI max RSS %M KB" \
    "$BIN" --config "$CFG" backup "$DEST" > "$out" 2>&1 &
job=$!
n=0
while kill -0 "$job" 2>/dev/null; do
    n=$((n + 1))
    replay --label "during $n: "
done
wait "$job" || { echo "backup failed:"; cat "$out"; exit 1; }
grep -v '^copying' "$out"
echo "== after: $(cached)"
replay --loops 3 --label "after "
du -sh --apparent-size "$DEST" | sed 's/^/apparent: /'
du -sh "$DEST" | sed 's/^/on disk:  /'
