#!/bin/bash
# torture-many.sh FIRST_SEED COUNT ITERATIONS [PARALLEL] [extra adv torture args...]
# Runs `adv torture` for seeds FIRST_SEED..FIRST_SEED+COUNT-1, PARALLEL at a time,
# each in its own directory under $ADV_TMP (default: a temp dir). Prints one
# line per seed and the failures in full; exits non-zero if any seed failed.
# A seed's directory is removed when it passes and kept when it fails.
set -uo pipefail
first=${1:?first seed}; count=${2:?count}; iters=${3:?iterations}; par=${4:-4}
shift 4 2>/dev/null || shift $#
here=$(cd "$(dirname "$0")/.." && pwd)
bin=${ADV_BIN:-$here/target/release/adv}
tmp=${ADV_TMP:-$(mktemp -d)}
mkdir -p "$tmp"
run_one() {
    local s=$1
    shift
    local out="$tmp/seed-$s.out"
    "$bin" torture --dir "$tmp/seed-$s" --seed "$s" --iterations "$iters" "$@" >"$out" 2>&1
    if [ $? -eq 0 ]; then
        echo "seed $s: ok ($(grep -o 'iterations: [0-9]*' "$out" | head -1))"
        rm -rf "$tmp/seed-$s"
        echo ok >"$tmp/seed-$s.status"
    else
        echo "seed $s: FAILED"
        grep -m1 -e 'FAILURE' -e 'panicked' "$out" | cut -c1-3000
        echo fail >"$tmp/seed-$s.status"
    fi
}
for ((s = first; s < first + count; s++)); do
    run_one "$s" "$@" &
    while [ "$(jobs -rp | wc -l)" -ge "$par" ]; do sleep 0.2; done
done
wait
failed=0
for ((s = first; s < first + count; s++)); do
    grep -q fail "$tmp/seed-$s.status" 2>/dev/null && failed=$((failed + 1))
done
echo "$count seeds, $failed failed (outputs in $tmp)"
[ "$failed" -eq 0 ]
