#!/bin/bash
# torture-many.sh FIRST_SEED COUNT ITERATIONS [PARALLEL] [extra adv torture args...]
# Runs `adv torture` for seeds FIRST_SEED..FIRST_SEED+COUNT-1, PARALLEL at a time,
# each in its own directory under $ADV_TMP (default: a temp dir). Prints one
# line per seed and the failures in full; exits non-zero if any seed failed.
set -uo pipefail
first=${1:?first seed}; count=${2:?count}; iters=${3:?iterations}; par=${4:-4}
shift 4 2>/dev/null || shift $#
here=$(cd "$(dirname "$0")/.." && pwd)
bin=${ADV_BIN:-$here/target/release/adv}
tmp=${ADV_TMP:-$(mktemp -d)}
mkdir -p "$tmp"
fail=0
run_one() {
    local s=$1
    local out="$tmp/seed-$s.out"
    "$bin" torture --dir "$tmp/seed-$s" --seed "$s" --iterations "$iters" "$@" >"$out" 2>&1
    local rc=$?
    if [ $rc -eq 0 ]; then
        echo "seed $s: ok ($(grep -o 'iterations: [0-9]*' "$out" | head -1))"
        rm -rf "$tmp/seed-$s"
    else
        echo "seed $s: FAILED"
        grep -m1 'FAILURE' "$out" | cut -c1-3000
    fi
    return $rc
}
pids=()
for ((s = first; s < first + count; s++)); do
    run_one "$s" "$@" &
    pids+=($!)
    while [ "$(jobs -rp | wc -l)" -ge "$par" ]; do sleep 0.2; done
done
for p in "${pids[@]}"; do
    wait "$p" || fail=1
done
exit $fail
