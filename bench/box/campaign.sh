#!/bin/bash
# campaign.sh [name]  (run on the box)  The relay comparison: three suite.sh
# passes per relay, the order rotated each pass so no relay always runs first or
# last, every result appended to /root/bench/results/<name>.jsonl. Then the
# best-of table (on a shared box other load only slows a run down, so the best
# pass is the least disturbed) and the median table beside it.
set -uo pipefail
. "$(dirname "$(readlink -f "$0")")/env.sh"
cd "$BOX_DIR"
name=${1:-campaign-$(date +%Y%m%d-%H%M)}
out=$BENCH_ROOT/results/$name.jsonl
assert_in_bench "$out"
[ -e "$out" ] && die "$out exists"
export SUITE_OUT=$out
echo "=== campaign $name: $(date -Is), ours = $(cat "$BENCH_ROOT/src/ours/.git-rev" 2>/dev/null)"
# ORDERS overrides the rotation, e.g. ORDERS="ours nostella|nostella ours|ours nostella".
IFS='|' read -r -a orders <<< "${ORDERS:-strfry ditto fastr ours|ours fastr ditto strfry|ditto ours strfry fastr}"
for order in "${orders[@]}"; do
    for r in $order; do
        ./suite.sh "$r"
    done
done
python3 -I ./compare.py --best "$out" > "$BENCH_ROOT/results/$name-best.md"
python3 -I ./compare.py "$out" > "$BENCH_ROOT/results/$name-median.md"
echo "=== campaign done: $(date -Is)"
