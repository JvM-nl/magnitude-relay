#!/bin/bash
# box-torture.sh MODE FIRST_SEED COUNT ITERATIONS [PARALLEL]  (run on the box)
# The crash torture (torture-many.sh) on the box, capped. MODE is plain,
# faults (a disk that fills up), power (crash points are power cuts) or
# faults+power. Stores and failing seeds' outputs stay under
# $ADV/work/torture-MODE-FIRST; the summary goes to $ADV/logs.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/box-env.sh"
mode=${1:?mode}; first=${2:?first seed}; count=${3:?count}; iters=${4:?iterations}; par=${5:-4}
case "$mode" in
    plain) extra=() ;;
    faults) extra=(--faults) ;;
    power) extra=(--power) ;;
    faults+power) extra=(--faults --power) ;;
    *) die "mode: plain, faults, power or faults+power" ;;
esac
adv=$ADV/adv-target/release/adv
[ -x "$adv" ] || die "build adv first (box-build.sh)"
work=$ADV_WORK/torture-$mode-$first
assert_in_adv "$work"
mkdir -p "$work"
log=$ADV_LOGS/torture-$mode-$first.log
start=$(date +%s)
status=0
ADV_BIN=$adv ADV_TMP=$work ADV_KEEP_PREOPEN=${ADV_KEEP_PREOPEN:-} \
    capped 16G "$ADV_SRC/adversarial/scripts/torture-many.sh" "$first" "$count" "$iters" "$par" "${extra[@]}" | tee "$log" || status=1
echo "$mode: seeds $first..$((first + count - 1)) x $iters iterations in $(($(date +%s) - start))s" | tee -a "$log"
exit $status
