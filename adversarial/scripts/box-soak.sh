#!/bin/bash
# box-soak.sh HOURS [PREFILL] [LOAD]  (run on the box)
# A separate relay instance under $ADV/work/soak, attacked by every hostile
# scenario over and over for HOURS while the canary and LOAD more checked,
# well-behaved clients (default 4) keep using it. A CSV line per scenario run
# ($ADV/logs/soak-<time>.csv) tracks the relay's memory (peak and after),
# open descriptors and the canary's latency, to see drift over hours. The
# relay binds 127.0.0.1 only; the store is prefilled with PREFILL events
# (default 200000) through the relay's own import.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/box-env.sh"
hours=${1:?hours}
prefill=${2:-200000}
load=${3:-4}
adv=$ADV/adv-target/release/adv
bin=$ADV_TARGET/release/$(ls "$ADV_TARGET/release" | grep -E -- '-relay$' | head -1)
[ -x "$adv" ] && [ -x "$bin" ] || die "build first (box-build.sh)"
dir=$ADV_WORK/soak
assert_in_adv "$dir"
stamp=$(date +%s)
capped 16G "$adv" hostile --bin "$bin" --dir "$dir" --hours "$hours" --rounds 1000000 \
    --prefill "$prefill" --load "$load" --threads 4 --secs 20 --latency-ms 1000 \
    --log "$ADV_LOGS/soak-$stamp.csv" 2>&1 | tee "$ADV_LOGS/soak-$stamp.log"
