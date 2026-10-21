#!/bin/bash
# box-fuzz.sh SECS [PARALLEL] [TARGET...]  (run on the box)
# Coverage-guided fuzzing with libFuzzer (cargo-fuzz, AddressSanitizer) of
# every target, or of those named: SECS seconds each, PARALLEL at a time.
# The first run installs a nightly toolchain and cargo-fuzz under $ADV (an
# isolated RUSTUP_HOME and CARGO_HOME; the box's own toolchain is untouched).
# Corpora persist in $ADV/fuzz/corpus/<target> from run to run, seeded from
# the stable runner's hand-made seeds; crashes, leaks and timeouts land in
# $ADV/fuzz/artifacts/<target>/. Needs box-build.sh first (for `adv`).
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/box-env.sh"
secs=${1:?seconds per target}
par=${2:-3}
shift $(($# < 2 ? $# : 2))
adv=$ADV/adv-target/release/adv
[ -x "$adv" ] || die "build adv first (box-build.sh)"
use_nightly
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    rustup toolchain install nightly --profile minimal
fi
if ! [ -x "$ADV/cargo/bin/cargo-fuzz" ]; then
    capped 8G cargo install cargo-fuzz --locked
fi
FUZZ=$ADV/fuzz
assert_in_adv "$FUZZ"
mkdir -p "$FUZZ/corpus" "$FUZZ/artifacts" "$FUZZ/seeds" "$FUZZ/logs"
"$adv" export-seeds --dir "$FUZZ/seeds" >/dev/null
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
    mapfile -t targets < <("$adv" targets)
fi
cd "$ADV_SRC/adversarial/fuzz"
capped 12G cargo fuzz build -O --debug-assertions --target-dir "$ADV/fuzz-target"
bins=$ADV/fuzz-target/x86_64-unknown-linux-gnu/release
run_target() {
    local t=$1
    mkdir -p "$FUZZ/corpus/$t" "$FUZZ/artifacts/$t"
    cp -n "$FUZZ/seeds/$t"/* "$FUZZ/corpus/$t/" 2>/dev/null || true
    capped 4G "$bins/$t" "$FUZZ/corpus/$t" \
        -max_total_time="$secs" -dict="$FUZZ/seeds/$t.dict" -max_len=65536 \
        -rss_limit_mb=3072 -timeout=10 -print_final_stats=1 \
        -artifact_prefix="$FUZZ/artifacts/$t/" >"$FUZZ/logs/$t.log" 2>&1
    local rc=$?
    local stats
    stats=$(grep -E '^stat::(number_of_executed_units|new_units_added|peak_rss_mb)' "$FUZZ/logs/$t.log" | tr '\n' ' ')
    local cov
    cov=$(grep -oE 'cov: [0-9]+ ft: [0-9]+ corp: [0-9]+' "$FUZZ/logs/$t.log" | tail -1)
    echo "$t: exit $rc; $cov; $stats; artifacts $(find "$FUZZ/artifacts/$t" -type f | wc -l)"
}
for t in "${targets[@]}"; do
    run_target "$t" &
    while [ "$(jobs -rp | wc -l)" -ge "$par" ]; do sleep 1; done
done
wait
echo "done: corpora in $FUZZ/corpus, artifacts in $FUZZ/artifacts, logs in $FUZZ/logs"
