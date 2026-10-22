#!/bin/bash
# box-build.sh REV  (runs on the build box; deploy.sh ships and calls it)
#
# One build for every relay: the source of REV (a `git archive` deploy.sh
# unpacked in $ROOT/src/REV) is tested and built here once, and the same bytes
# go to every host, so they all run the same commit.
#
#   1. `cargo test --workspace --release`, on Linux: one failure and nothing ships.
#   2. `cargo build --release -p relay-server` with RELAY_BUILD_REV=REV, so the
#      binary reports its commit (/stats "build", the landing page, the log).
#   3. Debug info stripped (symbols kept, so a panic still names its frames).
#
# Capped like every other job on this box (it also runs a live relay): CPUs
# 0-5, nice 10, four jobs, and the idle I/O class (without it the first run's
# compile and tests raised the live relay's disk-pressure warning to 11%); its
# own CARGO_TARGET_DIR, so builds are incremental.
# Prints ARTIFACT=<path> and SHA256=<hex> last.
set -euo pipefail
REV=${1:?usage: box-build.sh REV}
ROOT=/root/relay-build
SRC=$ROOT/src/$REV
OUT=$ROOT/out
[ -d "$SRC" ] || { echo "no source at $SRC" >&2; exit 1; }
export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_HOME=/root/bench/cargo-home
export RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu
export CARGO_BUILD_JOBS=4
export CARGO_TARGET_DIR=$ROOT/target
export RELAY_BUILD_REV=$REV
capped() { systemd-run --scope --quiet -p AllowedCPUs=0-5 nice -n 10 ionice -c 3 "$@"; }
cd "$SRC"
t0=$(date +%s)
echo "test   : workspace, release" >&2
if ! capped cargo test --workspace --release > "$ROOT/test-$REV.log" 2>&1; then
    grep -E "^test .* FAILED|panicked|^error" "$ROOT/test-$REV.log" | head -20 >&2
    echo "test   : FAILED (log: $ROOT/test-$REV.log); nothing built" >&2
    exit 1
fi
echo "test   : $(grep -E '^test result: ok' "$ROOT/test-$REV.log" | awk '{s+=$4} END {print s}') passed in $(( $(date +%s) - t0 ))s" >&2
t1=$(date +%s)
capped cargo build --release -p relay-server > "$ROOT/build-$REV.log" 2>&1 || { tail -20 "$ROOT/build-$REV.log" >&2; exit 1; }
mkdir -p "$OUT"
objcopy --strip-debug "$CARGO_TARGET_DIR/release/magnitude-relay" "$OUT/magnitude-relay-$REV.new"
mv -f "$OUT/magnitude-relay-$REV.new" "$OUT/magnitude-relay-$REV"
strings "$OUT/magnitude-relay-$REV" | grep -q "$REV" || { echo "the binary does not carry $REV" >&2; exit 1; }
echo "build  : $(( $(date +%s) - t1 ))s, $(du -h "$OUT/magnitude-relay-$REV" | cut -f1)" >&2
# Keep the last ten artifacts and sources.
ls -1t "$OUT"/magnitude-relay-* 2>/dev/null | tail -n +11 | xargs -r rm -f --
ls -1dt "$ROOT"/src/* 2>/dev/null | tail -n +11 | xargs -r rm -rf --
echo "ARTIFACT=$OUT/magnitude-relay-$REV"
echo "SHA256=$(sha256sum "$OUT/magnitude-relay-$REV" | cut -d' ' -f1)"
