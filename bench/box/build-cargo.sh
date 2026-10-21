#!/bin/bash
# build-cargo.sh <ditto|ours>  (run on the box)
# Release build of ditto-relay (src/ditto-relay @ da4ec6c) or our relay (src/ours, a
# `git archive` snapshot, see push-ours-src.sh), capped to CPUs 0-5, nice 10, 4 jobs.
#
#  * CARGO_HOME is /root/bench/cargo-home, so crate downloads land under /root/bench and
#    the shared /root/.cargo is not touched.
#  * RUSTUP_TOOLCHAIN pins the installed stable (1.98.0). ditto-relay's rust-toolchain.toml
#    asks for 1.99.0, which rustup would silently download; that download is not authorised
#    here and 1.98.0 builds it fine.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/env.sh"

which=${1:-}
case "$which" in
    ditto) SRC=$BENCH_ROOT/src/ditto-relay; PKG=();                BIN=ditto-relay;      DEST=$BIN_DITTO ;;
    ours)  SRC=$BENCH_ROOT/src/ours;        PKG=(-p relay-server); BIN=magnitude-relay;  DEST=$BIN_OURS ;;
    *) die "usage: build-cargo.sh <ditto|ours>" ;;
esac
assert_in_bench "$SRC"; assert_in_bench "$DEST"

export PATH="$HOME/.cargo/bin:$PATH"
export CARGO_HOME=$BENCH_ROOT/cargo-home
export RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu
export CARGO_BUILD_JOBS=4
cd "$SRC"
start=$(date +%s)
systemd-run --scope --quiet -p "AllowedCPUs=$CAP_CPUS" nice -n "$NICE_LEVEL" cargo build --release "${PKG[@]}"
echo "built $BIN in $(( $(date +%s) - start ))s"
mkdir -p "$BIN_DIR"
cp "target/release/$BIN" "$DEST"
ls -l "$DEST"
