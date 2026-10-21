#!/bin/bash
# build-cargo.sh <ditto|ours|ours-prof>  (run on the box)
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
    # Frame pointers on, in a target directory of its own, for profile.sh's stack sampling.
    ours-prof)
        SRC=$BENCH_ROOT/src/ours; PKG=(-p relay-server); BIN=magnitude-relay; DEST=$BIN_DIR/magnitude-relay-prof
        export CARGO_TARGET_DIR=$BENCH_ROOT/prof-target RUSTFLAGS="-C force-frame-pointers=yes" ;;
    *) die "usage: build-cargo.sh <ditto|ours|ours-prof>" ;;
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
# Copy, then rename over: a running relay keeps its old binary (cp onto it would fail).
cp "${CARGO_TARGET_DIR:-target}/release/$BIN" "$DEST.new"
mv -f "$DEST.new" "$DEST"
ls -l "$DEST"
