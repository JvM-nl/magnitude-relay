#!/bin/bash
# Shared settings for the adversarial scripts on the box. Sourced, never run.
#
# Everything lives under /root/bench/adv: sources, builds, the isolated
# toolchain (nightly, for libFuzzer), crate downloads, campaign data, logs.
# Nothing here writes, signals or deletes anything outside it (assert_in_adv
# guards every such path). Relays bind 127.0.0.1 only, on a free port.
# Every heavy process runs capped: CPUs 0-5 (6 and 7 are never used), nice
# 10, 4 cargo jobs, and a memory ceiling where it could balloon.

ADV=/root/bench/adv
ADV_SRC=$ADV/src
ADV_WORK=$ADV/work
ADV_LOGS=$ADV/logs
ADV_TARGET=$ADV/target
CAP_CPUS=0-5
NICE_LEVEL=10

die() {
    echo "error: $*" >&2
    exit 1
}

assert_in_adv() {
    local p
    p=$(readlink -m "$1")
    case "$p" in
        "$ADV"/*) ;;
        *) die "refusing to touch $p: outside $ADV" ;;
    esac
}

# Stable builds use the box's installed stable read-only; crate downloads go
# to our own CARGO_HOME, never to /root/.cargo.
use_stable() {
    export PATH="$HOME/.cargo/bin:$PATH"
    export CARGO_HOME=$ADV/cargo
    unset RUSTUP_HOME
    export RUSTUP_TOOLCHAIN=stable-x86_64-unknown-linux-gnu
    export CARGO_BUILD_JOBS=4
}

# Nightly (for cargo-fuzz) lives in its own RUSTUP_HOME and CARGO_HOME under
# $ADV: the box's default toolchain and /root/.cargo are never changed.
use_nightly() {
    export PATH="$ADV/cargo/bin:$HOME/.cargo/bin:$PATH"
    export CARGO_HOME=$ADV/cargo
    export RUSTUP_HOME=$ADV/rustup
    export RUSTUP_TOOLCHAIN=nightly
    export CARGO_BUILD_JOBS=4
}

# capped [MEM] CMD...: runs CMD on CPUs 0-5 at nice 10, under MEM (e.g. 8G).
capped() {
    local mem=$1
    shift
    systemd-run --scope --quiet -p "AllowedCPUs=$CAP_CPUS" -p "MemoryMax=$mem" nice -n "$NICE_LEVEL" "$@"
}

mkdir -p "$ADV_WORK" "$ADV_LOGS"
