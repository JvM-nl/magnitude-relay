#!/bin/bash
# Shared settings for the benchmark scripts. Sourced, never executed.
#
# HARD RULE: nothing in these scripts may write, signal, or delete anything outside
# /root/bench. Every path that is written, removed, or signalled goes through
# assert_in_bench. The one thing used from outside is the production strfry BINARY
# (/root/strfry/strfry), executed read-only with our own config.

BENCH_ROOT=/root/bench
BOX_DIR=$BENCH_ROOT/box
LOG_DIR=$BENCH_ROOT/logs
RUN_DIR=$BENCH_ROOT/run
BIN_DIR=$BENCH_ROOT/bin

# --- ports (all relays bind 127.0.0.1 only, inside 7801-7809) ---------------
PORT_FASTR=7801
PORT_DITTO=7802
PORT_STRFRY=7803
PORT_OURS=7804

# --- CPU pinning --------------------------------------------------------------
# Box: i7-6700, 4 cores x 2 threads. Hyperthread siblings: (0,4) (1,5) (2,6) (3,7).
# Relay under test: CPUs 0-3 (one thread on each physical core).
# Load generator:   CPUs 4-5 (siblings of 0 and 1, so they share cores with the relay).
# Left alone:       CPUs 6-7 (siblings of 2 and 3) for production.
# Every build and relay runs at nice 10. Override from the environment, e.g.
#   RELAY_CPUS=0,1,4,5 LOADGEN_CPUS=2,3 ./start.sh ours      (relay owns 2 whole cores)
RELAY_CPUS=${RELAY_CPUS:-0-3}
LOADGEN_CPUS=${LOADGEN_CPUS:-4-5}
NICE_LEVEL=${NICE_LEVEL:-10}
# The owner's cap: nothing of ours ever runs outside CPUs 0-5.
CAP_CPUS=0-5
# Open-file limit for the relay processes (hard limit on this box is 1048576).
NOFILE=${NOFILE:-524288}

# --- binaries ------------------------------------------------------------------
BIN_FASTR=$BIN_DIR/fastr
BIN_DITTO=$BIN_DIR/ditto-relay
# Overridable for profiling (profile.sh runs the frame-pointer build in its place).
BIN_OURS=${BIN_OURS:-$BIN_DIR/magnitude-relay}
BIN_STRFRY=/root/strfry/strfry   # production binary, read-only use, never modified

# --- per-relay data -------------------------------------------------------------
NAMES="ours strfry fastr ditto"

die() { echo "ERROR: $*" >&2; exit 1; }

# assert_in_bench PATH: abort unless PATH resolves to somewhere strictly inside /root/bench.
assert_in_bench() {
    local p r
    p=${1:?assert_in_bench needs a path}
    r=$(realpath -m -- "$p") || die "cannot resolve $p"
    case "$r" in
        "$BENCH_ROOT"/?*) ;;
        *) die "refusing: $p resolves to $r, outside $BENCH_ROOT" ;;
    esac
    case "$p" in
        *..*) die "refusing: $p contains .." ;;
    esac
}

valid_name() {
    case "$1" in ours|strfry|fastr|ditto) return 0 ;; *) return 1 ;; esac
}

port_of() {
    case "$1" in
        fastr) echo $PORT_FASTR ;; ditto) echo $PORT_DITTO ;;
        strfry) echo $PORT_STRFRY ;; ours) echo $PORT_OURS ;;
    esac
}

data_dir_of() {
    case "$1" in
        fastr) echo $BENCH_ROOT/fastr-data ;; ditto) echo $BENCH_ROOT/ditto-data ;;
        strfry) echo $BENCH_ROOT/strfry-db ;; ours) echo $BENCH_ROOT/ours-data ;;
    esac
}

conf_of() {
    case "$1" in
        fastr) echo $BENCH_ROOT/fastr.env ;; ditto) echo $BENCH_ROOT/ditto.toml ;;
        strfry) echo $BENCH_ROOT/strfry-bench.conf ;; ours) echo $BENCH_ROOT/ours.toml ;;
    esac
}

pidfile_of() { echo $RUN_DIR/$1.pid; }
logfile_of() { echo $LOG_DIR/$1.log; }
unit_of()    { echo bench-$1.scope; }

# alive_pid PID NAME: true if PID is a live process that really is OUR instance of NAME.
# Guards stop.sh against a stale pid file pointing at an unrelated (or production) process.
is_ours() {
    local pid=$1 name=$2 exe cmd
    [ -d /proc/$pid ] || return 1
    exe=$(readlink /proc/$pid/exe 2>/dev/null || true)
    cmd=$(tr '\0' ' ' 2>/dev/null < /proc/$pid/cmdline || true)
    case "$name" in
        strfry) [ "$exe" = "$BIN_STRFRY" ] && case "$cmd" in *"--config=$BENCH_ROOT/strfry-bench.conf"*) true ;; *) false ;; esac ;;
        fastr)  [ "$exe" = "$BIN_FASTR" ] ;;
        ditto)  [ "$exe" = "$BIN_DITTO" ] ;;
        ours)   [ "$exe" = "$BIN_OURS" ] ;;
    esac
}

# bench_pids: every live process that is one of our relay instances, one "name pid" per line.
# Matches on /proc/PID/exe (and, for strfry, our --config), never on a name pattern, so the
# production strfry is never matched.
bench_pids() {
    local d pid n exe
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        exe=$(readlink "$d/exe" 2>/dev/null || true)
        case "$exe" in
            "$BIN_FASTR"|"$BIN_DITTO"|"$BIN_OURS"|"$BIN_STRFRY") ;;
            *) continue ;;
        esac
        for n in $NAMES; do
            if is_ours "$pid" "$n"; then echo "$n $pid"; fi
        done
    done
}

# port_open PORT: true if something accepts TCP on 127.0.0.1:PORT.
port_open() {
    (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null
}
