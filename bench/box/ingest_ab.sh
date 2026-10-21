#!/bin/bash
# ingest_ab.sh <binary-a> <binary-b> [rounds] [events]  (run on the box)
# A short ingest A/B: the first `events` lines of the dataset (default 300k,
# about ten seconds a run) into a freshly wiped store, the two builds alternated
# A B A B for `rounds` rounds (default 4). Per run: events/s and latency from
# relay-bench, and the relay's CPU time per thread group (writer, reactor-*,
# syncer, store-bg, ...), in microseconds per event. CPU per thread is what a
# noisy box disturbs least; the writer's is the ingest ceiling. Also the size
# of the store each run leaves.
# A binary may be given as VAR=value@path: the relay then runs with VAR set,
# for comparing one build at two settings. DATA=<file.jsonl> ingests that
# file instead (its first `events` lines, taken as they are).
set -uo pipefail
export RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
export LOADGEN_CPUS=${LOADGEN_CPUS:-2,3}
. "$(dirname "$(readlink -f "$0")")/env.sh"
cd "$BOX_DIR"
a=${1:?binary a} b=${2:?binary b}
rounds=${3:-4}
events=${4:-300000}
full=$BENCH_ROOT/data/d1m.jsonl
data=${DATA:-$BENCH_ROOT/data/d$((events / 1000))k.jsonl}
assert_in_bench "$data"
[ -s "$data" ] || head -n "$events" "$full" > "$data"
[ "$(wc -l < "$data")" -ge "$events" ] || die "$data has fewer than $events lines"
hz=$(getconf CLK_TCK)
# "group utime stime" per thread, threads named reactor-0, reactor-1 ... as one group.
threads() {
    for t in /proc/"$1"/task/*; do
        printf '%s %s\n' "$(sed 's/-[0-9]*$//' "$t/comm")" "$(awk '{print $14, $15}' "$t/stat")"
    done | awk '{u[$1] += $2; s[$1] += $3} END {for (k in u) print k, u[k], s[k]}' | sort
}

run() { # [VAR=value@]binary
    local tag pid before after setting=
    case "$1" in *@*) setting=${1%%@*} ;; esac
    export BIN_OURS=${1#*@}
    tag=$(basename "$BIN_OURS")${setting:+ $setting}
    [ -n "$setting" ] && export "${setting?}"
    ./stop.sh ours >/dev/null 2>&1 || true
    ./wipe.sh ours >/dev/null
    ./start.sh ours >/dev/null || { echo "$tag did not start"; return; }
    pid=$(cat "$(pidfile_of ours)")
    before=$(threads "$pid")
    systemd-run --scope --quiet -p "AllowedCPUs=$LOADGEN_CPUS" nice -n "$NICE_LEVEL" \
        "$BIN_DIR/relay-bench" load --file "$data" --conns 8 --url "ws://127.0.0.1:$PORT_OURS" --label ab --threads 2 2>&1 \
        | awk -v tag="$tag" '$2 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {printf "%-24s %8s ev/s  p50 %7s  p99 %7s  p99.9 %7s  max %7s\n", tag, $4, $5, $7, $8, $9}'
    after=$(threads "$pid")
    join <(echo "$before") <(echo "$after") | awk -v tag="$tag" -v hz="$hz" -v n="$events" '
        { u = ($4 - $2) / hz * 1e6 / n; k = ($5 - $3) / hz * 1e6 / n; tot += u + k; sys += k
          if (u + k >= 0.05) line = line sprintf("  %s %.1f (sys %.1f)", $1, u + k, k) }
        END { printf "%-24s cpu us/event: total %.1f (sys %.1f) |%s\n", tag, tot, sys, line }'
    ./stop.sh ours >/dev/null
    printf '%-24s store after ingest: %s bytes on disk, log %s\n' "$tag" \
        "$(du -sB1 "$(data_dir_of ours)" | cut -f1)" "$(du -sB1 "$(data_dir_of ours)/log" | cut -f1)"
    [ -n "$setting" ] && unset "${setting%%=*}"
}

for r in $(seq 1 "$rounds"); do
    run "$a"
    run "$b"
done
