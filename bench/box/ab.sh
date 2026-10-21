#!/bin/bash
# ab.sh <binary-a> <binary-b> [rounds] [workload ...]  (run on the box)
# Two builds of our relay on the same workloads, alternated A B A B for `rounds`
# rounds (default 2), each run on a freshly wiped store, pinned and niced as
# suite.sh does. Per workload: ops/s from relay-bench, and the relay's CPU time
# (user + system) for that workload, which a noisy box disturbs far less than
# throughput. Workloads (default all): ingest dup classic vector count neg fanout.
# ingest always runs: the others read what it loads. DATA=<file.jsonl> uses
# that dataset instead of d1m (a `relay-bench gen` file, the workloads need its shape).
set -uo pipefail
export RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
export LOADGEN_CPUS=${LOADGEN_CPUS:-2,3}
. "$(dirname "$(readlink -f "$0")")/env.sh"
cd "$BOX_DIR"
a=${1:?binary a} b=${2:?binary b}
rounds=${3:-2}
shift 3 2>/dev/null || shift $#
want=" ${*:-ingest dup classic vector count neg fanout} "
data=${DATA:-$BENCH_ROOT/data/d1m.jsonl}
assert_in_bench "$data"
url=ws://127.0.0.1:$PORT_OURS
hz=$(getconf CLK_TCK)
cpu() { awk '{print $14 + $15}' /proc/"$1"/stat; }

step() { # label pid relay-bench args...
    local label=$1 pid=$2 t0 t1
    shift 2
    case "$want" in *" $label "*) ;; *) [ "$label" = ingest ] || return 0 ;; esac
    t0=$(cpu "$pid")
    systemd-run --scope --quiet -p "AllowedCPUs=$LOADGEN_CPUS" nice -n "$NICE_LEVEL" \
        "$BIN_DIR/relay-bench" "$@" --url "$url" --label ab --threads 2 2>&1 \
        | awk -v tag="$tag" '$2 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {printf "%-24s %-16s %10s ops/s  p50 %8s  p99 %8s\n", tag, $1, $4, $5, $7}'
    t1=$(cpu "$pid")
    printf '%-24s %-16s %10.2f s relay cpu\n' "$tag" "cpu:$label" "$(echo "($t1 - $t0) / $hz" | bc -l)"
}

run() { # binary
    export BIN_OURS=$1
    tag=$(basename "$1")
    ./stop.sh ours >/dev/null 2>&1 || true
    ./wipe.sh ours >/dev/null
    ./start.sh ours >/dev/null || { echo "$tag did not start"; return; }
    local pid
    pid=$(cat "$(pidfile_of ours)")
    step ingest "$pid" load --file "$data" --conns 8
    step dup "$pid" load --file "$data" --conns 8 --duplicates --count 300k
    step classic "$pid" query --file "$data" --workload classic --conns 8 --queries 8000
    step vector "$pid" query --file "$data" --workload vector --conns 8 --queries 8000
    step count "$pid" query --file "$data" --workload count --conns 8 --queries 8000
    step neg "$pid" neg --file "$data" --recipient-mode heavy --have 90 --sessions 80 --conns 4
    step fanout "$pid" fanout --subscribers 1000 --publishers 4 --rate 2000 --duration 15
    ./stop.sh ours >/dev/null
}

for r in $(seq 1 "$rounds"); do
    echo "=== round $r"
    run "$a"
    run "$b"
done
