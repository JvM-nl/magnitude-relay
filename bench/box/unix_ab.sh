#!/bin/bash
# unix_ab.sh [rounds]  (run on the box)  One relay, two ways in: the same workloads
# over loopback TCP and over the relay's Unix socket (as nginx would reach it),
# alternated, on one store loaded once. Per workload: ops/s and latency from
# relay-bench, and the relay's CPU time (user + system), which on Linux includes
# the loopback TCP work done in the relay's own sends.
set -uo pipefail
export RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
export LOADGEN_CPUS=${LOADGEN_CPUS:-2,3}
. "$(dirname "$(readlink -f "$0")")/env.sh"
cd "$BOX_DIR"
rounds=${1:-2}
data=$BENCH_ROOT/data/d1m.jsonl
sock=$RUN_DIR/ours.sock
conf=$BENCH_ROOT/ours-unix.toml
assert_in_bench "$conf"; assert_in_bench "$sock"
# The benchmark settings plus the socket.
sed "s|^\[relay\]|[relay]\nunix_socket = \"$sock\"|" "$BENCH_ROOT/ours.toml" > "$conf"
export OURS_CONF=$conf
hz=$(getconf CLK_TCK)
cpu() { awk '{print $14 + $15}' /proc/"$1"/stat; }

./stop.sh ours >/dev/null 2>&1 || true
./wipe.sh ours >/dev/null
trap './stop.sh ours >/dev/null 2>&1' EXIT
./start.sh ours >/dev/null || exit 1
pid=$(cat "$(pidfile_of ours)")
for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
lg() { # url args...
    local url=$1
    shift
    systemd-run --scope --quiet -p "AllowedCPUs=$LOADGEN_CPUS" nice -n "$NICE_LEVEL" \
        "$BIN_DIR/relay-bench" "$@" --url "$url" --label ab --threads 2 2>&1
}
lg "ws://127.0.0.1:$PORT_OURS" load --file "$data" --conns 8 > /dev/null
step() { # name args...
    local name=$1 t0 t1 url how
    shift
    for how in tcp unix; do
        if [ $how = tcp ]; then url="ws://127.0.0.1:$PORT_OURS"; else url="unix:$sock"; fi
        t0=$(cpu "$pid")
        lg "$url" "$@" | awk -v tag="$how" '$2 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {printf "%-5s %-16s %10s ops/s  p50 %8s  p99 %8s\n", tag, $1, $4, $5, $7}'
        t1=$(cpu "$pid")
        printf '%-5s %-16s %10.2f s relay cpu\n' "$how" "cpu:$name" "$(echo "($t1 - $t0) / $hz" | bc -l)"
    done
}
for r in $(seq 1 "$rounds"); do
    echo "=== round $r"
    step classic query --file "$data" --workload classic --conns 8 --queries 8000
    step vector query --file "$data" --workload vector --conns 8 --queries 8000
    step count query --file "$data" --workload count --conns 8 --queries 8000
    step fanout fanout --subscribers 1000 --publishers 4 --rate 2000 --duration 15
done
