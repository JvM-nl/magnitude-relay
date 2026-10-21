#!/bin/bash
# suite.sh <ours|strfry|fastr|ditto> [dataset]
# One full, identical benchmark pass against one relay: wipe its data, start it
# (pinned, capped, niced, as start.sh does), run every workload with relay-bench
# on the load-generator CPUs, then stop it. Every run appends one JSON line to
# /root/bench/results/suite.jsonl; the human tables go to the terminal.
#
# Export RELAY_CPUS / LOADGEN_CPUS to change pinning (default here: the relay owns
# two whole cores, 0,1,4,5; the load generator gets 2,3; 6,7 stay with production).
set -uo pipefail
export RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
export LOADGEN_CPUS=${LOADGEN_CPUS:-2,3}
. "$(dirname "$(readlink -f "$0")")/env.sh"
cd "$BOX_DIR"

name=${1:-}
valid_name "$name" || die "usage: suite.sh <ours|strfry|fastr|ditto> [dataset]"
data=${2:-$BENCH_ROOT/data/d1m.jsonl}
assert_in_bench "$data"
[ -f "$data" ] || die "missing dataset $data"
out=${SUITE_OUT:-$BENCH_ROOT/results/suite.jsonl}
mkdir -p "$BENCH_ROOT/results"
url=ws://127.0.0.1:$(port_of "$name")

lg() {
    systemd-run --scope --quiet -p "AllowedCPUs=$LOADGEN_CPUS" nice -n "$NICE_LEVEL" \
        "$BIN_DIR/relay-bench" "$@" --url "$url" --label "$name" --json "$out" --threads 2
    local rc=$?
    [ $rc -eq 0 ] || echo "[$name] relay-bench $1 exited $rc" >&2
    return 0
}

echo "=== $name: $(date -Is), dataset $data, relay cpus $RELAY_CPUS, loadgen cpus $LOADGEN_CPUS"
./stop.sh "$name" >/dev/null 2>&1 || true
./wipe.sh "$name"
./start.sh "$name" || die "$name did not start"
pid=$(cat "$(pidfile_of "$name")")

# Ingest: the whole dataset, 8 connections, 64 events in flight each.
lg load --file "$data" --conns 8
du -sh "$(data_dir_of "$name")" | sed "s/^/[$name] disk after load: /"
grep -E 'VmRSS|VmHWM' /proc/"$pid"/status | sed "s/^/[$name] /"
# The same numbers as a result line, for compare.py.
# rss_anon_kb is private memory; the rest of RSS is mapped files the kernel can drop.
printf '{"label":"%s","command":"footprint","workload":"after_ingest","time":%s,"disk_bytes":%s,"rss_kb":%s,"rss_anon_kb":%s,"hwm_kb":%s,"ok":true}\n' \
    "$name" "$(date +%s)" "$(du -sb "$(data_dir_of "$name")" | cut -f1)" \
    "$(awk '/VmRSS/{print $2}' /proc/"$pid"/status)" "$(awk '/RssAnon/{print $2}' /proc/"$pid"/status)" \
    "$(awk '/VmHWM/{print $2}' /proc/"$pid"/status)" >> "$out"
# Resends: the duplicate fast path.
lg load --file "$data" --conns 8 --duplicates --count 100k

# Reads. fastr serves no kind-1059 events without AUTH (hard-wired NIP-17), so
# the Vector workloads, COUNT and NIP-77 would only measure empty answers there.
lg query --file "$data" --workload classic --conns 8 --queries 4000
if [ "$name" != fastr ]; then
    lg query --file "$data" --workload vector --conns 8 --queries 4000
    lg query --file "$data" --workload count --conns 8 --queries 4000
    lg neg --file "$data" --recipient-mode light --have 90 --sessions 400 --conns 8
    lg neg --file "$data" --recipient-mode heavy --have 90 --sessions 40 --conns 4
fi

# Live delivery latency: 1000 subscribers, 2000 events/s for 20 s.
lg fanout --subscribers 1000 --publishers 4 --rate 2000 --duration 20

# Connection capacity and memory per connection.
lg idle --conns 10000 --hold 20 --pid "$pid"
grep -E 'VmRSS|VmHWM' /proc/"$pid"/status | sed "s/^/[$name] after idle: /"

./stop.sh "$name"
echo "=== $name done: $(date -Is)"
