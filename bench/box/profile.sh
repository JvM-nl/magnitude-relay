#!/bin/bash
# profile.sh [workload ...]  (run on the box)  Where our relay spends its CPU, workload by
# workload. Runs the suite's workloads (longer, so each gets enough samples) against the
# frame-pointer build (`build-cargo.sh ours-prof`), pinned and niced as suite.sh does,
# while bpftrace samples the relay's user stacks at 997 Hz. One bpftrace map per workload
# in $BENCH_ROOT/profiles/<stamp>/; bench/box/fold.py summarises them. With no arguments,
# every workload in order (later ones need the data the first one ingests).
set -uo pipefail
export RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
export LOADGEN_CPUS=${LOADGEN_CPUS:-2,3}
export BIN_OURS=/root/bench/bin/magnitude-relay-prof
. "$(dirname "$(readlink -f "$0")")/env.sh"
cd "$BOX_DIR"
[ -x "$BIN_OURS" ] || die "missing $BIN_OURS: run build-cargo.sh ours-prof"
data=$BENCH_ROOT/data/d1m.jsonl
out=$BENCH_ROOT/profiles/$(date +%Y%m%d-%H%M%S)
assert_in_bench "$out"
mkdir -p "$out"
url=ws://127.0.0.1:$PORT_OURS
lg() {
    systemd-run --scope --quiet -p "AllowedCPUs=$LOADGEN_CPUS" nice -n "$NICE_LEVEL" \
        "$BIN_DIR/relay-bench" "$@" --url "$url" --label prof --json "$out/results.jsonl" --threads 2 2>&1 | tail -4
}
prof() {
    local name=$1; shift
    if [ ${#want[@]} -gt 0 ] && [[ ! " ${want[*]} " =~ " $name " ]] && [ "$name" != ingest ]; then return; fi
    bpftrace -e "profile:hz:997 /pid == $pid/ { @[ustack(perf, 64)] = count(); }" -o "$out/$name.bt" 2> "$out/$name.err" &
    local bt=$!
    for _ in $(seq 1 100); do grep -q Attaching "$out/$name.bt" 2>/dev/null && break; sleep 0.1; done
    echo "== $name"
    "$@"
    kill -INT "$bt"
    wait "$bt"
}
want=("$@")
./stop.sh ours >/dev/null 2>&1 || true
./wipe.sh ours
./start.sh ours || die "relay did not start"
pid=$(cat "$(pidfile_of ours)")
echo "profiling pid $pid into $out"
prof ingest     lg load --file "$data" --conns 8
prof dup        lg load --file "$data" --conns 8 --duplicates --count 300k
prof classic    lg query --file "$data" --workload classic --conns 8 --queries 20000
prof vector     lg query --file "$data" --workload vector --conns 8 --queries 20000
prof count      lg query --file "$data" --workload count --conns 8 --queries 20000
prof neg_light  lg neg --file "$data" --recipient-mode light --have 90 --sessions 2000 --conns 8
prof neg_heavy  lg neg --file "$data" --recipient-mode heavy --have 90 --sessions 120 --conns 4
prof fanout     lg fanout --subscribers 1000 --publishers 4 --rate 2000 --duration 20
prof idle       lg idle --conns 10000 --hold 20 --pid "$pid"
./stop.sh ours
echo "done: $out"
