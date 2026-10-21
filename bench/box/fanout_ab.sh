#!/bin/bash
# fanout_ab.sh <binary-a> <binary-b> [pads...]  (run on the box)
# Live-delivery cost of two builds of our relay, alternated A B A B per event
# size: the schedule fixes deliveries per second, so what differs is the relay's
# CPU time for the same work, its peak memory, and delivery latency.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/env.sh"
export RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
cd "$BOX_DIR"
a=$1 b=$2
shift 2
pads=${*:-0 2000 6000}
hz=$(getconf CLK_TCK)

run() { # binary pad
    cp "$1" "$BIN_OURS.new" && mv -f "$BIN_OURS.new" "$BIN_OURS"
    ./stop.sh ours >/dev/null 2>&1 || true
    ./wipe.sh ours >/dev/null
    ./start.sh ours >/dev/null
    local pid t0 t1 line
    pid=$(cat "$(pidfile_of ours)")
    t0=$(awk '{print $14 + $15}' /proc/"$pid"/stat)
    line=$(systemd-run --scope --quiet -p AllowedCPUs=2,3 nice -n 10 "$BIN_DIR/relay-bench" fanout \
        --url ws://127.0.0.1:"$(port_of ours)" --subscribers 1000 --publishers 4 --rate 2000 --duration 20 \
        --pad "$2" --label ab --threads 2 2>&1 | grep -E "^fanout +[0-9]")
    t1=$(awk '{print $14 + $15}' /proc/"$pid"/stat)
    printf '%-28s pad %5s  cpu %6.2f s  peak %6s MB  %s\n' "$(basename "$1")" "$2" \
        "$(echo "($t1 - $t0) / $hz" | bc -l)" "$(( $(awk '/VmHWM/{print $2}' /proc/"$pid"/status) / 1024 ))" \
        "$(echo "$line" | awk '{print "deliv/s " $4 "  p50 " $5 "  p99 " $7}')"
    ./stop.sh ours >/dev/null
}

for pad in $pads; do
    for bin in "$a" "$b" "$a" "$b"; do
        run "$bin" "$pad"
    done
done
