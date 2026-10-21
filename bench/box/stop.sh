#!/bin/bash
# stop.sh <name|all>
# Stops benchmark relays by pid file (SIGTERM, then SIGKILL after 20 s) and verifies they are
# gone. A pid is signalled only if /proc/<pid>/exe (and, for strfry, our --config) says it is
# OUR instance, so a stale pid file can never hit another process, and the production strfry
# (same binary, different config) is never touched. `all` also sweeps for strays.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/env.sh"

arg=${1:-}
[ -n "$arg" ] || die "usage: stop.sh <ours|strfry|fastr|ditto|all>"
if [ "$arg" = all ]; then targets=$NAMES; else valid_name "$arg" || die "unknown relay $arg"; targets=$arg; fi

rc=0

stop_pid() {
    local name=$1 pid=$2 i
    kill -TERM "$pid" 2>/dev/null || true
    for i in $(seq 1 100); do
        is_ours "$pid" "$name" || return 0
        sleep 0.2
    done
    echo "[$name] pid $pid ignored SIGTERM for 20s, sending SIGKILL"
    kill -KILL "$pid" 2>/dev/null || true
    for i in $(seq 1 50); do
        is_ours "$pid" "$name" || return 0
        sleep 0.1
    done
    return 1
}

for name in $targets; do
    pidfile=$(pidfile_of "$name")
    assert_in_bench "$pidfile"
    pid=
    if [ -f "$pidfile" ]; then pid=$(cat "$pidfile"); fi
    if [ -n "$pid" ] && is_ours "$pid" "$name"; then
        if stop_pid "$name" "$pid"; then
            echo "[$name] stopped (pid $pid)"
        else
            echo "[$name] FAILED to stop pid $pid" >&2; rc=1
        fi
    else
        echo "[$name] not running"
    fi
    rm -f -- "$pidfile"
done

# Sweep: any of our instances still alive (pid file lost, or started by hand)?
if [ "$arg" = all ]; then
    while read -r name pid; do
        [ -n "${name:-}" ] || continue
        echo "[$name] stray pid $pid, stopping"
        stop_pid "$name" "$pid" || { echo "[$name] FAILED to stop stray $pid" >&2; rc=1; }
    done < <(bench_pids)
fi

# Verify: no instance of the requested relays is alive, no port still answers.
for name in $targets; do
    p=$(port_of "$name")
    if [ -n "$(bench_pids | awk -v n="$name" '$1==n')" ]; then echo "[$name] STILL RUNNING" >&2; rc=1; fi
    if port_open "$p"; then echo "[$name] port $p still answers" >&2; rc=1; fi
done
exit $rc
