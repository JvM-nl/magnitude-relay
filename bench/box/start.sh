#!/bin/bash
# start.sh <ours|strfry|fastr|ditto>
# Starts one relay in the background: capped to the owner's 6-of-8-thread limit, pinned to
# RELAY_CPUS, niced, logging to /root/bench/logs/<name>.log, pid in /root/bench/run/<name>.pid.
# Returns once the port answers; fails (and stops the relay) if it does not, or if the relay
# listens on anything other than 127.0.0.1:7801-7809.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/env.sh"

name=${1:-}
valid_name "$name" || die "usage: start.sh <ours|strfry|fastr|ditto>"

port=$(port_of "$name")
data=$(data_dir_of "$name")
conf=$(conf_of "$name")
pidfile=$(pidfile_of "$name")
logfile=$(logfile_of "$name")
unit=$(unit_of "$name")

for p in "$data" "$conf" "$pidfile" "$logfile" "$BIN_DIR" "$LOG_DIR" "$RUN_DIR"; do
    assert_in_bench "$p"
done
[ "$port" -ge 7801 ] && [ "$port" -le 7809 ] || die "port $port outside 7801-7809"
[ -f "$conf" ] || die "missing config $conf"

mkdir -p "$LOG_DIR" "$RUN_DIR"

# Refuse to start twice, and refuse if the port is taken by anything else.
if [ -f "$pidfile" ]; then
    old=$(cat "$pidfile")
    if is_ours "$old" "$name"; then die "$name already running (pid $old)"; fi
    mv -- "$pidfile" "$pidfile.stale-$(date +%s)"
fi
if port_open "$port"; then die "port $port already in use by another process"; fi

cd "$BENCH_ROOT"
ulimit -n "$NOFILE" || die "cannot raise open-file limit to $NOFILE"

# Build the command line for this relay.
case "$name" in
    fastr)
        [ -x "$BIN_FASTR" ] || die "missing $BIN_FASTR"
        mkdir -p "$data"
        set -a; . "$conf"; set +a
        # Config file and port must agree, or the readiness check would watch the wrong port.
        [ "${FASTR_PORT:-}" = "$port" ] || die "$conf sets FASTR_PORT=${FASTR_PORT:-} but env.sh says $port"
        # fastr defaults to 0.0.0.0:8080 and has no CLI flags: never start it without these.
        [ "${FASTR_ADDR:-}" = 127.0.0.1 ] || die "$conf must set FASTR_ADDR=127.0.0.1"
        [ "${FASTR_DATA_DIR:-}" = "$data" ] || die "$conf FASTR_DATA_DIR must be $data"
        cmd=("$BIN_FASTR")
        ;;
    ditto)
        [ -x "$BIN_DITTO" ] || die "missing $BIN_DITTO"
        mkdir -p "$data"
        cmd=("$BIN_DITTO" --config "$conf")
        ;;
    strfry)
        [ -x "$BIN_STRFRY" ] || die "missing $BIN_STRFRY"
        mkdir -p "$data"
        cmd=("$BIN_STRFRY" "--config=$conf" --verbosity=WARNING relay)
        ;;
    ours)
        [ -x "$BIN_OURS" ] || die "missing $BIN_OURS"
        "$BIN_OURS" --help 2>&1 | grep -q '^  serve' \
            || die "$BIN_OURS has no 'serve' command (stale source; rebuild from a tree that has serve.rs)"
        cmd=("$BIN_OURS" --config "$conf" serve)
        ;;
esac

echo "[$name] starting on 127.0.0.1:$port, cpus $RELAY_CPUS (cap $CAP_CPUS), nice $NICE_LEVEL"
echo "[$name] $(date -Is) start: ${cmd[*]}" >> "$logfile"

# systemd-run --scope execs the command inside a transient cgroup scope (no unit file is
# installed, the scope disappears with the process), so $! is the relay's own pid.
nohup systemd-run --scope --quiet --unit="${unit%.scope}" \
    -p "AllowedCPUs=$RELAY_CPUS" \
    nice -n "$NICE_LEVEL" "${cmd[@]}" >> "$logfile" 2>&1 < /dev/null &
pid=$!
echo "$pid" > "$pidfile"

# Wait for the port.
up=0
for _ in $(seq 1 300); do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "---- last log lines ----" >&2; tail -20 "$logfile" >&2
        rm -f -- "$pidfile"
        die "$name exited during startup"
    fi
    if port_open "$port"; then up=1; break; fi
    sleep 0.2
done
if [ "$up" != 1 ]; then
    "$BOX_DIR/stop.sh" "$name" || true
    die "$name did not answer on port $port within 60s"
fi

# Every listener this process owns must be 127.0.0.1 within 7801-7809.
bad=$(ss -ltnpH 2>/dev/null | grep "pid=$pid," | awk '{print $4}' \
      | grep -Ev '^127\.0\.0\.1:(780[1-9])$' || true)
if [ -n "$bad" ]; then
    echo "$name has unexpected listeners: $bad" >&2
    "$BOX_DIR/stop.sh" "$name" || true
    die "unexpected listener(s), stopped $name"
fi

echo "[$name] up: pid $pid, affinity $(grep Cpus_allowed_list /proc/$pid/status | cut -f2), nice $(ps -o ni= -p "$pid" | tr -d ' ')"
echo "[$name] NIP-11: $(curl -s -m 5 -H 'Accept: application/nostr+json' "http://127.0.0.1:$port/" | head -c 160)"
