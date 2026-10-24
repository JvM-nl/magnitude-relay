#!/bin/bash
# wipe.sh <ours|strfry|fastr|ditto|nostella>
# Deletes that relay's data directory (and only that), then leaves it ready for a fresh start.
# Refuses if the relay is running, and refuses any path that does not resolve to a directory
# directly under /root/bench whose name is the one env.sh assigns to the relay.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/env.sh"

name=${1:-}
valid_name "$name" || die "usage: wipe.sh <ours|strfry|fastr|ditto|nostella>"

dir=$(data_dir_of "$name")
assert_in_bench "$dir"

real=$(realpath -m -- "$dir")
# Must be exactly /root/bench/<one component>, and not a symlink to somewhere else.
case "$real" in
    "$BENCH_ROOT"/*/*) die "refusing: $real is nested deeper than $BENCH_ROOT/<dir>" ;;
esac
[ "$real" = "$dir" ] || die "refusing: $dir is not a plain path ($real)"
[ ! -L "$dir" ] || die "refusing: $dir is a symlink"
case "$(basename "$real")" in
    ours-data|strfry-db|fastr-data|ditto-data|nostella-data) ;;
    *) die "refusing: unexpected directory name $(basename "$real")" ;;
esac

pidfile=$(pidfile_of "$name")
if [ -f "$pidfile" ] && is_ours "$(cat "$pidfile")" "$name"; then
    die "$name is running (pid $(cat "$pidfile")); stop it first"
fi
if port_open "$(port_of "$name")"; then
    die "port $(port_of "$name") answers; stop $name first"
fi

if [ -d "$real" ]; then
    size=$(du -sh -- "$real" | cut -f1)
    rm -rf -- "$real"
    echo "[$name] wiped $real ($size)"
else
    echo "[$name] nothing to wipe ($real does not exist)"
fi
mkdir -p -- "$real"
