#!/bin/bash
# box-push.sh [rev]  (run on the Mac)  Ships a COMMITTED snapshot of the repo
# (default HEAD) to /root/bench/adv/src on the box with `git archive`, as
# bench/box/push-ours-src.sh does for the benchmarks (and never to
# /root/bench/src/ours). Uncommitted work is deliberately not sent, so every
# campaign runs a named commit. Files get fresh mtimes (tar -m): archive mtimes
# are the commit's, which can make cargo keep a build of a later revision.
set -euo pipefail
host=${ADV_HOST:-jskitty}
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
rev=$(git -C "$root" rev-parse "${1:-HEAD}")
ssh "$host" 'mkdir -p /root/bench/adv/src'
git -C "$root" archive "$rev" | ssh "$host" 'tar -x -m -C /root/bench/adv/src'
ssh "$host" "echo $rev > /root/bench/adv/src/.git-rev"
echo "sent $rev to $host:/root/bench/adv/src"
