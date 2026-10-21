#!/bin/bash
# push-ours-src.sh [rev]  (run on the Mac)  Ships a COMMITTED snapshot of this repo
# (default HEAD) to /root/bench/src/ours on the box with `git archive`. Uncommitted work
# in the tree is deliberately not sent, so the benchmarked binary is always a named commit.
# Extracts over the existing tree (nothing is deleted; files removed between revisions linger,
# which cargo ignores unless a `mod` names them). Does not touch /root/relay-src. Then on the box: box/build-cargo.sh ours
set -euo pipefail
host=${BENCH_HOST:-jskitty}
root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
rev=$(git -C "$root" rev-parse "${1:-HEAD}")
ssh "$host" 'mkdir -p /root/bench/src/ours'
git -C "$root" archive "$rev" | ssh "$host" 'tar -x -C /root/bench/src/ours'
# git archive stamps files with the commit's time: after a build of a newer
# commit, cargo would take an older one for already built. Fresh mtimes.
ssh "$host" 'find /root/bench/src/ours -type f -exec touch {} +'
ssh "$host" "echo $rev > /root/bench/src/ours/.git-rev"
echo "sent $rev to $host:/root/bench/src/ours"
