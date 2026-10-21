#!/bin/bash
# box-build.sh  (run on the box)  Release builds of the relay and of `adv`
# from /root/bench/adv/src (see box-push.sh), on the installed stable,
# capped. Binaries: $ADV/target/release/<relay> and $ADV/adv-target/release/adv.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/box-env.sh"
use_stable
cd "$ADV_SRC"
start=$(date +%s)
CARGO_TARGET_DIR=$ADV_TARGET capped 12G cargo build --release -p relay-server
cd "$ADV_SRC/adversarial"
CARGO_TARGET_DIR=$ADV/adv-target capped 12G cargo build --release
echo "built $(cat "$ADV_SRC/.git-rev" 2>/dev/null) in $(($(date +%s) - start))s"
