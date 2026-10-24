#!/bin/bash
# push.sh  (run on the Mac)  Installs these scripts and configs on the benchmark box:
#   scripts -> /root/bench/box/        configs -> /root/bench/
# Nothing else on the box is touched.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
host=${BENCH_HOST:-jskitty}
cd "$here"
ssh "$host" 'mkdir -p /root/bench/box'
scp -q env.sh start.sh stop.sh wipe.sh smoke.py build-fastr.sh build-cargo.sh suite.sh compare.py campaign.sh README.md "$host":/root/bench/box/
scp -q strfry-bench.conf ours.toml ditto.toml fastr.env nostella.toml "$host":/root/bench/
ssh "$host" 'chmod +x /root/bench/box/*.sh /root/bench/box/smoke.py'
echo "pushed to $host:/root/bench/box and $host:/root/bench"
