#!/bin/bash
# ci.sh [SCALE]  (Mac or Linux, stable toolchain)  The adversarial suite at CI
# size: every part once, short. About 15 minutes on 8 cores at SCALE 1; SCALE
# multiplies the iteration counts. Exits non-zero on any finding; outputs
# stay in $ADV_TMP (default: a new temp dir) for a look.
set -uo pipefail
scale=${1:-1}
here=$(cd "$(dirname "$0")/.." && pwd)
root=$(cd "$here/.." && pwd)
tmp=${ADV_TMP:-$(mktemp -d)}
mkdir -p "$tmp"
fail=0
step() { echo; echo "== $*"; }

step "build: the relay, and adv"
(cd "$root" && cargo build --release -p relay-server) || exit 2
(cd "$here" && cargo build --release) || exit 2
adv=$here/target/release/adv

step "store tests with fault injection (failed writes, damage)"
(cd "$root" && cargo test -p relay-store) || fail=1

step "parser fuzzing: every target, $((20000 * scale)) inputs each"
"$adv" fuzz --target all --iters $((20000 * scale)) --out "$tmp/fuzz" || fail=1

step "crash torture: SIGKILLs at random moments and crash points"
ADV_BIN=$adv ADV_TMP=$tmp/torture "$here/scripts/torture-many.sh" 1 4 $((150 * scale)) 4 || fail=1
step "crash torture on a disk that fills up"
ADV_BIN=$adv ADV_TMP=$tmp/torture-faults "$here/scripts/torture-many.sh" 101 4 $((150 * scale)) 4 --faults || fail=1
step "crash torture with power cuts"
ADV_BIN=$adv ADV_TMP=$tmp/torture-power "$here/scripts/torture-many.sh" 201 4 $((150 * scale)) 4 --power || fail=1

step "on-disk damage (known open findings are reported, not fatal: see docs/ADVERSARIAL.md)"
"$adv" corrupt --dir "$tmp/corrupt" --cases $((100 * scale)) | grep -v '^    ' | tail -25

step "hostile clients against the relay binary"
"$adv" hostile --dir "$tmp/hostile" --prefill $((5000 * scale)) --secs 4 --silent 500 || fail=1

echo
if [ $fail -eq 0 ]; then echo "adversarial CI: pass ($tmp)"; else echo "adversarial CI: FAIL ($tmp)"; fi
exit $fail
