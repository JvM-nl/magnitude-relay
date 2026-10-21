#!/bin/bash
# build-fastr.sh  (run on the box)
# Builds fastr at the pinned commit with the Odin toolchain from /root/bench/tools.
#
# Why not `just vendor && just build`: the box has neither cmake nor clang, and we do not
# apt-install on a production host. So:
#   * libsecp256k1 v0.7.0 is compiled by hand with gcc using exactly the flags the project's
#     CMake build would use (schnorrsig + extrakeys, ECMULT_WINDOW_SIZE=15, COMB 43/6,
#     x86_64 asm, C90, -O2) and archived to vendor/secp256k1/build/lib/libsecp256k1.a, which
#     is the path src/secp256k1/secp256k1.odin links;
#   * Odin links by running `clang`; tools/bin/clang is a two-line shim that execs gcc.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/env.sh"

SRC=$BENCH_ROOT/src/fastr
COMMIT=9341e53
assert_in_bench "$SRC"; assert_in_bench "$BIN_DIR"
export PATH=$BENCH_ROOT/tools/bin:$BENCH_ROOT/tools/odin:$PATH
cap() { systemd-run --scope --quiet -p "AllowedCPUs=$CAP_CPUS" nice -n "$NICE_LEVEL" "$@"; }

cd "$SRC"
[ "$(git rev-parse --short=7 HEAD)" = "$COMMIT" ] || die "fastr is not at $COMMIT (git checkout $COMMIT)"

if [ ! -d vendor/secp256k1 ]; then
    mkdir -p vendor
    git clone --depth 1 --branch v0.7.0 https://github.com/bitcoin-core/secp256k1 vendor/secp256k1
fi
S=vendor/secp256k1
assert_in_bench "$SRC/$S/build"
rm -rf "$SRC/$S/build"; mkdir -p "$S/build/lib" "$S/build/obj"
DEFS="-DENABLE_MODULE_SCHNORRSIG=1 -DENABLE_MODULE_EXTRAKEYS=1 -DECMULT_WINDOW_SIZE=15 \
      -DCOMB_BLOCKS=43 -DCOMB_TEETH=6 -DUSE_ASM_X86_64=1 -DSECP256K1_NO_API_VISIBILITY_ATTRIBUTES"
for f in secp256k1 precomputed_ecmult precomputed_ecmult_gen; do
    cap gcc -std=c90 -O2 -I"$S" -I"$S/include" -I"$S/src" $DEFS -c "$S/src/$f.c" -o "$S/build/obj/$f.o"
done
ar rcs "$S/build/lib/libsecp256k1.a" "$S"/build/obj/*.o

time cap odin build cmd/fastr -out:fastr -o:speed        # == `just build`
mkdir -p "$BIN_DIR"
cp fastr "$BIN_DIR/fastr"
# NOTE: never run the binary here to "test" it: fastr has no CLI flags, it just starts
# serving on 0.0.0.0:8080 with ./data. smoke.py via start.sh is the test.
ls -l "$BIN_DIR/fastr"
