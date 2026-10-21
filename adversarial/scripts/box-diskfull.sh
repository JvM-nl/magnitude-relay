#!/bin/bash
# box-diskfull.sh [SIZE_MB] [ROOM_MB]  (run on the box)
# The relay on a filesystem that really fills up: a tmpfs of SIZE_MB (default
# 160) mounted at $ADV/tmpfs for this run only (unmounted on exit, whatever
# happens), with all but ROOM_MB (default 24) taken by a filler file. See
# `adv diskfull` for what is checked.
set -euo pipefail
. "$(dirname "$(readlink -f "$0")")/box-env.sh"
size=${1:-160}
room=${2:-24}
adv=$ADV/adv-target/release/adv
bin=$ADV_TARGET/release/$(ls "$ADV_TARGET/release" | grep -E -- '-relay$' | head -1)
[ -x "$adv" ] && [ -x "$bin" ] || die "build first (box-build.sh)"
mnt=$ADV/tmpfs
assert_in_adv "$mnt"
mkdir -p "$mnt"
if mountpoint -q "$mnt"; then
    die "$mnt is already mounted"
fi
mount -t tmpfs -o "size=${size}m,mode=0700" tmpfs "$mnt"
trap 'umount "$mnt" && echo "unmounted $mnt"' EXIT
capped 4G "$adv" diskfull --bin "$bin" --dir "$mnt/run" --room-mb "$room" | tee "$ADV_LOGS/diskfull-$(date +%s).log"
