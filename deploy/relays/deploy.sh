#!/bin/bash
# deploy.sh [REV] [--only HOST] [--rebuild]  (run on the Mac, from anywhere in the repo)
#
# Every relay on the same commit, never two restarting at once:
#
#   1. REV (default HEAD; must be committed, as `git archive` ships it) is
#      tested and built ONCE on BUILD_HOST (box-build.sh: the whole workspace's
#      tests on Linux, then a release build stamped with REV). A build of REV
#      that already passed is reused unless --rebuild.
#   2. The same bytes go to each host in HOSTS order (hosts.env), checked by
#      SHA-256, and install.sh puts them into service there: restart, health
#      check, SOAK seconds of watching, automatic rollback on any failure.
#   3. The first failure stops the run: later hosts keep their build untouched.
#
#   deploy/relays/deploy.sh               # HEAD to every relay
#   deploy/relays/deploy.sh a4b1d83       # a given commit (also a way back)
#   deploy/relays/deploy.sh --only eu     # one relay
#   deploy/relays/status.sh               # what each relay runs, and its health
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
[ -f "$HERE/hosts.env" ] || { echo "no $HERE/hosts.env: copy hosts.env.example and fill in your relays"; exit 1; }
. "$HERE/hosts.env"
REV_ARG=HEAD ONLY="" REBUILD=0
while [ $# -gt 0 ]; do
    case "$1" in
        --only) ONLY=$2; shift 2 ;;
        --rebuild) REBUILD=1; shift ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) REV_ARG=$1; shift ;;
    esac
done
REV=$(git -C "$REPO" rev-parse --short=7 "$REV_ARG^{commit}")
[ -z "$(git -C "$REPO" status --porcelain --untracked-files=no)" ] || echo "note: uncommitted changes are not part of $REV and will not ship"
targets=$HOSTS
if [ -n "$ONLY" ]; then
    case " $HOSTS " in *" $ONLY "*) targets=$ONLY ;; *) echo "unknown host $ONLY (hosts: $HOSTS)"; exit 1 ;; esac
fi
on() { local h=$1; shift; local o="SSH_OPTS_$h" d="SSH_DEST_$h"; ssh -o BatchMode=yes ${!o} "${!d}" "$@"; }
LOCK=/tmp/magnitude-relay-deploy.lock
mkdir "$LOCK" 2>/dev/null || { echo "another deploy is running (remove $LOCK if not)"; exit 1; }
trap 'rmdir "$LOCK"' EXIT

echo "deploy : $REV ($(git -C "$REPO" log -1 --format=%s "$REV")) to: $targets"
B=$BUILD_HOST
if [ "$REBUILD" = 0 ] && on "$B" "test -f /root/relay-build/out/magnitude-relay-$REV"; then
    echo "build  : reusing the tested build of $REV"
    SHA=$(on "$B" "sha256sum /root/relay-build/out/magnitude-relay-$REV" | cut -d' ' -f1)
else
    echo "source : $REV to $B"
    git -C "$REPO" archive --format=tar "$REV" | on "$B" "set -e; d=/root/relay-build/src; mkdir -p \$d; rm -rf \$d/$REV.part; mkdir \$d/$REV.part; tar -x -m -C \$d/$REV.part; rm -rf \$d/$REV; mv \$d/$REV.part \$d/$REV"
    on "$B" "cat > /root/relay-build/box-build.sh" < "$HERE/box-build.sh"
    out=$(on "$B" "bash /root/relay-build/box-build.sh $REV") || { echo "build  : FAILED, nothing deployed"; exit 1; }
    SHA=$(sed -n 's/^SHA256=//p' <<< "$out")
fi
ART=/root/relay-build/out/magnitude-relay-$REV
[ ${#SHA} = 64 ] || { echo "no checksum for the build"; exit 1; }
echo "build  : $ART sha256 ${SHA:0:16}..."

for h in $targets; do
    echo "== $h"
    on "$h" "mkdir -p /usr/local/lib/magnitude-relay/incoming"
    on "$h" "cat > /usr/local/lib/magnitude-relay/install.sh" < "$HERE/install.sh"
    if [ "$h" = "$B" ]; then
        on "$h" "cp $ART /usr/local/lib/magnitude-relay/incoming/magnitude-relay-$REV"
    else
        # Build box to host through this machine; install.sh checks the checksum.
        on "$B" "cat $ART" | on "$h" "cat > /usr/local/lib/magnitude-relay/incoming/magnitude-relay-$REV"
    fi
    if ! on "$h" "bash /usr/local/lib/magnitude-relay/install.sh $REV $SHA $SOAK"; then
        echo "STOPPED at $h (rolled back there); not touched: $(sed "s/.*$h//" <<< "$targets")"
        exit 1
    fi
done
echo "done   : $targets on $REV"
"$HERE/status.sh"
