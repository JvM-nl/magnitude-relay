#!/bin/bash
# install.sh REV SHA256 [SOAK_SECONDS]  (runs on a relay host; deploy.sh ships and calls it)
#
# Puts the release deploy.sh copied to $LIB/incoming/magnitude-relay-REV into
# service, and keeps it only if the relay proves healthy:
#
#   1. The checksum must match the build box's (same bytes everywhere).
#   2. Each release lives in $LIB/releases/<rev>/; /usr/local/bin/magnitude-relay
#      is a symlink to the one in service, switched atomically. The first run
#      keeps the binary it replaces as a release of its own.
#   3. Restart (about 0.6 s on a full store), then within 30 s: the unit is
#      active, /live answers, and /stats reports build REV.
#   4. Soak: for SOAK seconds (default 30) it must stay active and answering,
#      with its uptime only growing (no crash-restart).
#
# Any failure puts the previous release back, restarts it, checks it, and exits
# 1, so deploy.sh stops and later hosts are never touched. One deploy at a time
# per host (flock). The relay's settings (/etc/magnitude-relay/relay.toml) are
# the host's own and never touched here.
set -euo pipefail
REV=${1:?usage: install.sh REV SHA256 [SOAK_SECONDS]}
SHA=${2:?usage: install.sh REV SHA256 [SOAK_SECONDS]}
SOAK=${3:-30}
LIB=/usr/local/lib/magnitude-relay
BIN=/usr/local/bin/magnitude-relay
UNIT=magnitude-relay
CONF=/etc/magnitude-relay/relay.toml
HOST=$(hostname)
say() { echo "[$HOST] $*"; }
die() { say "ERROR: $*"; exit 1; }

exec 9>/run/lock/magnitude-relay-deploy.lock
flock -n 9 || die "another deploy is running here"

PORT=$(sed -nE 's/^bind *= *"[^"]*:([0-9]+)".*/\1/p' "$CONF" | head -1)
[ -n "$PORT" ] || die "no bind port in $CONF"
URL=http://127.0.0.1:$PORT
build_now() { curl -s -m3 "$URL/stats" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("build","?"))' 2>/dev/null || echo "?"; }
uptime_now() { curl -s -m3 "$URL/live" | python3 -c 'import json,sys; print(json.load(sys.stdin)["uptime_secs"])' 2>/dev/null || echo -1; }

incoming=$LIB/incoming/magnitude-relay-$REV
[ -f "$incoming" ] || die "no $incoming"
echo "$SHA  $incoming" | sha256sum -c --quiet - || die "checksum mismatch for $incoming"
mkdir -p "$LIB/releases/$REV"
install -m 0755 "$incoming" "$LIB/releases/$REV/magnitude-relay"

# What is in service now, so it can come back.
prev=""
if [ -L "$BIN" ]; then
    prev=$(readlink -f "$BIN")
elif [ -f "$BIN" ]; then
    cur=$(build_now)
    case "$cur" in "?"|dev) cur="before-$(date +%s)" ;; esac
    mkdir -p "$LIB/releases/$cur"
    cp -p "$BIN" "$LIB/releases/$cur/magnitude-relay"
    prev=$LIB/releases/$cur/magnitude-relay
fi
[ "$prev" = "$LIB/releases/$REV/magnitude-relay" ] && prev=""
point() { ln -sfn "$1" "$BIN.next" && mv -Tf "$BIN.next" "$BIN"; }

# up REV_WANTED SECONDS: active, answering, reporting the build, within SECONDS.
up() {
    local want=$1 limit=$2 t=0
    while [ "$t" -lt $((limit * 10)) ]; do
        if systemctl is-active --quiet "$UNIT" && [ "$(uptime_now)" -ge 0 ] && { [ -z "$want" ] || [ "$(build_now)" = "$want" ]; }; then
            return 0
        fi
        sleep 0.1; t=$((t + 1))
    done
    return 1
}

rollback() {
    say "FAILED: $1"
    if [ -n "$prev" ]; then
        say "putting back $(basename "$(dirname "$prev")")"
        point "$prev"
        systemctl restart "$UNIT" || true
        if up "" 30; then say "rolled back: the previous release is serving"; else say "ROLLBACK DID NOT COME UP: look now"; fi
    fi
    exit 1
}

was=$(build_now)
point "$LIB/releases/$REV/magnitude-relay"
t0=$(date +%s.%N)
systemctl restart "$UNIT"
up "$REV" 30 || rollback "not healthy within 30 s of the restart (build $(build_now))"
say "$was -> $REV: serving again in $(python3 -c "print(round($(date +%s.%N) - $t0, 2))") s"

last=$(uptime_now)
end=$(( $(date +%s) + SOAK ))
while [ "$(date +%s)" -lt "$end" ]; do
    sleep 2
    systemctl is-active --quiet "$UNIT" || rollback "the unit stopped during the soak"
    now=$(uptime_now)
    [ "$now" -ge "$last" ] || rollback "it restarted during the soak (uptime $last -> $now)"
    last=$now
done
warn=$(curl -s -m3 "$URL/stats" | python3 -c 'import json,sys; print("; ".join(w["message"] for w in json.load(sys.stdin).get("warnings",[]) if w.get("level")=="critical"))' 2>/dev/null || true)
[ -z "$warn" ] || rollback "critical warning after the soak: $warn"
say "healthy for ${SOAK}s: keeping $REV"

# Kept. Tidying up can no longer change that: nothing below may fail the run
# (with pipefail, a grep that finds nothing to prune would).
set +e
# Keep the five newest releases (the one in service and the previous always).
keep=$(printf '%s\n%s\n' "$(dirname "$(readlink -f "$BIN")")" "$(dirname "${prev:-/x/x}")")
ls -1dt "$LIB"/releases/*/ 2>/dev/null | sed 's#/$##' | tail -n +6 | grep -vxF "$keep" | xargs -r rm -rf --
rm -f "$incoming"
exit 0
