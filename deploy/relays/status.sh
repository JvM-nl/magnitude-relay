#!/bin/bash
# status.sh: each relay's build, uptime, connections and health, side by side.
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/hosts.env"
on() { local h=$1; shift; local o="SSH_OPTS_$h" d="SSH_DEST_$h"; ssh -o BatchMode=yes -o ConnectTimeout=10 ${!o} "${!d}" "$@"; }
printf "%-9s %-9s %-9s %-7s %-6s %-6s %s\n" host build uptime conns active sync warnings
for h in $HOSTS; do
    on "$h" 'port=$(sed -nE "s/^bind *= *\"[^\"]*:([0-9]+)\".*/\1/p" /etc/magnitude-relay/relay.toml 2>/dev/null | head -1); a=$(systemctl is-active magnitude-relay); curl -s -m3 http://127.0.0.1:$port/stats | A=$a python3 -c "
import json,os,sys
d=json.load(sys.stdin); s=d.get(\"sync\",[])
u=d[\"uptime_secs\"]; up=f\"{u//86400}d{u%86400//3600}h\" if u>=86400 else f\"{u//3600}h{u%3600//60}m\"
print(d.get(\"build\",\"?\"), up, d[\"connections_open\"], os.environ[\"A\"], f\"{sum(x[\"connected\"] for x in s)}/{len(s)}\", \"; \".join(w[\"message\"] for w in d.get(\"warnings\",[])) or \"-\")
" 2>/dev/null || echo "? ? ? $a ? unreachable"' | { read -r b u c a s w; printf "%-9s %-9s %-9s %-7s %-6s %-6s %s\n" "$h" "$b" "$u" "$c" "$a" "$s" "$w"; }
done
