#!/bin/bash
# tls_ab.sh [rounds] [events]  (run on the box)  What it costs the machine to serve
# the relay over TLS, four ways, by the CPU of every process on the server side
# (the relay, and nginx when it is in front) per request:
#   plain       ws:// straight to the relay (no TLS: the reference)
#   nginx-unix  nginx terminates TLS, then the relay's Unix socket
#   nginx-tcp   nginx terminates TLS, then loopback TCP (how strfry is reached today)
#   builtin     the relay's own TLS (rustls)
# nginx here is a bench-only instance of the system binary: its own prefix, config,
# pid file and logs under /root/bench/nginx, loopback ports 7806/7807, the relay's
# CPUs, the production vhost's proxy settings. It is stopped by its own pid, checked
# against its command line; the production nginx is never signalled or read beyond
# its binary. Per mode: a fresh store, `events` ingested (default 300k), then the
# read workloads and live fan-out, each with server CPU in us per operation.
set -uo pipefail
export RELAY_CPUS=${RELAY_CPUS:-0,1,4,5}
export LOADGEN_CPUS=${LOADGEN_CPUS:-2,3}
. "$(dirname "$(readlink -f "$0")")/env.sh"
cd "$BOX_DIR"
rounds=${1:-2}
events=${2:-300000}
data=$BENCH_ROOT/data/d$((events / 1000))k.jsonl
[ -s "$data" ] || head -n "$events" "$BENCH_ROOT/data/d1m.jsonl" > "$data"
NGX=$BENCH_ROOT/nginx
TLS=$BENCH_ROOT/tls
sock=$RUN_DIR/ours.sock
conf=$BENCH_ROOT/ours-tls.toml
for p in "$NGX" "$TLS" "$sock" "$conf" "$data"; do assert_in_bench "$p"; done
hz=$(getconf CLK_TCK)

# A self-signed ECDSA P-256 certificate, the kind certbot issues by default.
mkdir -p "$TLS" "$NGX/tmp" "$NGX/logs"
if [ ! -s "$TLS/key.pem" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 -subj "/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout "$TLS/key.pem" -out "$TLS/cert.pem" 2>/dev/null || die "openssl"
fi
# The benchmark settings, plus the Unix socket and the relay's own TLS.
sed "s|^\[relay\]|[relay]\nunix_socket = \"$sock\"|" "$BENCH_ROOT/ours.toml" > "$conf"
printf '\n[tls]\nenabled = true\ncert = "%s"\nkey = "%s"\nhttps_bind = "127.0.0.1:7808"\n' "$TLS/cert.pem" "$TLS/key.pem" >> "$conf"
export OURS_CONF=$conf

# The production vhost's /nostr location (proxy settings, TLS 1.2/1.3), twice.
proxy() { cat <<EOF
        location / {
            proxy_pass $1;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header X-Forwarded-For \$remote_addr;
            proxy_set_header Host \$host;
            proxy_read_timeout 86400s;
            proxy_send_timeout 86400s;
            proxy_connect_timeout 60s;
            proxy_buffering off;
            proxy_cache off;
        }
EOF
}
cat > "$NGX/nginx.conf" <<EOF
worker_processes 4;
pid $RUN_DIR/nginx.pid;
error_log $NGX/logs/error.log warn;
events { worker_connections 16384; }
http {
    access_log off;
    sendfile on;
    tcp_nopush on;
    client_body_temp_path $NGX/tmp/body;
    proxy_temp_path $NGX/tmp/proxy;
    fastcgi_temp_path $NGX/tmp/fastcgi;
    uwsgi_temp_path $NGX/tmp/uwsgi;
    scgi_temp_path $NGX/tmp/scgi;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_certificate $TLS/cert.pem;
    ssl_certificate_key $TLS/key.pem;
    server {
        listen 127.0.0.1:7806 ssl http2;
$(proxy "http://unix:$sock")
    }
    server {
        listen 127.0.0.1:7807 ssl http2;
$(proxy "http://127.0.0.1:$PORT_OURS")
    }
}
EOF

ngx_master() { # the bench nginx's master pid, only if it really is ours
    local pid
    pid=$(cat "$RUN_DIR/nginx.pid" 2>/dev/null) || return 1
    tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | grep -q -- "-c $NGX/nginx.conf" && echo "$pid"
}
ngx_stop() {
    local pid
    pid=$(ngx_master) || return 0
    kill -QUIT "$pid"
    for _ in $(seq 1 50); do [ -d /proc/"$pid" ] || return 0; sleep 0.1; done
    kill -KILL "$pid"
}
ngx_start() {
    ngx_stop
    # -e: even the log nginx opens before reading its config is ours, not the system's.
    nginx -t -p "$NGX/" -e "$NGX/logs/error.log" -c "$NGX/nginx.conf" >/dev/null 2>&1 || { nginx -t -p "$NGX/" -e "$NGX/logs/error.log" -c "$NGX/nginx.conf"; die "nginx config"; }
    systemd-run --scope --quiet -p "AllowedCPUs=$RELAY_CPUS" nice -n "$NICE_LEVEL" nginx -p "$NGX/" -e "$NGX/logs/error.log" -c "$NGX/nginx.conf"
    for _ in $(seq 1 50); do ngx_master >/dev/null && return 0; sleep 0.1; done
    die "the bench nginx did not start"
}
# utime + stime of the relay and of the bench nginx's master and workers.
server_cpu() {
    local pids p t=0
    pids="$1 $(ngx_master) $(pgrep -P "$(ngx_master || echo 0)" 2>/dev/null)"
    for p in $pids; do
        [ -r /proc/"$p"/stat ] && t=$((t + $(awk '{print $14 + $15}' /proc/"$p"/stat)))
    done
    echo "$t"
}
trap 'ngx_stop; ./stop.sh ours >/dev/null 2>&1' EXIT

url_of() {
    case "$1" in
        plain) echo "ws://127.0.0.1:$PORT_OURS" ;;
        nginx-unix) echo "wss://localhost:7806" ;;
        nginx-tcp) echo "wss://localhost:7807" ;;
        builtin) echo "wss://localhost:7808" ;;
    esac
}
lg() { # url args...
    local url=$1
    shift
    systemd-run --scope --quiet -p "AllowedCPUs=$LOADGEN_CPUS" nice -n "$NICE_LEVEL" \
        "$BIN_DIR/relay-bench" "$@" --url "$url" --label tls --threads 2 2>&1
}
step() { # mode pid name ops-hint args...
    local mode=$1 pid=$2 name=$3 t0 t1 out ops
    shift 3
    t0=$(server_cpu "$pid")
    out=$(lg "$(url_of "$mode")" "$@")
    t1=$(server_cpu "$pid")
    # Operations: the rows' op counts (a query run has one row per workload).
    ops=$(echo "$out" | awk '$2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {n += $3} END {print n + 0}')
    echo "$out" | awk -v m="$mode" '$2 ~ /^[0-9]+$/ && $4 ~ /^[0-9]+$/ {printf "%-11s %-16s %10s ops/s  p50 %8s  p99 %8s\n", m, $1, $4, $5, $7}'
    printf '%-11s %-16s %8.2f s server cpu, %6.1f us/op over %s ops\n' "$mode" "cpu:$name" \
        "$(echo "($t1 - $t0) / $hz" | bc -l)" "$(echo "($t1 - $t0) / $hz * 1000000 / ($ops + ($ops == 0))" | bc -l)" "$ops"
}

ngx_start
for r in $(seq 1 "$rounds"); do
    echo "=== round $r"
    for mode in plain nginx-unix nginx-tcp builtin; do
        ./stop.sh ours >/dev/null 2>&1 || true
        ./wipe.sh ours >/dev/null
        ./start.sh ours >/dev/null || die "relay did not start"
        pid=$(cat "$(pidfile_of ours)")
        for _ in $(seq 1 100); do [ -S "$sock" ] && break; sleep 0.1; done
        step "$mode" "$pid" ingest load --file "$data" --conns 8
        step "$mode" "$pid" classic query --file "$data" --workload classic --conns 8 --queries 8000
        step "$mode" "$pid" vector query --file "$data" --workload vector --conns 8 --queries 8000
        step "$mode" "$pid" fanout fanout --subscribers 1000 --publishers 4 --rate 2000 --duration 15
    done
done
