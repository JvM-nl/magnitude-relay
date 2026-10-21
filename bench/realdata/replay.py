#!/usr/bin/env python3
"""replay.py HOST:PORT FILTERS_JSONL [--loops N] [--label TEXT]

Replays one REQ per line of FILTERS_JSONL over a single connection, one at a time,
and prints the time to EOSE: mean, p50, p99, max, and requests per second. One line
per loop. Standard library only, like req.py (the box has no WebSocket client).
"""
import base64
import json
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from req import frame, read_exact  # noqa: E402


def connect(host, port):
    s = socket.create_connection((host, int(port)))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    if b" 101 " not in head.split(b"\r\n")[0]:
        sys.exit(f"no upgrade: {head[:200]!r}")
    return s, bytearray(rest)


def until_eose(s, buf, sub):
    events = 0
    while True:
        b0, b1 = read_exact(s, 2, buf)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", read_exact(s, 2, buf))[0]
        elif n == 127:
            n = struct.unpack(">Q", read_exact(s, 8, buf))[0]
        payload = read_exact(s, n, buf)
        if b0 & 0x0F != 1:
            continue
        if payload.startswith(b'["EVENT"'):
            events += 1
            continue
        msg = json.loads(payload)
        if msg[0] in ("EOSE", "CLOSED") and msg[1] == sub:
            return events


def main():
    args = sys.argv[1:]
    loops = int(args[args.index("--loops") + 1]) if "--loops" in args else 1
    label = args[args.index("--label") + 1] if "--label" in args else ""
    host, port = args[0].rsplit(":", 1)
    filters = [json.loads(l) for l in open(args[1]) if l.strip()]
    s, buf = connect(host, port)
    for loop in range(loops):
        times, events = [], 0
        started = time.monotonic()
        for i, f in enumerate(filters):
            sub = f"r{i}"
            t = time.monotonic()
            s.sendall(frame(json.dumps(["REQ", sub, f])))
            events += until_eose(s, buf, sub)
            times.append(time.monotonic() - t)
            s.sendall(frame(json.dumps(["CLOSE", sub])))
        wall = time.monotonic() - started
        times.sort()
        ms = lambda x: f"{x * 1000:.2f}"
        print(f"{label}loop {loop + 1}: {len(times)} REQs, {events} events, mean {ms(sum(times) / len(times))} ms, "
              f"p50 {ms(times[len(times) // 2])}, p99 {ms(times[int(len(times) * 0.99)])}, max {ms(times[-1])} ms, "
              f"{len(times) / wall:.0f} REQ/s", flush=True)


if __name__ == "__main__":
    main()
