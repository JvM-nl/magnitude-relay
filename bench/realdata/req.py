#!/usr/bin/env python3
"""req.py HOST:PORT 'FILTER_JSON' [...]  One REQ, every answer printed as a line.

Standard library only (the box has no WebSocket client): a plain ws:// handshake,
masked text frames out, unfragmented frames in. Prints each EVENT's JSON, then the
EOSE/CLOSED line, and exits.
"""
import base64
import json
import os
import socket
import struct
import sys


def frame(text):
    data = text.encode()
    head = bytearray([0x81])
    n = len(data)
    if n < 126:
        head.append(0x80 | n)
    elif n < 65536:
        head += bytes([0x80 | 126]) + struct.pack(">H", n)
    else:
        head += bytes([0x80 | 127]) + struct.pack(">Q", n)
    mask = os.urandom(4)
    head += mask
    return bytes(head) + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def read_exact(s, n, buf):
    while len(buf) < n:
        chunk = s.recv(65536)
        if not chunk:
            raise EOFError("connection closed")
        buf += chunk
    out = bytes(buf[:n])
    del buf[:n]
    return out


def main():
    host, port = sys.argv[1].rsplit(":", 1)
    filters = [json.loads(f) for f in sys.argv[2:]]
    s = socket.create_connection((host, int(port)))
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        buf += s.recv(4096)
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    if b" 101 " not in head.split(b"\r\n")[0]:
        sys.exit(f"no upgrade: {head[:200]!r}")
    buf = bytearray(rest)
    s.sendall(frame(json.dumps(["REQ", "q"] + filters)))
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
        msg = json.loads(payload)
        if msg[0] == "EVENT":
            print(json.dumps(msg[2], separators=(",", ":")))
        else:
            print(json.dumps(msg))
            if msg[0] in ("EOSE", "CLOSED"):
                return


if __name__ == "__main__":
    main()
