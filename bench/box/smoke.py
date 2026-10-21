#!/usr/bin/env python3
"""Smoke test for one relay on 127.0.0.1:PORT. Standard library only (no pip).

  smoke.py PORT

Publishes one signed kind-1059 event (ephemeral author, one p tag), then reads it back
without AUTH by #p, by authors, by ids and by a kindless #p, and sends a minimal NEG-OPEN.
Prints one result line per check, then a one-line summary.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import sys
import time
import urllib.request

# ---- BIP-340 Schnorr (reference implementation, pure Python; one signature is fast enough)
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def padd(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def pmul(pt, k):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = padd(r, pt)
        pt = padd(pt, pt)
    return r


def th(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def sign(msg, sk, aux):
    d0 = int.from_bytes(sk, "big")
    pub = pmul(G, d0)
    d = d0 if pub[1] % 2 == 0 else N - d0
    t = (d ^ int.from_bytes(th("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(th("BIP0340/nonce", t + pub[0].to_bytes(32, "big") + msg), "big") % N
    r = pmul(G, k0)
    k = k0 if r[1] % 2 == 0 else N - k0
    e = int.from_bytes(th("BIP0340/challenge", r[0].to_bytes(32, "big") + pub[0].to_bytes(32, "big") + msg), "big") % N
    return r[0].to_bytes(32, "big") + ((k + e * d) % N).to_bytes(32, "big")


def verify(msg, pk32, sig):
    x = int.from_bytes(pk32, "big")
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if y * y % P != y2:
        return False
    pub = (x, y if y % 2 == 0 else P - y)
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    e = int.from_bytes(th("BIP0340/challenge", sig[:32] + pk32 + msg), "big") % N
    pt = padd(pmul(G, s), pmul(pub, N - e))
    return pt is not None and pt[1] % 2 == 0 and pt[0] == r


def make_event(kind, tags, content, sk):
    pk = pmul(G, int.from_bytes(sk, "big"))[0].to_bytes(32, "big")
    created = int(time.time())
    ser = json.dumps([0, pk.hex(), created, kind, tags, content], separators=(",", ":"), ensure_ascii=False)
    eid = hashlib.sha256(ser.encode()).digest()
    sig = sign(eid, sk, os.urandom(32))
    assert verify(eid, pk, sig), "self-check: signature does not verify"
    return {"id": eid.hex(), "pubkey": pk.hex(), "created_at": created, "kind": kind,
            "tags": tags, "content": content, "sig": sig.hex()}


# ---- minimal RFC 6455 client (no extensions offered, so no compression)
class WS:
    def __init__(self, port):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
                        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                        f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise IOError("closed during handshake")
            buf += chunk
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise IOError("handshake failed: " + head.split(b"\r\n")[0].decode())

    def _need(self, n, deadline):
        while len(self.buf) < n:
            left = deadline - time.time()
            if left <= 0:
                raise socket.timeout()
            self.s.settimeout(left)
            chunk = self.s.recv(65536)
            if not chunk:
                raise IOError("connection closed")
            self.buf += chunk

    def send(self, obj):
        data = json.dumps(obj, separators=(",", ":")).encode()
        mask = os.urandom(4)
        n = len(data)
        hdr = b"\x81" + (bytes([0x80 | n]) if n < 126 else b"\xfe" + struct.pack(">H", n) if n < 65536
                         else b"\xff" + struct.pack(">Q", n))
        self.s.sendall(hdr + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self, timeout):
        """Next text frame as parsed JSON, or None on timeout."""
        deadline = time.time() + timeout
        try:
            while True:
                self._need(2, deadline)
                b0, b1 = self.buf[0], self.buf[1]
                n, off = b1 & 0x7F, 2
                if n == 126:
                    self._need(4, deadline); n, off = struct.unpack(">H", self.buf[2:4])[0], 4
                elif n == 127:
                    self._need(10, deadline); n, off = struct.unpack(">Q", self.buf[2:10])[0], 10
                self._need(off + n, deadline)
                payload, self.buf = self.buf[off:off + n], self.buf[off + n:]
                op = b0 & 0x0F
                if op == 9:  # ping -> pong
                    self.s.sendall(b"\x8a\x80" + os.urandom(4))
                elif op == 8:
                    raise IOError("server closed the websocket")
                elif op in (1, 0):
                    return json.loads(payload.decode())
        except socket.timeout:
            return None

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def read_req(ws, sub, filt, timeout=6):
    """Send a REQ, return (events, terminal) where terminal is EOSE / CLOSED:reason / NO-REPLY."""
    ws.send(["REQ", sub, filt])
    events, extra = [], []
    end = time.time() + timeout
    while time.time() < end:
        m = ws.recv(max(0.05, end - time.time()))
        if m is None:
            return events, "NO-REPLY", extra
        if m[0] == "EVENT" and m[1] == sub:
            events.append(m[2])
        elif m[0] == "EOSE" and m[1] == sub:
            ws.send(["CLOSE", sub])
            return events, "EOSE", extra
        elif m[0] == "CLOSED" and m[1] == sub:
            return events, "CLOSED:" + (m[2] if len(m) > 2 else ""), extra
        else:
            extra.append(m[0] + (":" + str(m[1])[:40] if len(m) > 1 else ""))
    return events, "NO-REPLY", extra


def main():
    port = int(sys.argv[1])
    out = {}
    # NIP-11
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", headers={"Accept": "application/nostr+json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            doc = json.loads(r.read().decode())
        out["nip11"] = "ok name=%r software=%r version=%r nips=%s" % (
            doc.get("name"), doc.get("software"), doc.get("version"), doc.get("supported_nips"))
        out["nip11_limitation"] = json.dumps(doc.get("limitation"), sort_keys=True)
    except Exception as e:  # noqa
        out["nip11"] = "FAIL " + repr(e)

    sk, rsk = os.urandom(32), os.urandom(32)
    recipient = pmul(G, int.from_bytes(rsk, "big"))[0].to_bytes(32, "big").hex()
    ev = make_event(1059, [["p", recipient]], base64.b64encode(os.urandom(120)).decode(), sk)

    ws = WS(port)
    first = ws.recv(0.4)  # some relays greet with an AUTH challenge
    if first:
        out["greeting"] = json.dumps(first)[:100]
    ws.send(["EVENT", ev])
    ok = None
    end = time.time() + 6
    while time.time() < end:
        m = ws.recv(max(0.05, end - time.time()))
        if m is None:
            break
        if m[0] == "OK" and m[1] == ev["id"]:
            ok = m
            break
    out["publish"] = ("accepted" if ok and ok[2] else "REJECTED") + (" " + json.dumps(ok[3:]) if ok and len(ok) > 3 else "") \
        if ok else "NO OK REPLY"
    time.sleep(0.3)

    checks = [
        ("by_#p", {"kinds": [1059], "#p": [recipient]}),
        ("by_authors", {"kinds": [1059], "authors": [ev["pubkey"]]}),
        ("by_authors_nokind", {"authors": [ev["pubkey"]]}),
        ("by_ids", {"ids": [ev["id"]]}),
        ("by_#p_nokind", {"#p": [recipient]}),
    ]
    for label, filt in checks:
        evs, term, extra = read_req(ws, "t-" + label.replace("#", "h"), filt)
        got = any(e.get("id") == ev["id"] for e in evs)
        out[label] = ("YES" if got else "NO") + f" ({len(evs)} events, {term}" + (f", also {extra}" if extra else "") + ")"

    # NEG-OPEN: empty-set initial message = 61 | 00 (bound: infinity) | 00 (prefix len) | 02 (IdList) | 00 (0 ids)
    def neg_probe(sub, filt):
        ws.send(["NEG-OPEN", sub, filt, "6100000200"])
        reply, end = None, time.time() + 4
        seen = []
        while time.time() < end:
            m = ws.recv(max(0.05, end - time.time()))
            if m is None:
                break
            if m[0] in ("NEG-MSG", "NEG-ERR") and m[1] == sub:
                reply = m
                break
            seen.append(m[0])
        if reply is None:
            return "NOTHING" + (f" (saw {seen})" if seen else "")
        if reply[0] == "NEG-MSG":
            ws.send(["NEG-CLOSE", sub])
            return "NEG-MSG (%d hex chars; test event id %s in reply)" % (
                len(reply[2]), "PRESENT" if ev["id"] in reply[2] else "absent")
        return "NEG-ERR " + json.dumps(reply[2:])[:90]

    out["neg_open"] = neg_probe("n1", {"kinds": [1059]})
    out["neg_open_authors"] = neg_probe("n2", {"kinds": [1059], "authors": [ev["pubkey"]]})
    ws.close()

    for k, v in out.items():
        print(f"  {k:18s} {v}")
    print("SUMMARY port=%d publish=%s #p=%s authors=%s ids=%s neg(kinds)=%s neg(authors)=%s" % (
        port, out["publish"].split()[0], out["by_#p"].split()[0], out["by_authors"].split()[0],
        out["by_ids"].split()[0], out["neg_open"].split()[0], out["neg_open_authors"].split()[0]))


if __name__ == "__main__":
    main()
