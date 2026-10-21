#!/usr/bin/env python3
"""fold.py PROFILE_DIR [--top N] [--folded] [--callers TEXT] [--only WORKLOAD]

Summarises profile.sh's bpftrace maps: per workload, the share of samples spent in
each function itself (the leaf frame) and under it (anywhere on the stack), and per
crate. --callers TEXT shows, for functions whose name contains TEXT, the call
chains (three frames up) their samples came through. --folded also writes <workload>.folded (one "a;b;c count" line per stack, root
first) for flame graphs.
"""
import os
import re
import sys
from collections import Counter

HASH = re.compile(r"::h[0-9a-f]{16}$")
FRAME = re.compile(r"^\s*[0-9a-f]+ (.+?)\+\d+ \(")
BARE = re.compile(r"^\s*[0-9a-f]+ ([^ ]+) \(")


class V0:
    """Just enough of Rust's v0 symbol mangling to name a function: its path, with
    generic arguments dropped (so instances of one function count together)."""

    BASIC = "abcdefhijlmnostuvxyz"

    def __init__(self, s, at=0):
        self.s, self.i = s, at

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def take(self):
        c = self.peek()
        self.i += 1
        return c

    def base62(self):
        if self.peek() == "_":
            self.i += 1
            return 0
        n = 0
        while self.peek() != "_":
            c = self.take()
            n = n * 62 + ("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".index(c))
        self.i += 1
        return n + 1

    def ident(self):
        if self.peek() == "s":
            self.i += 1
            self.base62()
        if self.peek() == "u":
            self.i += 1
        j = self.i
        while self.peek().isdigit():
            self.i += 1
        n = int(self.s[j:self.i])
        if self.peek() == "_":
            self.i += 1
        out = self.s[self.i:self.i + n]
        self.i += n
        return out

    def backref(self, f):
        at = self.base62()
        return f(V0(self.s, at))

    def path(self):
        c = self.take()
        if c == "C":
            return self.ident()
        if c == "M":
            if self.peek() == "s":
                self.i += 1
                self.base62()
            self.path()
            return "<" + self.type() + ">"
        if c == "X":
            if self.peek() == "s":
                self.i += 1
                self.base62()
            self.path()
            t = self.type()
            return f"<{t} as {self.path()}>"
        if c == "Y":
            t = self.type()
            return f"<{t} as {self.path()}>"
        if c == "N":
            ns = self.take()
            parent = self.path()
            name = self.ident()
            if ns == "C":
                return parent + "::{closure}"
            if ns.isupper() and not name:
                return parent
            return parent + "::" + name
        if c == "I":
            p = self.path()
            while self.peek() != "E":
                self.generic()
            self.i += 1
            return p
        if c == "B":
            return self.backref(lambda q: q.path())
        raise ValueError(c)

    def generic(self):
        c = self.peek()
        if c == "L":
            self.i += 1
            self.base62()
        elif c == "K":
            self.i += 1
            self.const()
        else:
            self.type()

    def const(self):
        c = self.take()
        if c == "B":
            return self.backref(lambda q: q.const())
        if c == "p":
            return "_"
        while self.peek() != "_":
            self.i += 1
        self.i += 1
        return "k"

    def type(self):
        c = self.peek()
        if c and c in self.BASIC:
            self.i += 1
            return {"a": "i8", "b": "bool", "c": "char", "d": "f64", "e": "str", "f": "f32", "h": "u8", "i": "isize",
                    "j": "usize", "l": "i32", "m": "u32", "n": "i128", "o": "u128", "s": "i16", "t": "u16",
                    "u": "()", "v": "...", "x": "i64", "y": "u64", "z": "!"}[c]
        self.i += 1
        if c == "A":
            t = self.type()
            self.const()
            return f"[{t}; _]"
        if c == "S":
            return f"[{self.type()}]"
        if c == "T":
            ts = []
            while self.peek() != "E":
                ts.append(self.type())
            self.i += 1
            return "(" + ", ".join(ts) + ")"
        if c in "RQ":
            if self.peek() == "L":
                self.i += 1
                self.base62()
            return ("&" if c == "R" else "&mut ") + self.type()
        if c in "PO":
            return "*" + self.type()
        if c == "F":
            if self.peek() == "G":
                self.i += 1
                self.base62()
            if self.peek() == "U":
                self.i += 1
            if self.peek() == "K":
                self.i += 1
                if self.peek() == "C":
                    self.i += 1
                else:
                    self.ident()
            while self.peek() != "E":
                self.type()
            self.i += 1
            self.type()
            return "fn"
        if c == "D":
            if self.peek() == "G":
                self.i += 1
                self.base62()
            while self.peek() != "E":
                self.path()
                while self.peek() == "p":
                    self.i += 1
                    self.ident()
                    self.type()
            self.i += 1
            if self.peek() == "L":
                self.i += 1
                self.base62()
            return "dyn"
        if c == "B":
            return self.backref(lambda q: q.type())
        self.i -= 1
        return self.path()


def demangle(sym):
    if not sym.startswith("_R"):
        return sym
    try:
        out = V0(sym[2:]).path()
    except (ValueError, IndexError):
        return sym
    # A function inside an inherent impl: "<relay_store::version::Version>::query".
    return out


def name_of(line):
    m = FRAME.match(line) or BARE.match(line)
    if not m:
        return None
    sym = demangle(re.sub(r"\.\d+$", "", m.group(1)))
    return HASH.sub("", sym)


def read(path):
    stacks = Counter()
    frames = None
    for line in open(path, errors="replace"):
        if line.startswith("@["):
            frames = []
        elif frames is not None and line.startswith("]: "):
            if frames:
                stacks[tuple(reversed(frames))] += int(line[3:])
            frames = None
        elif frames is not None:
            n = name_of(line)
            if n:
                frames.append(n)
    return stacks


def crate(fn):
    head = fn.split("::")[0].lstrip("<").split(" as ")[0]
    if head.startswith("relay_"):
        return head
    if head in ("core", "alloc", "std", "hashbrown"):
        return "std"
    if head in ("tokio", "mio", "rustls", "ring", "secp256k1", "sha2"):
        return head
    if fn.startswith("__") or fn in ("memcpy", "memmove", "memset", "malloc", "free", "realloc") or "libc" in fn:
        return "libc"
    return "other"


def main():
    d = sys.argv[1]
    top = int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 25
    callers = sys.argv[sys.argv.index("--callers") + 1] if "--callers" in sys.argv else None
    only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
    for f in sorted(os.listdir(d)):
        if not f.endswith(".bt") or (only and f != only + ".bt"):
            continue
        stacks = read(os.path.join(d, f))
        total = sum(stacks.values())
        if not total:
            continue
        self_, incl, crates = Counter(), Counter(), Counter()
        for st, n in stacks.items():
            self_[st[-1]] += n
            crates[crate(st[-1])] += n
            for fn in set(st):
                incl[fn] += n
        w = f[:-3]
        print(f"\n######## {w}: {total} samples")
        print("  by crate (self): " + ", ".join(f"{c} {100 * n / total:.1f}%" for c, n in crates.most_common()))
        print("  -- self --")
        for fn, n in self_.most_common(top):
            print(f"  {100 * n / total:5.1f}%  {fn}")
        print("  -- inclusive (relay crates only) --")
        shown = 0
        for fn, n in incl.most_common():
            if crate(fn).startswith("relay_"):
                print(f"  {100 * n / total:5.1f}%  {fn}")
                shown += 1
                if shown == top:
                    break
        if callers:
            chains = Counter()
            for st, n in stacks.items():
                for i, fn in enumerate(st):
                    if callers in fn:
                        chains[" <- ".join(reversed(st[max(0, i - 3):i + 1]))] += n
                        break
            print(f"  -- call chains into *{callers}* --")
            for ch, n in chains.most_common(top):
                print(f"  {100 * n / total:5.1f}%  {ch}")
        if "--folded" in sys.argv:
            with open(os.path.join(d, w + ".folded"), "w") as out:
                for st, n in stacks.items():
                    out.write(";".join(st) + f" {n}\n")


if __name__ == "__main__":
    main()
