#!/usr/bin/env python3
"""compare.py FILE.jsonl...  Side-by-side table of suite.sh results.

Every relay-bench result line (and suite.sh's footprint lines) is grouped by
workload and relay; a relay that ran a workload more than once (several rounds)
gets the median of each number. Prints one Markdown table: throughput and
latency per workload, the best value in bold. A result that returned wrong
answers is shown as "wrong" and never wins; one the relay does not support as
"n/a".
"""
import json
import statistics
import sys
from collections import defaultdict

ORDER = ["ours", "strfry", "ditto", "fastr"]

# (command, workload) -> how to read it: list of (column title, key path, higher_is_better, unit)
LOAD = [("ev/s", ("ops_per_s",), True, ""), ("p50", ("lat_us", "p50"), False, "ms"), ("p99", ("lat_us", "p99"), False, "ms")]
QUERY = [("q/s", ("ops_per_s",), True, ""), ("p50", ("lat_us", "p50"), False, "ms"), ("p99", ("lat_us", "p99"), False, "ms")]


def get(d, path):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def metrics(command, workload):
    if command == "footprint":
        return [("disk", ("disk_bytes",), False, "GB"), ("RSS", ("rss_kb",), False, "MBk")]
    if command == "idle":
        return [("conn/s", ("ops_per_s",), True, ""), ("bytes/conn", ("detail", "rss_per_conn_bytes"), False, "")]
    if command == "fanout":
        return [("deliv/s", ("ops_per_s",), True, ""), ("p50", ("lat_us", "p50"), False, "ms"), ("p99", ("lat_us", "p99"), False, "ms"), ("missed", ("detail", "missed"), False, "")]
    if command == "load":
        return LOAD
    return QUERY


def fmt(v, unit):
    if v is None:
        return "-"
    if unit == "ms":
        return f"{v / 1000:.2f}"
    if unit == "GB":
        return f"{v / 1e9:.2f} GB"
    if unit == "MBk":
        return f"{v / 1024:.0f} MB"
    if v >= 100:
        return f"{v:,.0f}"
    return f"{v:.1f}"


def main():
    runs = defaultdict(list)  # (command, workload, label) -> [record]
    keys = []
    for path in sys.argv[1:]:
        for line in open(path):
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            k = (d["command"], d["workload"])
            if k not in keys:
                keys.append(k)
            runs[(d["command"], d["workload"], d["label"])].append(d)
    labels = [l for l in ORDER if any(k[2] == l for k in runs)]
    print("| workload | metric | " + " | ".join(labels) + " |")
    print("|---|---|" + "---|" * len(labels))
    for command, workload in keys:
        for title, path, higher, unit in metrics(command, workload):
            cells = {}
            for l in labels:
                rs = runs.get((command, workload, l), [])
                if not rs:
                    cells[l] = (None, "-")
                    continue
                if any(r.get("supported") is False for r in rs):
                    cells[l] = (None, "n/a")
                    continue
                if any(not r.get("ok", True) or r.get("mismatches", 0) or r.get("errors", 0) for r in rs):
                    cells[l] = (None, "wrong")
                    continue
                vals = [v for v in (get(r, path) for r in rs) if v is not None]
                if not vals:
                    cells[l] = (None, "-")
                    continue
                v = statistics.median(vals)
                cells[l] = (v, fmt(v, unit))
            scored = [c[0] for c in cells.values() if c[0] is not None]
            best = (max(scored) if higher else min(scored)) if len(scored) > 1 else None
            row = [f"**{c[1]}**" if best is not None and c[0] == best else c[1] for c in (cells[l] for l in labels)]
            unit_note = " (ms)" if unit == "ms" else ""
            print(f"| {workload} | {title}{unit_note} | " + " | ".join(row) + " |")


if __name__ == "__main__":
    main()
