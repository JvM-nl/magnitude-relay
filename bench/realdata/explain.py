import json, re
diff = open("diff.out").read()
only_a = set(re.findall(r"only in a: \d+ ([0-9a-f,]*)", diff))
prefixes = set(p for grp in only_a for p in grp.split(",") if p)
vanish = {}
dels = {}
events = {}
for fn in ("all.jsonl", "delta.jsonl"):
    for line in open(fn, "rb"):
        e = json.loads(line)
        if e["kind"] == 62 and any(t[:2] == ["relay", "ALL_RELAYS"] for t in e["tags"]):
            vanish[e["pubkey"]] = max(vanish.get(e["pubkey"], 0), e["created_at"])
        if e["kind"] == 5:
            for t in e["tags"]:
                if len(t) > 1 and t[0] == "e":
                    dels.setdefault(t[1], set()).add(e["pubkey"])
        if e["id"][:12] in prefixes:
            events[e["id"][:12]] = e
for p in sorted(prefixes):
    e = events.get(p)
    if not e:
        print(p, "not found in exports (arrived after the sync)")
        continue
    ps = [t[1] for t in e["tags"] if len(t) > 1 and t[0] == "p"]
    why = []
    if e["pubkey"] in vanish and e["created_at"] <= vanish[e["pubkey"]]:
        why.append("author vanished (NIP-62)")
    if e["kind"] == 1059 and any(p2 in vanish and e["created_at"] <= vanish[p2] for p2 in ps):
        why.append("wrap to a vanished recipient")
    if e["id"] in dels and (e["pubkey"] in dels[e["id"]] or any(p2 in dels[e["id"]] for p2 in ps)):
        why.append("kind-5 deletion by " + ("author" if e["pubkey"] in dels[e["id"]] else "p-tagged recipient"))
    print(p, "kind", e["kind"], "->", "; ".join(why) or "UNEXPLAINED")
