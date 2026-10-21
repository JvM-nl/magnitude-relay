import json
vanished = {}
for line in open("all.jsonl", "rb"):
    if b'"kind":62,' not in line:
        continue
    e = json.loads(line)
    if e["kind"] == 62 and any(t[:2] == ["relay", "ALL_RELAYS"] for t in e["tags"]):
        vanished[e["pubkey"]] = max(vanished.get(e["pubkey"], 0), e["created_at"])
src = open("all.jsonl", "rb")
out = open("all-out2.jsonl", "rb")
o = out.readline()
missing = []
for line in src:
    e = json.loads(line)
    if 20000 <= e["kind"] < 30000:
        continue
    if o == line:
        o = out.readline()
    else:
        missing.append(e)
leftover = (1 if o else 0) + sum(1 for _ in out)
why = {"author vanished": 0, "wrap to vanished": 0, "other": 0}
for e in missing:
    ps = [t[1] for t in e["tags"] if len(t) > 1 and t[0] == "p"]
    if e["pubkey"] in vanished and e["created_at"] <= vanished[e["pubkey"]] and e["kind"] != 62:
        why["author vanished"] += 1
    elif e["kind"] == 1059 and any(p in vanished and e["created_at"] <= vanished[p] for p in ps):
        why["wrap to vanished"] += 1
    else:
        why["other"] += 1
print(f"vanish requests (ALL_RELAYS): {len(vanished)} authors; missing from ours: {len(missing)}; unmatched lines left in ours: {leftover}")
print(why, "(other = the 24 deletions strfry never applied)")
