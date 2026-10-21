import json, random, collections, sys
random.seed(7)
until = int(open("synced_at").read())
recips = collections.Counter(); authors = collections.Counter(); kind_authors = collections.defaultdict(set); ids = []
for line in open("all.jsonl", "rb"):
    e = json.loads(line)
    k = e["kind"]
    if k == 1059:
        authors[e["pubkey"]] += 1
        for t in e["tags"]:
            if len(t) > 1 and t[0] == "p":
                recips[t[1]] += 1
    elif k in (0, 10050, 30078, 10002, 33302, 13303, 10063):
        kind_authors[k].add(e["pubkey"])
    if random.random() < 0.0002:
        ids.append(e["id"])
out = []
heavy = [r for r, _ in recips.most_common(20)]
multi = [r for r, c in recips.items() if c >= 3]
for r in heavy + random.sample(multi, min(280, len(multi))):
    out.append({"kinds": [1059], "#p": [r], "until": until, "limit": 500})
planes = [a for a, c in authors.most_common(400) if c >= 20]
for a in random.sample(planes, min(200, len(planes))):
    out.append({"kinds": [1059], "authors": [a], "until": until, "limit": 500})
for k, n in ((0, 150), (10050, 80), (30078, 80), (10002, 40), (33302, 40), (13303, 20), (10063, 20)):
    pool = list(kind_authors[k])
    for a in random.sample(pool, min(n, len(pool))):
        out.append({"kinds": [k], "authors": [a], "until": until, "limit": 100})
for i in range(0, len(ids) - 50, 50):
    out.append({"ids": ids[i:i+50]})
for k in (33302, 10050, 0):
    out.append({"kinds": [k], "until": until, "limit": 300})
random.shuffle(out)
with open("filters.jsonl", "w") as f:
    for x in out:
        f.write(json.dumps(x, separators=(",", ":")) + "\n")
print(len(out), "filters; until", until)
