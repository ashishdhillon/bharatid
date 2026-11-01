"""How often does each detector fire on ordinary English prompts (which should contain few Indian IDs)?
Usage: python -I scripts/fp_sanity.py CSV [CSV ...]   (public data: github.com/verazuo/jailbreak_llms)"""
import collections, csv, json, sys
from bharatid import scan

csv.field_size_limit(10 ** 8)
texts = []
for p in sys.argv[1:]:
    texts += [r["prompt"] for r in csv.DictReader(open(p, encoding="utf-8"))]
c = collections.Counter()
for t in texts:
    for m in scan(t):
        c[m.type] += 1
print(json.dumps({"prompts": len(texts), "matches_by_type": dict(c)}, indent=1))
