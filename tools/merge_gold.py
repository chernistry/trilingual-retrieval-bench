#!/usr/bin/env python3
"""Merge gold/b*.jsonl into one set with absolute expect paths and ids."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
i = 0
for f in sorted(ROOT.glob("gold/b*.jsonl")):
    for line in f.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line); i += 1
        r["id"] = i
        doc_lang = r["expect"][0].split("/")[1] if r.get("expect") else r["lang"]
        r["slice"] = "xling" if doc_lang != r["lang"] else r["lang"]
        r["expect"] = [str(ROOT / p) for p in r["expect"]]
        r.setdefault("relevant", list(r["expect"]))
        print(json.dumps(r, ensure_ascii=False))
