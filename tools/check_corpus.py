#!/usr/bin/env python3
"""Verify one synthetic-corpus batch: files exist, language matches folder,
length is in range, gold rows point at real files, no identifier shapes that
could be mistaken for real ones. Exit 0 = batch accepted."""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
batch = sys.argv[1]
gold = ROOT / "gold" / f"{batch}.jsonl"
errs = []

def lang_of(text):
    cyr = len(re.findall(r"[Ѐ-ӿ]", text))
    heb = len(re.findall(r"[֐-׿]", text))
    lat = len(re.findall(r"[A-Za-z]", text))
    tot = cyr + heb + lat or 1
    return max((("ru", cyr), ("he", heb), ("en", lat)), key=lambda x: x[1])[0], max(cyr, heb, lat) / tot

if not gold.exists():
    sys.exit(f"missing {gold}")
rows = [json.loads(l) for l in gold.read_text().splitlines() if l.strip()]
if len(rows) < 3:
    errs.append(f"gold: {len(rows)} rows, need >= 3")
docs = set()
for r in rows:
    for k in ("q", "lang", "expect", "kind"):
        if k not in r:
            errs.append(f"gold row missing {k}: {r}")
    for p in r.get("expect", []):
        if not (ROOT / p).exists():
            errs.append(f"gold expect not found: {p}")
        docs.add(p)
    if r.get("lang") not in ("ru", "en", "he"):
        errs.append(f"gold lang bad: {r.get('lang')}")

manifest = ROOT / "gold" / f"{batch}.files"
if not manifest.exists():
    sys.exit(f"missing {manifest} (one corpus path per line)")
paths = [l.strip() for l in manifest.read_text().splitlines() if l.strip()]
if len(paths) < 8:
    errs.append(f"manifest: {len(paths)} files, need >= 8")
for p in paths:
    f = ROOT / p
    if not f.exists():
        errs.append(f"missing {p}"); continue
    t = f.read_text(encoding="utf-8", errors="replace")
    words = len(t.split())
    if not 120 <= words <= 1200:
        errs.append(f"{p}: {words} words, want 120..1200")
    folder = f.parent.name
    l, share = lang_of(t)
    if l != folder or share < 0.7:
        errs.append(f"{p}: folder {folder} but text is {l} ({share:.0%})")
    if re.search(r"\b\d{9}\b", t):
        errs.append(f"{p}: 9-digit number (looks like a real ID); use 0XX-XXX-XXX style placeholders")
    if re.search(r"\b05\d[- ]?\d{7}\b", t):
        errs.append(f"{p}: real-shaped IL mobile number")
    if re.search(r"[\w.+-]+@(gmail|walla|hotmail|yahoo|outlook)\.", t):
        errs.append(f"{p}: real-provider email; use example.com")
    for m in re.finditer(r"[\w.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", t):
        dom = m.group(1).lower().rstrip(".")
        if dom not in ("example.com", "example.org", "example.net") and not dom.endswith(".example"):
            errs.append(f"{p}: e-mail domain {dom} is not a reserved example domain")
    if not t.lstrip().startswith("#"):
        errs.append(f"{p}: must start with a markdown heading")
if docs - set(paths):
    errs.append(f"gold points outside this batch: {docs - set(paths)}")
print(f"{batch}: {len(paths)} files, {len(rows)} gold rows")
if errs:
    print("\n".join(errs)); sys.exit(1)
