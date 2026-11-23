"""Summarize GuardDog JSON scan results: detection rates at score thresholds,
label counts, most frequent risks, and missed samples.

Usage: python scripts/summarize_scans.py <results_dir> [<results_dir> ...]
File names from docker/scan_samples.sh start with the dataset category
(malicious_intent_ / compromised_lib_); anything else is grouped as "other".
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

THRESHOLDS = (0.1, 5.0, 7.0)


def group_of(stem: str) -> str:
    for g in ("malicious_intent", "compromised_lib"):
        if stem.startswith(g):
            return g
    return "other"


def main(dirs):
    groups = defaultdict(list)
    errors = []
    for d in dirs:
        for f in sorted(Path(d).glob("*.json")):
            try:
                data = json.loads(f.read_text())
                score = data["risk_score"]["score"]
            except Exception:
                errors.append(f.stem)
                continue
            groups[group_of(f.stem)].append((f.stem, score, data))

    for g, rows in groups.items():
        n = len(rows)
        print(f"\n=== {g}: {n} scanned")
        for t in THRESHOLDS:
            hit = sum(1 for _, s, _ in rows if s >= t)
            print(f"  score >= {t:<4} : {hit:4d}/{n}  ({hit / n:.0%})")
        labels = Counter(d["risk_score"]["label"] for _, _, d in rows)
        print("  labels:", dict(labels.most_common()))
        risks = Counter(r["name"] for _, _, d in rows for r in {x["name"]: x for x in d["risks"]}.values())
        print("  top risks (packages containing):")
        for name, c in risks.most_common(8):
            print(f"    {c:4d}  {name}")
        missed = sorted((s, stem) for stem, s, _ in rows if s < 5.0)
        print(f"  below 5.0 ({len(missed)}), lowest first:")
        for s, stem in missed[:15]:
            print(f"    {s:4}  {stem}")

    if errors:
        print(f"\nunparseable/failed: {len(errors)}  e.g. {errors[:5]}")


if __name__ == "__main__":
    main(sys.argv[1:])
