"""Evidence coverage: do GuardDog's flagged files/lines survive into each budget's digest?

Usage: python scripts/bench/coverage.py <gd_results_dir> <abl_root>
Per malicious validation package with >=1 GuardDog source-code finding:
  file-level: any flagged file appears as a "=== path ===" section in the prompt
  line-level: any flagged code snippet (first 50 non-space chars) appears in the prompt
threat-* findings are used when present, otherwise capability-* findings.
Caveat: partly circular — the digest ranks files with risky-API regexes similar to GuardDog's rules.
"""

import json
import re
import sys
from pathlib import Path

BUDGETS = ("pkgonly", "b1024", "b2048", "b4096")


def norm_path(loc):
    path = loc.rsplit(":", 1)[0]
    if "/package/" in path:
        return path.split("/package/", 1)[1]
    parts = path.split("/")
    return "/".join(parts[3:]) if len(parts) > 3 else path


def findings(d):
    threat, cap = [], []
    for rule, v in (d.get("results") or {}).items():
        if not isinstance(v, list):
            continue
        for x in v:
            if isinstance(x, dict) and "location" in x:
                (threat if rule.startswith("threat") else cap).append((norm_path(x["location"]), x.get("code") or ""))
    return threat or cap


def squash(s):
    return re.sub(r"\s+", "", s)


def main(gd_dir, root):
    prompts = {b: {} for b in BUDGETS}
    for b in BUDGETS:
        for line in open(Path(root) / b / "valid.jsonl"):
            ex = json.loads(line)
            prompts[b][ex["id"]] = ex["messages"][1]["content"]
    rows = []
    for f in Path(gd_dir).glob("*.json"):
        try:
            d = json.loads(f.read_text())
        except Exception:  # noqa: BLE001
            continue
        fs = findings(d)
        pid = next((k for k in prompts["b4096"] if k.startswith("mal::")
                    and re.sub(r"[/@]", "_", k[5:]) == f.stem), None)
        if pid is None or not fs:
            continue
        r = {"id": pid}
        for b in BUDGETS:
            p = prompts[b][pid]
            sp = squash(p)
            r[b + "_file"] = any(path == "package.json" or f"=== {path} ===" in p for path, _ in fs)
            r[b + "_line"] = any(code and squash(code)[:50] in sp for _, code in fs)
        rows.append(r)
    n = len(rows)
    print(f"malicious valid packages with GuardDog source findings: {n}")
    for b in BUDGETS:
        print(f"  {b:8} flagged file present {sum(r[b + '_file'] for r in rows) / n:6.1%}   "
              f"flagged line present {sum(r[b + '_line'] for r in rows) / n:6.1%}")
    Path(root, "coverage.json").write_text(json.dumps(rows, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:3])
