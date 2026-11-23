"""Pack extracted packages into prompts at several token budgets for the ablation.

Usage: python -I scripts/bench/build_sets.py <packages.jsonl> <out_root> <tokenizer> [n_per_class_train] [n_per_class_valid]
Budgets: pkgonly (file list + filtered package.json, no code), 1024, 2048, 4096 user-content tokens.
The same packages (same order) are used at every budget. Name/version/description are never shown.
Duplicates (same 4096-token digest) are removed; valid items duplicating a train item are dropped.
"""

import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

from transformers import AutoTokenizer

SYSTEM = ("You are an npm supply-chain security analyst. Given the contents of an npm package, "
          "decide if it is malicious. Respond with JSON only.")
BUDGETS = {"pkgonly": 1024, "b1024": 1024, "b2048": 2048, "b4096": 4096}


def pieces(rec, with_code):
    fl = rec.get("file_list", [])
    head = "FILES (%d):\n" % len(fl) + "\n".join(f"{p} ({s} B)" for p, s in fl[:40])
    if len(fl) > 40:
        head += f"\n... {len(fl) - 40} more"
    out = [head, "\n\n=== package.json (name/version/description removed) ===\n" + json.dumps(rec.get("pkg", {}), indent=1)]
    if with_code:
        for s in rec["sections"]:
            out.append(f"\n\n=== {s['path']} ===\n{s['text']}")
    return out


def pack(tok, parts, budget):
    used, out, truncated = 0, [], False
    for p in parts:
        ids = tok.encode(p, add_special_tokens=False)
        room = budget - used
        if room <= 16:
            truncated = True
            break
        if len(ids) > room:
            out.append(tok.decode(ids[: room - 8]) + "\n...[truncated]")
            used = budget
            truncated = True
            break
        out.append(p)
        used += len(ids)
    return "".join(out), used, truncated


def main(src, out_root, tok_name, n_train=300, n_valid=150):
    tok = AutoTokenizer.from_pretrained(tok_name)
    recs = [json.loads(line) for line in open(src)]
    drops = Counter(r["drop_reason"] for r in recs if r["drop_reason"])
    recs = [r for r in recs if not r["drop_reason"]]
    print("dropped:", dict(drops), " kept:", len(recs))

    # full (unbudgeted) size in tokens, and dedupe on the 4096 digest
    seen, kept = {}, []
    for r in recs:
        full = "".join(pieces(r, True))
        r["full_tokens"] = len(tok.encode(full[:400_000], add_special_tokens=False))
        h = hashlib.sha1(pack(tok, pieces(r, True), 4096)[0].encode()).hexdigest()
        if h in seen and (seen[h] == "train" or r["split"] == seen[h]):
            continue
        seen[h] = r["split"]
        kept.append(r)
    print("after dedupe:", len(kept))

    rng = random.Random(7)
    chosen = []
    for split, n in (("train", n_train), ("valid", n_valid)):
        for label in ("malicious", "benign"):
            pool = [r for r in kept if r["split"] == split and r["label"] == label]
            rng.shuffle(pool)
            chosen += pool[:n]
            print(f"{split:5} {label:9} available {len(pool):4}  used {min(n, len(pool))}")
    rng.shuffle(chosen)

    meta = []
    for name, budget in BUDGETS.items():
        d = Path(out_root) / name
        d.mkdir(parents=True, exist_ok=True)
        files = {s: open(d / f"{s}.jsonl", "w") for s in ("train", "valid")}
        for r in chosen:
            text, used, trunc = pack(tok, pieces(r, name != "pkgonly"), budget)
            ans = json.dumps({"verdict": r["label"]})
            files[r["split"]].write(json.dumps({"id": r["id"], "messages": [
                {"role": "system", "content": SYSTEM},
                {"role": "user", "content": text},
                {"role": "assistant", "content": ans}]}) + "\n")
            if name == "b4096":
                meta.append({"id": r["id"], "label": r["label"], "split": r["split"], "full_tokens": r["full_tokens"]})
        for f in files.values():
            f.close()
        # mlx-lm requires a test file; reuse valid
        (d / "test.jsonl").write_text((d / "valid.jsonl").read_text())
    Path(out_root, "meta.jsonl").write_text("".join(json.dumps(m) + "\n" for m in meta))

    for split in ("train", "valid"):
        for label in ("malicious", "benign"):
            ft = sorted(m["full_tokens"] for m in meta if m["split"] == split and m["label"] == label)
            if ft:
                q = lambda p: ft[min(len(ft) - 1, int(p * len(ft)))]  # noqa: E731
                print(f"full tokens {split:5} {label:9} n={len(ft):3} p50={q(.5)} p75={q(.75)} p90={q(.9)} "
                      f"<=1k {sum(x <= 1024 for x in ft) / len(ft):.0%} <=2k {sum(x <= 2048 for x in ft) / len(ft):.0%} "
                      f"<=4k {sum(x <= 4096 for x in ft) / len(ft):.0%}")


if __name__ == "__main__":
    a = sys.argv[1:]
    main(a[0], a[1], a[2], *(int(x) for x in a[3:]))
