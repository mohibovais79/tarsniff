"""Build 1k-budget prompts for the whole NPMStudy benchmark (test only, no training).

Usage: python -I scripts/bench/build_bench_prompts.py <packages.jsonl> <out_dir> <tokenizer> [budget]
Uses the exact same prompt format as the ablation (build_sets.pieces/pack).
Order is interleaved malicious/benign (each shuffled, seed 7), so any prefix of the file is
balanced: the first 2,000 rows are a 1,000/1,000 sample, and the full run continues from there.
Packages with no code (drop_reason) are listed in no_code.jsonl, not prompted.
"""

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_sets import SYSTEM, pack, pieces  # noqa: E402
from transformers import AutoTokenizer  # noqa: E402


def main(src, out_dir, tok_name, budget=1024):
    tok = AutoTokenizer.from_pretrained(tok_name)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    by = {"malicious": [], "benign": []}
    nocode = []
    for line in open(src):
        r = json.loads(line)
        if r["drop_reason"]:
            nocode.append({"id": r["id"], "label": r["label"], "drop_reason": r["drop_reason"]})
            continue
        by[r["label"]].append(r)
    rng = random.Random(7)
    for v in by.values():
        rng.shuffle(v)
    order = []
    for i in range(max(map(len, by.values()))):
        for lab in ("malicious", "benign"):
            if i < len(by[lab]):
                order.append(by[lab][i])
    with open(out / "prompts.jsonl", "w") as fh:
        for k, r in enumerate(order):
            text, used, trunc = pack(tok, pieces(r, True), budget)
            fh.write(json.dumps({"id": r["id"], "label": r["label"], "truncated": trunc, "messages": [
                {"role": "system", "content": SYSTEM}, {"role": "user", "content": text}]}) + "\n")
            if (k + 1) % 1000 == 0:
                print(f"{k + 1}/{len(order)}", flush=True)
    (out / "no_code.jsonl").write_text("".join(json.dumps(x) + "\n" for x in nocode))
    print(f"prompts {len(order)} (mal {len(by['malicious'])}, ben {len(by['benign'])})  no_code {len(nocode)} "
          f"(mal {sum(x['label'] == 'malicious' for x in nocode)}, ben {sum(x['label'] == 'benign' for x in nocode)})")


if __name__ == "__main__":
    a = sys.argv[1:]
    main(a[0], a[1], a[2], *(int(x) for x in a[3:4]))
