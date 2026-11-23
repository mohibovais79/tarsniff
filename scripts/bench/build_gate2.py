"""Gate-2 data: old training set + benchmark packages that are kept apart from the gate test.

Test  = first 2,000 rows of bench/npmstudy/b1024/prompts.jsonl (the balanced gate sample, 1,000/1,000).
Train = old ablation train (300/300) + N_MAL/N_BEN benchmark rows from the rest, EXCLUDING any package whose
        name appears in the test set and any whose prompt text is identical to a test prompt.
Usage: python3 scripts/bench/build_gate2.py [n_mal] [n_ben]
"""
import hashlib
import json
import random
import sys
from pathlib import Path


def name(i):
    return i.split("::", 1)[1].rsplit("@", 1)[0]


def main(n_mal=200, n_ben=200):
    rows = [json.loads(l) for l in open("bench/npmstudy/b1024/prompts.jsonl")]
    test, rest = rows[:2000], rows[2000:]
    tnames = {name(r["id"]) for r in test}
    th = {hashlib.sha1(r["messages"][1]["content"].encode()).hexdigest() for r in test}
    pool = [r for r in rest if name(r["id"]) not in tnames
            and hashlib.sha1(r["messages"][1]["content"].encode()).hexdigest() not in th]
    print(f"rest {len(rest)}  after name/content exclusion {len(pool)}")
    rng = random.Random(11)
    pick = []
    for lab, n in (("malicious", int(n_mal)), ("benign", int(n_ben))):
        p = [r for r in pool if r["label"] == lab]; rng.shuffle(p); pick += p[:n]
        print(f"  {lab}: available {len(p)}, used {min(n, len(p))}")
    seen_names = set(); new = []
    for r in pick:  # one version per name, so one campaign/name cannot dominate
        if name(r["id"]) in seen_names:
            continue
        seen_names.add(name(r["id"]))
        new.append({"id": r["id"], "messages": r["messages"] + [
            {"role": "assistant", "content": json.dumps({"verdict": r["label"]})}]})
    old = [json.loads(l) for l in open("bench/abl/b1024/train.jsonl")]
    train = old + new; rng.shuffle(train)
    d = Path("bench/gate2"); d.mkdir(exist_ok=True)
    (d / "train.jsonl").write_text("".join(json.dumps(x) + "\n" for x in train))
    v = open("bench/abl/b1024/valid.jsonl").read().splitlines(keepends=True)[:20]
    (d / "valid.jsonl").write_text("".join(v)); (d / "test.jsonl").write_text("".join(v))
    (d / "gate_test_prompts.jsonl").write_text("".join(json.dumps(r) + "\n" for r in test))
    print(f"train {len(train)} = old {len(old)} + benchmark {len(new)} "
          f"(mal {sum('malicious' in x['messages'][2]['content'] for x in new)}, ben {sum('benign' in x['messages'][2]['content'] for x in new)})")


if __name__ == "__main__":
    main(*sys.argv[1:3])
