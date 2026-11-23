"""Score validation prompts with P(malicious) from the verdict token and report metrics.

Usage: python scripts/bench/eval_verdict.py <model> <adapter_dir|-> <valid.jsonl> <meta.jsonl> <out.json>
Score = softmax over the first token of "malicious" vs "benign" after '{"verdict": "'.
Reports P/R/F1/FPR at 0.5, ROC-AUC, bootstrap 95% CI for F1, and the same on the
"long" subset (full package > 1024 tokens) where the budget can make a difference.
"""

import json
import random
import sys
import time

import mlx.core as mx
from mlx_lm import load


def first_diff_tokens(tok):
    a = tok.encode('{"verdict": "malicious"}', add_special_tokens=False)
    b = tok.encode('{"verdict": "benign"}', add_special_tokens=False)
    i = next(k for k in range(min(len(a), len(b))) if a[k] != b[k])
    assert a[:i] == b[:i]
    return a[:i], a[i], b[i]


def metrics(rows):
    tp = sum(r["y"] and r["p"] >= 0.5 for r in rows)
    fp = sum((not r["y"]) and r["p"] >= 0.5 for r in rows)
    fn = sum(r["y"] and r["p"] < 0.5 for r in rows)
    tn = sum((not r["y"]) and r["p"] < 0.5 for r in rows)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    pos = [r["p"] for r in rows if r["y"]]
    neg = [r["p"] for r in rows if not r["y"]]
    auc = (sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))) if pos and neg else None
    return {"n": len(rows), "pos": len(pos), "neg": len(neg), "precision": prec, "recall": rec, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "auc": auc}


def boot_f1(rows, n=1000):
    rng = random.Random(0)
    vals = sorted(metrics([rng.choice(rows) for _ in rows])["f1"] for _ in range(n))
    return [vals[int(0.025 * n)], vals[int(0.975 * n)]]


def main(model_id, adapter, valid, meta_path, out):
    model, tok = load(model_id, adapter_path=None if adapter == "-" else adapter)
    prefix, t_mal, t_ben = first_diff_tokens(tok)
    meta = {m["id"]: m for m in map(json.loads, open(meta_path))}
    rows, t0 = [], time.perf_counter()
    for line in open(valid):
        ex = json.loads(line)
        prompt = tok.apply_chat_template(ex["messages"][:2], add_generation_prompt=True, tokenize=False,
                                         enable_thinking=False)
        ids = tok.encode(prompt, add_special_tokens=False) + prefix
        logits = model(mx.array(ids)[None])[0, -1]
        two = mx.softmax(mx.stack([logits[t_mal], logits[t_ben]]).astype(mx.float32))
        p = two[0].item()
        rows.append({"id": ex["id"], "y": ex["messages"][2]["content"].find("malicious") >= 0, "p": p,
                     "full_tokens": meta[ex["id"]]["full_tokens"], "prompt_tokens": len(ids)})
    dt = time.perf_counter() - t0
    long_rows = [r for r in rows if r["full_tokens"] > 1024]
    res = {"model": model_id, "adapter": adapter, "valid": valid,
           "all": metrics(rows), "all_f1_ci95": boot_f1(rows),
           "long": metrics(long_rows), "long_f1_ci95": boot_f1(long_rows) if long_rows else None,
           "sec_per_pkg_scoring": dt / len(rows), "peak_mem_gb": mx.get_peak_memory() / 1e9, "rows": rows}
    json.dump(res, open(out, "w"), indent=1)
    s = lambda m: f"P {m['precision']:.3f} R {m['recall']:.3f} F1 {m['f1']:.3f} FPR {m['fpr']:.3f} AUC {m['auc'] or 0:.3f} (n={m['n']})"  # noqa: E731
    print(f"ALL  {s(res['all'])}  F1 95%CI {res['all_f1_ci95'][0]:.3f}-{res['all_f1_ci95'][1]:.3f}")
    if long_rows:
        print(f"LONG {s(res['long'])}  F1 95%CI {res['long_f1_ci95'][0]:.3f}-{res['long_f1_ci95'][1]:.3f}")
    print(f"{res['sec_per_pkg_scoring']:.2f} s/pkg (scoring only), peak {res['peak_mem_gb']:.2f} GB")


if __name__ == "__main__":
    main(*sys.argv[1:6])
