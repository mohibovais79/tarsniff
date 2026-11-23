"""Compare our model with GuardDog 3.2.0 and IntelGuard on exactly the same benchmark packages.

Usage: python3 scripts/bench/bench_compare.py <scores.jsonl> [first_n] [out.json]
first_n: only the first N scored rows (e.g. 2000 = the balanced gate sample).
GuardDog verdict: risk_score >= 5 (our own scans). IntelGuard: is_malicious from its published results;
IntelGuard rows with status != success count as "not flagged" (same as the paper's FN for no_js_files).
Our model: threshold 0.5, plus recall at GuardDog's false-alarm rate (threshold chosen on these same rows:
optimistic, for diagnosis only).
"""

import json
import random
import re
import sys
from pathlib import Path

GD = Path("bench/npmstudy/gd")


def split_id(i):
    name, ver = i.split("::", 1)[1].rsplit("@", 1)
    return name, ver


def prf(ys, preds):
    tp = sum(y and p for y, p in zip(ys, preds)); fp = sum((not y) and p for y, p in zip(ys, preds))
    fn = sum(y and not p for y, p in zip(ys, preds)); tn = sum((not y) and not p for y, p in zip(ys, preds))
    P = tp / (tp + fp) if tp + fp else 0; R = tp / (tp + fn) if tp + fn else 0
    return {"P": P, "R": R, "F1": 2 * P * R / (P + R) if P + R else 0, "FPR": fp / (fp + tn) if fp + tn else 0,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def auc(ys, ss):
    pos = sorted(s for y, s in zip(ys, ss) if y); neg = sorted(s for y, s in zip(ys, ss) if not y)
    import bisect
    return sum(bisect.bisect_left(neg, x) + .5 * (bisect.bisect_right(neg, x) - bisect.bisect_left(neg, x))
               for x in pos) / (len(pos) * len(neg))


def ci(ys, preds, n=1000):
    rng = random.Random(0); idx = range(len(ys)); v = []
    for _ in range(n):
        s = [rng.choice(idx) for _ in idx]
        v.append(prf([ys[i] for i in s], [preds[i] for i in s])["F1"])
    v.sort(); return v[int(.025 * n)], v[int(.975 * n)]


def main(scores, first_n=None, out=None):
    rows = [json.loads(l) for l in open(scores)]
    if first_n:
        rows = rows[:int(first_n)]
    ig = {(r["name"], r["version"]): r for r in json.load(open("bench/npmstudy/intelguard_verdicts.json"))}
    ys, ours, gd, igv, gds, keep = [], [], [], [], [], []
    miss = {"gd": 0, "ig": 0}
    for r in rows:
        f = GD / (re.sub(r"[/@:]", "_", r["id"]) + ".json")
        k = split_id(r["id"]); g = ig.get(k) or ig.get((k[0].replace("/", "##"), k[1]))
        if not f.exists():
            miss["gd"] += 1; continue
        if g is None:
            miss["ig"] += 1; continue
        s = json.loads(f.read_text())["risk_score"]["score"]
        ys.append(r["y"]); ours.append(r["p"]); gds.append(s); gd.append(s >= 5)
        igv.append(bool(g["is_malicious"]) and g["status"] == "success"); keep.append(r)
    res = {"n": len(ys), "mal": sum(ys), "ben": len(ys) - sum(ys), "missing": miss}
    res["ours@0.5"] = prf(ys, [p >= .5 for p in ours]); res["ours@0.5"]["F1_ci95"] = ci(ys, [p >= .5 for p in ours])
    res["ours_auc"] = auc(ys, ours)
    res["guarddog>=5"] = prf(ys, gd); res["guarddog>=5"]["F1_ci95"] = ci(ys, gd); res["guarddog_auc"] = auc(ys, gds)
    res["intelguard"] = prf(ys, igv); res["intelguard"]["F1_ci95"] = ci(ys, igv)
    neg = sorted((p for y, p in zip(ys, ours) if not y), reverse=True)
    t = neg[int(res["guarddog>=5"]["FPR"] * len(neg))]
    res["ours_at_guarddog_fpr"] = {"threshold": t, **prf(ys, [p > t for p in ours])}
    fmt = lambda m: f"P {m['P']:.3f} R {m['R']:.3f} F1 {m['F1']:.3f} FPR {m['FPR']:.3f}"  # noqa: E731
    print(f"n={res['n']} (mal {res['mal']}, ben {res['ben']})  skipped {miss}")
    print(f"ours @0.5        {fmt(res['ours@0.5'])}  F1 CI {res['ours@0.5']['F1_ci95'][0]:.3f}-{res['ours@0.5']['F1_ci95'][1]:.3f}  AUC {res['ours_auc']:.3f}")
    print(f"ours @GD FPR     {fmt(res['ours_at_guarddog_fpr'])}  (threshold {t:.3f}, tuned on these rows)")
    print(f"GuardDog >=5     {fmt(res['guarddog>=5'])}  F1 CI {res['guarddog>=5']['F1_ci95'][0]:.3f}-{res['guarddog>=5']['F1_ci95'][1]:.3f}  AUC {res['guarddog_auc']:.3f}")
    print(f"IntelGuard       {fmt(res['intelguard'])}  F1 CI {res['intelguard']['F1_ci95'][0]:.3f}-{res['intelguard']['F1_ci95'][1]:.3f}")
    if out:
        Path(out).write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    main(*sys.argv[1:4])
