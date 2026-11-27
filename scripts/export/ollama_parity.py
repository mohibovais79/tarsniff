"""Score a validation set through Ollama (GGUF) and compare with the MLX scores.

Usage: python scripts/export/ollama_parity.py <valid.jsonl> <mlx_results.json> <out.json> [model]
Same score as eval_verdict.py: softmax over the first "malicious"/"benign" token after '{"verdict": "'.
"""
import json, math, sys, time, urllib.request

PREFIX = '{"verdict": "'


def render(msgs):
    s = "".join(f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>\n" for m in msgs)
    return s + "<|im_start|>assistant\n<think>\n\n</think>\n\n" + PREFIX


def score(msgs, model="tarsniff", host="http://localhost:11434"):
    body = {"model": model, "raw": True, "prompt": render(msgs), "stream": False,
            "options": {"num_predict": 1, "temperature": 0, "num_ctx": 4096},
            "logprobs": True, "top_logprobs": 20}
    req = urllib.request.Request(host + "/api/generate", json.dumps(body).encode(), {"Content-Type": "application/json"})
    d = json.load(urllib.request.urlopen(req, timeout=300))
    top = {t["token"]: t["logprob"] for t in d["logprobs"][0]["top_logprobs"]}
    lm, lb = top.get("mal", -30.0), top.get("ben", -30.0)
    return 1 / (1 + math.exp(lb - lm))


def main(valid, mlx_res, out, model="tarsniff"):
    ref = {r["id"]: r for r in json.load(open(mlx_res))["rows"]}
    rows, t0 = [], time.perf_counter()
    for line in open(valid):
        ex = json.loads(line)
        p = score(ex["messages"][:2], model)
        r = ref[ex["id"]]
        rows.append({"id": ex["id"], "y": r["y"], "p": p, "p_mlx": r["p"]})
    dt = (time.perf_counter() - t0) / len(rows)
    sys.path.insert(0, "scripts/bench")
    from eval_verdict import metrics
    agree = sum((r["p"] >= .5) == (r["p_mlx"] >= .5) for r in rows) / len(rows)
    mad = sum(abs(r["p"] - r["p_mlx"]) for r in rows) / len(rows)
    res = {"gguf": metrics(rows), "mlx": metrics([{**r, "p": r["p_mlx"]} for r in rows]),
           "verdict_agreement": agree, "mean_abs_diff_p": mad, "sec_per_pkg": dt, "rows": rows}
    json.dump(res, open(out, "w"), indent=1)
    f = lambda m: f"P {m['precision']:.3f} R {m['recall']:.3f} F1 {m['f1']:.3f} FPR {m['fpr']:.3f} AUC {m['auc']:.3f}"
    print("GGUF", f(res["gguf"])); print("MLX ", f(res["mlx"]))
    print(f"agreement {agree:.3f}  mean|dp| {mad:.3f}  {dt:.2f} s/pkg")


if __name__ == "__main__":
    main(*sys.argv[1:])
