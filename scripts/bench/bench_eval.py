"""Resumable benchmark scoring with a live log.

Usage: python -u scripts/bench/bench_eval.py <model> <adapter_dir> <prompts.jsonl> <scores.jsonl> [log_every]
- One JSON line per package is appended to <scores.jsonl> and flushed to disk (fsync) right away,
  so a crash/kill/power loss loses at most the package being scored.
- On start it re-reads <scores.jsonl>, drops a half-written last line, and skips packages already scored.
  To resume: run the exact same command again.
- Every <log_every> packages (default 25) it prints a timestamped line: progress, speed, ETA and running
  P/R/F1/FPR at threshold 0.5 over everything scored so far.
Score = P(malicious) from the verdict token, same method as eval_verdict.py.
"""

import json
import os
import sys
import time
from datetime import datetime

import mlx.core as mx
from mlx_lm import load

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from eval_verdict import first_diff_tokens  # noqa: E402


def log(msg):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def running(rows):
    tp = sum(r["y"] and r["p"] >= .5 for r in rows); fp = sum(not r["y"] and r["p"] >= .5 for r in rows)
    fn = sum(r["y"] and r["p"] < .5 for r in rows); tn = sum(not r["y"] and r["p"] < .5 for r in rows)
    p = tp / (tp + fp) if tp + fp else 0; rc = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * p * rc / (p + rc) if p + rc else 0
    return f"mal {tp + fn} ben {fp + tn} | P {p:.3f} R {rc:.3f} F1 {f1:.3f} FPR {fp / (fp + tn) if fp + tn else 0:.3f}"


def load_done(path):
    rows = []
    if not os.path.exists(path):
        return rows
    good = 0
    with open(path, "rb") as fh:
        data = fh.read()
    for line in data.splitlines(keepends=True):
        try:
            rows.append(json.loads(line)); good += len(line)
        except Exception:  # noqa: BLE001  half-written line from a crash
            break
    if good != len(data):
        log(f"dropping {len(data) - good} bytes of a half-written line")
        with open(path, "r+b") as fh:
            fh.truncate(good)
    return rows


def main(model_id, adapter, prompts, out, log_every=25):
    log_every = int(log_every)
    rows = load_done(out)
    done = {r["id"] for r in rows}
    todo = [json.loads(l) for l in open(prompts)]
    todo = [ex for ex in todo if ex["id"] not in done]
    log(f"start: {len(done)} already scored (resuming), {len(todo)} to go | model {model_id} adapter {adapter}")
    if rows:
        log(f"so far: {running(rows)}")
    model, tok = load(model_id, adapter_path=adapter)
    prefix, t_mal, t_ben = first_diff_tokens(tok)
    fh = open(out, "a")
    t0 = time.perf_counter()
    for k, ex in enumerate(todo, 1):
        prompt = tok.apply_chat_template(ex["messages"][:2], add_generation_prompt=True, tokenize=False,
                                         enable_thinking=False)
        ids = tok.encode(prompt, add_special_tokens=False) + prefix
        ts = time.perf_counter()
        logits = model(mx.array(ids)[None])[0, -1]
        p = mx.softmax(mx.stack([logits[t_mal], logits[t_ben]]).astype(mx.float32))[0].item()
        r = {"id": ex["id"], "y": ex["label"] == "malicious", "p": p, "prompt_tokens": len(ids),
             "truncated": ex.get("truncated"), "sec": round(time.perf_counter() - ts, 3)}
        fh.write(json.dumps(r) + "\n"); fh.flush(); os.fsync(fh.fileno())
        rows.append(r)
        if k == 1 or k % log_every == 0 or k == len(todo):
            el = time.perf_counter() - t0
            eta = el / k * (len(todo) - k)
            log(f"{len(rows)}/{len(rows) + len(todo) - k} | {el / k:.2f} s/pkg | ETA {eta / 3600:.1f} h | "
                f"{running(rows)} | peak {mx.get_peak_memory() / 1e9:.2f} GB")
    fh.close()
    log(f"BENCH_DONE {running(rows)}")


if __name__ == "__main__":
    main(*sys.argv[1:6])
