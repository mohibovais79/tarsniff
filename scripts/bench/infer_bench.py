"""Time per-package inference: prompt (package code) -> short JSON verdict.

Usage: python scripts/bench/infer_bench.py <model> <test.jsonl> [max_tokens]
Prints per-example prompt tokens, generated tokens, wall seconds, and peak memory.
"""

import json
import sys
import time

import mlx.core as mx
from mlx_lm import load, stream_generate
from mlx_lm.sample_utils import make_sampler


def main(model_id: str, test_path: str, max_tokens: int = 80):
    model, tok = load(model_id)
    rows = [json.loads(line) for line in open(test_path)]
    sampler = make_sampler(temp=0.0)
    times = []
    for i, r in enumerate(rows):
        msgs = r["messages"][:2]
        prompt = tok.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False, enable_thinking=False)
        t0 = time.perf_counter()
        last = None
        text = ""
        for last in stream_generate(model, tok, prompt, max_tokens=max_tokens, sampler=sampler):
            text += last.text
        dt = time.perf_counter() - t0
        print(f"[{i}] prompt_tok={last.prompt_tokens} gen_tok={last.generation_tokens} "
              f"prefill={last.prompt_tps:.0f} tok/s decode={last.generation_tps:.1f} tok/s "
              f"wall={dt:.2f}s peak={last.peak_memory:.2f}GB  out={text[:70]!r}")
        if i > 0:  # first call includes warm-up
            times.append(dt)
    print(f"SUMMARY model={model_id} sec/pkg(mean, excl. warm-up)={sum(times)/len(times):.2f} "
          f"pkgs/hour={3600*len(times)/sum(times):.0f} peak_mem={mx.get_peak_memory()/1e9:.2f}GB")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], *(int(a) for a in sys.argv[3:]))
