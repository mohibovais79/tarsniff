"""Run mlx_lm.lora with a callback that records seconds/step, tokens/step and peak memory.

Usage: python scripts/bench/lora_bench.py <same args as mlx_lm.lora>
Set steps_per_report: 1 in the config to get every step.
"""

import json
import sys
import time

import mlx_lm.lora as lora
from mlx_lm.tuner.callbacks import TrainingCallback


class Recorder(TrainingCallback):
    def __init__(self):
        self.rows = []

    def on_train_loss_report(self, info):
        self.rows.append(info)
        it = info['iteration']; total = getattr(self, "total", 0) or it
        eta = (total - it) / info['iterations_per_second'] / 60
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] step {it:3d}/{total}  ETA {eta:.0f} min  loss {info['train_loss']:.3f}  "
              f"{1 / info['iterations_per_second']:.2f} s/step  "
              f"{info['tokens_per_second']:.0f} tok/s  peak {info['peak_memory']:.2f} GB", flush=True)


rec = Recorder()
rec.total = next((int(a.split("=")[-1] if "=" in a else sys.argv[i + 2]) for i, a in enumerate(sys.argv[1:]) if a.startswith("--iters")), 0)
lora.get_reporting_callbacks = lambda *a, **k: rec

t0 = time.perf_counter()
sys.argv = ["mlx_lm.lora", *sys.argv[1:]]
lora.main()
steps = [r for r in rec.rows if r["iteration"] > 1]  # step 1 includes compile/warm-up
sec = [1 / r["iterations_per_second"] for r in steps]
summary = {
    "steps": len(rec.rows),
    "sec_per_step_mean_excl_first": round(sum(sec) / len(sec), 2),
    "tokens_per_sec_mean": round(sum(r["tokens_per_second"] for r in steps) / len(steps)),
    "peak_memory_gb": round(max(r["peak_memory"] for r in rec.rows), 2),
    "final_loss": round(rec.rows[-1]["train_loss"], 3),
    "wall_total_sec": round(time.perf_counter() - t0, 1),
}
print("SUMMARY " + json.dumps(summary))
