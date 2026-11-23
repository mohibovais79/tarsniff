#!/usr/bin/env bash
# Train + evaluate Qwen3-1.7B LoRA at each token budget, one after another.
set -uo pipefail
M=mlx-community/Qwen3-1.7B-4bit
A=bench/abl
for spec in pkgonly:1200 b1024:1200 b2048:2200 b4096:4300; do
  b=${spec%%:*}; seq=${spec##*:}
  if [ ! -s $A/results_$b.json ]; then
    uv run python scripts/bench/lora_bench.py -c $A/lora_abl.yaml --model $M --data $A/$b \
      --adapter-path $A/adapters/$b --max-seq-length $seq 2>&1 | sed -l 's/\x1b\[[0-9;]*m//g' > $A/train_$b.log
    grep -E "^step|SUMMARY|Error" $A/train_$b.log | tail -3
    uv run python scripts/bench/eval_verdict.py $M $A/adapters/$b $A/$b/valid.jsonl $A/meta.jsonl $A/results_$b.json 2>&1 \
      | grep -vE "Warning|PyTorch" | tee $A/eval_$b.log
  fi
done
# zero-shot base model on the 4096 prompts, for reference
[ -s $A/results_base_b4096.json ] || uv run python scripts/bench/eval_verdict.py $M - $A/b4096/valid.jsonl $A/meta.jsonl $A/results_base_b4096.json 2>&1 | grep -vE "Warning|PyTorch" | tee $A/eval_base_b4096.log
echo ABLATION_DONE
