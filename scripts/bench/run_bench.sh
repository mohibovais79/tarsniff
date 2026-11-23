#!/usr/bin/env bash
# Score the whole NPMStudy benchmark with the 1k adapter. Resumable: just run this again.
# If the scorer crashes it is restarted automatically (up to 5 times); it resumes from scores.jsonl.
# Live log: bench/npmstudy/bench_run.log
set -uo pipefail
cd "$(dirname "$0")/../.."
L=bench/npmstudy/bench_run.log
for try in 1 2 3 4 5; do
  uv run python -u scripts/bench/bench_eval.py mlx-community/Qwen3-1.7B-4bit bench/abl/adapters/b1024 \
    bench/npmstudy/b1024/prompts.jsonl bench/npmstudy/b1024/scores.jsonl 25 2>&1 \
    | grep --line-buffered -vE "Warning|PyTorch|Fetching" >> $L
  tail -1 $L | grep -q BENCH_DONE && exit 0
  echo "[$(date '+%F %T')] scorer exited without finishing (attempt $try) - restarting in 30 s" >> $L
  sleep 30
done
