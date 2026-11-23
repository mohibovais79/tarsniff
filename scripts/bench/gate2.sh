#!/usr/bin/env bash
# Gate 2, unattended: wait for 2,000 benchmark scores -> stop the full run -> retrain 1k model with
# benchmark data (checkpoint every 50 steps, auto-resume) -> score the held-out 2,000 (resumable) -> compare.
# Live log: bench/gate2/gate2.log      Safe to re-run: every stage skips what is already done.
set -uo pipefail
cd "$(dirname "$0")/../.."
M=mlx-community/Qwen3-1.7B-4bit; G=bench/gate2; A=$G/adapter; L=$G/gate2.log; ITERS=$(wc -l < $G/train.jsonl)
log() { echo "[$(TZ=Asia/Karachi date '+%F %T PKT')] $*" >> $L; }

# 1) stop the full benchmark run once the balanced 2,000 are scored
while [ "$(wc -l < bench/npmstudy/b1024/scores.jsonl)" -lt 2000 ] && pgrep -f run_bench.sh >/dev/null; do sleep 20; done
pkill -f run_bench.sh; pkill -f bench_eval.py.*npmstudy/b1024; sleep 5
log "full run stopped at $(wc -l < bench/npmstudy/b1024/scores.jsonl) scored (resume later with scripts/bench/run_bench.sh)"
python3 scripts/bench/bench_compare.py bench/npmstudy/b1024/scores.jsonl 2000 $G/gate1.json >> $L 2>&1

# 2) train with checkpoints; after a crash resume from the newest checkpoint.
#    Each attempt writes to its own dir $A/tryN with an OFFSET file (steps done before it), because
#    mlx-lm restarts checkpoint numbering at 0 on resume.
best() {  # prints "<total_steps> <file>" of the newest checkpoint over all attempts
  for d in $A/try*; do [ -f $d/OFFSET ] || continue
    for f in $d/0*_adapters.safetensors; do [ -f "$f" ] || continue
      echo "$(( $(cat $d/OFFSET) + 10#$(basename $f | cut -d_ -f1) )) $f"; done; done | sort -n | tail -1; }
mkdir -p $A
for try in 1 2 3 4 5; do
  [ -f $A/TRAIN_DONE ] && break
  read -r done_steps last <<< "$(best)"; done_steps=${done_steps:-0}
  extra=(); [ -n "${last:-}" ] && extra=(--resume-adapter-file "$last")
  n=$((ITERS - done_steps)); D=$A/try$(( $(ls -d $A/try* 2>/dev/null | wc -l) + 1 )); mkdir -p $D; echo $done_steps > $D/OFFSET
  log "training attempt $try: $done_steps steps done, $n to go ${last:+(resume from $last)}"
  uv run python -u scripts/bench/lora_bench.py -c configs/lora_train.yaml --model $M --data $G \
     --adapter-path $D --iters $n --max-seq-length 1200 ${extra[@]+"${extra[@]}"} 2>&1 \
     | sed -l 's/\x1b\[[0-9;]*m//g' | grep --line-buffered -E "^\[|SUMMARY|Error|error|Traceback" >> $L
  if tail -3 $L | grep -q "^SUMMARY"; then cp $D/adapters.safetensors $D/adapter_config.json $A/; touch $A/TRAIN_DONE; log "training done"; break; fi
  log "training exited without finishing - retrying in 30 s"; sleep 30
done
[ -f $A/TRAIN_DONE ] || { log "GATE2_FAILED training"; exit 1; }

# 3) score the held-out 2,000 (resumable)
for try in 1 2 3; do
  uv run python -u scripts/bench/bench_eval.py $M $A $G/gate_test_prompts.jsonl $G/scores.jsonl 25 2>&1 \
    | grep --line-buffered -vE "Warning|PyTorch|Fetching" >> $L
  tail -1 $L | grep -q BENCH_DONE && break
done

# 4) compare: old model vs new model vs GuardDog vs IntelGuard, same 2,000 packages
log "=== OLD 1k model (gate 1) ==="; python3 scripts/bench/bench_compare.py bench/npmstudy/b1024/scores.jsonl 2000 >> $L 2>&1
log "=== NEW model trained with benchmark data (gate 2) ==="; python3 scripts/bench/bench_compare.py $G/scores.jsonl 2000 $G/gate2.json >> $L 2>&1
log "GATE2_DONE"
