#!/usr/bin/env bash
# Scan the sample zips listed in /data/pick.txt (inside the npm-samples Docker volume)
# with GuardDog, offline, in a locked-down container. Only JSON results reach the host.
# Usage: docker/scan_samples.sh <host_results_dir> [jobs]
set -euo pipefail
out="$(mkdir -p "$1" && cd "$1" && pwd)"
jobs="${2:-8}"

docker run --rm \
  --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:size=4g --tmpfs /home/scanner/.cache \
  --memory 6g --pids-limit 512 \
  -v npm-samples:/data:ro \
  -v "$out":/out \
  --entrypoint bash guarddog-scan:3.2.0 -c '
scan() {
  p="$1"; name=$(echo "$p" | cut -d/ -f3,4,5 | tr "/@" "__")
  f="/out/$name.json"; [ -s "$f" ] && exit 0
  timeout 600 guarddog npm scan "/data/ds/$p" --zip-password infected --output-format json >"$f" 2>"/out/$name.err" || true
}
export -f scan
xargs -P '"$jobs"' -I{} bash -c "scan {}" < /data/pick.txt
'
