#!/usr/bin/env bash
# Scan a list of npm packages with GuardDog in parallel and print a score table.
# Usage: scripts/scan_batch.sh <out_dir> pkg1 pkg2 ...
# Env: JOBS (default 6)
set -uo pipefail
out="$1"; shift
mkdir -p "$out"
export out

scan_one() {
  local pkg="$1" f
  f="$out/$(echo "$pkg" | tr '/@' '__').json"
  [ -s "$f" ] && return 0
  guarddog npm scan "$pkg" --output-format json >"$f" 2>"${f%.json}.err" || true
}
export -f scan_one

printf '%s\n' "$@" | xargs -P "${JOBS:-6}" -I{} bash -c 'scan_one "$@"' _ {}

python3 - "$out" <<'EOF'
import json, sys, pathlib
rows = []
for f in sorted(pathlib.Path(sys.argv[1]).glob("*.json")):
    try:
        d = json.loads(f.read_text())
    except Exception:
        rows.append((f.stem, "ERR", "-", "-", "-")); continue
    rs = d.get("risk_score", {})
    risks = sorted({r["name"] for r in d.get("risks", [])})
    rows.append((d["package"], rs.get("score"), rs.get("label"), d.get("issues"), ", ".join(risks)))
rows.sort(key=lambda r: -(r[1] if isinstance(r[1], (int, float)) else -1))
print(f"{'package':28} {'score':>5}  {'label':18} {'issues':>6}  risks")
for p, s, l, i, r in rows:
    print(f"{p:28} {s!s:>5}  {l!s:18} {i!s:>6}  {r}")
EOF
