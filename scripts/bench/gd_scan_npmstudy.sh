#!/usr/bin/env bash
# Run GuardDog 3.2.0 over the NPMStudy manifest, offline, inside the container.
# Nested malicious tarballs must first be copied (still compressed) to /bench/mal_tgz/ in the volume.
# Usage (inside container): gd_scan_npmstudy.sh <jobs>     results -> /out/<id>.json
set -uo pipefail
jobs="${1:-4}"

scan() {
  id="$1"; path="$2"
  safe=$(printf '%s' "$id" | sed 's#[/@:]#_#g')
  f="/out/$safe.json"; [ -s "$f" ] && return 0
  target="$path"
  if [[ "$path" == *"::"* ]]; then  # nested in NPMStudy.zip -> pre-copied by the one-off step
    inner="${path#*::}"; inner="${inner#NPMStudy/Dataset/zip_malware/}"
    target="/bench/mal_tgz/${inner//\//__}"
  fi
  timeout 600 guarddog npm scan "$target" --output-format json >"$f.part" 2>/dev/null; [ -s "$f.part" ] && mv "$f.part" "$f"
  rm -f "$f.part"
}
export -f scan

cut -f1,4 /bench/bm_manifest.tsv | tr '\t' ' ' | xargs -P "$jobs" -L1 bash -c 'scan "$0" "$1"'
echo GD_DONE
