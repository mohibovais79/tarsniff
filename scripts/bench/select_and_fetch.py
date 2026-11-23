"""Pick samples for the token-budget ablation and fetch them into the npm-samples volume.

Runs INSIDE the guarddog-scan container WITH network (fetch step only):
  - malicious: one version per package name from the Datadog npm list, split by date
      train = 2026-01..2026-05, valid = 2026-06..2026-10   (avoids same-campaign leakage)
    -> added to the existing sparse checkout at /data/ds
  - benign: random popular packages from GuardDog's top_npm_packages.json plus a fixed
    "tricky" list; latest tarball downloaded straight from the registry (never npm install)
    -> /data/benign/<safe_name>.tgz ; split random 70/30
Writes /data/exp_manifest.tsv : id, label, split, path, date

Usage (in container): python select_and_fetch.py N_MAL_TRAIN N_MAL_VALID N_BEN
"""

import json
import os
import random
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import guarddog

TRICKY = [
    "esbuild", "core-js", "sqlite3", "@swc/core", "next", "playwright", "bcrypt", "cypress",
    "nodemon", "ngrok", "node-sass", "webpack", "prisma", "dotenv", "node-gyp", "javascript-obfuscator",
    "typescript", "puppeteer", "electron", "husky", "sharp", "localtunnel", "cross-env", "@prisma/client",
    "canvas", "better-sqlite3", "protobufjs", "es5-ext", "fsevents", "nx", "turbo", "@sentry/cli",
    "msw", "lefthook", "deasync", "bufferutil", "utf-8-validate", "re2", "argon2", "keytar",
]


def pick_malicious(n_train, n_valid, rng):
    rows = [line.strip() for line in open("/data/npm_zips.txt")]
    by_split = {"train": {}, "valid": {}}
    for r in rows:
        m = re.search(r"/(\d{4}-\d{2}-\d{2})-", r)
        if not m:
            continue
        date = m.group(1)
        split = "train" if "2026-01" <= date[:7] <= "2026-05" else "valid" if "2026-06" <= date[:7] <= "2026-10" else None
        if split is None or "-security" in r:  # npm "security holding" placeholders
            continue
        name = r.split("/")[3]
        by_split[split].setdefault(name, []).append((r, date))
    out = []
    for split, n in (("train", n_train), ("valid", n_valid)):
        names = sorted(by_split[split])
        rng.shuffle(names)
        for name in names[:n]:
            path, date = rng.choice(by_split[split][name])
            out.append((f"mal::{name}", "malicious", split, path, date))
    return out


def fetch_benign(name):
    safe = name.replace("/", "__").replace("@", "_")
    dest = Path(f"/data/benign/{safe}.tgz")
    if dest.exists() and dest.stat().st_size > 0:
        return name, str(dest)
    try:
        url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
        meta = json.load(urllib.request.urlopen(url + "/latest", timeout=30))
        tarball = meta["dist"]["tarball"]
        if not tarball.startswith("https://registry.npmjs.org/"):
            return name, None
        data = urllib.request.urlopen(tarball, timeout=120).read()
        if len(data) > 60_000_000:
            return name, None
        dest.write_bytes(data)
        return name, str(dest)
    except Exception as e:  # noqa: BLE001
        print("benign fetch failed", name, e, file=sys.stderr)
        return name, None


def main(n_mal_train, n_mal_valid, n_ben):
    rng = random.Random(42)
    mal = pick_malicious(n_mal_train, n_mal_valid, rng)

    res = Path(os.path.dirname(guarddog.__file__)) / "analyzer/metadata/resources/top_npm_packages.json"
    top = json.load(open(res))["packages"]
    top = [p for p in top if p not in TRICKY]
    rng.shuffle(top)
    want = TRICKY + top[: n_ben - len(TRICKY)]

    # malicious: extend the sparse checkout (blobs fetched on demand)
    paths = [m[3] for m in mal]
    subprocess.run(["git", "-C", "/data/ds", "sparse-checkout", "add", "--stdin"],
                   input="\n".join(paths).encode(), check=True)

    Path("/data/benign").mkdir(exist_ok=True)
    with ThreadPoolExecutor(12) as ex:
        got = [g for g in ex.map(fetch_benign, want) if g[1]]
    ben = []
    for name, path in got:
        split = "valid" if rng.random() < 0.3 else "train"
        ben.append((f"ben::{name}", "benign", split, path, ""))

    with open("/data/exp_manifest.tsv", "w") as fh:
        for row in mal + ben:
            fh.write("\t".join(row) + "\n")
    print(f"malicious {len(mal)}  benign {len(ben)}/{len(want)}")


if __name__ == "__main__":
    main(*(int(a) for a in sys.argv[1:4]))
