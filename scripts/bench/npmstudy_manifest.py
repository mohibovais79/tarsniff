"""Build /bench/bm_manifest.tsv for the NPMStudy benchmark (runs in container, offline).

Malicious: the 6,420 packages IntelGuard was scored on (label "malware" in its results),
           read as tarballs nested in NPMStudy.zip.
Benign:    tarballs fetched by fetch_npmstudy_benign.py (status ok).
Row: id, label, split("test"), path, ""   with id = "mal::<name>@<version>" / "ben::<name>@<version>",
     name using "/" for scopes, e.g. "@scope/pkg".
"""

import zipfile
from pathlib import Path

Z = "/bench/NPMStudy.zip"


def name_from_dir(d):
    # zip dirs encode "@scope/pkg" as "@scope##pkg"
    return d.replace("##", "/")


def main():
    z = zipfile.ZipFile(Z)
    tgz = {}
    for n in z.namelist():
        if n.startswith("NPMStudy/Dataset/zip_malware/") and n.endswith(".tgz"):
            _, _, _, d, ver, _ = n.split("/", 5)
            tgz[(name_from_dir(d), ver)] = n
    import json
    labelled = set()
    for n in z.namelist():
        if n.startswith("NPMStudy/Experiment/Results/IntelGuard/malware/") and n.endswith("result.json"):
            d = json.loads(z.read(n))
            labelled.add((name_from_dir(d["package_name"]), d["package_version"]))
    rows, missing = [], 0
    for key in sorted(labelled):
        if key in tgz:
            rows.append((f"mal::{key[0]}@{key[1]}", "malicious", "test", f"{Z}::{tgz[key]}", ""))
        else:
            missing += 1
    ok = {}
    for line in open("/bench/benign_fetch_log.tsv"):
        entry, status = line.rstrip("\n").split("\t")
        if status == "ok":
            d, ver, _ = entry.split("/", 2)
            name = ("@" + d[1:].split("@", 1)[0] + "/" + d[1:].split("@", 1)[1]) if d.startswith("@") else d
            ok[(name, ver)] = "/bench/benign/" + entry.replace("/", "__")
    for key, p in sorted(ok.items()):
        if Path(p).exists():
            rows.append((f"ben::{key[0]}@{key[1]}", "benign", "test", p, ""))
    with open("/bench/bm_manifest.tsv", "w") as fh:
        for r in rows:
            fh.write("\t".join(r) + "\n")
    print(f"malicious {sum(r[1] == 'malicious' for r in rows)} (labelled {len(labelled)}, no tgz {missing})  "
          f"benign {sum(r[1] == 'benign' for r in rows)}")


if __name__ == "__main__":
    main()
