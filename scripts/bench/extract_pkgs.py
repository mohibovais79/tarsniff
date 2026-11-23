"""Read every archive in /data/exp_manifest.tsv IN MEMORY (nothing extracted, nothing executed)
and emit one JSON line per package with its text files ranked for the digest.

Runs inside the guarddog-scan container with --network none. Output goes to stdout as JSONL;
code only ever leaves the container as JSON string fields.

Per package:
  id, label, split, date, drop_reason (placeholder / no_code / unreadable / None)
  file_list: [[path, size]...]      all files (for the FILES section)
  pkg: filtered package.json (scripts/main/bin/dependencies... — no name/version/description)
  sections: [{path, prio, risk, text}]  text files in digest priority order
     prio 1 = run by an install hook, 2 = main/bin entry, 3 = other code (by risk score)
"""

import io
import json
import re
import sys
import tarfile
import zipfile
from pathlib import PurePosixPath

CODE_EXT = {".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".sh", ".py", ".ps1", ".bat", ".cmd", ".vbs", ".coffee"}
SKIP_RE = re.compile(r"(\.d\.ts$|\.map$|(^|/)(test|tests|__tests__|spec|docs?|examples?|benchmark)/|\.min\.css$)", re.I)
HOOKS = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare")
KEEP_PKG = ("scripts", "main", "bin", "module", "exports", "dependencies", "optionalDependencies",
            "peerDependencies", "bundleDependencies", "engines", "os", "cpu", "gypfile", "binary")
RISK = re.compile(
    r"child_process|\bexec(Sync)?\(|\bspawn(Sync)?\(|\beval\(|new Function|require\(['\"](https?|net|dns|tls|dgram)['\"]\)"
    r"|fetch\(|XMLHttpRequest|axios|\.ssh|\.npmrc|\.aws|\.env\b|process\.env|os\.(homedir|hostname|userInfo|networkInterfaces)"
    r"|Buffer\.from\([^)]*base64|atob\(|fromCharCode|\\x[0-9a-f]{2}|discord(app)?\.com/api/webhooks|webhook|curl |wget |powershell"
    r"|[A-Za-z0-9+/]{120,}={0,2}", re.I)
MAX_FILE_CHARS = 120_000
MAX_PKG_CHARS = 600_000


_OUTER = {}


def read_members(path):
    """Yield (relative_path, bytes) for regular files, stripped of archive prefixes.
    path may be "<outer.zip>::<member.tgz>" to read a tarball nested in a zip, in memory."""
    if "::" in path:
        outer, inner = path.split("::", 1)
        z = _OUTER.setdefault(outer, zipfile.ZipFile(outer))
        with tarfile.open(fileobj=io.BytesIO(z.read(inner)), mode="r:gz") as t:
            for m in t.getmembers():
                if not m.isfile() or m.size > 5_000_000:
                    continue
                yield m.name, t.extractfile(m).read(), m.size
        return
    if path.endswith(".zip"):
        z = zipfile.ZipFile(path)
        for i in z.infolist():
            if i.is_dir() or i.file_size > 5_000_000:
                continue
            yield i.filename, z.read(i, pwd=b"infected"), i.file_size
    else:
        with tarfile.open(path, "r:gz") as t:
            for m in t.getmembers():
                if not m.isfile() or m.size > 5_000_000:
                    continue
                yield m.name, t.extractfile(m).read(), m.size


def normalise(name):
    p = PurePosixPath(name).parts
    if "package" in p:  # npm tarballs / Datadog zips: .../package/<file>
        p = p[p.index("package") + 1:]
    elif len(p) > 1:
        p = p[1:]
    return "/".join(p)


def hook_targets(scripts, files):
    targets = []
    for h in HOOKS:
        cmd = scripts.get(h) or ""
        for tok in re.findall(r"[\w./@-]+\.(?:c?js|mjs|sh|py|ps1|bat)", cmd):
            tok = tok.lstrip("./")
            if tok in files:
                targets.append(tok)
        if re.search(r"\bnode\s+([\w./-]+)\b", cmd):
            t = re.search(r"\bnode\s+([\w./-]+)", cmd).group(1).lstrip("./")
            for cand in (t, t + ".js", t + "/index.js"):
                if cand in files and cand not in targets:
                    targets.append(cand)
    return targets


def process(row):
    pid, label, split, path, date = row
    if not path.startswith("/"):  # Datadog sample path relative to the sparse checkout
        path = "/data/ds/" + path
    rec = {"id": pid, "label": label, "split": split, "date": date, "drop_reason": None}
    try:
        members = [(normalise(n), b, s) for n, b, s in read_members(path)]
    except Exception as e:  # noqa: BLE001
        rec["drop_reason"] = f"unreadable: {type(e).__name__}"
        return rec
    # strip Datadog label-leaking metadata
    members = [m for m in members if not re.search(r"(^|/)package_info-.*\.json$", m[0]) and m[0]]
    files = {n: (b, s) for n, b, s in members}
    rec["file_list"] = sorted([[n, s] for n, (_, s) in files.items()])[:200]
    pkg = {}
    if "package.json" in files:
        try:
            pkg = json.loads(files["package.json"][0].decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            pkg = {}
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    rec["pkg"] = {k: pkg[k] for k in KEEP_PKG if k in pkg}
    if isinstance(rec["pkg"].get("scripts"), dict):  # only scripts that run on install/lifecycle matter most
        rec["pkg"]["scripts"] = {k: v for k, v in scripts.items()}

    code = {n: b for n, (b, _) in files.items()
            if PurePosixPath(n).suffix.lower() in CODE_EXT and not SKIP_RE.search(n)}
    has_hook_inline = any(scripts.get(h) for h in HOOKS)
    if not code and not has_hook_inline:
        rec["drop_reason"] = "no_code"
        return rec
    desc = str(pkg.get("description", "")).lower()
    if "security holding" in desc or str(pkg.get("version", "")).endswith("-security"):
        rec["drop_reason"] = "placeholder"
        return rec

    hooks = hook_targets(scripts, code)
    entries = []
    for e in [pkg.get("main") or "index.js"] + (list(pkg["bin"].values()) if isinstance(pkg.get("bin"), dict)
                                              else [pkg["bin"]] if isinstance(pkg.get("bin"), str) else []):
        if not isinstance(e, str):
            continue
        e = e.lstrip("./")
        for cand in (e, e + ".js", e + "/index.js"):
            if cand in code and cand not in entries and cand not in hooks:
                entries.append(cand)
                break
    sections, total = [], 0
    rest = [n for n in code if n not in hooks and n not in entries]

    def text_of(n):
        t = code[n].decode("utf-8", "replace")
        t = "\n".join(line for line in t.splitlines() if line.strip())
        return t[:MAX_FILE_CHARS]

    ranked = [(1, n) for n in hooks] + [(2, n) for n in entries]
    scored = []
    for n in rest:
        t = text_of(n)
        scored.append((len(RISK.findall(t)), -len(t), n, t))
    scored.sort(reverse=True)
    for prio, n in ranked:
        t = text_of(n)
        sections.append({"path": n, "prio": prio, "risk": len(RISK.findall(t)), "text": t})
        total += len(t)
    for risk, _, n, t in scored:
        if total > MAX_PKG_CHARS:
            break
        sections.append({"path": n, "prio": 3, "risk": risk, "text": t})
        total += len(t)
    rec["sections"] = sections
    rec["code_chars_total"] = sum(len(b) for b in code.values())
    return rec


def main(manifest="/data/exp_manifest.tsv"):
    for line in open(manifest):
        row = line.rstrip("\n").split("\t")
        sys.stdout.write(json.dumps(process(row)) + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:2])
