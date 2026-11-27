"""Turn an npm tarball into the text digest the model was trained on.

Same logic as scripts/bench/extract_pkgs.py + build_sets.py (training/eval), so the prompt
the CLI sends matches what the model saw during fine-tuning. The archive is read IN MEMORY:
nothing is extracted to disk and nothing from the package is ever executed.
"""

import io
import json
import re
import tarfile
from pathlib import PurePosixPath

SYSTEM = ("You are an npm supply-chain security analyst. Given the contents of an npm package, "
          "decide if it is malicious. Respond with JSON only.")
BUDGET = 1024  # user-content tokens; the budget the shipped model was trained and validated with

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

# Safety caps for untrusted archives (decompression bombs, huge packages).
MAX_MEMBER_BYTES = 5_000_000        # files above this are skipped (same as training)
MAX_TOTAL_BYTES = 300_000_000       # stop reading if declared uncompressed size passes this
MAX_MEMBERS = 20_000


class ArchiveTooLarge(Exception):
    pass


def read_tarball(data: bytes):
    """Return [(path, bytes, size)] for regular files in a .tgz, read in memory with caps."""
    out, total = [], 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for k, m in enumerate(t):
            if k >= MAX_MEMBERS:
                raise ArchiveTooLarge(f"more than {MAX_MEMBERS} entries")
            if not m.isfile():
                continue
            total += m.size
            if total > MAX_TOTAL_BYTES:
                raise ArchiveTooLarge(f"unpacked size over {MAX_TOTAL_BYTES // 1_000_000} MB")
            if m.size > MAX_MEMBER_BYTES:
                out.append((m.name, None, m.size))
                continue
            out.append((m.name, t.extractfile(m).read(), m.size))
    return out


def normalise(name):
    p = PurePosixPath(name).parts
    if "package" in p:
        p = p[p.index("package") + 1:]
    elif len(p) > 1:
        p = p[1:]
    return "/".join(p)


def hook_targets(scripts, files):
    targets = []
    for h in HOOKS:
        cmd = scripts.get(h) or ""
        if not isinstance(cmd, str):
            continue
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


def extract(members):
    """members: [(path, bytes|None, size)] -> record dict (same fields as extract_pkgs.process)."""
    members = [(normalise(n), b, s) for n, b, s in members]
    members = [m for m in members if m[0] and not re.search(r"(^|/)package_info-.*\.json$", m[0])]
    files = {n: (b, s) for n, b, s in members}
    rec = {"drop_reason": None, "file_list": sorted([[n, s] for n, (_, s) in files.items()])[:200]}
    pkg = {}
    if "package.json" in files and files["package.json"][0] is not None:
        try:
            pkg = json.loads(files["package.json"][0].decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            pkg = {}
    if not isinstance(pkg, dict):
        pkg = {}
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    rec["pkg"] = {k: pkg[k] for k in KEEP_PKG if k in pkg}
    rec["name"], rec["version"] = pkg.get("name"), pkg.get("version")
    rec["hooks"] = {h: scripts[h] for h in HOOKS if scripts.get(h)}

    code = {n: b for n, (b, _) in files.items()
            if b is not None and PurePosixPath(n).suffix.lower() in CODE_EXT and not SKIP_RE.search(n)}
    if not code and not rec["hooks"]:
        rec["drop_reason"] = "no_code"
        return rec
    desc = str(pkg.get("description", "")).lower()
    if "security holding" in desc or str(pkg.get("version", "")).endswith("-security"):
        rec["drop_reason"] = "placeholder"
        return rec

    hooks = hook_targets(scripts, code)
    entries = []
    bins = pkg.get("bin")
    bins = list(bins.values()) if isinstance(bins, dict) else [bins] if isinstance(bins, str) else []
    for e in [pkg.get("main") or "index.js"] + bins:
        if not isinstance(e, str):
            continue
        e = e.lstrip("./")
        for cand in (e, e + ".js", e + "/index.js"):
            if cand in code and cand not in entries and cand not in hooks:
                entries.append(cand)
                break
    rest = [n for n in code if n not in hooks and n not in entries]

    def text_of(n):
        t = code[n].decode("utf-8", "replace")
        t = "\n".join(line for line in t.splitlines() if line.strip())
        return t[:MAX_FILE_CHARS]

    sections, total = [], 0
    for prio, n in [(1, n) for n in hooks] + [(2, n) for n in entries]:
        t = text_of(n)
        sections.append({"path": n, "prio": prio, "risk": len(RISK.findall(t)), "text": t})
        total += len(t)
    scored = sorted(((len(RISK.findall(t)), -len(t), n, t) for n in rest for t in [text_of(n)]), reverse=True)
    for risk, _, n, t in scored:
        if total > MAX_PKG_CHARS:
            break
        sections.append({"path": n, "prio": 3, "risk": risk, "text": t})
        total += len(t)
    rec["sections"] = sections
    return rec


def pieces(rec):
    fl = rec.get("file_list", [])
    head = "FILES (%d):\n" % len(fl) + "\n".join(f"{p} ({s} B)" for p, s in fl[:40])
    if len(fl) > 40:
        head += f"\n... {len(fl) - 40} more"
    out = [head, "\n\n=== package.json (name/version/description removed) ===\n" + json.dumps(rec.get("pkg", {}), indent=1)]
    for s in rec.get("sections", []):
        out.append(f"\n\n=== {s['path']} ===\n{s['text']}")
    return out


def pack(tok, parts, budget=BUDGET):
    """Concatenate parts until the token budget is used. Returns (text, used, truncated, n_parts_shown)."""
    used, out, truncated = 0, [], False
    for p in parts:
        ids = tok.encode(p, add_special_tokens=False).ids
        room = budget - used
        if room <= 16:
            truncated = True
            break
        if len(ids) > room:
            out.append(tok.decode(ids[: room - 8]) + "\n...[truncated]")
            used = budget
            truncated = True
            break
        out.append(p)
        used += len(ids)
    return "".join(out), used, truncated, len(out)
