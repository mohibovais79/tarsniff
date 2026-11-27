"""tarsniff command line: check an npm package for malware before installing it.

  tarsniff scan lodash               latest version from the npm registry
  tarsniff scan left-pad@1.3.0       a specific version
  tarsniff scan ./some-package.tgz   a local tarball (e.g. from `npm pack`)

The tarball is downloaded and read in memory. Nothing is installed, extracted or executed.
The verdict comes from a fine-tuned Qwen3-1.7B served locally by Ollama.
Exit code: 0 = looks benign, 1 = flagged malicious, 2 = could not scan.
"""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from importlib.resources import files

from tokenizers import Tokenizer

from . import digest

REGISTRY = os.environ.get("TARSNIFF_REGISTRY", "https://registry.npmjs.org")
MAX_DOWNLOAD = 60_000_000
HF_MODEL = "hf.co/mohibovais79/tarsniff:Q4_K_M"
THRESHOLD = 0.5  # fixed default (not tuned); trade-offs at other thresholds are in the README
URL_RE = re.compile(r"(https?://|wss?://)[^\s'\"`)]+", re.I)


class ScanError(Exception):
    pass


def http_get(url, limit, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "tarsniff/0.1", "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(limit + 1)
    except urllib.error.HTTPError as e:
        raise ScanError(f"HTTP {e.code} for {url}") from None
    except urllib.error.URLError as e:
        raise ScanError(f"cannot reach {url}: {e.reason}") from None
    if len(data) > limit:
        raise ScanError(f"download larger than {limit // 1_000_000} MB, refusing")
    return data


def parse_spec(spec):
    if spec.startswith("@"):
        name, _, ver = spec[1:].partition("@")
        name = "@" + name
    else:
        name, _, ver = spec.partition("@")
    return name, ver or None


def fetch_registry(spec):
    name, ver = parse_spec(spec)
    meta = json.loads(http_get(f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}", 80_000_000))
    ver = ver or meta.get("dist-tags", {}).get("latest")
    info = meta.get("versions", {}).get(ver)
    if not info:
        raise ScanError(f"{name}@{ver} not found on the registry")
    dist = info.get("dist", {})
    data = http_get(dist["tarball"], MAX_DOWNLOAD)
    integ = dist.get("integrity", "")
    if integ.startswith("sha512-"):
        if base64.b64encode(hashlib.sha512(data).digest()).decode() != integ[7:]:
            raise ScanError("tarball does not match the registry's sha512 integrity, refusing")
    return f"{name}@{ver}", data


def render(system, user):
    return (f"<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{user}<|im_end|>\n"
            '<|im_start|>assistant\n<think>\n\n</think>\n\n{"verdict": "')


def p_malicious(prompt, model, host):
    body = {"model": model, "raw": True, "prompt": prompt, "stream": False,
            "options": {"num_predict": 1, "temperature": 0, "num_ctx": 4096},
            "logprobs": True, "top_logprobs": 20}
    req = urllib.request.Request(host.rstrip("/") + "/api/generate", json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    try:
        d = json.load(urllib.request.urlopen(req, timeout=600))
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", "replace")[:300]
        if e.code == 404 and model == "tarsniff":
            # not created locally: fall back to the name `ollama pull` gives the Hugging Face model
            return p_malicious(prompt, HF_MODEL, host)
        if e.code == 404:
            msg += f"\n  model '{model}' is not in Ollama - run: ollama pull {HF_MODEL}"
        raise ScanError(f"Ollama error {e.code}: {msg}") from None
    except urllib.error.URLError:
        raise ScanError(f"cannot reach Ollama at {host} - is it running? (`ollama serve`)") from None
    try:
        top = {t["token"]: t["logprob"] for t in d["logprobs"][0]["top_logprobs"]}
    except (KeyError, IndexError, TypeError):
        raise ScanError("Ollama returned no logprobs - update Ollama (tested with 0.40.18)") from None
    lm, lb = top.get("mal", -30.0), top.get("ben", -30.0)
    return 1 / (1 + math.exp(lb - lm))


IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
TLDS = ("com|net|org|io|top|xyz|site|online|info|biz|cc|tk|ru|cn|me|app|dev|link|live|shop|pw|su|ws|co|in|pk|"
        "club|fun|icu|cloud|tech|store|lol|vip|win|bid|click|space|work|today|zip|mov|ngrok-free|oast|pro")
HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:" + TLDS + r")\b(?![\w(])")


def redact(line):
    """Hide URLs, IPs and host names so demo output never spreads attacker infrastructure."""
    line = URL_RE.sub(lambda m: m.group(1) + "[url]", line)
    line = IP_RE.sub("[ip]", line)
    return HOST_RE.sub("[host]", line)


def evidence(rec, n_shown_sections, max_lines=8):
    out = []
    for s in rec.get("sections", [])[:n_shown_sections]:
        for i, line in enumerate(s["text"].splitlines(), 1):
            if digest.RISK.search(line):
                out.append((s["path"], redact(line.strip())[:140]))
                if len(out) >= max_lines:
                    return out
    return out


def scan(target, model, host):
    t0 = time.perf_counter()
    if os.path.isfile(target):
        label, data = os.path.basename(target), open(target, "rb").read(MAX_DOWNLOAD + 1)
        if len(data) > MAX_DOWNLOAD:
            raise ScanError("file larger than 60 MB, refusing")
    else:
        label, data = fetch_registry(target)
    try:
        members = digest.read_tarball(data)
    except digest.ArchiveTooLarge as e:
        raise ScanError(f"archive refused: {e}") from None
    except Exception as e:  # noqa: BLE001
        raise ScanError(f"not a readable .tgz: {type(e).__name__}") from None
    rec = digest.extract(members)
    res = {"package": label, "files": len(members), "hooks": rec.get("hooks", {})}
    if rec["drop_reason"] == "placeholder":
        res.update(verdict="removed", p=None, note="npm already replaced this package with a security placeholder")
        return res
    if rec["drop_reason"] == "no_code":
        res.update(verdict="no_code", p=None, note="no code files and no install scripts: nothing to run")
        return res
    tok = Tokenizer.from_str(files("tarsniff").joinpath("tokenizer.json").read_text(encoding="utf-8"))
    text, used, trunc, n_parts = digest.pack(tok, digest.pieces(rec))
    p = p_malicious(render(digest.SYSTEM, text), model, host)
    shown = [s["path"] for s in rec["sections"][: max(0, n_parts - 2)]]
    res.update(verdict="malicious" if p >= THRESHOLD else "benign", p=p, tokens=used, truncated=trunc,
               files_read=shown, evidence=evidence(rec, max(0, n_parts - 2)),
               seconds=round(time.perf_counter() - t0, 2))
    return res


def report(res):
    v = res["verdict"]
    c = (lambda code, s: f"\033[{code}m{s}\033[0m") if sys.stdout.isatty() and not os.environ.get("NO_COLOR") \
        else (lambda code, s: s)
    head = {"malicious": c("1;31", "FLAGGED: likely malicious"), "benign": c("1;32", "looks benign"),
            "removed": c("1;33", "already removed by npm"), "no_code": c("1;32", "no code to run")}[v]
    print(f"\n  {res['package']}  ->  {head}")
    if res.get("p") is not None:
        print(f"  P(malicious) = {res['p']:.3f}   (threshold {THRESHOLD}, {res['tokens']} tokens read"
              f"{', truncated' if res['truncated'] else ''}, {res['seconds']} s)")
    if res.get("note"):
        print(f"  {res['note']}")
    if res["hooks"]:
        print("  install scripts (run automatically by npm install):")
        for k, cmd in res["hooks"].items():
            print(f"    {k}: {redact(str(cmd))[:120]}")
    if res.get("files_read"):
        print(f"  files the model read ({len(res['files_read'])}): " + ", ".join(res["files_read"][:6])
              + (" ..." if len(res["files_read"]) > 6 else ""))
    if res.get("evidence") and v == "malicious":
        print("  risky lines it saw (URLs redacted):")
        for path, line in res["evidence"]:
            print(f"    {path}: {line}")
    print()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tarsniff", description="Check an npm package for malware before installing it.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan name[@version] from the npm registry, or a local .tgz")
    s.add_argument("targets", nargs="+")
    s.add_argument("--model", default=os.environ.get("TARSNIFF_MODEL", "tarsniff"))
    s.add_argument("--host", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    s.add_argument("--json", action="store_true", help="print JSON lines instead of the report")
    a = ap.parse_args(argv)
    host = a.host if a.host.startswith("http") else "http://" + a.host
    worst = 0
    for t in a.targets:
        try:
            res = scan(t, a.model, host)
        except ScanError as e:
            res = {"package": t, "verdict": "error", "error": str(e)}
        if a.json:
            print(json.dumps(res))
        elif res["verdict"] == "error":
            print(f"\n  {t}  ->  could not scan: {res['error']}\n", file=sys.stderr)
        else:
            report(res)
        worst = max(worst, {"malicious": 1, "error": 2}.get(res["verdict"], 0))
    return worst


if __name__ == "__main__":
    sys.exit(main())
