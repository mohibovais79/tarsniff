"""Score the pre-registered live set with tarsniff (Ollama GGUF) and compare with GuardDog.

Usage: python scripts/bench/live_score.py <records.jsonl> <gd_dir> <live_set.jsonl> <out.json>
Every record is reported, including misses and unscorable ones.
"""
import json, re, sys, time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "Developer/personal/tarsniff/src"))
from tarsniff import digest  # noqa: E402
from tarsniff.cli import THRESHOLD, p_malicious, redact, render  # noqa: E402
from tokenizers import Tokenizer  # noqa: E402


def main(records, gd_dir, live_set, out, model="tarsniff", host="http://localhost:11434"):
    tok = Tokenizer.from_file(str(Path.home() / "Developer/personal/tarsniff/src/tarsniff/tokenizer.json"))
    meta = {re.sub(r"[/@:]", "_", r["name"] + "@" + r["version"]) + ".tgz": r for r in map(json.loads, open(live_set))}
    rows = []
    for rec in map(json.loads, open(records)):
        m = meta[rec["file"]]
        row = {"id": m["id"], "published": m["published"], "package": f"{m['name']}@{m['version']}",
               "hooks": {k: redact(str(v)) for k, v in rec.get("hooks", {}).items()}, "drop_reason": rec["drop_reason"]}
        if not rec["drop_reason"]:
            text, used, trunc, _ = digest.pack(tok, digest.pieces(rec))
            t0 = time.perf_counter()
            row["p"] = p_malicious(render(digest.SYSTEM, text), model, host)
            row["sec"] = time.perf_counter() - t0
            row["truncated"] = trunc
        try:
            g = json.loads((Path(gd_dir) / (rec["file"] + ".json")).read_text())
            row["gd_score"] = g["risk_score"]["score"]
            row["gd_hits"] = sorted(k for k, v in g["results"].items() if v)
        except Exception as e:  # noqa: BLE001
            row["gd_score"], row["gd_hits"] = None, [f"error {type(e).__name__}"]
        rows.append(row)
    n = len(rows)
    ts = sum(r.get("p", 0) >= THRESHOLD for r in rows)
    gd = sum((r["gd_score"] or 0) >= 5 for r in rows)
    either = sum(r.get("p", 0) >= THRESHOLD or (r["gd_score"] or 0) >= 5 for r in rows)
    res = {"n": n, "tarsniff_flagged": ts, "guarddog_flagged": gd, "either": either,
           "tarsniff_recall": ts / n, "guarddog_recall": gd / n, "rows": rows}
    json.dump(res, open(out, "w"), indent=1)
    print(f"live malware n={n}: tarsniff {ts}/{n} ({ts/n:.0%})  GuardDog>=5 {gd}/{n} ({gd/n:.0%})  either {either}/{n}")
    print(f"only tarsniff: {sum(r.get('p',0)>=THRESHOLD and (r['gd_score'] or 0)<5 for r in rows)}  "
          f"only GuardDog: {sum(r.get('p',0)<THRESHOLD and (r['gd_score'] or 0)>=5 for r in rows)}")


if __name__ == "__main__":
    main(*sys.argv[1:5])
