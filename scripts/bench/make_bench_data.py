"""Build a throwaway chat-JSONL dataset for LoRA speed/memory benchmarking.

Uses benign JS files from the local global npm install as the "package code",
so every example has realistic code and roughly the target length.
Labels are fake (alternating) — this data is only for timing, never for training.

Usage: python scripts/bench/make_bench_data.py <js_root> <out_dir> <tokenizer_model> [code_tokens]
The code section is trimmed to exactly code_tokens tokens (default 1700) with the
given model's tokenizer, so the full chat example is ~1.8k tokens for every model.
"""

import json
import random
import sys
from pathlib import Path

SYSTEM = (
    "You are an npm supply-chain security analyst. Given the install-time contents "
    "of an npm package, decide if it is malicious. Respond with JSON only."
)
ANSWERS = [
    {"verdict": "benign", "behaviors": [], "evidence": "Library code only; no install script, no sensitive file reads, no outbound requests."},
    {"verdict": "malicious", "behaviors": ["data_collection", "data_exfiltration"], "evidence": "postinstall reads environment variables and posts them to an external host."},
]


def main(root: str, out: str, tok_model: str, code_tokens: int = 1700):
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(tok_model)
    files = sorted(p for p in Path(root).rglob("*.js") if 8_000 < p.stat().st_size < 60_000)
    random.Random(0).shuffle(files)
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for i, f in enumerate(files[:60]):
        ids = tok.encode(f.read_text(errors="replace")[:40_000], add_special_tokens=False)
        code = tok.decode(ids[:code_tokens])
        user = (
            f"PACKAGE: {f.parent.name}@1.0.{i}\nDESCRIPTION: utility module\n\n"
            '=== package.json (scripts) ===\n{"postinstall": "node index.js"}\n\n'
            f"=== {f.name} ===\n{code}"
        )
        rows.append({"messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": user},
            {"role": "assistant", "content": json.dumps(ANSWERS[i % 2])},
        ]})
    for name, part in (("train", rows[:48]), ("valid", rows[48:54]), ("test", rows[54:60])):
        with open(out_dir / f"{name}.jsonl", "w") as fh:
            for r in part:
                fh.write(json.dumps(r) + "\n")
    print(f"wrote {len(rows)} examples to {out_dir}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], *(int(a) for a in sys.argv[4:]))
