"""Base vs fine-tuned on the live set, same prompts, same first-token score (MLX).

Usage: python scripts/bench/live_base_vs_tuned.py <records_mal.jsonl> <records_ben.jsonl> <adapter> <out.json>
"""
import json, sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "Developer/personal/tarsniff/src"))
sys.path.insert(0, "scripts/bench")
import mlx.core as mx  # noqa: E402
from mlx_lm import load  # noqa: E402
from tarsniff import digest  # noqa: E402
from tokenizers import Tokenizer  # noqa: E402
from eval_verdict import first_diff_tokens, metrics  # noqa: E402

MODEL = "mlx-community/Qwen3-1.7B-4bit"


def prompts(paths):
    tok = Tokenizer.from_file(str(Path.home() / "Developer/personal/tarsniff/src/tarsniff/tokenizer.json"))
    out = []
    for path, y in paths:
        for rec in map(json.loads, open(path)):
            if rec["drop_reason"]:
                continue
            out.append({"file": rec["file"], "y": y, "user": digest.pack(tok, digest.pieces(rec))[0]})
    return out


def score(items, adapter):
    model, tok = load(MODEL, adapter_path=adapter)
    prefix, t_mal, t_ben = first_diff_tokens(tok)
    res = []
    for it in items:
        p = tok.apply_chat_template([{"role": "system", "content": digest.SYSTEM}, {"role": "user", "content": it["user"]}],
                                    add_generation_prompt=True, tokenize=False, enable_thinking=False)
        logits = model(mx.array(tok.encode(p, add_special_tokens=False) + prefix)[None])[0, -1]
        res.append(mx.softmax(mx.stack([logits[t_mal], logits[t_ben]]).astype(mx.float32))[0].item())
    return res


def main(mal, ben, adapter, out):
    items = prompts([(mal, True), (ben, False)])
    out_d = {}
    for name, ad in (("base", None), ("tuned", adapter)):
        ps = score(items, ad)
        rows = [{"y": it["y"], "p": p, "file": it["file"]} for it, p in zip(items, ps)]
        out_d[name] = metrics(rows)
        out_d[name + "_rows"] = rows
        m = out_d[name]
        print(f"{name:5} recall {m['recall']:.3f} ({sum(r['y'] and r['p']>=.5 for r in rows)}/{m['pos']})  "
              f"false alarms {m['fpr']:.3f} ({sum((not r['y']) and r['p']>=.5 for r in rows)}/{m['neg']})  "
              f"F1 {m['f1']:.3f}  AUC {m['auc']:.3f}", flush=True)
    json.dump(out_d, open(out, "w"), indent=1)


if __name__ == "__main__":
    main(*sys.argv[1:5])
