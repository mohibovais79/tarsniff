# tarsniff

**Check an npm package for malware before you install it**, using a small fine-tuned Qwen model
that runs on your own laptop.

```
$ tarsniff scan modelbufs@1.0.1

  modelbufs@1.0.1  ->  FLAGGED: likely malicious
  P(malicious) = 0.999   (threshold 0.5, 1024 tokens read, truncated, 2.26 s)
  install scripts (run automatically by npm install):
    postinstall: node canary.cjs
  files the model read (1): canary.cjs
  risky lines it saw (URLs redacted):
    canary.cjs: const { execFileSync } = require("node:child_process");
    canary.cjs: const receiver = "https://[url]";
    canary.cjs: const user = read(() => os.userInfo(), {});
    ...
```

*(A real package, reported as malware on 26 Nov 2026 and still on npm when this was written.)*

- **Model on Hugging Face:** https://huggingface.co/mohibovais79/tarsniff
  (Qwen3-1.7B + LoRA, 4-bit GGUF, 1.0 GB, plus the LoRA adapter)
- **Slides:** https://claude.ai/artifact/SMTSrzhM9apkvDNUgiwY6E
- **Runs locally:** Ollama on a Mac mini M4 (16 GB), about 1 second per package. No cloud, no API key.
- Built for the **Qwen Local Hackathon 2026**.

## Why

`npm install` runs a package's install scripts automatically, so a malicious package can steal
tokens, SSH keys, cloud credentials and crypto wallets the moment it is installed. This happens
constantly: **OSV published more than 1,400 malicious-npm-package reports between 13 and 27 Nov 2026**.

Popular open-source scanners such as GuardDog match hand-written rules, so new attack code that
doesn't match a rule gets through. Strong LLM-based detectors exist in research, but they call large
cloud models. tarsniff asks a different question: **can a 1.7B model, fine-tuned for this one job,
read the code like an analyst and still run on a normal laptop?**

## How it works

1. **Fetch, don't install.** Download the tarball from the npm registry and verify npm's sha512
   checksum. The archive is read **in memory**: nothing is extracted to disk, installed or executed.
   Size caps protect against archive bombs.
2. **Focus.** Build a digest of at most 1,024 tokens: the file list, `package.json` (with name,
   version and description removed so the model judges the code, not the name), the files run by
   install hooks, the main/bin entry files, then other code ranked by risky API use
   (`child_process`, network, `process.env`, base64 blobs, webhooks…).
3. **Judge.** The fine-tuned Qwen reads the digest. The score is P(malicious), taken from the
   probability of the first answer token, not from free text.
4. **Act.** Print the verdict, install scripts, files read and risky lines (URLs, IPs and hosts
   redacted). Exit code 1 when flagged, so `tarsniff scan X && npm install X` never installs a
   flagged package.

## Install and run

You need [Ollama](https://ollama.com) (macOS, Windows or Linux; tested with 0.40.18) and Python 3.10+.

```bash
# 1. the model (1.0 GB)
ollama pull hf.co/mohibovais79/tarsniff:Q4_K_M
ollama cp hf.co/mohibovais79/tarsniff:Q4_K_M tarsniff

# 2. the CLI
pip install git+https://github.com/mohibovais79/tarsniff
#    or: uv tool install git+https://github.com/mohibovais79/tarsniff

# 3. scan
tarsniff scan lodash                     # latest version
tarsniff scan left-pad@1.3.0             # a specific version
tarsniff scan ./my-package-1.0.0.tgz     # a local tarball (e.g. from `npm pack`)
tarsniff scan some-pkg && npm install some-pkg
tarsniff scan lodash chalk --json        # JSON output
```

Options: `--model` (default `tarsniff`), `--host` (default `http://localhost:11434`).
Exit codes: 0 looks benign, 1 flagged, 2 could not scan.

## Results

Hardware for everything below: **Mac mini M4, 16 GB**. All test packages are newer than the
training data (training malware ends May 2026).

### Live npm attacks (Nov 2026)

The test set was fixed **before** scoring: every npm malware report OSV published from 13 to 27 Nov
2026 whose malicious version could still be downloaded from npm on 27 Nov (98 reports; 24 were
removed by npm before download, 74 scored). Safe control: the latest versions of 286 popular npm
packages, downloaded the same day.

| | Malware caught (74) | Safe packages flagged (286) |
|---|---|---|
| **tarsniff** (threshold 0.5) | **62 (84%)** | 29 (10%) |
| GuardDog 3.2.0 (risk score ≥ 5) | 45 (61%) | 5 (2%) |
| Either tool | 70 (95%) | 32 |

ROC-AUC: tarsniff 0.938, GuardDog 0.902. tarsniff caught 25 attacks GuardDog missed; GuardDog
caught 8 that tarsniff missed. A higher threshold trades recall for fewer false alarms
(0.8: 47/74 caught, 5/286 flagged). Per-package results: [`results/live/`](results/live/).

### Before and after fine-tuning

Same live packages, same prompts, base Qwen3-1.7B vs tarsniff (packages that contain code:
73 malicious, 280 safe), scored with MLX:

| | Base Qwen3-1.7B (4-bit) | tarsniff |
|---|---|---|
| Safe packages wrongly flagged | 93% | **9%** |
| Malware caught | 96% | 85% |
| F1 | 0.35 | **0.77** |
| ROC-AUC | 0.82 | **0.95** |

Real outputs on the safe package `@csstools/css-tokenizer`:

- **Base model:** `{"isMalicious": true, "reason": "The package contains a class ParseError with methods that could be used for error injection…"}`
- **tarsniff:** `{"verdict": "benign"}`

The base model calls almost everything malicious, which makes it useless as a gate. Fine-tuning
teaches it what normal code looks like. Full outputs:
[`results/live/before_after_generated.json`](results/live/before_after_generated.json).

### Held-out validation and input-size ablation

300 held-out packages (150 malware from Jun–Oct 2026, 150 benign); one LoRA trained per input size:

| Input given to the model | F1 | False-alarm rate | ROC-AUC |
|---|---|---|---|
| Base model, no fine-tuning (4,096 tokens) | 0.673 | 96% | 0.809 |
| File list + package.json only | 0.641 | 7.3% | 0.748 |
| **1,024 tokens (shipped)** | **0.750** | **6.7%** | **0.879** |
| 2,048 tokens | 0.683 | 10.7% | 0.791 |
| 4,096 tokens | 0.709 | 14.0% | 0.820 |

More code did not help a model this size: the 1,024-token digest, which puts install scripts and
risky code first, was best, and it is also the fastest.

### NPMStudy benchmark

On a balanced 2,000-package sample of the NPMStudy benchmark (arXiv 2603.27549):

| | F1 | False-alarm rate | ROC-AUC |
|---|---|---|---|
| tarsniff, 1.7B local (threshold 0.5) | 0.862 | 27% | 0.967 |
| tarsniff at GuardDog's false-alarm rate (threshold 0.91, picked on this sample) | 0.917 | 4.2% | – |
| GuardDog 3.2.0 | 0.922 | 4.8% | 0.939 |
| IntelGuard (GPT-4.1-mini API, published per-package results) | 0.958 | 1.4% | – |

This benchmark's benign packages are harder for tarsniff at the default threshold. IntelGuard uses
a cloud model and a curated knowledge base; tarsniff is a 1 GB local file.

### The GGUF matches the original

On the 300 held-out packages, the Q4_K_M GGUF in Ollama vs the MLX model: F1 0.747 vs 0.750, same
verdict on 99.7% of packages ([`results/gguf_vs_mlx_parity.json`](results/gguf_vs_mlx_parity.json)).

## Dataset

- **Malicious:** npm samples from the
  [Datadog malicious-software-packages dataset](https://github.com/DataDog/malicious-software-packages-dataset)
  (Apache-2.0), one version per package name. Split by date so one campaign can't land in both
  train and test: train = Jan–May 2026, validation = Jun–Oct 2026.
- **Benign:** popular npm packages (GuardDog's top-npm list plus a hand-picked list of "tricky"
  legitimate packages), downloaded straight from the registry.
- **Training set:** 600 packages, 300 malicious and 300 benign. Duplicates removed; package name,
  version and description stripped from every prompt.
- **Live test:** [OSV](https://osv.dev) npm `MAL-` reports, see above.

Malware samples, datasets and model weights are never committed to this repository.

## Training

| | |
|---|---|
| Base model | [Qwen3-1.7B](https://huggingface.co/Qwen/Qwen3-1.7B), 4-bit MLX build ([mlx-community/Qwen3-1.7B-4bit](https://huggingface.co/mlx-community/Qwen3-1.7B-4bit)) |
| Method | LoRA: rank 16, scale 20, dropout 0, all layers; loss on the answer only (`mask_prompt`) |
| Target | `{"verdict": "malicious"}` / `{"verdict": "benign"}` |
| Run | [MLX-LM](https://github.com/ml-explore/mlx-lm) 0.32.2, 600 steps, batch 1, learning rate 1e-4, Adam, max length 1,200 tokens, gradient checkpointing |
| Hardware and cost | Mac mini M4, 16 GB: 36 minutes, 2.9 GB peak memory |
| Export | `mlx_lm.fuse --dequantize` → [llama.cpp](https://github.com/ggml-org/llama.cpp) `convert_hf_to_gguf.py` (bf16) → `llama-quantize Q4_K_M` → Ollama |

Config: [`configs/lora_abl.yaml`](configs/lora_abl.yaml).

## Reproduce

All malware handling happens inside a locked-down Docker container (`--network none --read-only
--cap-drop ALL`; only the download step has network). Nothing is ever `npm install`-ed.

1. `docker build -t guarddog-scan:3.2.0 docker` builds the isolated scanner image (it also runs GuardDog).
2. `scripts/bench/select_and_fetch.py` (in the container) picks samples, split by date.
3. `scripts/bench/extract_pkgs.py` (in the container, offline) reads archives in memory into JSON.
4. `scripts/bench/build_sets.py` builds the prompts at each token budget.
5. `scripts/bench/run_ablation.sh` trains one LoRA per budget and evaluates it (`eval_verdict.py`).
6. `scripts/export/ollama_parity.py` checks the GGUF against MLX.
7. `scripts/bench/live_osv.py` builds the pre-registered live set, `live_score.py` scores it
   against GuardDog, and `live_base_vs_tuned.py` compares the base and fine-tuned models.

## Safety

- tarsniff never installs, extracts or runs the package it scans.
- Downloads are capped (60 MB compressed, 300 MB uncompressed, 20,000 entries) and verified
  against npm's checksum.
- Output redacts URLs, IP addresses and host names, so the tool never spreads attacker
  infrastructure.

## Limitations

The model reads 1,024 tokens, so malicious code buried deep inside a large, legitimate-looking
package (such as a hijacked release of a popular library) can be missed. On popular packages it
raises more false alarms than GuardDog. The two tools catch different attacks, so running both
works best.

## Resources

Tools and data
- [Qwen3-1.7B](https://huggingface.co/Qwen/Qwen3-1.7B) by the Qwen team (Apache-2.0)
- [MLX-LM](https://github.com/ml-explore/mlx-lm) for LoRA training on Apple silicon
- [llama.cpp](https://github.com/ggml-org/llama.cpp) for GGUF conversion and quantization
- [Ollama](https://ollama.com) for local inference
- [Datadog malicious-software-packages dataset](https://github.com/DataDog/malicious-software-packages-dataset)
- [OSV](https://osv.dev) and [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) for current malware reports
- [GuardDog](https://github.com/DataDog/guarddog), the rule-based baseline

Related research
- *How Effective Are NPM Malicious Package Detectors? A Large-Scale Empirical Study*, [arXiv 2603.27549](https://arxiv.org/abs/2603.27549) (the NPMStudy benchmark)
- *Bridging Expert Reasoning and LLM Detection: A Knowledge-Driven Framework for Malicious Packages*, [arXiv 2601.16458](https://arxiv.org/abs/2601.16458) (IntelGuard)
- *DistillGuard: Malicious NPM Package Detection and API Attack Chain Analysis via Static Graph and LLM Distillation*, [arXiv 2609.28996](https://arxiv.org/abs/2609.28996)
- *Taint-Based Code Slicing for LLMs-based Malicious NPM Package Detection*, [arXiv 2512.12313](https://arxiv.org/abs/2512.12313)

## Team

Mohib Ahmed ([@mohibovais79](https://github.com/mohibovais79))

## License

Apache-2.0 (see [LICENSE](LICENSE)). Model weights: Apache-2.0, derived from Qwen3-1.7B. Training
data: Datadog malicious-software-packages dataset (Apache-2.0), with attribution.
