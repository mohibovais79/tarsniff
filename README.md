# tarsniff

Check an npm package for malware **before** you install it. tarsniff downloads the package tarball
(never runs `npm install`), reads its code, and asks a small fine-tuned Qwen model, running locally
on your laptop, whether it looks malicious.

Status: work in progress for the Qwen Local Hackathon 2026.

- `scripts/bench/` experiment scripts (dataset building, LoRA training, evaluation, baselines)
- `configs/` MLX-LM LoRA training configs
- `docker/` isolated, offline container for handling malware samples

Malware samples, datasets and model weights are never committed to this repository.
