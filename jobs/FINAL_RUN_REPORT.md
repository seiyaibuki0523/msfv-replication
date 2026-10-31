# MSFV — Final Run Report (round-1 + round-2 + nemotron detection fix)

Completed 2026-08-24, all-OpenRouter on the run host.

## Completion
- **Round-1 (641 jobs)**: ✅ 60 detection + 581 verification, 0 failures.
- **Round-2 A `naive_verify` (60)**: ✅ RQ4 single-prompt control, finding_idx aligned with `full`.
- **Round-2 C `vext` (36, optional)**: not run (needs external-family verifier choice).
- **nemotron detection fix**: ✅ re-run to reproducibility (see below).

Final tallies: detection 60/60 · tier3 24/24 · verify+naive 641 config metas · naive 60/60.

## Detection reproducibility (5-seed CV of findings_count)
| model | dvd | pygoat | nodegoat | smartbugs |
|---|---|---|---|---|
| qwen3-coder | 238 (CV 1%) | 122 (0%) | 56 (0%) | 1010 (0%) |
| gemma-4-31B | 238 (CV 1%) | 122 (0%) | 56 (0%) | 1051 (0%) |
| Nemotron-3-Super-120B | 214 (CV 2%) | 115 (2%) | 55 (1%) | 894 (CV 8%) |

nemotron detection is now reproducible and at a comparable finding level to
qwen/gemma. smartbugs CV 8% (one low seed, 757 vs ~928) is the residual.

## The nemotron detection bug (root-cause chain)
nemotron detection was non-reproducible; qwen/gemma (same OpenRouter, same
temp) were deterministic. Diagnosed and fixed in layers:

1. **max_tokens truncation** — 16000 too low; nemotron `<think>` hit the cap →
   L3 filter verdicts truncated → dropped candidates. (raised to 40000)
2. **OpenRouter provider mixing** — OpenRouter load-balances the model across
   two upstream providers with different quantization and output caps
   (DeepInfra bf16/cap-16384 vs DigitalOcean uncapped). Random per-request
   routing → inconsistent quant + re-truncation on the capped provider.
   (pinned one provider via `AISEC_OPENROUTER_PROVIDER`)
3. **reasoning nondeterminism** — nemotron is a reasoning model; `<think>` at
   temperature 0.2 explores different paths per call (seed is NOT honored by
   OpenRouter) → different L3 decisions. (temp=0 greedy + `detailed thinking off`)
4. **shared-pool load nondeterminism** — at high concurrency the provider's
   batching + rate-limiting suppressed and destabilised findings (e.g. dvd 54,
   smartbugs 267 under load vs 214 / ~928 at low concurrency). (re-run at
   low concurrency, PAR=2/CONC=4)

Final nemotron **detection** config: `openrouter:nemotron-120b` pinned to
DeepInfra, temp=0, detailed-thinking-off, max_tokens=12000, low concurrency.
nemotron **verify** keeps thinking-on / temp 0.2 (verify is stable, CV 2.1%,
and is the studied stage).

Earlier stable results were from a self-hosted vLLM nemotron (single
deterministic node, since repurposed); the instability appeared only after
detection moved to OpenRouter for high concurrency. qwen/gemma survived the
move because they are non-reasoning models.

## Superseded / broken data (archived, NOT for the paper)
`data/ablation/old/`:
- `broken-nemotron-superseded.tar.gz` — 16k-truncated, mixed-provider, and
  thinking-on-pinned nemotron attempts (3 × 20 run_dirs).
- `nemotron_interrupted`, `nemotron_hiconc_nodegoat_pygoat`,
  `nemotron_hiconc_dvd_smartbugs` — high-concurrency / interrupted nemotron
  detection (CV 8-56%), superseded by the low-concurrency re-run.

## Manifests
All detection run manifests share identical temperature/top_p/max_tokens/
prompt_template_hash within each arm (nemotron detection: temp=0; others temp
0.2). tool_versions uniform (OpenRouter, forge 1.7.1, python 3.12).
