# MSFV Round-3 — Run Report

Completed 2026-09-02, the run host (Tailscale). A + B ran concurrently.

## A batch — re-run st_nemotron_smartbugs_s5 (5 jobs) ✅
- **Acceptance PASSED**: new candidates = **933** (target 917–931; the old 757
  was a low-concurrency-load artifact, not real seed behaviour).
- smartbugs / Nemotron detection is now `[922, 934, 931, 925, 933]`,
  mean 929, **CV 0.5%** (was 8.6% with the 757 outlier).
- config: DeepInfra pinned, temperature 0, detailed-thinking-off,
  max_tokens 12000, **low concurrency (CONC=4)** — matches the nemotron
  detection re-run.
- 4 verification configs re-run on the new pool (full, noidentity, noconcern,
  nosource; nopoc/full_rep skipped per spec).

## B batch — self-verify 2×3 control (72 jobs) ✅ 72/72, 0 failures
Frozen gemma pools (`st_gemma_{bench}_s{1,2,3}`), verified by gemma & qwen,
configs full/full_rep2/full_rep3. Mean shipped (full, 4 bench × 3 seed):

| pool | gemma verifier | qwen verifier |
|---|---|---|
| gemma | 117.2 (self) | 135.6 (cross) |
| qwen  | 82.2 (cross) | 106.1 (self) |

1. **Self-verify bias**: present but asymmetric/modest — qwen is more lenient on
   its own pool (106 self vs 82 gemma-cross); gemma is not (117 self vs 136
   qwen-cross). Bias exists but does not dominate.
2. **Verifier ranking is pool-robust**: gemma verifier ships fewer than qwen on
   BOTH pools (117<136 on gemma pool, 82<106 on qwen pool) → the aggressiveness
   ranking holds regardless of candidate pool.

## Concurrency used
- A (nemotron): low concurrency CONC=4, DeepInfra pinned (per hard rule 6).
- B (gemma/qwen verifiers): normal concurrency (6 run_dirs × CONC=8).

## Manifests
All run manifests written; nemotron A-batch uses temp=0/thinking-off, B-batch
gemma/qwen verifiers use temp 0.2. tool_versions uniform (OpenRouter, python 3.12).

## Not run
Round-2 C (vext, external-family verifier) — still optional; the three in-house
verifiers are well-separated (spec's run-C criterion not met).
