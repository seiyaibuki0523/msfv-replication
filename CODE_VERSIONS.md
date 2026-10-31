# Code versions used by the experiments

All runs executed the tree in `frozen-code/` (the launchers put `frozen-code/src/main` and `frozen-code/src` on
`sys.path`; nothing was imported from any other copy of the code). Two versions of that tree were used.

| Version | `pipeline.py` SHA-256 (first 16 hex) | Runs |
|---|---|---|
| round 1 — git commit `8fbe80b` of the author's repository, 2026-08-20 | `2a30e5c743a0b751` | the 641 round-1 configurations of 2026-08-20: qwen and gemma detection, all leave-one-out, power-set and `full` verification passes of seeds 1–5, and the first Nemotron detection attempt (superseded, not in this package) |
| round 2 onwards — working tree, 2026-08-21 | `c8d73b9457a11ff4` | `naive_verify` (2026-08-21), the final Nemotron detection re-run (2026-08-22), round 3 (2026-09-02: cross-verifier gemma/qwen pools, seed-5 re-runs), round 4 (2026-09-10: Nemotron-pool cross-verifier cells and repeat passes) |

`frozen-code/` is the round-2 version. The round-1 versions of the two files that differ are in
`frozen-code/versions/`, together with the full diff (`changes_round1_to_round2.diff`, 102 insertions, 2
deletions across `pipeline.py`, `nvidia_adapter.py` and `experiments/run_ablation_fast.py`).

## What changed between the versions

1. `core/analysis/pipeline.py` (+61 lines): a `naive_verify` prompt path, taken only when
   `AISEC_VERIFY_MODE=naive` — the single-prompt control of RQ4. The structured verification prompt, the signal
   assembly and the PoC-signal rendering used by every other configuration are byte-identical in both versions
   (the diff touches nothing on that path except the one-line dispatch).
2. `core/ai_engine/nvidia_adapter.py` (+35 lines): three environment switches that were needed to make the
   Nemotron detection arm reproducible (`jobs/FINAL_RUN_REPORT.md`): `AISEC_NEMOTRON_THINKING=off` prepends the
   "detailed thinking off" system directive; `AISEC_LLM_TEMPERATURE` forces the sampling temperature;
   `AISEC_OPENROUTER_PROVIDER` pins one upstream provider. When the variables are unset the request is identical
   to the round-1 code.
3. `experiments/run_ablation_fast.py` (+8 lines): registers the `naive_verify` configuration.

Consequently the verification prompt whose hash the article reports in Table 2(b)
(`pipeline.py sha256:2a30e5c743a0b751`) is the prompt used in every structured configuration of every round;
runs made with the round-2 tree differ from it only by code that those runs did not execute (naive mode) or
by the documented Nemotron detection settings.

## How to read `manifest.json:prompt_template_hash`

The 40 manifests written at run time on 2026-08-20 by `experiments/run_jobs_v2.py` record the hash of the
`pipeline.py` that ran (`2a30e5c743a0b751`). The remaining 92 manifests were written on 2026-09-10 by
`experiments/write_manifests.py` for the run directories that lacked one; that script records the hash of
`frozen-code/pipeline.py` at the time it was written (`c8d73b9457a11ff4`), which is the round-2 version, not
necessarily the version that produced the run. Use the table above, not the manifest field, to determine which
version a run executed.

## Inference settings per arm (as recorded in the manifests and run reports)

| Arm | Model (OpenRouter id) | temperature | top_p | max_tokens | reasoning | provider | concurrency |
|---|---|---|---|---|---|---|---|
| qwen detection | `qwen/qwen3-coder-next` | 0.2 | 0.7 | 2048 | n/a | not pinned | 16 |
| gemma detection | `google/gemma-4-31b-it` | 0.2 | 0.7 | 2048 | n/a | not pinned | 16 |
| Nemotron detection (final re-run) | `nvidia/nemotron-3-super-120b-a12b` | 0 | 0.7 | 12000 | off | DeepInfra | 4 |
| Nemotron verification | `nvidia/nemotron-3-super-120b-a12b` | 0.2 | 0.7 | 16000 | on | not pinned (rounds 1–2) / DeepInfra (rounds 3–4) | 16 / 4 |
| gemma / qwen verification (cross-verifier) | as above | 0.2 | 0.7 | 2048 | n/a | not pinned | 8 |

Seeds 1–5 were passed as the `seed` parameter of the chat-completions request; the providers did not honour
it (repeat passes with the same seed differ; Table 11 of the article and `analysis/extra.py` section E).
Detection chains for the qwen and gemma arms fall back to Nemotron on a failed call
(`AISEC_FAST_CHAIN="openrouter:<arm>,openrouter:nemotron-120b"`).

PoC generation. Solidity PoCs are written by the detection model inside the Layer-4 analysis (`poc.code`) and
executed with host `forge`; Python and JavaScript PoC scripts are generated on demand by the Layer-4.5 generator
(`core/analysis/poc_generator.py`, chain `AISEC_POC_GEN_BACKEND`) for non-self-rejected findings of high
severity and executed in the Docker sandbox. The launchers set that chain to the arm's own detection chain for
the qwen and gemma arms (`experiments/run_jobs_v2.py`) and to `openrouter:qwen3-coder,openrouter:nemotron-120b`
for the final Nemotron detection re-run (`experiments/rerun_nemotron.py`, `round3_run.py`). The
`detection.poc_generation` field of the 20 `st_nemotron_*` manifests, which the backfill script had filled
with "same chain as detection", was corrected to record this; no other manifest field was changed.
