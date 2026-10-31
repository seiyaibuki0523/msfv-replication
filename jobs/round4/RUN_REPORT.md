# MSFV Round-4 — Run Report

Completed 2026-09-10 13:48 on the run host. Verification only — no detection was re-run.

## Completion
- **104/104 configs done, 0 failed** (`progress.csv`); `failures.log` empty.
- B2: 16 run_dirs × {full_rep2, full_rep3} = 32 ✅
- C : 24 run_dirs × {full, full_rep2, full_rep3} = 72 ✅
- Manifests written by `write_manifests.py`: **92 new, 40 kept → 132 total** (= 108 original + 24 new C run_dirs) ✅

## Actual concurrency / provider
| batch | verifier | run_dirs in parallel | per-run conc | provider |
|---|---|---|---|---|
| B2 | Nemotron-3-Super-120B-A12B | 2 | 4 | **DeepInfra pinned** (reasoning on, temp 0.2, default max_tokens — same as round-3 Nemotron verify) |
| C | gemma-4-31B / qwen3-coder | 6 | 8 | **not pinned** (same as round-1/3 gemma/qwen verifiers) |

## Acceptance
1. SHIP rules reproduce `metadata.shipped`: `load.py` over `data/ablation` → **948 configs, 0 `SHIP MISMATCH`** ✅
2. C batch baseline integrity: `st_nemotron-v{gemma,qwen}_{bench}_s{1,2,3}/baseline` `findings_count` == `st_nemotron_{bench}_s{seed}/baseline` for **all 24** ✅ (pools copied, never re-detected)
3. Manifest count `ls data/ablation/st_*/manifest.json | wc -l` = **132** ✅

## B2 — new rep shipped vs existing `full` (Nemotron verifier)
| run_dir | full | rep2 | rep3 | note |
|---|---|---|---|---|
| st_gemma_dvd_s2 | 46 | 25 | 33 | ⚠ rep2 Δ−21 |
| st_gemma_dvd_s3 | 39 | 44 | 39 | |
| st_gemma_pygoat_s2 | 38 | 33 | 30 | |
| st_gemma_pygoat_s3 | 40 | 30 | 37 | |
| st_gemma_nodegoat_s2 | 23 | 23 | 19 | |
| st_gemma_nodegoat_s3 | 23 | 22 | 20 | |
| st_gemma_smartbugs_s2 | 253 | 254 | 239 | |
| st_gemma_smartbugs_s3 | 271 | 264 | 262 | |
| st_qwen_dvd_s2 | 38 | 37 | 37 | |
| st_qwen_dvd_s3 | 41 | 43 | 38 | |
| st_qwen_pygoat_s2 | 34 | 31 | 33 | |
| st_qwen_pygoat_s3 | 31 | 23 | 27 | |
| st_qwen_nodegoat_s2 | 9 | 8 | 10 | |
| st_qwen_nodegoat_s3 | 14 | 11 | 12 | |
| st_qwen_smartbugs_s2 | 162 | 138 | 157 | ⚠ rep2 Δ−24 |
| st_qwen_smartbugs_s3 | 167 | 153 | 155 | |

Two cells exceed the |Δ|≥20 screen (`gemma_dvd_s2` rep2, `qwen_smartbugs_s2` rep2). In both, the other rep sits close to `full`, consistent with Nemotron reasoning-on run-to-run variance (temp 0.2, seed not honoured by OpenRouter). **Kept as-is per instructions — reported, not deleted.** Final screen against ±3×SD_verif from Table 2(a) to be applied at analysis time.

## Not done (by design)
No detection re-run; existing `full`/`full_rep*`/LOO/power-set directories untouched; gemma/qwen verifiers not pinned.

---

## Addendum (round-4b) — Nemotron-pool self cell, 16 configs ✅

Completed 2026-09-10 15:45. `st_nemotron_{dvd,pygoat,nodegoat,smartbugs}_s{2,3}` × {full_rep2, full_rep3}
(Nemotron verifier, DeepInfra pinned, conc=4, 2 run_dirs in parallel — same as B2). Table 8's Nemotron-pool
self cell goes from n=5 to n=9; all 36 cells are now 3 pools × 3 reps.

- **16/16 done, 0 failed**; `failures.log` empty; `load.py` → 964 configs, **0 SHIP MISMATCH**.
- No detection re-run; `write_manifests.py` not needed (these 8 run_dirs already had manifests).
- Package: `msfv-round4b-2026-09-10-nemotron-self-reps.tar.gz` (8 run_dirs, 27M).

| run_dir | full | rep2 | rep3 |
|---|---|---|---|
| st_nemotron_dvd_s2 | 19 | 20 | 19 |
| st_nemotron_dvd_s3 | 19 | 16 | 18 |
| st_nemotron_pygoat_s2 | 64 | 63 | 67 |
| st_nemotron_pygoat_s3 | 62 | 64 | 60 |
| st_nemotron_nodegoat_s2 | 23 | 23 | 23 |
| st_nemotron_nodegoat_s3 | 23 | 24 | 23 |
| st_nemotron_smartbugs_s2 | 134 | 122 | 122 |
| st_nemotron_smartbugs_s3 | 108 | 123 | 126 |

No cell exceeds the |Δ|≥20 screen. Note `smartbugs_s3`: the existing `full` (108) sits below both new reps
(123/126, Δ+15/+18) — within tolerance, flagged only for the Table 2(a) ±3×SD_verif check at analysis time.
