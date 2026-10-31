# MSFV v2 batch — RUN_REPORT

Generated: 2026-08-21 (all-OpenRouter, the run host). Elapsed ≈ 22h.

## Completion
- **Required (optional=no): 641/641 done** (60/60 detection, 581/581 verification)
- **Failed: 0**
- **Skipped (optional=yes): 36** — Tier-3 EXTERNAL-FAMILY verifier (spec: run only if the three in-house verifiers land too close; not triggered)

## Timing per benchmark (minutes, from progress.csv)

| benchmark | detection median | detection max | verify median | verify max |
|---|---|---|---|---|
| dvd | 12 | 72 | 124 | 194 |
| pygoat | 22 | 140 | 77 | 100 |
| nodegoat | 6 | 85 | 14 | 19 |
| smartbugs | 44 | 81 | 86 | 124 |

## Manifest parameter consistency
- ✅ All 60 run manifests share identical temperature / top_p / max_tokens / prompt_template_hash.
- tool_versions distinct sets: 1 (✅ uniform)

## Anomalies
- Detection runs > 2× benchmark median:
  - dvd: 27 min
  - dvd: 44 min
  - dvd: 42 min
  - dvd: 64 min
  - dvd: 72 min
  - pygoat: 72 min
  - pygoat: 74 min
  - pygoat: 94 min
  - pygoat: 108 min
  - pygoat: 140 min
  - nodegoat: 68 min
  - nodegoat: 35 min
  - nodegoat: 53 min
  - nodegoat: 85 min
- Findings count deviating > 50% from same model+benchmark median:
  - st_nemotron_dvd_s5: 22 vs median 56
  - st_nemotron_dvd_s4: 16 vs median 56
  - st_nemotron_pygoat_s4: 31 vs median 65
  - st_nemotron_nodegoat_s1: 3 vs median 26
  - st_nemotron_nodegoat_s3: 45 vs median 26
  - st_nemotron_smartbugs_s1: 219 vs median 82

## Notes
- All detection ran once per run_dir; every verify config shared that run_dir's candidate pool (hard rule).
- Tier-3 cross-model verify (gemma/qwen verifiers) reused the frozen qwen pool via source_pool.
- Full 4-signal ablation: identity/concern now independently removable; per-signal contribution recovered by joining only_* configs on (file, function).
- SmartBugs PoC configs excluded per spec (1161 emitted / 0 compiled).