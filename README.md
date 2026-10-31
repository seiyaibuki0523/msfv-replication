# Replication package — *Reducing Hallucinated False Positives in LLM-Based Vulnerability Detection via Multi-Signal Focused Verification*

Casper Chen (Cevanex, Taipei, Taiwan). Manuscript submitted to IEEE Access. Package version 1.0 (2026-09-11).

> **GitHub mirror of the Zenodo replication package.** The article has since been published:
> C. Chen, "Reducing Hallucinated False Positives in LLM-Based Vulnerability Detection via Multi-Signal Focused
> Verification," *IEEE Access*, vol. 14, pp. 153128–153147, 2026, doi: [10.1109/ACCESS.2026.3739345](https://doi.org/10.1109/ACCESS.2026.3739345)
> (published 2 October 2026; open access, CC BY 4.0; [IEEE Xplore](https://ieeexplore.ieee.org/document/11719504)).
>
> * Every file in this repository is byte-identical to the archived package `msfv-replication-package-v1.0.tar.gz`
>   ([doi:10.5281/zenodo.22704663](https://doi.org/10.5281/zenodo.22704663), SHA-256
>   `e948413aba7d7ad193a3170cd0d5792079c7cf578d3a08d6df67e9a1525fc3cc`), except this `README.md`, which carries
>   this notice above the archived text. `sha256sum -c CHECKSUMS.sha256 --ignore-missing` therefore reports exactly
>   one mismatch (`README.md`); the archived `README.md` is at tag `zenodo-v1.0`.
> * **`data/ablation/` — the raw run outputs (132 run directories, 3,024 files, 2.8 GB) — is not committed to git.**
>   `scripts/fetch_zenodo_data.sh` downloads it from Zenodo, verifies every part, the reassembled archive and the
>   extracted files, and puts it where the scripts below expect it (see `data/ablation/README.md`).
> * Package version 1.1 ([doi:10.5281/zenodo.23030516](https://doi.org/10.5281/zenodo.23030516), 2026-09-29) added
>   `analysis/analysis_final_revision.py` and `README_v1.1.md`, which accompany the accepted article (Table 4 over the
>   verification pool, F1 over all runs, alert-count terminology, random-removal reference); both are included.
>   After `load.py`, run `python3 analysis_final_revision.py pkg.pkl` in `analysis/`.
> * Tags `zenodo-v1.0` and `zenodo-v1.1` mark the trees exactly as archived; `main` adds only this notice,
>   `scripts/fetch_zenodo_data.sh`, `data/ablation/README.md`, `.gitignore` and `CITATION.cff`.

This package contains everything needed to (a) recompute every table in the article from the recorded
per-finding outputs, (b) audit the adjudication study, and (c) re-run the pipeline itself.

| Directory | Contents |
|---|---|
| `frozen-code/` | The pipeline as it ran (detection layers 0–5, the multi-signal verification stage 5.5, PoC generator/validator/sandbox, Semgrep rule packs). `frozen-code/versions/` holds the round-1 version of the two files that changed between rounds (see `CODE_VERSIONS.md`). |
| `experiments/` | The scripts that launched every run (`run_ablation_fast.py` is the driver; `run_jobs_v2.py`, `rerun_nemotron.py`, `round3_run.py`, `round4_run.py` are the batch launchers), `write_manifests.py`, and `ground_truth/` (the labelled vulnerabilities of the four benchmarks). |
| `data/ablation/` | **132 run directories, 964 run-configurations**: the raw output of every configuration reported in the article. |
| `data/adjudication/` | The 253-item adjudication study of RQ1 (protocol, items, both judges' labels and justifications, scripts). |
| `analysis/` | Scripts that regenerate the tables of the article from `data/ablation/` (see `analysis/README.md`). |
| `jobs/` | Job lists, progress files and run reports of the four experiment rounds (some operator notes are in Chinese). |
| `analyze/` | Earlier analysis helpers of the author (superseded by `analysis/`, kept for provenance). |
| `CHECKSUMS.sha256` | SHA-256 of every file in the package. |

Licences: code (`frozen-code/`, `experiments/`, `analysis/`, `analyze/`, `data/adjudication/*.py`) under the MIT
licence (`LICENSE`); data and documents (`data/`, `jobs/`, `*.md`) under CC BY 4.0 (`LICENSE-DATA`). Third-party
material quoted in the data is listed in `THIRD_PARTY.md`.

## 1. The run directories

Each run directory is named `st_<detector>[-v<verifier>]_<benchmark>_s<seed>`:

* `<detector>` ∈ `qwen` (qwen3-coder), `gemma` (gemma-4-31B), `nemotron` (Nemotron-3-Super-120B-A12B) — the model
  that produced the candidate pool (detection, PoC generation);
* `-v<verifier>` is present only for the cross-verifier experiment (RQ7b), where a frozen pool produced by
  `<detector>` was verified by `<verifier>`; without the suffix the verifier is Nemotron-3-Super-120B-A12B;
* `<benchmark>` ∈ `dvd` (Damn Vulnerable DeFi), `pygoat`, `nodegoat`, `smartbugs` (SmartBugs-curated);
* `<seed>` ∈ 1–5 (main experiments) or 1–3 (cross-verifier and repeat passes).

Inside a run directory every configuration is a sub-directory with three files:

| File | Content |
|---|---|
| `findings.json` | One record per candidate finding: `finding` (Semgrep rule id, file, line, message, CWE), `layer` (4 = per-finding deep analysis, 5 = proactive category scan), `analysis` (the detection model's write-up, starting with `Confirmed: yes/no`), `poc` (generated proof-of-concept code and its execution result), `verification` (the verifier's verdicts for the (file, function) pairs of the finding), `severity_override`, `note`. |
| `metadata.json` | `findings_count`, `shipped`, `verify_signals`, PoC counters (`poc_emit`, `poc_compile`, `poc_triggered`), elapsed time. |
| `scan_state.json` | The complete pipeline state: selected files, Semgrep results, per-layer outputs, token and call counters. |

and the run directory carries one `manifest.json` with the inference settings of its detection and verification
arms (model ids, temperature, top_p, max_tokens, reasoning mode, provider pinning, concurrency, seed handling,
tool versions, and the SHA-256 prefix of `pipeline.py`; see `CODE_VERSIONS.md` for how to read that field).

Configuration names (`metadata.json:verify_signals` gives the admitted signals):

| Name | Signals | Used for |
|---|---|---|
| `baseline` | verification disabled | the no-verification reference (denominator of the false-positive reduction) |
| `full` | identity, source, concern, PoC | main result; `full_rep2`, `full_rep3` are repeated verification passes over the same frozen pool |
| `noidentity`, `nosource`, `noconcern`, `nopoc` | leave-one-out | signal ablation (no `nopoc` on SmartBugs, where the PoC signal is structurally absent) |
| `keep_IS`, `keep_IC`, `keep_IP`, `keep_SC`, `keep_SP`, `keep_CP`, `only_I`, `only_S`, `only_C`, `only_P` | two- and one-signal subsets | the complete power set (qwen detection, seeds 1–5) |
| `noconcern_full` | identity, source, PoC | a second no-concern pass kept for completeness |
| `naive_verify` | all four, single unstructured prompt | the RQ4 single-prompt control (`AISEC_VERIFY_MODE=naive`) |

Counts: 60 main run directories (3 detectors × 4 benchmarks × 5 seeds), 72 cross-verifier run directories
(3 pools × 2 verifiers × 4 benchmarks × 3 seeds); 964 configuration directories in total (820 from rounds 1–3,
144 from round 4: the cross-verifier cells of the Nemotron pool and the repeat passes needed to bring every
cross-verifier cell to n = 9).

**Ship rules.** A finding is *not* shipped when (1) the detection layer self-rejected it (`Confirmed: no`),
(2) every verification verdict attached to it is `false_positive`, (3) at the precision-first threshold only,
every verdict is `false_positive` or `downgraded`, or (4) its severity is clamped to informational.
`analysis/load.py` applies these rules and checks that they reproduce `metadata.json:shipped` for all 964
configurations (they do).

## 2. Regenerating the tables

```
cd analysis
python3 load.py ../data/ablation pkg.pkl      # ~1 min; prints "configs 964" and no SHIP MISMATCH lines
python3 emit_tex.py                           # LaTeX bodies of every table of the article
python3 extra.py                              # agreement, PoC recall cost, seed evidence, cost/latency
```

Requires Python ≥ 3.10 with `numpy` and `scipy`. `analysis/README.md` maps each table of the article to the
function that computes it and states the matching rules (file-level and mechanism-aware criteria, CWE → class
mapping, significance tests, kappa).

## 3. The adjudication study (RQ1)

`data/adjudication/` contains `PROTOCOL.md` (the instructions both judges received), `items.json` (the 253
sampled claims with the information shown to the judges), `hidden.json` (the verifier decision, PoC state and
benchmark label withheld from the judges), `batches/` and `results/` (per-judge inputs and outputs),
`merged.csv`/`merged.json` (both labels and justifications per item), `summary.json` (the numbers in the table),
`make_sample.py` (sampling) and `analyze.py` (aggregation). The judges read the benchmark source from local
checkouts (`source_root`); obtain them as described in `THIRD_PARTY.md`.

## 4. Re-running the pipeline

Prerequisites: Python 3.12, the packages in `frozen-code/requirements.txt`, the `semgrep` CLI, Foundry
(`forge` 1.7.1 was used) for Solidity PoCs, Docker for the multi-language PoC sandbox
(`frozen-code/docker/`), an OpenRouter API key, and local checkouts of the benchmarks (`THIRD_PARTY.md`).

```
cp frozen-code/.env.example frozen-code/.env       # fill in OPENROUTER_API_KEY
export MSFV_ROOT=$(pwd)                            # this package
export MSFV_SCAN_TARGETS=/path/to/_scan_targets    # contains dvd/ pygoat/ nodegoat/ smartbugs/
export PYTHONPATH=$MSFV_ROOT/frozen-code/src/main:$MSFV_ROOT/frozen-code/src
python3 experiments/run_ablation_fast.py --help    # single cell; see the docstring for AISEC_ABL_* switches
python3 experiments/run_jobs_v2.py                 # round-1 batch (jobs/v2/jobs.csv)
```

The runner scripts originally carried absolute paths of the author's machine; they now read `MSFV_ROOT`,
`MSFV_SCAN_TARGETS`, `MSFV_PYTHON`, `MSFV_ENV_FILE`, `AISEC_ROOT` and `AISEC_WORKSPACE` with defaults relative
to this package. Budget: the 641 configurations of round 1 took about 22 hours of wall-clock time on
OpenRouter at the concurrencies recorded in the manifests.

Reproducibility caveats (also in the article, Section IV-E RQ8): OpenRouter providers did not honour the
`seed` parameter, so repeated passes with identical settings differ (the variance decomposition and the
finding-level agreement tables quantify this); Semgrep registry packs are fetched at scan time and are not
version-pinned; the Nemotron detection arm had to be pinned to one provider and run with reasoning off to
become reproducible (`jobs/FINAL_RUN_REPORT.md` documents the diagnosis).

## 5. What was redacted

The recorded outputs are published as produced, with these mechanical substitutions applied uniformly to
every text file (`analysis/../CHECKSUMS.sha256` covers the redacted files):

* absolute paths of the author's machine were replaced: benchmark file paths are now relative to the benchmark
  root (`pygoat/introduction/views.py`), other paths use the placeholders `<MSFV_ROOT>`, `<AISEC_ROOT>`,
  `<AISEC_WORKSPACE>`, `<HOME>`, `<BENCHMARK_CHECKOUTS>`;
* the Semgrep `rule_id` of custom rules, which Semgrep derives from the absolute path of the rule file,
  was normalised from `Users.….custom_rules.<rule>` to `custom_rules.<rule>` (the rule files are in
  `frozen-code/src/main/core/analysis/custom_rules/`);
* private host addresses and the run host's name were replaced by placeholders;
* `frozen-code/.env.example` was reduced to the pipeline's own configuration (the deployment configuration of
  the commercial product the code was frozen from was removed).

No finding, verdict, count or timestamp was altered.

## 6. Known gaps

* `frozen-code/requirements.txt` is the production list without exact pins; the versions installed on the run
  host were not recorded. `python-dotenv` and `pydantic-settings`, which the code imports, were added.
* The exact upstream commits of the benchmark checkouts are given in `THIRD_PARTY.md` where known.
* `frozen-code/SNAPSHOT.md` (written at freeze time) under-describes the tree: it lists 58 source files (there
  are 62; `poc_generator.py`, `poc_sandbox.py` and `regression_check.py` are present but not listed), describes
  `custom_rules/` as Solidity + C/C++ (nine language packs are present), and marks the "L5.5 verify scope"
  item as pending although it is implemented (`pipeline.py`, `l4_to_verify`).
* The provider pin of the final Nemotron *detection* re-run (2026-08-22) is recorded as DeepInfra in
  `jobs/FINAL_RUN_REPORT.md` and in the manifests; `experiments/rerun_nemotron.py` accepts the provider from the
  environment and its fallback default is a different provider. The launch environment is not part of the package.

## 7. Citation

Please cite the article and this package:

> C. Chen, "Reducing Hallucinated False Positives in LLM-Based Vulnerability Detection via Multi-Signal Focused
> Verification," IEEE Access, 2026. Replication package: Zenodo, version 1.0 (the DOI is shown on the Zenodo
> record page that hosts this archive).
