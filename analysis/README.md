# Regenerating the tables of the article

```
python3 load.py ../data/ablation pkg.pkl     # reads every findings/metadata/scan_state file (964 configurations)
python3 emit_tex.py                          # prints the LaTeX body of every table
python3 emit_tex.py volume recall            # or a subset
python3 extra.py                             # the derived numbers quoted in the text (see below)
```

`load.py` prints `configs 964` and must print no `SHIP MISMATCH` line: it re-derives each configuration's
shipped count from the four ship rules and checks it against `metadata.json:shipped`. Requires Python ≥ 3.10,
`numpy`, `scipy`. Environment overrides: `MSFV_PKL` (pickle path), `MSFV_GT_DIR` (ground-truth directory),
`MSFV_SB_JSON` (SmartBugs annotation file).

| Article table | `emit_tex.py` name | Computation (`recompute.py` / `extra.py`) |
|---|---|---|
| 1 PoC states | `poc` | `Analysis.table_poc` — PoC emission/compile/trigger counts pooled over detectors and runs |
| 2(a) variance decomposition | `repro` | `Analysis.table_repro` — SD over five runs vs SD over three passes on the seed-1 pool |
| 3 detection breadth, volume, FP-cut | `volume` | `Analysis.table_volume` — baseline vs shipped counts, FP-cut = 1 − shipped/baseline, 95% CI (t, n=5) |
| 4 classification (both criteria) | `classification` | `Analysis.table_classification(mech=True/False)` — finding-level confusion matrix, per-run percentages averaged |
| 5 vulnerability-level recall | `recall` | `Analysis.table_recall` — retention = caught/detected, E2E = caught/GT |
| 6 precision before/after | `selectivity` | pooled over five runs: TP/FP in the baseline pool, precision at none/P1/R1, removal rates |
| 7 adjudication | `adjudication` | `../data/adjudication/analyze.py` → `summary.json` (judge B primary; A and the agreed subset C) |
| 8 marginal contribution | `marginal` | `Analysis.table_marginal` — mean change in shipped count over the subset pairs that differ in one signal |
| 9 leave-one-out, three detectors | `ablation_models` | `Analysis.table_ablation_models` |
| 10 cross-verifier | `crossverifier` | `Analysis.table_crossverifier(pools=3)` + `extra.cross_prec_ret` — n = 9 per cell (3 seeds × 3 passes) |
| 11 finding-level stability | `agreement` | `extra.agreement_main` (seed-1 pools, three Nemotron passes), `extra.agreement_cross` (seeds 1–3 × 3 passes); Fleiss' κ |
| 12 power set | `powerset` | `Analysis.table_powerset` |
| 13 paired significance | `significance_simple` | `Analysis.table_significance` — exact binomial on discordant findings, Holm within each model × benchmark cell |
| 14 single-signal agreement | `kappa` | `Analysis.table_kappa` — Cohen's κ / φ on (file, function) verdict keys, "any confirmed" binarisation |
| 15 CWE → class mapping | (static) | `gt.CWEMAP`, `gt.L5MAP` |
| 16 label provenance | `provenance` | `Analysis.table_provenance` |

`expected_output/` holds the output of these commands on the released data (`tables_regenerated.tex`,
`text_numbers_regenerated.txt`); every table body there matches the article.

Two remarks on provenance. (1) `experiments/eval_recall.py` and `eval_mechanism.py` are the author's original
evaluation scripts; under the file-level criterion `eval_recall.py` additionally credits a vulnerability when a
Layer-5 (proactive-scan) record cites its file, which on SmartBugs credits one contract more than the
Layer-4-only rule used for every row of Table 5 (Detect 95.2 instead of 94.2). The article reports the
Layer-4-only figures of `recompute.py`. (2) Table 16 pools the label provenance over all 964 configurations of
this package; verification passes re-list the findings of their frozen pool, so the table weights each pool by
the number of passes run on it.

Numbers quoted in the text but not in a table come from `extra.py`: finding-level agreement (A), precision of
every configuration (B), cost and latency (C), the run-configuration inventory (D), the same-seed evidence
(E), and the PoC recall cost and PoC nature (F); `emit_tex.py poc_cost` prints the RQ3 PoC-cost rows.

Matching rules (implemented in `gt.py` / `recompute.py`): only Layer-4 findings can match a labelled
vulnerability; the ground-truth file is matched by path suffix; the finding's class comes from its CWE
numbers through Table 15 (`gt.CWEMAP`) or, for Layer-5 records, from the query name (`gt.L5MAP`), and is
otherwise *unmappable*; the file-level criterion requires only the file, the mechanism-aware criterion also
the class; SmartBugs is matched per contract; "Detect" counts labelled vulnerabilities caught by the
no-verification baseline after detector self-rejection; a finding is shipped under the four rules listed in
the top-level README.
