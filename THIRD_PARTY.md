# Third-party material

## Benchmarks

The pipeline was run against local checkouts of four public benchmark projects. They are **not** included in
this package; the recorded outputs quote fragments of their source code (Semgrep snippets, function bodies
handed to the models, generated PoC scripts that import or re-implement benchmark functions). To re-run the
pipeline or to re-read the code behind the adjudication items, obtain the checkouts yourself:

| Benchmark | Upstream | Licence | Version used |
|---|---|---|---|
| Damn Vulnerable DeFi (`dvd`) | https://github.com/theredguild/damn-vulnerable-defi | MIT | v4 (Foundry edition); commit: see `BENCHMARK_COMMITS` below |
| OWASP PyGoat (`pygoat`) | https://github.com/adeyosemanputra/pygoat | MIT | commit: see below |
| OWASP NodeGoat (`nodegoat`) | https://github.com/OWASP/NodeGoat | Apache-2.0 | package.json version 1.3.0; commit: see below |
| SmartBugs-curated (`smartbugs`) | https://github.com/smartbugs/smartbugs-curated | Apache-2.0 | commit `230e649123477eff332742a59a1c7cc6dc286cab` (2024-06-16) |

`BENCHMARK_COMMITS`: the exact commits of the dvd/pygoat/nodegoat checkouts used for the runs
(`_scan_targets/<benchmark>`) were not recorded by the pipeline. If you hold the original checkouts, record
them with `git -C _scan_targets/<benchmark> rev-parse HEAD` and add them here.

The ground truth in `experiments/ground_truth/` was derived from each benchmark's own documentation as
described in `experiments/ground_truth/GROUND_TRUTH.md`; `smartbugs_vulnerabilities.json` is the upstream
annotation file of SmartBugs-curated, copied verbatim (Apache License 2.0, Copyright the SmartBugs authors).

## Semgrep

The detection stage runs the `semgrep` CLI with the first-party rule packs in
`frozen-code/src/main/core/analysis/custom_rules/` **and** with registry packs fetched live from the Semgrep
Registry (`p/security-audit`, `p/smart-contracts`, `p/python`, `p/javascript`, `p/nodejs`, `p/nodejsscan`,
`p/typescript`, `p/golang`, `p/java`, `p/kotlin`, `p/rust`, `p/php`, `p/ruby`, `p/csharp`, `p/c`,
`p/cwe-top-25`; see `semgrep_runner.py`). Registry content is governed by Semgrep's terms, is not
redistributed here, is versioned server-side and was not pinned; some registry rules behave differently for
authenticated and anonymous users. The `rule_id` values in the recorded findings identify the rule that fired.

## Models

Inference used third-party hosted models through OpenRouter: `qwen/qwen3-coder-next`,
`google/gemma-4-31b-it`, `nvidia/nemotron-3-super-120b-a12b`. Their outputs (analyses, PoC code, verdicts)
are recorded in the data as produced. The adjudication study used Claude Opus 4.8 and Claude Fable 5.1
(Anthropic) as independent judges; their labels and justifications are in `data/adjudication/`.

## Docker sandbox

`frozen-code/docker/Dockerfile.poc-sandbox` builds on `debian:bookworm-slim` with distribution packages
(clang, g++, make, python3, nodejs, golang, rustc, cargo); no third-party code is vendored.
