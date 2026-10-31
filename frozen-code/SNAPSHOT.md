# Frozen Code Snapshot — MSFV Paper

A read-only copy of the whitebox vulnerability-detection pipeline code used
in the paper's experiments. Severed from the production repo's git history
on the date below so subsequent production iteration cannot disturb the
experimental baseline.

## Provenance

| Field                | Value                                                 |
|----------------------|-------------------------------------------------------|
| Source repo          | `cevanex-AISecTool` (private, https://github.com/Cevanex) |
| Source commit        | `acaeeb0b617b58d93436858a583e0d3504b04cfd`            |
| Copy date            | 2026-06-05                                            |
| Source working tree  | clean (only untracked `_scan_targets/`, `logs/`, `.claude/` excluded) |
| Python version used  | 3.12 (production venv)                                 |

## Paper scope (what's IN this freeze)

The paper is about the **multi-signal verification** stage of the whitebox
pipeline. The freeze contains the code paths exercised by the experiments:

| Layer  | Phase string      | Role in paper                                            |
|--------|-------------------|----------------------------------------------------------|
| L0     | `init`            | File selection (file_filter fallback path)               |
| L1     | `global_map`      | AST + bidirectional call graph (paper §3 — graph construction) |
| L2     | `semgrep`         | Semgrep raw findings (custom rules + language packs)     |
| L3     | `local_filter`    | Local-model interest filter (Qwen3-Coder primary)        |
| L4     | `opus_analysis`   | Deep per-finding analysis (severity-aware backend)       |
| L4.5   | `fuzz`            | PoC validator — forge subprocess, NO LLM                 |
| L5     | `global_queries`  | Global pattern queries against global_map                |
| L5.5   | `verify_global`   | **Multi-signal verification** — the paper's central stage |

Backend chain layer (`core/ai_engine/`) needed for the Nemotron-via-vLLM path.

## What's OUT (intentionally excluded)

- SaaS / customer-facing Cevanex API (`src/cevanex/api/`, `services/`,
  `repositories/`, `db/`, `domain/`, `security/`) — multi-tenancy,
  webhooks, billing
- Blackbox / pentest / CTF / dashboard / web server
- Tests (focus is reproducibility, not regression coverage)
- `core/skills/` and `core/memory/` (Cevanex/blackbox-specific; pipeline runs
  with `skill_context=""` by default)
- Most of `cevanex/adapters/` (S3 storage, Fernet encryption, postgres,
  webhook dispatchers, report renderers — operational add-ons not needed
  for the detection pipeline)

## What's IN from `cevanex/adapters/` (whitebox-load-bearing)

The paper's "no SaaS, just the pipeline" framing was tightened on 2026-06-08
after the Log4j run produced 0 Jndi findings: missing the language-router
+ query-pack dispatch meant Layer 5 fell back to Solidity-tuned defaults
on Java code. These adapters live above `CheckpointedPipeline` and decide
*what* the pipeline scans + *which* L5 queries fire — they ARE part of the
whitebox flow and the paper experiments must use them.

- `cevanex/adapters/language_router.py` — classifies repo files into
  solidity / general / config / ambiguous / skipped via extension +
  content sniffing
- `cevanex/adapters/query_packs.py` — selects a language-aware L5 query
  pack: `SOLIDITY_QUERIES` / `C_FAMILY_QUERIES` / `LUA_QUERIES` /
  `GENERIC_APP_QUERIES` (Java/Python/JS/Go) + `ALWAYS_ON_QUERIES`
- `cevanex/adapters/llm_router_classifier.py` — LLM disambiguation for
  ambiguous files (unused by minimal runner but kept for completeness)
- `core/analysis/regression_check.py` — Phase-A regression check
  (optional, gated by `AISEC_REGRESSION_CHECK=1`)

## Files in this freeze (58 source files)

```
src/main/core/
  __init__.py
  config.py
  cost_tracker.py
  hooks.py
  ui.py
  analysis/
    __init__.py
    pipeline.py              ← CheckpointedPipeline (L0-L5.5 orchestration)
    scan_state.py            ← phase checkpointing + cost forward
    global_map.py            ← Layer 1 AST + call graph builder
    semgrep_runner.py        ← Layer 2 (incl. "requires login" fix)
    file_filter.py           ← Layer 0 default scope
    local_filter.py          ← Layer 3 per-finding interest filter
    cluster_filter.py        ← Layer 3 cluster-mode opt-in
    defocus.py
    context_bundle.py        ← Layer 4 context assembly
    context_budget.py
    two_tier_context.py
    seed_matchers.py
    poc_validator.py         ← Layer 4.5 (forge subprocess only)
    result_cache.py
    call_graph/              ← slither + tree-sitter integrators
    custom_rules/            ← Semgrep custom rules (Solidity + C/C++)
    platforms/               ← language-specific AST plugins
    sources/                 ← empty namespace package
  ai_engine/
    __init__.py
    mixed_router.py          ← global LM dispatcher
    local_llm.py             ← resolve_task_chain, _VLLM_ALIASES, multi-server routing
    fallback_lm.py           ← FallbackLM (chain + parse-error fast path)
    claude_adapter.py        ← Anthropic adapter
    nvidia_adapter.py        ← vLLM / NVIDIA NIM adapter (Nemotron path)
    ollama_url.py
    prompt_cache_registry.py
  vault/
    __init__.py
    prompts.py               ← render_finding_hint, render_patterns_for_query
    search.py
    client.py

src/cevanex/                ← whitebox-load-bearing adapters only (added 2026-06-08)
  __init__.py
  adapters/
    __init__.py
    language_router.py        ← classify_repo, RouterResult, FileClassification
    query_packs.py            ← select_query_pack + 5 language packs
    llm_router_classifier.py  ← LLM disambiguation for ambiguous files

requirements.txt
.env.example
```

## How to run an experiment

```bash
# 1. Create venv + install deps (frozen as of acaeeb0)
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Configure backends — copy and edit
cp .env.example .env
# minimum env to run the paper experiments:
#   AISEC_VERIFY_BACKEND="vllm:nemotron-120b,vllm:gemma-4-31b,sonnet"
#   AISEC_QUERY_BACKEND="sonnet"
#   AISEC_ANALYSE_CRITICAL_BACKEND="opus,sonnet,vllm:nemotron-120b"
#   AISEC_ANALYSE_HIGH_BACKEND="sonnet,vllm:nemotron-120b"
#   AISEC_LOCAL_FILTER_MODEL="vllm:qwen3-coder,vllm:nemotron-120b,vllm:gemma-4-31b,sonnet"
#   VLLM_URL="http://<your-nemotron-host>:8000/v1"
#   VLLM_GEMMA_URL="http://<your-gemma-host>:8000/v1"
#   VLLM_QWEN_URL="http://<your-qwen-host>:8000/v1"
#   ANTHROPIC_API_KEY="..." (only required if Anthropic appears in any chain)

# 3. Run the pipeline against a target repo
export PYTHONPATH="$(pwd)/src/main:$(pwd)/src"
python -c "
from core.analysis.pipeline import CheckpointedPipeline
from core.analysis.scan_state import ScanState
state = ScanState.load('paper_run_001')
state.mode = 'whitebox'
pipeline = CheckpointedPipeline(state, parallel_workers=3)
results = pipeline.run_whitebox('/path/to/target-repo')
print(f'produced {len(results)} findings')
"
```

## Environment variables used in paper experiments

These were the configurations evaluated. The exact chain composition affects
results — record the value used in each experiment's metadata.

| Variable                          | Paper-experiment value                                       |
|-----------------------------------|--------------------------------------------------------------|
| `AISEC_VERIFY_BACKEND`            | `vllm:nemotron-120b,vllm:gemma-4-31b,sonnet`                 |
| `AISEC_QUERY_BACKEND`             | `sonnet`                                                     |
| `AISEC_ANALYSE_CRITICAL_BACKEND`  | `opus,sonnet,vllm:nemotron-120b`                             |
| `AISEC_ANALYSE_HIGH_BACKEND`      | `sonnet,vllm:nemotron-120b`                                  |
| `AISEC_LOCAL_FILTER_MODEL`        | `vllm:qwen3-coder,vllm:nemotron-120b,vllm:gemma-4-31b,sonnet`|
| `AISEC_CLUSTER_MODE`              | `0` (per-finding L3, not cluster batched)                    |
| `AISEC_PARALLEL_OPUS`             | `3`                                                          |
| `VLLM_URL` / `VLLM_GEMMA_URL` / `VLLM_QWEN_URL` | site-specific Tailscale endpoints                |

## Paper-side ablation patches (frozen-code only, not in production)

These commits sit on top of the initial freeze and are paper-experiment
specific. They are NOT propagated back to production:

| Commit   | Change                                                          |
|----------|-----------------------------------------------------------------|
| `f6e5a0d`| Add `AISEC_DISABLE_POC_VALIDATOR` + `AISEC_DISABLE_VERIFY` knobs|
| `79a3133`| Fix `_parse_output` source_root regression (pre-experiment)     |
| `4ae39d4`| Add `AISEC_TOLERANT_LAYER_ERRORS` knob for strict single-model  |
| `47810b7`| Fix `tui.warn` → `tui.warning` typo in tolerance path           |
| `9e49fc3`| L3 schema de-bias — strip `attack_path` / `severity_hint` /     |
|          | `brief` fields from `NemotronFindingTriage` signature; flip     |
|          | docstring from "default TRUE_POSITIVE" to "default              |
|          | FALSE_POSITIVE". These fields were dead-stored (no downstream   |
|          | reader) but introduced a strong positivity bias: the model      |
|          | committed to filling `attack_path` and reverse-engineered       |
|          | `verdict=TRUE_POSITIVE`. Result: ~7× L4 surface bloat vs the    |
|          | 8-min Opus-4.6 baseline. Restores L3's role as a filter.        |
| pending  | **L5.5 verify scope expansion** — verify now processes BOTH     |
|          | L4 per-finding output AND L5 cross-function prose, not just L5. |
|          | v0.1 only verified L5 (`layer5_results = [...layer == 5]`).     |
|          | Paper §III-B claims "each candidate" is verified; this commit   |
|          | aligns implementation to paper. L4 self-rejected findings       |
|          | ("Confirmed: no") are skipped to avoid 3× cost inflation.       |
|          | All 4 signals (identity, source, concern, PoC verdict) flow     |
|          | through L4 verify exactly as for L5.                            |

## Notable code changes near the snapshot point (last ~24h before acaeeb0)

These commits in production immediately preceded the freeze. They constitute
the experimental baseline:

| Commit   | Subject                                                          |
|----------|------------------------------------------------------------------|
| `acaeeb0`| Layer 4 silent failure — Semgrep "requires login" + abs-path bug |
| `43de3df`| docs: correct pipeline layer numbering vs code                   |
| `961f7f6`| .env.example + RUNBOOK: Qwen L2 primary + sonnet tails           |
| `5917951`| FallbackLM parse-error fast path — skip remaining vLLM links     |
| `1018093`| DSPy parse-error resilience — 3-layer safety net                 |
| `ae7aab3`| docs: agent harness — CLAUDE.md + 4 architecture docs            |
| `a749e27`| audit fixes: cost attribution + L5 chain + PoC gate              |
| `21020b1`| cost + wall-time fixes: severity-aware L4 + parallel regression  |

## Dry-run verification

A dry-run import of all paper-relevant modules succeeds (run 2026-06-05):

```
OK — all paper-relevant modules import cleanly.
  AnalyseFinding output fields: ['vulnerability_analysis', 'poc_solidity', 'poc_strategy', 'expected_outcome']
  GlobalPatternQuery output:    ['findings']
  VerifyFinding output:         ['verdict_json']
  vLLM aliases: ['nemotron-120b', 'nemotron-49b', 'gemma-4-31b', 'qwen3-coder']
  Pricing entries: 16
```

## Missing dependencies note

- `requirements.txt` is the full production list. The paper experiments only
  need a subset — at minimum: `dspy`, `anthropic`, `litellm`, `rich`,
  `pydantic`, `requests`, `pyyaml`. Slither / tree-sitter are needed only
  if you want the Solidity call-graph enrichment in Layer 1 (without them,
  `global_map.py` falls back to a simpler AST walker).
- `forge` (Foundry CLI) is required for Layer 4.5 PoC validation. Without
  it, `PocValidator.is_available()` returns False and the layer auto-skips.
- `semgrep` CLI required for Layer 2.

## Reproducibility caveats

- LLM outputs are non-deterministic across runs even with `temperature=0`
  (model serving infrastructure introduces variability). Multi-run averaging
  is advised for any quantitative claim.
- The Anthropic prompt-cache 5-minute TTL means cold-start vs warm runs
  produce different cost numbers for the same input. Cost claims in the
  paper should specify which.
- vLLM server-reported model IDs occasionally drift across model deploys.
  Check `_VLLM_ALIASES` in `local_llm.py` against `curl $VLLM_URL/v1/models`
  if you see "unknown model" errors.
