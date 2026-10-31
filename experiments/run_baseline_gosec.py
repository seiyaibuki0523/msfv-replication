#!/usr/bin/env python3
"""Paper §4 experiment runner — detection-only baseline (no verify, no PoC).

Usage:
    python run_baseline.py <run_id>

Each invocation:
  * Forces strict Sonnet-only on every layer that calls an LM
    (single-model variable control).
  * Disables Layer 4.5 PocValidator and Layer 5.5 multi-signal verify via the
    paper-specific env gates added in frozen-code commit f6e5a0d.
  * Clears the result cache so each run is a hermetic fresh scan.
  * Persists all findings + ScanState + metadata under
      ./dvd_no_verify/run_<run_id>/

The output of this script feeds the FP-rate calculation that goes opposite
the multi-signal-verified runs in the paper.

Prior baseline (Nemotron-only, run_1.nemotron_partial_archive/) crashed
mid-L4 with empty-response AdapterParseError — moved to a sibling
archive folder for reference. Sonnet variant doesn't hit that.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path


# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #

FROZEN = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "frozen-code"))
EXPERIMENTS = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "data/gosec_no_verify"))
TARGET = Path(os.path.join(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"), "gosec"))
PROD_ENV = Path(os.environ.get("MSFV_ENV_FILE", os.path.expanduser("~/.aisec.env")))

# Strict Nemotron-only on every layer. Single-model variable control.
# Nemotron occasionally returns an empty response (~0.5-1% per call)
# which DSPy surfaces as AdapterParseError. The TOLERANT_LAYER_ERRORS
# knob (set below) keeps the per-call success in the ScanState so the
# run completes with ~200 partial findings rather than discarding
# everything on the first failure.
BACKEND = "vllm:nemotron-120b"


# --------------------------------------------------------------------------- #
# Boot                                                                        #
# --------------------------------------------------------------------------- #

def setup_env() -> None:
    """Push all backend env vars + paper ablation flags before importing core.*."""
    # Load production .env for VLLM_URL / ANTHROPIC_API_KEY (boot wants
    # them present even if we don't use Anthropic).
    if PROD_ENV.exists():
        for line in PROD_ENV.read_text().splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k.strip(), v)

    # Strict Sonnet on every LM-touching layer.
    for env in [
        "AISEC_LOCAL_FILTER_MODEL",
        "AISEC_CLUSTER_MODEL",
        "AISEC_ANALYSE_CRITICAL_BACKEND",
        "AISEC_ANALYSE_HIGH_BACKEND",
        "AISEC_QUERY_BACKEND",
        "AISEC_VERIFY_BACKEND",          # disabled but set for completeness
        "AISEC_POC_VERIFY_BACKEND",      # disabled, ditto
    ]:
        os.environ[env] = BACKEND

    # Paper ablation flags.
    os.environ["AISEC_DISABLE_POC_VALIDATOR"] = "1"
    os.environ["AISEC_DISABLE_VERIFY"] = "1"

    # Tolerate per-call failures (defence in depth — Sonnet rarely
    # parse-errors, but a transient 5xx shouldn't trash a 200-call run).
    os.environ["AISEC_TOLERANT_LAYER_ERRORS"] = "1"

    # Resource cap.
    os.environ["AISEC_PARALLEL_OPUS"] = "3"

    # Result cache + state checkpoint live under the cevanex workspace.
    # Reuse it so we don't fight the global singleton paths inside core.config.
    os.environ.setdefault(
        "AISEC_WORKSPACE", os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace")
    )

    # PYTHONPATH must include frozen-code's src/main BEFORE production paths
    # so we exercise the snapshotted code, not production. Also add src/ so
    # the cevanex package (language_router, query_packs) resolves.
    sys.path.insert(0, str(FROZEN / "src" / "main"))
    sys.path.insert(0, str(FROZEN / "src"))


def clear_caches() -> None:
    """Wipe the result cache so each run is hermetic.

    Note: does NOT wipe sibling-run state files — those are per-run
    (unique timestamped state_id) and contain partial salvage data
    that must survive even if a later run starts. Earlier versions
    wiped paper_run_*.json globally and destroyed run_2's salvage
    when run_3 booted (paper §4 incident, commit 47810b7).
    """
    workspace = Path(os.environ["AISEC_WORKSPACE"])
    cache = workspace / "cache" / "findings"
    for entry in cache.glob("*.json") if cache.exists() else []:
        entry.unlink(missing_ok=True)
    # DVD repo: drop forge artifacts (irrelevant once L4.5 disabled, but
    # keeps the repo file count stable from run to run).
    for sub in ("lib", "out", "cache", "test/fuzz"):
        path = TARGET / sub
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Run                                                                         #
# --------------------------------------------------------------------------- #

def run_once(run_id: str) -> dict:
    out_dir = EXPERIMENTS / f"run_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    clear_caches()

    # Late import — env must be set first.
    from core.analysis.pipeline import CheckpointedPipeline
    from core.analysis.scan_state import ScanState
    from cevanex.adapters.language_router import classify_repo
    from cevanex.adapters.query_packs import select_query_pack

    state_id = f"paper_run_{run_id}_{int(time.time())}"
    state = ScanState.load(state_id)
    state.mode = "whitebox"

    # Cross-language dispatch (mirrors production scan_runners). Layer 5
    # falls back to Solidity-tuned defaults without this — useless on
    # Java / TS / Python. Detection-only baseline still needs it because
    # the L5 queries that run at all run from this pack.
    triage = classify_repo(str(TARGET))
    pack_label, custom_queries = select_query_pack(triage)
    print(f"  router:    solidity={len(triage.solidity)} general={len(triage.general)} "
          f"config={len(triage.config)} ambiguous={len(triage.ambiguous)} "
          f"skipped={len(triage.skipped)}")
    print(f"  L5 pack:   {pack_label}  ({len(custom_queries)} queries)")

    pipeline = CheckpointedPipeline(
        state, parallel_workers=3, custom_queries=custom_queries,
    )

    print(f"=== gosec baseline run_{run_id} @ {time.strftime('%Y-%m-%d %H:%M:%S')} ===")
    print(f"  target:  {TARGET}")
    print(f"  state:   {state_id}")
    print(f"  output:  {out_dir}")
    print(f"  backends: ALL = {BACKEND}")
    print(f"  ablation: AISEC_DISABLE_POC_VALIDATOR=1 AISEC_DISABLE_VERIFY=1")
    print()

    start = time.time()
    error_msg: str | None = None
    results: list[dict] = []
    try:
        results = list(pipeline.run_whitebox(str(TARGET)) or [])
    except Exception as exc:  # noqa: BLE001
        error_msg = f"{type(exc).__name__}: {exc}"
        print(f"\n!!! Pipeline raised: {error_msg}")
        # Salvage partial results from the live ScanState — even with
        # AISEC_TOLERANT_LAYER_ERRORS=1, an unrecoverable error (rate
        # limit exhausted, auth failure, etc.) still terminates the
        # run, but the successful per-finding results already saved
        # to state are still valid paper-side data.
        workspace = Path(os.environ["AISEC_WORKSPACE"])
        state_file = workspace / "state" / f"{state_id}.json"
        if state_file.exists():
            try:
                live = json.loads(state_file.read_text())
                results = live.get("opus_results", [])
                print(f"    ↳ salvaged {len(results)} partial results from ScanState")
            except Exception as inner:  # noqa: BLE001
                print(f"    ↳ salvage failed: {inner}")
    elapsed = time.time() - start

    # --- persist results --------------------------------------------------- #
    (out_dir / "findings.json").write_text(
        json.dumps(results, default=str, indent=2)
    )

    # Copy the live ScanState checkpoint into the run folder.
    # ScanState writes ``{target_id}.json`` — note that target_id has no
    # ``cev_`` prefix when the runner creates the state directly (only
    # the Cevanex API path prefixes it).
    workspace = Path(os.environ["AISEC_WORKSPACE"])
    state_file = workspace / "state" / f"{state_id}.json"
    if state_file.exists():
        shutil.copy(state_file, out_dir / "scan_state.json")

    metadata = {
        "run_id": run_id,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(start)),
        "elapsed_seconds": round(elapsed, 2),
        "elapsed_human": f"{int(elapsed // 60)}m {int(elapsed % 60)}s",
        "target": str(TARGET),
        "state_id": state_id,
        "findings_count": len(results),
        "error": error_msg,
        "backends_all_layers": BACKEND,
        "ablation": {
            "AISEC_DISABLE_POC_VALIDATOR": True,
            "AISEC_DISABLE_VERIFY": True,
        },
        "parallel_workers": 3,
        "frozen_commit": "f6e5a0d",
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    # --- summary print ----------------------------------------------------- #
    by_layer = {}
    by_severity = {}
    for r in results:
        layer = r.get("layer", "?")
        by_layer[layer] = by_layer.get(layer, 0) + 1
        sev = (r.get("finding", {}).get("severity")
               or r.get("severity", "")).upper() or "?"
        by_severity[sev] = by_severity.get(sev, 0) + 1

    print()
    print(f"=== run_{run_id} done in {metadata['elapsed_human']} ===")
    print(f"  findings: {len(results)}")
    print(f"  by layer: {by_layer}")
    print(f"  by severity: {by_severity}")
    if error_msg:
        print(f"  ERROR:    {error_msg}")
    print()

    return metadata


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    setup_env()
    meta = run_once(sys.argv[1])
    sys.exit(0 if meta.get("error") is None else 1)
