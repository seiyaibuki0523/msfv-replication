#!/usr/bin/env python3
"""Paper §4 experiment runner — DVD with full multi-signal verification.

Companion to run_baseline.py. Same all-Nemotron pipeline, but Layer
4.5 (PoC validator) and Layer 5.5 (multi-signal verify) are LEFT ON.
This produces the post-verify data that the paper compares against
the detection-only baseline.

Usage:
    python run_verify.py <run_id>

Output:
    <MSFV_ROOT>/data/log4j_with_verify/run_<run_id>/
      findings.json     final opus_results (with verify dicts attached)
      scan_state.json   full ScanState
      metadata.json     timing + ablation flags
      stdout.log        runner stdout
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
OUTPUT_ROOT = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "data/log4j_with_verify"))
TARGET = Path(os.path.join(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"), "log4j/log4j-core"))
PROD_ENV = Path(os.environ.get("MSFV_ENV_FILE", os.path.expanduser("~/.aisec.env")))

# Strict Nemotron-only on every layer — same single-model variable
# control as the no-verify baseline. Layer 4.5 / Layer 5.5 also use
# Nemotron, so the paper compares apples to apples.
BACKEND = "vllm:nemotron-120b"


# --------------------------------------------------------------------------- #
# Boot                                                                        #
# --------------------------------------------------------------------------- #

def setup_env() -> None:
    """Push backend chains. NOTE: AISEC_DISABLE_POC_VALIDATOR /
    AISEC_DISABLE_VERIFY are NOT set — full pipeline runs."""
    if PROD_ENV.exists():
        for line in PROD_ENV.read_text().splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k.strip(), v)

    # Strict Nemotron on every LM-touching layer, including verify.
    for env in [
        "AISEC_LOCAL_FILTER_MODEL",
        "AISEC_CLUSTER_MODEL",
        "AISEC_ANALYSE_CRITICAL_BACKEND",
        "AISEC_ANALYSE_HIGH_BACKEND",
        "AISEC_QUERY_BACKEND",
        "AISEC_VERIFY_BACKEND",          # L5.5 — central to the paper
        "AISEC_POC_VERIFY_BACKEND",
    ]:
        os.environ[env] = BACKEND

    # Tolerate per-call failures so a single Nemotron empty response
    # doesn't trash the whole run. Same setting as no-verify baseline.
    os.environ["AISEC_TOLERANT_LAYER_ERRORS"] = "1"

    # IMPORTANT: do NOT set AISEC_DISABLE_POC_VALIDATOR / DISABLE_VERIFY.
    # The whole point of this runner is to exercise the verify path.
    os.environ.pop("AISEC_DISABLE_POC_VALIDATOR", None)
    os.environ.pop("AISEC_DISABLE_VERIFY", None)

    os.environ["AISEC_PARALLEL_OPUS"] = "3"
    os.environ.setdefault(
        "AISEC_WORKSPACE", os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace")
    )

    sys.path.insert(0, str(FROZEN / "src" / "main"))
    sys.path.insert(0, str(FROZEN / "src"))


def clear_caches() -> None:
    """Wipe the result cache so each run is hermetic. Does not touch
    sibling-run state files (per-run state_id avoids collision)."""
    workspace = Path(os.environ["AISEC_WORKSPACE"])
    cache = workspace / "cache" / "findings"
    for entry in cache.glob("*.json") if cache.exists() else []:
        entry.unlink(missing_ok=True)
    for sub in ("lib", "out", "cache", "test/fuzz"):
        path = TARGET / sub
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Run                                                                         #
# --------------------------------------------------------------------------- #

def run_once(run_id: str) -> dict:
    out_dir = OUTPUT_ROOT / f"run_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    clear_caches()

    from core.analysis.pipeline import CheckpointedPipeline
    from core.analysis.scan_state import ScanState
    from cevanex.adapters.language_router import classify_repo
    from cevanex.adapters.query_packs import select_query_pack

    state_id = f"paper_verify_run_{run_id}_{int(time.time())}"
    state = ScanState.load(state_id)
    state.mode = "whitebox"

    # Cross-language dispatch (mirrors production cevanex.api.scan_runners).
    # Without this, Layer 5 falls back to the pipeline's default Solidity-tuned
    # GLOBAL_PATTERN_QUERIES — fine on DVD, useless on Java / TS / Python.
    triage = classify_repo(str(TARGET))
    pack_label, custom_queries = select_query_pack(triage)
    print(f"  router:    solidity={len(triage.solidity)} general={len(triage.general)} "
          f"config={len(triage.config)} ambiguous={len(triage.ambiguous)} "
          f"skipped={len(triage.skipped)}")
    print(f"  L5 pack:   {pack_label}  ({len(custom_queries)} queries)")

    pipeline = CheckpointedPipeline(
        state, parallel_workers=3, custom_queries=custom_queries,
    )

    print(f"=== Log4j verify run_{run_id} @ {time.strftime('%Y-%m-%d %H:%M:%S')} ===")
    print(f"  target:    {TARGET}")
    print(f"  state:     {state_id}")
    print(f"  output:    {out_dir}")
    print(f"  backends:  ALL = {BACKEND}")
    print(f"  layers:    L1..L5.5 ALL ENABLED (verify + PoC validator on)")
    print()

    start = time.time()
    error_msg: str | None = None
    results: list[dict] = []
    try:
        results = list(pipeline.run_whitebox(str(TARGET)) or [])
    except Exception as exc:  # noqa: BLE001
        error_msg = f"{type(exc).__name__}: {exc}"
        print(f"\n!!! Pipeline raised: {error_msg}")
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

    (out_dir / "findings.json").write_text(
        json.dumps(results, default=str, indent=2)
    )

    workspace = Path(os.environ["AISEC_WORKSPACE"])
    state_file = workspace / "state" / f"{state_id}.json"
    if state_file.exists():
        shutil.copy(state_file, out_dir / "scan_state.json")

    # Verify-specific metrics
    l4 = [r for r in results if r.get("layer") == 4]
    l5 = [r for r in results if r.get("layer") == 5]
    l5_with_verify = [r for r in l5 if "verification" in r]
    pocs_emitted = sum(1 for r in l4 if r.get("poc", {}).get("code"))
    pocs_validated = sum(
        1 for r in l4
        if (r.get("poc") or {}).get("validation") is not None
    )
    pocs_triggered = sum(
        1 for r in l4
        if ((r.get("poc") or {}).get("validation") or {})
                                 .get("poc_triggers_bug") is True
    )
    severity_overrides = sum(
        1 for r in l5 if r.get("severity_override")
    )

    metadata = {
        "run_id": run_id,
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                    time.localtime(start)),
        "elapsed_seconds": round(elapsed, 2),
        "elapsed_human": f"{int(elapsed // 60)}m {int(elapsed % 60)}s",
        "target":       str(TARGET),
        "target_label": "log4j-2.14.1",
        "state_id":     state_id,
        "findings_count": len(results),
        "error":          error_msg,
        "backends_all_layers": BACKEND,
        "ablation": {
            "AISEC_DISABLE_POC_VALIDATOR": False,
            "AISEC_DISABLE_VERIFY":        False,
            "AISEC_TOLERANT_LAYER_ERRORS": True,
        },
        "parallel_workers": 3,
        "frozen_commit":    "47810b7",
        # verify-specific
        "L4_results":              len(l4),
        "L5_results":              len(l5),
        "L5_with_verification":    len(l5_with_verify),
        "L4_pocs_emitted":         pocs_emitted,
        "L4_pocs_validated_by_L45": pocs_validated,
        "L4_pocs_triggered_bug":   pocs_triggered,
        "L5_severity_overrides":   severity_overrides,
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    print()
    print(f"=== run_{run_id} done in {metadata['elapsed_human']} ===")
    print(f"  findings:               {len(results)}")
    print(f"  by layer:               L4={len(l4)}  L5={len(l5)}")
    print(f"  L5 with verification:   {len(l5_with_verify)}/{len(l5)}")
    print(f"  PoCs emitted by L4:     {pocs_emitted}")
    print(f"  PoCs forge-validated:   {pocs_validated}")
    print(f"  PoCs triggered bug:     {pocs_triggered}")
    print(f"  severity overrides:     {severity_overrides}")
    if error_msg:
        print(f"  ERROR: {error_msg}")
    print()

    return metadata


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    setup_env()
    meta = run_once(sys.argv[1])
    sys.exit(0 if meta.get("error") is None else 1)
