#!/usr/bin/env python3
"""Signal-ablation runner for the MSFV paper (review #2).

Runs ONE (benchmark, config) cell. The orchestrating shell script runs the
four configs per benchmark sharing a warmed result cache so the detection
stage (L1-L5 + PoC generation) is identical across configs — only the
verify prompt changes. This controls the detection-stage non-determinism
that would otherwise confound the ablation.

Configs:
  baseline   detection only — AISEC_DISABLE_VERIFY=1 (ships every candidate)
  full       all 4 signals  — identity + source + concern + poc
  nosource   identity + concern + poc      (AISEC_VERIFY_SIGNALS)
  nopoc      identity + source + concern   (AISEC_VERIFY_SIGNALS)

identity + concern are always-on (structurally load-bearing); the paper
only removes source / poc one at a time.

Usage:
  python run_ablation.py <benchmark> <config>
    benchmark ∈ {dvd, pygoat, nodegoat, smartbugs}
    config    ∈ {baseline, full, nosource, nopoc}
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

FROZEN = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "frozen-code"))
PROD_ENV = Path(os.environ.get("MSFV_ENV_FILE", os.path.expanduser("~/.aisec.env")))
TARGETS_ROOT = Path(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"))
DATA = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "data", "ablation"))
BACKEND = "vllm:nemotron-120b"

TARGET_DIRS = {
    "dvd":       TARGETS_ROOT / "dvd",
    "pygoat":    TARGETS_ROOT / "pygoat",
    "nodegoat":  TARGETS_ROOT / "nodegoat",
    "smartbugs": TARGETS_ROOT / "smartbugs",
}

CONFIG_SIGNALS = {
    "baseline": None,                                  # verify disabled
    "full":     "identity,source,concern,poc",
    "nosource": "identity,concern,poc",
    "nopoc":    "identity,source,concern",
}


def setup_env(config: str) -> None:
    if PROD_ENV.exists():
        for line in PROD_ENV.read_text().splitlines():
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k.strip(), v)

    # L4/L5/verify stay on Nemotron (the security-analysis model — paper's
    # focus). L3 is a binary TP/FP gate that does NOT need deep reasoning;
    # the Nemotron reasoning model spends ~10-100s/call on it. Route L3 to
    # qwen3-coder (non-reasoning, ~0.5s/call, ~20× faster) with a Nemotron
    # fallback for robustness. L3 backend doesn't enter the verify-signal
    # ablation, so this only speeds up detection without affecting the
    # full/-source/-poc comparison.
    for env in ["AISEC_CLUSTER_MODEL",
                "AISEC_ANALYSE_CRITICAL_BACKEND", "AISEC_ANALYSE_HIGH_BACKEND",
                "AISEC_QUERY_BACKEND", "AISEC_VERIFY_BACKEND",
                "AISEC_POC_VERIFY_BACKEND"]:
        os.environ[env] = BACKEND
    os.environ["AISEC_LOCAL_FILTER_MODEL"] = BACKEND  # nemotron (qwen over-rejects: 3% pass → recall collapse)

    os.environ["AISEC_TOLERANT_LAYER_ERRORS"] = "1"

    # Server-safe concurrency. The self-hosted vLLM (Nemotron-3 reasoning,
    # ~500 reasoning tokens/call) thrashes the GPU when hit with many
    # parallel generations. AISEC_PARALLEL_VLLM defaults to 16 (!), which
    # overloaded L3 local_filter → 236-293s latencies + TTFT pileup. Probe
    # showed concurrency=2 holds TTFT at 0.17s. Throttle ALL stages to 2.
    _conc = os.getenv("AISEC_LAB_CONCURRENCY", "2")
    os.environ["AISEC_PARALLEL_VLLM"] = _conc   # L3 local_filter
    os.environ["AISEC_PARALLEL_LOCAL"] = _conc  # L3 ollama path (unused here)
    os.environ["AISEC_PARALLEL_OPUS"] = _conc   # L4 / L5 / L5.5
    os.environ.setdefault("AISEC_WORKSPACE", os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace"))

    # Config-specific knobs.
    os.environ.pop("AISEC_DISABLE_VERIFY", None)
    os.environ.pop("AISEC_DISABLE_POC_VALIDATOR", None)
    os.environ.pop("AISEC_VERIFY_SIGNALS", None)

    if config == "baseline":
        os.environ["AISEC_DISABLE_VERIFY"] = "1"
        os.environ["AISEC_DISABLE_POC_VALIDATOR"] = "1"
    else:
        sig = CONFIG_SIGNALS[config]
        os.environ["AISEC_VERIFY_SIGNALS"] = sig
        # PoC validator stays ON for all verify configs so poc.validation
        # is identical; AISEC_VERIFY_SIGNALS controls whether verify reads it.

    sys.path.insert(0, str(FROZEN / "src" / "main"))
    sys.path.insert(0, str(FROZEN / "src"))


def main(benchmark: str, config: str) -> int:
    target = TARGET_DIRS[benchmark]
    out_dir = DATA / benchmark / config
    out_dir.mkdir(parents=True, exist_ok=True)

    setup_env(config)

    from core.analysis.pipeline import CheckpointedPipeline
    from core.analysis.scan_state import ScanState
    from cevanex.adapters.language_router import classify_repo
    from cevanex.adapters.query_packs import select_query_pack

    # NOTE: cache is shared across configs (the orchestrator clears it ONCE
    # before 'baseline'). Detection L4/L5 hit cache → identical candidates.
    state_id = f"abl_{benchmark}_{config}_{int(time.time())}"
    state = ScanState.load(state_id)
    state.mode = "whitebox"

    triage = classify_repo(str(target))
    pack_label, custom_queries = select_query_pack(triage)

    # Scope the scan to the TARGET's own code, excluding vendored
    # dependencies under lib/ (Foundry) / node_modules/. Scanning deps is
    # both a methodological error (you audit the project, not OpenZeppelin)
    # and the reason L3 ballooned to 1040 findings (723 were lib/ noise) vs
    # the paper's 317. lib/ stays ON DISK so the PoC forge build still
    # resolves imports — we only drop it from the *scan* file list. This
    # matches the original paper-run scope (src/ only) → restores recall.
    from core.analysis.file_filter import filter_files
    all_files, _root = filter_files(str(target))
    file_scope = [
        f for f in all_files
        if "/lib/" not in f and "/node_modules/" not in f
        and not f.endswith(".t.sol")  # test harnesses aren't the target
    ]
    print(f"  scope: {len(file_scope)}/{len(all_files)} files "
          f"(dropped {len(all_files)-len(file_scope)} lib/test/dep)")

    _workers = int(os.getenv("AISEC_LAB_CONCURRENCY", "2"))
    pipeline = CheckpointedPipeline(
        state, parallel_workers=_workers, custom_queries=custom_queries,
        file_scope=file_scope,
    )

    print(f"=== ablation {benchmark}/{config} @ {time.strftime('%H:%M:%S')} ===")
    print(f"  target: {target}")
    print(f"  pack: {pack_label} ({len(custom_queries)} queries)")
    print(f"  AISEC_VERIFY_SIGNALS={os.environ.get('AISEC_VERIFY_SIGNALS','(unset)')}")
    print(f"  AISEC_DISABLE_VERIFY={os.environ.get('AISEC_DISABLE_VERIFY','0')}")
    print()

    start = time.time()
    error_msg = None
    results = []
    try:
        results = list(pipeline.run_whitebox(str(target)) or [])
    except Exception as exc:  # noqa: BLE001
        error_msg = f"{type(exc).__name__}: {exc}"
        print(f"!!! pipeline raised: {error_msg}")
        wf = Path(os.environ["AISEC_WORKSPACE"]) / "state" / f"{state_id}.json"
        if wf.exists():
            try:
                results = json.loads(wf.read_text()).get("opus_results", [])
                print(f"  salvaged {len(results)} partial results")
            except Exception:
                pass
    elapsed = time.time() - start

    (out_dir / "findings.json").write_text(json.dumps(results, default=str, indent=2))
    wf = Path(os.environ["AISEC_WORKSPACE"]) / "state" / f"{state_id}.json"
    if wf.exists():
        shutil.copy(wf, out_dir / "scan_state.json")

    # PoC stats (Solidity targets)
    l4 = [r for r in results if r.get("layer") == 4]
    poc_emit = sum(1 for r in l4 if (r.get("poc") or {}).get("code"))
    poc_compile = sum(1 for r in l4 if ((r.get("poc") or {}).get("validation") or {}).get("poc_compile") is True)
    poc_trig = sum(1 for r in l4 if ((r.get("poc") or {}).get("validation") or {}).get("poc_triggers_bug") is True)
    poc_repaired = sum(1 for r in l4 if (r.get("poc") or {}).get("repaired"))

    meta = {
        "benchmark": benchmark, "config": config, "state_id": state_id,
        "findings_count": len(results),
        "elapsed_human": f"{int(elapsed//60)}m {int(elapsed%60)}s",
        "verify_signals": os.environ.get("AISEC_VERIFY_SIGNALS"),
        "disable_verify": os.environ.get("AISEC_DISABLE_VERIFY", "0"),
        "poc_emit": poc_emit, "poc_compile": poc_compile,
        "poc_triggered": poc_trig, "poc_repaired": poc_repaired,
        "error": error_msg, "backend": BACKEND,
    }
    (out_dir / "metadata.json").write_text(json.dumps(meta, indent=2))
    print(f"\n=== {benchmark}/{config} done: {len(results)} findings, "
          f"PoC emit={poc_emit} compile={poc_compile} trig={poc_trig} repaired={poc_repaired}, "
          f"{meta['elapsed_human']} ===")
    return 0 if error_msg is None else 1


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
