#!/usr/bin/env python3
"""Efficient signal-ablation: detect ONCE, verify N times on the saved snapshot.

The slow approach re-ran the whole pipeline per config (cache-accelerated, but
still re-walked orchestration AND re-ran the expensive PoC forge validation
every time). This runner instead:

  1. DETECT once  — full pipeline L0-L5 + PoC validation, verify DISABLED.
     The resulting candidate set (opus_results with poc.validation + the
     global_map) IS the baseline (every candidate shipped, no verify) and is
     saved as a reusable checkpoint.

  2. VERIFY×N      — for each config {full, nosource, nopoc}, copy the
     checkpoint, reset its phase to ``verify_global``, set
     AISEC_VERIFY_SIGNALS, and resume run_whitebox. The pipeline runs ONLY
     the verify stage against the *identical* saved candidates. No detection
     re-run, no PoC re-validation. Guaranteed-identical candidate set across
     configs (not cache-dependent).

Usage:  python run_ablation_fast.py <benchmark>
Output: data/ablation/<bm>/{baseline,full,nosource,nopoc}/
"""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import sys
import time
from pathlib import Path

FROZEN = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "frozen-code"))
PROD_ENV = Path(os.environ.get("MSFV_ENV_FILE", os.path.expanduser("~/.aisec.env")))
TARGETS_ROOT = Path(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"))
DATA = Path(os.getenv("AISEC_ABL_DATA",
                      os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "data", "ablation")))
WS = Path(os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace"))
BACKEND = os.getenv("AISEC_VERIFY_BACKEND_OVERRIDE", "vllm:nemotron-120b")

# ── Run mode ───────────────────────────────────────────────────────────────
# AISEC_ABL_MODE selects which phases run. Lets detection and verify be run as
# separate passes (detection is fast + parallel across hosts; verify is the
# slow Nemotron-bound stage), instead of always coupling them per cell.
#
#   full     detect + verify (default; original behaviour)
#   baseline detect only → write baseline + persist baseline/scan_state.json,
#            then STOP. Verify deferred to a later `verify` pass.
#   verify   skip detection; resume from the persisted baseline/scan_state.json
#            and run the verify configs only. Requires a prior baseline run.
MODE = os.getenv("AISEC_ABL_MODE", "full").strip().lower()
if MODE not in ("full", "baseline", "verify"):
    MODE = "full"

TARGET_DIRS = {k: TARGETS_ROOT / v for k, v in {
    "dvd": "dvd", "pygoat": "pygoat", "nodegoat": "nodegoat",
    "smartbugs": "smartbugs",
    # Stratified sample (~5 contracts/category, all 10 categories). The full
    # 143-contract set explodes to 768+ L4 candidates and the per-finding L4
    # analysis can't finish; the sample stays tractable (~200 L4) while keeping
    # line-level recall meaningful across every vuln category.
    "smartbugs_sampled": "smartbugs_sampled"}.items()}

VERIFY_CONFIGS = {
    # paper §IV full 4-signal ablation. name -> AISEC_VERIFY_SIGNALS allow-list.
    "full":       "identity,source,concern,poc",
    "noidentity": "source,concern,poc",
    "noconcern":  "identity,source,poc",
    "nosource":   "identity,concern,poc",
    "nopoc":      "identity,source,concern",
    "keep_IS":    "identity,source",
    "keep_IC":    "identity,concern",
    "keep_IP":    "identity,poc",
    "keep_SC":    "source,concern",
    "keep_SP":    "source,poc",
    "keep_CP":    "concern,poc",
    "only_I":     "identity",
    "only_S":     "source",
    "only_C":     "concern",
    "only_P":     "poc",
    "noconcern_full": "identity,source,poc",  # Tier 5 (same signals as noconcern)
    "full_rep2":  "identity,source,concern,poc",  # Tier 4 replicate
    "full_rep3":  "identity,source,concern,poc",  # Tier 4 replicate
    # Round-2 A batch: same info as full, single unstructured prompt (naive).
    # Dispatched via AISEC_VERIFY_MODE=naive in the verify loop below.
    "naive_verify": "identity,source,concern,poc",
}
# Optional restriction of which verify configs to run (AISEC_ABL_VERIFY_CONFIGS,
# comma list). Used to run smartbugs at full-only (its ~1000 findings make the
# 3-config signal-ablation prohibitively slow; the ablation is kept complete on
# dvd/pygoat/nodegoat). Empty = all three.
_only = os.getenv("AISEC_ABL_VERIFY_CONFIGS", "").strip()
if _only:
    _keys = [k.strip() for k in _only.split(",") if k.strip() in VERIFY_CONFIGS]
    if _keys:
        VERIFY_CONFIGS = {k: VERIFY_CONFIGS[k] for k in _keys}


def base_env() -> None:
    if PROD_ENV.exists():
        for line in PROD_ENV.read_text().splitlines():
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    # Iteration-speed config (option A): detection layers (L3 filter, L4
    # analysis, L5 global queries) run on the FAST non-reasoning qwen3-coder
    # so a full detection takes ~15 min instead of ~140 min — making the
    # recall-tuning loop actually iterable. The VERIFY layer (L5.5), which is
    # the paper's studied stage, stays on Nemotron for quality. qwen no longer
    # over-rejects at L3 because the prompt is now the permissive
    # recall-preserving pre-filter (commit 6e55313), not the old aggressive one.
    # Each detection backend carries a Nemotron fallback for robustness.
    # qwen3-coder host was DOWN on 2026-06-11 (URLError); gemma-4-31B is up and
    # fast enough for L3/L4 detection. Primary=gemma, fallback=nemotron — both
    # confirmed live. (Set AISEC_FAST_CHAIN to override when qwen is back.)
    FAST = os.getenv("AISEC_FAST_CHAIN", "vllm:gemma-4-31b,vllm:nemotron-120b")
    os.environ["AISEC_LOCAL_FILTER_MODEL"]      = FAST   # L3
    os.environ["AISEC_ANALYSE_CRITICAL_BACKEND"] = FAST  # L4 critical
    os.environ["AISEC_ANALYSE_HIGH_BACKEND"]     = FAST  # L4 high/medium
    os.environ["AISEC_QUERY_BACKEND"]            = FAST  # L5 global queries
    os.environ["AISEC_CLUSTER_MODEL"]            = FAST
    os.environ["AISEC_VERIFY_BACKEND"]           = BACKEND  # L5.5 — Nemotron (studied stage)
    os.environ["AISEC_POC_VERIFY_BACKEND"]       = BACKEND
    # Layer 4.5 multi-language PoC recipe generation (container sandbox).
    # Writing a runnable PoC is a coding task → qwen3-coder primary, with a
    # reasoning/cloud tail for the cases qwen botches. Solidity PoCs still come
    # from L4 (poc_solidity) + host forge; this backend is only for the
    # non-Solidity self-contained PoCs run in the docker sandbox.
    #
    # NOTE: PoC-gen is NOT a studied variable (verify consumes the execution
    # VERDICT, not the generated code), so it need not match the arm's detect
    # chain. AISEC_POC_GEN_OVERRIDE lets us pin it to a FAST backend — critical
    # for the verify PoC-fold, where the slow gemma host (9 tok/s) would take
    # 1-2 min per PoC script × N findings sequentially.
    os.environ["AISEC_POC_GEN_BACKEND"] = os.getenv("AISEC_POC_GEN_OVERRIDE", FAST)
    os.environ["AISEC_TOLERANT_LAYER_ERRORS"] = "1"
    conc = os.getenv("AISEC_LAB_CONCURRENCY", "16")
    os.environ["AISEC_PARALLEL_VLLM"] = conc
    os.environ["AISEC_PARALLEL_OPUS"] = conc
    os.environ.setdefault("AISEC_WORKSPACE", str(WS))
    os.environ.setdefault("AISEC_LLM_TIMEOUT", "240")
    # CRITICAL: when this script is invoked via `venv/bin/python run_...py`
    # (no `source activate`), the venv's bin/ is NOT on PATH, so the
    # `semgrep` subprocess spawned by semgrep_runner fails with
    # FileNotFoundError → run_semgrep returns [] → 0 findings → degenerate
    # detection. Prepend the venv bin so semgrep (and forge, etc.) resolve.
    venv_bin = os.environ.get("MSFV_VENV_BIN", "")
    if venv_bin not in os.environ.get("PATH", ""):
        os.environ["PATH"] = venv_bin + ":" + os.environ.get("PATH", "")
    sys.path.insert(0, str(FROZEN / "src" / "main"))
    sys.path.insert(0, str(FROZEN / "src"))


def _scope(target: Path):
    from core.analysis.file_filter import filter_files
    allf, _ = filter_files(str(target))
    return [f for f in allf if "/lib/" not in f and "/node_modules/" not in f
            and not f.endswith(".t.sol")]


def _l4_self_rejected(r) -> bool:
    """L4 'Confirmed: no' IS a false positive the analyser caught — it must
    NOT count as shipped. (Previously these shipped, inflating the ship count
    by the whole confirmed:no mass — e.g. DVD 130 FPs, making 233 'shipped'
    when only 103 were real candidates.)"""
    if r.get("layer") != 4:
        return False
    a = (r.get("analysis") or "").strip().split("\n", 1)[0].lower()
    return a.startswith("confirmed: no") and "unclear" not in a


def _ship(opus):
    n = 0
    for r in opus:
        if _l4_self_rejected(r):
            continue  # confirmed:no = FP, not shipped
        sov = (r.get("severity_override") or "").lower()
        v = r.get("verification")
        drop = False
        if isinstance(v, list) and v:
            vv = [e.get("verdict") for e in v if isinstance(e, dict)]
            if vv and all(d == "false_positive" for d in vv):
                drop = True
            elif vv and all(d in ("false_positive", "downgraded") for d in vv) \
                    and not any(d == "confirmed" for d in vv):
                drop = True
        if not (drop or sov == "info"):
            n += 1
    return n


def _write_out(bm, cfg, opus, elapsed, signals, state_src=None):
    out = DATA / bm / cfg
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(opus, default=str, indent=2))
    if state_src and Path(state_src).exists():
        shutil.copy(state_src, out / "scan_state.json")
    l4 = [r for r in opus if r.get("layer") == 4]
    meta = {
        "benchmark": bm, "config": cfg, "findings_count": len(opus),
        "shipped": _ship(opus), "verify_signals": signals,
        "elapsed_human": f"{int(elapsed//60)}m {int(elapsed%60)}s",
        "poc_emit": sum(1 for r in l4 if (r.get("poc") or {}).get("code")),
        "poc_compile": sum(1 for r in l4 if ((r.get("poc") or {}).get("validation") or {}).get("poc_compile") is True),
        "poc_triggered": sum(1 for r in l4 if ((r.get("poc") or {}).get("validation") or {}).get("poc_triggers_bug") is True),
        "poc_repaired": sum(1 for r in l4 if (r.get("poc") or {}).get("repaired")),
    }
    (out / "metadata.json").write_text(json.dumps(meta, indent=2))
    print(f"  [{bm}/{cfg}] findings={len(opus)} ship={meta['shipped']} "
          f"PoC {meta['poc_compile']}/{meta['poc_emit']}✓ {meta['poc_triggered']}⚡ "
          f"{meta['elapsed_human']}")


def _fold_container_poc(checkpoint: dict, root: str) -> list:
    """verify-mode PoC fold (AISEC_ABL_POC_FOLD=1): generate container PoC on an
    existing baseline checkpoint's L4 findings that lack it, so the subsequent
    verify consumes the PoC signal. For cells baselined before the docker
    sandbox image existed. Does NOT touch L4/L5 findings — only fills in
    poc.validation. Idempotent: skips if container PoC already present. Solidity
    findings are unaffected (forge, pre-generated at L4). Mutates + returns
    opus_results."""
    opus = checkpoint.get("opus_results", [])
    gmap = checkpoint.get("global_map") or {}
    from core.analysis.poc_sandbox import PocSandbox, SandboxConfig
    sandbox = PocSandbox(SandboxConfig())
    if not sandbox.is_available():
        print("  [poc-fold] sandbox unavailable — skip (verify uses source-only)")
        return opus
    if any((r.get("poc") or {}).get("method") not in (None, "forge")
           for r in opus if r.get("layer") == 4):
        print("  [poc-fold] container PoC already present — skip")
        return opus
    from core.analysis.poc_validator import PocValidator, PocConfig
    from core.analysis.poc_generator import PocGenerator
    from core.analysis.context_bundle import _lookup_function_body
    validator = PocValidator(PocConfig())
    generator = PocGenerator()

    def _src(file_rel, line):
        return _lookup_function_body(gmap, file_rel, line)

    n = sum(1 for r in opus if r.get("layer") == 4)
    print(f"  [poc-fold] container PoC on {n} L4 findings @ {time.strftime('%H:%M:%S')}")
    return validator.validate_all(opus, root, sandbox=sandbox,
                                  generator=generator, source_lookup=_src)


def main(bm: str) -> int:
    base_env()
    # Accept either a registered benchmark name OR an arbitrary directory path
    # (local repo / freshly-cloned github checkout, used by the GUI). For a
    # path, the output label is the sanitised basename.
    import re as _re
    if bm in TARGET_DIRS:
        target = TARGET_DIRS[bm]
    elif os.path.isdir(bm):
        target = Path(bm)
        bm = _re.sub(r"[^\w.-]", "_", target.name) or "target"
    else:
        print(f"unknown target: {bm} (not a benchmark name or an existing dir)")
        return 2
    # Output-label override (stability driver): resolve the target above from
    # the real benchmark/dir, but write results under a distinct label such as
    # ``st_<arm>_<bm>_r<N>`` so 3 repeats × 3 arms never clobber each other and
    # each shows as its own dashboard row.
    label = os.getenv("AISEC_ABL_LABEL", "").strip()
    if label:
        bm = _re.sub(r"[^\w.-]", "_", label) or bm
    from core.analysis.pipeline import CheckpointedPipeline
    from core.analysis.scan_state import ScanState
    from cevanex.adapters.language_router import classify_repo
    from cevanex.adapters.query_packs import select_query_pack

    _, custom_queries = select_query_pack(classify_repo(str(target)))
    file_scope = _scope(target)
    workers = int(os.getenv("AISEC_LAB_CONCURRENCY", "16"))
    state_dir = WS / "state"

    # ── 1. Obtain the detection checkpoint ─────────────────────────────
    if MODE == "verify":
        # VERIFY-ONLY: skip detection, resume from the baseline checkpoint a
        # prior baseline/full run persisted at baseline/scan_state.json.
        saved = DATA / bm / "baseline" / "scan_state.json"
        if not saved.exists():
            print(f"!!! verify mode but no baseline checkpoint at {saved} — "
                  f"run baseline first. Aborting.")
            return 1
        checkpoint = json.loads(saved.read_text())
        n_l4 = sum(1 for r in checkpoint.get("opus_results", []) if r.get("layer") == 4)
        print(f"=== VERIFY-ONLY {bm}: loaded baseline checkpoint ({n_l4} L4) "
              f"@ {time.strftime('%H:%M:%S')} ===")
        # Fold L4.5 container PoC into verify for cells baselined before the
        # docker sandbox existed (AISEC_ABL_POC_FOLD=1) — adds poc.validation to
        # the loaded checkpoint's findings so verify consumes it. L4/L5 untouched.
        if os.getenv("AISEC_ABL_POC_FOLD") == "1":
            checkpoint["opus_results"] = _fold_container_poc(checkpoint, str(target))
    else:
        # DETECT once (verify disabled, PoC validator ON).
        os.environ["AISEC_DISABLE_VERIFY"] = "1"
        os.environ.pop("AISEC_DISABLE_POC_VALIDATOR", None)
        os.environ.pop("AISEC_VERIFY_SIGNALS", None)
        det_id = f"abl_{bm}_detect_{int(time.time())}"
        state = ScanState.load(det_id)
        state.mode = "whitebox"
        pipe = CheckpointedPipeline(state, parallel_workers=workers,
                                    custom_queries=custom_queries, file_scope=file_scope)
        print(f"=== DETECT {bm} (scope {len(file_scope)} files) @ {time.strftime('%H:%M:%S')} ===")
        t0 = time.time()
        try:
            det_results = list(pipe.run_whitebox(str(target)) or [])
        except Exception as e:  # noqa: BLE001
            print(f"!!! detect raised: {e}")
            f = state_dir / f"{det_id}.json"
            det_results = json.loads(f.read_text()).get("opus_results", []) if f.exists() else []
        det_elapsed = time.time() - t0
        det_file = state_dir / f"{det_id}.json"
        # baseline = the detected candidate set (no verify); also persists the
        # full scan_state as baseline/scan_state.json for a later verify pass.
        _write_out(bm, "baseline", det_results, det_elapsed, None, det_file)
        if not det_file.exists():
            print("no detection checkpoint — abort")
            return 1
        checkpoint = json.loads(det_file.read_text())

    # Degeneracy guard (both fresh detection and a loaded checkpoint): a network
    # blip can make Semgrep's auto-registry silently return 0 findings, giving
    # an empty L4 candidate set. Proceeding would produce meaningless data that
    # looks like success. Detect it and bail loudly so the run is re-done.
    n_l4 = sum(1 for r in checkpoint.get("opus_results", []) if r.get("layer") == 4)
    if n_l4 == 0:
        print(f"!!! DEGENERATE DETECTION: 0 L4 findings — NOT running verify.")
        (DATA / bm / "baseline" / "DEGENERATE.flag").write_text(
            "detection produced 0 L4 findings — semgrep/network failure\n")
        return 2

    # BASELINE-ONLY: detection done + checkpoint persisted. Stop here; verify is
    # deferred to a later `verify` pass. Banks detection fast (parallel across
    # hosts, no Nemotron verify bottleneck) before the serialized verify stage.
    if MODE == "baseline":
        print(f"=== {bm} baseline-only: detection done, verify deferred ===")
        return 0

    # ── 2. VERIFY×N on copies of the checkpoint ────────────────────────
    # Verify (L5.5) always runs on the shared Nemotron host. With several arm
    # drivers running concurrently, serialise the verify batch across processes
    # via an advisory file lock (AISEC_VERIFY_LOCK) so arms take turns rather
    # than overloading Nemotron. Detection (above) stays fully parallel; only
    # this ~5-min verify tail is mutually exclusive. No-op when the env is unset
    # (standalone runs). Per-config errors are caught inside the loop, so it
    # never raises past the release below.
    _vlock = None
    _vlock_path = os.getenv("AISEC_VERIFY_LOCK")
    if _vlock_path:
        _vlock = open(_vlock_path, "w")
        print(f"  [verify] waiting for verify lock @ {time.strftime('%H:%M:%S')}")
        fcntl.flock(_vlock, fcntl.LOCK_EX)
        print(f"  [verify] lock acquired @ {time.strftime('%H:%M:%S')}")
    for cfg, signals in VERIFY_CONFIGS.items():
        vid = f"abl_{bm}_{cfg}_{int(time.time())}"
        c = json.loads(json.dumps(checkpoint))  # deep copy
        c["target_id"] = vid
        c["current_phase"] = "verify_global"
        for r in c.get("opus_results", []):
            r.pop("verification", None)
            r.pop("severity_override", None)
        (state_dir / f"{vid}.json").write_text(json.dumps(c, ensure_ascii=False))

        os.environ.pop("AISEC_DISABLE_VERIFY", None)
        os.environ["AISEC_VERIFY_SIGNALS"] = signals
        # naive_verify (round-2): single unstructured prompt, all signals present.
        if cfg == "naive_verify":
            os.environ["AISEC_VERIFY_MODE"] = "naive"
        else:
            os.environ.pop("AISEC_VERIFY_MODE", None)
        st = ScanState.load(vid)
        vp = CheckpointedPipeline(st, parallel_workers=workers,
                                  custom_queries=custom_queries, file_scope=file_scope)
        print(f"=== VERIFY {bm}/{cfg} [{signals}] @ {time.strftime('%H:%M:%S')} ===")
        t0 = time.time()
        try:
            vres = list(vp.run_whitebox(str(target)) or [])
        except Exception as e:  # noqa: BLE001
            print(f"!!! verify {cfg} raised: {e}")
            f = state_dir / f"{vid}.json"
            vres = json.loads(f.read_text()).get("opus_results", []) if f.exists() else []
        _write_out(bm, cfg, vres, time.time() - t0, signals, state_dir / f"{vid}.json")

    if _vlock is not None:
        fcntl.flock(_vlock, fcntl.LOCK_UN)
        _vlock.close()
        print(f"  [verify] lock released @ {time.strftime('%H:%M:%S')}")

    print(f"\n=== {bm} ablation complete ===")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
