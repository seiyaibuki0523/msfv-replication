#!/usr/bin/env python3
"""Stability / run-to-run variance driver for the MSFV paper.

Re-runs the FULL matrix (3 detect arms × all benchmarks) TWICE so we can report
the spread (mean ± range) of ship counts / recall across identical configs —
the paper's "stability" claim. (2 repeats per cell, per Casper 2026-07-20.)

Design decisions (per Casper, 2026-07-20):
  * Full matrix: qwen / gemma / nemotron detect arms × dvd, pygoat, nodegoat,
    smartbugs (full 143). 2 runs each = 24 cells (12 per driver ×? no: 8/arm).
  * VERIFY is always Nemotron (the studied stage) — held fixed across arms so
    the only thing that moves between arms is the DETECTION model.
  * Order per arm = run → bm, so RUN 1 completes for the arm first, then r2
    layers on the variance.
  * Benchmark order is STAGGERED per arm (rotated by arm index) so no two arms
    sit on the same benchmark at once — load spreads across the three hosts.
  * Verify tail is SERIALISED across arms via an advisory file lock (all verify
    is Nemotron; they queue instead of overloading it).
  * Each cell writes to data/ablation/st_<arm>_<bm>_r<N>/ via AISEC_ABL_LABEL.
  * Resumable: a cell with all 4 config metadata.json present (and no
    DEGENERATE.flag) is SKIPPED — completed runs survive a restart, so we never
    re-run what already finished. Only wipe a cell to force it to re-run.

Every detect/verify chain carries a cloud-Nemotron tail so a flapping
self-hosted vLLM host degrades to the same model on a live host instead of
producing degenerate 0-finding data.

Launch (background):
  nohup python3 \
      <MSFV_ROOT>/experiments/run_stability.py \
      > /tmp/aisec_stability/driver.log 2>&1 &
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

EXP = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "experiments"))
VENV_PY = os.environ.get("MSFV_PYTHON", "python3")
DATA = Path(os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "data", "ablation"))
STATE = Path("<AISEC_WORKSPACE>/state")
TARGETS_ROOT = Path(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"))
# Per-arm working copies of each benchmark repo. Concurrent arms must NOT share
# a foundry project — forge writes out/ cache/ foundry.lock in-place, and three
# arms hammering the same dir deadlocks (observed 2026-07-20). Each arm gets its
# own copy so forge is isolated. State stays in the shared workspace (unique
# target_id per cell → no collision), so the live dashboard still sees runs.
STAB_REPOS = Path("<AISEC_WORKSPACE>/stab_repos")
_COPY_EXCLUDES = ("out", "cache", ".git", "node_modules", "broadcast", "artifacts")
# Cross-process advisory lock so the verify tail (always Nemotron) runs one arm
# at a time. Detection stays parallel (distinct hosts); only verify serialises.
VERIFY_LOCK = Path("<AISEC_WORKSPACE>/verify.lock")
LOGDIR = Path("/tmp/aisec_stability"); LOGDIR.mkdir(exist_ok=True)

# NEMOTRON ROUTING → NVIDIA CLOUD (2026-07-22): the self-hosted nemotron vLLM
# cluster (VLLM_URL) is being repurposed to a different model after 14:00, so
# every nemotron call — the nemotron detection arm AND the always-nemotron
# verify stage — must go to the NVIDIA cloud NIM. self-hosted nemotron
# (vllm:nemotron-120b) is removed from every chain; qwen/gemma keep their own
# self-hosted detection host with a cloud-nemotron fallback tail.
NEMO = "openrouter:nemotron-120b"   # OpenRouter (same Nemotron-3-Super-120B; high-concurrency, no 429)

# arm -> AISEC_FAST_CHAIN (detection: L3/L4/L5/PoC-gen). Verify is separate.
# All-OpenRouter: same model weights as the self-hosted vLLM hosts, moved to
# OpenRouter so the experiment can run at high concurrency (no 429).
ARMS = {
    "qwen":     f"openrouter:qwen3-coder,{NEMO}",
    "gemma":    f"openrouter:gemma-4-31b,{NEMO}",
    "nemotron": f"{NEMO}",
}
# Studied stage — held fixed for every arm/run so variance is comparable.
VERIFY = f"{NEMO}"

BENCHMARKS = ["dvd", "pygoat", "nodegoat", "smartbugs"]
RUNS = (1, 2)  # 2 repeats per model×benchmark (stability spread). Override: AISEC_STAB_RUNS
CONFIGS = ("baseline", "full", "nosource", "nopoc")
CONCURRENCY = os.getenv("AISEC_LAB_CONCURRENCY", "16")
SHIP = os.getenv("AISEC_SHIP_MIN_SEVERITY", "medium")

# ── Run mode (AISEC_STAB_MODE) — forwarded to run_ablation_fast AISEC_ABL_MODE ─
#   full      detect + verify per cell (default). Cell done = all 4 configs.
#   baseline  detection only: bank baseline + baseline/scan_state.json, defer
#             verify. Fast + parallel across hosts (no Nemotron bottleneck).
#             Cell done = baseline/metadata.json exists.
#   verify    verify-only: resume each cell from its saved baseline checkpoint
#             and run the 3 verify configs (serialized on Nemotron). Skips a
#             cell that has no baseline yet. Cell done = all 4 configs.
MODE = os.getenv("AISEC_STAB_MODE", "full").strip().lower()
if MODE not in ("full", "baseline", "verify"):
    MODE = "full"


def _expected_configs(label: str) -> tuple[str, ...]:
    """Configs a cell must have to count done. smartbugs runs full-only verify
    (its ~1000 findings make the 3-config ablation prohibitively slow), so it
    needs baseline+full; other benchmarks keep the complete 4-config ablation."""
    if "smartbugs" in label:
        return ("baseline", "full")
    return CONFIGS


def _cell_done(label: str) -> bool:
    d = DATA / label
    if (d / "baseline" / "DEGENERATE.flag").exists():
        return False  # degenerate detection — must be re-run
    if MODE == "baseline":
        return (d / "baseline" / "metadata.json").exists()
    # full & verify: done once the cell's expected configs are all written
    return all((d / c / "metadata.json").exists() for c in _expected_configs(label))


def _repo_copy(arm: str, bm: str) -> Path:
    """Isolated per-arm working copy of benchmark ``bm`` (forge writes in-place,
    so concurrent arms need separate dirs). Excludes regenerable build output;
    reused across r1/r2/r3 of the same arm (they run serially)."""
    src = TARGETS_ROOT / bm
    dst = STAB_REPOS / f"{arm}__{bm}"
    dst.mkdir(parents=True, exist_ok=True)
    ex: list[str] = []
    for e in _COPY_EXCLUDES:
        ex += ["--exclude", e]
    subprocess.run(["rsync", "-a", *ex, f"{src}/", f"{dst}/"], check=False)
    return dst


def _cell_running(label: str, fresh: float = 900.0) -> bool:
    """True if another process is actively working this cell — a scan-state
    file abl_<label>_*.json touched within ``fresh`` seconds. Lets concurrent
    arm-drivers (and an orphaned cell from a previous serial driver) coexist:
    we wait it out instead of double-launching the same label. Self-healing —
    if the owner dies/stalls > fresh, the file goes stale and we take over."""
    now = time.time()
    for p in STATE.glob(f"abl_{label}_*.json"):
        try:
            if now - p.stat().st_mtime <= fresh:
                return True
        except OSError:
            pass
    return False


def _run_cell(arm: str, bm: str, run: int) -> int:
    label = f"st_{arm}_{bm}_r{run}"
    if _cell_done(label):
        print(f"[skip] {label} already complete", flush=True)
        return 0
    if MODE == "verify" and not (DATA / label / "baseline" / "metadata.json").exists():
        print(f"[skip] {label} has no baseline checkpoint — run baseline first",
              flush=True)
        return 0
    # Another process (a concurrent driver, or an orphaned cell from the old
    # serial driver) owns this label right now — wait it out rather than
    # double-launch. If it completes we skip; if it stalls the state goes
    # stale and _cell_running() flips false, so we take over.
    while _cell_running(label):
        if _cell_done(label):
            print(f"[skip] {label} finished by another worker", flush=True)
            return 0
        print(f"[wait] {label} in flight elsewhere — polling", flush=True)
        time.sleep(30)
    if _cell_done(label):
        return 0
    repo = _repo_copy(arm, bm)  # isolated forge dir for this arm
    env = dict(os.environ)
    env["AISEC_ABL_LABEL"] = label            # output label (target is the copy)
    env["AISEC_FAST_CHAIN"] = ARMS[arm]
    env["AISEC_VERIFY_BACKEND_OVERRIDE"] = VERIFY
    env["AISEC_SHIP_MIN_SEVERITY"] = SHIP
    env["AISEC_LAB_CONCURRENCY"] = CONCURRENCY
    env["AISEC_LLM_TIMEOUT"] = "240"
    # CRITICAL for a variance study: the result cache key is sha256(layer+prompt)
    # — model-blind and run-blind. Left on, r2/r3 would replay r1's cache (fake
    # zero variance) and arms would read each other's cached findings (cross-
    # model contamination). Off → every run makes real LLM calls.
    env["AISEC_RESULT_CACHE"] = "0"
    env["AISEC_ABL_MODE"] = MODE          # full | baseline | verify
    if "smartbugs" in label:
        env["AISEC_ABL_VERIFY_CONFIGS"] = "full"   # smartbugs: full-only verify (cost)
    if MODE == "verify" and ("pygoat" in label or "nodegoat" in label):
        # non-Solidity cells baselined before the sandbox image existed lack
        # container PoC → generate it on the checkpoint before verify (idempotent)
        env["AISEC_ABL_POC_FOLD"] = "1"
    # Verify serialisation lock: only needed for a rate-limited shared host
    # (the old self-hosted Nemotron). On OpenRouter (no rate limit, conc 1024
    # fine) it just slows verify down → OFF by default. Re-enable with
    # AISEC_STAB_VERIFY_LOCK=1 if a backend ever needs serialised verify.
    if MODE != "baseline" and os.getenv("AISEC_STAB_VERIFY_LOCK", "0") == "1":
        env["AISEC_VERIFY_LOCK"] = str(VERIFY_LOCK)
    logp = LOGDIR / f"{label}.log"
    print(f"[run ] {label}  mode={MODE}  detect={ARMS[arm]}  repo={repo.name}  "
          f"@ {time.strftime('%H:%M:%S')}", flush=True)
    t0 = time.time()
    with open(logp, "w") as lf:
        rc = subprocess.run(
            [VENV_PY, str(EXP / "run_ablation_fast.py"), str(repo)],
            cwd=str(EXP), env=env, stdout=lf, stderr=subprocess.STDOUT).returncode
    dt = int(time.time() - t0)
    tag = "ok" if rc == 0 else f"rc={rc}"
    print(f"[done] {label}  {tag}  {dt//60}m{dt%60}s  (log {logp})", flush=True)
    return rc


def main() -> int:
    # Filters (env, so 3 arm-scoped drivers can run concurrently on their own
    # vLLM hosts):
    #   AISEC_STAB_ARMS=qwen        one arm per driver (default: all three)
    #   AISEC_STAB_RUNS=1,2,3       which repeats (default: all three)
    arms = [a for a in os.getenv("AISEC_STAB_ARMS", ",".join(ARMS)).split(",")
            if a in ARMS]
    runs = [int(x) for x in os.getenv("AISEC_STAB_RUNS", ",".join(map(str, RUNS))).split(",")
            if x.strip().isdigit()]
    # Legacy positional: run_stability.py <arm>  (convenience)
    if len(sys.argv) > 1 and sys.argv[1] in ARMS:
        arms = [sys.argv[1]]
    # Stagger benchmark order per arm so no two arms sit on the same benchmark
    # at once (rotate by the arm's index): qwen dvd→…, gemma pygoat→…, nemotron
    # nodegoat→…. Load spreads across the three vLLM hosts and the verify tails
    # naturally offset.
    def _bench_order(arm: str) -> list[str]:
        off = list(ARMS).index(arm) % len(BENCHMARKS)
        return BENCHMARKS[off:] + BENCHMARKS[:off]
    plan = [(r, a, b) for r in runs for a in arms for b in _bench_order(a)]
    total = len(plan)
    print(f"=== STABILITY MATRIX: {total} cells "
          f"(arms={arms} × {len(BENCHMARKS)} bm × runs={runs}) ===", flush=True)
    # Parallel fan-out (AISEC_STAB_PARALLEL=1): run all of this arm's cells at
    # once instead of one-at-a-time. Safe on OpenRouter (no rate limit) — each
    # _run_cell just blocks on its subprocess, so threads mostly wait on I/O.
    # Bounded by AISEC_STAB_MAXPAR (default = all) to cap docker-sandbox
    # containers (Docker VM RAM is the real ceiling).
    if os.getenv("AISEC_STAB_PARALLEL") == "1":
        import concurrent.futures as _cf
        mp = int(os.getenv("AISEC_STAB_MAXPAR", str(len(plan))) or len(plan))
        print(f"=== PARALLEL fan-out: {total} cells, max {mp} at once ===", flush=True)
        with _cf.ThreadPoolExecutor(max_workers=max(1, mp)) as ex:
            futs = {ex.submit(_run_cell, a, b, r): (r, a, b) for (r, a, b) in plan}
            for f in _cf.as_completed(futs):
                r, a, b = futs[f]
                try:
                    f.result()
                except Exception as e:  # noqa: BLE001
                    print(f"[ERR ] run{r} {a} {b}: {e}", flush=True)
    else:
        for i, (r, a, b) in enumerate(plan, 1):
            print(f"--- cell {i}/{total} : run{r} {a} {b} ---", flush=True)
            try:
                _run_cell(a, b, r)
            except Exception as e:  # noqa: BLE001 — one cell must not kill the driver
                print(f"[ERR ] run{r} {a} {b}: {e}", flush=True)
    # summary
    done = sum(1 for r in RUNS for a in ARMS for b in BENCHMARKS
               if _cell_done(f"st_{a}_{b}_r{r}"))
    print(f"=== stability driver finished: "
          f"{done}/{len(RUNS)*len(ARMS)*len(BENCHMARKS)} cells complete ===",
          flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
