#!/usr/bin/env python3
"""MSFV v2 batch runner — executes jobs/v2/jobs.csv per jobs/v2/spec.json.

Design (see jobs/v2/jobs.md):
  * detection runs ONCE per run_dir (baseline); every verify config on that
    run_dir shares the same candidate pool.
  * verification configs for a run_dir are batched into ONE run_ablation_fast
    call (AISEC_ABL_VERIFY_CONFIGS=<list>) so the baseline is loaded once.
  * a verify job's candidate pool is its `source_pool` column (Tier 3 reuses a
    frozen qwen pool with a different verifier model); pool != run_dir → the
    pool's baseline is copied into the run_dir before verify.
  * scheduling: SmartBugs detection is submitted first (longest pole); other
    benchmarks run in parallel; a run_dir's verify is submitted as soon as its
    pool detection finishes (dependency-driven), so dvd/pygoat/nodegoat finish
    while SmartBugs detection is still going.
  * all LLM traffic is OpenRouter (high concurrency, no 429).

Resumable: a unit whose output metadata already exists is skipped. Progress is
appended to progress.csv; failures to failures.log. A detection/verify unit
exceeding --max-run-min (default 750, = 2x SmartBugs median) is aborted.

Usage:
  python run_jobs_v2.py --dry-run                 # print the plan, run nothing
  python run_jobs_v2.py [--parallel N] [--max-run-min M] [--only-stage detection|verification]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, Future
from pathlib import Path

ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
JOBS = ROOT / "jobs" / "v2"
DATA = ROOT / "data" / "ablation"
SCAN = Path(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"))
WORKSPACE = Path(os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace"))
REPO_COPIES = WORKSPACE / "job_repos"          # per-run isolated repo copies (dvd)
PY = os.environ.get("MSFV_PYTHON", "python3")
ABLATION = str(ROOT / "experiments" / "run_ablation_fast.py")
NEMO = "openrouter:nemotron-120b"

# detection_model -> AISEC_FAST_CHAIN (detection L3/L4/L5/PoC-gen)
DET_CHAIN = {
    "gemma-4-31B": f"openrouter:gemma-4-31b,{NEMO}",
    "qwen3-coder": f"openrouter:qwen3-coder,{NEMO}",
    "Nemotron-3-Super-120B-A12B": NEMO,
}
# verification_model -> AISEC_VERIFY_BACKEND_OVERRIDE
VERIFY_BACKEND = {
    "Nemotron-3-Super-120B-A12B": NEMO,
    "gemma-4-31B": "openrouter:gemma-4-31b",
    "qwen3-coder": "openrouter:qwen3-coder",
    # EXTERNAL-FAMILY intentionally absent — those jobs are optional=yes (skip).
}
# dvd builds forge artifacts into the repo → each run needs an isolated copy.
NEEDS_REPO_COPY = {"dvd"}

_lock = threading.Lock()
_progress_path = JOBS / "progress.csv"
_failures_path = JOBS / "failures.log"


def log(msg: str) -> None:
    with _lock:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def record_progress(run_dir: str, config: str, status: str, start: float, end: float) -> None:
    with _lock:
        new = not _progress_path.exists()
        with open(_progress_path, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["run_dir", "config", "status", "start", "end", "elapsed_min"])
            em = round((end - start) / 60, 1) if end and start else ""
            w.writerow([run_dir, config, status,
                        time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(start)) if start else "",
                        time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(end)) if end else "",
                        em])


def record_failure(run_dir: str, config: str, err: str) -> None:
    with _lock:
        with open(_failures_path, "a") as f:
            f.write(f"\n===== {run_dir}/{config} @ {time.strftime('%Y-%m-%dT%H:%M:%S')} =====\n{err}\n")


def seed_of(run_dir: str) -> str:
    # run_dir = st_(model)_(bench)_s(N)
    rep = run_dir.rsplit("_", 1)[-1]
    return rep[1:] if rep.startswith("s") else "1"


def repo_for(bench: str, run_dir: str) -> str:
    base = SCAN / bench
    if bench not in NEEDS_REPO_COPY:
        return str(base)
    dst = REPO_COPIES / run_dir
    if not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        # rsync a clean copy (exclude regenerable forge artifacts)
        subprocess.run(["rsync", "-a", "--delete",
                        "--exclude", "out", "--exclude", "cache", "--exclude", ".git",
                        f"{base}/", f"{dst}/"], check=True)
    return str(dst)


def write_manifest(run_dir: str, det_model: str, seed: str) -> None:
    out = DATA / run_dir
    out.mkdir(parents=True, exist_ok=True)
    tmpl = (ROOT / "frozen-code" / "src" / "main" / "core" / "analysis" / "pipeline.py")
    import hashlib
    thash = hashlib.sha256(tmpl.read_bytes()).hexdigest()[:16] if tmpl.exists() else "n/a"
    try:
        forge_v = subprocess.run([f"{PY.rsplit('/',1)[0]}/forge", "--version"],
                                 capture_output=True, text=True, timeout=10).stdout.strip().split("\n")[0]
    except Exception:
        forge_v = "n/a"
    manifest = {
        "run_dir": run_dir,
        "model_version_with_revision_or_quant": det_model,
        "temperature": float(os.getenv("AISEC_LLM_TEMPERATURE", "0.2")),
        "top_p": 0.7,
        "top_k": None,
        "max_tokens": "per-model (nvidia_adapter._default_max_tokens); override AISEC_LLM_MAX_TOKENS",
        "seed_param_or_nondeterminism_note":
            f"AISEC_LLM_SEED={seed} passed to OpenRouter chat.completions; if the "
            f"serving provider ignores seed, replicate variation is from "
            f"temperature=0.2 sampling nondeterminism",
        "prompt_template_hash": f"pipeline.py:sha256:{thash}",
        "tool_versions": {"python": sys.version.split()[0], "forge": forge_v,
                          "backend": "OpenRouter"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))


def base_env(seed: str) -> dict:
    e = dict(os.environ)
    e["AISEC_RESULT_CACHE"] = "0"
    e["AISEC_LAB_CONCURRENCY"] = os.getenv("JOB_CONCURRENCY", "16")
    e["AISEC_LLM_SEED"] = seed
    e["AISEC_LLM_TIMEOUT"] = os.getenv("AISEC_LLM_TIMEOUT", "180")
    return e


def run_unit(cmd_env: dict, repo: str, label: str, tag: str, max_run_min: int) -> None:
    """Run one run_ablation_fast invocation with a wall-clock guard."""
    logpath = JOBS / "logs" / f"{label}__{tag}.log"
    logpath.parent.mkdir(parents=True, exist_ok=True)
    with open(logpath, "w") as lf:
        p = subprocess.Popen([PY, "-u", ABLATION, repo], env=cmd_env,
                             stdout=lf, stderr=subprocess.STDOUT)
        deadline = time.time() + max_run_min * 60
        while p.poll() is None:
            if time.time() > deadline:
                p.kill()
                raise TimeoutError(f"{label}/{tag} exceeded {max_run_min} min — aborted")
            time.sleep(15)
        if p.returncode != 0:
            raise RuntimeError(f"{label}/{tag} exited {p.returncode}; see {logpath}")


def do_detection(run_dir: str, bench: str, det_model: str, max_run_min: int) -> None:
    seed = seed_of(run_dir)
    write_manifest(run_dir, det_model, seed)  # always (re)write manifest
    if (DATA / run_dir / "baseline" / "metadata.json").exists():
        log(f"skip detection {run_dir} (done)")
        return
    repo = repo_for(bench, run_dir)
    e = base_env(seed)
    e["AISEC_ABL_MODE"] = "baseline"
    e["AISEC_ABL_LABEL"] = run_dir
    e["AISEC_FAST_CHAIN"] = DET_CHAIN[det_model]
    e["AISEC_POC_GEN_OVERRIDE"] = DET_CHAIN[det_model]
    for k in ("abl_" + run_dir,):  # clear stale state
        for sf in WORKSPACE.glob(f"state/abl_{run_dir}_*.json"):
            sf.unlink()
    t0 = time.time()
    log(f"DETECTION start {run_dir} [{det_model}] bench={bench}")
    try:
        run_unit(e, repo, run_dir, "detection", max_run_min)
        record_progress(run_dir, "baseline", "done", t0, time.time())
        log(f"DETECTION done  {run_dir}")
    except Exception as ex:
        record_progress(run_dir, "baseline", "failed", t0, time.time())
        record_failure(run_dir, "baseline", str(ex))
        log(f"DETECTION FAIL  {run_dir}: {ex}")
        raise


def do_verify(run_dir: str, bench: str, pool: str, verify_model: str,
              configs: list[str], max_run_min: int) -> None:
    todo = [c for c in configs
            if not (DATA / run_dir / c / "metadata.json").exists()]
    if not todo:
        log(f"skip verify {run_dir} (all {len(configs)} configs done)")
        return
    # pool baseline must exist; for Tier 3 copy it into this run_dir
    pool_base = DATA / pool / "baseline"
    if not (pool_base / "metadata.json").exists():
        raise RuntimeError(f"verify {run_dir}: pool {pool} has no baseline")
    if pool != run_dir:
        dst = DATA / run_dir / "baseline"
        if not (dst / "metadata.json").exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(pool_base, dst)
    seed = seed_of(run_dir)
    repo = repo_for(bench, run_dir)
    e = base_env(seed)
    e["AISEC_ABL_MODE"] = "verify"
    e["AISEC_ABL_LABEL"] = run_dir
    e["AISEC_ABL_VERIFY_CONFIGS"] = ",".join(todo)
    e["AISEC_VERIFY_BACKEND_OVERRIDE"] = VERIFY_BACKEND[verify_model]
    e["AISEC_POC_GEN_OVERRIDE"] = DET_CHAIN.get("qwen3-coder")  # PoC-gen fast backend
    for sf in WORKSPACE.glob(f"state/abl_{run_dir}_*.json"):
        # keep baseline state; verify writes its own vids
        pass
    t0 = time.time()
    log(f"VERIFY start {run_dir} [{verify_model}] configs={todo}")
    try:
        run_unit(e, repo, run_dir, "verify", max_run_min)
        for c in todo:
            ok = (DATA / run_dir / c / "metadata.json").exists()
            record_progress(run_dir, c, "done" if ok else "failed", t0, time.time())
        log(f"VERIFY done  {run_dir}")
    except Exception as ex:
        for c in todo:
            record_progress(run_dir, c, "failed", t0, time.time())
        record_failure(run_dir, ",".join(todo), str(ex))
        log(f"VERIFY FAIL  {run_dir}: {ex}")
        raise


def load_plan():
    rows = [r for r in csv.DictReader(open(JOBS / "jobs.csv")) if r["optional"] == "no"]
    detections = {}   # run_dir -> (bench, det_model)
    verifies = {}     # run_dir -> dict(bench,pool,verify_model,configs=set)
    for r in rows:
        rd = r["run_dir"]; bench = r["benchmark"]
        if r["stage"] == "detection":
            detections[rd] = (bench, r["detection_model"])
        else:
            v = verifies.setdefault(rd, {"bench": bench,
                                         "pool": r["source_pool"] or rd,
                                         "verify_model": r["verification_model"],
                                         "configs": []})
            v["configs"].append(r["config"])
    return detections, verifies


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parallel", type=int, default=int(os.getenv("JOB_PARALLEL", "6")))
    ap.add_argument("--max-run-min", type=int, default=750)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only-stage", choices=["detection", "verification"])
    args = ap.parse_args()

    detections, verifies = load_plan()
    # SmartBugs detection first (longest pole), then the rest.
    det_order = sorted(detections, key=lambda rd: (0 if detections[rd][0] == "smartbugs" else 1, rd))

    if args.dry_run:
        print(f"detections: {len(detections)} run_dirs")
        for rd in det_order[:6]:
            print("  DET", rd, detections[rd])
        print(f"verify run_dirs: {len(verifies)}")
        exdir = next(iter(verifies))
        print("  VER example", exdir, verifies[exdir]["verify_model"],
              verifies[exdir]["pool"], len(verifies[exdir]["configs"]), "configs")
        vjobs = sum(len(v["configs"]) for v in verifies.values())
        print(f"total: {len(detections)} detections + {vjobs} verify-config jobs")
        # verify every verify pool has a detection
        missing = {v["pool"] for v in verifies.values()} - set(detections)
        print("pools missing detection:", missing or "none")
        return 0

    ex = ThreadPoolExecutor(max_workers=args.parallel)
    det_futures: dict[str, Future] = {}

    if args.only_stage != "verification":
        for rd in det_order:
            bench, dm = detections[rd]
            det_futures[rd] = ex.submit(do_detection, rd, bench, dm, args.max_run_min)

    # submit verifies as their pool detection completes
    verify_futures = []
    if args.only_stage != "detection":
        pending = dict(verifies)
        done_pools = set()
        # if resuming, pools already detected are ready immediately
        for rd in detections:
            if (DATA / rd / "baseline" / "metadata.json").exists():
                done_pools.add(rd)
        while pending:
            ready = [rd for rd, v in pending.items()
                     if v["pool"] in done_pools
                     or (det_futures.get(v["pool"]) and det_futures[v["pool"]].done())]
            for rd in ready:
                v = pending.pop(rd)
                if v["verify_model"] not in VERIFY_BACKEND:
                    log(f"skip verify {rd}: verifier {v['verify_model']} not runnable (optional)")
                    continue
                verify_futures.append(
                    ex.submit(do_verify, rd, v["bench"], v["pool"],
                              v["verify_model"], v["configs"], args.max_run_min))
            # refresh done pools
            for rd, fut in det_futures.items():
                if fut.done() and fut.exception() is None:
                    done_pools.add(rd)
            if not ready:
                time.sleep(10)

    ex.shutdown(wait=True)
    log("ALL UNITS COMPLETE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
