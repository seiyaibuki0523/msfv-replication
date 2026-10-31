#!/usr/bin/env python3
"""Round-3 runner (jobs/26-9-2-job/jobs_round3.csv).

A batch: re-run st_nemotron_smartbugs_s5 detection at the final reproducible
config (DeepInfra + temp=0 + thinking-off + max 12000, LOW concurrency), then
its 4 verify configs. B batch: 72 self-verify control jobs on the frozen gemma
pools (gemma & qwen verifiers, full/full_rep2/full_rep3) — no new detection.
A and B run concurrently (B does not depend on A).
"""
from __future__ import annotations
import csv, os, shutil, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
JOBS = ROOT / "jobs" / "26-9-2-job"
DATA = ROOT / "data" / "ablation"
SCAN = Path(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"))
WS = Path(os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace"))
PY = os.environ.get("MSFV_PYTHON", "python3")
ABL = str(ROOT / "experiments" / "run_ablation_fast.py")
NEMO = "openrouter:nemotron-120b"
LOGD = JOBS / "logs"; LOGD.mkdir(parents=True, exist_ok=True)
PROG = JOBS / "progress.csv"; FAIL = JOBS / "failures.log"
import threading
_lock = threading.Lock()

VBACKEND = {"Nemotron-3-Super-120B-A12B": NEMO,
            "gemma-4-31B": "openrouter:gemma-4-31b",
            "qwen3-coder": "openrouter:qwen3-coder"}


def bench_of(rd):
    for b in ("dvd", "pygoat", "nodegoat", "smartbugs"):
        if f"_{b}_" in rd:
            return b
    return "?"


def rec(rd, cfg, status, t0):
    with _lock:
        new = not PROG.exists()
        with open(PROG, "a", newline="") as f:
            w = csv.writer(f)
            if new:
                w.writerow(["run_dir", "config", "status", "elapsed_min"])
            w.writerow([rd, cfg, status, round((time.time()-t0)/60, 1)])


def run_unit(env, repo, label, tag):
    lp = LOGD / f"{label}__{tag}.log"
    with open(lp, "w") as lf:
        rc = subprocess.Popen([PY, "-u", ABL, repo], env={k: v for k, v in env.items() if k != "_REPO"},
                              stdout=lf, stderr=subprocess.STDOUT).wait()
    if rc != 0:
        with _lock:
            open(FAIL, "a").write(f"\n===== {label}/{tag} rc={rc} see {lp} =====\n")
    return rc


def base(seed, conc):
    e = dict(os.environ)
    e.update(AISEC_RESULT_CACHE="0", AISEC_LAB_CONCURRENCY=str(conc), AISEC_LLM_SEED=str(seed),
             AISEC_LLM_TIMEOUT="300", AISEC_LLM_RETRIES="4")
    return e


def a_detection(rd):
    bench = bench_of(rd); seed = rd.rsplit("_", 1)[-1][1:]
    # archive old
    src = DATA / rd
    if src.exists():
        arch = DATA / "old" / "round3_seed5_pre"; arch.mkdir(parents=True, exist_ok=True)
        d = arch / rd
        if d.exists():
            shutil.rmtree(d)
        shutil.move(str(src), str(d))
    for sf in WS.glob(f"state/abl_{rd}_*.json"):
        sf.unlink()
    e = base(seed, 4)  # LOW concurrency
    e.update(AISEC_ABL_MODE="baseline", AISEC_ABL_LABEL=rd, AISEC_FAST_CHAIN=NEMO,
             AISEC_POC_GEN_OVERRIDE=f"openrouter:qwen3-coder,{NEMO}", AISEC_LLM_MAX_TOKENS="12000",
             AISEC_NEMOTRON_THINKING="off", AISEC_LLM_TEMPERATURE="0",
             AISEC_OPENROUTER_PROVIDER="DeepInfra")
    t0 = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] A-DET {rd} (low-conc, temp0, DeepInfra)", flush=True)
    rc = run_unit(e, str(SCAN/bench), rd, "detection")
    rec(rd, "baseline", "done" if rc == 0 else "failed", t0)
    return rc


def do_verify(rd, pool, vmodel, configs, conc, pin=False):
    bench = bench_of(rd); seed = rd.rsplit("_", 1)[-1][1:]
    todo = [c for c in configs if not (DATA/rd/c/"metadata.json").exists()]
    if not todo:
        return
    pool_base = DATA / pool / "baseline"
    if not (pool_base/"metadata.json").exists():
        with _lock:
            open(FAIL, "a").write(f"\n===== {rd}: pool {pool} missing =====\n")
        return
    if pool != rd:
        dst = DATA / rd / "baseline"
        if not (dst/"metadata.json").exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(pool_base, dst)
    for sf in WS.glob(f"state/abl_{rd}_*.json"):
        pass
    e = base(seed, conc)
    e.update(AISEC_ABL_MODE="verify", AISEC_ABL_LABEL=rd, AISEC_ABL_VERIFY_CONFIGS=",".join(todo),
             AISEC_VERIFY_BACKEND_OVERRIDE=VBACKEND[vmodel],
             AISEC_POC_GEN_OVERRIDE=f"openrouter:qwen3-coder,{NEMO}")
    if pin:
        e["AISEC_OPENROUTER_PROVIDER"] = "DeepInfra"
    else:
        e.pop("AISEC_OPENROUTER_PROVIDER", None)
    t0 = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] VER {rd} [{vmodel}] {todo}", flush=True)
    rc = run_unit(e, str(SCAN/bench), rd, "verify")
    for c in todo:
        rec(rd, c, "done" if (DATA/rd/c/"metadata.json").exists() else "failed", t0)


def main():
    rows = list(csv.DictReader(open(JOBS/"jobs_round3.csv")))
    # A batch
    a_det = [r["run_dir"] for r in rows if r["batch"].startswith("A") and r["stage"] == "detection"]
    a_ver = {}
    for r in rows:
        if r["batch"].startswith("A") and r["stage"] == "verification":
            a_ver.setdefault(r["run_dir"], {"pool": r["source_pool"], "vm": r["verification_model"], "cfgs": []})["cfgs"].append(r["config"])
    # B batch grouped
    b = {}
    for r in rows:
        if r["batch"].startswith("B"):
            b.setdefault(r["run_dir"], {"pool": r["source_pool"], "vm": r["verification_model"], "cfgs": []})["cfgs"].append(r["config"])
    print(f"A: {len(a_det)} detection + {sum(len(v['cfgs']) for v in a_ver.values())} verify | B: {len(b)} run_dirs / {sum(len(v['cfgs']) for v in b.values())} verify")
    if "--dry-run" in sys.argv:
        for rd, v in list(b.items())[:3]:
            print("  B", rd, v["vm"], v["pool"], v["cfgs"])
        return 0

    def run_A():
        for rd in a_det:
            if a_detection(rd) == 0:
                v = a_ver.get(rd)
                if v:
                    do_verify(rd, v["pool"], v["vm"], v["cfgs"], 4, pin=True)  # nemotron verify, low conc + pin

    def run_B():
        with ThreadPoolExecutor(max_workers=6) as ex:
            list(ex.map(lambda kv: do_verify(kv[0], kv[1]["pool"], kv[1]["vm"], kv[1]["cfgs"], 8, pin=False), b.items()))

    with ThreadPoolExecutor(max_workers=2) as top:
        fa = top.submit(run_A); fb = top.submit(run_B)
        fa.result(); fb.result()
    print("ROUND-3 COMPLETE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
