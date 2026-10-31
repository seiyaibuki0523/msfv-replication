#!/usr/bin/env python3
"""Round-2 A batch: naive_verify on existing candidate pools (verify-only).

Idempotent + resumable: skips run_dirs whose naive_verify output already exists,
and skips run_dirs whose baseline pool is not present yet (nemotron pools are
being re-run). Run it now (does qwen+gemma = 40); run it again after the
nemotron re-run finishes (picks up the 20 nemotron once their pools exist).

verifier = Nemotron @ DEFAULT max_tokens (matches the full-config verify these
are compared against). One call per finding, single unstructured prompt.
"""
from __future__ import annotations
import csv, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
JOBS = ROOT / "jobs" / "native_verify"
DATA = ROOT / "data" / "ablation"
SCAN = Path(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"))
WS = Path(os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace"))
PY = os.environ.get("MSFV_PYTHON", "python3")
ABL = str(ROOT / "experiments" / "run_ablation_fast.py")
NEMO = "openrouter:nemotron-120b"
PAR = int(os.getenv("R2_PAR", "6"))
LOGD = JOBS / "logs"; LOGD.mkdir(parents=True, exist_ok=True)
PROG = JOBS / "progress.csv"; FAIL = JOBS / "failures.log"


def bench_of(rd):
    for b in ("dvd", "pygoat", "nodegoat", "smartbugs"):
        if f"_{b}_" in rd:
            return b
    return "?"


def rec(rd, status, t0):
    new = not PROG.exists()
    with open(PROG, "a", newline="") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["run_dir", "config", "status", "elapsed_min"])
        w.writerow([rd, "naive_verify", status, round((time.time()-t0)/60, 1)])


def do(rd):
    bench = bench_of(rd); seed = rd.rsplit("_", 1)[-1][1:]
    pool = DATA / rd / "baseline" / "metadata.json"
    out = DATA / rd / "naive_verify" / "metadata.json"
    if out.exists():
        return ("skip-done", rd)
    if not pool.exists():
        return ("skip-nopool", rd)   # nemotron pool still re-running
    for sf in WS.glob(f"state/abl_{rd}_naive*.json"):
        sf.unlink()
    e = dict(os.environ)
    e.update(AISEC_ABL_MODE="verify", AISEC_ABL_LABEL=rd,
             AISEC_ABL_VERIFY_CONFIGS="naive_verify",
             AISEC_VERIFY_BACKEND_OVERRIDE=NEMO,
             AISEC_POC_GEN_OVERRIDE=f"openrouter:qwen3-coder,{NEMO}",
             AISEC_RESULT_CACHE="0", AISEC_LAB_CONCURRENCY=os.getenv("R2_CONC", "12"),
             AISEC_LLM_SEED=seed, AISEC_LLM_TIMEOUT="180", AISEC_LLM_RETRIES="4",
             AISEC_OPENROUTER_PROVIDER=os.getenv("AISEC_OPENROUTER_PROVIDER", "DigitalOcean"))
    e.pop("AISEC_LLM_MAX_TOKENS", None)  # default — match full's verify
    t0 = time.time()
    lp = LOGD / f"{rd}__naive.log"
    print(f"[{time.strftime('%H:%M:%S')}] NAIVE {rd}", flush=True)
    with open(lp, "w") as lf:
        rc = subprocess.Popen([PY, "-u", ABL, str(SCAN/bench)], env=e,
                             stdout=lf, stderr=subprocess.STDOUT).wait()
    ok = out.exists()
    rec(rd, "done" if ok else "failed", t0)
    if not ok:
        with open(FAIL, "a") as f:
            f.write(f"\n===== {rd}/naive_verify rc={rc} see {lp} =====\n")
    return ("done" if ok else "failed", rd)


def main():
    rows = [r for r in csv.DictReader(open(JOBS/"jobs_round2.csv"))
            if r["batch"] == "A_naive_verify"]
    run_dirs = sorted({r["run_dir"] for r in rows})
    # qwen + gemma first (runnable now); nemotron last (gated on pool existence)
    run_dirs.sort(key=lambda rd: (0 if ("_qwen_" in rd or "_gemma_" in rd) else 1, rd))
    print(f"A batch run_dirs: {len(run_dirs)}")
    if "--dry-run" in sys.argv:
        for rd in run_dirs:
            pool = (DATA/rd/"baseline"/"metadata.json").exists()
            done = (DATA/rd/"naive_verify"/"metadata.json").exists()
            print(f"  {rd:26} pool={'Y' if pool else 'N'} done={'Y' if done else 'N'}")
        return 0
    with ThreadPoolExecutor(max_workers=PAR) as ex:
        res = list(ex.map(do, run_dirs))
    import collections
    c = collections.Counter(s for s, _ in res)
    print(f"RESULT: {dict(c)}", flush=True)
    nopool = [rd for s, rd in res if s == "skip-nopool"]
    if nopool:
        print(f"waiting for pools (re-run these after nemotron re-run): {len(nopool)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
