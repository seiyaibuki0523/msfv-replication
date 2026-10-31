#!/usr/bin/env python3
"""Round-4 runner (jobs/round4/jobs_round4.csv) — verification only, no new detection.

B2 batch (32 jobs): Nemotron verifier, full_rep2 / full_rep3 on the existing gemma and qwen
   pools of seeds 2 and 3 (seed 1 already has them). Same settings as the round-3 Nemotron
   verification: temperature 0.2, reasoning on, default max_tokens, DeepInfra pinned, LOW
   concurrency (CONC=4).
C batch (72 jobs): gemma and qwen verifiers on the frozen Nemotron pools st_nemotron_{bench}_s{1,2,3}
   (baseline copied into st_nemotron-v{gemma,qwen}_{bench}_s{seed}), configs full / full_rep2 /
   full_rep3. Same settings as the round-3 B batch: temperature 0.2, no provider pin, CONC=8.
Afterwards write_manifests.py fills in manifest.json for every run_dir that lacks one.

Modelled on experiments/round3_run.py (same env contract for run_ablation_fast.py). Resumable:
a config whose metadata.json exists is skipped. Progress -> jobs/round4/progress.csv,
failures -> jobs/round4/failures.log, per-unit logs -> jobs/round4/logs/.

Usage (on the run host):
  cd <MSFV_ROOT>
  python3 experiments/round4_run.py --dry-run
  nohup python3 experiments/round4_run.py > jobs/round4/run.log 2>&1 &
  python3 experiments/write_manifests.py            # after the runs finish
"""
from __future__ import annotations
import csv, os, shutil, subprocess, sys, time, threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
JOBS = ROOT / "jobs" / "round4"
DATA = ROOT / "data" / "ablation"
SCAN = Path(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"))
WS = Path(os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace"))
PY = os.environ.get("MSFV_PYTHON", "python3")
ABL = str(ROOT / "experiments" / "run_ablation_fast.py")
NEMO = "openrouter:nemotron-120b"
LOGD = JOBS / "logs"; LOGD.mkdir(parents=True, exist_ok=True)
PROG = JOBS / "progress.csv"; FAIL = JOBS / "failures.log"
_lock = threading.Lock()

VBACKEND = {"Nemotron-3-Super-120B-A12B": NEMO,
            "gemma-4-31B": "openrouter:gemma-4-31b",
            "qwen3-coder": "openrouter:qwen3-coder"}
NEMO_CONC = int(os.getenv("R4_NEMO_CONC", "4"))     # hard rule 6: nemotron always low concurrency
OTHER_CONC = int(os.getenv("R4_CONC", "8"))
PAR_B2 = int(os.getenv("R4_PAR_B2", "2"))            # run_dirs in flight for the Nemotron batch
PAR_C = int(os.getenv("R4_PAR_C", "6"))              # run_dirs in flight for the gemma/qwen batch


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
                w.writerow(["run_dir", "config", "status", "start", "elapsed_min"])
            w.writerow([rd, cfg, status, time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t0)),
                        round((time.time() - t0) / 60, 1)])


def run_unit(env, repo, label, tag):
    lp = LOGD / f"{label}__{tag}.log"
    with open(lp, "w") as lf:
        rc = subprocess.Popen([PY, "-u", ABL, repo], env=env, stdout=lf, stderr=subprocess.STDOUT).wait()
    if rc != 0:
        with _lock:
            open(FAIL, "a").write(f"\n===== {label}/{tag} rc={rc} see {lp} =====\n")
    return rc


def base(seed, conc):
    e = dict(os.environ)
    e.update(AISEC_RESULT_CACHE="0", AISEC_LAB_CONCURRENCY=str(conc), AISEC_LLM_SEED=str(seed),
             AISEC_LLM_TIMEOUT="300", AISEC_LLM_RETRIES="4")
    # never inherit detection-only knobs
    for k in ("AISEC_NEMOTRON_THINKING", "AISEC_LLM_TEMPERATURE", "AISEC_LLM_MAX_TOKENS", "AISEC_VERIFY_MODE"):
        e.pop(k, None)
    return e


def do_verify(rd, pool, vmodel, configs, conc, pin):
    bench = bench_of(rd); seed = rd.rsplit("_", 1)[-1][1:]
    todo = [c for c in configs if not (DATA / rd / c / "metadata.json").exists()]
    if not todo:
        print(f"[{time.strftime('%H:%M:%S')}] skip {rd} (done)", flush=True)
        return
    pool_base = DATA / pool / "baseline"
    if not (pool_base / "metadata.json").exists():
        with _lock:
            open(FAIL, "a").write(f"\n===== {rd}: pool {pool} missing =====\n")
        print(f"!! pool missing for {rd}: {pool}", flush=True)
        return
    if pool != rd:
        dst = DATA / rd / "baseline"
        if not (dst / "metadata.json").exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(pool_base, dst)
    e = base(seed, conc)
    e.update(AISEC_ABL_MODE="verify", AISEC_ABL_LABEL=rd, AISEC_ABL_VERIFY_CONFIGS=",".join(todo),
             AISEC_VERIFY_BACKEND_OVERRIDE=VBACKEND[vmodel],
             AISEC_POC_GEN_OVERRIDE=f"openrouter:qwen3-coder,{NEMO}")
    if pin:
        e["AISEC_OPENROUTER_PROVIDER"] = "DeepInfra"
    else:
        e.pop("AISEC_OPENROUTER_PROVIDER", None)
    t0 = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] VER {rd} [{vmodel}] conc={conc} pin={pin} {todo}", flush=True)
    run_unit(e, str(SCAN / bench), rd, "verify")
    for c in todo:
        rec(rd, c, "done" if (DATA / rd / c / "metadata.json").exists() else "failed", t0)


def main():
    rows = list(csv.DictReader(open(JOBS / "jobs_round4.csv")))
    groups = {}
    for r in rows:
        g = groups.setdefault(r["run_dir"], {"batch": r["batch"], "pool": r["source_pool"],
                                              "vm": r["verification_model"], "cfgs": []})
        g["cfgs"].append(r["config"])
    b2 = {k: v for k, v in groups.items() if v["batch"].startswith("B2")}
    c = {k: v for k, v in groups.items() if v["batch"].startswith("C")}
    print(f"B2: {len(b2)} run_dirs / {sum(len(v['cfgs']) for v in b2.values())} jobs (Nemotron verifier, conc={NEMO_CONC}, pinned)")
    print(f"C : {len(c)} run_dirs / {sum(len(v['cfgs']) for v in c.values())} jobs (gemma/qwen verifiers, conc={OTHER_CONC})")
    missing = [v["pool"] for v in groups.values() if not (DATA / v["pool"] / "baseline" / "metadata.json").exists()]
    print("pools missing:", sorted(set(missing)) or "none")
    if "--dry-run" in sys.argv:
        for rd, v in list(b2.items())[:2] + list(c.items())[:2]:
            print("  ", rd, v["vm"], v["pool"], v["cfgs"])
        return 0

    def run_b2():
        with ThreadPoolExecutor(max_workers=PAR_B2) as ex:
            list(ex.map(lambda kv: do_verify(kv[0], kv[1]["pool"], kv[1]["vm"], kv[1]["cfgs"], NEMO_CONC, True), b2.items()))

    def run_c():
        with ThreadPoolExecutor(max_workers=PAR_C) as ex:
            list(ex.map(lambda kv: do_verify(kv[0], kv[1]["pool"], kv[1]["vm"], kv[1]["cfgs"], OTHER_CONC, False), c.items()))

    with ThreadPoolExecutor(max_workers=2) as top:
        fb = top.submit(run_b2); fc = top.submit(run_c)
        fb.result(); fc.result()
    done = sum(1 for r in rows if (DATA / r["run_dir"] / r["config"] / "metadata.json").exists())
    print(f"ROUND-4 COMPLETE: {done}/{len(rows)} configs have metadata.json", flush=True)
    return 0 if done == len(rows) else 1


if __name__ == "__main__":
    sys.exit(main())
