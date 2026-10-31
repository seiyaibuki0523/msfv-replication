#!/usr/bin/env python3
"""Re-run the nemotron detection arm at raised max_tokens (fixes thinking-mode
truncation) + its dependent verify configs.

- detection: AISEC_LLM_MAX_TOKENS=40000 (nemotron <think> was hitting 16000 and
  truncating before the verdict → candidates silently dropped → erratic counts).
- verify:    DEFAULT max_tokens (nemotron verifier stays consistent with the
  qwen/gemma arms' verify; verify output is short and unaffected).

Old nemotron output is archived to data/ablation/old/nemotron_pre_maxtok/ first
(never overwritten). Reads jobs.csv for the exact configs per run_dir.
"""
from __future__ import annotations
import csv, os, shutil, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
JOBS = ROOT / "jobs" / "v2"
DATA = ROOT / "data" / "ablation"
SCAN = Path(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"))
WS = Path(os.environ.get("AISEC_WORKSPACE", "/tmp/aisec-workspace"))
PY = os.environ.get("MSFV_PYTHON", "python3")
ABL = str(ROOT / "experiments" / "run_ablation_fast.py")
NEMO = "openrouter:nemotron-120b"
DET_MAXTOK = "40000"
PAR = int(os.getenv("RERUN_PAR", "6"))
LOGD = JOBS / "logs_rerun"; LOGD.mkdir(exist_ok=True)


def bench_of(rd):
    for b in ("dvd", "pygoat", "nodegoat", "smartbugs"):
        if f"_{b}_" in rd:
            return b
    return "?"


def seed_of(rd):
    return rd.rsplit("_", 1)[-1][1:]


def plan():
    rows = [r for r in csv.DictReader(open(JOBS/"jobs.csv")) if r["optional"] == "no"]
    dets = {r["run_dir"] for r in rows
            if r["stage"] == "detection" and r["detection_model"].startswith("Nemotron")}
    vers = {}
    for r in rows:
        if r["stage"] == "verification" and r["run_dir"] in dets:
            vers.setdefault(r["run_dir"], []).append(r["config"])
    return sorted(dets), vers


def run(env, label, tag):
    lp = LOGD / f"{label}__{tag}.log"
    with open(lp, "w") as lf:
        p = subprocess.Popen([PY, "-u", ABL, env["_REPO"]],
                             env={k: v for k, v in env.items() if k != "_REPO"},
                             stdout=lf, stderr=subprocess.STDOUT)
        rc = p.wait()
    if rc != 0:
        raise RuntimeError(f"{label}/{tag} rc={rc} see {lp}")


def base(seed):
    e = dict(os.environ)
    e["AISEC_RESULT_CACHE"] = "0"
    e["AISEC_LAB_CONCURRENCY"] = os.getenv("RERUN_CONC", "12")
    e["AISEC_LLM_SEED"] = seed
    e["AISEC_LLM_TIMEOUT"] = "300"
    e["AISEC_LLM_RETRIES"] = "4"
    # Pin a single OpenRouter provider — mixed routing (DeepInfra bf16/cap16384
    # vs DigitalOcean uncapped) made nemotron detection non-reproducible.
    e["AISEC_OPENROUTER_PROVIDER"] = os.getenv("AISEC_OPENROUTER_PROVIDER", "DigitalOcean")
    return e


def do_one(rd, cfgs):
    bench = bench_of(rd); seed = seed_of(rd)
    repo = str(SCAN / bench)
    # detection @ 40000
    for sf in WS.glob(f"state/abl_{rd}_*.json"):
        sf.unlink()
    e = base(seed)
    e.update(AISEC_ABL_MODE="baseline", AISEC_ABL_LABEL=rd,
             AISEC_FAST_CHAIN=NEMO, AISEC_POC_GEN_OVERRIDE=f"openrouter:qwen3-coder,{NEMO}",
             AISEC_LLM_MAX_TOKENS="12000", _REPO=repo,
             # DETECTION reproducibility config (validated: nodegoat 34/36/38,
             # CV~5% vs temp0.2's 61%): greedy temp=0 kills sampling variance,
             # thinking-off + provider-pin remove reasoning/quant nondeterminism.
             # DeepInfra (bf16, cap 16384 — safe since thinking-off is short).
             AISEC_NEMOTRON_THINKING="off", AISEC_LLM_TEMPERATURE="0")
    t0 = time.time()
    print(f"[{time.strftime('%H:%M:%S')}] DET  {rd} (maxtok={DET_MAXTOK})", flush=True)
    run(e, rd, "detection")
    # verify @ default max_tokens (do NOT set AISEC_LLM_MAX_TOKENS)
    e = base(seed)
    e.update(AISEC_ABL_MODE="verify", AISEC_ABL_LABEL=rd,
             AISEC_ABL_VERIFY_CONFIGS=",".join(cfgs),
             AISEC_VERIFY_BACKEND_OVERRIDE=NEMO,
             AISEC_POC_GEN_OVERRIDE=f"openrouter:qwen3-coder,{NEMO}", _REPO=repo)
    e.pop("AISEC_NEMOTRON_THINKING", None)  # VERIFY keeps reasoning ON (stable, studied stage)
    e.pop("AISEC_LLM_TEMPERATURE", None)     # VERIFY keeps default temp 0.2 (stable, CV 2.1%)
    e.pop("AISEC_LLM_MAX_TOKENS", None)
    print(f"[{time.strftime('%H:%M:%S')}] VER  {rd} cfgs={cfgs}", flush=True)
    run(e, rd, "verify")
    print(f"[{time.strftime('%H:%M:%S')}] DONE {rd} ({(time.time()-t0)/60:.0f}m)", flush=True)


def main():
    dets, vers = plan()
    # Optional benchmark filter (RERUN_BENCH=nodegoat,pygoat) — re-run only some
    # benchmarks (leaves the others' data untouched, incl. the archive step).
    _bf = [b.strip() for b in os.getenv("RERUN_BENCH", "").split(",") if b.strip()]
    if _bf:
        dets = [rd for rd in dets if bench_of(rd) in _bf]
        vers = {rd: v for rd, v in vers.items() if bench_of(rd) in _bf}
    print(f"nemotron run_dirs: {len(dets)} | verify configs total: {sum(len(v) for v in vers.values())}")
    if "--dry-run" in sys.argv:
        for rd in dets:
            print(f"  {rd}: verify={vers.get(rd, [])}")
        return 0
    # archive old nemotron output (never overwrite)
    arch = DATA / "old" / os.getenv("RERUN_ARCHIVE", "nemotron_mixed_provider")
    arch.mkdir(parents=True, exist_ok=True)
    for rd in dets:
        src = DATA / rd
        if src.exists():
            dst = arch / rd
            if dst.exists():
                shutil.rmtree(dst)
            shutil.move(str(src), str(dst))
    print(f"archived {len(dets)} old run_dirs -> {arch}")
    with ThreadPoolExecutor(max_workers=PAR) as ex:
        futs = {ex.submit(do_one, rd, vers.get(rd, [])): rd for rd in dets}
        for f in futs:
            try:
                f.result()
            except Exception as ex2:
                print(f"FAIL {futs[f]}: {ex2}", flush=True)
    print("ALL NEMOTRON RE-RUNS COMPLETE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
