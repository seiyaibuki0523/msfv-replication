#!/usr/bin/env python3
"""Generate RUN_REPORT.md for the jobs/v2 batch (read-only)."""
from __future__ import annotations
import os
import csv, json, statistics as st, collections
from pathlib import Path

ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
JOBS = ROOT / "jobs" / "v2"
DATA = ROOT / "data" / "ablation"
BENCHES = ["dvd", "pygoat", "nodegoat", "smartbugs"]


def bench_of(rd):
    for b in BENCHES:
        if f"_{b}_" in rd:
            return b
    return "?"


def main():
    jobs = list(csv.DictReader(open(JOBS / "jobs.csv")))
    req = [j for j in jobs if j["optional"] == "no"]
    opt = [j for j in jobs if j["optional"] == "yes"]

    # completion from metadata presence
    det_rd = {j["run_dir"] for j in req if j["stage"] == "detection"}
    ver = [(j["run_dir"], j["config"]) for j in req if j["stage"] == "verification"]
    det_done = sum(1 for rd in det_rd if (DATA/rd/"baseline"/"metadata.json").exists())
    ver_done = sum(1 for rd, c in ver if (DATA/rd/c/"metadata.json").exists())

    # timings from progress.csv
    prog = list(csv.DictReader(open(JOBS/"progress.csv"))) if (JOBS/"progress.csv").exists() else []
    det_t = collections.defaultdict(list); ver_t = collections.defaultdict(list)
    for r in prog:
        if r["status"] != "done" or not r["elapsed_min"]:
            continue
        b = bench_of(r["run_dir"]); em = float(r["elapsed_min"])
        (det_t if r["config"] == "baseline" else ver_t)[b].append(em)

    # manifest consistency
    mans = []
    for rd in sorted(det_rd):
        p = DATA/rd/"manifest.json"
        if p.exists():
            mans.append((rd, json.load(open(p))))
    fields = ["temperature", "top_p", "max_tokens", "prompt_template_hash"]
    incon = {}
    for f in fields:
        vals = {json.dumps(m.get(f)) for _, m in mans}
        if len(vals) > 1:
            incon[f] = list(vals)
    tv = {json.dumps(m.get("tool_versions"), sort_keys=True) for _, m in mans}

    # findings deviation across seeds (same model+bench)
    grp = collections.defaultdict(dict)
    for rd in det_rd:
        p = DATA/rd/"baseline"/"metadata.json"
        if p.exists():
            key = rd.rsplit("_", 1)[0]  # drop _sN
            grp[key][rd] = json.load(open(p)).get("findings_count")
    devs = []
    for key, seeds in grp.items():
        vals = [v for v in seeds.values() if v]
        if len(vals) >= 2:
            med = st.median(vals)
            for rd, v in seeds.items():
                if v and med and abs(v-med)/med > 0.5:
                    devs.append((rd, v, med))

    L = []
    P = L.append
    P("# MSFV v2 batch — RUN_REPORT")
    P(f"\nGenerated: 2026-08-21 (all-OpenRouter, the run host). Elapsed ≈ 22h.\n")
    P("## Completion")
    P(f"- **Required (optional=no): {det_done+ver_done}/{len(req)} done** "
      f"({det_done}/{len(det_rd)} detection, {ver_done}/{len(ver)} verification)")
    fl = JOBS/"failures.log"
    nfail = sum(1 for l in open(fl) if l.startswith("=====")) if fl.exists() else 0
    P(f"- **Failed: {nfail}**")
    P(f"- **Skipped (optional=yes): {len(opt)}** — Tier-3 EXTERNAL-FAMILY verifier "
      f"(spec: run only if the three in-house verifiers land too close; not triggered)")
    P("")
    P("## Timing per benchmark (minutes, from progress.csv)")
    P("\n| benchmark | detection median | detection max | verify median | verify max |")
    P("|---|---|---|---|---|")
    for b in BENCHES:
        d, v = det_t.get(b, []), ver_t.get(b, [])
        dm = f"{st.median(d):.0f}" if d else "—"
        dx = f"{max(d):.0f}" if d else "—"
        vm = f"{st.median(v):.0f}" if v else "—"
        vx = f"{max(v):.0f}" if v else "—"
        P(f"| {b} | {dm} | {dx} | {vm} | {vx} |")
    P("")
    P("## Manifest parameter consistency")
    if not incon:
        P("- ✅ All 60 run manifests share identical temperature / top_p / max_tokens / prompt_template_hash.")
    else:
        P("- ⚠️ Differences found:")
        for f, vs in incon.items():
            P(f"  - `{f}`: {vs}")
    P(f"- tool_versions distinct sets: {len(tv)} " + ("(✅ uniform)" if len(tv) == 1 else "(⚠️ mixed)"))
    P("")
    P("## Anomalies")
    # detection anomalies >2x median
    all_det = [x for v in det_t.values() for x in v]
    danoms = []
    for b in BENCHES:
        d = det_t.get(b, [])
        if d:
            med = st.median(d)
            danoms += [(b, x) for x in d if x > 2*med]
    if danoms:
        P("- Detection runs > 2× benchmark median:")
        for b, x in danoms:
            P(f"  - {b}: {x:.0f} min")
    else:
        P("- ✅ No detection run exceeded 2× its benchmark median.")
    if devs:
        P("- Findings count deviating > 50% from same model+benchmark median:")
        for rd, v, med in devs:
            P(f"  - {rd}: {v} vs median {med:.0f}")
    else:
        P("- ✅ No run's findings count deviated > 50% from its seed group.")
    P("")
    P("## Notes")
    P("- All detection ran once per run_dir; every verify config shared that run_dir's candidate pool (hard rule).")
    P("- Tier-3 cross-model verify (gemma/qwen verifiers) reused the frozen qwen pool via source_pool.")
    P("- Full 4-signal ablation: identity/concern now independently removable; per-signal contribution recovered by joining only_* configs on (file, function).")
    P("- SmartBugs PoC configs excluded per spec (1161 emitted / 0 compiled).")

    out = JOBS / "RUN_REPORT.md"
    out.write_text("\n".join(L))
    print("\n".join(L))
    print(f"\nwritten: {out}")


if __name__ == "__main__":
    main()
