#!/usr/bin/env python3
"""MSFV v2 batch dashboard — read-only terminal monitor (rich).

Watches the jobs/v2 batch: scans jobs.csv (plan), data/ablation (done),
progress.csv, failures.log, and cevanex-workspace/state (live activity).
Purely observes — never writes anything the run touches.

Usage (on the run host):
  python dash_v2.py            # live, refresh every 8s
  python dash_v2.py --once     # one snapshot
  python dash_v2.py --grid     # emphasise the per-experiment grid
"""
from __future__ import annotations
import csv, json, os, sys, time, shutil
from pathlib import Path

ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
JOBS = ROOT / "jobs" / "v2"
DATA = ROOT / "data" / "ablation"
STATE = Path("<AISEC_WORKSPACE>/state")
BENCHES = ["dvd", "pygoat", "nodegoat", "smartbugs"]
REFRESH = 8

C = {"g": "\033[92m", "y": "\033[93m", "r": "\033[91m", "b": "\033[94m",
     "c": "\033[96m", "m": "\033[95m", "w": "\033[97m", "d": "\033[2m",
     "0": "\033[0m", "B": "\033[1m", "gray": "\033[90m"}


def cw(s: str) -> int:
    """visible width (strip ANSI)."""
    import re
    return len(re.sub(r"\033\[[0-9;]*m", "", s))


def load_plan():
    dets, vers = {}, {}
    for r in csv.DictReader(open(JOBS / "jobs.csv")):
        if r["optional"] != "no":
            continue
        rd, bench = r["run_dir"], r["benchmark"]
        if r["stage"] == "detection":
            dets[rd] = bench
        else:
            v = vers.setdefault(rd, {"bench": bench, "vm": r["verification_model"],
                                     "pool": r["source_pool"] or rd, "cfgs": []})
            v["cfgs"].append(r["config"])
    return dets, vers


def bar(done, total, width=30, color="g"):
    frac = (done / total) if total else 0
    fill = round(frac * width)
    return f"{C[color]}{'█'*fill}{C['gray']}{'─'*(width-fill)}{C['0']} {C['w']}{done}/{total}{C['0']} {C['d']}{frac*100:4.1f}%{C['0']}"


def minibar(done, total, width=10):
    frac = (done / total) if total else 0
    fill = round(frac * width)
    col = "g" if done == total and total else ("y" if done else "gray")
    return f"{C[col]}{'█'*fill}{C['gray']}{'─'*(width-fill)}{C['0']}"


def meta(rd, cfg):
    p = DATA / rd / cfg / "metadata.json"
    if p.exists():
        try:
            return json.load(open(p))
        except Exception:
            return {}
    return None


def running(max_age=150):
    now = time.time(); out = {}
    if STATE.exists():
        for f in STATE.glob("abl_*.json"):
            age = now - f.stat().st_mtime
            if age < max_age:
                out[f.stem[4:]] = age
    return out


def fmt_dur(sec):
    if sec is None:
        return "?"
    m = int(sec // 60)
    if m < 60:
        return f"{m}m"
    return f"{m//60}h{m%60:02d}"


def snapshot(grid_focus=False):
    dets, vers = load_plan()
    W = shutil.get_terminal_size((120, 40)).columns
    out = []
    P = out.append

    # ---- header + overall ----
    det_done = sum(1 for rd in dets if (DATA/rd/"baseline"/"metadata.json").exists())
    ver_total = sum(len(v["cfgs"]) for v in vers.values())
    ver_done = sum(1 for rd, v in vers.items() for c in v["cfgs"] if (DATA/rd/c/"metadata.json").exists())
    tot_done, tot = det_done + ver_done, len(dets) + ver_total

    # timing / throughput / ETA from progress.csv
    rate = None; started = None; done_rows = fail_rows = 0
    pcsv = JOBS / "progress.csv"
    if pcsv.exists():
        rows = list(csv.DictReader(open(pcsv)))
        done_rows = sum(1 for r in rows if r["status"] == "done")
        fail_rows = sum(1 for r in rows if r["status"] == "failed")
        ts = [r["start"] for r in rows if r["start"]]
        if ts:
            try:
                started = time.mktime(time.strptime(min(ts), "%Y-%m-%dT%H:%M:%S"))
            except Exception:
                started = None
    if started:
        elapsed = time.time() - started
        if tot_done > 0 and elapsed > 0:
            rate = tot_done / elapsed  # jobs/sec
    eta = None
    if rate and rate > 0:
        eta = (tot - tot_done) / rate

    P(f"{C['B']}{C['c']}╔══ MSFV v2 batch ═══ {time.strftime('%Y-%m-%d %H:%M:%S')} "
      f"{'═'*max(0, W-42)}{C['0']}")
    P(f"  {C['B']}DETECTION{C['0']} " + bar(det_done, len(dets), 30, "b"))
    P(f"  {C['B']}VERIFY   {C['0']} " + bar(ver_done, ver_total, 30, "g"))
    P(f"  {C['B']}TOTAL    {C['0']} " + bar(tot_done, tot, 30, "c")
      + f"   {C['d']}elapsed {fmt_dur(time.time()-started) if started else '?'}"
      f" · ETA {C['y']}{fmt_dur(eta)}{C['0']}"
      + (f" {C['d']}(~{rate*3600:.0f} jobs/h){C['0']}" if rate else ""))
    if fail_rows:
        P(f"  {C['r']}⚠ {fail_rows} failed unit(s){C['0']}  {C['d']}(tail -40 {JOBS}/failures.log){C['0']}")

    # ---- per-benchmark ----
    P("")
    P(f"  {C['d']}{'benchmark':10} {'detection':^22} {'verification':^26}{C['0']}")
    for b in BENCHES:
        dd = sum(1 for rd, bb in dets.items() if bb == b and (DATA/rd/"baseline"/"metadata.json").exists())
        dt = sum(1 for bb in dets.values() if bb == b)
        vd = sum(1 for rd, v in vers.items() if v["bench"] == b for c in v["cfgs"] if (DATA/rd/c/"metadata.json").exists())
        vt = sum(len(v["cfgs"]) for v in vers.values() if v["bench"] == b)
        P(f"  {C['w']}{b:10}{C['0']} {minibar(dd,dt,12)} {dd:>2}/{dt:<2}   {minibar(vd,vt,16)} {vd:>3}/{vt:<3}")

    # ---- running now ----
    run = running()
    P("")
    P(f"  {C['B']}running now{C['0']} {C['d']}({len(run)} active · state fresh <150s){C['0']}")
    if run:
        for name, age in sorted(run.items(), key=lambda x: x[1])[:10]:
            base = name.rsplit("_", 1)[0]
            stage = "detect" if "detect" in name else "verify"
            col = "b" if stage == "detect" else "g"
            P(f"    {C[col]}●{C['0']} {base:34} {C['d']}{stage:6} {int(age):>3}s{C['0']}")
    else:
        P(f"    {C['d']}(none fresh — between units){C['0']}")

    # ---- per-experiment grid ----
    P("")
    P(f"  {C['B']}per experiment{C['0']} {C['d']}(D=detection ✓/·  then verify configs done/total){C['0']}")
    # build one cell string per run_dir, grouped by benchmark
    def cell(rd):
        det_ok = (DATA/rd/"baseline"/"metadata.json").exists()
        v = vers.get(rd)
        vt = len(v["cfgs"]) if v else 0
        vd = sum(1 for c in v["cfgs"] if (DATA/rd/c/"metadata.json").exists()) if v else 0
        bm = meta(rd, "baseline")
        nf = bm.get("findings_count") if bm else None
        dmark = f"{C['g']}D✓{C['0']}" if det_ok else f"{C['gray']}D·{C['0']}"
        run_hot = any(k.startswith(rd + "_") for k in run)
        dot = f"{C['y']}▸{C['0']}" if run_hot else " "
        short = rd[3:] if rd.startswith("st_") else rd  # drop st_
        nfs = f"{C['d']}f{nf}{C['0']}" if nf is not None else f"{C['gray']}f?{C['0']}"
        return f"{dot}{short:22}{dmark} {minibar(vd,vt,8)}{C['w']}{vd:>2}/{vt:<2}{C['0']} {nfs}"

    all_rd = sorted(set(dets) | set(vers), key=lambda r: (
        BENCHES.index(next((b for b in BENCHES if f"_{b}_" in r), "dvd")), r))
    # column packing
    sample = cell(all_rd[0]) if all_rd else ""
    colw = max(46, cw(sample) + 2)
    ncol = max(1, W // colw)
    cur_bench = None
    rowbuf = []
    for rd in all_rd:
        b = next((x for x in BENCHES if f"_{x}_" in rd), "?")
        if b != cur_bench:
            if rowbuf:
                P("  " + "".join(rowbuf)); rowbuf = []
            cur_bench = b
            P(f"  {C['m']}{C['B']}▼ {b}{C['0']}")
        c = cell(rd)
        rowbuf.append(c + " " * max(0, colw - cw(c)))
        if len(rowbuf) == ncol:
            P("  " + "".join(rowbuf)); rowbuf = []
    if rowbuf:
        P("  " + "".join(rowbuf))

    # ---- round-2 A: naive_verify ----
    r2 = ROOT / "jobs" / "native_verify" / "jobs_round2.csv"
    if r2.exists():
        a_rds = sorted({row["run_dir"] for row in csv.DictReader(open(r2))
                        if row["batch"] == "A_naive_verify"})
        done = sum(1 for rd in a_rds if (DATA/rd/"naive_verify"/"metadata.json").exists())
        nopool = sum(1 for rd in a_rds
                     if not (DATA/rd/"baseline"/"metadata.json").exists())
        P("")
        P(f"  {C['B']}{C['m']}ROUND-2 A · naive_verify{C['0']} "
          f"{C['d']}(RQ4 single-prompt control){C['0']}")
        P("  " + bar(done, len(a_rds), 30, "m")
          + (f"   {C['d']}{nopool} waiting on nemotron re-run pools{C['0']}" if nopool else ""))
        # per detection-model
        for mdl in ("qwen", "gemma", "nemotron"):
            grp = [rd for rd in a_rds if f"st_{mdl}_" in rd]
            gd = sum(1 for rd in grp if (DATA/rd/"naive_verify"/"metadata.json").exists())
            P(f"    {mdl:9} {minibar(gd, len(grp), 14)} {gd:>2}/{len(grp):<2}")
        # running naive units
        nrun = [k for k in run if "naive" in k]
        if nrun:
            P(f"    {C['y']}running:{C['0']} " + ", ".join(sorted(
                k.rsplit('_naive', 1)[0].replace('st_', '') for k in nrun))[:120])
    return "\n".join(out)


def main():
    once = "--once" in sys.argv
    grid = "--grid" in sys.argv
    try:
        while True:
            snap = snapshot(grid)
            if not once:
                os.system("clear")
            print(snap)
            if once:
                break
            print(f"\n{C['d']}refresh {REFRESH}s · Ctrl-C exits (experiment keeps running) · read-only{C['0']}")
            time.sleep(REFRESH)
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
