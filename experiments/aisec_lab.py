#!/usr/bin/env python3
"""
AISEC LAB — experiment console for the MSFV paper.

A terminal dashboard (Claude-CLI aesthetic) to launch ablation runs, watch
live progress, and read out recall / FP-reduction tables — without hand-
poking JSON state files.

Usage:
    python aisec_lab.py                 # live status dashboard (default)
    python aisec_lab.py status          # same — live, refreshes every 3s
    python aisec_lab.py run <benchmark> # launch a 4-config ablation
    python aisec_lab.py recall <benchmark>
    python aisec_lab.py kill            # stop all running scans (asks first)

Benchmarks: dvd · pygoat · nodegoat · smartbugs
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ── paths ──────────────────────────────────────────────────────────────────
ROOT = Path(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent))
ABL = ROOT / "data" / "ablation"
RUNS = ROOT / "data" / "runs"
EXP = ROOT / "experiments"
FROZEN = ROOT / "frozen-code"
STATE_DIR = Path("<AISEC_WORKSPACE>/state")
VLLM_URL = "http://<nemotron-host>:8000/v1"

BENCHMARKS = ["dvd", "pygoat", "nodegoat", "smartbugs_sampled", "smartbugs"]
CONFIGS = ["baseline", "full", "nosource", "nopoc"]
PHASES = ["init", "global_map", "semgrep", "local_filter", "opus_analysis",
          "fuzz", "global_queries", "verify_global", "done"]

# Cumulative progress fraction at the END of each phase. L3 (local_filter) is
# the heavy chunk (e.g. DVD ~1040 findings); L4 next. Tuned from observed runs.
PHASE_CUM = {
    "init": 0.02, "global_map": 0.05, "semgrep": 0.10,
    "local_filter": 0.50, "opus_analysis": 0.80, "fuzz": 0.83,
    "global_queries": 0.90, "verify_global": 0.99, "done": 1.0,
}
PHASE_START = {  # cumulative fraction at the START of each phase
    p: ([0.0] + [PHASE_CUM[x] for x in PHASES])[i]
    for i, p in enumerate(PHASES)
}

# ── palette (Claude-CLI-ish) ─────────────────────────────────────────────────
C_ACCENT = "bright_cyan"
C_OK = "bright_green"
C_RUN = "bright_cyan"
C_WAIT = "grey42"
C_WARN = "yellow"
C_ERR = "bright_red"
C_DIM = "grey50"

console = Console()


# ── data ─────────────────────────────────────────────────────────────────────
def _short_commit() -> str:
    try:
        return subprocess.run(
            ["git", "-C", str(FROZEN), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=3
        ).stdout.strip() or "?"
    except Exception:
        return "?"


def _vllm_health() -> tuple[bool, str]:
    try:
        import urllib.request
        t0 = time.monotonic()
        with urllib.request.urlopen(f"{VLLM_URL}/models", timeout=4) as r:
            data = json.loads(r.read())
        dt = (time.monotonic() - t0) * 1000
        mid = (data.get("data") or [{}])[0].get("id", "?").split("/")[-1]
        return True, f"{mid}  ({dt:.0f}ms)"
    except Exception as e:
        return False, f"unreachable ({type(e).__name__})"


def _ship_count(opus: list) -> int:
    n = 0
    for r in opus:
        sev = (r.get("severity_override") or "").lower()
        v = r.get("verification")
        drop = False
        if isinstance(v, list) and v:
            vv = [e.get("verdict") for e in v if isinstance(e, dict)]
            if vv and all(d == "false_positive" for d in vv):
                drop = True
            elif vv and all(d in ("false_positive", "downgraded") for d in vv) \
                    and not any(d == "confirmed" for d in vv):
                drop = True
        if not (drop or sev == "info"):
            n += 1
    return n


def _live_state(bm: str, cfg: str) -> dict | None:
    """Most recent live state file for a (bm,cfg) still running."""
    patterns = [f"abl_{bm}_{cfg}_*.json"]
    # fast runner: detection runs under abl_<bm>_detect_* and IS the baseline
    # work, so surface it in the baseline cell while detection is in flight.
    if cfg == "baseline":
        patterns.append(f"abl_{bm}_detect_*.json")
    hits = []
    for pat in patterns:
        hits.extend(STATE_DIR.glob(pat))
    hits.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    if not hits:
        return None
    try:
        s = json.loads(hits[0].read_text())
        # start time = the unix stamp baked into the state_id suffix
        stem = hits[0].stem  # abl_dvd_baseline_1781056208
        start = None
        try:
            start = int(stem.rsplit("_", 1)[1])
        except Exception:
            start = int(hits[0].stat().st_ctime)
        return {
            "phase": s.get("current_phase"),
            "l4": s.get("layer4_call_count", 0),
            "l5": s.get("layer5_call_count", 0),
            "l55": s.get("layer55_call_count", 0),
            "opus": len(s.get("opus_results", [])),
            "pending": len(s.get("pending_findings", [])),
            "semgrep": len(s.get("semgrep_results", [])),
            "filtered": len(s.get("filtered_findings", [])),
            "mtime": hits[0].stat().st_mtime,
            "start": start,
        }
    except Exception:
        return None


_PHASE_TOKENS = ("detect", "baseline", "full", "nosource", "nopoc")


def _inflight_labels(max_age: float = 5400.0) -> set[str]:
    """Ablation cell labels with a *live* scan-state file — so a cell shows on
    the dashboard while it is still DETECTING (before any data/ dir is written).

    Parses ``abl_<label>_<phase>_<ts>.json`` in STATE_DIR back to ``<label>``
    (label may itself contain ``_``, e.g. ``st_qwen_dvd_r1``). Only files
    touched within ``max_age`` seconds count, so weeks-old June state files are
    not resurrected as ghost rows."""
    now = time.time()
    labels: set[str] = set()
    for p in STATE_DIR.glob("abl_*.json"):
        try:
            if now - p.stat().st_mtime > max_age:
                continue
        except OSError:
            continue
        parts = p.stem.split("_")[1:]          # drop leading 'abl'
        if parts and parts[-1].isdigit():
            parts = parts[:-1]                  # drop timestamp
        if parts and parts[-1] in _PHASE_TOKENS:
            parts = parts[:-1]                  # drop phase token
        if parts:
            labels.add("_".join(parts))
    return labels


TRIAGE_LOG = Path("<AISEC_WORKSPACE>/logs/triage.jsonl")


def _l3_done_since(start: float) -> int:
    """Count layer3_filter calls logged at/after ``start`` (this config's L3
    progress). Reads the triage log from the tail, stopping once entries
    predate the config — cheap even on a 25k-line log."""
    if not TRIAGE_LOG.exists():
        return 0
    n = 0
    try:
        lines = TRIAGE_LOG.read_bytes().splitlines()
    except Exception:
        return 0
    for raw in reversed(lines):
        if b"layer3_filter" not in raw:
            continue
        try:
            d = json.loads(raw)
        except Exception:
            continue
        ts = d.get("ts", 0)
        if ts < start - 5:
            break  # older than this config — stop scanning
        if d.get("tag") == "layer3_filter":
            n += 1
    return n


def _progress(live: dict) -> tuple[float, float | None]:
    """Estimate (fraction 0-1, eta_seconds|None) for a running config."""
    phase = live.get("phase") or "init"
    base = PHASE_START.get(phase, 0.0)
    end = PHASE_CUM.get(phase, base)
    sub = 0.0  # sub-phase fraction within the current phase

    if phase == "opus_analysis":
        done = live["l4"]
        total = live["l4"] + live["pending"]
        sub = (done / total) if total else 0.0
    elif phase == "verify_global":
        # rough: L5.5 calls vs (L4-confirmed + L5) — unknown total, cap at .8
        sub = min(0.8, live["l55"] / max(1, live["l4"] + live["l5"]))
    elif phase == "local_filter":
        # state doesn't checkpoint mid-L3 (filtered populates only at phase
        # end), so measure real progress from the triage log: L3 calls done
        # since this config started / total semgrep findings.
        total = live.get("semgrep", 0)
        if total and live.get("start"):
            sub = min(0.99, _l3_done_since(live["start"]) / total)
        else:
            sub = 0.0
    elif phase == "done":
        return 1.0, 0.0

    # Phases with no per-item signal (fuzz / global_queries / verify_global)
    # would otherwise freeze the bar at PHASE_START for their whole duration.
    # Give them a gentle elapsed-based creep using the mtime gap so the bar
    # always advances toward (not past) the phase end.
    if phase in ("fuzz", "global_queries", "verify_global") and sub == 0.0:
        gap = time.time() - live.get("mtime", time.time())
        sub = min(0.9, gap / 120.0)  # ~2 min to nearly fill the phase band

    frac = base + (end - base) * sub
    frac = max(0.0, min(0.999, frac))

    eta = None
    if live.get("start") and frac > 0.04:
        elapsed = time.time() - live["start"]
        if elapsed > 5:
            eta = elapsed * (1 - frac) / frac
    return frac, eta


def _bar(frac: float, width: int = 14) -> str:
    filled = int(round(frac * width))
    return "█" * filled + "░" * (width - filled)


def _fmt_eta(sec: float | None) -> str:
    if sec is None:
        return "—"
    if sec < 90:
        return f"{int(sec)}s"
    if sec < 5400:
        return f"{int(sec/60)}m"
    return f"{sec/3600:.1f}h"


def _final(bm: str, cfg: str) -> dict | None:
    m = ABL / bm / cfg / "metadata.json"
    if not m.exists():
        return None
    try:
        meta = json.loads(m.read_text())
        ss = ABL / bm / cfg / "scan_state.json"
        ship = None
        if ss.exists():
            ship = _ship_count(json.loads(ss.read_text()).get("opus_results", []))
        meta["_ship"] = ship
        return meta
    except Exception:
        return None


def _running_pids() -> list[str]:
    try:
        out = subprocess.run(["pgrep", "-fl", "run_ablation"],
                             capture_output=True, text=True, timeout=3).stdout
        return [l for l in out.splitlines() if "run_ablation" in l]
    except Exception:
        return []


def _running_labels() -> set[str]:
    """Cell labels of live run_ablation_fast processes, read from their
    AISEC_ABL_LABEL env. Needed because per-cell runs are launched with the
    repo PATH (stab_repos/<arm>__<bm>) as argv — the label only lives in the
    environment, so a command-line substring match misses them (and a cell in
    the pre-verify PoC-fold phase has no live state file yet)."""
    labels: set[str] = set()
    try:
        pids = subprocess.run(["pgrep", "-f", "run_ablation_fast"],
                              capture_output=True, text=True, timeout=3).stdout.split()
    except Exception:
        return labels
    for pid in pids:
        try:
            env = subprocess.run(["ps", "eww", "-p", pid],
                                 capture_output=True, text=True, timeout=3).stdout
        except Exception:
            continue
        for tok in env.split():
            if tok.startswith("AISEC_ABL_LABEL="):
                labels.add(tok.split("=", 1)[1])
                break
    return labels


# ── rendering ────────────────────────────────────────────────────────────────
def _status_cell(bm: str, cfg: str, running: bool) -> tuple[str, str, str]:
    """Return (glyph, phase_text, detail) for a config cell."""
    fin = _final(bm, cfg)
    live = _live_state(bm, cfg)
    now = time.time()

    # Re-run detection: if a live verify state file is NEWER than the finished
    # metadata, a fresh verify is overwriting this config → show it as running,
    # not the stale 'done' from the previous pass.
    if fin is not None and live is not None:
        try:
            mt = (ABL / bm / cfg / "metadata.json").stat().st_mtime
            if live["mtime"] > mt + 5:
                fin = None
        except OSError:
            pass

    if fin and fin.get("error") is None:
        ship = fin.get("_ship")
        ship_s = f"ship {ship}" if ship is not None else ""
        poc = ""
        if fin.get("poc_emit"):
            poc = f" · PoC {fin.get('poc_compile',0)}/{fin.get('poc_emit')}✓ {fin.get('poc_triggered',0)}⚡"
        return (f"[{C_OK}]✓[/]",
                f"[{C_OK}]done[/]",
                f"[{C_DIM}]{fin.get('findings_count','?')} found · {ship_s}{poc} · {fin.get('elapsed_human','')}[/]")
    if fin and fin.get("error"):
        return (f"[{C_ERR}]✗[/]", f"[{C_ERR}]error[/]",
                f"[{C_DIM}]{str(fin.get('error'))[:48]}[/]")

    if live:
        stale = now - live["mtime"]
        phase = live["phase"] or "?"
        frac, eta = _progress(live)
        bar = _bar(frac)
        det = f"[{C_ACCENT}]{bar}[/] {frac*100:.0f}%  [{C_DIM}]ETA {_fmt_eta(eta)}[/]"
        sub = f"[{C_DIM}]L4 {live['l4']} · L5 {live['l5']} · L5.5 {live['l55']}[/]"
        # local_filter / global_queries don't checkpoint mid-phase, so a
        # long gap there is normal (L3 can run ~60 min). Only the per-finding
        # phases (opus_analysis / verify_global save after each) should ever
        # look stalled on a short threshold.
        stall_limit = 1800 if phase in ("local_filter", "global_queries") else 600
        if stale > stall_limit:
            return (f"[{C_WARN}]⚠[/]", f"[{C_WARN}]{phase}[/]",
                    f"[{C_WARN}]stalled {int(stale/60)}m[/]\n{det}")
        glyph = f"[{C_RUN}]●[/]" if running else f"[{C_DIM}]◌[/]"
        return (glyph, f"[{C_RUN}]{phase}[/]", f"{det}\n{sub}")

    return (f"[{C_WAIT}]○[/]", f"[{C_WAIT}]pending[/]", "")


def build_dashboard() -> Group:
    ok, vmsg = _vllm_health()
    commit = _short_commit()
    pids = _running_pids()

    # header
    vstyle = C_OK if ok else C_ERR
    vglyph = "●" if ok else "✗"
    header = Text()
    header.append("  AISEC LAB ", style=f"bold {C_ACCENT}")
    header.append("· MSFV signal-ablation console\n", style=C_DIM)
    header.append("  frozen-code ", style=C_DIM)
    header.append(commit, style=C_ACCENT)
    header.append("    vLLM ", style=C_DIM)
    header.append(f"{vglyph} {vmsg}", style=vstyle)
    header.append("    scans ", style=C_DIM)
    header.append(f"{len(pids)} running", style=C_RUN if pids else C_DIM)

    # Auto-discover every ablation cell on disk (canonical benchmarks first,
    # then stability cells like ``st_<arm>_<bm>_r<N>`` the driver creates).
    on_disk = {p.name for p in ABL.iterdir() if p.is_dir()} if ABL.exists() else set()
    present = (on_disk | _inflight_labels()) - {"old"}
    order = [b for b in BENCHMARKS if b in present] + \
            sorted(b for b in present if b not in BENCHMARKS)
    running_labels = _running_labels()   # cells with a live process (env label)

    # Compact per-cell block (24+ cells don't fit as one tall table → pack into
    # a multi-column grid). SAME info as the old wide table — name + progress
    # bar + ETA header, then every config's full status (glyph/phase + findings/
    # ship/PoC/elapsed via _status_cell) — just stacked vertically per block so
    # 3 fit side by side.
    _ABBR = {"baseline": "b", "full": "f", "nosource": "ns", "nopoc": "np"}

    def _cell_block(bm: str):
        running_now = bm in running_labels   # live process for this exact cell
        expect_v = 1 if "smartbugs" in bm else 3   # smartbugs = full-only verify
        base_done = _final(bm, "baseline") is not None
        vdone = min(sum(1 for c in ("full", "nosource", "nopoc") if _final(bm, c)),
                    expect_v)
        # progress + ETA (same weighting as before: detection = 90%)
        if not base_done:
            lv = _live_state(bm, "baseline")
            f, eta = _progress(lv) if lv else (0.0, None)
            frac = f * 0.90
        else:
            frac = 0.90 + (vdone / expect_v) * 0.10
            rem = expect_v - vdone
            eta = rem * 90 if rem else 0
        disp = bm[3:] if bm.startswith("st_") else bm
        badge = f"[{C_RUN}]● re-run[/] " if running_now else ""
        lines = [f"{badge}[bold white]{disp[:26]}[/]  "
                 f"[{C_ACCENT}]{_bar(frac, 8)} {frac*100:.0f}%[/]"
                 + (f" [{C_DIM}]ETA {_fmt_eta(eta)}[/]" if eta else "")]
        # Compact one-line-per-config (many cells → keep it short): glyph +
        # ship + PoC-trigger only. Running config shows phase %.
        for cfg in CONFIGS:
            if "smartbugs" in bm and cfg in ("nosource", "nopoc") \
                    and not _final(bm, cfg):
                continue
            running = running_now and _live_state(bm, cfg) is not None
            fin = _final(bm, cfg)
            live = _live_state(bm, cfg)
            # re-run: live newer than metadata → treat as running
            if fin and live:
                try:
                    if live["mtime"] > (ABL / bm / cfg / "metadata.json").stat().st_mtime + 5:
                        fin = None
                except OSError:
                    pass
            ab = f"[{C_DIM}]{_ABBR[cfg]:>2}[/]"
            if fin and fin.get("error") is None:
                ship = fin.get("_ship")
                poc = f" [{C_DIM}]⚡{fin.get('poc_triggered',0)}[/]" if fin.get("poc_emit") else ""
                lines.append(f"{ab} [{C_OK}]✓[/] s{ship}{poc}")
            elif fin and fin.get("error"):
                lines.append(f"{ab} [{C_ERR}]✗err[/]")
            elif live:
                fr, _e = _progress(live)
                lines.append(f"{ab} [{C_RUN}]●{fr*100:.0f}%[/]")
            else:
                lines.append(f"{ab} [{C_WAIT}]○[/]")
        blk = Text.from_markup("\n".join(lines))
        done = base_done and vdone >= expect_v and not running_now
        border = C_RUN if running_now else (C_OK if done
                                            else (C_WARN if base_done else C_DIM))
        return Panel(blk, box=box.ROUNDED, border_style=border, padding=(0, 1))

    # Too many cells to show at once (baselines + v1/v2 verify passes = 30+).
    # Focus on the ACTIVE set: cells running now OR updated recently. Older
    # done cells are hidden to keep it on-screen. Override with AISEC_LAB_ALL=1.
    def _recent(bm: str, secs: float = 1200.0) -> bool:
        for c in CONFIGS:
            m = ABL / bm / c / "metadata.json"
            try:
                if m.exists() and (time.time() - m.stat().st_mtime) < secs:
                    return True
            except OSError:
                pass
        return False

    show_all = os.getenv("AISEC_LAB_ALL") == "1"
    visible = [bm for bm in order
               if any((_final(bm, c) or _live_state(bm, c)) for c in CONFIGS)
               and (show_all or bm in running_labels or _recent(bm, 300))]
    hidden = sum(1 for bm in order
                 if any(_final(bm, c) for c in CONFIGS)) - len(visible)
    blocks = [_cell_block(bm) for bm in visible]

    NCOL = 4   # cells per row
    if blocks:
        grid = Table.grid(expand=True, padding=(0, 1))
        for _ in range(NCOL):
            grid.add_column(ratio=1)
        for i in range(0, len(blocks), NCOL):
            chunk = list(blocks[i:i + NCOL])
            while len(chunk) < NCOL:
                chunk.append(Text(""))
            grid.add_row(*chunk)
        body = grid
    else:
        body = Align.center(
            Text("no experiments yet — `python aisec_lab.py run dvd` to start",
                 style=C_DIM), vertical="middle")

    footer = Text()
    footer.append(f"  updated {time.strftime('%H:%M:%S')}", style=C_DIM)
    footer.append("   ●running ✓done ○pending ⚠stalled ✗error", style=C_DIM)
    if hidden > 0 and not show_all:
        footer.append(f"   ({hidden} done hidden · AISEC_LAB_ALL=1 to show)",
                      style=C_DIM)

    return Group(
        Panel(header, box=box.ROUNDED, border_style=C_ACCENT, padding=(0, 1)),
        body,
        footer,
    )


def cmd_status(once: bool = False) -> None:
    # One-shot static render: works in any terminal (VSCode integrated term,
    # pipes, non-TTY) where rich Live refuses to draw. `status once`.
    if once or not console.is_terminal:
        Console(force_terminal=True).print(build_dashboard())
        return
    try:
        with Live(build_dashboard(), console=console, refresh_per_second=2,
                  screen=False) as live:
            while True:
                time.sleep(3)
                live.update(build_dashboard())
    except KeyboardInterrupt:
        console.print(f"\n[{C_DIM}]bye[/]")


def cmd_run(bm: str) -> None:
    if bm not in BENCHMARKS:
        console.print(f"[{C_ERR}]unknown benchmark {bm}[/] — pick from {BENCHMARKS}")
        return
    console.print(Panel(
        f"Launching 4-config ablation for [{C_ACCENT}]{bm}[/]\n"
        f"[{C_DIM}]baseline → full → nosource → nopoc  (shared detection cache)[/]",
        box=box.ROUNDED, border_style=C_ACCENT))
    # single-benchmark wrapper
    script = f"""#!/usr/bin/env bash
set -uo pipefail
cd {EXP}
source <AISEC_VENV>/bin/activate
export AISEC_LAB_CONCURRENCY=16   # tuned: clean server handles 16
export AISEC_LLM_TIMEOUT=240      # data-driven: L3 p99=268s, 240 catches 99%
WS=<AISEC_WORKSPACE>
rm -f "$WS"/cache/findings/*.json 2>/dev/null || true
rm -f "$WS"/state/abl_{bm}_*.json 2>/dev/null || true
for cfg in baseline full nosource nopoc; do
  python run_ablation.py {bm} "$cfg" 2>&1 | tee -a {ABL}/{bm}/${{cfg}}_stdout.log
done
"""
    sh = Path(f"/tmp/aisec_run_{bm}.sh")
    sh.write_text(script)
    (ABL / bm).mkdir(parents=True, exist_ok=True)
    subprocess.Popen(["caffeinate", "-dis", "bash", str(sh)],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    console.print(f"[{C_OK}]launched[/] under caffeinate -dis. "
                  f"run [{C_ACCENT}]python aisec_lab.py status[/] to watch.")


def cmd_recall(bm: str) -> None:
    rd = RUNS / f"{bm}_ablation_run_1"
    # eval_recall expects the legacy layout; fall back to ablation dir
    target = rd if rd.exists() else (RUNS / f"{bm}_run_1")
    try:
        out = subprocess.run(
            [sys.executable, str(EXP / "eval_recall.py"), bm, str(target)],
            capture_output=True, text=True, timeout=30)
        data = json.loads(out.stdout) if out.stdout.strip().startswith("{") else None
    except Exception as e:
        console.print(f"[{C_ERR}]recall eval failed: {e}[/]")
        return
    if not data:
        console.print(f"[{C_DIM}]{out.stdout or out.stderr}[/]")
        return
    t = Table(box=box.ROUNDED, border_style=C_DIM,
              title=f"recall / TP-retention — {data.get('benchmark')}")
    t.add_column("run"); t.add_column("TP detected", justify="right")
    t.add_column("TP retained", justify="right")
    t.add_column("retention", justify="right")
    t.add_column("shipped", justify="right")
    for r in data.get("runs", []):
        ret = r.get("recall_retention")
        rs = f"{ret:.0%}" if isinstance(ret, (int, float)) else "—"
        style = C_OK if (isinstance(ret, (int, float)) and ret >= 0.95) else C_WARN
        t.add_row(str(r.get("run")),
                  str(r.get("TP_detected", r.get("TP_files_detected", "—"))),
                  str(r.get("TP_retained", r.get("TP_files_retained", "—"))),
                  f"[{style}]{rs}[/]",
                  str(r.get("shipped_total", "—")))
    console.print(t)


def cmd_kill() -> None:
    pids = _running_pids()
    if not pids:
        console.print(f"[{C_DIM}]nothing running[/]")
        return
    console.print(f"[{C_WARN}]running:[/]")
    for p in pids:
        console.print(f"  [{C_DIM}]{p}[/]")
    if console.input(f"[{C_WARN}]kill all? [y/N] [/]").strip().lower() == "y":
        subprocess.run(["pkill", "-f", "run_ablation"], check=False)
        subprocess.run(["pkill", "-f", "aisec_run_"], check=False)
        console.print(f"[{C_OK}]killed[/]")
    else:
        console.print(f"[{C_DIM}]left running[/]")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "status":
        cmd_status(once=("once" in sys.argv[2:]))
    elif cmd == "run" and len(sys.argv) > 2:
        cmd_run(sys.argv[2])
    elif cmd == "recall" and len(sys.argv) > 2:
        cmd_recall(sys.argv[2])
    elif cmd == "kill":
        cmd_kill()
    else:
        print(__doc__)
