#!/usr/bin/env python3
"""Recall / TP-retention harness for the MSFV paper (review #1).

Answers the reviewer's core objection: "a verifier that rejects everything
also gets FP 0% — of the findings you dropped, how many were true positives?"

Computed per ablation config from the run's scan_state.json:
  * TP_detected      — ground-truth vulns caught by the BASELINE (pre-verify)
  * TP_retained      — ground-truth vulns still caught after a verify config
  * recall_retention = TP_retained / TP_detected   (reject-everything → ~0)
  * shipped_total    — findings shipped (the FP side of the trade-off)

A challenge / labeled file counts as "caught" if EITHER:
  * an L4 finding on its contract/file is shipped, OR
  * an L5 global-query finding's prose references its contract.
L5 matters: subtle DeFi logic bugs (oracle, arbitrary-call, flashloan-
governance) are not semgrep-flaggable — they are caught by L5 semantic
queries, NOT L4. An earlier L4-only metric under-counted DVD recall 15→11.

Layout (ablation runner output):
  data/ablation/<bm>/{baseline,full,nosource,nopoc}/scan_state.json

Usage:
  python eval_recall.py dvd        data/ablation/dvd
  python eval_recall.py smartbugs  data/ablation/smartbugs  [sb_repo]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

GT_DIR = Path(__file__).parent / "ground_truth"
LINE_WINDOW = 8  # smartbugs line-match tolerance
CONFIGS = ("baseline", "full", "nosource", "nopoc")


# --------------------------------------------------------------------------- #
# Shipped-finding extraction (mirrors the verdict logic used elsewhere)       #
# --------------------------------------------------------------------------- #

import os as _os


def _is_shipped(r: dict, min_sev: str | None = None) -> bool:
    """Ship policy = precision-recall operating point.

    min_sev (env AISEC_SHIP_MIN_SEVERITY, default "medium"):
      "medium" — aggressive/precision-first: drop L4 confirmed:no, all-FP, and
                 all-downgraded (no confirmed). The downgraded findings (verify
                 saw merit but not at severity) are NOT shipped.
      "low"    — balanced/recall-first: ship downgraded too; drop only L4
                 confirmed:no and all-FP (info). Same verify verdicts, lower
                 reporting threshold.
    """
    if min_sev is None:
        min_sev = _os.getenv("AISEC_SHIP_MIN_SEVERITY", "medium").lower()
    ship_low = min_sev == "low"
    # L4 "Confirmed: no" IS a false positive the analyser rejected — never shipped.
    if r.get("layer") == 4:
        a = (r.get("analysis") or "").strip().split("\n", 1)[0].lower()
        if a.startswith("confirmed: no") and "unclear" not in a:
            return False
    sev_ov = (r.get("severity_override") or "").lower()
    v = r.get("verification")
    if isinstance(v, list) and v:
        verds = [e.get("verdict") for e in v if isinstance(e, dict)]
        if verds and all(d == "false_positive" for d in verds):
            return False
        if not ship_low and verds \
                and all(d in ("false_positive", "downgraded") for d in verds) \
                and not any(d == "confirmed" for d in verds):
            return False
    if sev_ov == "info":   # all-FP collapses to info — dropped under both
        return False
    return True


def _finding_file(r: dict) -> str:
    return (r.get("finding") or {}).get("file") or ""


def _finding_line(r: dict) -> int:
    try:
        return int((r.get("finding") or {}).get("line") or 0)
    except (ValueError, TypeError):
        return 0


def _l5_prose(r: dict) -> str:
    """Flatten an L5 global-query finding to searchable text."""
    return json.dumps(r, default=str)


def _l5_caught_files(findings: list[dict], shipped_only: bool) -> list[str]:
    """Files an L5 global-query finding pins a vulnerability to.

    Precise, not prose-fuzzy: an L5 finding cites multiple functions across
    many contracts, each with its OWN verify verdict. A contract counts as
    caught only when its cited function survives — i.e. verdict != FP (for the
    pre-verify baseline, any citation counts). This stops a single kept L5
    finding from crediting every contract it merely *mentions*."""
    out: list[str] = []
    for r in findings:
        if r.get("layer") != 5:
            continue
        v = r.get("verification")
        if isinstance(v, list) and v:
            for e in v:
                if not isinstance(e, dict):
                    continue
                f = e.get("file") or ""
                if not f:
                    continue
                if shipped_only and e.get("verdict") == "false_positive":
                    continue  # FP citation is not a catch
                out.append(f)
        elif not shipped_only:
            # no verification (e.g. detection baseline) — fall back to prose
            out.append(_l5_prose(r))
    return out


def _load(state_path: Path) -> list[dict]:
    if not state_path.exists():
        return []
    return json.loads(state_path.read_text()).get("opus_results", [])


# --------------------------------------------------------------------------- #
# DVD recall (contract-level: L4 file-match OR L5 prose-match)                #
# --------------------------------------------------------------------------- #

def _dvd_caught(findings: list[dict], gt, shipped_only: bool) -> set[str]:
    caught: set[str] = set()
    # L4: a shipped finding whose file is the vulnerable contract.
    for r in findings:
        if r.get("layer") != 4:
            continue
        if shipped_only and not _is_shipped(r):
            continue
        fp = _finding_file(r)
        if not fp:
            continue
        for c in gt:
            contract = c["contract"]
            if (fp.endswith(contract) or contract.endswith(fp)
                    or Path(fp).name == Path(contract).name):
                caught.add(c["challenge"])
    # L5: a global-query finding whose surviving (non-FP) citation pins the
    # vulnerable contract.
    l5_files = _l5_caught_files(findings, shipped_only)
    blob = " ".join(l5_files)
    for c in gt:
        name = Path(c["contract"]).name           # SideEntranceLenderPool.sol
        if any(name == Path(f).name for f in l5_files if not f.startswith("{")) \
                or (name[:-4] in blob and shipped_only is False):
            caught.add(c["challenge"])
    return caught


def eval_dvd(run_dir: Path) -> dict:
    gt = json.loads((GT_DIR / "dvd.json").read_text())["challenges"]
    base = _load(run_dir / "baseline" / "scan_state.json")
    detected = _dvd_caught(base, gt, shipped_only=False)
    rows = []
    for cfg in CONFIGS:
        st = _load(run_dir / cfg / "scan_state.json")
        if not st:
            continue
        caught = _dvd_caught(st, gt, shipped_only=(cfg != "baseline"))
        rows.append({
            "config": cfg,
            "TP_caught": len(caught),
            "lost_vs_detected": sorted(detected - caught),
            "recall_retention": round(len(caught) / len(detected), 3) if detected else None,
            "shipped_total": sum(1 for r in st if r.get("layer") in (4, 5) and _is_shipped(r)),
        })
    return {"benchmark": "DVD", "n_ground_truth": len(gt),
            "TP_detected_baseline": len(detected), "configs": rows}


# --------------------------------------------------------------------------- #
# SmartBugs recall (line-level: L4 file+line; L5 prose file-name match)       #
# --------------------------------------------------------------------------- #

def _sb_caught(findings, gt, shipped_only) -> set[str]:
    hit: set[str] = set()
    for r in findings:
        if r.get("layer") != 4:
            continue
        if shipped_only and not _is_shipped(r):
            continue
        fn = Path(_finding_file(r)).name
        ln = _finding_line(r)
        if fn in gt and any(abs(gl - ln) <= LINE_WINDOW for gl in gt[fn]):
            hit.add(fn)
    l5_text = " ".join(_l5_prose(r) for r in findings if r.get("layer") == 5
                       and (not shipped_only or _is_shipped(r)))
    for fn in gt:
        if fn in l5_text:
            hit.add(fn)
    return hit


def eval_smartbugs(run_dir: Path, sb_repo: Path) -> dict:
    labels = json.loads((sb_repo / "vulnerabilities.json").read_text())
    gt: dict[str, set[int]] = {}
    for entry in labels:
        name = Path(entry["path"]).name
        lines: set[int] = set()
        for v in entry.get("vulnerabilities", []):
            lines.update(v.get("lines", []) or [])
        gt[name] = lines
    base = _load(run_dir / "baseline" / "scan_state.json")
    detected = _sb_caught(base, gt, shipped_only=False)
    rows = []
    for cfg in CONFIGS:
        st = _load(run_dir / cfg / "scan_state.json")
        if not st:
            continue
        caught = _sb_caught(st, gt, shipped_only=(cfg != "baseline"))
        rows.append({
            "config": cfg,
            "TP_files_caught": len(caught),
            "recall_retention": round(len(caught) / len(detected), 3) if detected else None,
            "shipped_total": sum(1 for r in st if r.get("layer") in (4, 5) and _is_shipped(r)),
        })
    return {"benchmark": "SmartBugs", "n_labeled_files": len(gt),
            "TP_detected_baseline": len(detected), "configs": rows}


# --------------------------------------------------------------------------- #
# Generic file-level recall (pygoat / nodegoat — "vulns" schema)              #
# --------------------------------------------------------------------------- #

def _file_caught(findings, gt_files, shipped_only) -> set[str]:
    """gt_files: dict name->relpath. Caught if a shipped L4 finding is on the
    file, or an L5 finding's prose references its basename."""
    caught: set[str] = set()
    for r in findings:
        if r.get("layer") != 4:
            continue
        if shipped_only and not _is_shipped(r):
            continue
        fp = _finding_file(r)
        if not fp:
            continue
        for name, rel in gt_files.items():
            if fp.endswith(rel) or rel.endswith(fp) or Path(fp).name == Path(rel).name:
                caught.add(name)
    l5_files = _l5_caught_files(findings, shipped_only)
    blob = " ".join(l5_files)
    for name, rel in gt_files.items():
        base = Path(rel).name
        if any(base == Path(f).name for f in l5_files if not f.startswith("{")) \
                or (base in blob):
            caught.add(name)
    return caught


def eval_filelevel(bench: str, run_dir: Path) -> dict:
    gt = json.loads((GT_DIR / f"{bench}.json").read_text())["vulns"]
    gt_files = {v["name"]: v["file"] for v in gt}
    base = _load(run_dir / "baseline" / "scan_state.json")
    detected = _file_caught(base, gt_files, shipped_only=False)
    rows = []
    for cfg in CONFIGS:
        st = _load(run_dir / cfg / "scan_state.json")
        if not st:
            continue
        caught = _file_caught(st, gt_files, shipped_only=(cfg != "baseline"))
        rows.append({
            "config": cfg,
            "TP_caught": len(caught),
            "lost_vs_detected": sorted(detected - caught),
            "recall_retention": round(len(caught) / len(detected), 3) if detected else None,
            "shipped_total": sum(1 for r in st if r.get("layer") in (4, 5) and _is_shipped(r)),
        })
    return {"benchmark": bench, "n_ground_truth": len(gt),
            "TP_detected_baseline": len(detected), "configs": rows}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    bench, run_dir = sys.argv[1], Path(sys.argv[2])
    if bench == "dvd":
        res = eval_dvd(run_dir)
    elif bench in ("pygoat", "nodegoat"):
        res = eval_filelevel(bench, run_dir)
    elif bench == "smartbugs":
        sb = Path(sys.argv[3]) if len(sys.argv) > 3 else \
            Path(os.path.join(os.environ.get("MSFV_SCAN_TARGETS", "/path/to/_scan_targets"), "smartbugs"))
        res = eval_smartbugs(run_dir, sb)
    else:
        print(f"unknown benchmark {bench}")
        sys.exit(2)
    print(json.dumps(res, indent=2))
