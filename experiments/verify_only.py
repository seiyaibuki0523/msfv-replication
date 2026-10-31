#!/usr/bin/env python3
"""Re-run ONLY the verify configs from an existing detect checkpoint.

Used when a network blip corrupts the verify stage but the (expensive)
detect checkpoint is intact — re-running detect would waste ~20min and the
forge PoC validation. This reuses the saved detect state and runs the three
verify configs (full / nosource / nopoc) against the identical candidate set.

Usage:  python verify_only.py <benchmark> [detect_state_path]
        (if detect_state_path omitted, uses newest abl_<bm>_detect_*.json)
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Reuse the tested helpers from the main runner.
from run_ablation_fast import (
    base_env, _scope, _write_out, VERIFY_CONFIGS, TARGET_DIRS, WS,
)


def main(bm: str, detect_path: str | None = None) -> int:
    base_env()
    target = TARGET_DIRS[bm]
    from core.analysis.pipeline import CheckpointedPipeline
    from core.analysis.scan_state import ScanState
    from cevanex.adapters.language_router import classify_repo
    from cevanex.adapters.query_packs import select_query_pack

    state_dir = WS / "state"
    if detect_path is None:
        cands = sorted(state_dir.glob(f"abl_{bm}_detect_*.json"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        if not cands:
            print(f"!!! no detect checkpoint for {bm}")
            return 1
        detect_path = str(cands[0])
    print(f"=== VERIFY-ONLY {bm} from {Path(detect_path).name} ===")

    checkpoint = json.loads(Path(detect_path).read_text())
    n_l4 = sum(1 for r in checkpoint.get("opus_results", []) if r.get("layer") == 4)
    if n_l4 == 0:
        print("!!! detect checkpoint has 0 L4 findings — abort")
        return 2
    print(f"  reusing {n_l4} L4 findings (no detect re-run)")

    _, custom_queries = select_query_pack(classify_repo(str(target)))
    file_scope = _scope(target)
    workers = int(os.getenv("AISEC_LAB_CONCURRENCY", "16"))

    for cfg, signals in VERIFY_CONFIGS.items():
        vid = f"abl_{bm}_{cfg}_{int(time.time())}"
        c = json.loads(json.dumps(checkpoint))  # deep copy
        c["target_id"] = vid
        c["current_phase"] = "verify_global"
        for r in c.get("opus_results", []):
            r.pop("verification", None)
            r.pop("severity_override", None)
        (state_dir / f"{vid}.json").write_text(json.dumps(c, ensure_ascii=False))

        os.environ.pop("AISEC_DISABLE_VERIFY", None)
        os.environ["AISEC_VERIFY_SIGNALS"] = signals
        st = ScanState.load(vid)
        vp = CheckpointedPipeline(st, parallel_workers=workers,
                                  custom_queries=custom_queries, file_scope=file_scope)
        print(f"=== VERIFY {bm}/{cfg} [{signals}] @ {time.strftime('%H:%M:%S')} ===")
        t0 = time.time()
        try:
            vres = list(vp.run_whitebox(str(target)) or [])
        except Exception as e:  # noqa: BLE001
            print(f"!!! verify {cfg} raised: {e}")
            f = state_dir / f"{vid}.json"
            vres = json.loads(f.read_text()).get("opus_results", []) if f.exists() else []
        _write_out(bm, cfg, vres, time.time() - t0, signals, state_dir / f"{vid}.json")

    print(f"\n=== {bm} verify-only complete ===")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
