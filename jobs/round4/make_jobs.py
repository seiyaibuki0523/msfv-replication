#!/usr/bin/env python3
"""Generate jobs/round4/jobs_round4.csv (verification-only, 104 jobs)."""
import csv
BENCHES = ["dvd", "pygoat", "nodegoat", "smartbugs"]
NEMO = "Nemotron-3-Super-120B-A12B"
VM = {"gemma": "gemma-4-31B", "qwen": "qwen3-coder"}
rows = []
# B2: Nemotron verifier replicates on the gemma and qwen pools, seeds 2-3 (seed 1 already has rep2/rep3)
for pool in ("gemma", "qwen"):
    for b in BENCHES:
        for s in (2, 3):
            rd = f"st_{pool}_{b}_s{s}"
            for cfg in ("full_rep2", "full_rep3"):
                rows.append(dict(batch="B2_nemotron_reps", priority=1, stage="verification", run_dir=rd, benchmark=b,
                                 detection_model=VM[pool], verification_model=NEMO, config=cfg, signals="I,S,C,P",
                                 seed=s, source_pool=rd, blocked_by="", optional="no",
                                 why="Table 8 的 Nemotron 列目前只有 seed1 三次 + seed2/3 各一次 (n=5)；補 seed2/3 的 rep2/rep3 後三個 verifier 都是 n=9"))
# C: Nemotron pools verified by gemma and qwen (completes the 3x3 pool x verifier matrix), seeds 1-3, three passes
for ver in ("gemma", "qwen"):
    for b in BENCHES:
        for s in (1, 2, 3):
            rd = f"st_nemotron-v{ver}_{b}_s{s}"
            for cfg in ("full", "full_rep2", "full_rep3"):
                rows.append(dict(batch="C_nemotron_pool_cross", priority=2, stage="verification", run_dir=rd, benchmark=b,
                                 detection_model=NEMO, verification_model=VM[ver], config=cfg, signals="I,S,C,P",
                                 seed=s, source_pool=f"st_nemotron_{b}_s{s}", blocked_by="", optional="no",
                                 why="Nemotron 候選池從未用 gemma/qwen 驗證；補齊後 3 偵測 x 3 驗證 x 4 benchmark 的網格完整，論文可寫 36 個組合"))
with open("jobs_round4.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader(); w.writerows(rows)
print(len(rows), "jobs")
