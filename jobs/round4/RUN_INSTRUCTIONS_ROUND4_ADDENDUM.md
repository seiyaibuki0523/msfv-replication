# 第四輪補件（8 個 run_dir、16 個 config，約 1 小時）

第四輪 104 個 config 已全部驗收（見 RUN_REPORT.md）。把 Nemotron 池加進 Table 8 之後，只剩 Nemotron 池的 **self** 格（Nemotron 驗證 Nemotron 池）是 n=5——`st_nemotron_{bench}_s{2,3}` 沒有 `full_rep2` / `full_rep3`。補這 16 個 config 後全表 36 格都是 n=9。

```bash
cd <MSFV_ROOT>
tail -n +2 jobs/round4/jobs_round4_addendum.csv >> jobs/round4/jobs_round4.csv   # 追加 16 列（B2 批：Nemotron 驗證器、DeepInfra 固定、併發 4）
python3 experiments/round4_run.py --dry-run   # 應只列出這 16 個待跑
nohup python3 experiments/round4_run.py > jobs/round4/run_addendum.log 2>&1 &
```

runner 可重入：已有 `metadata.json` 的 config 全部跳過，所以直接重跑同一個指令即可。跑完打包 `st_nemotron_{dvd,pygoat,nodegoat,smartbugs}_s{2,3}` 這 8 個 run_dir（含新的 rep）成 `msfv-round4b-<日期>-nemotron-self-reps.tar.gz` 給我；`write_manifests.py` 不用再跑（這 8 個 run_dir 已有 manifest）。
