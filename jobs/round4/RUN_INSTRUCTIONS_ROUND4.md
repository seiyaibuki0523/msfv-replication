# MSFV 第四輪實驗 — 執行說明（給 the run host 上的 Claude）

附檔：`jobs/round4/jobs_round4.csv`（104 列）、`experiments/round4_run.py`、`experiments/write_manifests.py`

**這一輪只跑驗證層，沒有新的 detection。104 個 verification job + 補 68 個 manifest，估計 3–5 小時、十幾美元。**

---

## 目的（對應 access10.tex 的兩個缺口）

| 批 | 內容 | 數量 | 修什麼 |
|---|---|---|---|
| **B2** | Nemotron 驗證器在 `st_gemma_{bench}_s{2,3}`、`st_qwen_{bench}_s{2,3}` 上補 `full_rep2`、`full_rep3` | 16 run_dir × 2 = 32 | Table 8 的 Nemotron 列現在是「seed1 三次 + seed2/3 各一次」(n=5)，補完後三個 verifier 都是 3 池 × 3 次 (n=9)，caption 不必再解釋不平衡設計；Table 2(a) 的 SD_verif 也可用 3 個 seed 估 |
| **C** | gemma、qwen 驗證器驗 Nemotron 候選池：`st_nemotron-vgemma_{bench}_s{1,2,3}`、`st_nemotron-vqwen_{bench}_s{1,2,3}`，配置 `full`、`full_rep2`、`full_rep3` | 24 run_dir × 3 = 72 | Nemotron 池從未被 gemma/qwen 驗證；補完後 3 偵測 × 3 驗證 × 4 benchmark 網格完整，論文可以把「28 combinations」改回「36」 |
| **M** | 為沒有 `manifest.json` 的 68 個 run_dir 補 manifest（含每臂實際設定與 OpenRouter 模型識別碼） | 68 | R1-4 要 exact model versions / temperature；資料包目前只有 qwen/gemma 主實驗的 40 個 manifest |

## 前置檢查（開跑前回報）

1. `data/ablation` 裡以下候選池都在（各要有 `baseline/metadata.json`）：
   - `st_gemma_{dvd,pygoat,nodegoat,smartbugs}_s{2,3}`、`st_qwen_..._s{2,3}`（B2）
   - `st_nemotron_{dvd,pygoat,nodegoat,smartbugs}_s{1,2,3}`（C；注意 `st_nemotron_smartbugs_s5` 是 round-3 重跑過的，這裡不用）
   - `python experiments/round4_run.py --dry-run` 會列出缺的池。
2. `OPENROUTER_API_KEY` 在環境裡；`AISEC_OPENROUTER_PROVIDER` **不要**預先設在環境裡（runner 會對 Nemotron 批自己設 DeepInfra、對 gemma/qwen 批清掉）。
3. `.env` 裡沒有殘留 `AISEC_NEMOTRON_THINKING` / `AISEC_LLM_TEMPERATURE` / `AISEC_LLM_MAX_TOKENS`（runner 也會清，但請確認）。

## 執行

```bash
cd <MSFV_ROOT>
python3 experiments/round4_run.py --dry-run
nohup python3 experiments/round4_run.py > jobs/round4/run.log 2>&1 &
tail -f jobs/round4/run.log          # 進度也會寫到 jobs/round4/progress.csv，失敗寫到 failures.log
```

- B2 與 C 並行；B2 內同時最多 2 個 run_dir、每個 run_dir 併發 4（Nemotron 低併發 + DeepInfra 固定，與 round-3 的 Nemotron 驗證相同）；C 內同時最多 6 個 run_dir、併發 8、不固定 provider（與 round-3 B 批相同）。可用環境變數調：`R4_NEMO_CONC`、`R4_CONC`、`R4_PAR_B2`、`R4_PAR_C`。
- 可重入：已有 `metadata.json` 的 config 會跳過，中斷後直接重跑同一指令即可。
- 硬規則不變：**絕不重跑 detection**；C 批的 baseline 是從 `st_nemotron_{bench}_s{seed}/baseline` 複製過來的，跑完請確認兩者 `findings_count` 相同。

跑完後：

```bash
python3 experiments/write_manifests.py        # 只補缺的；--force 會全部重寫（不建議）
```

## 驗收

1. `progress.csv` 中 104 個 config 全部 `done`，`failures.log` 為空或已重跑成功。
2. 每個新 config 的 `metadata.json` 存在，且 `shipped` 能用四條 ship 規則從 `findings.json` 重現（`revision-2026-09-10/analysis/load.py` 會檢查，印出 `SHIP MISMATCH` 即為異常）。
3. C 批：`st_nemotron-v*_{bench}_s{seed}/baseline/metadata.json` 的 `findings_count` 與 `st_nemotron_{bench}_s{seed}/baseline` 相同。
4. B2 批合理性：新 rep 的 shipped 數應落在該 run_dir `full` 的 ±(3 × Table 2(a) 該格 SD_verif) 內；若某格明顯離群（例如 Nemotron/PyGoat 池 shipped 差 20 以上），不要刪，回報即可。
5. `ls data/ablation/st_*/manifest.json | wc -l` 應等於 run_dir 總數（原 108 + 新 24 = 132）。

## 打包

```
msfv-round4-<日期>-nemotron-reps.tar.gz      # B2 的 16 個 run_dir（含新 rep 與既有 baseline/full）
msfv-round4-<日期>-nemotron-pool-cross.tar.gz # C 的 24 個 run_dir
msfv-round4-<日期>-manifests.tar.gz          # data/ablation/st_*/manifest.json 全部 132 個
msfv-round4-<日期>-meta.tar.gz               # jobs/round4/{jobs_round4.csv,progress.csv,failures.log,run.log,RUN_REPORT.md}
```

`RUN_REPORT.md` 請含：完成數 / 失敗數、每批實際併發與 provider、B2 各格新 rep 的 shipped 數與既有值、C 批 baseline findings_count 核對結果、manifest 補寫數。

## 不要做的事

- 不要重跑任何 detection，不要動既有的 `full` / `full_rep*` / LOO / power-set 目錄。
- 不要把 `AISEC_OPENROUTER_PROVIDER=DeepInfra` 套到 gemma/qwen 驗證器（round-1/3 的 gemma/qwen 都沒固定 provider，固定了會和既有格子不同條件）。
- Nemotron 驗證保持 reasoning on、temperature 0.2、預設 max_tokens（不要沿用 detection 的 thinking-off / temp 0 / 12000）。

## 順便確認一件事（寫進 RUN_REPORT.md）

`data/ablation/old/README.md` 說最終的 Nemotron detection 是「max_tokens 40000 + pin **DigitalOcean** + thinking-off」，但 `jobs/FINAL_RUN_REPORT.md`、`jobs/26-9-2-job/RUN_REPORT.md` 與 `experiments/round3_run.py` 都是「12000 + pin **DeepInfra**」。請從 `jobs/v2/logs/` 或 nemotron 重跑的 log（`AISEC_OPENROUTER_PROVIDER`、`AISEC_LLM_MAX_TOKENS` 的實際值）確認 `st_nemotron_*_s{1..4}` 到底是哪一組設定；論文 Table 2(b) 目前寫 DeepInfra / 12000，若不對要改。
