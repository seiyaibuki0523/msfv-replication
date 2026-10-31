# 交給執行 agent 的 Prompt（整份複製貼上）

---

你要幫我執行一批 MSFV 論文改稿用的實驗。附上兩個檔案：

- `jobs.csv` — 677 個 job 的完整清單，每列一個 job
- `spec.json` — 硬規則、manifest 欄位、執行順序

**這批實驗總計約 335 小時（序列），能並行就照我們之前的開，開越多越好，用新版的實驗API。開始前請先完成階段 0 與階段 1，並檢查docker有沒有開啟，這是最重要的不然實驗要重跑任何一項做不到就停下來問我，不要硬跑。**

---

## 階段 0 — 封存舊資料（先做這個）

現有的實驗資料全部移到 `old/`，依日期分資料夾，**不要刪除、不要覆蓋、不要跟新資料混在同一層**：

```
old/
├── 2026-07-20-stability-r1-partial/
├── 2026-07-23-baselines-12/
├── 2026-07-23-baselines-12-withPoC/
├── 2026-07-23-stability-full-24cells/
└── 2026-07-23-verify-stability-purebaseline/
```

在 `old/README.md` 記下這兩件事（之後不要誤用這些資料）：

- `st_gemma_smartbugs_r1` raw=890 vs `r2`=329（2.7 倍差距），疑似截斷，**不可當 replicate**
- `st_nemotron_pygoat_r1` raw=61 vs `r2`=118（1.9 倍差距），同上
- `st_nemotron_smartbugs_r1` detection 耗時 1593 分鐘，是中位數的 4 倍，同樣可疑

舊資料保留作為新結果的交叉檢查，**不併入新的統計**。

---

## 階段 1 — Pre-flight（六項全過才能開跑）

| # | 項目 | 驗收標準 |
|---|---|---|
| P1 | 推論參數 pin 死 | 每個 run 產出 `manifest.json`，欄位見 `spec.json` 的 `manifest_fields_per_run` |
| P2 | seed 的操作定義 | API 支援 seed 參數就顯式傳 1–5；不支援就記錄「變異來自 temperature=T 的取樣非決定性」。二選一，寫進 manifest |
| P3 | **per-signal verdict logging** | `findings.json` 每筆要記錄 `spec.json` 的 `per_finding_logging_required` 全部欄位。**現行 pipeline 沒有這個**，必須先加 |
| P4 | 換掉 `derive_shipped` | 現行版本只能重現 19/132。改成四規則版：`¬(L4 且 Confirmed:no)` ∧ `¬(全部 verdict 為 false_positive)` ∧ `(medium 門檻下需至少一個 confirmed)` ∧ `¬(severity_override == info)`。改完在舊資料上驗證，應達 270/270 |
| P5 | prompt 模板固定 | 各 config 之間**只能差在 `signals` 欄列出的訊號有無**，其他字句完全相同 |
| P6 | 磁碟空間 | SmartBugs 單一 run 的 findings.json 約 880 筆，總計預估數 GB，先確認空間足夠 |

**P3 最關鍵。** 沒有 per-signal verdict，Tier 1 與 Tier 2 那 465 個 job 的訊號貢獻分析會完全做不出來，等於白跑。**驗收方式：先跑一個 NodeGoat 的 job（最快，約 5 分鐘），人工檢查 findings.json 是否含四個訊號的個別判定，確認無誤才往下。**

---

## 階段 2–6 — 執行

依 `spec.json` 的 `execution_order`。只跑 `optional == no` 的 641 個 job，`optional == yes` 的 36 個先不要跑。

### 排程（重要）

**SmartBugs 的 detection 立刻開跑**，它是最長的一根桿子：15 個 run × 6.2 小時 = 93 小時，佔總時間 87%。同時平行跑 DVD / PyGoat / NodeGoat，這三個加起來只有 43 小時，第二天就能全部做完。

**不要把 SmartBugs 排在最前面序列執行，那會卡住所有其他 benchmark。**

### 硬規則（違反任何一條就要重跑）

1. **每個 `run_dir` 只跑一次 detection**（`stage=detection` 那列），然後該 `run_dir` 底下所有 config 都吃同一份候選池
2. **絕對不要為了不同 config 重跑 detection** —— 會破壞 config 之間的配對，等於自廢統計檢定力
3. `jobs.csv` 的 `source_pool` 欄指明每個 verification job 該吃哪個候選池，照它走
4. config 之間只抽換 `signals` 欄列出的訊號，prompt 其他部分完全相同
5. run 目錄名須符合 `^st_(model)_(bench)_(rep)$`，三個欄位內**不得含底線**；config 子目錄名可以有底線
6. SmartBugs 含 PoC 的 config 已從清單移除（實測 1161 emitted / 0 compiled），不要自行補回

### 目錄結構

```
st_qwen_dvd_s1/
├── manifest.json
├── baseline/     {findings.json, metadata.json}
├── full/
├── noidentity/
├── noconcern/
├── nosource/
├── nopoc/
├── keep_IS/ ... only_P/      ← Tier 2，僅 qwen 的 run_dir 有
├── full_rep2/ full_rep3/     ← Tier 4，僅 seed 1 有
└── noconcern_full/           ← Tier 5，僅 qwen 有
```

---

## 監控與失敗處理

- **進度記錄**：維護 `progress.csv`，每個 job 記 `run_dir, config, status(pending/running/done/failed), start, end, elapsed_min`。中斷後要能從這裡續跑
- **異常偵測**：SmartBugs detection 中位數 373 分鐘。**任何 run 超過 750 分鐘（2 倍中位數）就中止並回報**，不要讓它跑到 26 小時
- **失敗不要靜默跳過**：任何 job 失敗，記進 `failures.log`（含完整錯誤訊息），繼續跑其他 job，最後一併回報。不要自動重試超過 2 次
- **不要中途換模型版本或參數**。如果某個模型不可用，停下來問我，不要自行代換

---

## 完成後打包

依 benchmark 分包（SmartBugs 會很大，不要跟其他混在一起）：

```
msfv-2026-08-<日期>-dvd.tar.gz
msfv-2026-08-<日期>-pygoat.tar.gz
msfv-2026-08-<日期>-nodegoat.tar.gz
msfv-2026-08-<日期>-smartbugs.tar.gz
msfv-2026-08-<日期>-meta.tar.gz    ← progress.csv, failures.log, 全部 manifest.json
```

並產出一份 `RUN_REPORT.md`，包含：

- 完成 / 失敗 / 跳過的 job 數，以及跳過的原因
- 每個 benchmark 的 detection 與 verification 實際耗時（中位數、最大值）
- 所有 manifest 的參數是否完全一致（不一致就列出差異）
- 疑似異常的 run（耗時超過 2 倍中位數、findings 數偏離同組其他 seed 超過 50%）

---

## 開跑前請先回報我三件事

1. P1–P6 的檢查結果，特別是 **P3 的 NodeGoat 驗收 job** 是否確認有 per-signal verdict
2. 你打算開幾條並行、預估完成時間
3. 磁碟空間是否足夠

**這三件確認完再開始跑，不要直接開始。**
