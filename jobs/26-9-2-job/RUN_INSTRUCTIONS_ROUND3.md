# MSFV 第三輪實驗 — 執行說明

附檔：`jobs_round3.csv`（77 列，含 `why` 欄）

**這一輪很小：1 個 detection + 76 個 verification，約 $13、一天內完成。**

---

## 為什麼不重跑全部

你擔心高併發造成 nemotron 掉資料。我對現有資料做了三重檢驗，**沒有掉資料的證據**：

| 檢驗 | 結果 |
|---|---|
| 641 個非 baseline run-config 的 verdict 遺失 | **0**（無 verdict 的 L4 finding 數恰等於自我否決數，8/8 cell 差額為 0） |
| L5 無 verdict 是否隨機分布 | **不是**。84 個 run_dir 中 63 個全部有 verdict、21 個全部沒有，**0 個同 run 內不一致** |
| shipped 值可從 `findings.json` 重現 | **725/725** |

第二項是關鍵鑑別。**隨機掉資料會讓同一個 run_dir 的不同 config 表現不一致**，因為每個 config 是獨立的 API 呼叫批次。實測是全有或全無，沒有混合 → 結構性行為（小樣本上 L5 citation 被過濾），不是併發問題。

而且那 21 個 run_dir（NodeGoat 20 + SmartBugs 1）的 L5 findings **照常出貨**（6/6 shipped），沒有影響下游數字。

重跑全部要 3–5 天、約 $90，而且**新資料仍會有 run-to-run 變異**——你無法用「再跑一次」證明第一次沒問題，只能用一致性檢驗，而那個檢驗已經通過。

---

## A 批 — 重跑 `st_nemotron_smartbugs_s5`（5 job）

### 為什麼

該格的 candidates 逐 seed 為 **[917, 931, 926, 918, 755]**。seed 5 的 755 明顯偏離，使該格 CV 達 **8.6%**，而其他 11 格是 0–4%。

這是唯一一個殘留異常。修掉之後 Table 3 的 `Nemotron / SmartBugs` 那列（目前 894 ± 77）會收斂。

### 做法

1. 以**最終設定**重跑 detection：固定 DeepInfra provider、temperature 0、thinking-off、max_tokens 12000、**低併發**
2. 候選池變更後，該 seed 的所有 verification config 必須跟著重跑：`full`、`noidentity`、`noconcern`、`nosource`
3. `nopoc` 不需要（SmartBugs 結構上無 PoC，等同 `full`）
4. `full_rep2` / `full_rep3` 不需要（只在 seed 1）

### 驗收

新的 candidates 數應落在 917–931 區間。**若仍在 750–800，回報並停下來**——那代表 seed 5 的偏離不是併發造成的，而是該 seed 的真實行為，此時應保留原始資料並寫進 Limitations。

---

## B 批 — 自我驗證對照（72 job）

### 問題

Tier 3 的 cross-verifier 實驗**只用 qwen 候選池**，而其中一個 arm 是 **qwen 驗證 qwen 自己的偵測輸出**。這使得「qwen 是較弱的 verifier」與「qwen 同意自己先前的推理」無法分離。

現況矩陣：

| 候選池 | Nemotron verifier | gemma verifier | qwen verifier |
|---|---|---|---|
| **qwen** | ✅ Tier 1 | ✅ Tier 3 | ✅ Tier 3 ◆ |
| **gemma** | ✅ Tier 1 | ❌ 缺 ◆ | ❌ 缺 |

◆ = 自我驗證

補完 gemma 池那兩格，就形成 **2×3 設計**：2 個池 × 3 個 verifier，其中 2 格在對角線（自驗）、4 格在非對角線（交叉）。

### 為什麼不做 3×3

nemotron 池有兩個已知問題：decoding 設定不同（greedy + 固定 provider）、SmartBugs 的 CV 殘留。把它拉進 cross-verifier 實驗會**引入 decoding confound**，反而分不清差異來源。2×3 足夠且乾淨。

### 做法

- 候選池凍結：**現有的 `st_gemma_{bench}_s{1,2,3}`**，不需要新的 detection
- verification 模型：`gemma-4-31B`、`qwen3-coder`
- config：`full`、`full_rep2`、`full_rep3`（同池重跑 3 次）
- 4 benchmark × 3 pool × 3 repeat × 2 verifier = **72**
- Nemotron 那一格不重跑（Tier 1 已有）

### 目錄命名

```
st_gemma-vgemma_dvd_s1/{full, full_rep2, full_rep3}
st_gemma-vqwen_dvd_s1/{full, full_rep2, full_rep3}
```

⚠️ `RUN_RE = ^st_(model)_(bench)_s(\d+)$`，三個欄位內不得含底線。`gemma-vgemma` 用連字號，合法。

### 補完之後能量到三件事

1. **自我驗證偏誤的大小**：對角線（qwen×qwen、gemma×gemma）vs 交叉格
2. **verifier 排名是否穩健**：目前「Nemotron 四個 benchmark 皆最佳」是在 qwen 池上得到的，兩個池都成立才站得住
3. **池 × verifier 交互作用**：最佳 verifier 會不會隨池變動

### 目前的線索

如果自驗偏誤主導，qwen 應該在四個 benchmark 都最保守（出貨最多）。實測是 **2:2** —— DVD 和 SmartBugs 是 qwen 最保守，PyGoat 和 NodeGoat 是 **gemma** 最保守。所以偏誤可能存在但不主導。B 批會給出確切答案。

---

## 沿用的硬規則

1. 每個 `run_dir` 只跑一次 detection；所有 verification config 吃同一份候選池
2. **絕不為了不同 config 重跑 detection**
3. `source_pool` 欄指明該 verification job 吃哪份池
4. prompt 模板固定，config 間只抽換 `signals` 欄列出的訊號
5. 每個 run 輸出 `manifest.json`
6. **nemotron 一律低併發**（A 批），gemma/qwen 可正常併發
7. 失敗記進 `failures.log`，不靜默跳過

---

## 執行順序

| 階段 | 內容 | job | 可否並行 |
|---|---|---|---|
| 1 | A 批 detection（1 個，低併發） | 1 | — |
| 2 | B 批全部（吃現有 gemma 池） | 72 | 與階段 1 並行 |
| 3 | A 批 verification（等階段 1） | 4 | — |

**階段 1 和 2 可同時開始**，B 批不依賴 A 批。

---

## 打包

```
msfv-round3-<日期>-rerun-seed5.tar.gz
msfv-round3-<日期>-selfverify.tar.gz
msfv-round3-<日期>-meta.tar.gz     # progress.csv, failures.log, manifest
```

`RUN_REPORT.md` 需含：

1. **A 批的驗收結果**：新的 candidates 數 vs 舊的 755 vs 其他 seed 的 917–931
2. B 批的完成數與失敗數
3. 所有 manifest 的參數一致性
4. A 批實際使用的併發數

---

## 開跑前回報

1. A 批要用的併發數與 provider（應與 nemotron 重跑時相同）
2. B 批的 gemma 候選池是否完整存在（`st_gemma_{bench}_s{1,2,3}` × 4 benchmark = 12 個 run_dir）
