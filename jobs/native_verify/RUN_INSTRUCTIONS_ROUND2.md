# MSFV 第二輪實驗 — 執行說明

附檔：`jobs_round2.csv`（96 列，含 `why` 欄說明每項理由）

---

## 目前狀態

| 批次 | 狀態 |
|---|---|
| 第一輪 641 job | ✅ 完成（2026-08-21） |
| nemotron 重跑（20 detection + 103 verify） | 🔄 進行中，6-parallel detached |
| **本文件的 A / C** | ⬜ 待跑 |
| max_tokens 控制檢查 | ❌ 已取消 —— gemma/qwen 五 seed CV 0.0–0.6%，與截斷不相容 |

`jobs_round2.csv` 的欄位：`batch, priority, stage, run_dir, benchmark, detection_model, verification_model, config, signals, seed, source_pool, blocked_by, optional, why`

- `optional=no` → 必跑（60 列）
- `blocked_by` 非空 → 等 nemotron 重跑完成後才能跑（20 列）
- **現在就能跑：40 列**（A 批的 qwen/gemma）

---

## 沿用第一輪的硬規則（不變）

1. 每個 `run_dir` 只跑一次 detection；所有 verification config 吃同一份候選池
2. **絕不為了不同 config 重跑 detection** —— 會破壞 config 間的配對
3. `source_pool` 欄指明該 verification job 吃哪份池，照它走
4. run 目錄名須符合 `^st_(model)_(bench)_(rep)$`，三欄內不得含底線（連字號可以）
5. 每個 run 輸出 `manifest.json`
6. 失敗記進 `failures.log`，不靜默跳過，自動重試上限 2 次

---

## A 批 — `naive_verify`（60 job，priority 1）

### 目的

RQ4 目前引用他人論文的數字做比較（跨 benchmark、跨設定）。本組提供**同候選池、同模型、同 seed** 的單次 prompt 對照，讓 RQ4 變成三點直接比較：

```
baseline (不驗證)  →  naive_verify (單次 prompt)  →  full (多訊號)
```

### 這是一個新 config，pipeline 裡還沒有，要先實作

**核心設計原則：資訊量相同，結構不同。**

`naive_verify` 必須拿到跟 `full` **完全一樣的資訊**（identity + source + concern + PoC 結果），差別只在於「不做結構化的訊號分解」。否則測到的會是「資訊有無」而不是「結構有無」，實驗就白做了。

### 必須與 `full` 相同（控制變因）

| 項目 | 說明 |
|---|---|
| 候選池 | 同一份 `source_pool`，逐筆 `finding_idx` 對應 |
| verification 模型 | Nemotron-3-Super-120B-A12B |
| temperature / top_p / max_tokens | 與 `full` 完全相同（含 nemotron 重跑後的新 max_tokens） |
| 輸出 schema | `confirmed` / `downgraded` / `false_positive` —— **必須相同**，否則無法套用同一套 shipped 四規則 |
| 每筆 finding 一次呼叫 | 不批次、不合併 |
| 資訊內容 | identity、source、concern、PoC 結果全部提供 |

### 必須與 `full` 不同（實驗變因）

| 項目 | 說明 |
|---|---|
| 訊號角色 | prompt **不標示**四個訊號各自的角色，不給任何「PoC 是客觀證據」「source 是確認依據」之類的指引 |
| 呼叫結構 | 單次呼叫，無分階段、無結構化裁決 |
| **§III-D 的 PoC 納入政策** | **不套用**。PoC 的原始結果直接放進 prompt，包含「編譯失敗」，且不加任何解讀指引。這正是要測的東西之一 |

### Prompt 模板（照抄，不要改寫）

```
You are reviewing a potential security vulnerability found in a codebase.

File: {file}
Line: {line}
Function: {function}

Reported issue:
{concern_text}

Source code:
{source_code}

Proof-of-concept execution result:
{poc_raw}

Is this a genuine, exploitable vulnerability?

Respond with JSON only, no other text:
{"verdict": "confirmed" | "downgraded" | "false_positive", "reason": "<one sentence>"}
```

**`{poc_raw}` 的填法**（不做任何解讀，這是重點）：

- PoC 觸發成功 → `PoC compiled and triggered the reported behavior.`
- PoC 編譯成功但未觸發 → `PoC compiled but did not trigger the reported behavior.`
- PoC 編譯失敗 → `PoC failed to compile. Error: {error}`
- 沒有 PoC → `No proof-of-concept was generated.`

**不要**加「編譯失敗不代表沒有漏洞」這類提示。`full` 有這個政策，`naive_verify` 沒有，這就是差異所在。

### 輸出

與 `full` 相同的目錄結構：

```
st_qwen_dvd_s1/naive_verify/{findings.json, metadata.json}
```

`findings.json` 的 `verification` 區塊格式與 `full` 一致（`function`, `file`, `verdict`, `severity`, `reason`），且**逐筆 `finding_idx` 與 `full` 對齊**，這樣才能做 finding 級配對檢定。

### 執行順序

1. **先跑 qwen 20 個**（Table 1 主設定，最快看到結果）
2. 再跑 gemma 20 個
3. nemotron 20 個 —— `blocked_by` 欄有標，等 detection 重跑完成

---

## C 批 — 第 4 個 verifier 家族（36 job，optional=yes）

### 目的

Tier 3 產生一個新宣稱：**verifier 選擇讓 FP-cut 變動 20–30pp，Nemotron 在四個 benchmark 皆最佳**。目前只有三個模型支撐這個排名，加入一個不同家族可擋下「都是同級開源模型」的質疑。

### 做法

- detection 凍結：qwen 的 seed 1–3 候選池（`source_pool` 欄已指定）
- verification 模型：**從 DeepSeek-V3 / Llama-3.3-70B / Mistral-Large 擇一**，選定後填進 CSV 的 `verification_model` 欄取代 `EXTERNAL-FAMILY`，中途不要更換
- config：`full`、`full_rep2`、`full_rep3`（同池重跑 3 次）
- 4 benchmark × 3 pool × 3 repeat = 36

### 何時跑

A 批跑完之後。不急，也可以不跑。

---

## 完成後打包

```
msfv-round2-<日期>-naive_verify.tar.gz     # A 批
msfv-round2-<日期>-vext.tar.gz             # C 批（若有跑）
msfv-round2-<日期>-meta.tar.gz             # progress.csv, failures.log, 全部 manifest.json
```

`RUN_REPORT.md` 需包含：

1. 完成 / 失敗 / 跳過的 job 數與原因
2. A 批的 `naive_verify` 與對應 `full` 的 `finding_idx` 是否逐筆對齊（不對齊的話配對檢定做不了）
3. 所有 manifest 的參數一致性

---

## 開跑前回報

1. `naive_verify` 已實作，且已跑一個 NodeGoat job 驗證輸出 schema 與 `full` 一致、`finding_idx` 對齊（NodeGoat 最快，約 1 分鐘）
2. C 批若要跑，選定的外部家族模型

確認完再開始跑 A 批的其餘部分。
