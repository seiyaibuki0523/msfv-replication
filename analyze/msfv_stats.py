"""
msfv_stats.py — MSFV 論文修訂用統計核心

設計原則：所有數字都從 per-finding 記錄推導，人工不輸入任何數字。
依賴：numpy, scipy, pandas, scikit-learn（不需要 statsmodels）
"""

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import cohen_kappa_score, matthews_corrcoef

Z95 = 1.959963984540054  # z_{0.975}


# ─────────────────────────────────────────────────────────────
# 1. 比例的 Wilson 信賴區間
#    precision / recall 都是比例，count 小的時候常態近似會給出
#    超出 [0,1] 的荒謬區間。Wilson 不會。
# ─────────────────────────────────────────────────────────────

def wilson_ci(k, n, z=Z95):
    """
    k 次成功 / n 次試驗 的 Wilson score interval。

    k > n 時（例如同一個 ground truth 位置被多筆 finding 命中，
    使 TP 超過標註總數）會回傳 nan 並不再計算 —— 這種情況代表
    比對規則有問題，不該被靜默吃掉。
    """
    if n is None or not np.isfinite(n) or n <= 0:
        return (np.nan, np.nan)
    if k is None or not np.isfinite(k) or k < 0 or k > n:
        return (np.nan, np.nan)
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    half = (z / denom) * np.sqrt(max(0.0, p * (1 - p) / n + z**2 / (4 * n**2)))
    return (max(0.0, center - half), min(1.0, center + half))


# ─────────────────────────────────────────────────────────────
# 2. 單一配置的完整指標
#    R2-2 要求：TP / FP / FN / TN + precision / recall / F1
#    R1-1 要求：end-to-end recall（分母是 benchmark 的漏洞總數，
#              不是 detector 找到的數量）
# ─────────────────────────────────────────────────────────────

def confusion(df):
    """df 需有 ground_truth (bool) 與 shipped (bool) 兩欄。"""
    gt, sh = df["ground_truth"].to_numpy(bool), df["shipped"].to_numpy(bool)
    return dict(
        tp=int((gt & sh).sum()),
        fp=int((~gt & sh).sum()),
        fn=int((gt & ~sh).sum()),   # 被 verifier 擋掉的真漏洞
        tn=int((~gt & ~sh).sum()),  # 被 verifier 正確擋掉的誤報
    )


def metrics(df, total_ground_truth_vulns, baseline_fp=None):
    """
    total_ground_truth_vulns: benchmark 標註的漏洞總數（如 SmartBugs = 143）
                              這是 end-to-end recall 的分母
    baseline_fp:              未經驗證時的 FP 數，用來算 FP count reduction
    """
    c = confusion(df)
    tp, fp, fn = c["tp"], c["fp"], c["fn"]
    out = dict(c)

    # precision
    out["precision"] = tp / (tp + fp) if tp + fp else np.nan
    out["precision_ci"] = wilson_ci(tp, tp + fp)

    # retention recall：分母是 detector 找到的（tp + fn）— 原稿報的是這個
    out["retention_recall"] = tp / (tp + fn) if tp + fn else np.nan
    out["retention_recall_ci"] = wilson_ci(tp, tp + fn)

    # end-to-end recall：分母是 benchmark 全部漏洞 — R1-1 要的
    out["e2e_recall"] = tp / total_ground_truth_vulns
    out["e2e_recall_ci"] = wilson_ci(tp, total_ground_truth_vulns)

    p, r = out["precision"], out["e2e_recall"]
    out["f1_e2e"] = 2 * p * r / (p + r) if (p and r and p + r) else np.nan

    # FP count reduction（不是 FPR！R1-3 / R2-2 要求正名）
    if baseline_fp:
        out["fp_count_reduction"] = (baseline_fp - fp) / baseline_fp
        out["baseline_fp"] = baseline_fp

    return out


# ─────────────────────────────────────────────────────────────
# 3. FP reduction 的 bootstrap CI
#    它是比值，抽樣分布不好看，別套公式
# ─────────────────────────────────────────────────────────────

def fp_reduction_ci(baseline_fp_flags, verified_fp_flags, n_boot=10000, seed=0):
    """兩個等長 bool array：同一批 finding 在 baseline / verified 下是否為 FP。"""
    rng = np.random.default_rng(seed)
    b = np.asarray(baseline_fp_flags, bool)
    v = np.asarray(verified_fp_flags, bool)
    n = len(b)
    reps = np.empty(n_boot)
    for i in range(n_boot):
        idx = rng.integers(0, n, n)
        bf, vf = b[idx].sum(), v[idx].sum()
        reps[i] = (bf - vf) / bf if bf else np.nan
    lo, hi = np.nanpercentile(reps, [2.5, 97.5])
    point = (b.sum() - v.sum()) / b.sum() if b.sum() else np.nan
    return point, (lo, hi)


# ─────────────────────────────────────────────────────────────
# 4. 信號非冗餘性（R1-2 / R2-5）
#    不要說 "independent"，說 "non-redundant" 並附上數字
# ─────────────────────────────────────────────────────────────

def signal_agreement(df, signal_cols):
    """每對信號判決之間的 Cohen's kappa 與 phi(=MCC)。"""
    rows = []
    for i, a in enumerate(signal_cols):
        for b in signal_cols[i + 1:]:
            x = df[a].to_numpy(int)
            y = df[b].to_numpy(int)
            rows.append(dict(
                sig_a=a, sig_b=b,
                kappa=cohen_kappa_score(x, y),
                phi=matthews_corrcoef(x, y) if len(set(x)) > 1 and len(set(y)) > 1 else np.nan,
            ))
    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────
# 5. 跨 seed 的配對檢定 + 多重比較校正（R2-3 / R2-4）
#    同一批 finding 被不同配置評估 → 配對；seed 數少 → 非參數
# ─────────────────────────────────────────────────────────────

def holm(pvals):
    """Holm-Bonferroni step-down 校正。"""
    p = np.asarray(pvals, float)
    m = len(p)
    order = np.argsort(p)
    adj = np.empty(m)
    running = 0.0
    for rank, idx in enumerate(order):
        val = min(1.0, (m - rank) * p[idx])
        running = max(running, val)
        adj[idx] = running
    return adj


def compare_configs(per_seed, metric, reference="Full", pair_on=("seed",)):
    """
    per_seed: DataFrame，需有 config、<metric>，以及 pair_on 指定的配對鍵。
    對每個配置 vs reference 做配對 Wilcoxon，再 Holm 校正。

    pair_on 必須讓 (config, *pair_on) 唯一 —— 例如跨多個 benchmark 時要用
    ("model","bench","seed")，只用 ("seed",) 會讓不同 benchmark 的列互相碰撞。
    """
    pair_on = list(pair_on)
    dup = per_seed.duplicated(["config"] + pair_on).sum()
    if dup:
        raise ValueError(
            f"(config, {', '.join(pair_on)}) 有 {dup} 筆重複 —— "
            f"配對鍵不唯一，請把區隔欄位加進 pair_on")

    ref = per_seed[per_seed.config == reference].set_index(pair_on)[metric]
    rows = []
    for cfg in per_seed.config.unique():
        if cfg == reference:
            continue
        cur = per_seed[per_seed.config == cfg].set_index(pair_on)[metric]
        common = ref.index.intersection(cur.index)
        a = ref.loc[common].to_numpy(float)
        b = cur.loc[common].to_numpy(float)
        ok = np.isfinite(a) & np.isfinite(b)      # 丟掉任一側是 NaN 的配對
        a, b = a[ok], b[ok]
        if len(a) < 2 or np.allclose(a, b):
            w, p = np.nan, 1.0
        else:
            w, p = stats.wilcoxon(a, b)
        rows.append(dict(config=cfg, n_pairs=len(a),
                         mean_diff=float(np.mean(a - b)) if len(a) else np.nan,
                         stat=w, p_raw=p))
    out = pd.DataFrame(rows)
    if len(out):
        out["p_holm"] = holm(out.p_raw)
        out["sig_005"] = out.p_holm < 0.05
    return out


def agg_across_seeds(per_seed, metric):
    """mean ± SD + 95% CI of the mean（t 分布）。"""
    g = per_seed.groupby("config")[metric]
    res = g.agg(["count", "mean", "std"]).rename(columns={"count": "n"})
    tcrit = stats.t.ppf(0.975, res.n - 1)
    sem = res["std"] / np.sqrt(res.n)
    res["ci_lo"], res["ci_hi"] = res["mean"] - tcrit * sem, res["mean"] + tcrit * sem
    return res.reset_index()


# ─────────────────────────────────────────────────────────────
# 6. 表格與 numbers.tex 生成（R2-1 的根本解）
#    正文絕不手打數字，全部走 \newcommand
# ─────────────────────────────────────────────────────────────

class Numbers:
    """收集要在正文引用的數字，輸出成 numbers.tex。"""

    def __init__(self):
        self._d = {}

    def add(self, name, value, fmt="{:.1f}", suffix=""):
        key = "".join(w.capitalize() if i else w
                      for i, w in enumerate(name.replace("_", " ").split()))
        self._d[key] = fmt.format(value) + suffix
        return f"\\{key}"

    def pct(self, name, value):
        return self.add(name, value * 100, "{:.1f}", r"\%")

    def write(self, path):
        with open(path, "w") as f:
            f.write("% AUTO-GENERATED — do not edit by hand\n")
            for k, v in sorted(self._d.items()):
                f.write(f"\\newcommand{{\\{k}}}{{{v}}}\n")
        return path


def latex_table(df, caption, label, float_fmt="%.3f"):
    body = df.to_latex(index=False, float_format=float_fmt, escape=False)
    return (f"\\begin{{table}}[t]\n\\centering\n\\caption{{{caption}}}\n"
            f"\\label{{{label}}}\n{body}\\end{{table}}\n")
