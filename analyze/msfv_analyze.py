#!/usr/bin/env python3
"""
msfv_analyze.py — MSFV 資料包統計工具

用法:
    python msfv_analyze.py <資料包目錄> [-o 輸出目錄] [--gt ground_truth.csv]

範例:
    python msfv_analyze.py ./2026-07-23-verify-stability-purebaseline
    python msfv_analyze.py ./data -o results/ --gt labels/ground_truth.csv

輸入格式（自動偵測）:
    <pkg>/st_{model}_{bench}_{rep}/{config}/metadata.json
                                           findings.json
                                           scan_state.json
    <pkg>/VERIFY_*.json                    （可選，會自動驗算）

輸出:
    inventory.csv           每個 run-config 一列
    reduction.csv           下降幅度（含 mean/SD/CI）
    coverage.csv            ablation 覆蓋缺口
    contradictions.txt      自動偵測的矛盾
    shipped_mismatch.csv    metadata.shipped 與 per-finding 推導的落差
    per_finding.csv         逐 finding 記錄（有 --gt 時含 TP/FP 標記）
    metrics.csv             完整指標（需要 --gt）
    tables.tex              可直接 \\input 的 LaTeX 表格
    numbers.tex             正文用的 \\newcommand 巨集
"""

import argparse, json, re, sys
from pathlib import Path
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent))
from msfv_stats import (wilson_ci, metrics, agg_across_seeds, compare_configs,
                        Numbers, latex_table, signal_agreement)

RUN_RE = re.compile(r"^st_(?P<model>[^_]+)_(?P<bench>[^_]+)_(?P<rep>[^_]+)$")


# ═══════════════════════════════════════════════════════════
# shipped 判定 —— 改這裡就好
# ═══════════════════════════════════════════════════════════

def derive_shipped(f: dict) -> bool:
    """
    從單筆 finding 推導它是否 shipped。

    ⚠️ 目前這只是「盡力而為」的近似，在 132 個 run-config 中只有 19 個
    能完全重現 metadata.json 的 shipped 值。把你 pipeline 裡真正的
    出貨判定邏輯搬進來，shipped_mismatch.csv 就會歸零。
    """
    v = f.get("verification")
    if isinstance(v, list) and v:
        return "confirmed" in {x.get("verdict") for x in v if isinstance(x, dict)}
    if f.get("layer") == 5:
        return True
    a = f.get("analysis")
    if isinstance(a, str):
        m = re.search(r"Confirmed:\s*(\w+)", a)
        return bool(m and m.group(1).lower() == "yes")
    return False


def signal_verdicts(f: dict) -> dict:
    """抽出可用於非冗餘性分析的訊號級旗標。"""
    v = f.get("verification")
    vs = {x.get("verdict") for x in v if isinstance(x, dict)} if isinstance(v, list) else set()
    poc = f.get("poc") or {}
    return dict(
        sig_confirmed=int("confirmed" in vs),
        sig_false_positive=int("false_positive" in vs),
        sig_downgraded=int("downgraded" in vs),
        sig_has_poc=int(bool(poc)),
        sig_poc_triggered=int(bool(poc.get("triggered")) if isinstance(poc, dict) else 0),
        sig_sev_override=f.get("severity_override"),
    )


# ═══════════════════════════════════════════════════════════
# 載入
# ═══════════════════════════════════════════════════════════

def load_package(pkg: Path):
    """回傳 (inventory_df, per_finding_df, summary_files)"""
    inv, pf = [], []
    run_dirs = sorted(d for d in pkg.iterdir() if d.is_dir() and RUN_RE.match(d.name))
    if not run_dirs:
        sys.exit(f"✗ 在 {pkg} 找不到 st_*_*_* 形式的 run 目錄")

    for rd in run_dirs:
        g = RUN_RE.match(rd.name).groupdict()
        for cd in sorted(d for d in rd.iterdir() if d.is_dir()):
            mp = cd / "metadata.json"
            if not mp.exists():
                continue
            m = json.loads(mp.read_text())
            row = dict(run=rd.name, **g, config=cd.name,
                       findings_count=m.get("findings_count"),
                       shipped=m.get("shipped"),
                       verify_signals=m.get("verify_signals") or "",
                       elapsed=m.get("elapsed_human"),
                       poc_emit=m.get("poc_emit"), poc_compile=m.get("poc_compile"),
                       poc_triggered=m.get("poc_triggered"), poc_repaired=m.get("poc_repaired"))

            fp = cd / "findings.json"
            if fp.exists():
                fl = json.loads(fp.read_text())
                row["n_records"] = len(fl)
                row["shipped_derived"] = sum(1 for f in fl if derive_shipped(f))
                for i, f in enumerate(fl):
                    fi = f.get("finding") or {}
                    pf.append(dict(run=rd.name, **g, config=cd.name, idx=i,
                                   layer=f.get("layer"),
                                   rule_id=fi.get("rule_id"), file=fi.get("file"),
                                   line=fi.get("line"), cwe=fi.get("cwe"),
                                   severity=fi.get("severity"),
                                   shipped=derive_shipped(f), **signal_verdicts(f)))
            inv.append(row)

    summaries = sorted(pkg.glob("VERIFY*.json"))
    return pd.DataFrame(inv), pd.DataFrame(pf), summaries


# ═══════════════════════════════════════════════════════════
# 分析
# ═══════════════════════════════════════════════════════════

def add_reduction(inv: pd.DataFrame) -> pd.DataFrame:
    """以 config=='baseline' 為分母算 finding count reduction。"""
    key = ["model", "bench", "rep"]
    base = (inv[inv.config == "baseline"].set_index(key).shipped.rename("baseline_shipped"))
    out = inv.join(base, on=key)
    out["reduction_pct"] = (out.baseline_shipped - out.shipped) / out.baseline_shipped * 100
    return out


def coverage(inv: pd.DataFrame) -> pd.DataFrame:
    cov = inv.pivot_table(index=["model", "bench"], columns="config",
                          values="rep", aggfunc="count").fillna(0).astype(int)
    return cov


def find_contradictions(inv: pd.DataFrame, red: pd.DataFrame) -> list:
    out = []
    p = inv.pivot_table(index=["model", "bench", "rep"], columns="config",
                        values="shipped", aggfunc="first")

    # 1. 聲稱相等的配置實際不等
    for a, b in [("full", "nopoc"), ("full", "nosource"), ("nopoc", "nosource")]:
        if a in p and b in p:
            sub = p[[a, b]].dropna()
            neq = sub[sub[a] != sub[b]]
            if len(neq):
                out.append(f"[相等性] {a} vs {b}: {len(neq)}/{len(sub)} 組不相等 — "
                           f"任何「{a} 等於 {b}」的聲明都要逐組檢查，不要只看四捨五入後的百分比")

    # 2. 移除訊號後方向不一致
    for cfg in [c for c in p.columns if c not in ("baseline", "full")]:
        if "full" not in p:
            break
        sub = p[["full", cfg]].dropna()
        if not len(sub):
            continue
        d = sub[cfg] - sub["full"]
        up, dn, eq = int((d > 0).sum()), int((d < 0).sum()), int((d == 0).sum())
        if up and dn:
            out.append(f"[方向] {cfg} vs full: 多 {up} 例 / 少 {dn} 例 / 相同 {eq} 例 — "
                       f"方向不一致，「每個訊號都改善系統」不成立")

    # 3. 跨模型 pattern 不一致
    for cfg in [c for c in p.columns if c not in ("baseline", "full")]:
        if "full" not in p:
            break
        for bench in p.index.get_level_values("bench").unique():
            sub = p.xs(bench, level="bench")[["full", cfg]].dropna()
            if len(sub) < 2:
                continue
            sign = np.sign(sub[cfg] - sub["full"]).groupby(level="model").mean()
            if sign.max() > 0 and sign.min() < 0:
                hi = ", ".join(sign[sign > 0].index)
                lo = ", ".join(sign[sign < 0].index)
                out.append(f"[跨模型] {bench}/{cfg}: {hi} 上升但 {lo} 下降 — "
                           f"R1-2 說的 cross-model pattern 不一致")

    # 4. baseline 在同組內不一致（表示 detection 沒被凍結）
    for (m, b), g in inv[inv.config == "baseline"].groupby(["model", "bench"]):
        if g.shipped.nunique() > 1:
            out.append(f"[baseline 漂移] {m}/{b}: baseline shipped = {sorted(g.shipped)} — "
                       f"detection 未凍結")

    # 5. 只重跑 verification 的警訊
    frozen = [f"{m}/{b}" for (m, b), g in inv[inv.config == "baseline"].groupby(["model", "bench"])
              if g.shipped.nunique() == 1 and len(g) > 1]
    if frozen:
        out.append(f"[實驗設計] {len(frozen)} 組的 baseline shipped 完全相同 — "
                   f"detection 被凍結，只重跑了 verification。這正是 R1-4 / R2-4 反對的設計")

    return out


def verify_summaries(paths) -> list:
    """驗算 VERIFY_*.json 的自報統計值。"""
    out = []
    for p in paths:
        d = json.loads(p.read_text())
        rows = d.get("rows", {})
        if not rows:
            continue
        skey = next((k for k in ("samples", "runs") for r in rows.values() if k in r), None)
        if not skey:
            continue
        vals, mism = [], []
        for k, r in rows.items():
            s = np.array(r[skey], float)
            cv = s.std(ddof=0) / s.mean() * 100
            sp = (s.max() - s.min()) / s.mean() * 100
            vals.append((cv, sp))
            for field, calc in (("cv_pct", cv), ("range_pct", sp), ("spread_pct", sp)):
                if field in r and abs(r[field] - calc) > 0.06:
                    mism.append(f"    {k}.{field}: 宣稱 {r[field]} vs 實算 {calc:.2f}  {r[skey]}")
        cvs = np.array([v[0] for v in vals]); sps = np.array([v[1] for v in vals])
        out.append(f"  {p.name}  n={len(rows)}")
        for label, claimed, calc in [
            ("mean_cv_pct", d.get("mean_cv_pct"), cvs.mean()),
            ("median_cv_pct", d.get("median_cv_pct"), np.median(cvs)),
            ("max_cv_pct", d.get("max_cv_pct"), cvs.max()),
            ("mean_spread_pct", d.get("mean_spread_pct"), sps.mean()),
            ("median_spread_pct", d.get("median_spread_pct"), np.median(sps)),
            ("max_spread_pct", d.get("max_spread_pct"), sps.max()),
            ("n_config_groups", d.get("n_config_groups"), len(rows)),
            ("n_config_triples", d.get("n_config_triples"), len(rows)),
        ]:
            if claimed is None:
                continue
            ok = abs(float(claimed) - float(calc)) <= 0.06
            out.append(f"    {'✓' if ok else '✗'} {label}: 宣稱 {claimed} / 實算 {calc:.2f}")
        out.append(f"    逐列不符: {len(mism)}")
        out += mism[:10]
    return out


def _norm(s):
    return str(s).strip().lstrip("./") if s is not None and str(s) != "nan" else ""


def _challenge_of(path):
    """DVD 風格：src/<challenge>/Foo.sol → challenge 名。"""
    parts = _norm(path).split("/")
    return parts[1] if len(parts) > 2 and parts[0] == "src" else (parts[0] if parts else "")


def match_findings_to_gt(pf: pd.DataFrame, gt: pd.DataFrame):
    """
    把 finding 對到 ground truth 實例。

    支援 4 種 match_mode，可以在同一份 CSV 裡混用 —— 因為四個 benchmark
    的標註粒度本來就不同（SmartBugs 有行級，DVD 只有 challenge 級）：

      line       同檔且 |finding.line - gt.line| <= line_tolerance
      function   同檔且 gt.function 出現在 finding 的 rule_id / file
      file       同檔即算命中（PyGoat / NodeGoat 的 lab 級標註）
      challenge  同 challenge 目錄即算命中（DVD）

    回傳 (pf_with_flags, gt_hits)
      pf_with_flags: 多出 ground_truth（bool）與 matched_vuln_ids（字串）
      gt_hits:       每個 (run, config, vuln_id) 是否被 shipped 的 finding 命中
    """
    pf = pf.copy()
    pf["_file"] = pf.file.map(_norm)
    pf["_chal"] = pf.file.map(_challenge_of)
    gt = gt.copy()
    gt["_file"] = gt.file.map(_norm)
    gt["_chal"] = gt.get("challenge", pd.Series("", index=gt.index)).map(_norm)
    gt.loc[gt._chal == "", "_chal"] = gt.loc[gt._chal == "", "_file"].map(_challenge_of)
    if "line_tolerance" not in gt:
        gt["line_tolerance"] = 0
    gt["line_tolerance"] = gt.line_tolerance.fillna(0).astype(int)

    matched = defaultdict(set)          # finding row index -> {vuln_id}
    hits = []                           # (run, config, vuln_id, hit_by_shipped)

    for bench, gsub in gt.groupby("bench"):
        psub = pf[pf.bench == bench]
        if not len(psub):
            print(f"  ! ground truth 有 bench='{bench}' 但 finding 裡沒有，略過")
            continue
        for _, v in gsub.iterrows():
            mode = _norm(v.get("match_mode")) or "line"
            if mode == "line":
                cand = psub[(psub._file == v._file) &
                            (psub.line.sub(float(v.line)).abs() <= v.line_tolerance)]
            elif mode == "function":
                fn = _norm(v.get("function"))
                cand = psub[(psub._file == v._file) &
                            psub.rule_id.fillna("").str.contains(re.escape(fn), case=False)] \
                    if fn else psub[psub._file == v._file]
            elif mode == "file":
                cand = psub[psub._file == v._file]
            elif mode == "challenge":
                cand = psub[psub._chal == v._chal]
            else:
                print(f"  ! 未知 match_mode='{mode}' (vuln_id={v.vuln_id})，當作 line")
                cand = psub[(psub._file == v._file) & (psub.line == v.line)]

            for i in cand.index:
                matched[i].add(v.vuln_id)
            for (run, cfg), g in cand.groupby(["run", "config"]):
                hits.append(dict(run=run, config=cfg, bench=bench, vuln_id=v.vuln_id,
                                 n_findings=len(g), hit_by_shipped=bool(g.shipped.any())))
            # 完全沒被任何 finding 碰到的 GT 也要留一列，否則 recall 分母會漏
            covered = set(cand.groupby(["run", "config"]).groups)
            for run, cfg in psub.groupby(["run", "config"]).groups:
                if (run, cfg) not in covered:
                    hits.append(dict(run=run, config=cfg, bench=bench, vuln_id=v.vuln_id,
                                     n_findings=0, hit_by_shipped=False))

    pf["matched_vuln_ids"] = pd.Series(
        {i: ";".join(sorted(s)) for i, s in matched.items()}).reindex(pf.index).fillna("")
    pf["ground_truth"] = pf.matched_vuln_ids != ""
    return pf.drop(columns=["_file", "_chal"]), pd.DataFrame(hits)


def apply_ground_truth(pf: pd.DataFrame, gt_path: Path):
    """
    產出完整指標。

    ⚠ precision 與 recall 的單位刻意不同，這是偵測評估的標準做法，
      但必須在論文裡寫明：

        precision   分母 = shipped 的 finding 數        （finding 級）
        e2e recall   分母 = 該 benchmark 的 GT 實例總數  （漏洞級）

      混用單位正是原稿 retention / end-to-end recall 混淆的來源。
    """
    gt = pd.read_csv(gt_path)
    need = {"vuln_id", "bench"}
    if not need <= set(gt.columns):
        sys.exit(f"✗ ground truth 缺必要欄位: {need - set(gt.columns)}")
    for c in ("match_mode", "file", "line", "line_tolerance", "function", "challenge"):
        if c not in gt:
            gt[c] = "" if c not in ("line", "line_tolerance") else 0

    dup = gt.vuln_id.duplicated().sum()
    if dup:
        print(f"  ⚠ ground truth 有 {dup} 個重複 vuln_id，已去重")
        gt = gt.drop_duplicates("vuln_id")

    totals = gt.groupby("bench").vuln_id.nunique().to_dict()
    print(f"  GT 實例數: {totals}")

    pf, hits = match_findings_to_gt(pf, gt)

    rows = []
    for (mo, be, rp, cf), g in pf.groupby(["model", "bench", "rep", "config"]):
        run = g.run.iloc[0]
        shipped = g[g.shipped]
        tp_f = int(shipped.ground_truth.sum())        # shipped 且對到 GT 的 finding
        fp_f = int((~shipped.ground_truth).sum())     # shipped 但沒對到 GT
        held = g[~g.shipped]
        fn_f = int(held.ground_truth.sum())           # 被擋掉的真漏洞 finding
        tn_f = int((~held.ground_truth).sum())        # 被正確擋掉的誤報

        # 漏洞級 recall（以 vuln_id 去重，一個實例被多筆命中只算一次）
        h = hits[(hits.run == run) & (hits.config == cf)]
        found = int(h[h.hit_by_shipped].vuln_id.nunique())
        total = totals.get(be, np.nan)

        prec = tp_f / (tp_f + fp_f) if tp_f + fp_f else np.nan
        rec = found / total if total and np.isfinite(total) else np.nan
        rows.append(dict(
            model=mo, bench=be, rep=rp, config=cf,
            tp=tp_f, fp=fp_f, fn=fn_f, tn=tn_f,
            n_shipped=len(shipped), n_findings=len(g),
            precision=prec,
            precision_lo=wilson_ci(tp_f, tp_f + fp_f)[0],
            precision_hi=wilson_ci(tp_f, tp_f + fp_f)[1],
            vulns_found=found, vulns_total=total,
            e2e_recall=rec,
            e2e_recall_lo=wilson_ci(found, total)[0],
            e2e_recall_hi=wilson_ci(found, total)[1],
            f1=2 * prec * rec / (prec + rec) if (prec and rec and prec + rec) else np.nan))

    met = pd.DataFrame(rows)

    # FP count reduction，以同 (model,bench,rep) 的 baseline 為分母
    key = ["model", "bench", "rep"]
    bfp = (met[met.config == "baseline"].set_index(key).fp.rename("baseline_fp"))
    met = met.join(bfp, on=key)
    met["fp_count_reduction"] = (met.baseline_fp - met.fp) / met.baseline_fp
    return pf, met, hits


# ═══════════════════════════════════════════════════════════
# main
# ═══════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="MSFV 資料包統計工具")
    ap.add_argument("package", type=Path, help="資料包目錄")
    ap.add_argument("-o", "--out", type=Path, default=Path("results"))
    ap.add_argument("--gt", type=Path, help="ground_truth.csv（有的話會算完整指標）")
    a = ap.parse_args()

    if not a.package.is_dir():
        sys.exit(f"✗ 找不到目錄: {a.package}")
    a.out.mkdir(parents=True, exist_ok=True)

    print(f"▶ 讀取 {a.package}")
    inv, pf, summaries = load_package(a.package)
    print(f"  {inv.run.nunique()} 個 run / {len(inv)} 個 run-config / {len(pf)} 筆 finding")

    red = add_reduction(inv)
    red.to_csv(a.out / "inventory.csv", index=False)
    if len(pf):
        pf.to_csv(a.out / "per_finding.csv", index=False)

    # shipped 落差
    if "shipped_derived" in red:
        mm = red[red.shipped != red.shipped_derived][
            ["run", "config", "shipped", "shipped_derived", "n_records"]].copy()
        mm["diff"] = mm.shipped_derived - mm.shipped
        mm.to_csv(a.out / "shipped_mismatch.csv", index=False)
        print(f"\n▶ shipped 推導落差: {len(mm)}/{len(red)} 個 run-config 不吻合")
        if len(mm):
            print("  → metadata.json 的 shipped 無法從 findings.json 重現。")
            print("     請把真正的出貨邏輯填進 derive_shipped()，見 shipped_mismatch.csv")

    # 覆蓋缺口
    cov = coverage(inv)
    cov.to_csv(a.out / "coverage.csv")
    print("\n▶ ablation 覆蓋（rep 數）")
    print(cov.to_string().replace("\n", "\n  "))
    holes = [(i, c) for i in cov.index for c in cov.columns if cov.loc[i, c] == 0]
    if holes:
        print(f"  ⚠ {len(holes)} 個空格: " + ", ".join(f"{m}/{b}·{c}" for (m, b), c in holes))

    # 下降幅度
    nb = red[red.config != "baseline"]
    if len(nb):
        agg = (nb.groupby(["model", "bench", "config"]).reduction_pct
               .agg(n="count", mean="mean", sd="std", min="min", max="max").round(2).reset_index())
        agg.to_csv(a.out / "reduction.csv", index=False)
        print("\n▶ finding count reduction %（依 model×bench×config）")
        print(agg.to_string(index=False).replace("\n", "\n  "))

    # 矛盾
    con = find_contradictions(inv, red)
    (a.out / "contradictions.txt").write_text("\n".join(con))
    print(f"\n▶ 自動偵測矛盾: {len(con)} 項")
    for c in con:
        print(f"  • {c}")

    # 彙總檔驗算
    if summaries:
        print("\n▶ 彙總檔驗算")
        for line in verify_summaries(summaries):
            print(line)

    # ground truth
    tex_tables, nums = [], Numbers()
    if a.gt:
        print(f"\n▶ 套用 ground truth: {a.gt}")
        pf2, met, hits = apply_ground_truth(pf, a.gt)
        pf2.to_csv(a.out / "per_finding.csv", index=False)
        met.to_csv(a.out / "metrics.csv", index=False)
        hits.to_csv(a.out / "gt_hits.csv", index=False)
        show = ["model", "bench", "rep", "config", "tp", "fp", "fn", "tn",
                "precision", "vulns_found", "vulns_total", "e2e_recall",
                "f1", "fp_count_reduction"]
        print(met[show].round(3).to_string(index=False).replace("\n", "\n  "))

        bad = met[(met.e2e_recall > 1) | (met.precision > 1)]
        if len(bad):
            print(f"\n  ⚠ {len(bad)} 個配置的比例 > 1 —— 比對規則仍有問題，請檢查")

        agg_m = (met.groupby("config")[["precision", "e2e_recall", "fp_count_reduction"]]
                 .agg(["mean", "std"]).round(4))
        print("\n▶ 跨 rep 彙總（mean / SD）")
        print(agg_m.to_string().replace("\n", "\n  "))
        agg_m.to_csv(a.out / "metrics_summary.csv")

        for cfg in met.config.unique():
            sc = met[met.config == cfg]
            if len(sc) > 1:
                nums.pct(f"{cfg} mean precision", sc.precision.mean())
                nums.pct(f"{cfg} mean e2e recall", sc.e2e_recall.mean())
                nums.pct(f"{cfg} mean fp reduction", sc.fp_count_reduction.mean())
        tex_tables.append(latex_table(
            met[show].round(3), "Full classification metrics per configuration",
            "tab:metrics"))

        if met.rep.nunique() > 1:
            ps = met[["config", "model", "bench", "rep", "precision"]]
            cmp = compare_configs(ps, "precision", reference="full",
                                  pair_on=("model", "bench", "rep"))
            if len(cmp):
                cmp.to_csv(a.out / "config_comparison.csv", index=False)
                print("\n▶ 配置比較（配對 Wilcoxon + Holm 校正）")
                print(cmp.round(4).to_string(index=False).replace("\n", "\n  "))
    else:
        print("\n▶ 未提供 --gt，因此 TP/FP/FN/TN、precision、recall 全部無法計算。")
        print("  目前的 reduction 是 *finding count* reduction，不是 FP count reduction。")

    # LaTeX 輸出
    if len(nb):
        tex_tables.insert(0, latex_table(agg, "Finding count reduction by configuration",
                                         "tab:reduction"))
        for _, r in agg.iterrows():
            nums.pct(f"{r.model} {r.bench} {r.config} reduction", r["mean"] / 100)
    tex_tables.insert(0, latex_table(cov.reset_index(), "Ablation coverage (number of repetitions)",
                                     "tab:coverage"))
    (a.out / "tables.tex").write_text("\n".join(tex_tables))
    nums.write(a.out / "numbers.tex")

    print(f"\n✔ 輸出完成 → {a.out}/")
    for f in sorted(a.out.iterdir()):
        print(f"    {f.name}")


if __name__ == "__main__":
    main()
