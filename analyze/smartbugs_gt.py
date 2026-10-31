#!/usr/bin/env python3
"""
smartbugs_gt.py — 從 SmartBugs Curated 產出 ground_truth.csv

SmartBugs Curated 有兩個標註來源，本工具都支援並可交叉驗證：

  A) vulnerabilities.json   repo 根目錄，由 scripts/get_vulns_lines.js 生成（權威）
  B) .sol 檔內嵌註解        @vulnerable_at_lines 與 // <yes> <report> CATEGORY

用法:
    # 只用 .sol 內嵌註解（只要有 dataset/ 目錄就能跑）
    python smartbugs_gt.py --dataset path/to/smartbugs-curated/dataset

    # 只用 vulnerabilities.json
    python smartbugs_gt.py --vulns path/to/vulnerabilities.json

    # 兩者都給 → 交叉驗證，不一致處會列出來
    python smartbugs_gt.py --dataset .../dataset --vulns .../vulnerabilities.json

    # 指定輸出與 file 欄前綴（要對得上你 scan 記錄裡的路徑）
    python smartbugs_gt.py --dataset .../dataset --prefix dataset/ -o ground_truth_smartbugs.csv

輸出欄位（與 msfv_analyze.py --gt 相容）:
    vuln_id, bench, match_mode, file, line, line_tolerance,
    function, challenge, category, source, notes
"""

import argparse, csv, json, re, sys
from pathlib import Path
from collections import defaultdict

MARKER = re.compile(r"//\s*<yes>\s*<report>\s*(?P<cat>[A-Za-z_][A-Za-z0-9_\-]*)")
AT_LINES = re.compile(r"@vulnerable_at_lines:\s*(?P<lines>[\d,\s]+)")


# ─────────────────────────────────────────────────────────────
# 來源 B：直接解析 .sol
# ─────────────────────────────────────────────────────────────

def from_sol_files(dataset_dir: Path, prefix: str):
    """
    解析每個 .sol：
      - @vulnerable_at_lines: 12,34   → 宣告的漏洞行
      - // <yes> <report> CAT         → 標記註解，漏洞行是它「下面」第一行非空白程式碼
    兩者取聯集，並回報彼此不一致處。
    """
    rows, disagree = [], []
    sols = sorted(dataset_dir.rglob("*.sol"))
    if not sols:
        sys.exit(f"✗ {dataset_dir} 底下找不到 .sol")

    for p in sols:
        rel = p.relative_to(dataset_dir).as_posix()
        fkey = prefix + rel
        category = p.parent.name          # DASP 目錄名
        try:
            lines = p.read_text(errors="replace").splitlines()
        except Exception as e:
            print(f"  ! 讀不到 {p}: {e}", file=sys.stderr)
            continue

        declared = set()
        marked = {}      # line_no -> category

        for i, ln in enumerate(lines, start=1):
            m = AT_LINES.search(ln)
            if m:
                declared |= {int(x) for x in re.findall(r"\d+", m.group("lines"))}
            mk = MARKER.search(ln)
            if mk:
                # 標記註解在漏洞行的上方；往下找第一行有實質內容的
                for j in range(i, len(lines)):
                    nxt = lines[j].strip()
                    if nxt and not nxt.startswith("//"):
                        marked[j + 1] = mk.group("cat").lower()
                        break

        union = sorted(declared | set(marked))
        only_decl = sorted(declared - set(marked))
        only_mark = sorted(set(marked) - declared)
        if only_decl or only_mark:
            disagree.append((fkey, only_decl, only_mark))

        for ln_no in union:
            src = ("both" if ln_no in declared and ln_no in marked
                   else "at_lines" if ln_no in declared else "marker")
            rows.append(dict(
                vuln_id=f"sb:{rel}:L{ln_no}", bench="smartbugs", match_mode="line",
                file=fkey, line=ln_no, line_tolerance=0,
                function="", challenge="",
                category=marked.get(ln_no, category), source=f"sol:{src}", notes=""))
    return rows, disagree, len(sols)


# ─────────────────────────────────────────────────────────────
# 來源 A：vulnerabilities.json
# ─────────────────────────────────────────────────────────────

def _walk_for_vulns(obj, path_hint=None):
    """
    vulnerabilities.json 的確切 schema 版本間有差異，因此用容錯遍歷：
    找出任何帶 (path|name) 與 (lines|line) 的節點。
    """
    out = []

    def rec(o, hint):
        if isinstance(o, dict):
            p = o.get("path") or o.get("name") or o.get("file") or hint
            cat = (o.get("category") or o.get("vulnerability")
                   or o.get("type") or o.get("class"))
            lns = o.get("lines", o.get("line"))
            if p and lns is not None:
                if isinstance(lns, (int, str)):
                    lns = [lns]
                if isinstance(lns, list):
                    nums = [int(x) for x in lns
                            if isinstance(x, int) or (isinstance(x, str) and x.isdigit())]
                    for n in nums:
                        out.append((str(p), n, str(cat) if cat else ""))
            for v in o.values():
                rec(v, p if isinstance(p, str) else hint)
        elif isinstance(o, list):
            for v in o:
                rec(v, hint)

    rec(obj, path_hint)
    return out


def from_vulns_json(vj: Path, prefix: str):
    data = json.loads(vj.read_text())
    triples = _walk_for_vulns(data)
    if not triples:
        sys.exit(f"✗ 無法從 {vj} 解析出 (path, line) —— 請把檔案結構貼給我，我調整 parser")

    rows = []
    for p, ln, cat in sorted(set(triples)):
        rel = p.split("dataset/", 1)[-1] if "dataset/" in p else p.lstrip("./")
        fkey = prefix + rel
        rows.append(dict(
            vuln_id=f"sb:{rel}:L{ln}", bench="smartbugs", match_mode="line",
            file=fkey, line=ln, line_tolerance=0, function="", challenge="",
            category=(cat or Path(rel).parent.name).lower(),
            source="vulnerabilities.json", notes=""))
    return rows


# ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="SmartBugs Curated → ground_truth.csv")
    ap.add_argument("--dataset", type=Path, help="smartbugs-curated/dataset 目錄")
    ap.add_argument("--vulns", type=Path, help="vulnerabilities.json")
    ap.add_argument("--prefix", default="dataset/",
                    help="加在 file 欄前面的前綴，要與 scan 記錄的路徑一致（預設 dataset/）")
    ap.add_argument("-o", "--out", type=Path, default=Path("ground_truth_smartbugs.csv"))
    a = ap.parse_args()

    if not a.dataset and not a.vulns:
        ap.error("至少要給 --dataset 或 --vulns 之一")

    rows_sol = rows_vj = None
    if a.dataset:
        rows_sol, disagree, n_files = from_sol_files(a.dataset, a.prefix)
        print(f"▶ .sol 解析: {n_files} 個合約 → {len(rows_sol)} 個漏洞行")
        if disagree:
            print(f"  ⚠ {len(disagree)} 個檔的 @vulnerable_at_lines 與 <yes> 標記不一致:")
            for f, od, om in disagree[:8]:
                print(f"    {f}  只在 at_lines={od}  只在 marker={om}")
            print("    （已取聯集。這些不一致要在論文的標註程序裡說明）")

    if a.vulns:
        rows_vj = from_vulns_json(a.vulns, a.prefix)
        print(f"▶ vulnerabilities.json: {len(rows_vj)} 個漏洞行")

    # 交叉驗證
    if rows_sol and rows_vj:
        s, v = {r["vuln_id"] for r in rows_sol}, {r["vuln_id"] for r in rows_vj}
        print(f"\n▶ 交叉驗證: 交集 {len(s & v)} / 只在 .sol {len(s - v)} / 只在 json {len(v - s)}")
        for x in sorted(s - v)[:5]:
            print(f"    只在 .sol : {x}")
        for x in sorted(v - s)[:5]:
            print(f"    只在 json : {x}")
        rows = rows_vj + [r for r in rows_sol if r["vuln_id"] not in v]
        print("  → 以 vulnerabilities.json 為主，補上只在 .sol 出現的")
    else:
        rows = rows_vj or rows_sol

    # 統計
    by_file = defaultdict(int)
    by_cat = defaultdict(int)
    for r in rows:
        by_file[r["file"]] += 1
        by_cat[r["category"]] += 1

    print(f"\n▶ 合計 {len(rows)} 個漏洞實例，分佈於 {len(by_file)} 個合約")
    print("  依類別:")
    for c, n in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"    {n:4d}  {c}")
    print("\n  ⚠ 這兩個數字都要寫進論文，而且要講清楚 recall 的分母用哪個:")
    print(f"       contract-level  分母 = {len(by_file)}")
    print(f"       instance-level  分母 = {len(rows)}")

    cols = ["vuln_id", "bench", "match_mode", "file", "line", "line_tolerance",
            "function", "challenge", "category", "source", "notes"]
    with a.out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"\n✔ 已寫出 → {a.out}")


if __name__ == "__main__":
    main()
