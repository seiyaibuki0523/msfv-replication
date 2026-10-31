# -*- coding: utf-8 -*-
"""Final-files revision numbers (R1's three comments).

1. Table 4 recomputed over the verification pool (= baseline-shipped candidates: not self-rejected,
   not clamped to informational), so that detector self-rejection is no longer counted as a
   verification decision; F1 averaged over ALL runs (F1 = 0 when TP = 0).
2. False-positive reduction proper (share of unlabelled pool findings withheld) for Table 3's rows.
3. Random-removal comparison: expected TP / precision if the same number of alerts were removed
   uniformly at random (hypergeometric), per detector-benchmark cell, plus a one-sided probability.
"""
import sys, json, math
from math import comb
from recompute import Analysis, mean, sd, ci95, BENCHES, DETS

PKL = sys.argv[1] if len(sys.argv) > 1 else '/home/claude/analysis/pkg3.pkl'
A = Analysis(pkl=PKL)
BN = {'dvd': 'DVD', 'pygoat': 'PyGoat', 'nodegoat': 'NodeGoat', 'smartbugs': 'SmartBugs'}


def pool_mask(run):
    b = A.baseline(run)
    return [x['ship_med'] for x in b['findings']]


def confusion_pool(c, low=False, mech=True):
    h = A.hits(c['run'], mech)
    pm = pool_mask(c['run'])
    tp = fp = fn = tn = 0
    out_of_pool_shipped = 0
    for x, sh in zip(c['findings'], A.ship(c, low)):
        pos = bool(h[x['idx']])
        if not pm[x['idx']]:
            if sh:
                out_of_pool_shipped += 1
            continue
        if sh and pos: tp += 1
        elif sh: fp += 1
        elif pos: fn += 1
        else: tn += 1
    return tp, fp, fn, tn, out_of_pool_shipped


def ms(v, d=1):
    return f"{mean(v):.{d}f}({sd(v):.{d}f})"


# ---------------------------------------------------------------- 1. Table 4 over the pool
print("=== sanity: full-config findings shipped but outside the baseline pool ===")
oop = 0
for c in A.cfgs:
    if c['config'] == 'full':
        oop += confusion_pool(c, False, True)[4] + confusion_pool(c, True, True)[4]
print("out-of-pool shipped (all full configs, both thresholds):", oop)

table4 = {}
print("\n=== Table 4 (qwen, full) over the verification pool; F1 over all runs ===")
for mech, title in ((True, 'Mechanism-aware criterion'), (False, 'File-level criterion')):
    print('%', title)
    for b in BENCHES:
        for low, thr in ((False, 'P1'), (True, 'R1')):
            confs = A.series('qwen', b, 'full', lambda c: confusion_pool(c, low, mech)[:4])
            tp, fp, fn, tn = [[c[i] for c in confs] for i in range(4)]
            prec = [100 * a / (a + b_) if a + b_ else 0.0 for a, b_ in zip(tp, fp)]
            rec = [100 * a / (a + b_) if a + b_ else 0.0 for a, b_ in zip(tp, fn)]
            f1 = [2 * p * r / (p + r) if p + r else 0.0 for p, r in zip(prec, rec)]
            fpr = [100 * b_ / (b_ + d) if b_ + d else 0.0 for b_, d in zip(fp, tn)]
            table4[(mech, b, thr)] = dict(tp=tp, fp=fp, fn=fn, tn=tn, prec=prec, rec=rec, f1=f1, fpr=fpr)
            lab = BN[b] if thr == 'P1' else ''
            print(f"{lab:9} & {thr} & {ms(tp)} & {ms(fp)} & {ms(fn)} & {ms(tn)} & {ms(prec)} & {ms(rec)} & {ms(f1)} & {ms(fpr)} \\\\")
    print('\\hline')

print("\n=== ranges for RQ1 text (P1, mechanism-aware) ===")
for k in ('prec', 'rec', 'f1', 'fpr'):
    vals = {b: mean(table4[(True, b, 'P1')][k]) for b in BENCHES}
    lo = min(vals, key=vals.get); hi = max(vals, key=vals.get)
    print(f"{k}: min {vals[lo]:.1f} ({lo}), max {vals[hi]:.1f} ({hi});", {b: round(v, 1) for b, v in vals.items()})
print("pool sizes (mean over runs):", {b: mean([sum(confusion_pool(c, False, True)[:4]) for c in
      [A.idx[(f'st_qwen_{b}_s{s}', 'full')] for s in range(1, 6)]]) for b in BENCHES})
print("file-level SmartBugs P1:", {k: ms(table4[(False, 'smartbugs', 'P1')][k]) for k in ('tp', 'fp', 'fn', 'tn', 'prec', 'fpr')})
print("file-level DVD P1 precision:", ms(table4[(False, 'dvd', 'P1')]['prec']))
print("old-rule F1 (runs with TP>0) vs new F1 (all runs), mech P1:")
for b in BENCHES:
    r = table4[(True, b, 'P1')]
    old = [f for f, tp in zip(r['f1'], r['tp']) if tp > 0] or [0.0]
    print(f"  {b}: old {mean(old):.1f}  new {mean(r['f1']):.1f}  (runs with TP=0: {sum(1 for t in r['tp'] if t == 0)})")

# ---------------------------------------------------------------- 2. FP reduction proper
print("\n=== False-positive reduction proper (share of unlabelled pool findings withheld), P1 and R1 ===")
fpred = {}
for det in DETS:
    for b in BENCHES:
        rows = []
        for s in range(1, 6):
            run = f'st_{det}_{b}_s{s}'
            if (run, 'full') not in A.idx:
                continue
            c = A.idx[(run, 'full')]
            tp, fp, fn, tn, _ = confusion_pool(c, False, True)
            tpl, fpl, fnl, tnl, _ = confusion_pool(c, True, True)
            N = tp + fp + fn + tn; K = tp + fn
            rows.append(dict(N=N, K=K, n=tp + fp, t=tp, n_low=tpl + fpl, t_low=tpl,
                             fp_red=100 * tn / (tn + fp) if tn + fp else 0.0,
                             fp_red_low=100 * tnl / (tnl + fpl) if tnl + fpl else 0.0,
                             tp_red=100 * fn / (tp + fn) if tp + fn else 0.0,
                             alert_red=100 * (fn + tn) / N if N else 0.0))
        fpred[(det, b)] = rows
        print(f"{det:9} {b:9} alert-cut P1 {mean([r['alert_red'] for r in rows]):5.1f}  FP-cut P1 {ms([r['fp_red'] for r in rows])}  "
              f"TP-cut P1 {mean([r['tp_red'] for r in rows]):5.1f}  FP-cut R1 {ms([r['fp_red_low'] for r in rows])}")

# ---------------------------------------------------------------- 3. random removal
print("\n=== Random-removal comparison (hypergeometric), P1, mechanism-aware ===")


def hyper_cdf(N, K, n, t):
    """P(X <= t), X ~ Hypergeom(N, K, n)."""
    den = comb(N, n)
    return sum(comb(K, k) * comb(N - K, n - k) for k in range(0, t + 1)) / den


rand = {}
for det in DETS:
    for b in BENCHES:
        rows = fpred[(det, b)]
        exp_tp = [r['n'] * r['K'] / r['N'] if r['N'] else 0 for r in rows]
        obs_tp = [r['t'] for r in rows]
        # pooled urn over the five runs
        N = sum(r['N'] for r in rows); K = sum(r['K'] for r in rows); n = sum(r['n'] for r in rows); t = sum(r['t'] for r in rows)
        p_le = hyper_cdf(N, K, n, t)
        p_ge = 1 - hyper_cdf(N, K, n, t - 1) if t > 0 else 1.0
        pool_prec = 100 * K / N if N else 0
        obs_prec = 100 * t / n if n else 0
        rand[(det, b)] = dict(exp_tp=mean(exp_tp), obs_tp=mean(obs_tp), p_le=p_le, p_ge=p_ge, pool_prec=pool_prec, obs_prec=obs_prec,
                              below=sum(1 for e, o in zip(exp_tp, obs_tp) if o < e))
        print(f"{det:9} {b:9} pool prec {pool_prec:5.1f} obs prec {obs_prec:5.1f}  E[TP] {mean(exp_tp):5.2f} obs TP {mean(obs_tp):5.2f}  "
              f"runs below random {rand[(det, b)]['below']}/5  P(TP<=obs) {p_le:.3g}  P(TP>=obs) {p_ge:.3g}")

json.dump({'table4': {f'{int(m)}|{b}|{t}': v for (m, b, t), v in table4.items()},
           'fpred': {f'{d}|{b}': v for (d, b), v in fpred.items()},
           'random': {f'{d}|{b}': v for (d, b), v in rand.items()}},
          open('/home/claude/analysis/final_revision_numbers.json', 'w'), indent=1)
print("\nwritten final_revision_numbers.json")
