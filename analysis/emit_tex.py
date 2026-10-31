# -*- coding: utf-8 -*-
"""Render the recomputed tables as LaTeX tabular bodies (same layout as the manuscript)."""
import math, json, sys
from recompute import Analysis, mean, sd, ci95, BENCHES, DETS, SIGS
import extra

BN = {'dvd': 'DVD', 'pygoat': 'PyGoat', 'nodegoat': 'NodeGoat', 'smartbugs': 'SmartBugs'}
DN = {'gemma': 'gemma-4-31B', 'qwen': 'qwen3-coder', 'nemotron': 'Nemotron-120B'}
DS = {'gemma': 'gemma', 'qwen': 'qwen', 'nemotron': 'Nemotron'}


def pm(v, d=0):
    return f"{mean(v):.{d}f} $\\pm$ {sd(v):.{d}f}"


def ms(v, d=1):
    return f"{mean(v):.{d}f}({sd(v):.{d}f})"


def f1(x, d=1):
    return f"{x:.{d}f}"


def sci(p):
    if p >= 0.01:
        return f"{p:.3f}"
    m, e = f"{p:.1e}".split('e')
    return f"{m}e$-${int(e[1:]):02d}"


def volume(A):
    V = A.table_volume(); L = []
    for det in DETS:
        for i, b in enumerate(BENCHES):
            r = V[(det, b)]
            lab = DN[det] if i == 0 else ''
            L.append(f"{lab:13} & {BN[b]:9} & {pm(r['detect'],1)} & {pm(r['cand'])} & {pm(r['base'])} & {pm(r['share'],1)} & "
                     f"{pm(r['ship_p1'])} & {pm(r['cut_p1'],1)} & [{r['ci_p1'][0]:.1f}, {r['ci_p1'][1]:.1f}] & {pm(r['ship_r1'])} & {pm(r['cut_r1'],1)} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def classification(A):
    """Table: finding-level confusion matrix, mechanism-aware block then file-level block."""
    L = []
    for mech, title in ((True, 'Mechanism-aware criterion'), (False, 'File-level criterion')):
        C = A.table_classification(mech=mech)
        L.append('\\multicolumn{10}{l}{\\textit{' + title + '}} \\\\')
        for b in BENCHES:
            for j, thr in enumerate(('P1', 'R1')):
                r = C[(b, thr)]
                lab = BN[b] if j == 0 else ''
                f1v = [f for f, tp in zip(r['f1'], r['tp']) if tp > 0] or [0.0]   # footnote: runs with >= 1 TP
                L.append(f"{lab:9} & {thr} & {ms(r['tp'])} & {ms(r['fp'])} & {ms(r['fn'])} & {ms(r['tn'])} & {ms(r['prec'])} & {ms(r['rec'])} & {ms(f1v)} & {ms(r['fpr'])} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def recall(A):
    R = A.table_recall(); L = []
    for b in BENCHES:
        for j, crit in enumerate(('file', 'mechanism')):
            r = R[(b, crit)]
            lab = BN[b] if j == 0 else ''
            L.append(f"{lab:9} & {'File' if crit == 'file' else 'Mechanism'} & {r['gt']} & {mean(r['detect']):.1f} & {ms(r['ret_p1'])} & {ms(r['ret_r1'])} & {ms(r['e2e_p1'])} & {ms(r['e2e_r1'])} \\\\")
    return '\n'.join(L)


def marginal(A):
    M = A.table_marginal(); L = []
    names = {'I': 'Identity', 'S': 'Source', 'C': 'Concern', 'P': 'PoC'}
    for s in 'ISCP':
        cells = []
        for b in BENCHES:
            if s == 'P' and b == 'smartbugs':      # PoC signal structurally unavailable on SmartBugs
                cells.append('---'); continue
            v = M[s][b][0]
            cells.append(f"${'+' if v >= 0 else '-'}{abs(v):.1f}$")
        L.append(f"{names[s]:8} & " + ' & '.join(cells) + " \\\\")
    return '\n'.join(L)


def ablation_models(A):
    AM = A.table_ablation_models(); L = []
    for det in DETS:
        for i, b in enumerate(BENCHES):
            r = AM[(det, b)]
            lab = DS[det] if i == 0 else ''
            cells = []
            for cfg in ('full', 'noidentity', 'noconcern', 'nosource', 'nopoc'):
                if r[cfg] is None:
                    cells += ['---', '---']
                else:
                    cells += [ms(r[cfg]['tp']), ms(r[cfg]['fp'])]
            L.append(f"{lab:8} & {BN[b]:9} & " + ' & '.join(cells) + " \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def powerset(A, with_prec=False):
    PS = A.table_powerset(); L = []
    order = [('Full', 'full'), ('$-$Identity', 'noidentity'), ('$-$Concern', 'noconcern'), ('$-$Source', 'nosource'), ('$-$PoC', 'nopoc'), None,
             ('Keep I,S', 'keep_IS'), ('Keep I,C', 'keep_IC'), ('Keep I,P', 'keep_IP'), ('Keep S,C', 'keep_SC'), ('Keep S,P', 'keep_SP'), ('Keep C,P', 'keep_CP'), None,
             ('Only I', 'only_I'), ('Only S', 'only_S'), ('Only C', 'only_C'), ('Only P', 'only_P')]
    for item in order:
        if item is None:
            L.append('\\hline'); continue
        name, cfg = item
        cells = []
        for b in BENCHES:
            r = PS[cfg][b]
            if r is None:
                cells += ['---', '---'] + (['---'] if with_prec else [])
            else:
                prec = [100 * a / (a + c) if a + c else 0.0 for a, c in zip(r['tp'], r['fp'])]
                cells += [ms(r['tp']), ms(r['fp'])] + ([f"{mean(prec):.1f}"] if with_prec else [])
        L.append(f"{name:12} & {','.join(SIGS[cfg]):7} & " + ' & '.join(cells) + " \\\\")
    return '\n'.join(L)


def significance(A):
    S = A.table_significance()
    order = [(det, b) for det in DETS for b in BENCHES]
    left = order[:6]; right = order[6:]
    abl = [('noidentity', '$-$Id '), ('noconcern', '$-$Con'), ('nosource', '$-$Src'), ('nopoc', '$-$PoC')]

    def half(det, b, a, name, first):
        r = S[(det, b, a)]
        p = sci(r['p']) + ('$^{*' + ('\\dagger' if r['rev'] else '') + '}$' if r['sig'] else '')
        lab_m = DS[det].lower() if first == 'both' else ''
        lab_b = BN[b] if first in ('both', 'bench') else ''
        return f"{lab_m:8} & {lab_b:9} & {name} & {r['full']:3} & {r['abl']:3} & {r['n']:4} & {p}"
    L = []
    for (dl, bl), (dr, br) in zip(left, right):
        for k, (a, name) in enumerate(abl):
            fl = 'both' if (k == 0 and bl == BENCHES[0]) else ('bench' if k == 0 else 'none')
            fr = 'both' if (k == 0 and br == BENCHES[0]) else ('bench' if k == 0 else 'none')
            L.append(half(dl, bl, a, name, fl) + '\n      & ' + half(dr, br, a, name, fr)[9:].lstrip() + ' \\\\')
    return '\n'.join(L)


def significance_simple(A):
    """Two half tables rendered as plain rows (model label only at first row of each model)."""
    S = A.table_significance()
    abl = [('noidentity', '$-$Id '), ('noconcern', '$-$Con'), ('nosource', '$-$Src'), ('nopoc', '$-$PoC')]
    cells = []
    for det in DETS:
        for b in BENCHES:
            for k, (a, name) in enumerate(abl):
                r = S[(det, b, a)]
                p = sci(r['p']) + ('$^{*' + ('\\dagger' if r['rev'] else '') + '}$' if r['sig'] else '')
                cells.append((det, b, k, f"{name} & {r['full']:3} & {r['abl']:3} & {r['n']:4} & {p}"))
    half = len(cells) // 2
    L = []
    for i in range(half):
        out = []
        for (det, b, k, body) in (cells[i], cells[half + i]):
            lab_m = DS[det].lower() if ((b == BENCHES[0] and k == 0) or i == 0) else ''
            lab_b = BN[b] if k == 0 else ''
            out.append(f"{lab_m:8} & {lab_b:9} & {body}")
        L.append(out[0] + '\n      & ' + out[1] + ' \\\\')
    return '\n'.join(L)


def kappa(A):
    K = A.table_kappa(); L = []
    for b in BENCHES:
        first = True
        for pair in ('I-S', 'I-C', 'I-P', 'S-C', 'S-P', 'C-P'):
            if (b, pair) not in K:
                continue
            k, phi, agr, n = K[(b, pair)]
            lab = BN[b] if first else ''; first = False
            if math.isnan(k) or math.isnan(phi) or (abs(k) < 1e-9 and abs(phi) < 1e-9):
                L.append(f"{lab:9} & {pair.replace('-', '--')} & {n:4} & ---      & ---      & --- \\\\")
            else:
                def sgn(x):
                    return ('$-$' if x < 0 else '') + f"{abs(x):.3f}"
                L.append(f"{lab:9} & {pair.replace('-', '--')} & {n:4} & {sgn(k)} & {sgn(phi)} & {agr:.1f} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def crossverifier(A, prec=None):
    """Table: controlled cross-model comparison, three frozen pools x three verifiers, n=9 per cell,
    with finding-level precision and retention (extra.cross_prec_ret)."""
    POOLS = ('gemma', 'qwen', 'nemotron')
    X = A.table_crossverifier(pools=POOLS)
    if prec is None:
        prec = extra.cross_prec_ret(A, pools=POOLS)
    L = []
    for pool in POOLS:
        for i, b in enumerate(BENCHES):
            for j, ver in enumerate(('nemotron', 'gemma', 'qwen')):
                r = X[(pool, b, ver)]; pr = prec[(pool, b, ver)]
                lab_p = (pool if pool != 'nemotron' else 'Nemotron') if (i == 0 and j == 0) else ''
                lab_b = BN[b] if j == 0 else ''
                L.append(f"{lab_p:8} & {lab_b:9} & {DS[ver]:8} & {r['rel']:5} & {mean(r['pool']):.0f}({sd(r['pool']):.0f}) & {ms(r['cut'])} & {r['ci'][0]:.1f}--{r['ci'][1]:.1f} & {ms(pr['prec'])} & {ms(pr['ret'])} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def adjudication(A=None, summary=None):
    """Table: adjudication of verifier decisions (from data/adjudication/summary.json)."""
    import os
    if summary is None:
        summary = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'adjudication', 'summary.json')
    S = json.load(open(summary))
    BN2 = {'dvd': 'DVD', 'pygoat': 'PyGoat', 'nodegoat': 'NodeGoat', 'smartbugs': 'SmartBugs'}
    L = ['%% (a) composition of each stratum (%, judge B)']
    for i, r in enumerate(S['rows']):
        lab = BN2[r['bench']] if r['stratum'] == 'shipped' else ''
        L.append(f"{lab:9} & {r['stratum']:8} & {r['pool']:3} & {r['n']:2} & {100*r['B_true']:.0f} & {100*r['B_over']:.0f} & {100*r['B_false']:.0f} & {100*r['agree_n']/r['n']:.0f} \\\\")
    L.append('%% (b) share of each class withheld by the verifier (%)')
    for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs', 'all'):
        cells = []
        for cls in ('TRUE', 'OVERSTATED', 'FALSE'):
            for judge in ('B', 'A', 'C'):
                v = S['selectivity'][judge][bench][cls]
                cells.append('---' if v is None or v != v else f"{100*v:.0f}")
        L.append(f"{(BN2.get(bench, 'All')):9} & " + ' & '.join(cells) + ' \\\\')
    return '\n'.join(L)


def repro(A):
    R = A.table_repro(); L = []
    for det in DETS:
        for i, b in enumerate(BENCHES):
            r = R[(det, b)]
            lab = DS[det] if i == 0 else ''
            L.append(f"{lab:8} & {BN[b]:9} & {r['sd_tot']:.2f} & {r['sd_det']:.2f} & {r['sd_ver']:.2f} & {r['cv']:.1f} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def poc(A):
    P = A.table_poc(); L = []
    for b in BENCHES:
        r = P[b]; e = r['emitted']
        pct = lambda x: f"{x} ({100 * x / e:.1f}\\%)" if e else f"{x}"
        L.append(f"{BN[b]:9} & {e:4} & {pct(r['triggered'])} & {pct(r['compiled_not'])} & {pct(r['failed'])} \\\\")
    return '\n'.join(L)


def poc_by_detector(A):
    """PoC states per detection model (new): emitted / triggered / compiled-not / failed, 5 runs pooled."""
    L = []
    for det in DETS:
        for i, b in enumerate(BENCHES):
            em = tr = cn = fc = 0
            for s in range(1, 6):
                c = A.idx[(f'st_{det}_{b}_s{s}', 'full')]
                for x in c['findings']:
                    if x['layer'] != 4 or not x['poc_code']:
                        continue
                    em += 1
                    if x['poc_compile'] is True and x['poc_trig'] is True: tr += 1
                    elif x['poc_compile'] is True: cn += 1
                    else: fc += 1
            lab = DS[det] if i == 0 else ''
            L.append(f"{lab:8} & {BN[b]:9} & {em:4} & {tr:3} & {cn:3} & {fc:4} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def provenance(A):
    P = A.table_provenance('all'); L = []
    for b in BENCHES:
        r = P[b]
        f = lambda n: f"{n:,}".replace(',', '\\,')
        L.append(f"{BN[b]:9} & {f(r['findings']):>9} & {f(r['cwe']):>8} & {f(r['l5']):>5} & {f(r['unmap']):>8} & {r['pct']:.1f} \\\\")
    return '\n'.join(L)


def agreement(A):
    M = extra.agreement_main(A); X = extra.agreement_cross(A); L = []
    for det in DETS:
        for i, b in enumerate(BENCHES):
            r = M[(det, b)]
            lab = DS[det] if i == 0 else ''
            L.append(f"{lab:8} & {BN[b]:9} & Nemotron & {r['n']:4} & {r['unanimous']:.1f} & {r['kappa']:.2f} \\\\")
        L.append('\\hline')
    for pool in ('gemma', 'qwen'):
        for ver in ('gemma', 'qwen'):
            for i, b in enumerate(BENCHES):
                r = X[(pool, ver, b)]
                lab = f"{pool} pool" if i == 0 else ''
                L.append(f"{lab:10} & {BN[b]:9} & {DS[ver]:8} & {r['n']:4} & {r['unanimous']:.1f} & {r['kappa']:.2f} \\\\")
            L.append('\\hline')
    return '\n'.join(L[:-1])


def cost(A):
    C = extra.cost(A); L = []
    for det in DETS:
        for i, b in enumerate(BENCHES):
            r = C[(det, b)]
            lab = DS[det] if i == 0 else ''
            L.append(f"{lab:8} & {BN[b]:9} & {mean(r['cands']):.0f} & {mean(r['det_min']):.0f} & {mean(r['calls']):.0f} & {mean(r['in_per_call']):.0f} & {mean(r['out_per_call']):.0f} & {mean(r['ver_min']):.1f} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def selectivity(A, mech=True):
    """Precision before/after verification and TP/FP removal rates, pooled over five runs."""
    L = []
    for det in DETS:
        for i, b in enumerate(BENCHES):
            tot = [0] * 6
            for s in range(1, 6):
                run = f'st_{det}_{b}_s{s}'
                base = A.idx[(run, 'baseline')]; full = A.idx[(run, 'full')]
                h = A.hits(run, mech)
                for k, (c, low) in enumerate(((base, False), (full, False), (full, True))):
                    for x, sh in zip(c['findings'], A.ship(c, low)):
                        if sh:
                            tot[2 * k + (0 if h[x['idx']] else 1)] += 1
            tpb, fpb, tp1, fp1, tpr, fpr = tot
            pb = 100 * tpb / (tpb + fpb); p1 = 100 * tp1 / (tp1 + fp1) if tp1 + fp1 else 0.0; pr = 100 * tpr / (tpr + fpr)
            lab = DS[det] if i == 0 else ''
            L.append(f"{lab:8} & {BN[b]:9} & {tpb / 5:.1f} & {fpb / 5:.1f} & {pb:.1f} & {p1:.1f} & {pr:.1f} & "
                     f"{100 * (1 - tp1 / tpb) if tpb else 0:.1f} & {100 * (1 - fp1 / fpb):.1f} & {100 * (1 - tpr / tpb) if tpb else 0:.1f} & {100 * (1 - fpr / fpb):.1f} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


def poc_cost(A):
    P = extra.poc_cost(A); L = []
    for det in ('gemma', 'qwen', 'nemotron'):
        for i, b in enumerate(('dvd', 'pygoat', 'nodegoat')):
            r = P[(det, b)]
            lab = DS[det] if i == 0 else ''
            L.append(f"{lab:8} & {BN[b]:9} & {r['tp_nopoc']:.1f} & {r['tp_full']:.1f} & {r['tp_ret']:.1f} & {r['fp_nopoc']:.1f} & {r['fp_full']:.1f} & {r['fp_ret']:.1f} & {r['prec_nopoc']:.1f} & {r['prec_full']:.1f} & {r['tp_ret_r1']:.1f} \\\\")
        L.append('\\hline')
    return '\n'.join(L[:-1])


if __name__ == '__main__':
    A = Analysis(cs='--cs' in sys.argv)
    which = [a for a in sys.argv[1:] if not a.startswith('--')] or ['poc', 'repro', 'volume', 'classification', 'recall', 'selectivity', 'adjudication', 'marginal', 'ablation_models', 'crossverifier', 'agreement', 'powerset', 'significance_simple', 'kappa', 'provenance', 'poc_by_detector', 'cost', 'poc_cost']
    for w in which:
        print(f'%%%% ---- {w} ----')
        print(globals()[w](A))
        print()
