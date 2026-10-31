# -*- coding: utf-8 -*-
"""Recompute every table of the manuscript from the per-finding records.

Usage: python3 recompute.py [--cs] [--json out.json]
  --cs   parse CWE labels case-sensitively (reproduces the submitted manuscript);
         default is case-insensitive (fixes the 'cwe-NN' labels of the Node.js rules).
"""
import pickle, re, math, json, sys, collections, statistics as st
from scipy.stats import binomtest, t as tdist
import gt as G

import os
PKL = os.environ.get('MSFV_PKL', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pkg.pkl'))
BENCHES = ('dvd', 'pygoat', 'nodegoat', 'smartbugs')
DETS = ('gemma', 'qwen', 'nemotron')
SIGS = {'full': 'ISCP', 'noidentity': 'SCP', 'noconcern': 'ISP', 'nosource': 'ICP', 'nopoc': 'ISC',
        'keep_IS': 'IS', 'keep_IC': 'IC', 'keep_IP': 'IP', 'keep_SC': 'SC', 'keep_SP': 'SP', 'keep_CP': 'CP',
        'only_I': 'I', 'only_S': 'S', 'only_C': 'C', 'only_P': 'P'}
GT = G.load_gt()
GTN = {b: len(GT[b]) for b in BENCHES}


def mean(v):
    return st.mean(v) if v else float('nan')


def sd(v):
    return st.stdev(v) if len(v) > 1 else 0.0


def ci95(v):
    n = len(v)
    if n < 2:
        return (float('nan'), float('nan'))
    h = tdist.ppf(0.975, n - 1) * sd(v) / math.sqrt(n)
    return (mean(v) - h, mean(v) + h)


def fmt(v, d=1):
    return f"{mean(v):.{d}f}({sd(v):.{d}f})"


def fm(fpath, gfile):
    return bool(fpath) and (fpath.endswith(gfile) or gfile.endswith(fpath))


class Analysis:
    def __init__(self, cs=False, pkl=None):
        self.cs = cs
        self.cfgs = pickle.load(open(pkl or PKL, 'rb'))
        self.idx = {(c['run'], c['config']): c for c in self.cfgs}
        self.runs = sorted({c['run'] for c in self.cfgs})
        self._pos = {}
        self._annotate()

    # ---- classes / positives ------------------------------------------------
    def cwe_nums(self, x):
        raw = x['cwe_raw']
        if not raw:
            return []
        s = ' '.join(str(v) for v in raw) if isinstance(raw, list) else str(raw)
        return re.findall(r'CWE-(\d+)', s) if self.cs else re.findall(r'CWE-?(\d+)', s, flags=re.I)

    def classes(self, x, bench):
        """(set of classes or None, source) — machine sources only (CWE table, L5 query)."""
        if x['layer'] == 5:
            m = G.L5MAP[bench].get((x.get('query') or '').strip().lower())
            return (m if m else None), 'L5'
        cls = set()
        for n in self.cwe_nums(x):
            cls |= G.CWEMAP[bench].get(n, set())
        return (cls if cls else None), 'CWE'

    def _annotate(self):
        """Per finding (L4 only): gt ids hit under file / mechanism criterion (suffix path match)."""
        for c in self.cfgs:
            if c['config'] != 'baseline':
                continue
            bench = c['bench']
            fileh, mechh = [], []
            for x in c['findings']:
                fh, mh = set(), set()
                if x['layer'] == 4:
                    cls, _ = self.classes(x, bench)
                    for g in GT[bench]:
                        if not fm(x['file'], g['file']):
                            continue
                        fh.add(g['id'])
                        if cls is None:
                            continue
                        if bench == 'smartbugs':
                            if cls & g['cats']:
                                mh.add(g['id'])
                        elif g['cat'] in cls:
                            mh.add(g['id'])
                fileh.append(fh); mechh.append(mh)
            self._pos[c['run']] = (fileh, mechh)

    def hits(self, run, mech):
        return self._pos[run][1 if mech else 0]

    # ---- per configuration metrics -----------------------------------------
    def ship(self, c, low=False):
        return [x['ship_low'] if low else x['ship_med'] for x in c['findings']]

    def shipped_count(self, c, low=False):
        return sum(self.ship(c, low))

    def baseline(self, run):
        return self.idx[(run, 'baseline')]

    def confusion(self, c, low=False, mech=True):
        h = self.hits(c['run'], mech)
        tp = fp = fn = tn = 0
        for x, sh in zip(c['findings'], self.ship(c, low)):
            pos = bool(h[x['idx']])
            if sh and pos: tp += 1
            elif sh: fp += 1
            elif pos: fn += 1
            else: tn += 1
        return tp, fp, fn, tn

    def caught(self, c, low=False, mech=True):
        h = self.hits(c['run'], mech)
        got = set()
        for x, sh in zip(c['findings'], self.ship(c, low)):
            if sh:
                got |= h[x['idx']]
        return got

    def detect(self, run, mech=True):
        """GT items surfaced by detection = caught by the baseline (after self-rejection)."""
        return self.caught(self.baseline(run), low=False, mech=mech)

    def fpcut(self, c, low=False):
        b = self.shipped_count(self.baseline(c['run']))
        return 100.0 * (b - self.shipped_count(c, low)) / b

    def series(self, det, bench, config, fn, seeds=range(1, 6), ver=None):
        out = []
        for s in seeds:
            run = f'st_{det}{"-v" + ver if ver else ""}_{bench}_s{s}'
            if (run, config) in self.idx:
                out.append(fn(self.idx[(run, config)]))
        return out

    # ---- Table: volume ------------------------------------------------------
    def table_volume(self):
        rows = {}
        for det in DETS:
            for bench in BENCHES:
                r = {}
                r['detect'] = self.series(det, bench, 'baseline', lambda c: len(self.detect(c['run'], True)))
                r['cand'] = self.series(det, bench, 'baseline', lambda c: len(c['findings']))
                r['base'] = self.series(det, bench, 'baseline', lambda c: self.shipped_count(c))
                r['share'] = [100.0 * (a - b) / a for a, b in zip(r['cand'], r['base'])]
                r['ship_p1'] = self.series(det, bench, 'full', lambda c: self.shipped_count(c))
                r['cut_p1'] = self.series(det, bench, 'full', lambda c: self.fpcut(c))
                r['ci_p1'] = ci95(r['cut_p1'])
                r['ship_r1'] = self.series(det, bench, 'full', lambda c: self.shipped_count(c, True))
                r['cut_r1'] = self.series(det, bench, 'full', lambda c: self.fpcut(c, True))
                r['removed_p1'] = [a - b for a, b in zip(r['base'], r['ship_p1'])]
                rows[(det, bench)] = r
        return rows

    # ---- Table: classification (qwen) --------------------------------------
    def table_classification(self, det='qwen', config='full', mech=True):
        rows = {}
        for bench in BENCHES:
            for low, thr in ((False, 'P1'), (True, 'R1')):
                confs = self.series(det, bench, config, lambda c: self.confusion(c, low, mech))
                tp, fp, fn, tn = [[c[i] for c in confs] for i in range(4)]
                prec = [100 * a / (a + b) if a + b else 0.0 for a, b in zip(tp, fp)]
                rec = [100 * a / (a + b) if a + b else 0.0 for a, b in zip(tp, fn)]
                f1 = [2 * p * r / (p + r) if p + r else 0.0 for p, r in zip(prec, rec)]
                fpr = [100 * b / (b + d) if b + d else 0.0 for b, d in zip(fp, tn)]
                rows[(bench, thr)] = dict(tp=tp, fp=fp, fn=fn, tn=tn, prec=prec, rec=rec, f1=f1, fpr=fpr,
                                          prec_pooled=100 * sum(tp) / (sum(tp) + sum(fp)) if sum(tp) + sum(fp) else 0.0)
        return rows

    # ---- Table: recall (qwen) ----------------------------------------------
    def table_recall(self, det='qwen', config='full'):
        rows = {}
        for bench in BENCHES:
            for mech, crit in ((False, 'file'), (True, 'mechanism')):
                det_n = self.series(det, bench, 'baseline', lambda c: len(self.detect(c['run'], mech)))
                r = dict(gt=GTN[bench], detect=det_n)
                for low, thr in ((False, 'p1'), (True, 'r1')):
                    caught = self.series(det, bench, config, lambda c: len(self.caught(c, low, mech)))
                    r['ret_' + thr] = [100 * a / b if b else 0.0 for a, b in zip(caught, det_n)]
                    r['e2e_' + thr] = [100 * a / GTN[bench] for a in caught]
                    r['caught_' + thr] = caught
                rows[(bench, crit)] = r
        return rows

    # ---- Table: power set / LOO --------------------------------------------
    def table_powerset(self, det='qwen', low=False, mech=True):
        rows = {}
        for cfg in SIGS:
            rows[cfg] = {}
            for bench in BENCHES:
                confs = self.series(det, bench, cfg, lambda c: self.confusion(c, low, mech))
                if not confs:
                    rows[cfg][bench] = None
                    continue
                rows[cfg][bench] = dict(tp=[c[0] for c in confs], fp=[c[1] for c in confs],
                                        ship=[c[0] + c[1] for c in confs])
        return rows

    def table_ablation_models(self, low=False, mech=True):
        rows = {}
        for det in DETS:
            for bench in BENCHES:
                r = {}
                for cfg in ('full', 'noidentity', 'noconcern', 'nosource', 'nopoc'):
                    confs = self.series(det, bench, cfg, lambda c: self.confusion(c, low, mech))
                    r[cfg] = None if not confs else dict(tp=[c[0] for c in confs], fp=[c[1] for c in confs],
                                                         ship=[c[0] + c[1] for c in confs])
                rows[(det, bench)] = r
        return rows

    def table_marginal(self, det='qwen'):
        ps = self.table_powerset(det)
        bysig = {SIGS[k]: v for k, v in ps.items()}
        out = {}
        for sig in 'ISCP':
            out[sig] = {}
            for bench in BENCHES:
                diffs = []
                for k, v in bysig.items():
                    if sig in k or v[bench] is None:
                        continue
                    withk = ''.join(ch for ch in 'ISCP' if ch in k or ch == sig)
                    w = bysig.get(withk)
                    if w is None or w[bench] is None:
                        continue
                    diffs.append(mean(w[bench]['ship']) - mean(v[bench]['ship']))
                out[sig][bench] = (mean(diffs), len(diffs))
        return out

    # ---- Table: significance ------------------------------------------------
    @staticmethod
    def holm(ps):
        m = len(ps); order = sorted(range(m), key=lambda i: ps[i]); adj = [0] * m; cur = 0
        for rank, i in enumerate(order):
            cur = max(cur, min(1.0, (m - rank) * ps[i])); adj[i] = cur
        return adj

    def discordant(self, det, bench, abl, low=False, ref='full'):
        fo = ao = 0
        for s in range(1, 6):
            run = f'st_{det}_{bench}_s{s}'
            if (run, abl) not in self.idx or (run, ref) not in self.idx:
                continue
            for x, y in zip(self.ship(self.idx[(run, ref)], low), self.ship(self.idx[(run, abl)], low)):
                if x and not y: fo += 1
                elif y and not x: ao += 1
        return fo, ao

    def table_significance(self, low=False):
        rows = {}
        for det in DETS:
            for bench in BENCHES:
                abls = ['noidentity', 'noconcern', 'nosource', 'nopoc']
                res = {}
                for a in abls:
                    fo, ao = self.discordant(det, bench, a, low)
                    n = fo + ao
                    p = binomtest(min(fo, ao), n, 0.5).pvalue if n > 0 else 1.0
                    res[a] = [fo, ao, n, p]
                adj = self.holm([res[a][3] for a in abls])
                for a, pa in zip(abls, adj):
                    fo, ao, n, p = res[a]
                    expected_dec = a != 'nopoc'  # removing I/C/S expected to ship fewer (fo > ao)
                    rev = (pa < 0.05) and ((ao > fo) if expected_dec else (fo > ao))
                    rows[(det, bench, a)] = dict(full=fo, abl=ao, n=n, p_raw=p, p=pa, sig=pa < 0.05, rev=rev)
        return rows

    # ---- Table: kappa -------------------------------------------------------
    def keyvec(self, run, cfg):
        d = collections.OrderedDict()
        for x in self.idx[(run, cfg)]['findings']:
            for e in (x['ver'] or []):
                key = (e['file'], e['function'])
                d[key] = d.get(key, False) or (e['verdict'] == 'confirmed')
        return d

    @staticmethod
    def kappa_phi(a, b):
        n = len(a)
        n11 = sum(1 for x, y in zip(a, b) if x and y); n00 = sum(1 for x, y in zip(a, b) if not x and not y)
        n10 = sum(1 for x, y in zip(a, b) if x and not y); n01 = n - n11 - n00 - n10
        po = (n11 + n00) / n; pa = (n11 + n10) / n; pb = (n11 + n01) / n
        pe = pa * pb + (1 - pa) * (1 - pb)
        k = (po - pe) / (1 - pe) if pe < 1 else float('nan')
        den = math.sqrt((n11 + n10) * (n01 + n00) * (n11 + n01) * (n10 + n00))
        phi = (n11 * n00 - n10 * n01) / den if den else float('nan')
        return k, phi, 100 * po, n

    def table_kappa(self, det='qwen'):
        names = {'I': 'only_I', 'S': 'only_S', 'C': 'only_C', 'P': 'only_P'}
        rows = {}
        for bench in BENCHES:
            for a, b in (('I', 'S'), ('I', 'C'), ('I', 'P'), ('S', 'C'), ('S', 'P'), ('C', 'P')):
                A, B = [], []
                ok = True
                for s in range(1, 6):
                    run = f'st_{det}_{bench}_s{s}'
                    if (run, names[a]) not in self.idx or (run, names[b]) not in self.idx:
                        ok = False; break
                    da = self.keyvec(run, names[a]); db = self.keyvec(run, names[b])
                    A += list(da.values()); B += [db.get(k, False) for k in da]
                if not ok:
                    continue
                rows[(bench, f'{a}-{b}')] = self.kappa_phi(A, B)
        return rows

    # ---- Table: cross-verifier ---------------------------------------------
    def table_crossverifier(self, pools=('gemma', 'qwen'), seeds=(1, 2, 3)):
        """Frozen candidate pools (detection model `pool`, seeds 1-3) adjudicated by each verifier.
        Nemotron verifier = the main-experiment runs of that pool (full, full_rep2, full_rep3 where
        present); gemma/qwen verifiers = st_<pool>-v<ver>_<bench>_s<seed>/{full,full_rep2,full_rep3}.
        Every available pass is used, so n is 9 where all three passes exist for all three seeds."""
        rows = {}
        for pool in pools:
            for bench in BENCHES:
                for ver in ('nemotron', 'gemma', 'qwen'):
                    cuts, pools_ = [], []
                    for s_ in seeds:
                        run = f'st_{pool}_{bench}_s{s_}' if ver == 'nemotron' else f'st_{pool}-v{ver}_{bench}_s{s_}'
                        for cfg in ('full', 'full_rep2', 'full_rep3'):
                            if (run, cfg) in self.idx:
                                c = self.idx[(run, cfg)]
                                cuts.append(self.fpcut(c)); pools_.append(self.shipped_count(self.baseline(run)))
                    pools3 = [self.shipped_count(self.baseline(f'st_{pool}_{bench}_s{s_}')) for s_ in seeds]
                    rows[(pool, bench, ver)] = dict(cut=cuts, pool=pools3, ci=ci95(cuts), n=len(cuts),
                                                    rel='self' if pool == ver else 'cross')
        return rows

    def table_crossverifier_alt(self):
        """Alternative: Nemotron verifier restricted to seeds 1-3 (same seeds as other verifiers)."""
        rows = {}
        for pool in ('gemma', 'qwen'):
            for bench in BENCHES:
                cuts, pools = [], []
                for s in range(1, 4):
                    run = f'st_{pool}_{bench}_s{s}'
                    for cfg in ('full', 'full_rep2', 'full_rep3'):
                        if (run, cfg) in self.idx:
                            c = self.idx[(run, cfg)]
                            cuts.append(self.fpcut(c)); pools.append(self.shipped_count(self.baseline(run)))
                rows[(pool, bench, 'nemotron')] = dict(cut=cuts, pool=pools, ci=ci95(cuts), n=len(cuts))
        return rows

    # ---- Table: repro (a) variance decomposition ----------------------------
    def table_repro(self):
        rows = {}
        for det in DETS:
            for bench in BENCHES:
                tot = self.series(det, bench, 'full', lambda c: self.shipped_count(c))
                run = f'st_{det}_{bench}_s1'
                ver = [self.shipped_count(self.idx[(run, cfg)]) for cfg in ('full', 'full_rep2', 'full_rep3') if (run, cfg) in self.idx]
                sd_tot, sd_ver = sd(tot), sd(ver)
                sd_det = math.sqrt(max(0.0, sd_tot ** 2 - sd_ver ** 2))
                rows[(det, bench)] = dict(sd_tot=sd_tot, sd_det=sd_det, sd_ver=sd_ver, cv=100 * sd_ver / mean(ver),
                                          tot=tot, ver=ver)
        return rows

    # ---- Table: PoC states --------------------------------------------------
    def table_poc(self, config='full'):
        rows = {}
        for bench in BENCHES:
            em = tr = cn = fc = 0
            for det in DETS:
                for s in range(1, 6):
                    c = self.idx[(f'st_{det}_{bench}_s{s}', config)]
                    for x in c['findings']:
                        if x['layer'] != 4 or not x['poc_code']:
                            continue
                        em += 1
                        if x['poc_compile'] is True and x['poc_trig'] is True: tr += 1
                        elif x['poc_compile'] is True: cn += 1
                        else: fc += 1
            rows[bench] = dict(emitted=em, triggered=tr, compiled_not=cn, failed=fc)
        return rows

    # ---- Table: provenance --------------------------------------------------
    def table_provenance(self, which='all'):
        rows = {}
        for bench in BENCHES:
            n = cwe = l5 = 0
            for c in self.cfgs:
                if c['bench'] != bench:
                    continue
                if which == 'main' and c['pool_verified_by']:
                    continue
                for x in c['findings']:
                    n += 1
                    cls, src = self.classes(x, bench)
                    if cls is None:
                        continue
                    if src == 'L5': l5 += 1
                    else: cwe += 1
            rows[bench] = dict(findings=n, cwe=cwe, l5=l5, unmap=n - cwe - l5, pct=100 * (n - cwe - l5) / n)
        return rows


if __name__ == '__main__':
    cs = '--cs' in sys.argv
    A = Analysis(cs=cs)
    print('mode:', 'case-sensitive (paper)' if cs else 'case-insensitive (corrected)')
    V = A.table_volume()
    for k, r in V.items():
        print(k, f"detect {mean(r['detect']):.1f} cand {mean(r['cand']):.0f}±{sd(r['cand']):.0f} base {mean(r['base']):.0f}±{sd(r['base']):.0f} "
              f"share {mean(r['share']):.1f}±{sd(r['share']):.1f} shipP1 {mean(r['ship_p1']):.0f}±{sd(r['ship_p1']):.0f} cut {mean(r['cut_p1']):.1f}±{sd(r['cut_p1']):.1f} "
              f"CI [{r['ci_p1'][0]:.1f},{r['ci_p1'][1]:.1f}] shipR1 {mean(r['ship_r1']):.0f}±{sd(r['ship_r1']):.0f} cut {mean(r['cut_r1']):.1f}±{sd(r['cut_r1']):.1f}")
