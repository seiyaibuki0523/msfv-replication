# -*- coding: utf-8 -*-
"""Additional analyses requested by the reviewers / pre-submission audit:
  A. finding-level agreement of the verification stage across repeated passes (Fleiss kappa)
  B. precision for every configuration (LOO, power set, cross-verifier)
  C. cost / latency (verification calls, tokens per call, wall-clock)
  D. run-configuration inventory (the '821' figure)
  E. seed handling evidence (repeated passes with the same seed differ)
  F. PoC recall cost (TPs suppressed by the PoC verdict) and PoC nature
"""
import collections, math, re, statistics as st, json
from recompute import Analysis, mean, sd, ci95, BENCHES, DETS, SIGS


def fleiss_kappa(rows, k=2):
    """rows: list of per-subject count vectors (length k) that sum to n raters."""
    rows = [r for r in rows if sum(r) > 0]
    if not rows:
        return float('nan')
    n = sum(rows[0]); N = len(rows)
    pj = [sum(r[j] for r in rows) / (N * n) for j in range(k)]
    Pi = [(sum(x * x for x in r) - n) / (n * (n - 1)) for r in rows]
    Pbar = sum(Pi) / N; Pe = sum(p * p for p in pj)
    return (Pbar - Pe) / (1 - Pe) if Pe < 1 else float('nan')


def agreement_main(A, low=False):
    """Seed-1 pool of each detector x benchmark, verified three times by Nemotron (full, full_rep2, full_rep3)."""
    out = {}
    for det in DETS:
        for bench in BENCHES:
            run = f'st_{det}_{bench}_s1'
            cfgs = [A.idx[(run, c)] for c in ('full', 'full_rep2', 'full_rep3') if (run, c) in A.idx]
            if len(cfgs) < 3:
                continue
            base = A.baseline(run)
            ships = [A.ship(c, low) for c in cfgs]
            rows = []; unanimous = 0; n = 0; flips = 0
            for i, bx in enumerate(base['findings']):
                if not bx['ship_med']:      # never reaches the verifier
                    continue
                votes = [s[i] for s in ships]
                yes = sum(votes); rows.append([yes, 3 - yes]); n += 1
                if yes in (0, 3): unanimous += 1
                else: flips += 1
            out[(det, bench)] = dict(n=n, unanimous=100 * unanimous / n, kappa=fleiss_kappa(rows),
                                     counts=[sum(s) for s in ships])
    return out


def agreement_cross(A, low=False):
    """Frozen pools (gemma, qwen; seeds 1-3) verified three times by gemma / qwen verifiers."""
    out = {}
    for pool in ('gemma', 'qwen'):
        for ver in ('gemma', 'qwen'):
            for bench in BENCHES:
                rows = []; unanimous = 0; n = 0
                for s in range(1, 4):
                    run = f'st_{pool}-v{ver}_{bench}_s{s}'
                    cfgs = [A.idx[(run, c)] for c in ('full', 'full_rep2', 'full_rep3')]
                    base = A.baseline(run)
                    ships = [A.ship(c, low) for c in cfgs]
                    for i, bx in enumerate(base['findings']):
                        if not bx['ship_med']:
                            continue
                        yes = sum(s_[i] for s_ in ships); rows.append([yes, 3 - yes]); n += 1
                        if yes in (0, 3): unanimous += 1
                out[(pool, ver, bench)] = dict(n=n, unanimous=100 * unanimous / n, kappa=fleiss_kappa(rows))
    return out


def precision_tables(A):
    """Precision (mean of per-run, and pooled) for LOO across detectors, power set (qwen), cross-verifier."""
    res = {'loo': {}, 'powerset': {}, 'cross': {}}
    for det in DETS:
        for bench in BENCHES:
            for cfg in ('full', 'noidentity', 'noconcern', 'nosource', 'nopoc'):
                confs = A.series(det, bench, cfg, lambda c: A.confusion(c, False, True))
                if not confs:
                    continue
                tp = [c[0] for c in confs]; fp = [c[1] for c in confs]
                prec = [100 * a / (a + b) if a + b else 0.0 for a, b in zip(tp, fp)]
                res['loo'][(det, bench, cfg)] = dict(tp=tp, fp=fp, prec=prec,
                                                     pooled=100 * sum(tp) / (sum(tp) + sum(fp)) if sum(tp) + sum(fp) else 0.0)
    for cfg in SIGS:
        for bench in BENCHES:
            confs = A.series('qwen', bench, cfg, lambda c: A.confusion(c, False, True))
            if not confs:
                continue
            tp = [c[0] for c in confs]; fp = [c[1] for c in confs]
            prec = [100 * a / (a + b) if a + b else 0.0 for a, b in zip(tp, fp)]
            res['powerset'][(cfg, bench)] = dict(tp=tp, fp=fp, prec=prec,
                                                 pooled=100 * sum(tp) / (sum(tp) + sum(fp)) if sum(tp) + sum(fp) else 0.0)
    for pool in ('gemma', 'qwen'):
        for bench in BENCHES:
            for ver in ('nemotron', 'gemma', 'qwen'):
                confs = []
                if ver == 'nemotron':
                    runs = [(f'st_{pool}_{bench}_s1', c) for c in ('full', 'full_rep2', 'full_rep3')] + \
                           [(f'st_{pool}_{bench}_s{s}', 'full') for s in (2, 3)]
                else:
                    runs = [(f'st_{pool}-v{ver}_{bench}_s{s}', c) for s in (1, 2, 3) for c in ('full', 'full_rep2', 'full_rep3')]
                for run, cfg in runs:
                    confs.append(A.confusion(A.idx[(run, cfg)], False, True))
                tp = [c[0] for c in confs]; fp = [c[1] for c in confs]
                prec = [100 * a / (a + b) if a + b else 0.0 for a, b in zip(tp, fp)]
                # retention of detector-caught vulnerabilities (mechanism-aware)
                rets = []
                for run, cfg in runs:
                    d = A.detect(run, True)
                    rets.append(100 * len(A.caught(A.idx[(run, cfg)], False, True)) / len(d) if d else float('nan'))
                res['cross'][(pool, bench, ver)] = dict(tp=tp, fp=fp, prec=prec, ret=rets,
                                                        pooled=100 * sum(tp) / (sum(tp) + sum(fp)) if sum(tp) + sum(fp) else 0.0)
    return res


def secs(h):
    m = re.match(r'(?:(\d+)h )?(?:(\d+)m )?(\d+)s', h or '')
    return None if not m else int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60 + int(m.group(3))


def cost(A):
    """Detection wall-clock (baseline config) and verification calls/tokens/wall-clock ('full' config,
    which is the first configuration of each verification batch, so its token counters are verify-only)."""
    out = {}
    for det in DETS:
        for bench in BENCHES:
            det_t, ver_t, calls, tin, tout, cands, verified = [], [], [], [], [], [], []
            for s in range(1, 6):
                run = f'st_{det}_{bench}_s{s}'
                b = A.idx[(run, 'baseline')]; f = A.idx[(run, 'full')]
                det_t.append(secs(b['meta'].get('elapsed_human')))
                ver_t.append(secs(f['meta'].get('elapsed_human')))
                calls.append(f['ss'].get('layer55_call_count'))
                tin.append(f['ss'].get('total_opus_input_tokens')); tout.append(f['ss'].get('total_opus_output_tokens'))
                cands.append(len(b['findings'])); verified.append(A.shipped_count(b))
            out[(det, bench)] = dict(det_min=[t / 60 for t in det_t], ver_min=[t / 60 for t in ver_t], calls=calls,
                                     tok_in=tin, tok_out=tout, cands=cands, verified=verified,
                                     in_per_call=[a / c for a, c in zip(tin, calls) if c],
                                     out_per_call=[a / c for a, c in zip(tout, calls) if c])
    return out


def inventory(A):
    cnt = collections.Counter()
    for c in A.cfgs:
        fam = 'cross' if c['pool_verified_by'] else 'main'
        cnt[(fam, c['config'])] += 1
    return cnt


def seed_evidence(A):
    """Same pool, same seed parameter, three verification passes: how often do verdict sets differ?"""
    out = []
    for det in DETS:
        for bench in BENCHES:
            run = f'st_{det}_{bench}_s1'
            cfgs = [A.idx[(run, c)] for c in ('full', 'full_rep2', 'full_rep3') if (run, c) in A.idx]
            if len(cfgs) < 3:
                continue
            s = [A.ship(c) for c in cfgs]
            n = sum(1 for x in A.baseline(run)['findings'] if x['ship_med'])
            diff12 = sum(1 for a, b in zip(s[0], s[1]) if a != b); diff13 = sum(1 for a, b in zip(s[0], s[2]) if a != b)
            out.append((det, bench, n, [sum(x) for x in s], diff12, diff13))
    return out


def poc_cost(A):
    """TP/FP retained when the PoC verdict is added to the other three signals (Full vs -PoC), per detector."""
    out = {}
    for det in DETS:
        for bench in ('dvd', 'pygoat', 'nodegoat'):
            f = A.series(det, bench, 'full', lambda c: A.confusion(c, False, True))
            n = A.series(det, bench, 'nopoc', lambda c: A.confusion(c, False, True))
            if not f or not n:
                continue
            tpf, fpf = sum(c[0] for c in f), sum(c[1] for c in f)
            tpn, fpn = sum(c[0] for c in n), sum(c[1] for c in n)
            fr1 = A.series(det, bench, 'full', lambda c: A.confusion(c, True, True))
            nr1 = A.series(det, bench, 'nopoc', lambda c: A.confusion(c, True, True))
            tpf1, fpf1 = sum(c[0] for c in fr1), sum(c[1] for c in fr1)
            tpn1, fpn1 = sum(c[0] for c in nr1), sum(c[1] for c in nr1)
            out[(det, bench)] = dict(tp_full=tpf / 5, fp_full=fpf / 5, tp_nopoc=tpn / 5, fp_nopoc=fpn / 5,
                                     tp_ret=100 * tpf / tpn if tpn else float('nan'), fp_ret=100 * fpf / fpn if fpn else float('nan'),
                                     prec_full=100 * tpf / (tpf + fpf) if tpf + fpf else 0, prec_nopoc=100 * tpn / (tpn + fpn) if tpn + fpn else 0,
                                     tp_ret_r1=100 * tpf1 / tpn1 if tpn1 else float('nan'), fp_ret_r1=100 * fpf1 / fpn1 if fpn1 else float('nan'))
    return out


if __name__ == '__main__':
    import sys
    A = Analysis(cs='--cs' in sys.argv)
    print('=== A. finding-level agreement, main pools (seed 1, 3 Nemotron passes), P1 ship decision')
    for k, v in agreement_main(A).items():
        print(f"  {k}: n={v['n']} unanimous={v['unanimous']:.1f}% Fleiss kappa={v['kappa']:.3f} shipped={v['counts']}")
    print('=== A. cross-verifier pools (3 seeds x 3 passes)')
    for k, v in agreement_cross(A).items():
        print(f"  {k}: n={v['n']} unanimous={v['unanimous']:.1f}% kappa={v['kappa']:.3f}")
    print('=== C. cost')
    for k, v in cost(A).items():
        print(f"  {k}: detection {mean(v['det_min']):.0f} min; verify calls {mean(v['calls']):.0f}; in/out tokens per call {mean(v['in_per_call']):.0f}/{mean(v['out_per_call']):.0f}; verify wall {mean(v['ver_min']):.1f} min")
    print('=== D. inventory', sum(inventory(A).values()))
    for k, v in sorted(inventory(A).items()):
        print('  ', k, v)
    print('=== E. seed evidence (same seed, three passes): shipped counts and #findings whose decision differs')
    for r in seed_evidence(A):
        print('  ', r)
    print('=== F. PoC cost (P1, pooled over 5 runs)')
    for k, v in poc_cost(A).items():
        print(f"  {k}: TP {v['tp_nopoc']:.1f}->{v['tp_full']:.1f} ({v['tp_ret']:.1f}% kept)  FP {v['fp_nopoc']:.1f}->{v['fp_full']:.1f} ({v['fp_ret']:.1f}% kept)  prec {v['prec_nopoc']:.1f}->{v['prec_full']:.1f}  R1: TP kept {v['tp_ret_r1']:.1f}% FP kept {v['fp_ret_r1']:.1f}%")


def cross_prec_ret(A, pools=('gemma', 'qwen', 'nemotron'), seeds=(1, 2, 3)):
    """Finding-level precision and retention of detector-surfaced vulnerabilities (mechanism-aware,
    precision-first) for every cross-verifier cell, using the same n=9 run set as
    Analysis.table_crossverifier (three seeds x three passes)."""
    res = {}
    for pool in pools:
        for bench in BENCHES:
            for ver in ('nemotron', 'gemma', 'qwen'):
                prec, rets = [], []
                for s_ in seeds:
                    run = f'st_{pool}_{bench}_s{s_}' if ver == 'nemotron' else f'st_{pool}-v{ver}_{bench}_s{s_}'
                    for cfg in ('full', 'full_rep2', 'full_rep3'):
                        if (run, cfg) not in A.idx:
                            continue
                        c = A.idx[(run, cfg)]
                        tp, fp, fn, tn = A.confusion(c, False, True)
                        prec.append(100 * tp / (tp + fp) if tp + fp else 0.0)
                        d = A.detect(run, True)
                        rets.append(100 * len(A.caught(c, False, True)) / len(d) if d else float('nan'))
                res[(pool, bench, ver)] = dict(prec=prec, ret=rets, n=len(prec))
    return res
