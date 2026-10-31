# -*- coding: utf-8 -*-
"""Aggregate the two judges' adjudications against the hidden strata / labels."""
import json, os, glob, collections, math, os
OUT = os.path.dirname(os.path.abspath(__file__))
items = {it['id']: it for it in json.load(open(f'{OUT}/items.json'))}
hidden = {h['id']: h for h in json.load(open(f'{OUT}/hidden.json'))}
POOL = {('dvd', 'shipped'): 34, ('dvd', 'withheld'): 70, ('pygoat', 'shipped'): 56, ('pygoat', 'withheld'): 50,
        ('nodegoat', 'shipped'): 6, ('nodegoat', 'withheld'): 13, ('smartbugs', 'shipped'): 154, ('smartbugs', 'withheld'): 199}
LABELS = ['TRUE_DOCUMENTED', 'TRUE_UNDOCUMENTED', 'OVERSTATED', 'FALSE', 'UNSURE']
J = {'A': {}, 'B': {}}
for f in glob.glob(f'{OUT}/results/*.json'):
    judge = os.path.basename(f)[0]
    for r in json.load(open(f)):
        J[judge][r['id']] = r
missing = {j: sorted(set(items) - set(J[j])) for j in J}
extra = {j: sorted(set(J[j]) - set(items)) for j in J}
print('missing per judge:', {j: len(v) for j, v in missing.items()}, 'extra:', {j: len(v) for j, v in extra.items()})
ids = [i for i in items if i in J['A'] and i in J['B']]
print('items with both judgments:', len(ids))


def coarse(l):
    return {'TRUE_DOCUMENTED': 'TRUE', 'TRUE_UNDOCUMENTED': 'TRUE', 'OVERSTATED': 'OVERSTATED', 'FALSE': 'FALSE', 'UNSURE': 'UNSURE'}[l]


def kappa(a, b, cats):
    n = len(a); po = sum(1 for x, y in zip(a, b) if x == y) / n
    pe = sum((sum(1 for x in a if x == c) / n) * (sum(1 for y in b if y == c) / n) for c in cats)
    return (po - pe) / (1 - pe) if pe < 1 else float('nan'), po


la = [J['A'][i]['label'] for i in ids]; lb = [J['B'][i]['label'] for i in ids]
k5, po5 = kappa(la, lb, LABELS)
k3, po3 = kappa([coarse(x) for x in la], [coarse(x) for x in lb], ['TRUE', 'OVERSTATED', 'FALSE', 'UNSURE'])
kb, pob = kappa([coarse(x) == 'TRUE' for x in la], [coarse(x) == 'TRUE' for x in lb], [True, False])
kf, pof = kappa([x == 'FALSE' for x in la], [x == 'FALSE' for x in lb], [True, False])
print(f'agreement: 5-class po={po5:.3f} kappa={k5:.3f} | 3-class po={po3:.3f} kappa={k3:.3f} | true-vs-not po={pob:.3f} kappa={kb:.3f} | false-vs-not po={pof:.3f} kappa={kf:.3f}')
conf = collections.Counter((coarse(J['A'][i]['label']), coarse(J['B'][i]['label'])) for i in ids)
print('confusion A x B (3-class):')
for a in ['TRUE', 'OVERSTATED', 'FALSE', 'UNSURE']:
    print(f'  A={a:10}', {b: conf[(a, b)] for b in ['TRUE', 'OVERSTATED', 'FALSE', 'UNSURE']})

# ---- per benchmark x stratum rates (unweighted within stratum = estimate of that stratum's population rate)
rows = []
for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs'):
    for stratum in ('shipped', 'withheld'):
        sub = [i for i in ids if items[i]['benchmark'] == bench and hidden[i]['stratum'] == stratum]
        n = len(sub)
        d = dict(bench=bench, stratum=stratum, n=n, pool=POOL[(bench, stratum)])
        for j in ('A', 'B'):
            c = collections.Counter(coarse(J[j][i]['label']) for i in sub)
            d[f'{j}_true'] = c['TRUE'] / n; d[f'{j}_over'] = c['OVERSTATED'] / n; d[f'{j}_false'] = c['FALSE'] / n
            d[f'{j}_unsure'] = c['UNSURE'] / n
        # consensus (both agree on the coarse class)
        agree = [i for i in sub if coarse(J['A'][i]['label']) == coarse(J['B'][i]['label'])]
        c = collections.Counter(coarse(J['A'][i]['label']) for i in agree)
        d['agree_n'] = len(agree); d['C_true'] = c['TRUE'] / n; d['C_over'] = c['OVERSTATED'] / n; d['C_false'] = c['FALSE'] / n
        d['C_disagree'] = 1 - len(agree) / n
        # benchmark-label view
        d['label_tp'] = sum(1 for i in sub if hidden[i]['label_tp_mech']) / n
        rows.append(d)
print('\nbench      stratum  n  pool | A: true over false | B: true over false | consensus: true over false disagree | label-TP')
for d in rows:
    print(f"{d['bench']:10} {d['stratum']:8} {d['n']:2} {d['pool']:4} | {d['A_true']:.2f} {d['A_over']:.2f} {d['A_false']:.2f} | {d['B_true']:.2f} {d['B_over']:.2f} {d['B_false']:.2f} | {d['C_true']:.2f} {d['C_over']:.2f} {d['C_false']:.2f} {d['C_disagree']:.2f} | {d['label_tp']:.2f}")

# ---- population-weighted selectivity: P(withheld | class) per benchmark and pooled
print('\nSelectivity (population-weighted by stratum pool size): fraction of each class that the verifier WITHHELD')
def sel(judge_label):
    out = {}
    for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs', 'all'):
        w = collections.Counter(); tot = collections.Counter()
        for i in ids:
            b = items[i]['benchmark']
            if bench != 'all' and b != bench: continue
            st = hidden[i]['stratum']
            n_s = sum(1 for k in ids if items[k]['benchmark'] == b and hidden[k]['stratum'] == st)
            wt = POOL[(b, st)] / n_s
            cls = judge_label(i)
            if cls is None: continue
            tot[cls] += wt
            if st == 'withheld': w[cls] += wt
        out[bench] = {c: (w[c] / tot[c] if tot[c] else float('nan'), tot[c]) for c in ('TRUE', 'OVERSTATED', 'FALSE')}
    return out
for name, fn in (('judge A', lambda i: coarse(J['A'][i]['label'])), ('judge B', lambda i: coarse(J['B'][i]['label'])),
                 ('consensus', lambda i: coarse(J['A'][i]['label']) if coarse(J['A'][i]['label']) == coarse(J['B'][i]['label']) else None)):
    S = sel(fn)
    print(f'  {name}:')
    for bench, d in S.items():
        print(f"    {bench:10} " + '  '.join(f"{c}: withheld {v[0]*100:5.1f}% (est. pool {v[1]:6.1f})" for c, v in d.items()))

# ---- composition of the verified pool (weighted): what share of candidates is hallucinated?
print('\nEstimated composition of the candidates that reach the verifier (weighted), consensus where agreed, else split:')
for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs'):
    comp = collections.Counter(); N = 0
    for i in ids:
        if items[i]['benchmark'] != bench: continue
        st = hidden[i]['stratum']; n_s = sum(1 for k in ids if items[k]['benchmark'] == bench and hidden[k]['stratum'] == st)
        wt = POOL[(bench, st)] / n_s; N += wt
        for j in ('A', 'B'):
            comp[coarse(J[j][i]['label'])] += wt / 2
    print(f"  {bench:10} pool={N:.0f}  " + '  '.join(f"{c}: {comp[c]/N*100:5.1f}%" for c in ('TRUE', 'OVERSTATED', 'FALSE', 'UNSURE')))

# ---- relation to benchmark labels: among label-negative shipped findings, how many are TRUE per the judges?
print('\nLabel-negative (benchmark says FP) findings: judges say TRUE / OVERSTATED / FALSE (unweighted, both judges pooled)')
for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs'):
    for st in ('shipped', 'withheld'):
        sub = [i for i in ids if items[i]['benchmark'] == bench and hidden[i]['stratum'] == st and not hidden[i]['label_tp_mech']]
        c = collections.Counter(coarse(J[j][i]['label']) for i in sub for j in ('A', 'B'))
        n = 2 * len(sub) or 1
        print(f"  {bench:10} {st:8} n={len(sub):2}  TRUE {c['TRUE']/n*100:5.1f}%  OVERSTATED {c['OVERSTATED']/n*100:5.1f}%  FALSE {c['FALSE']/n*100:5.1f}%")
print('\nLabel-positive findings (benchmark says TP): judges agree TRUE?')
for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs'):
    sub = [i for i in ids if items[i]['benchmark'] == bench and hidden[i]['label_tp_mech']]
    c = collections.Counter(coarse(J[j][i]['label']) for i in sub for j in ('A', 'B'))
    n = 2 * len(sub) or 1
    print(f"  {bench:10} n={len(sub):2}  TRUE {c['TRUE']/n*100:5.1f}%  OVERSTATED {c['OVERSTATED']/n*100:5.1f}%  FALSE {c['FALSE']/n*100:5.1f}%")

# ---- verifier verdict vs judge (withheld = FP or downgraded)
print('\nWithheld findings by verifier verdict (false_positive vs downgraded) and judge consensus:')
for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs'):
    for verdict in ('false_positive', 'downgraded'):
        sub = [i for i in ids if items[i]['benchmark'] == bench and hidden[i]['stratum'] == 'withheld' and hidden[i]['verifier_verdicts'] and all(v == verdict for v in hidden[i]['verifier_verdicts'])]
        c = collections.Counter(coarse(J[j][i]['label']) for i in sub for j in ('A', 'B')); n = 2 * len(sub) or 1
        print(f"  {bench:10} {verdict:14} n={len(sub):2}  TRUE {c['TRUE']/n*100:5.1f}%  OVERSTATED {c['OVERSTATED']/n*100:5.1f}%  FALSE {c['FALSE']/n*100:5.1f}%")

# ---- dump merged table for human review
merged = []
for i in ids:
    merged.append(dict(id=i, benchmark=items[i]['benchmark'], stratum=hidden[i]['stratum'], file=items[i]['file'], line=items[i]['line'],
                       rule=items[i]['rule_id'], verifier=hidden[i]['verifier_verdicts'], label_tp=hidden[i]['label_tp_mech'],
                       A=J['A'][i]['label'], B=J['B'][i]['label'], agree=coarse(J['A'][i]['label']) == coarse(J['B'][i]['label']),
                       A_conf=J['A'][i].get('confidence'), B_conf=J['B'][i].get('confidence'),
                       A_just=J['A'][i].get('justification'), B_just=J['B'][i].get('justification')))
json.dump(merged, open(f'{OUT}/merged.json', 'w'), indent=1, ensure_ascii=False)
import csv
with open(f'{OUT}/merged.csv', 'w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=list(merged[0].keys())); w.writeheader(); w.writerows(merged)
print('\ndisagreements (coarse):', sum(1 for m in merged if not m['agree']), 'of', len(merged))
