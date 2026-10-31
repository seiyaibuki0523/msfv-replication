# -*- coding: utf-8 -*-
"""Build the adjudication sample: qwen detection, seed 1, precision-first point.
Strata: per benchmark, 40 verifier-withheld + 40 verifier-shipped L4 findings.
Judges see: file, line, rule, scanner message, snippet, detector analysis, and the
documented (ground-truth) entries for that file. They do NOT see the verifier verdict,
the PoC state, or our label-based TP/FP flag (kept in hidden.json)."""
import json, os, os, random, sys, collections
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'analysis'))
from recompute import Analysis
import gt as G

random.seed(20260910)
A = Analysis(cs=False)
GT = G.load_gt()
PKG = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ablation')
OUT = os.path.dirname(os.path.abspath(__file__))
N = 40
BENCH_DIR = {'dvd': 'dvd', 'pygoat': 'pygoat', 'nodegoat': 'nodegoat', 'smartbugs': 'smartbugs'}


def gt_for_file(bench, path):
    out = []
    for g in GT[bench]:
        if path.endswith(g['file']) or g['file'].endswith(path):
            if bench == 'smartbugs':
                out.append(dict(file=g['file'], categories=sorted(g['cats']), lines=sorted(g['lines'])))
            else:
                out.append(dict(id=g['id'], file=g['file'], category=g['cat']))
    return out


items, hidden = [], []
for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs'):
    run = f'st_qwen_{bench}_s1'
    raw_full = json.load(open(f'{PKG}/{run}/full/findings.json'))
    base = A.idx[(run, 'baseline')]; full = A.idx[(run, 'full')]
    h = A.hits(run, True); hf = A.hits(run, False)
    pools = {'shipped': [], 'withheld': []}
    for xb, xf in zip(base['findings'], full['findings']):
        if xb['layer'] != 4 or not xb['ship_med']:
            continue            # never reached the verifier
        (pools['shipped'] if xf['ship_med'] else pools['withheld']).append(xf['idx'])
    for stratum, idxs in pools.items():
        chosen = random.sample(idxs, min(N, len(idxs)))
        for i in chosen:
            r = raw_full[i]; f = r.get('finding') or {}
            iid = f'{bench}-{i:04d}'
            items.append(dict(
                id=iid, benchmark=bench, source_root=f'<BENCHMARK_CHECKOUTS>/{BENCH_DIR[bench]}',
                file=f.get('file'), line=f.get('line'), end_line=f.get('end_line'),
                rule_id=(f.get('rule_id') or '').split('.')[-1], cwe=f.get('cwe'),
                scanner_message=f.get('message'), snippet=f.get('code'),
                detector_analysis=r.get('analysis'),
                documented_entries_for_this_file=gt_for_file(bench, f.get('file') or ''),
            ))
            ver = r.get('verification') or []
            hidden.append(dict(id=iid, stratum=stratum, verifier_verdicts=[e.get('verdict') for e in ver],
                               verifier_reasons=[(e.get('reason') or '')[:200] for e in ver],
                               severity_override=r.get('severity_override'),
                               label_tp_mech=bool(h[i]), label_tp_file=bool(hf[i]), gt_ids_mech=sorted(h[i]),
                               poc_compile=((r.get('poc') or {}).get('validation') or {}).get('poc_compile'),
                               poc_trig=((r.get('poc') or {}).get('validation') or {}).get('poc_triggers_bug')))
        print(bench, stratum, 'available', len(idxs), 'sampled', len(chosen))

json.dump(items, open(f'{OUT}/items.json', 'w'), indent=1, ensure_ascii=False)
json.dump(hidden, open(f'{OUT}/hidden.json', 'w'), indent=1, ensure_ascii=False)
# mixed batches: per benchmark, shipped + withheld items shuffled together and split in two halves,
# with an independent shuffle per judge
os.makedirs(f'{OUT}/batches', exist_ok=True)
for judge in ('A', 'B'):
    for bench in ('dvd', 'pygoat', 'nodegoat', 'smartbugs'):
        sub = [it for it in items if it['benchmark'] == bench]
        rnd = random.Random(sum(map(ord, judge + bench)))
        rnd.shuffle(sub)
        halves = [sub[0::2], sub[1::2]] if len(sub) > 24 else [sub]
        for k, part in enumerate(halves, 1):
            json.dump(part, open(f'{OUT}/batches/{judge}_{bench}_b{k}.json', 'w'), indent=1, ensure_ascii=False)
print('items', len(items))
