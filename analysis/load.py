# -*- coding: utf-8 -*-
"""Load the MSFV data package (st_*/<config>/{findings,metadata,scan_state}.json)
into a compact pickle for table recomputation.

Run-dir naming:
  st_<det>_<bench>_s<seed>             main experiments (verifier = Nemotron)
  st_<pool>-v<verifier>_<bench>_s<seed> cross-verifier (frozen pool)
"""
import json, glob, os, re, sys, pickle, collections
from datetime import datetime

PKG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'ablation')
OUT = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pkg.pkl')
BENCHES = ('dvd', 'pygoat', 'nodegoat', 'smartbugs')
RUN_RE = re.compile(r'^st_(?P<det>[a-z]+)(?:-v(?P<ver>[a-z]+))?_(?P<bench>dvd|pygoat|nodegoat|smartbugs)_s(?P<seed>\d+)$')


def self_rejected(r):
    if r.get('layer') != 4:
        return False
    a = (r.get('analysis') or '').strip().split('\n', 1)[0].lower()
    return a.startswith('confirmed: no') and 'unclear' not in a


def shipped(r, low=False):
    """The four ship rules (Section IV-B). low=True -> recall-first threshold."""
    if self_rejected(r):
        return False
    sev_ov = (r.get('severity_override') or '').lower()
    v = r.get('verification')
    if isinstance(v, list) and v:
        verds = [e.get('verdict') for e in v if isinstance(e, dict)]
        if verds and all(d == 'false_positive' for d in verds):
            return False
        if (not low) and verds and all(d in ('false_positive', 'downgraded') for d in verds) \
                and not any(d == 'confirmed' for d in verds):
            return False
    if sev_ov == 'info':
        return False
    return True


def cwe_numbers(c):
    """Return list of CWE numbers (as strings) from a cwe field of any shape."""
    if not c:
        return []
    if isinstance(c, list):
        s = ' '.join(str(x) for x in c)
    else:
        s = str(c)
    return re.findall(r'CWE-?(\d+)', s, flags=re.I) or re.findall(r'\b(\d{2,4})\b', s)


def compact(r, idx):
    f = r.get('finding') or {}
    v = r.get('verification')
    ver = None
    if isinstance(v, list):
        ver = [dict(file=e.get('file') or '', function=e.get('function') or '',
                    verdict=e.get('verdict'), severity=e.get('severity'))
               for e in v if isinstance(e, dict)]
    poc = r.get('poc') if isinstance(r.get('poc'), dict) else None
    pv = (poc or {}).get('validation') or {}
    return dict(
        idx=idx,
        layer=r.get('layer'),
        file=f.get('file') or '',
        line=f.get('line'),
        rule_id=f.get('rule_id') or '',
        cwe=cwe_numbers(f.get('cwe')),
        cwe_raw=f.get('cwe'),
        query=r.get('query'),
        self_rej=self_rejected(r),
        first_line=(r.get('analysis') or '').strip().split('\n', 1)[0][:40] if isinstance(r.get('analysis'), str) else None,
        sev_ov=(r.get('severity_override') or None),
        ver=ver,
        l5_text=(r.get('findings') if r.get('layer') == 5 else None),
        poc_code=bool((poc or {}).get('code')),
        poc_compile=pv.get('poc_compile'),
        poc_trig=pv.get('poc_triggers_bug'),
        poc_method=pv.get('poc_method') or (poc or {}).get('method'),
        ship_med=shipped(r, low=False),
        ship_low=shipped(r, low=True),
    )


def main():
    configs = []
    for rd in sorted(glob.glob(os.path.join(PKG, 'st_*'))):
        name = os.path.basename(rd)
        m = RUN_RE.match(name)
        if not m:
            print('skip', name); continue
        g = m.groupdict()
        manifest = None
        mp = os.path.join(rd, 'manifest.json')
        if os.path.exists(mp):
            manifest = json.load(open(mp))
        for cd in sorted(os.listdir(rd)):
            d = os.path.join(rd, cd)
            if not os.path.isdir(d):
                continue
            fp, mdp, ssp = (os.path.join(d, x) for x in ('findings.json', 'metadata.json', 'scan_state.json'))
            if not os.path.exists(fp):
                continue
            recs = json.load(open(fp))
            meta = json.load(open(mdp)) if os.path.exists(mdp) else {}
            ss = {}
            if os.path.exists(ssp):
                s = json.load(open(ssp))
                ss = {k: s.get(k) for k in ('created_at', 'updated_at', 'total_opus_input_tokens',
                                            'total_opus_output_tokens', 'total_cost_usd',
                                            'layer4_call_count', 'layer5_call_count', 'layer55_call_count',
                                            'layer4_cache_hits', 'layer55_cache_hits', 'target_id')}
                ss['n_semgrep'] = len(s.get('semgrep_results') or [])
                ss['n_filtered'] = len(s.get('filtered_findings') or [])
                ss['n_selected_files'] = len(s.get('selected_files') or [])
            configs.append(dict(
                run=name, det=g['det'], ver=(g['ver'] or 'nemotron'), pool_verified_by=g['ver'],
                bench=g['bench'], seed=int(g['seed']), config=cd, meta=meta, manifest=manifest,
                ss=ss, findings=[compact(r, i) for i, r in enumerate(recs)]))
            # sanity: ship rules reproduce metadata.shipped
            n = sum(1 for x in configs[-1]['findings'] if x['layer'] in (4, 5) and x['ship_med'])
            if meta.get('shipped') is not None and n != meta['shipped']:
                print('SHIP MISMATCH', name, cd, n, meta['shipped'])
    print('configs', len(configs))
    pickle.dump(configs, open(OUT, 'wb'))


if __name__ == '__main__':
    main()
