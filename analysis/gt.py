# -*- coding: utf-8 -*-
"""Ground truth + matching criteria (file-level and mechanism-aware)."""
import json, os, re, collections

_HERE = os.path.dirname(os.path.abspath(__file__))
GT_DIR = os.environ.get('MSFV_GT_DIR', os.path.join(os.path.dirname(_HERE), 'experiments', 'ground_truth'))
SB_JSON = os.environ.get('MSFV_SB_JSON', os.path.join(GT_DIR, 'smartbugs_vulnerabilities.json'))
LINE_WINDOW = 8

# ---- Table cwemap (paper) : CWE number -> set of benchmark classes -------------
CWEMAP = {
    'dvd': {
        '284': {'access_control', 'access_control_upgrade', 'access_control_calldata'},
        '285': {'access_control', 'access_control_upgrade', 'access_control_calldata'},
        '841': {'reentrancy'}, '400': {'denial_of_service'}, '807': {'oracle_manipulation'},
        '665': {'access_control_upgrade'},
        '190': {'logic_rounding', 'logic_price'}, '682': {'logic_rounding', 'logic_price'},
        '681': {'logic_rounding'}, '837': {'message_replay'}, '294': {'message_replay'},
        '367': {'governance_flashloan'}, '754': {'arbitrary_call'},
    },
    'pygoat': {
        '89': {'sql_injection'}, '78': {'command_injection'}, '94': {'command_injection'},
        '95': {'command_injection'}, '502': {'insecure_deserialization'}, '611': {'xxe'},
        '79': {'xss'}, '80': {'xss'}, '918': {'ssrf'},
        '565': {'broken_access_control'}, '639': {'broken_access_control'},
        '668': {'broken_access_control'}, '784': {'broken_access_control'},
    },
    'nodegoat': {
        '94': {'ssji'}, '95': {'ssji'}, '89': {'nosql_injection'}, '943': {'nosql_injection'},
        '256': {'weak_crypto'}, '327': {'weak_crypto'}, '522': {'weak_crypto'},
        '400': {'redos'}, '1333': {'redos'}, '284': {'broken_access_control'},
        '639': {'broken_access_control'}, '79': {'xss'}, '116': {'xss'}, '918': {'ssrf'},
    },
    'smartbugs': {
        '284': {'access_control'}, '285': {'access_control'}, '347': {'access_control'},
        '841': {'reentrancy'}, '190': {'arithmetic'}, '191': {'arithmetic'}, '681': {'arithmetic'},
        '682': {'arithmetic'}, '400': {'denial_of_service'},
        '20': {'unchecked_low_level_calls'}, '252': {'unchecked_low_level_calls'}, '778': {'unchecked_low_level_calls'},
        '330': {'bad_randomness'}, '338': {'bad_randomness'}, '341': {'bad_randomness'},
        '367': {'front_running', 'time_manipulation'}, '294': {'time_manipulation'},
    },
}

# ---- L5 query -> benchmark classes (fallback when no CWE) ----------------------
L5MAP = {
    'dvd': {
        'reentrancy_check': {'reentrancy'},
        'access_control_gaps': {'access_control', 'access_control_upgrade', 'access_control_calldata'},
        'arbitrary_external_call': {'arbitrary_call'},
        'oracle_manipulation': {'oracle_manipulation'},
        'flash_loan_exposure': {'governance_flashloan'},
    },
    'smartbugs': {
        'reentrancy_check': {'reentrancy'},
        'access_control_gaps': {'access_control'},
        'arbitrary_external_call': set(),
        'oracle_manipulation': set(),
        'flash_loan_exposure': set(),
        'insecure_crypto': {'bad_randomness'},
    },
    'pygoat': {
        'auth_and_authorization': {'broken_access_control'},
        'injection_sinks': {'sql_injection', 'command_injection'},
        'ssrf_and_path_traversal': {'ssrf'},
        'deserialization_and_eval': {'insecure_deserialization'},
        'insecure_crypto': set(),
        'sandbox_or_eval_escape': {'command_injection'},
        'xss': {'xss'},
    },
    'nodegoat': {
        'auth_and_authorization': {'broken_access_control'},
        'injection_sinks': {'nosql_injection', 'ssji'},
        'ssrf_and_path_traversal': {'ssrf'},
        'deserialization_and_eval': {'ssji'},
        'insecure_crypto': {'weak_crypto'},
        'sandbox_or_eval_escape': {'ssji'},
        'xss': {'xss'},
    },
}


def load_gt():
    gt = {}
    d = json.load(open(os.path.join(GT_DIR, 'dvd.json')))['challenges']
    gt['dvd'] = [dict(id=c['challenge'], file=c['contract'], cat=c['category'], lines=None) for c in d]
    for b in ('pygoat', 'nodegoat'):
        d = json.load(open(os.path.join(GT_DIR, f'{b}.json')))['vulns']
        gt[b] = [dict(id=v['name'], file=v['file'], cat=v['category'], lines=None) for v in d]
    sb = json.load(open(SB_JSON))
    items = []
    for e in sb:
        cat_dir = e['path'].split('/')[1]
        lines = set()
        cats = set()
        for v in e.get('vulnerabilities', []):
            lines.update(v.get('lines') or [])
            cats.add(v.get('category'))
        items.append(dict(id=os.path.basename(e['path']), file=e['path'], cat=cat_dir,
                          cats=cats, lines=lines))
    gt['smartbugs'] = items
    return gt


def file_match(fpath, gfile):
    if not fpath:
        return False
    return fpath.endswith(gfile) or gfile.endswith(fpath) or os.path.basename(fpath) == os.path.basename(gfile)


def finding_classes(x, bench):
    """(classes:set|None, source) using only machine sources: CWE table, then L5 query."""
    if x['layer'] == 5:
        m = L5MAP[bench].get((x.get('query') or '').strip().lower())
        return (m if m else None), 'L5'
    cls = set()
    for n in x['cwe']:
        cls |= CWEMAP[bench].get(n, set())
    return (cls if cls else None), 'CWE'


def l5_files(x, shipped_only):
    """Files an L5 record pins: cited files (verdict != FP when shipped_only)."""
    out = []
    if x['ver']:
        for e in x['ver']:
            if not e['file']:
                continue
            if shipped_only and e['verdict'] == 'false_positive':
                continue
            out.append(e['file'])
    return out
