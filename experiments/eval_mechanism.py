#!/usr/bin/env python3
"""Mechanism-aware recall (paper §4.2 FP_t): a TP counts only when a SHIPPED
finding lands on the ground-truth file AND its vulnerability CLASS matches the
GT category — not merely the file.

Finding class is resolved by a documented precedence (most→least objective):
  1. CWE from the semgrep finding metadata        (objective; registry+custom)
  2. L5 global-query name                          (semantic query = its class)
  3. rule_id / analysis keyword fallback           (heuristic; LAST resort)
  4. UNMAPPABLE                                     (counted + reported, never silently matched)

GT category → canonical class uses an explicit table; smartbugs SWC categories
map through the official SWC→CWE registry. Everything is logged so the
unmappable rate is visible (a reviewer-facing number, not hidden).
"""
from __future__ import annotations

import os
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.join(os.environ.get("MSFV_ROOT", Path(__file__).resolve().parent.parent), "experiments"))
import eval_recall as E  # _is_shipped, _finding_file, _l5_caught_files

# --------------------------------------------------------------------------- #
# Canonical classes + mappings                                                #
# --------------------------------------------------------------------------- #

# CWE → canonical class (objective primary signal).
CWE_TO_CANON = {
    "78": "command_injection", "77": "command_injection",
    "89": "sql_injection",
    "943": "nosql_injection",
    "79": "xss", "80": "xss",
    "94": "code_injection", "95": "code_injection",      # eval / SSJI / SSTI
    "502": "insecure_deserialization",
    "611": "xxe",
    "918": "ssrf",
    "1333": "redos", "400": "dos", "730": "dos",
    "22": "path_traversal", "98": "file_inclusion",
    "256": "weak_crypto", "327": "weak_crypto", "328": "weak_crypto",
    "326": "weak_crypto", "916": "weak_crypto", "330": "bad_randomness",
    "284": "access_control", "862": "access_control", "863": "access_control",
    "639": "access_control", "287": "access_control", "732": "access_control",
    "841": "reentrancy",
    "190": "arithmetic", "191": "arithmetic", "682": "arithmetic",
    "252": "unchecked_call", "1164": "unchecked_call",
    "362": "front_running", "829": "time_manipulation",
    "120": "memory_safety", "119": "memory_safety", "416": "memory_safety",
    "134": "format_string",
}

# Official SWC → CWE (smartbugs categories are SWC families; SWC registry table).
# Only the families present in the smartbugs dataset dir names.
SWC_DIR_TO_CANON = {
    "access_control": "access_control",          # SWC-105/106/115
    "arithmetic": "arithmetic",                  # SWC-101
    "bad_randomness": "bad_randomness",          # SWC-120
    "denial_of_service": "dos",                  # SWC-113/128
    "front_running": "front_running",            # SWC-114
    "reentrancy": "reentrancy",                  # SWC-107
    "short_addresses": "arithmetic",             # SWC-133 (encoding) ~ input
    "time_manipulation": "time_manipulation",    # SWC-116
    "unchecked_low_level_calls": "unchecked_call",  # SWC-104
    "other": "other",
}

# GT category label (DVD/pygoat/nodegoat) → canonical class.
GTCAT_TO_CANON = {
    # pygoat / nodegoat
    "command_injection": "command_injection", "sql_injection": "sql_injection",
    "nosql_injection": "nosql_injection", "xss": "xss", "xxe": "xxe",
    "ssrf": "ssrf", "insecure_deserialization": "insecure_deserialization",
    "broken_access_control": "access_control", "ssji": "code_injection",
    "redos": "redos", "weak_crypto": "weak_crypto",
    # DVD
    "reentrancy": "reentrancy", "access_control": "access_control",
    "access_control_calldata": "access_control",
    "access_control_upgrade": "access_control",
    "arbitrary_call": "arbitrary_call",
    "oracle_manipulation": "oracle_manipulation",
    "governance_flashloan": "governance_flashloan",
    "logic_price": "oracle_manipulation", "logic_rounding": "arithmetic",
    "denial_of_service": "dos", "message_replay": "access_control",
}

# L5 global-query name → canonical class (L5 findings carry no CWE; the query
# IS the class). Covers the expanded Solidity pack + web/c packs.
L5QUERY_TO_CANON = {
    "reentrancy_check": "reentrancy",
    "flash_loan_exposure": "oracle_manipulation",
    "oracle_manipulation": "oracle_manipulation",
    "arbitrary_external_call": "arbitrary_call",
    "access_control_gaps": "access_control",
    "auth_and_authorization": "access_control",
    "trust_boundary_violations": "unchecked_call",
    "injection_sinks": "command_injection",
    "command_injection": "command_injection",
    "deserialization_and_eval": "insecure_deserialization",
    "sandbox_or_eval_escape": "code_injection",
    "ssrf_and_request_forwarding": "ssrf", "ssrf_and_path_traversal": "ssrf",
    "secrets_and_credentials": "weak_crypto", "insecure_crypto": "weak_crypto",
    "buffer_overflow": "memory_safety", "use_after_free_and_double_free": "memory_safety",
    "format_string": "format_string", "integer_issues": "arithmetic",
    "nginx_lua_injection": "code_injection",
    "auth_and_shared_dict_misuse": "access_control",
}

# Keyword fallback (LAST resort, only when no CWE and not L5). Logged separately.
_KW = [
    ("command_injection", ["command-inj", "subprocess", "os.system", "shell=true", "os-command"]),
    ("sql_injection", ["sql-inj", "raw-query", "raw sql", "sqli", " sql injection"]),
    ("nosql_injection", ["nosql", "$where"]),
    ("code_injection", ["ssji", "eval(", "server-side javascript"]),
    ("insecure_deserialization", ["deserial", "pickle", "yaml.load", "unserialize"]),
    ("xss", ["xss", "cross-site script", "|safe", "autoescape"]),
    ("xxe", ["xxe", "external entity"]),
    ("ssrf", ["ssrf", "server-side request"]),
    ("redos", ["redos", "catastrophic backtrack"]),
    ("weak_crypto", ["md5", "sha1", "weak hash", "plaintext password"]),
    ("reentrancy", ["reentran"]),
    ("access_control", ["access control", "onlyowner", "missing access", "idor", "authoriz", "unprotected"]),
    ("oracle_manipulation", ["oracle", "spot price", "price manip", "getmarketprice", "twap"]),
    ("arbitrary_call", ["arbitrary call", "arbitrary external", "delegatecall"]),
    ("governance_flashloan", ["governance", "flash loan", "flashloan"]),
    ("unchecked_call", ["unchecked", "return value", "low-level call"]),
    ("arithmetic", ["overflow", "underflow", "rounding"]),
    ("memory_safety", ["buffer overflow", "use-after-free", "use after free", "out-of-bounds"]),
    ("dos", ["denial of service", "unbounded loop", "gas limit"]),
]


# Gas-optimization / style / best-practice lints — NOT security weaknesses.
# These come from the registry packs and are correctly un-mappable to a vuln
# class; they must be bucketed as "non-security" (not "UNMAPPABLE"), else they
# inflate the apparent classification-failure rate. L4/verify drop them anyway.
_NON_SECURITY = (
    "non-payable", "custom-error", "array-length", "nested-if",
    "short-revert", "multiple-require", "state-variable-read", "ownable2step",
    "increment", "msg-value-multicall", "storage-gap", "performance",
    "gas", "naming", "style", "unused", "shadow", "literal", "todo",
    "use-", "prefer-", "cache-",
)


def finding_canon(r):
    """Return (canonical_class_or_None, source) for one finding.

    source ∈ {CWE, L5-query, keyword, non-security, UNMAPPABLE}. "non-security"
    is a gas/style lint (correctly not a vuln class); "UNMAPPABLE" is a genuine
    classification failure — only the latter is the reviewer-facing risk."""
    f = r.get("finding") or {}
    rid_low = str(f.get("rule_id", "")).lower()
    if r.get("layer") == 4 and any(t in rid_low for t in _NON_SECURITY):
        return None, "non-security"
    if r.get("layer") == 5:
        q = (r.get("query") or "").strip().lower()
        return L5QUERY_TO_CANON.get(q), "L5-query"
    cwe = f.get("cwe")
    if cwe:
        # cwe may be "CWE-79", ["CWE-79"], "CWE-79: ..." — pull the number
        s = cwe[0] if isinstance(cwe, list) and cwe else str(cwe)
        m = re.search(r"(\d+)", s)
        if m and m.group(1) in CWE_TO_CANON:
            return CWE_TO_CANON[m.group(1)], "CWE"
    # fallback: keyword on rule_id + analysis
    txt = (str(f.get("rule_id", "")) + " " + str(f.get("message", "")) + " " +
           str(r.get("analysis", ""))).lower()
    for canon, kws in _KW:
        if any(k in txt for k in kws):
            return canon, "keyword"
    return None, "UNMAPPABLE"


def gt_canon(category, is_smartbugs=False):
    if is_smartbugs:
        return SWC_DIR_TO_CANON.get(category, category)
    return GTCAT_TO_CANON.get(category, category)


def mechanism_caught(findings, gt_items, file_key, cat_key, name_key,
                     shipped_only, is_smartbugs, src_counter):
    caught = set()
    for r in findings:
        if r.get("layer") not in (4, 5):
            continue
        if shipped_only and not E._is_shipped(r):
            continue
        canon, src = finding_canon(r)
        src_counter[src] += 1
        if canon is None:
            continue
        # which file(s) does this finding pin?
        if r.get("layer") == 5:
            files = [Path(x).name for x in E._l5_caught_files([r], shipped_only)
                     if not x.startswith("{")]
        else:
            fp = E._finding_file(r)
            files = [Path(fp).name] if fp else []
        for it in gt_items:
            if Path(it[file_key]).name in files and canon == gt_canon(it[cat_key], is_smartbugs):
                caught.add(it[name_key])
    return caught
