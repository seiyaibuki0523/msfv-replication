"""
Context bundle builder.

Packages the complete context Claude Opus needs to analyse a single finding:
  1. Full body of the function containing the finding
  2. Full bodies of every function in its transitive call chain
     (BFS through call_graph until we hit external boundaries)
  3. State variables in the affected file
  4. Access-control metadata for the file

Layer 5 global queries receive the full implementations of all functions
relevant to the query topic — no keyword-filtered stub summaries.
"""

from __future__ import annotations

import os
import re


def build_context_bundle(
    global_map: dict,
    finding: dict,
    source_root: str,
    context_window: int = 20,   # kept for API compatibility; not the primary path  # noqa: ARG001
) -> dict:
    """
    Build a context bundle for a single Semgrep finding.

    Args:
        global_map:  Output of global_map.build_global_map().
        finding:     A single finding dict from semgrep_runner.run_semgrep().
        source_root: Root directory of the scanned codebase.

    Returns a dict for serialisation into an Opus prompt.
    """
    file_rel    = finding.get("file", "")
    target_line = finding.get("line", 0)

    # Normalise file_rel relative to source_root. global_map keys are
    # always repo-relative (``src/Foo.sol::bar``); an absolute path
    # from upstream (e.g. semgrep with absolute targets) would silently
    # fail _lookup_function_body. semgrep_runner now strips absolute
    # paths upstream; this is a defence in depth.
    if file_rel and os.path.isabs(file_rel):
        try:
            rel = os.path.relpath(file_rel, source_root)
            if not rel.startswith(".."):
                file_rel = rel
        except ValueError:
            pass

    # Synthetic (skill-based) findings → read the entire file for deep audit
    if finding.get("synthetic"):
        full_path = os.path.join(source_root, file_rel)
        try:
            with open(full_path, encoding="utf-8", errors="ignore") as fh:
                file_content = fh.read()
        except OSError:
            file_content = ""
        # Truncate very large files to stay within context limits
        max_chars = 30_000
        if len(file_content) > max_chars:
            file_content = file_content[:max_chars] + "\n\n... [truncated — file exceeds 30K chars]"
        return {
            "target_file":          file_rel,
            "target_line":          1,
            "target_function_key":  f"{file_rel}::<full_file>",
            "target_function_body": file_content,
            "callee_chain":         {},
            "entry_points":         {},
            "related_state":        [],
            "file_access_control":  {},
            "finding": {
                "rule_id":  "skill_audit",
                "message":  finding.get("message", f"Skill-based deep audit of {file_rel}"),
                "severity": "",
                "cwe":      "",
                "owasp":    "",
                "code":     "",
            },
        }

    # Locate the exact function that contains this finding
    func_key, func_body = _lookup_function_body(global_map, file_rel, target_line)

    # Fallback chain when global_map lookup fails:
    #   (a) Use ``finding.code`` if the producer (e.g. interest_detector)
    #       carried the function body forward — this avoids brittle disk
    #       re-extraction that can return SPDX headers for functions
    #       reported at line 1.
    #   (b) Otherwise scan the source file. ``_extract_full_function``
    #       now returns an empty string on read errors, which surfaces
    #       cleanly here instead of polluting the Opus prompt with
    #       ``[file not found]``-style sentinels.
    #
    # ``"requires login"`` is treated as empty — it's a Semgrep cloud
    # redaction sentinel (Pro-tier rules anti-piracy mark when caller
    # isn't authenticated to Semgrep AppSec Platform). Letting it
    # through gave the LLM nothing to analyse, which caused every L4
    # call to return "Confirmed: no" in RUN MAC-19c. The semgrep_runner
    # already strips this upstream; this is a second-line defence.
    _REDACTION_SENTINELS = {"requires login", ""}
    if not func_body:
        carry_forward = (finding.get("code") or "").strip()
        if carry_forward and carry_forward not in _REDACTION_SENTINELS:
            func_key = finding.get("function_key") or f"{file_rel}::<unknown>"
            func_body = carry_forward
        else:
            func_key  = f"{file_rel}::<unknown>"
            func_body = _extract_full_function(source_root, file_rel, target_line)

    # Bidirectional call chain
    callees, entry_points = _collect_full_call_chain(global_map, func_key)

    return {
        "target_file":          file_rel,
        "target_line":          target_line,
        "target_function_key":  func_key,
        "target_function_body": func_body,
        "callee_chain":         callees,        # {key: body} everything called downward
        "entry_points":         entry_points,   # {key: body} public/external callers upward
        "related_state":        _get_related_state(global_map, file_rel),
        "file_access_control":  _get_file_ac(global_map, file_rel),
        "finding": {
            "rule_id":  finding.get("rule_id", ""),
            "message":  finding.get("message", ""),
            "severity": finding.get("severity", ""),
            "cwe":      finding.get("cwe", ""),
            "owasp":    finding.get("owasp", ""),
            "code":     finding.get("code", ""),
        },
    }


def format_bundle_for_prompt(bundle: dict) -> str:
    """Render a context bundle as a prompt string for Opus.

    Leads with real code — the complete function and its entire call chain —
    so the LLM analyses implementation, not inferred names.
    """
    parts: list[str] = []

    # 1. Finding header
    f = bundle.get("finding", {})
    if f.get("rule_id") == "skill_audit":
        parts.append(
            f"## Audit Target\n"
            f"File: {bundle.get('target_file', '')}\n"
            f"Task: {f.get('message', '')}\n\n"
            f"Perform a thorough security audit of the ENTIRE file below. "
            f"Identify all vulnerabilities, logic errors, integer overflows, "
            f"access control issues, and potential attack vectors."
        )
    else:
        parts.append(
            f"## Semgrep Finding\n"
            f"Rule: {f.get('rule_id', '')}\n"
            f"Severity: {f.get('severity', '')}  CWE: {f.get('cwe', '')}\n"
            f"Message: {f.get('message', '')}\n"
            f"Flagged code:\n```\n{f.get('code', '')}\n```"
        )

    # 2. Public/external entry points that can reach this finding (attack surface)
    entry_points = bundle.get("entry_points", {})
    if entry_points:
        ep_parts = []
        for k, body in entry_points.items():
            ep_parts.append(f"### `{k}`\n```\n{body}\n```")
        parts.append(
            "## Entry Points (public/external callers that reach this finding)\n\n"
            + "\n\n".join(ep_parts)
        )

    # 3. Full body of the function that contains the finding
    func_key  = bundle.get("target_function_key", "")
    func_body = bundle.get("target_function_body", "")
    label = func_key if func_key else (
        f"{bundle.get('target_file', '')} line {bundle.get('target_line', '')}"
    )
    parts.append(
        f"## Flagged Function: `{label}`\n"
        f"```\n{func_body}\n```"
    )

    # 4. Complete downward call chain (everything the flagged function calls)
    callees = bundle.get("callee_chain", {})
    if callees:
        callee_parts = []
        for k, body in callees.items():
            callee_parts.append(f"### `{k}`\n```\n{body}\n```")
        parts.append("## Callee Chain (all functions called by the flagged function)\n\n" + "\n\n".join(callee_parts))

    # 5. State variables
    if bundle.get("related_state"):
        parts.append(
            "## State Variables\n"
            + "\n".join(f"  {s}" for s in bundle["related_state"])
        )

    # 6. Access control for the file
    ac = bundle.get("file_access_control", {})
    if ac:
        ac_lines = [f"  {k.split('::')[-1]}: {v}" for k, v in ac.items()]
        parts.append("## Access Control (all functions in file)\n" + "\n".join(ac_lines))

    return "\n\n".join(parts)


# ---------------------------------------------------------------------------
# Global pattern queries (Layer 5)
# ---------------------------------------------------------------------------

GLOBAL_PATTERN_QUERIES: list[dict] = [
    {
        "name": "reentrancy_check",
        "query": (
            "Analyse the function implementations above for reentrancy vulnerabilities.\n"
            "A reentrancy bug exists when a function:\n"
            "  1. Makes an external call (.call / .transfer / .send / external contract)\n"
            "  2. Modifies state variables AFTER that external call\n"
            "  3. Does NOT have a reentrancy guard (nonReentrant or equivalent)\n"
            "Trace the exact control-flow path. Name the function, the external call site, "
            "the state variable modified after it, and the line numbers."
        ),
    },
    {
        "name": "flash_loan_exposure",
        "query": (
            "Analyse the function implementations above for flash-loan / price-manipulation exposure.\n"
            "Look for: spot price reads (no TWAP), oracle calls within the same block, "
            "large state changes based on a single-block price, absence of slippage checks.\n"
            "Name the vulnerable function, the oracle dependency, and the exploitable path."
        ),
    },
    {
        "name": "access_control_gaps",
        "query": (
            "Analyse the function implementations above for missing access control.\n"
            "For every public or external function that modifies state or transfers value, "
            "verify whether it has an access-control modifier (onlyOwner, onlyRole, require(msg.sender==...), etc.).\n"
            "List each function that can be called by ANY address and explain the impact."
        ),
    },
    {
        "name": "trust_boundary_violations",
        "query": (
            "Analyse the function implementations above for trust-boundary violations.\n"
            "Look for: unchecked return values from .call(), missing require() after external calls, "
            "implicit trust of external oracle or contract data without validation.\n"
            "Identify the specific call site and what could go wrong."
        ),
    },
]


def format_global_query_prompt(global_map: dict, query: dict) -> str:
    """Build a prompt for a Layer 5 global pattern query.

    Includes the complete implementations of all functions relevant to the
    query so the LLM reads real code rather than inferred metadata.
    """
    from core.analysis.global_map import format_global_map_for_prompt

    # Compact metadata header (state vars, access control)
    map_text = format_global_map_for_prompt(global_map, token_budget=1500)

    # Actual function implementations, filtered by topic
    bodies_text = _select_relevant_bodies_with_chains(global_map, query["name"])

    return (
        f"{map_text}\n\n"
        f"## Function Implementations\n\n"
        f"{bodies_text}\n\n"
        f"## Security Analysis Query\n"
        f"{query['query']}\n\n"
        "Base your answer on the actual function implementations above. "
        "Reference specific variable names, call sites, and control-flow paths. "
        "If you find no issues, state that clearly."
    )


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def _lookup_function_body(
    global_map: dict, file_rel: str, target_line: int
) -> tuple[str, str]:
    """Return (func_key, body) for the function in file_rel that contains target_line.

    Uses function_start_lines to find the function whose start is closest to
    and at or before target_line.
    """
    start_lines  = global_map.get("function_start_lines", {})
    function_bodies = global_map.get("function_bodies", {})

    best_key   = ""
    best_start = -1

    for key, start in start_lines.items():
        if not key.startswith(file_rel + "::"):
            continue
        if start <= target_line and start > best_start:
            best_key   = key
            best_start = start

    if best_key and best_key in function_bodies:
        return best_key, function_bodies[best_key]
    return "", ""


def _collect_full_call_chain(
    global_map: dict,
    start_key: str,
) -> tuple[dict[str, str], dict[str, str]]:
    """Bidirectional context construction.

    Downward (callees): budget-aware BFS via :mod:`context_budget`.
    Callees over budget are kept as structural summaries rather than
    dropped, so Opus still sees the relevant call surface but the
    chain fits a 200k-window prompt on protocols the size of Aave.

    Upward (callers): walks reverse_call_graph to the first public /
    external function (the attack-surface boundary), then adds:
      * constructor / initialize / upgrade hooks for any contract in
        the chain (B-P1-2)
      * functions that write state variables the flagged function
        reads (B-P1-2)

    Returns dicts of ``{func_key: rendered_body}`` for backward
    compatibility with the existing renderers — summarised callees
    are tagged inline so the prompt can label them.
    """
    function_bodies     = global_map.get("function_bodies", {})
    call_graph          = global_map.get("call_graph", {})
    reverse_call_graph  = global_map.get("reverse_call_graph", {})
    access_control      = global_map.get("access_control", {})
    typed_call_graph    = global_map.get("call_graph_typed") or {}
    state_variables     = global_map.get("state_variables") or []

    flagged_body = function_bodies.get(start_key, "")

    # ── Downward BFS (callees), budget-aware ────────────────────────────
    callees: dict[str, str] = {}
    try:
        from core.analysis.context_budget import build_callee_chain_budgeted

        chain, stats = build_callee_chain_budgeted(
            start_key,
            call_graph=call_graph,
            function_bodies=function_bodies,
            state_variables=state_variables,
            typed_call_graph=typed_call_graph,
            resolve_callee=_resolve_callee,
        )
        for key, ctx in chain.items():
            tag = " [SUMMARY]" if ctx.is_summary else ""
            callees[key + tag] = ctx.body

        import logging
        logging.getLogger(__name__).info(
            "callee_chain: tokens=%d/%d included=%d summarised=%d skipped=%d depth=%d",
            stats.tokens_used, stats.budget, stats.included,
            stats.summarized, stats.skipped, stats.max_depth_seen,
        )
    except Exception as exc:
        # Defensive fallback to the original unbounded BFS so a bug in
        # the budget code can't tank a scan.
        import logging
        logging.getLogger(__name__).info("budget BFS failed (%s) — using unbounded", exc)
        visited_down: set[str] = {start_key}
        queue_down: list[str] = [start_key]
        while queue_down:
            current = queue_down.pop(0)
            for raw_callee in call_graph.get(current, []):
                resolved = _resolve_callee(raw_callee, function_bodies)
                if resolved and resolved not in visited_down:
                    visited_down.add(resolved)
                    callees[resolved] = function_bodies[resolved]
                    queue_down.append(resolved)

    # ── Upward BFS (callers → public/external entry points) ───────────
    callers: dict[str, str] = {}
    visited_up: set[str] = {start_key}
    queue_up: list[str] = [start_key]

    while queue_up:
        current = queue_up.pop(0)
        ctrl = access_control.get(current, "")
        is_public_boundary = bool(
            re.search(r"\b(public|external)\b", ctrl)
        )
        if current != start_key and current not in callers:
            callers[current] = function_bodies.get(current, "")
        if is_public_boundary and current != start_key:
            continue
        for parent in reverse_call_graph.get(current, []):
            if parent not in visited_up:
                visited_up.add(parent)
                queue_up.append(parent)

    # ── Lifecycle augmentation (B-P1-2) ────────────────────────────────
    try:
        from core.analysis.context_budget import (
            find_lifecycle_keys, find_state_setters,
        )

        # Contracts whose code is anywhere in the upward chain.
        contracts: set[str] = set()
        for k in list(callers) + [start_key]:
            # Key shape: ``rel_file::Contract.fn`` or ``rel_file::fn``
            if "::" in k:
                right = k.split("::", 1)[1]
                if "." in right:
                    contracts.add(right.split(".", 1)[0])

        for lc_key in find_lifecycle_keys(function_bodies, contracts):
            if lc_key not in callers and lc_key != start_key:
                body = function_bodies[lc_key]
                callers[f"{lc_key} [LIFECYCLE]"] = body

        # State-var setters for vars the flagged function reads.
        known_vars: set[str] = set()
        for sv in state_variables:
            name = getattr(sv, "name", None) if not isinstance(sv, str) else None
            if name:
                known_vars.add(name)
            elif isinstance(sv, str):
                m = re.search(r"([A-Za-z_]\w*)\s*[;=]?\s*$", sv)
                if m:
                    known_vars.add(m.group(1))

        if flagged_body and known_vars:
            for setter_key in find_state_setters(function_bodies, flagged_body, known_vars):
                if setter_key in callers or setter_key == start_key:
                    continue
                # Skip if we already added it as lifecycle.
                if any(setter_key in k for k in callers):
                    continue
                callers[f"{setter_key} [STATE-SETTER]"] = function_bodies[setter_key]
    except Exception as exc:
        import logging
        logging.getLogger(__name__).info("lifecycle augmentation skipped: %s", exc)

    return callees, callers


def _resolve_callee(raw: str, function_bodies: dict) -> str:
    """Resolve a callee string to a function_bodies key, or '' if external."""
    # Already a full key (stored by intra-file call detection)
    if "::" in raw and raw in function_bodies:
        return raw

    # Fuzzy match: "obj.method()" — try to find "::method" in function_bodies
    short = raw.split("(")[0]          # strip "()"
    if "." in short:
        short = short.split(".")[-1]   # take method name after last dot

    for key in function_bodies:
        if key.endswith("::" + short):
            return key

    return ""


def _extract_full_function(
    source_root: str, file_rel: str, target_line: int
) -> str:
    """Fallback: scan source file for the function containing target_line.

    Returns an empty string on file errors so callers can detect "no body
    available" and either use an alternate source or skip the finding.
    Previously returned literal sentinel strings (``"[file not found]"``)
    which were passed verbatim into Opus prompts, producing placeholder
    findings that lacked any analysable content.
    """
    full_path = os.path.join(source_root, file_rel)
    if not os.path.exists(full_path):
        return ""
    try:
        with open(full_path, encoding="utf-8", errors="ignore") as fh:
            all_lines = fh.readlines()
    except OSError:
        return ""

    n   = len(all_lines)
    idx = min(max(target_line - 1, 0), n - 1)
    ext = os.path.splitext(file_rel)[1].lower()

    # Scan backwards for the function definition
    func_start = max(0, idx - 120)
    for i in range(idx, max(-1, idx - 120), -1):
        stripped = all_lines[i].strip()
        if ext == ".sol" and re.match(r"function\s+\w+", stripped):
            func_start = i
            break
        elif ext in (".cpp", ".h", ".hpp") and re.match(
            r"(?:TER|NotTEC|void|bool|int|auto|std::\w+|Expected\w*|Buffer|uint256)\s+", stripped
        ):
            func_start = i
            break
        elif ext == ".py" and re.match(r"(?:async\s+)?def\s+\w+", stripped):
            func_start = i
            break
        elif ext in (".js", ".ts", ".jsx", ".tsx") and re.match(
            r"(?:export\s+)?(?:async\s+)?(?:function\s+\w+|\w+\s*[=:]\s*(?:async\s*)?\()", stripped
        ):
            func_start = i
            break

    # Scan forward for the function end
    if ext in (".sol", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".cpp", ".h", ".hpp"):
        depth = 0
        found_open = False
        func_end = n
        for i in range(func_start, n):
            for ch in all_lines[i]:
                if ch == "{":
                    depth += 1
                    found_open = True
                elif ch == "}":
                    depth -= 1
                    if found_open and depth == 0:
                        func_end = i + 1
                        break
            else:
                continue
            break
    else:
        # Python: use indentation
        raw = all_lines[func_start]
        base_indent = len(raw) - len(raw.lstrip())
        func_end = n
        for i in range(func_start + 1, n):
            line = all_lines[i]
            if not line.strip():
                continue
            if len(line) - len(line.lstrip()) <= base_indent:
                func_end = i
                break

    lines = all_lines[func_start:func_end]
    return "".join(
        f"{func_start + i + 1:4d} | {line}" for i, line in enumerate(lines)
    )


def _get_related_state(global_map: dict, file_rel: str) -> list[str]:
    return [sv for sv in global_map.get("state_variables", []) if sv.startswith(file_rel)]


def _get_file_ac(global_map: dict, file_rel: str) -> dict:
    return {
        k: v for k, v in global_map.get("access_control", {}).items()
        if k.startswith(file_rel + "::")
    }


_GUARD_PATTERNS = re.compile(
    r"\b(nonReentrant|ReentrancyGuard|reentrancyGuard|noReentrant|locked|_lock)\b",
    re.IGNORECASE,
)


def _caller_chain_has_guard(global_map: dict, start_key: str) -> bool:
    """Return True if start_key or any of its transitive callers has a reentrancy guard.

    Checks both access_control modifiers (e.g. "[nonReentrant]") and the
    function body itself (e.g. `require(!locked)`).
    """
    access_control     = global_map.get("access_control", {})
    reverse_call_graph = global_map.get("reverse_call_graph", {})
    function_bodies    = global_map.get("function_bodies", {})

    visited: set[str] = set()
    queue = [start_key]

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)

        # Check access_control for modifier-level guard
        ctrl = access_control.get(current, "")
        if _GUARD_PATTERNS.search(ctrl):
            return True

        # Check function body for inline guard
        body = function_bodies.get(current, "")
        if _GUARD_PATTERNS.search(body):
            return True

        # Walk up to callers
        for parent in reverse_call_graph.get(current, []):
            if parent not in visited:
                queue.append(parent)

    return False


# ---------------------------------------------------------------------------
# Layer 5: relevant body selection with transitive closure
# ---------------------------------------------------------------------------

def _select_relevant_bodies_with_chains(
    global_map: dict,
    query_name: str,
) -> str:
    """Return full implementations (with call chains) for functions relevant to query_name.

    Seed selection is dispatched per-function by language (``seed_matchers``),
    so a Rust-only repo is matched against Rust-shaped patterns rather than
    the Solidity ``.call(`` / ``onlyOwner`` heuristics. Mixed-language repos
    are handled natively: each function independently picks its own matcher
    based on the file extension in its key.
    """
    from core.analysis.seed_matchers import match_seeds

    function_bodies = global_map.get("function_bodies", {})
    access_control  = global_map.get("access_control", {})

    if not function_bodies:
        return "_(No function bodies — re-run Layer 1.)_"

    seeds = match_seeds(query_name, function_bodies, access_control)

    # Reentrancy has one extra refinement on top of the raw match: drop
    # seeds whose caller chain already has a reentrancy guard — saves the
    # LLM from flagging obviously-guarded paths.
    if query_name == "reentrancy_check":
        seeds = [s for s in seeds if not _caller_chain_has_guard(global_map, s)]

    # Expand each seed bidirectionally: full callee chain + entry points
    collected: dict[str, str] = {}
    for seed in seeds:
        if seed not in collected:
            collected[seed] = function_bodies[seed]
        callees, entry_points = _collect_full_call_chain(global_map, seed)
        for k, v in callees.items():
            if k not in collected:
                collected[k] = v
        for k, v in entry_points.items():
            if k not in collected:
                collected[k] = v

    if not collected:
        return "_(No matching functions for this query.)_"

    chunks = [f"### `{k}`\n```\n{v}\n```" for k, v in collected.items()]
    return "\n\n".join(chunks)
