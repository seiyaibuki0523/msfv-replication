"""Budget-aware callee-chain construction.

Replaces the unbounded BFS in :mod:`context_bundle` with:

* **Token budget**: stop expanding once accumulated body bytes exceed
  ``AISEC_CALLEE_TOKEN_BUDGET`` (default 8000 tokens ≈ 32k chars).
* **Relevance scoring**: each callee gets a score so high-signal
  functions (shared state vars, external calls, state-modifying) win
  the budget. Low-signal pure / view callees past depth 2 get filtered.
* **Summary fallback**: when a callee would put the chain over budget,
  we keep a structural summary (signature + state-vars-touched +
  external-call presence + ``// truncated``) instead of dropping it
  entirely. The renderer marks the summary distinctly so Opus knows.

Two scoring modes available:

* ``v1`` — original 4-signal heuristic from the spec (shared state,
  external call, state-modifying, distance).
* ``v2`` — adds: state-var criticality weighting + cross-write coupling
  + data-flow heuristic. Default. Disable with ``AISEC_RELEVANCE_V2=0``.

All behaviour is tunable via env var so an operator can revert to the
old unbounded chain with ``AISEC_CALLEE_TOKEN_BUDGET=0`` (disables
truncation entirely).
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass
from typing import Iterable

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #

def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name, "1" if default else "0").strip().lower()
    return val in {"1", "true", "yes", "on"}


CALLEE_TOKEN_BUDGET = _env_int("AISEC_CALLEE_TOKEN_BUDGET", 8000)
CALLEE_MAX_DEPTH    = _env_int("AISEC_CALLEE_MAX_DEPTH", 5)
RELEVANCE_V2        = _env_bool("AISEC_RELEVANCE_V2", True)
# Pure / view callees below this score are skipped past depth 2.
SKIP_PURE_VIEW_BELOW = 0.3


@dataclass
class FunctionCtx:
    """Per-callee context — either a full body or a structural summary."""
    body: str
    is_summary: bool
    score: float
    depth: int
    is_lifecycle: bool = False
    is_state_setter: bool = False


# --------------------------------------------------------------------------- #
# Token approximation                                                         #
# --------------------------------------------------------------------------- #

def _approx_tokens(text: str) -> int:
    """Cheap token approximation — 4 chars ≈ 1 token works well enough
    for Solidity / Rust / Python where Opus's tokenizer is similar.
    """
    return max(1, len(text) // 4)


# --------------------------------------------------------------------------- #
# Pure / view detection                                                       #
# --------------------------------------------------------------------------- #

_PURE_VIEW_RE = re.compile(r"\b(pure|view)\b")


def _is_pure_or_view(body: str) -> bool:
    """Heuristic — checks the function signature (anything before the
    opening brace) for ``pure`` / ``view`` keywords. Cheap and works
    for Solidity. Returns False for Python / Rust / Go where the
    concept doesn't apply.
    """
    head = body.split("{", 1)[0]
    return bool(_PURE_VIEW_RE.search(head))


# --------------------------------------------------------------------------- #
# State-variable analysis                                                     #
# --------------------------------------------------------------------------- #

_STATE_VAR_NAME_RE = re.compile(r"\b([A-Za-z_]\w*)\b")


def _state_vars_touched(body: str, known_vars: set[str]) -> set[str]:
    """Best-effort: any token in ``body`` that matches a known state-var
    name counts. False positives possible (local var shadowing) but
    cheap and good enough as a signal.
    """
    if not body or not known_vars:
        return set()
    tokens = set(_STATE_VAR_NAME_RE.findall(body))
    return tokens & known_vars


_WRITE_PATTERNS = (
    "=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>=",
    "++", "--", ".push(", ".pop(", "delete ",
)


def _state_vars_written(body: str, known_vars: set[str]) -> set[str]:
    """Heuristic: a state var ``name`` is written if it appears in a
    line that contains one of the write operators after the name.
    """
    if not body or not known_vars:
        return set()
    written: set[str] = set()
    for var in known_vars:
        # Cheap LOC-level check — line that mentions the var AND has
        # a write operator after it.
        for line in body.splitlines():
            if var not in line:
                continue
            after = line.split(var, 1)[1]
            if any(op in after for op in _WRITE_PATTERNS):
                written.add(var)
                break
    return written


# --------------------------------------------------------------------------- #
# State-var criticality (B-P2-1)                                              #
# --------------------------------------------------------------------------- #

_CRIT_HIGH_KEYWORDS = (
    "balance", "balances", "supply", "totalsupply", "owner", "admin",
    "governance", "governor", "deposits", "shares", "collateral", "reserves",
)
_CRIT_MEDIUM_KEYWORDS = (
    "allowance", "allowances", "approved", "delegated", "permitted",
    "whitelist", "blacklist", "role", "roles",
)


def _state_var_criticality(name: str) -> float:
    """0.2 (low) / 0.5 (medium) / 0.9 (high). Keyword-based heuristic."""
    lower = (name or "").lower()
    if any(k in lower for k in _CRIT_HIGH_KEYWORDS):
        return 0.9
    if any(k in lower for k in _CRIT_MEDIUM_KEYWORDS):
        return 0.5
    return 0.2


# --------------------------------------------------------------------------- #
# Relevance scoring                                                           #
# --------------------------------------------------------------------------- #

def relevance_score(
    callee_body: str,
    flagged_body: str,
    known_state_vars: set[str],
    depth: int,
    typed_edges: list | None = None,
) -> float:
    """Score a callee on [0, 1]. Higher means more useful to Opus.

    Uses v2 (criticality + cross-write + data flow + external + distance)
    when ``AISEC_RELEVANCE_V2=1``, else v1 (4-signal heuristic).
    """
    if RELEVANCE_V2:
        return _score_v2(callee_body, flagged_body, known_state_vars, depth, typed_edges)
    return _score_v1(callee_body, flagged_body, known_state_vars, depth, typed_edges)


def _score_v1(callee_body, flagged_body, known_state_vars, depth, typed_edges) -> float:
    flagged_state = _state_vars_touched(flagged_body, known_state_vars)
    callee_state  = _state_vars_touched(callee_body, known_state_vars)
    score = 0.0

    shared = flagged_state & callee_state
    score += 0.5 * min(len(shared) / 3.0, 1.0)

    if typed_edges and any(getattr(e, "is_external_like", lambda: False)() for e in typed_edges):
        score += 0.2

    if _state_vars_written(callee_body, known_state_vars):
        score += 0.15

    score *= max(0.3, 1.0 - 0.15 * depth)
    return min(score, 1.0)


def _score_v2(callee_body, flagged_body, known_state_vars, depth, typed_edges) -> float:
    flagged_touch = _state_vars_touched(flagged_body, known_state_vars)
    callee_touch  = _state_vars_touched(callee_body, known_state_vars)
    flagged_write = _state_vars_written(flagged_body, known_state_vars)
    callee_write  = _state_vars_written(callee_body, known_state_vars)
    score = 0.0

    # 1. Shared state-vars weighted by their criticality.
    for var in flagged_touch & callee_touch:
        score += _state_var_criticality(var) * 0.3

    # 2. Cross-write coupling — both write the same var.
    if flagged_write & callee_write:
        score += 0.3

    # 3. External / low-level / delegate edge in the callee.
    if typed_edges and any(getattr(e, "is_external_like", lambda: False)() for e in typed_edges):
        score += 0.2

    # 4. State-modifying callee (no shared var required).
    if callee_write:
        score += 0.1

    # 5. Distance penalty (gentler than v1).
    score *= max(0.4, 1.0 - 0.1 * depth)
    return min(score, 1.0)


# --------------------------------------------------------------------------- #
# Summarisation                                                               #
# --------------------------------------------------------------------------- #

_SUMMARY_CACHE: dict[str, str] = {}


def summarise_function(
    body: str,
    *,
    known_state_vars: set[str] | None = None,
    target_tokens: int = 200,
) -> str:
    """Produce a short structural summary for a function whose full
    body would blow the callee-chain budget.

    Deterministic + cheap: extracts signature, first/last 2 lines,
    state vars touched, and external-call markers. No LLM call.
    Ollama-backed summaries can be plugged in later via
    ``AISEC_OLLAMA_SUMMARY=1`` (TODO).
    """
    cache_key = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:32]
    if cache_key in _SUMMARY_CACHE:
        return _SUMMARY_CACHE[cache_key]

    head = body.split("\n", 1)[0]  # function signature line(s)
    # First 2 + last 2 non-empty body lines as a structural fingerprint.
    lines = [ln for ln in body.splitlines() if ln.strip()]
    sample = (lines[:3] + ["// ... (body truncated) ..."] + lines[-2:]) if len(lines) > 8 else lines

    touched = _state_vars_touched(body, known_state_vars or set())
    written = _state_vars_written(body, known_state_vars or set())
    has_external = any(
        marker in body
        for marker in (".call(", ".delegatecall(", ".staticcall(", ".transfer(", ".send(")
    )

    parts = [head, "// === SUMMARY (full body omitted to fit budget) ==="]
    if touched:
        parts.append(f"// reads state: {', '.join(sorted(touched)[:6])}")
    if written:
        parts.append(f"// writes state: {', '.join(sorted(written)[:6])}")
    if has_external:
        parts.append("// performs external call / value transfer")
    parts.append("// ---")
    parts.extend(sample)

    summary = "\n".join(parts)
    if _approx_tokens(summary) > target_tokens * 2:
        summary = summary[: target_tokens * 4] + "\n// ..."
    _SUMMARY_CACHE[cache_key] = summary
    return summary


def reset_summary_cache() -> None:
    _SUMMARY_CACHE.clear()


# --------------------------------------------------------------------------- #
# Budget-aware callee chain                                                   #
# --------------------------------------------------------------------------- #

@dataclass
class CalleeChainStats:
    """Diagnostic numbers Casper asked for in the spec."""
    tokens_used:     int = 0
    budget:          int = 0
    included:        int = 0
    summarized:      int = 0
    skipped:         int = 0
    max_depth_seen:  int = 0


def build_callee_chain_budgeted(
    start_key: str,
    *,
    call_graph: dict[str, list[str]],
    function_bodies: dict[str, str],
    state_variables: Iterable[str] | Iterable,
    typed_call_graph: dict[str, list] | None = None,
    budget: int | None = None,
    max_depth: int | None = None,
    resolve_callee=None,
) -> tuple[dict[str, FunctionCtx], CalleeChainStats]:
    """Budget-aware BFS down the call graph.

    Returns ``(chain, stats)`` where ``chain`` maps function key to
    :class:`FunctionCtx` (with full body OR a summary depending on
    whether the callee fit the budget). When the budget is 0 (default
    disabled), behaviour reverts to the original unbounded BFS.
    """
    budget = budget if budget is not None else CALLEE_TOKEN_BUDGET
    max_depth = max_depth if max_depth is not None else CALLEE_MAX_DEPTH

    chain: dict[str, FunctionCtx] = {}
    stats = CalleeChainStats(budget=budget)
    if not function_bodies.get(start_key):
        return chain, stats

    # Build the known state-var name set once.
    var_names: set[str] = set()
    for sv in state_variables or []:
        if isinstance(sv, str):
            # Loose format from regex parser: "file.sol: type name" or
            # "file.sol: uint256 totalSupply".
            m = re.search(r"([A-Za-z_]\w*)\s*[;=]?\s*$", sv)
            if m:
                var_names.add(m.group(1))
        else:
            # Typed StateVar object from Slither.
            name = getattr(sv, "name", None)
            if name:
                var_names.add(name)

    flagged_body = function_bodies[start_key]

    # BFS queue: (key, depth, parent_key)
    queue: list[tuple[str, int, str | None]] = [(start_key, 0, None)]
    visited: set[str] = {start_key}

    # Resolver — caller can supply the fuzzy resolver from context_bundle
    # so we match its key conventions exactly.
    if resolve_callee is None:
        def resolve_callee(raw: str, bodies: dict[str, str]) -> str:  # type: ignore[misc]
            return raw if raw in bodies else ""

    # Score every reachable callee first so we can sort the queue by
    # relevance and spend the budget on the most signal-rich ones.
    # We use a priority list (highest score first).
    scored: list[tuple[float, str, int]] = []  # (score, key, depth)
    pending_queue = [(start_key, 0)]
    seen_score = {start_key}

    while pending_queue:
        cur, depth = pending_queue.pop(0)
        if depth >= max_depth:
            continue
        for raw in call_graph.get(cur, []):
            key = resolve_callee(raw, function_bodies)
            if not key or key in seen_score:
                continue
            seen_score.add(key)
            body = function_bodies.get(key, "")
            if not body:
                continue
            edges = (typed_call_graph or {}).get(key, [])
            score = relevance_score(
                callee_body=body,
                flagged_body=flagged_body,
                known_state_vars=var_names,
                depth=depth + 1,
                typed_edges=edges or None,
            )
            # Pure / view drop past depth 2 unless score is high.
            if depth + 1 > 2 and _is_pure_or_view(body) and score < SKIP_PURE_VIEW_BELOW:
                stats.skipped += 1
                continue
            scored.append((score, key, depth + 1))
            pending_queue.append((key, depth + 1))
            stats.max_depth_seen = max(stats.max_depth_seen, depth + 1)

    scored.sort(key=lambda t: (-t[0], t[2]))

    # Now greedily fill the budget by score order.
    for score, key, depth in scored:
        body = function_bodies[key]
        body_tokens = _approx_tokens(body)
        if budget == 0:
            # Disabled — include everything as full body.
            chain[key] = FunctionCtx(body=body, is_summary=False, score=score, depth=depth)
            stats.tokens_used += body_tokens
            stats.included += 1
            continue

        if stats.tokens_used + body_tokens <= budget:
            chain[key] = FunctionCtx(body=body, is_summary=False, score=score, depth=depth)
            stats.tokens_used += body_tokens
            stats.included += 1
        else:
            # Try a summary; only include if even the summary fits.
            summary = summarise_function(body, known_state_vars=var_names)
            sum_tokens = _approx_tokens(summary)
            if stats.tokens_used + sum_tokens <= budget * 1.1:  # 10% leeway
                chain[key] = FunctionCtx(body=summary, is_summary=True, score=score, depth=depth)
                stats.tokens_used += sum_tokens
                stats.summarized += 1
            else:
                stats.skipped += 1

    return chain, stats


# --------------------------------------------------------------------------- #
# Lifecycle / state-setter augmentation                                       #
# --------------------------------------------------------------------------- #

_LIFECYCLE_PATTERNS = (
    "constructor",      # Solidity / C++
    "initialize",       # OpenZeppelin upgradeable
    "__init__",         # Python
    "setUp",            # Foundry
    "_authorizeUpgrade",  # UUPS hook
    "upgradeTo",        # ERC-1967
    "upgradeToAndCall",
)


def find_lifecycle_keys(function_bodies: dict[str, str], contracts: Iterable[str]) -> list[str]:
    """Return function keys that look like lifecycle / init / upgrade hooks
    for any of the ``contracts`` named.
    """
    contracts = set(contracts or [])
    out: list[str] = []
    for key in function_bodies:
        # key format: ``rel_file::Contract.fn`` or ``rel_file::fn``
        if "::" not in key:
            continue
        right = key.split("::", 1)[1]
        if "." in right:
            contract, fn = right.split(".", 1)
        else:
            contract, fn = "", right
        if contracts and contract not in contracts:
            continue
        if any(fn.lower().startswith(p.lower()) or p.lower() in fn.lower()
               for p in _LIFECYCLE_PATTERNS):
            out.append(key)
    return out


def find_state_setters(
    function_bodies: dict[str, str],
    flagged_body: str,
    known_state_vars: set[str],
) -> list[str]:
    """Find functions that *write* state vars *read* by the flagged
    function. These are critical for understanding initialisation +
    deployment-time bugs.
    """
    read_vars = _state_vars_touched(flagged_body, known_state_vars)
    if not read_vars:
        return []
    setters: list[str] = []
    for key, body in function_bodies.items():
        if _state_vars_written(body, read_vars):
            setters.append(key)
    return setters


__all__ = [
    "FunctionCtx",
    "CalleeChainStats",
    "build_callee_chain_budgeted",
    "relevance_score",
    "summarise_function",
    "reset_summary_cache",
    "find_lifecycle_keys",
    "find_state_setters",
    "CALLEE_TOKEN_BUDGET",
    "CALLEE_MAX_DEPTH",
]
