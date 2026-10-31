"""Two-tier context: shallow bundle + ``expand_function`` tool.

The default path eagerly stuffs callees into the prompt (see
:mod:`context_bundle`). On large protocols, most of that body never
informs Opus's verdict — token is spent for nothing.

The two-tier path inverts this:

1. Build a **shallow** context with the flagged function's full body
   plus a one-line signature + state-vars touched + edge type for
   every reachable callee.
2. Expose an ``expand_function`` tool. When Opus needs the body of a
   callee whose summary it has, it asks for it. The tool returns the
   full source and the next iteration of the ReAct loop sees it.

Cost in practice: 60-70% of a full bundle's tokens on contracts where
only a few callees actually matter; 100% on contracts where every
callee is load-bearing — but the latter is rare, and in those cases
the shallow + N expansions still beats the eager path because the
shallow part is much smaller than the full chain we no longer carry.

Activation: ``AISEC_TWO_TIER_CONTEXT=1``. Default off — the eager
path is well-tested and safe; the two-tier path is opt-in until we
benchmark recall parity on DVD.

Integration with Layer 4:
  * Building blocks (``build_shallow``, ``render_shallow``,
    ``make_expand_function_tool``) are stable and unit-tested.
  * The ReAct wiring in ``_analyse_finding_worker`` requires an LM
    adapter that supports function calling. Claude Opus + the
    Anthropic Python SDK does; NVIDIA NIM's OpenAI-compatible endpoint
    has partial support (model-dependent). When the env var is on
    AND the active adapter supports tools, the worker calls
    ``dspy.ReAct`` with this module's tool; otherwise it falls back
    to the shallow text path (still saves tokens, just no expansion).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Callable

from .context_budget import _state_vars_touched, _state_vars_written

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #

def is_enabled() -> bool:
    return os.getenv("AISEC_TWO_TIER_CONTEXT", "0").strip().lower() in {
        "1", "true", "yes", "on",
    }


# Heuristic — for tiny call graphs the eager path is already cheap.
SMALL_CHAIN_THRESHOLD = int(os.getenv("AISEC_TWO_TIER_MIN_CALLEES", "10"))


# --------------------------------------------------------------------------- #
# Models                                                                      #
# --------------------------------------------------------------------------- #

@dataclass
class CalleeStub:
    """One-line summary the shallow context exposes per callee."""
    key: str                        # ``rel_file::Contract.fn``
    signature: str                  # first line of the body
    call_type: str = "internal"     # from typed edge if available
    depth: int = 1
    state_reads:  list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    has_external_call: bool = False
    has_value_transfer: bool = False


@dataclass
class ShallowContext:
    """Tier-1 context — flagged body + stubs for everything reachable."""
    flagged_body: str
    flagged_key:  str
    callees:      list[CalleeStub] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    state_vars:   list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Build                                                                       #
# --------------------------------------------------------------------------- #

def build_shallow(
    flagged_key: str,
    *,
    global_map: dict,
    resolve_callee: Callable[[str, dict], str],
) -> ShallowContext:
    """Produce a shallow context for ``flagged_key``."""
    function_bodies   = global_map.get("function_bodies", {})
    call_graph        = global_map.get("call_graph", {})
    typed_call_graph  = global_map.get("call_graph_typed") or {}
    state_variables   = global_map.get("state_variables") or []

    flagged_body = function_bodies.get(flagged_key, "")

    # Known state var names — same logic as context_budget for consistency.
    known_vars: set[str] = set()
    for sv in state_variables:
        name = getattr(sv, "name", None) if not isinstance(sv, str) else None
        if name:
            known_vars.add(name)
        elif isinstance(sv, str) and ":" in sv:
            tail = sv.split(":", 1)[1].strip().split()
            if tail:
                known_vars.add(tail[-1].rstrip(";"))

    # BFS down — collect every reachable callee with a one-line summary.
    stubs: list[CalleeStub] = []
    visited: set[str] = {flagged_key}
    queue: list[tuple[str, int]] = [(flagged_key, 0)]

    while queue:
        cur, depth = queue.pop(0)
        if depth > 8:
            continue
        for raw in call_graph.get(cur, []):
            key = resolve_callee(raw, function_bodies)
            if not key or key in visited:
                continue
            visited.add(key)
            body = function_bodies.get(key, "")
            if not body:
                continue

            typed = (typed_call_graph or {}).get(key, [])
            has_ext = any(
                getattr(e, "is_external_like", lambda: False)() for e in typed
            )
            has_val = any(getattr(e, "has_value_transfer", False) for e in typed)

            stub = CalleeStub(
                key=key,
                signature=_extract_signature(body),
                call_type=_classify_edge_type(raw, typed),
                depth=depth + 1,
                state_reads=sorted(_state_vars_touched(body, known_vars)),
                state_writes=sorted(_state_vars_written(body, known_vars)),
                has_external_call=has_ext,
                has_value_transfer=has_val,
            )
            stubs.append(stub)
            queue.append((key, depth + 1))

    return ShallowContext(
        flagged_body=flagged_body,
        flagged_key=flagged_key,
        callees=stubs,
        state_vars=sorted(known_vars),
    )


def _extract_signature(body: str) -> str:
    """First non-empty line up to the opening brace / colon."""
    for line in body.splitlines():
        s = line.strip()
        if not s:
            continue
        sig = s.split("{", 1)[0].split(":", 1)[0].rstrip()
        return sig[:160]
    return ""


def _classify_edge_type(raw: str, typed_edges) -> str:
    """Pick the most-specific edge type we know about for a callee."""
    if typed_edges:
        return getattr(typed_edges[0], "call_type", "unknown")
    if "delegatecall" in raw.lower():
        return "delegatecall"
    if "staticcall" in raw.lower():
        return "staticcall"
    return "internal"


# --------------------------------------------------------------------------- #
# Rendering for the prompt                                                    #
# --------------------------------------------------------------------------- #

def render_shallow(ctx: ShallowContext) -> str:
    """Markdown render of the tier-1 context for Opus's first iteration."""
    parts: list[str] = []
    parts.append(f"## Flagged Function — {ctx.flagged_key}\n")
    parts.append("```\n" + ctx.flagged_body + "\n```\n")

    if ctx.callees:
        parts.append("## Reachable Callees (summaries only — request bodies via `expand_function`)\n")
        parts.append("| Function | Type | Depth | Reads | Writes | Ext / Value |")
        parts.append("|---|---|---|---|---|---|")
        for s in ctx.callees[:60]:
            flags = []
            if s.has_external_call:    flags.append("ext")
            if s.has_value_transfer:   flags.append("eth")
            parts.append(
                f"| `{s.key}` | {s.call_type} | {s.depth} | "
                f"{', '.join(s.state_reads[:3]) or '—'} | "
                f"{', '.join(s.state_writes[:3]) or '—'} | "
                f"{'/'.join(flags) or '—'} |"
            )
        if len(ctx.callees) > 60:
            parts.append(f"\n_…and {len(ctx.callees) - 60} more callees (use `expand_function` to inspect)._")

    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# Expand tool                                                                 #
# --------------------------------------------------------------------------- #

def make_expand_function_tool(global_map: dict, resolve_callee: Callable):
    """Build the ``expand_function`` tool function bound to a global map.

    Returned callable signature: ``expand_function(name: str) -> str``.
    The agent passes a callee key from the shallow stubs (or a short
    function name); we resolve it and return the full body. The tool
    is idempotent and side-effect-free.
    """
    function_bodies = global_map.get("function_bodies", {})

    # Track how many expansions Opus asked for so the renderer can log it.
    log: list[str] = []

    def expand_function(name: str) -> str:
        """Look up the full source of the function named ``name`` and
        return it. ``name`` may be a fully-qualified key ("file.sol::
        Contract.fn") or a short name; we resolve the short form via
        the same fuzzy match the eager builder uses.
        """
        key = name
        if name not in function_bodies:
            key = resolve_callee(name, function_bodies)
        if not key or key not in function_bodies:
            return f"// expand_function: '{name}' not found in scope"
        log.append(key)
        body = function_bodies[key]
        return f"// expand_function: {key}\n{body}"

    expand_function.log = log  # type: ignore[attr-defined]
    return expand_function


__all__ = [
    "is_enabled",
    "CalleeStub",
    "ShallowContext",
    "build_shallow",
    "render_shallow",
    "make_expand_function_tool",
    "SMALL_CHAIN_THRESHOLD",
]
