"""Glue between the typed call-graph builders and the legacy global map.

``build_global_map`` (the existing entry point) produces a dict with
loose string-typed fields. The typed builders here produce richer
data — but downstream code already consumes the loose schema, so we
*merge* the typed output into the loose schema rather than replacing
it.

Concretely, ``enrich_global_map`` does three things:

1. Try the Slither builder. On success, **replace** the regex-derived
   entries for the Solidity files Slither covered (``function_bodies``,
   ``call_graph``, ``access_control``, ``state_variables``,
   ``function_summaries``, ``function_start_lines``).
2. Stash the typed ``CallEdge`` list on the dict under
   ``call_graph_typed`` so downstream callers can opt into the rich
   schema without breaking the legacy ``call_graph: dict[str, list[str]]``
   contract.
3. Rebuild the reverse call graph from the merged forward graph so
   ``context_bundle`` always sees the canonical inversion.

Tree-sitter integration plugs in here later via the same pattern.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from .models import CallEdge

logger = logging.getLogger(__name__)


def enrich_global_map(
    global_map: dict[str, Any],
    source_root: str,
    selected_files: list[str] | None = None,
) -> dict[str, Any]:
    """Merge typed-builder output into the legacy global map.

    Idempotent — running twice with the same input gives the same
    result. Safe to call even when no typed builder is available
    (returns ``global_map`` unchanged).
    """
    has_solidity = any(
        f.lower().endswith(".sol") for f in (selected_files or [])
    )

    typed_call_graph: dict[str, list[CallEdge]] = {}

    # ---- Solidity via Slither ----------------------------------------
    if has_solidity:
        from . import slither_solidity
        if slither_solidity.is_available():
            sl = slither_solidity.build(source_root, selected_files)
            if sl is not None:
                _merge_solidity(global_map, sl, typed_call_graph)
                logger.info(
                    "Slither IR parsed %d contracts → %d functions, %d typed edges",
                    len(sl.get("contracts_seen") or []),
                    len(sl.get("function_bodies") or {}),
                    sum(len(v) for v in typed_call_graph.values()),
                )

    # ---- Non-Solidity via tree-sitter --------------------------------
    # Each file is parsed independently — failure on one doesn't poison
    # the rest. Slither already handled .sol, so we skip those here.
    from . import tree_sitter_generic
    if tree_sitter_generic.is_available():
        ts_files = 0
        ts_edges = 0
        for path in (selected_files or []):
            ext = os.path.splitext(path)[1].lower()
            if ext == ".sol" or ext not in tree_sitter_generic.EXT_TO_LANG:
                continue
            rel = os.path.relpath(path, source_root).replace("\\", "/")
            frag = tree_sitter_generic.parse_file(path, rel, source_root)
            if frag is None:
                continue
            _merge_treesitter_frag(global_map, frag, typed_call_graph)
            ts_files += 1
            ts_edges += sum(len(v) for v in (frag.get("call_graph") or {}).values())
        if ts_files:
            logger.info(
                "tree-sitter parsed %d files → %d typed edges",
                ts_files, ts_edges,
            )

    # ---- Stash typed edges; never drop existing flat call_graph ----
    if typed_call_graph:
        global_map["call_graph_typed"] = typed_call_graph
        # Mirror typed edges into the loose call_graph format so the
        # legacy BFS path keeps working without code changes.
        for caller, edges in typed_call_graph.items():
            flat = [e.target for e in edges]
            global_map.setdefault("call_graph", {})[caller] = flat

    # ---- Rebuild reverse call graph from the (now merged) forward ---
    reverse: dict[str, list[str]] = {}
    for caller, callees in (global_map.get("call_graph") or {}).items():
        for raw in callees:
            if "::" not in raw:
                continue
            reverse.setdefault(raw, [])
            if caller not in reverse[raw]:
                reverse[raw].append(caller)
    global_map["reverse_call_graph"] = reverse

    return global_map


def _merge_solidity(
    global_map: dict[str, Any],
    sl: dict[str, Any],
    typed_call_graph: dict[str, list[CallEdge]],
) -> None:
    """Override the regex-derived Solidity entries with Slither's output."""
    # The Slither path uses ``rel_file::Contract.fn`` keys which align
    # with the regex parser's ``rel_file::function_name`` convention
    # except that Slither also includes the contract name. We keep
    # both — Layer 4 lookup will prefer the Slither key when present.
    function_bodies = global_map.setdefault("function_bodies", {})
    function_summaries = global_map.setdefault("function_summaries", {})
    function_start_lines = global_map.setdefault("function_start_lines", {})
    access_control = global_map.setdefault("access_control", {})

    for key, body in (sl.get("function_bodies") or {}).items():
        function_bodies[key] = body
    for key, summary in (sl.get("function_summaries") or {}).items():
        function_summaries[key] = summary
    for key, line in (sl.get("function_start_lines") or {}).items():
        function_start_lines[key] = line
    for key, ctrl in (sl.get("access_control") or {}).items():
        access_control[key] = ctrl

    # State variables get appended (regex path may emit empty entries
    # for non-Solidity files; Slither's typed StateVar takes priority
    # for Solidity contracts).
    state_vars = global_map.setdefault("state_variables", [])
    sv_seen = {(sv.get("contract") if isinstance(sv, dict) else sv.contract,
                sv.get("name") if isinstance(sv, dict) else sv.name)
               for sv in state_vars if sv}
    for sv in (sl.get("state_variables") or []):
        ident = (sv.contract, sv.name)
        if ident not in sv_seen:
            state_vars.append(sv)
            sv_seen.add(ident)

    for caller, edges in (sl.get("call_graph") or {}).items():
        typed_call_graph[caller] = edges


def _merge_treesitter_frag(
    global_map: dict[str, Any],
    frag: dict[str, Any],
    typed_call_graph: dict[str, list[CallEdge]],
) -> None:
    """Merge a per-file tree-sitter fragment into the global map.

    Tree-sitter alone can't resolve cross-file calls (no type info),
    so the typed edges land in the same shape as Slither's output but
    with ``call_type='internal'`` and only the bare function name as
    target. The fuzzy resolver in ``context_bundle`` walks these to
    full keys downstream.
    """
    function_bodies = global_map.setdefault("function_bodies", {})
    function_summaries = global_map.setdefault("function_summaries", {})
    function_start_lines = global_map.setdefault("function_start_lines", {})

    for key, body in (frag.get("function_bodies") or {}).items():
        function_bodies[key] = body
    for key, summary in (frag.get("function_summaries") or {}).items():
        function_summaries[key] = summary
    for key, line in (frag.get("function_start_lines") or {}).items():
        function_start_lines[key] = line
    for caller, edges in (frag.get("call_graph") or {}).items():
        typed_call_graph[caller] = edges


__all__ = ["enrich_global_map"]
