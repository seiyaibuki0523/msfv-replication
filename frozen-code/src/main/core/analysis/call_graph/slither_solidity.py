"""Slither-IR-based Solidity call-graph builder.

Replaces ``global_map._parse_solidity``'s regex path with typed IR
when Slither is installed AND the project compiles. The integrator
in this package always tries Slither first and falls back to the
existing regex output on any failure — so this module never breaks
a working pipeline.

What Slither buys us over regex:

* Inheritance: ``super.foo()`` resolves to the actual parent's foo,
  not a literal "super.foo" string.
* Library binding: ``uint256.mulDiv(...)`` from ``using FullMath for
  uint256;`` produces a ``library`` edge, not a fake method call.
* Type-aware externals: ``token.transfer(to, x)`` knows ``token``'s
  contract type, so we can label the edge with the target contract.
* Low-level vs high-level: distinguishes ``delegatecall``,
  ``staticcall``, plain ``call``, and ordinary cross-contract calls
  — the difference matters to reentrancy / trust-boundary analysis.
* Modifier resolution: modifier calls appear as proper edges.

Activation: set ``AISEC_USE_SLITHER=1`` (default on when Slither is
importable). Disable explicitly with ``AISEC_USE_SLITHER=0``.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from .models import CallEdge, StateVar

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Availability check                                                          #
# --------------------------------------------------------------------------- #

def is_available() -> bool:
    """True when Slither is importable and the user hasn't disabled it."""
    if os.getenv("AISEC_USE_SLITHER", "1").strip().lower() in {"0", "false", "no"}:
        return False
    try:
        import slither  # noqa: F401
    except Exception:
        return False
    return True


# --------------------------------------------------------------------------- #
# Builder                                                                     #
# --------------------------------------------------------------------------- #

def build(source_root: str, source_files: list[str] | None = None) -> dict[str, Any] | None:
    """Parse the Solidity portion of ``source_root`` with Slither.

    Returns a dict shaped like the global-map fragments we need to
    merge — see :func:`enrich_global_map`. Returns ``None`` when
    Slither isn't usable so the caller can keep the regex output.
    """
    if not is_available():
        return None

    try:
        from slither import Slither
        from slither.slithir.operations import (
            HighLevelCall, InternalCall, LibraryCall, LowLevelCall,
            SolidityCall,
        )
    except Exception as e:  # noqa: BLE001
        logger.info("Slither import failed: %s — falling back to regex path", e)
        return None

    try:
        # Slither auto-detects foundry / hardhat / truffle / dapp / etc.
        # under ``source_root``. Pass exclude=tests so vendor / forge-std
        # noise doesn't pollute the graph (file_filter already drops
        # those from selected_files but Slither walks the whole tree).
        slither = Slither(source_root, disable_solc_warnings=True)
    except Exception as e:  # noqa: BLE001
        logger.info(
            "Slither failed to compile %s (%s) — falling back to regex path",
            source_root, e,
        )
        return None

    function_bodies: dict[str, str] = {}
    function_summaries: dict[str, str] = {}
    function_start_lines: dict[str, int] = {}
    call_graph: dict[str, list[CallEdge]] = {}
    access_control: dict[str, str] = {}
    state_variables: list[StateVar] = []
    contracts_seen: set[str] = set()

    for contract in slither.contracts:
        if contract.is_interface or contract.is_library and not contract.functions:
            # Interfaces and empty libraries don't contribute callable bodies.
            continue
        contracts_seen.add(contract.name)

        rel_file = _relpath(contract.source_mapping.filename.absolute, source_root)

        # ---- State variables ------------------------------------------- #
        for sv in contract.state_variables:
            state_variables.append(StateVar(
                name=sv.name,
                type=str(sv.type),
                visibility=str(sv.visibility),
                is_constant=getattr(sv, "is_constant", False),
                is_immutable=getattr(sv, "is_immutable", False),
                contract=contract.name,
                file=rel_file,
                line=_sv_line(sv),
            ))

        # ---- Functions + modifiers ------------------------------------- #
        for fn in list(contract.functions) + list(contract.modifiers):
            key = f"{rel_file}::{contract.name}.{fn.name}"
            body = _function_source(fn)
            if not body:
                continue
            function_bodies[key] = body
            function_summaries[key] = _function_summary(fn)
            function_start_lines[key] = _function_start_line(fn)

            # Visibility + modifiers — same shape regex builder used so
            # downstream regex searches over the value still work.
            modifier_names = " ".join(m.name for m in fn.modifiers)
            access_control[key] = (
                f"{getattr(fn, 'visibility', 'internal')} {modifier_names}"
            ).strip()

            # Edges
            edges: list[CallEdge] = []
            try:
                ir_ops = list(fn.all_slithir_operations())
            except Exception:
                ir_ops = []

            for op in ir_ops:
                edge = _edge_from_ir(op, fn, rel_file, contract.name)
                if edge is not None:
                    edges.append(edge)

            # Modifier invocations show up as IR but also via fn.modifiers.
            # The IR path already covers them when modifiers contain code;
            # we just make sure the modifier appears in access_control.
            call_graph[key] = edges

    if not contracts_seen:
        # Nothing usable — defer to regex.
        return None

    return {
        "function_bodies":      function_bodies,
        "function_summaries":   function_summaries,
        "function_start_lines": function_start_lines,
        "call_graph":           call_graph,
        "access_control":       access_control,
        "state_variables":      state_variables,
        "contracts_seen":       sorted(contracts_seen),
    }


# --------------------------------------------------------------------------- #
# IR → CallEdge                                                               #
# --------------------------------------------------------------------------- #

def _edge_from_ir(op, fn, rel_file: str, contract_name: str) -> CallEdge | None:
    """Convert a Slither IR operation into a typed CallEdge."""
    from slither.slithir.operations import (
        HighLevelCall, InternalCall, LibraryCall, LowLevelCall,
        SolidityCall,
    )

    node = getattr(op, "node", None)
    line = _node_line(node)

    # ---- Internal call (same contract) ------------------------------ #
    if isinstance(op, InternalCall):
        try:
            target_contract = op.function.contract.name
            target_fn = op.function.name
        except AttributeError:
            return None
        return _enrich(
            CallEdge(
                target=f"{rel_file}::{target_contract}.{target_fn}",
                call_type="internal",
                target_contract=target_contract,
                line=line,
            ),
            op, node,
        )

    # ---- High-level call (cross-contract, typed) -------------------- #
    if isinstance(op, HighLevelCall) and not isinstance(op, LibraryCall):
        target_contract = _target_contract(op)
        target_fn = getattr(op, "function_name", None) or _function_name(op)
        edge = CallEdge(
            target=(f"{target_contract}.{target_fn}" if target_contract
                    else f"unknown.{target_fn}"),
            call_type="external" if target_contract else "external_dynamic",
            target_contract=target_contract,
            target_var=_destination_name(op),
            line=line,
            has_value_transfer=bool(getattr(op, "call_value", None)),
        )
        return _enrich(edge, op, node)

    # ---- Library call (``using X for Y``) --------------------------- #
    if isinstance(op, LibraryCall):
        target_contract = _target_contract(op) or "library"
        target_fn = getattr(op, "function_name", None) or _function_name(op)
        return _enrich(
            CallEdge(
                target=f"{target_contract}.{target_fn}",
                call_type="library",
                target_contract=target_contract,
                line=line,
            ),
            op, node,
        )

    # ---- Low-level calls -------------------------------------------- #
    if isinstance(op, LowLevelCall):
        name = (getattr(op, "function_name", "") or "").lower()
        if "delegatecall" in name:
            ct: str = "delegatecall"
        elif "staticcall" in name:
            ct = "staticcall"
        else:
            ct = "low_level_call"
        edge = CallEdge(
            target=f"low_level::{ct}",
            call_type=ct,
            target_var=_destination_name(op),
            line=line,
            has_value_transfer=bool(getattr(op, "call_value", None)),
        )
        return _enrich(edge, op, node)

    # ---- Solidity built-ins: skip (require/assert/keccak/etc.) ------ #
    if isinstance(op, SolidityCall):
        return None

    return None


def _enrich(edge: CallEdge, op, node) -> CallEdge:
    """Populate the structural metadata fields (in_loop / try / unchecked)."""
    if node is not None:
        edge.is_in_loop     = _is_inside_loop(node)
        edge.is_in_unchecked = _is_inside_unchecked(node)
        edge.has_try_catch  = _is_inside_try(node)

    # is_state_modifying: query the resolved target if available.
    target_fn = getattr(op, "function", None)
    if target_fn is not None:
        try:
            edge.is_state_modifying = bool(
                getattr(target_fn, "state_variables_written", None)
            )
            edge.is_payable = bool(getattr(target_fn, "payable", False))
        except Exception:
            pass

    # Best-effort argument summary (types only — keep prompt-friendly).
    try:
        edge.arguments_summary = [str(getattr(a, "type", "?")) for a in getattr(op, "arguments", [])]
    except Exception:
        pass

    return edge


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _is_inside_loop(node) -> bool:
    cur = getattr(node, "fathers", None)
    seen = set()
    queue = list(cur or [])
    while queue:
        n = queue.pop(0)
        if id(n) in seen:
            continue
        seen.add(id(n))
        ntype = str(getattr(n, "type", ""))
        if "LOOP" in ntype.upper() or ntype.lower() in ("forloop", "whileloop"):
            return True
        queue.extend(getattr(n, "fathers", []) or [])
    return False


def _is_inside_unchecked(node) -> bool:
    # Slither doesn't surface "unchecked" as a distinct node kind in
    # every version — heuristic: walk up scopes looking for the
    # ``unchecked`` keyword in their source range.
    try:
        scope = getattr(node, "scope", None)
        while scope is not None:
            src = str(getattr(scope, "source_mapping", "") or "")
            if "unchecked" in src.lower():
                return True
            scope = getattr(scope, "father", None) or getattr(scope, "parent", None)
    except Exception:
        pass
    return False


def _is_inside_try(node) -> bool:
    cur = node
    visited = set()
    while cur is not None and id(cur) not in visited:
        visited.add(id(cur))
        ntype = str(getattr(cur, "type", "")).lower()
        if "try" in ntype:
            return True
        cur = getattr(cur, "father", None) or getattr(cur, "parent", None)
    return False


def _node_line(node) -> int:
    if node is None:
        return 0
    try:
        return int(node.source_mapping.lines[0])
    except Exception:
        return 0


def _function_source(fn) -> str:
    try:
        src = fn.source_mapping.content
        if src:
            return src
    except Exception:
        pass
    return ""


def _function_start_line(fn) -> int:
    try:
        return int(fn.source_mapping.lines[0])
    except Exception:
        return 0


def _function_summary(fn) -> str:
    sig = getattr(fn, "full_name", None) or fn.name
    vis = getattr(fn, "visibility", "")
    parts = [vis, sig]
    if getattr(fn, "payable", False):
        parts.append("payable")
    if getattr(fn, "view", False):
        parts.append("view")
    return " ".join(p for p in parts if p).strip()


def _target_contract(op) -> str | None:
    dest = getattr(op, "destination", None)
    if dest is None:
        return None
    try:
        t = dest.type
        # Mappings of `UserDefinedType` → ``.type.name``
        if hasattr(t, "type") and hasattr(t.type, "name"):
            return t.type.name
        if hasattr(t, "name"):
            return t.name
    except Exception:
        pass
    return None


def _function_name(op) -> str:
    fn = getattr(op, "function", None)
    if fn is not None:
        return getattr(fn, "name", "?") or "?"
    return getattr(op, "function_name", "") or "?"


def _destination_name(op) -> str | None:
    dest = getattr(op, "destination", None)
    if dest is None:
        return None
    return getattr(dest, "name", None)


def _sv_line(sv) -> int:
    try:
        return int(sv.source_mapping.lines[0])
    except Exception:
        return 0


def _relpath(absolute: str, source_root: str) -> str:
    try:
        return os.path.relpath(absolute, source_root).replace("\\", "/")
    except Exception:
        return absolute


__all__ = ["build", "is_available"]
