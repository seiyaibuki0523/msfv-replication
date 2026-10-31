"""Call-graph builders that produce typed ``CallEdge`` records.

Two backends:

* ``slither_solidity`` — for ``.sol`` projects. Resolves inheritance,
  library binding, modifier calls, low-level / delegatecall / staticcall
  semantics, and type-aware external calls. Replaces the regex parser
  in :mod:`core.analysis.global_map` when Slither is installed and the
  project compiles.

* ``tree_sitter_generic`` — for JS / TS / Go / Rust / Python (and
  anything else with a tree-sitter grammar). Optional; only used when
  the ``tree_sitter`` package and the matching language pack are
  importable. Falls back to the existing regex / AST path otherwise.

Both backends emit the same :class:`CallEdge` schema so the downstream
context-bundle / Layer 5 seed code doesn't care which parser produced
the graph.

The legacy regex path keeps working — these builders are opt-in,
strictly additive, and never tear down a working pipeline when their
dependencies aren't installed.
"""

from __future__ import annotations

from .models import CallEdge, CallType, StateVar
from .integrator import enrich_global_map

__all__ = [
    "CallEdge",
    "CallType",
    "StateVar",
    "enrich_global_map",
]
