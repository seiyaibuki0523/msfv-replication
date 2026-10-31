"""Tree-sitter-backed parser for JS / TS / Go / Rust / Python.

Same role as :mod:`slither_solidity` but for the non-Solidity files
that ``global_map`` currently parses with regex / brace counting.
Tree-sitter gives us:

* Real AST nodes, so ``function_declaration`` vs
  ``method_definition`` vs ``arrow_function`` are distinguishable.
* Robust to comments, template literals, string contents, partially
  written code — none of which the regex parser handles.
* One uniform extraction surface across all five languages — adding a
  sixth (e.g. Java, Kotlin) is just a new query.

Optional dependencies — this whole module silently no-ops when the
``tree_sitter`` package isn't installed. Activation:

    ``AISEC_USE_TREESITTER=1`` (default on if ``tree_sitter`` imports).

The grammar packs we look for, in order of preference:

    tree_sitter_languages       (pre-built, bundled binaries, easiest)
    tree_sitter_<lang>          (per-language packs)
    individual .so loads        (skipped — too system-specific)

Falls back to the regex parser when the grammar pack for a given
language isn't importable. So an operator can install only the
languages they need (``pip install tree_sitter tree-sitter-javascript``).
"""

from __future__ import annotations

import logging
import os
from typing import Any

from .models import CallEdge

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Availability check                                                          #
# --------------------------------------------------------------------------- #

def is_available() -> bool:
    if os.getenv("AISEC_USE_TREESITTER", "1").strip().lower() in {"0", "false", "no"}:
        return False
    try:
        import tree_sitter  # noqa: F401
    except Exception:
        return False
    return True


# Cached parser instances, lazily built per language.
_PARSERS: dict[str, Any] = {}
_LANG_CACHE: dict[str, Any] = {}


def _get_language(lang: str):
    """Return a ``tree_sitter.Language`` for ``lang`` (e.g. 'javascript'),
    or ``None`` when the grammar pack isn't installed.
    """
    if lang in _LANG_CACHE:
        return _LANG_CACHE[lang]
    # Preferred: ``tree_sitter_languages`` ships pre-built grammars.
    try:
        from tree_sitter_languages import get_language as _g
        l = _g(lang)
        _LANG_CACHE[lang] = l
        return l
    except Exception:
        pass
    # Per-language packs ("tree_sitter_javascript", etc.).
    try:
        mod = __import__(f"tree_sitter_{lang}")
        from tree_sitter import Language
        # Newer packs expose .language() / language_typescript() / etc.
        for attr in ("language", "language_typescript", "language_tsx"):
            fn = getattr(mod, attr, None)
            if callable(fn):
                _LANG_CACHE[lang] = Language(fn())
                return _LANG_CACHE[lang]
    except Exception:
        pass
    _LANG_CACHE[lang] = None
    return None


def _get_parser(lang: str):
    if lang in _PARSERS:
        return _PARSERS[lang]
    language = _get_language(lang)
    if language is None:
        _PARSERS[lang] = None
        return None
    try:
        from tree_sitter import Parser
        parser = Parser(language) if "language" in Parser.__init__.__code__.co_varnames else Parser()
        if not hasattr(parser, "language") or parser.language is None:
            parser.set_language(language)
        _PARSERS[lang] = parser
        return parser
    except Exception:
        _PARSERS[lang] = None
        return None


# --------------------------------------------------------------------------- #
# Extension → tree-sitter language name                                       #
# --------------------------------------------------------------------------- #

EXT_TO_LANG: dict[str, str] = {
    ".js":  "javascript",
    ".jsx": "javascript",
    ".ts":  "typescript",
    ".tsx": "tsx",
    ".go":  "go",
    ".rs":  "rust",
    ".py":  "python",
}


# --------------------------------------------------------------------------- #
# Per-language node-kind specs                                                #
# --------------------------------------------------------------------------- #

# Minimal spec: which AST node kinds correspond to function declarations
# and call sites, and how to extract the name node from each. We avoid
# tree-sitter Query objects (their API churned between 0.20 / 0.21 /
# 0.22) and walk the tree manually.

LANG_SPECS: dict[str, dict] = {
    "javascript": {
        "function_kinds": (
            "function_declaration", "method_definition", "arrow_function",
            "function", "generator_function_declaration",
        ),
        "name_field": ("name", "property"),
        "call_kind": "call_expression",
        "call_func_field": "function",
    },
    "typescript": {
        "function_kinds": (
            "function_declaration", "method_definition", "arrow_function",
            "function", "generator_function_declaration",
        ),
        "name_field": ("name", "property"),
        "call_kind": "call_expression",
        "call_func_field": "function",
    },
    "tsx": {
        "function_kinds": (
            "function_declaration", "method_definition", "arrow_function",
        ),
        "name_field": ("name", "property"),
        "call_kind": "call_expression",
        "call_func_field": "function",
    },
    "go": {
        "function_kinds": ("function_declaration", "method_declaration"),
        "name_field": ("name", "field"),
        "call_kind": "call_expression",
        "call_func_field": "function",
    },
    "rust": {
        "function_kinds": ("function_item",),
        "name_field": ("name",),
        "call_kind": "call_expression",
        "call_func_field": "function",
    },
    "python": {
        "function_kinds": ("function_definition", "async_function_definition"),
        "name_field": ("name",),
        "call_kind": "call",
        "call_func_field": "function",
    },
}


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #

def parse_file(path: str, rel: str, source_root: str) -> dict[str, Any] | None:
    """Parse one source file with tree-sitter.

    Returns a partial global-map fragment for this file
    (``function_bodies`` / ``function_start_lines`` / ``call_graph``)
    or ``None`` when tree-sitter / the grammar isn't available.
    """
    if not is_available():
        return None
    ext = os.path.splitext(path)[1].lower()
    lang = EXT_TO_LANG.get(ext)
    if lang is None:
        return None
    parser = _get_parser(lang)
    spec = LANG_SPECS.get(lang)
    if parser is None or spec is None:
        return None

    try:
        with open(path, "rb") as f:
            source = f.read()
        tree = parser.parse(source)
    except Exception as e:
        logger.info("tree-sitter parse failed for %s: %s", path, e)
        return None

    root = tree.root_node
    function_bodies: dict[str, str] = {}
    function_summaries: dict[str, str] = {}
    function_start_lines: dict[str, int] = {}
    call_graph: dict[str, list[CallEdge]] = {}

    # Walk: gather function nodes; for each, gather inner call-expr nodes.
    funcs = _find_function_nodes(root, spec)
    for fn_node, fn_name in funcs:
        if not fn_name:
            continue
        key = f"{rel}::{fn_name}"
        body = source[fn_node.start_byte:fn_node.end_byte].decode("utf-8", errors="ignore")
        function_bodies[key] = body
        function_start_lines[key] = fn_node.start_point[0] + 1
        function_summaries[key] = _summary_for(body)

        # Collect call edges inside this function body.
        edges: list[CallEdge] = []
        for call_node, callee_name in _find_call_nodes(fn_node, spec):
            if not callee_name:
                continue
            edges.append(CallEdge(
                target=callee_name,
                call_type="internal",   # tree-sitter alone can't resolve cross-file
                line=call_node.start_point[0] + 1,
            ))
        call_graph[key] = edges

    if not function_bodies:
        return None
    return {
        "function_bodies":      function_bodies,
        "function_summaries":   function_summaries,
        "function_start_lines": function_start_lines,
        "call_graph":           call_graph,
    }


# --------------------------------------------------------------------------- #
# Tree walking helpers                                                        #
# --------------------------------------------------------------------------- #

def _find_function_nodes(root, spec) -> list[tuple[Any, str]]:
    kinds = set(spec["function_kinds"])
    name_fields = spec["name_field"]
    out: list[tuple[Any, str]] = []

    cursor = root.walk()
    visited = False
    while True:
        node = cursor.node
        if node.type in kinds:
            name = ""
            for nf in name_fields:
                child = node.child_by_field_name(nf)
                if child is not None:
                    name = child.text.decode("utf-8", errors="ignore")
                    break
            if not name:
                # Anonymous / arrow function — try the parent's name (e.g.
                # ``const foo = () => ...`` makes the arrow function the
                # value child of a variable_declarator named ``foo``).
                parent = node.parent
                if parent is not None:
                    for nf in ("name", "left"):
                        child = parent.child_by_field_name(nf)
                        if child is not None:
                            name = child.text.decode("utf-8", errors="ignore")
                            break
            out.append((node, name))
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                visited = True
                break
        if visited:
            break
    return out


def _find_call_nodes(root, spec) -> list[tuple[Any, str]]:
    call_kind = spec["call_kind"]
    func_field = spec["call_func_field"]
    out: list[tuple[Any, str]] = []
    cursor = root.walk()
    visited = False
    while True:
        node = cursor.node
        if node.type == call_kind:
            fn_node = node.child_by_field_name(func_field)
            if fn_node is not None:
                # ``foo()`` → identifier; ``obj.method()`` → member_expression;
                # ``obj.field.method()`` → nested member_expression. We want
                # the rightmost identifier (the method being called).
                name = _rightmost_identifier(fn_node)
                if name:
                    out.append((node, name))
        if cursor.goto_first_child():
            continue
        while not cursor.goto_next_sibling():
            if not cursor.goto_parent():
                visited = True
                break
        if visited:
            break
    return out


def _rightmost_identifier(node) -> str:
    """Walk ``member_expression`` / ``selector_expression`` chains right
    to find the actual callee name. Falls back to the whole node text.
    """
    cur = node
    for _ in range(8):
        # JS member_expression: property field is the right side.
        prop = cur.child_by_field_name("property")
        if prop is not None:
            cur = prop
            continue
        # Go selector_expression: field is the right side.
        field = cur.child_by_field_name("field")
        if field is not None:
            cur = field
            continue
        # Python attribute: attribute field is the right side.
        attr = cur.child_by_field_name("attribute")
        if attr is not None:
            cur = attr
            continue
        break
    return cur.text.decode("utf-8", errors="ignore")


def _summary_for(body: str) -> str:
    head = body.split("\n", 1)[0].strip()
    return head[:160]


__all__ = ["is_available", "parse_file", "EXT_TO_LANG"]
