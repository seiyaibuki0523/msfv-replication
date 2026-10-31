"""
Layer 1 — Global map builder.

Zero LLM cost. Uses Python's built-in `ast` module for .py files
and regex heuristics for .sol / .js / .ts / .go / .rs.

Stores the complete function body for every function so downstream
layers can feed real code — not guesses from function names — to the LLM.
"""

from __future__ import annotations

import ast
import os
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_global_map(selected_files: list[str], source_root: str) -> dict:
    """
    Build a language-aware global map from the selected file list.

    Returns a dict with:
        structure_summary    — human-readable one-liner per file
        function_summaries   — {rel::func → one-line description}
        function_bodies      — {rel::func → complete source text}
        function_start_lines — {rel::func → start line number (1-based)}
        call_graph           — {rel::caller → [rel::callee | "obj.method()"]}
        reverse_call_graph   — {rel::callee → [rel::caller]} (inverted, intra-codebase only)
        external_calls       — list of cross-boundary call sites
        state_variables      — list of state var declarations (Solidity focus)
        access_control       — {rel::func → "visibility [modifiers]"}
        import_graph         — {rel → [imported modules]}
    """
    result: dict = {
        "structure_summary": [],
        "function_summaries": {},
        "function_bodies": {},
        "function_start_lines": {},
        "call_graph": {},
        "reverse_call_graph": {},
        "external_calls": [],
        "state_variables": [],
        "access_control": {},
        "import_graph": {},
    }

    for path in selected_files:
        rel = os.path.relpath(path, source_root)
        ext = Path(path).suffix.lower()

        try:
            content = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue

        if ext == ".py":
            _parse_python(path, rel, content, result)
        elif ext == ".sol":
            _parse_solidity(path, rel, content, result)
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            _parse_js_ts(path, rel, content, result)
        elif ext == ".go":
            _parse_go(path, rel, content, result)
        elif ext == ".rs":
            _parse_rust(path, rel, content, result)
        elif ext in (".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".ipp"):
            _parse_cpp(path, rel, content, result)
        elif ext == ".lua":
            _parse_lua(path, rel, content, result)
        else:
            _parse_generic(path, rel, content, result)

    # Build reverse call graph (callee → [callers]) from the forward graph.
    # Used by context_bundle to trace upward to public/external entry points.
    reverse: dict[str, list[str]] = {}
    for caller, callees in result["call_graph"].items():
        for raw_callee in callees:
            # Only invert intra-codebase edges (keys containing "::")
            if "::" not in raw_callee:
                continue
            reverse.setdefault(raw_callee, [])
            if caller not in reverse[raw_callee]:
                reverse[raw_callee].append(caller)
    result["reverse_call_graph"] = reverse

    # Opt-in: enrich with typed call-graph builders (Slither for
    # Solidity, tree-sitter for the others). Falls back to the regex
    # output above when the dependency isn't available. The integrator
    # rebuilds reverse_call_graph from the merged forward graph.
    try:
        from core.analysis.call_graph import enrich_global_map
        enrich_global_map(result, source_root, selected_files)
    except Exception as e:
        # Never let an enrichment failure break the pipeline — log + skip.
        import logging
        logging.getLogger(__name__).info(
            "Typed call-graph enrichment skipped: %s", e
        )

    return result


def format_global_map_for_prompt(global_map: dict, token_budget: int = 4000) -> str:
    """
    Render the global map metadata (structure / state / access control) as a
    compact string.  Function bodies are NOT included here — they are injected
    by context_bundle.py at query time so they can be filtered by relevance.
    """
    char_budget = token_budget * 4
    lines: list[str] = ["=== CODEBASE GLOBAL MAP ===\n"]

    if global_map.get("structure_summary"):
        lines.append("## File Structure")
        for s in global_map["structure_summary"][:50]:
            lines.append(f"  {s}")
        lines.append("")

    if global_map.get("state_variables"):
        lines.append("## State Variables")
        for sv in global_map["state_variables"][:50]:
            lines.append(f"  {sv}")
        lines.append("")

    if global_map.get("access_control"):
        lines.append("## Access Control")
        for func, ctrl in list(global_map["access_control"].items())[:60]:
            lines.append(f"  {func}: {ctrl}")
        lines.append("")

    if global_map.get("external_calls"):
        lines.append("## External Calls")
        for call in global_map["external_calls"][:40]:
            lines.append(f"  {call}")
        lines.append("")

    text = "\n".join(lines)
    if len(text) > char_budget:
        text = text[:char_budget] + "\n... [truncated to fit token budget]"
    return text


# ---------------------------------------------------------------------------
# Language parsers
# ---------------------------------------------------------------------------

_PY_ROUTE_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch", "head", "options",
    "websocket", "add_url_rule", "api_view",
}
_PY_AUTH_DECORATORS = {
    "login_required", "requires_auth", "permission_required",
    "permission_classes", "authentication_classes", "jwt_required",
    "csrf_protect", "staff_member_required",
}


def _py_decorator_head(deco_ast) -> str:
    """Best-effort rendering of a decorator's head name.

    Python-3.8-compatible (doesn't use ``ast.unparse``). Handles:
        @foo                → "foo"
        @foo.bar            → "foo.bar"
        @foo("arg")         → "foo"
        @foo.bar("arg")     → "foo.bar"
    """
    target = deco_ast.func if isinstance(deco_ast, ast.Call) else deco_ast

    def render(node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = render(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    return render(target)


def _parse_python(path: str, rel: str, content: str, result: dict) -> None:
    try:
        tree = ast.parse(content, filename=path)
    except SyntaxError:
        result["structure_summary"].append(f"{rel}: [parse error]")
        return

    source_lines = content.splitlines()
    functions: list[str] = []
    imports: list[str] = []

    # Collect all top-level and class-method function names first (for intra-file call graph)
    all_fn_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            all_fn_names.add(node.name)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            docstring = ast.get_docstring(node) or ""
            summary = (docstring.split("\n")[0][:80] if docstring
                       else _infer_summary_from_name(node.name))
            key = f"{rel}::{node.name}"
            result["function_summaries"][key] = summary
            result["function_start_lines"][key] = node.lineno
            functions.append(node.name)

            # ── access_control ────────────────────────────────────────
            # Python has no keyword visibility — infer from conventions.
            # ``_underscore_name`` → private-by-convention.
            # A route decorator (app.route / router.get / etc.) → "public".
            # An auth decorator (login_required, requires_auth, …) is
            # recorded as an inline modifier so the ACCESS_CONTROL matcher
            # can see it, mirroring how Solidity records ``[onlyOwner]``.
            deco_heads = [_py_decorator_head(d) for d in node.decorator_list]
            has_route = any(
                (h.split(".")[-1] in _PY_ROUTE_DECORATORS) for h in deco_heads
            )
            has_auth = any(
                (h.split(".")[-1] in _PY_AUTH_DECORATORS) for h in deco_heads
            )
            if has_route:
                vis_label = "public"
            elif node.name.startswith("_"):
                vis_label = "private"
            else:
                vis_label = "public"   # module-level sans underscore ≈ exported

            tags: list[str] = []
            if has_auth:
                tags.append("auth_required")
            for h in deco_heads:
                short = h.split(".")[-1]
                if short in _PY_AUTH_DECORATORS:
                    tags.append(short)
            ctrl = vis_label
            if tags:
                ctrl = f"{vis_label} [{', '.join(dict.fromkeys(tags))}]"
            result["access_control"][key] = ctrl

            # Full function body — no truncation
            fn_start = node.lineno - 1
            fn_end = getattr(node, "end_lineno", len(source_lines))
            result["function_bodies"][key] = "\n".join(source_lines[fn_start:fn_end])

            # Build call graph: both intra-file calls and external calls
            callees: list[str] = []
            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                if isinstance(child.func, ast.Attribute):
                    try:
                        obj = ast.unparse(child.func.value)
                        call_str = f"{obj}.{child.func.attr}()"
                    except Exception:
                        continue
                    if not call_str.startswith("self."):
                        result["external_calls"].append(f"{rel}:{node.name} → {call_str}")
                    callees.append(call_str)
                elif isinstance(child.func, ast.Name):
                    name = child.func.id
                    # Resolve intra-file calls to full keys
                    if name in all_fn_names:
                        callees.append(f"{rel}::{name}")
                    else:
                        callees.append(f"{name}()")

            if callees:
                result["call_graph"][key] = list(dict.fromkeys(callees))

        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            mod = getattr(node, "module", None) or ""
            for alias in getattr(node, "names", []):
                imports.append(f"{mod}.{alias.name}" if mod else alias.name)

    result["import_graph"][rel] = imports[:30]
    label = f"functions=[{', '.join(functions[:15])}]" if functions else ""
    result["structure_summary"].append(f"{rel}: {label}")


def _parse_solidity(path: str, rel: str, content: str, result: dict) -> None:
    contracts = re.findall(r"\b(?:contract|interface|library)\s+(\w+)", content)

    fn_pattern = re.compile(r"function\s+(\w+)\s*\(")
    mod_pattern = re.compile(
        r"function\s+\w+\s*\([^)]*\)\s*((?:[^{;])*)[{;]",
        re.DOTALL,
    )

    # ── Pass 1: collect names, bodies, modifiers ───────────────────────────
    functions: list[str] = []
    fn_data: dict[str, dict] = {}   # name → {key, body, start_line}

    for m in fn_pattern.finditer(content):
        name = m.group(1)
        functions.append(name)
        key = f"{rel}::{name}"
        start_line = content[:m.start()].count("\n") + 1

        mod_m = mod_pattern.match(content, m.start())
        modifiers = re.sub(r"\s+", " ", mod_m.group(1).strip()) if mod_m else ""

        visibility = "public"
        for v in ("public", "private", "internal", "external"):
            if re.search(r"\b" + v + r"\b", modifiers):
                visibility = v
                break

        skip_words = {
            "public", "private", "internal", "external", "view", "pure",
            "payable", "override", "virtual", "returns", "memory", "storage",
            "calldata", "indexed",
        }
        custom_mods = [
            w for w in re.split(r"[\s(),]+", modifiers)
            if w and w not in skip_words and re.match(r"^[A-Za-z_]\w*$", w)
        ]
        ctrl = visibility + (f" [{', '.join(custom_mods)}]" if custom_mods else "")

        body = _extract_sol_func_body(content, m.start())

        result["access_control"][key] = ctrl
        result["function_summaries"][key] = _infer_summary_from_name(name)
        result["function_start_lines"][key] = start_line
        result["function_bodies"][key] = body

        fn_data[name] = {"key": key, "body": body}

    all_fn_names = set(fn_data.keys())

    # ── Pass 2: build call graph now that all names are known ──────────────
    for name, data in fn_data.items():
        key  = data["key"]
        body = data["body"]
        callees: list[str] = []

        # obj.method() — cross-contract or library calls
        for cm in re.finditer(r"\b(\w+)\.(\w+)\s*\(", body):
            callees.append(f"{cm.group(1)}.{cm.group(2)}()")

        # Direct internal calls: functionName(...)
        for cm in re.finditer(r"\b(\w+)\s*\(", body):
            callee_name = cm.group(1)
            if callee_name in all_fn_names and callee_name != name:
                callees.append(f"{rel}::{callee_name}")

        if callees:
            result["call_graph"][key] = list(dict.fromkeys(callees))

    # ── State variables ────────────────────────────────────────────────────
    sv_pattern = re.compile(
        r"^\s*(mapping\s*\([^)]+\)|address|uint\d*|int\d*|bool|bytes\d*|string)\s+"
        r"(?:public\s+|private\s+|internal\s+)?(\w+)\s*;",
        re.MULTILINE,
    )
    for m in sv_pattern.finditer(content):
        result["state_variables"].append(f"{rel}: {m.group(0).strip()}")

    # ── External call sites ────────────────────────────────────────────────
    ext_pattern = re.compile(r"\b(\w+)\.(?:call|transfer|send|transferFrom|safeTransfer)\b")
    for m in ext_pattern.finditer(content):
        result["external_calls"].append(f"{rel}: {m.group(0)}")

    label = f"contracts=[{', '.join(contracts[:5])}] functions=[{', '.join(functions[:15])}]"
    result["structure_summary"].append(f"{rel}: {label}")


def _parse_js_ts(path: str, rel: str, content: str, result: dict) -> None:
    functions: list[str] = []

    fn_pattern = re.compile(
        r"(?:export\s+)?(?:async\s+)?(?:"
        r"function\s+(\w+)"
        r"|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>"
        r"|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function"
        r")"
    )
    # Detect Express/Koa/Fastify/Next.js route-register lines a few lines
    # up from each function definition (covers both inline handlers and
    # referenced handler variables).
    _ROUTE_RE = re.compile(
        r"\b(?:app|router|server|fastify)\s*\.\s*"
        r"(?:get|post|put|delete|patch|use|all|options|head)\s*\(",
        re.IGNORECASE,
    )
    _AUTH_RE = re.compile(
        r"\b(?:authenticate|requireAuth|isAuthenticated|jwt\.verify|"
        r"passport\.authenticate|csrfProtection|ensureAuth)\b",
        re.IGNORECASE,
    )
    _EXTCALL_RE = re.compile(
        r"\b(?:fetch\s*\(|axios\s*\.\s*\w+|\.\s*post\s*\(|\.\s*get\s*\("
        r"|new\s+XMLHttpRequest|new\s+WebSocket|navigator\.sendBeacon)",
    )

    for m in fn_pattern.finditer(content):
        name = m.group(1) or m.group(2) or m.group(3)
        if not name:
            continue
        functions.append(name)
        key = f"{rel}::{name}"
        start_line = content[:m.start()].count("\n") + 1
        result["function_summaries"][key] = _infer_summary_from_name(name)
        result["function_start_lines"][key] = start_line
        body = _extract_js_func_body(content, m.start())
        result["function_bodies"][key] = body

        # ── access_control ────────────────────────────────────────────
        # Look only at the 2 lines IMMEDIATELY preceding the definition
        # for a route-register call (Express-style inline handlers) —
        # anything further back belongs to a previous function and must
        # not bleed into this function's access_control.
        preamble_lines = content[: m.start()].splitlines()[-2:]
        preamble = "\n".join(preamble_lines)

        is_exported = bool(re.search(r"\bexport\b", content[m.start(): m.start() + 30]))
        has_route   = bool(_ROUTE_RE.search(preamble)) or bool(_ROUTE_RE.search(body[:200]))
        # Auth signals must come from THIS function's own body.
        has_auth    = bool(_AUTH_RE.search(body))

        if has_route or is_exported:
            vis_label = "public"
        elif name.startswith("_"):
            vis_label = "private"
        else:
            vis_label = "public"

        tags: list[str] = []
        if has_auth:
            tags.append("auth_check")
        ctrl = vis_label
        if tags:
            ctrl = f"{vis_label} [{', '.join(tags)}]"
        result["access_control"][key] = ctrl

        # ── external_calls ────────────────────────────────────────────
        for em in _EXTCALL_RE.finditer(body):
            line = start_line + body[: em.start()].count("\n")
            snippet = body[em.start(): em.start() + 80].splitlines()[0].strip()
            result["external_calls"].append(f"{rel}:{line}:{snippet}")

    all_fn_names = set(functions)

    # Build call graph
    for name in functions:
        key  = f"{rel}::{name}"
        body = result["function_bodies"].get(key, "")
        if not body:
            continue
        callees: list[str] = []
        for cm in re.finditer(r"\b(\w+)\s*\(", body):
            callee = cm.group(1)
            if callee in all_fn_names and callee != name:
                callees.append(f"{rel}::{callee}")
        for cm in re.finditer(r"\b(\w+)\.(\w+)\s*\(", body):
            callees.append(f"{cm.group(1)}.{cm.group(2)}()")
        if callees:
            result["call_graph"][key] = list(dict.fromkeys(callees))

    imports = re.findall(r"(?:import|require)\s*\(?['\"]([^'\"]+)['\"]", content)
    result["import_graph"][rel] = imports[:30]
    result["structure_summary"].append(
        f"{rel}: functions=[{', '.join(dict.fromkeys(functions))[:15]}]"
    )


_GO_HTTP_SIG_RE = re.compile(
    r"\(\s*\w+\s+http\.ResponseWriter\s*,\s*\w+\s+\*http\.Request\s*\)",
)
_GO_MIDDLE_RE = re.compile(
    r"\bmiddleware\.(?:Auth|Require|Protected|JWT)|AuthenticatedUser\(",
    re.IGNORECASE,
)
_GO_EXTCALL_RE = re.compile(
    r"\b(?:"
    r"http\.(?:Get|Post|Head|NewRequest|Do)"
    r"|exec\.Command"
    r"|rpc\.Call|client\.Call"
    r"|grpc\.Dial"
    r"|kafka\.Writer"
    r")",
)


def _parse_go(path: str, rel: str, content: str, result: dict) -> None:
    functions: list[str] = []
    fn_pat = re.compile(r"^func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(", re.MULTILINE)

    for m in fn_pat.finditer(content):
        name = m.group(1)
        functions.append(name)
        key = f"{rel}::{name}"
        start_line = content[:m.start()].count("\n") + 1
        result["function_summaries"][key] = _infer_summary_from_name(name)
        result["function_start_lines"][key] = start_line
        body = _extract_brace_body(content, m.start())
        result["function_bodies"][key] = body

        # ── access_control ────────────────────────────────────────────
        # Go visibility = capital first letter. HTTP handler signature
        # marks the function as a public entry-point regardless of name.
        # `middleware.Auth(...)` anywhere in the body ticks the auth box.
        sig_line = content[m.start(): m.start() + 200].splitlines()[0]
        is_http_handler = bool(_GO_HTTP_SIG_RE.search(sig_line))
        is_exported     = name[:1].isupper() if name else False
        has_auth        = bool(_GO_MIDDLE_RE.search(body))

        if is_http_handler or is_exported:
            vis_label = "public"
        else:
            vis_label = "private"

        tags: list[str] = []
        if is_http_handler:
            tags.append("http_handler")
        if has_auth:
            tags.append("auth_check")
        ctrl = vis_label
        if tags:
            ctrl = f"{vis_label} [{', '.join(tags)}]"
        result["access_control"][key] = ctrl

        # ── external_calls ────────────────────────────────────────────
        for em in _GO_EXTCALL_RE.finditer(body):
            line = start_line + body[: em.start()].count("\n")
            snippet = body[em.start(): em.start() + 80].splitlines()[0].strip()
            result["external_calls"].append(f"{rel}:{line}:{snippet}")

    all_fn_names = set(functions)
    for name in functions:
        key  = f"{rel}::{name}"
        body = result["function_bodies"].get(key, "")
        callees: list[str] = []
        for cm in re.finditer(r"\b(\w+)\s*\(", body):
            callee = cm.group(1)
            if callee in all_fn_names and callee != name:
                callees.append(f"{rel}::{callee}")
        if callees:
            result["call_graph"][key] = list(dict.fromkeys(callees))

    imports = re.findall(r'"([^"]+)"', content)
    result["import_graph"][rel] = [i for i in imports if "/" in i][:30]
    result["structure_summary"].append(
        f"{rel}: functions=[{', '.join(functions[:15])}]"
    )


_RUST_FN_PAT = re.compile(
    r"^"
    r"(?P<decorators>(?:\s*#\[[^\]]*\]\s*\n)*)"                 # zero-or-more attribute macros
    r"(?P<vis>pub(?:\([^)]*\))?\s+)?"                            # pub / pub(crate) / pub(super)
    r"(?:async\s+)?"
    r"(?:unsafe\s+)?"
    r"fn\s+(?P<name>\w+)\s*(?:<[^>]*>)?\s*\(",
    re.MULTILINE,
)

# Soroban / std patterns that cross a trust boundary.
_RUST_EXTCALL_PAT = re.compile(
    r"\b(?:"
    r"token_client\s*\.\s*(?:transfer|transfer_from|balance|burn|mint|approve|clawback|set_authorized)"
    r"|Client\s*::\s*new\b"
    r"|env\s*\.\s*invoke_contract\b"
    r"|\.invoke\s*\("
    r"|tokio\s*::\s*spawn\b"
    r"|std\s*::\s*process\s*::\s*Command\b"
    r"|reqwest\s*::\s*|reqwest_client\s*\."
    r")"
)

# Rust parser.
def _parse_rust(path: str, rel: str, content: str, result: dict) -> None:
    functions: list[str] = []

    for m in _RUST_FN_PAT.finditer(content):
        name = m.group("name")
        vis_raw = (m.group("vis") or "").strip()
        decorators_raw = (m.group("decorators") or "").strip()

        functions.append(name)
        key = f"{rel}::{name}"
        start_line = content[:m.start()].count("\n") + 1
        result["function_summaries"][key] = _infer_summary_from_name(name)
        result["function_start_lines"][key] = start_line
        body = _extract_brace_body(content, m.start())
        result["function_bodies"][key] = body

        # ── access_control ───────────────────────────────────────────────
        # Rust visibility + relevant attribute macros form the equivalent
        # of a Solidity modifier line. Solidity-like seed filters look for
        # "public"/"external" so we surface Rust visibilities in the same
        # vocabulary (``pub`` → effectively "public").
        vis_label = "private"
        if vis_raw:
            if "pub(crate)" in vis_raw:
                vis_label = "pub(crate)"
            elif "pub(super)" in vis_raw:
                vis_label = "pub(super)"
            elif vis_raw.startswith("pub"):
                vis_label = "public"   # Solidity-aligned label

        # Attribute macros like `#[only_admin]`, `#[access_control(...)]`
        # are tracked inside ``[...]`` — mirroring how the Solidity parser
        # records modifiers such as ``[onlyOwner, nonReentrant]``.
        macro_tags: list[str] = []
        for deco in re.findall(r"#\[([^\]]+)\]", decorators_raw):
            head = deco.strip().split("(", 1)[0].strip()
            # Ignore generic lints / test markers.
            if head in {"cfg", "allow", "deny", "warn", "test", "cfg_attr", "derive", "inline", "must_use", "doc"}:
                continue
            macro_tags.append(head)
        # Also check the body for an explicit ``require_auth(...)`` call —
        # it's effectively an in-function modifier on Soroban and we want
        # the downstream ACCESS_CONTROL matcher to see it.
        if re.search(r"\brequire_auth\s*\(", body):
            macro_tags.append("require_auth")

        ctrl = vis_label
        if macro_tags:
            ctrl = f"{vis_label} [{', '.join(dict.fromkeys(macro_tags))}]"
        result["access_control"][key] = ctrl

        # ── external_calls ───────────────────────────────────────────────
        for em in _RUST_EXTCALL_PAT.finditer(body):
            call_line = start_line + body[: em.start()].count("\n")
            snippet = body[em.start(): em.start() + 80].splitlines()[0]
            result["external_calls"].append(f"{rel}:{call_line}:{snippet.strip()}")

    # ── call_graph (unchanged) ──────────────────────────────────────────
    all_fn_names = set(functions)
    for name in functions:
        key  = f"{rel}::{name}"
        body = result["function_bodies"].get(key, "")
        callees: list[str] = []
        for cm in re.finditer(r"\b(\w+)\s*\(", body):
            callee = cm.group(1)
            if callee in all_fn_names and callee != name:
                callees.append(f"{rel}::{callee}")
        if callees:
            result["call_graph"][key] = list(dict.fromkeys(callees))

    result["structure_summary"].append(
        f"{rel}: functions=[{', '.join(functions[:15])}]"
    )


def _parse_cpp(path: str, rel: str, content: str, result: dict) -> None:
    """Parse C/C++ files: free functions, methods, classes, structs, includes."""
    functions: list[str] = []
    classes: list[str] = []

    # ── Classes / structs ─────────────────────────────────────────────────
    class_pat = re.compile(
        r"^\s*(?:template\s*<[^>]*>\s*)?(?:class|struct)\s+(\w+)",
        re.MULTILINE,
    )
    for m in class_pat.finditer(content):
        classes.append(m.group(1))

    # ── Function / method definitions ─────────────────────────────────────
    # Matches patterns like:
    #   TER Transactor::apply()
    #   void doApply(...)
    #   std::optional<T> funcName(...)
    #   NotTEC preflight(PreflightContext const& ctx)
    #   auto Class::method(...) -> ReturnType
    fn_pat = re.compile(
        r"^[ \t]*"
        r"(?:template\s*<[^>]*>\s*)?"                          # optional template<...>
        r"(?:static\s+|inline\s+|virtual\s+|constexpr\s+)*"   # optional qualifiers
        r"(?:"
        r"  (?:TER|NotTEC|TELresult|void|bool|int|unsigned|long|double|float|char|auto|size_t"
        r"  |std::\w+(?:<[^>]*>)?|Expected\w*|Buffer|uint(?:8|16|32|64)_t|int(?:8|16|32|64)_t"
        r"  |STAmount|STObject|STArray|AccountID|Currency|Keylet|SLE"
        r"  |Json::Value|Blob|Slice|ripple::\w+|beast::\w+|\w+Result"
        r"  |[A-Z]\w*)"                                        # return type
        r")"
        r"(?:\s*[&*])*\s+"                                     # pointers/refs
        r"(?:(\w+)::)?(\w+)"                                   # optional Class:: + funcName
        r"\s*\([^)]*\)"                                        # parameter list
        r"(?:\s*(?:const|noexcept|override|final|->[ \w:&*<>]+))*"  # trailing qualifiers
        r"\s*\{",                                               # opening brace
        re.MULTILINE | re.VERBOSE,
    )

    fn_data: dict[str, dict] = {}
    for m in fn_pat.finditer(content):
        cls_name = m.group(1) or ""
        func_name = m.group(2)
        if not func_name or func_name in ("if", "for", "while", "switch", "catch", "else"):
            continue

        qualified = f"{cls_name}::{func_name}" if cls_name else func_name
        functions.append(qualified)
        key = f"{rel}::{qualified}"
        start_line = content[:m.start()].count("\n") + 1

        body = _extract_brace_body(content, m.start())

        result["function_summaries"][key] = _infer_summary_from_name(func_name)
        result["function_start_lines"][key] = start_line
        result["function_bodies"][key] = body
        result["access_control"][key] = "public" if cls_name else "free"

        fn_data[qualified] = {"key": key, "body": body}

    # ── Call graph ────────────────────────────────────────────────────────
    all_fn_names = set(fn_data.keys())
    # Also build a short-name → qualified lookup for intra-file resolution
    short_to_qualified: dict[str, str] = {}
    for qname in all_fn_names:
        short = qname.split("::")[-1] if "::" in qname else qname
        short_to_qualified.setdefault(short, qname)

    for qname, data in fn_data.items():
        key = data["key"]
        body = data["body"]
        callees: list[str] = []

        # obj.method() or Class::method() calls
        for cm in re.finditer(r"\b(\w+)(?:::|\.)(\w+)\s*\(", body):
            call_q = f"{cm.group(1)}::{cm.group(2)}"
            if call_q in all_fn_names and call_q != qname:
                callees.append(f"{rel}::{call_q}")
            else:
                callees.append(f"{cm.group(1)}.{cm.group(2)}()")

        # Direct function calls: funcName(...)
        for cm in re.finditer(r"\b(\w+)\s*\(", body):
            callee_short = cm.group(1)
            if callee_short in short_to_qualified:
                resolved = short_to_qualified[callee_short]
                if resolved != qname:
                    callees.append(f"{rel}::{resolved}")

        if callees:
            result["call_graph"][key] = list(dict.fromkeys(callees))

    # ── Member variables (class-level state) ──────────────────────────────
    member_pat = re.compile(
        r"^\s+(?:mutable\s+)?(?:std::\w+(?:<[^>]*>)?|\w+)\s+(\w+)_;",
        re.MULTILINE,
    )
    for m in member_pat.finditer(content):
        result["state_variables"].append(f"{rel}: {m.group(0).strip()}")

    # ── #include graph ────────────────────────────────────────────────────
    includes = re.findall(r'#include\s*[<"]([^>"]+)[>"]', content)
    result["import_graph"][rel] = includes[:30]

    # ── External calls (potential security boundaries) ────────────────────
    ext_calls = re.findall(
        r"\b(exec\w*|system|popen|eval|ShellExecute|CreateProcess"
        r"|boost::process|std::system)\s*\(",
        content,
    )
    for call in ext_calls:
        result["external_calls"].append(f"{rel}: {call}()")

    label_parts = []
    if classes:
        label_parts.append(f"classes=[{', '.join(classes[:10])}]")
    if functions:
        label_parts.append(f"functions=[{', '.join(functions[:15])}]")
    result["structure_summary"].append(f"{rel}: {' '.join(label_parts)}")


def _parse_generic(path: str, rel: str, content: str, result: dict) -> None:
    """Fallback for languages without a dedicated AST parser.

    We still want Layer 5 to be able to analyse the code, so we expose the
    whole file as a single pseudo-function body. The LLM is reliable
    enough at finding function boundaries in raw source for the patterns
    our query packs care about (injection, hardcoded creds, SSRF, etc.).
    Granular call-graph analysis is lost — that needs a real parser per
    language — but the code becomes visible to Layer 5 instead of being
    silently skipped.
    """
    if not content.strip():
        return
    key = f"{rel}::__file__"
    truncated = content[:50_000]   # safety cap so a 5MB blob doesn't blow up
    result["function_bodies"][key] = truncated
    result["function_summaries"][key] = f"{rel} (raw file, no AST parser)"
    result["function_start_lines"][key] = 1
    result["structure_summary"].append(
        f"{rel}: [generic, {len(content)} bytes — full body exposed at "
        f"{key}]"
    )


# --------------------------------------------------------------------------- #
# Lua                                                                          #
# --------------------------------------------------------------------------- #

_LUA_FUNC_HEAD_RE = re.compile(
    r"^(\s*)"
    r"(?:local\s+)?"
    r"(?:function\s+([\w.:]+)|([\w.:]+)\s*=\s*function)"
    r"\s*\([^)]*\)",
    re.MULTILINE,
)

# Keywords that open a new ``end``-terminated block in Lua.
_LUA_OPEN_RE = re.compile(
    r"\b(function|if|while|for|do|repeat)\b",
)
_LUA_CLOSE_RE = re.compile(r"\b(end|until)\b")
_LUA_THEN_RE = re.compile(r"\bthen\b")


def _parse_lua(path: str, rel: str, content: str, result: dict) -> None:
    """Minimal Lua parser.

    Extracts function names + bodies via regex + naïve nesting count.
    Sufficient to populate ``function_bodies`` / ``function_start_lines``
    so Layer 5 LLM queries have code to analyse. Does NOT build a precise
    call graph — that would need lua-parser or tree-sitter-lua.
    """
    found_any = False
    for m in _LUA_FUNC_HEAD_RE.finditer(content):
        name = m.group(2) or m.group(3) or "<anon>"
        body_start = m.start()
        line_no = content.count("\n", 0, body_start) + 1
        body = _extract_lua_body(content, m.end())
        if not body:
            continue
        key = f"{rel}::{name}"
        result["function_bodies"][key] = (content[body_start:m.end()] + body)[:20_000]
        result["function_summaries"][key] = _infer_summary_from_name(name.split(".")[-1].split(":")[-1])
        result["function_start_lines"][key] = line_no
        found_any = True

    if found_any:
        result["structure_summary"].append(f"{rel}: lua, {content.count(chr(10)) + 1} lines")
    else:
        # Single function with no detectable head, or just module-level code.
        # Fall back to dumping the whole file like _parse_generic.
        _parse_generic(path, rel, content, result)


def _extract_lua_body(content: str, after_head: int) -> str:
    """Walk forward from after_head until the matching ``end`` of the function.

    Lua uses ``end`` to close ``function``/``if``/``while``/``for``/``do``,
    and ``until`` to close ``repeat``. We track depth: opens add to depth,
    closes subtract; the depth starts at 1 (we're inside the function).
    """
    depth = 1
    pos = after_head
    n = len(content)
    while pos < n and depth > 0:
        # Find next keyword. Whichever comes first wins.
        opener_m = _LUA_OPEN_RE.search(content, pos)
        closer_m = _LUA_CLOSE_RE.search(content, pos)
        if not closer_m:
            return content[after_head:pos + 5_000]   # unterminated, return chunk
        if opener_m and opener_m.start() < closer_m.start():
            # ``if`` / ``while`` / ``for`` need ``then``/``do`` before counting.
            kw = opener_m.group(1)
            if kw == "function":
                depth += 1
            elif kw in ("while", "for", "if"):
                # Skip past the matching ``then`` or ``do``.
                pos = opener_m.end()
                tail = _LUA_THEN_RE.search(content, pos) if kw == "if" else None
                if kw == "if":
                    if tail is None:
                        return content[after_head:pos + 5_000]
                    pos = tail.end()
                    depth += 1
                else:
                    do_pos = content.find("do", pos)
                    if do_pos == -1:
                        return content[after_head:pos + 5_000]
                    pos = do_pos + 2
                    depth += 1
                continue
            elif kw == "do":
                depth += 1
            elif kw == "repeat":
                depth += 1
            pos = opener_m.end()
        else:
            closer = closer_m.group(1)
            depth -= 1
            pos = closer_m.end()
            if depth == 0:
                return content[after_head:pos]
    return content[after_head:pos]


# ---------------------------------------------------------------------------
# Body extractors
# ---------------------------------------------------------------------------

def _extract_sol_func_body(content: str, start: int) -> str:
    """Extract a Solidity function body starting at *start* via brace counting.
    No line-count truncation — returns the complete function.
    """
    brace_pos = content.find("{", start)
    if brace_pos == -1:
        nl = content.find("\n", start)
        return content[start: nl if nl != -1 else start + 300].strip()

    depth = 0
    # Safety cap: skip past strings/comments is not perfect with this simple
    # scanner, but works for the vast majority of well-formed Solidity.
    for i in range(brace_pos, len(content)):
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[start: i + 1]
    return content[start: start + 5000]


def _extract_brace_body(content: str, start: int) -> str:
    """Generic brace-counting body extractor for Go / Rust / JS / TS."""
    brace_pos = content.find("{", start)
    if brace_pos == -1:
        nl = content.find("\n", start)
        return content[start: nl if nl != -1 else start + 300].strip()

    depth = 0
    for i in range(brace_pos, len(content)):
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[start: i + 1]
    return content[start: start + 5000]


def _extract_js_func_body(content: str, start: int) -> str:
    """JS/TS function body — handles both block bodies ({}) and arrow expressions."""
    # Arrow function with expression body: const f = () => expr
    arrow_expr = re.match(
        r"[^=]+=\s*(?:async\s*)?\([^)]*\)\s*=>\s*([^{;\n][^\n]*)",
        content[start:],
    )
    if arrow_expr and not content[start + arrow_expr.start(1):].lstrip().startswith("{"):
        end = content.find("\n", start + arrow_expr.start(1))
        return content[start: end if end != -1 else start + 200]

    return _extract_brace_body(content, start)


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def _infer_summary_from_name(name: str) -> str:
    s = re.sub(r"([A-Z])", r" \1", name).lower().replace("_", " ").strip()
    return s
