"""Python web backend platform adapter.

Covers FastAPI, Flask, Django, Starlette, and bare WSGI/ASGI handlers.
Smart-contract queries (reentrancy, flash_loan) are skipped. The remaining
two queries — access_control_gaps and trust_boundary_violations — get
Python-specific framing.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_PY_ROUTE = re.compile(
    r"@(?:app|router|blueprint|api|bp)\.(?:route|get|post|put|delete|patch|options|head)\b|"
    r"@(?:csrf_exempt|require_http_methods|api_view)\b|"
    r"path\s*\(\s*['\"]"  # Django urls.py
)
_RE_PY_AUTH = re.compile(
    r"@(?:login_required|requires_auth|permission_required|"
    r"authentication_classes|jwt_required|jwt_required_in_request|"
    r"token_required|admin_required|staff_member_required|"
    r"user_passes_test)\b|"
    r"\brequest\.user\.is_authenticated\b|"
    r"\bIsAuthenticated\b|"
    r"\bDepends\s*\(\s*get_current_user"
)


def _py_access_seed(key: str, body: str, ac: dict) -> bool:
    return bool(_RE_PY_ROUTE.search(body) and not _RE_PY_AUTH.search(body))


class WebPythonAdapter(PlatformAdapter):
    name = "web_python"
    label = "Web — Python (FastAPI / Flask / Django)"
    file_extensions = (".py",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".py"):
            return 0.0
        score = 0.0
        # Framework imports
        if re.search(r"\bfrom\s+(fastapi|flask|django|starlette|sanic|aiohttp|tornado|bottle|falcon)\b", content):
            score += 0.6
        if re.search(r"\bfrom\s+rest_framework\b", content):
            score += 0.5
        # Decorator-based routing
        if _RE_PY_ROUTE.search(content):
            score += 0.3
        # ASGI / WSGI app patterns
        if re.search(r"\b(?:app|application)\s*=\s*(?:Flask|FastAPI|Sanic|Starlette)\b", content):
            score += 0.2
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            # Smart-contract-only queries: skip
            "reentrancy_check":     QuerySpec(enabled=False, notes="Not a Python web concern."),
            "flash_loan_exposure":  QuerySpec(enabled=False, notes="Not applicable."),

            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Python web (FastAPI / Flask / Django / Starlette). "
                    "Auth lives in decorators (@login_required, @jwt_required, "
                    "@permission_required), middleware (Django auth middleware), "
                    "or DI dependencies (FastAPI `Depends(get_current_user)`). "
                    "For each route handler that mutates state (DB write, file write, "
                    "external API write, sending email) — check whether ANY of the above "
                    "is present. A bare @app.post(...) handler with no auth and "
                    "request.json being persisted is the bug. "
                    "Also flag IDOR: handlers that take an ID from path/query and read/write "
                    "without checking the row's ownership against request.user.id."
                ),
                seed_matcher=_py_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Python web. Trust-boundary risks include: "
                    "(a) `pickle.loads`, `yaml.load` (without SafeLoader), `eval()`, "
                    "`exec()` on any value reachable from request data → RCE; "
                    "(b) `requests.get(user_url)` → SSRF (must enforce a denylist for "
                    "10.0.0.0/8, 127.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, "
                    "::1, fc00::/7, link-local, 0.0.0.0/8); "
                    "(c) string concatenation into `cursor.execute(...)` or raw SQL → SQLi; "
                    "(d) `os.path.join(user_input, ...)` → path traversal; "
                    "(e) `subprocess.run(..., shell=True)` with user data → command injection; "
                    "(f) `Markup(user_html)` / `mark_safe(user_html)` → XSS."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "@login_required / Depends(...)":     "Python's auth decorator/DI patterns; missing on a write-handler = bug",
            "Django REST `permission_classes`":   "If empty or [AllowAny] on a state-mutating viewset, flag",
            "Pydantic models":                    "Schema validation at the boundary, but does NOT validate authorization",
            "raw `cursor.execute(...)` strings":  "If %s is not used (or string-fmt is used), SQLi candidate",
        }

    def exploit_harness_kind(self) -> str:
        return "pytest_httpx"


register(WebPythonAdapter())
