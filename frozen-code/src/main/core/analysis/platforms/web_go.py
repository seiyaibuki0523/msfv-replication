"""Go web backend adapter.

Covers net/http, Gin, Echo, Chi, Fiber, gRPC handlers, and the standard
ServeHTTP pattern. Memos (the disclosure target the user is currently
working with) is one of these.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_GO_HANDLER = re.compile(
    r"func\s+\w+\s*\([^)]*http\.ResponseWriter[^)]*\*http\.Request|"
    r"func\s+\w+\s*\(\s*c\s+\*?(?:gin\.Context|echo\.Context|fiber\.Ctx|chi\.Mux)\b|"
    r"func\s+\([^)]+\)\s+ServeHTTP\s*\(",
    re.MULTILINE,
)
_RE_GO_AUTH = re.compile(
    r"\bmiddleware\.(?:Auth|Require|Protected|JWT|RequireAuth|RequireRole)\b|"
    r"\bauthn\.|\bauthz\.|\bAuthMiddleware\b|"
    r"\b\.Use\s*\(\s*[A-Z]\w*Auth\w*\b|"
    r"\bgetUser(?:FromCtx|FromRequest)\b|"
    r"\bUserFromContext\b"
)


def _go_access_seed(key: str, body: str, ac: dict) -> bool:
    return bool(_RE_GO_HANDLER.search(body) and not _RE_GO_AUTH.search(body))


class WebGoAdapter(PlatformAdapter):
    name = "web_go"
    label = "Web — Go (net/http, Gin, Echo, Chi, Fiber)"
    file_extensions = (".go",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".go"):
            return 0.0
        score = 0.0
        if re.search(r"\bnet/http\b", content):
            score += 0.5
        if re.search(r"\b(?:gin-gonic/gin|labstack/echo|go-chi/chi|gofiber/fiber)\b", content):
            score += 0.6
        if re.search(r"\bhttp\.(?:ListenAndServe|Handle|HandleFunc)\b", content):
            score += 0.3
        if _RE_GO_HANDLER.search(content):
            score += 0.2
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check":     QuerySpec(enabled=False, notes="Not applicable."),
            "flash_loan_exposure":  QuerySpec(enabled=False, notes="Not applicable."),

            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Go web (net/http, Gin, Echo, Chi, Fiber). "
                    "Auth lives in middleware: `r.Use(AuthMiddleware)`, "
                    "`router.Group(\"/api\", AuthMiddleware)`, or per-route wrappers. "
                    "For each handler mutating state — check the route registration "
                    "site, not just the handler body, to confirm a guard wraps it. "
                    "Pattern that's a bug: `r.HandleFunc(\"/admin/...\", h)` with no "
                    "auth middleware on r and no inline check inside h. "
                    "Also flag IDOR: handlers reading `chi.URLParam` / `c.Param` IDs "
                    "without checking ownership against `userFromCtx(ctx).ID`."
                ),
                seed_matcher=_go_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Go web. Trust risks: "
                    "(a) `os/exec.Command(userStr, ...)` with shell-style splitting → "
                    "command injection; "
                    "(b) `http.Get(userURL)` → SSRF (denylist 10/8, 127/8, 172.16/12, "
                    "192.168/16, 169.254/16, ::1, fc00::/7, link-local); "
                    "(c) string concat into `db.Query(\"SELECT ... \"+x)` → SQLi "
                    "(use parameterised `db.Query(\"... ?\", x)`); "
                    "(d) `path/filepath.Join(userPath, ...)` without `filepath.Clean` "
                    "and a base-prefix check → path traversal; "
                    "(e) `json.Unmarshal` of untrusted body into a struct with embedded "
                    "fields — accepts unknown fields silently unless `DisallowUnknownFields()`; "
                    "(f) `template/html` is auto-escaping; `text/template` is NOT — XSS risk; "
                    "(g) `gob.Decode` of untrusted bytes is RCE-equivalent."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "Chi router groups":          "`r.Group(...)` scope is where middleware applies; check the parent",
            "Gin `c.MustGet(\"user\")`":  "Used to retrieve auth'd user; if absent, route is unauthenticated",
            "`http.HandleFunc` direct":   "No router/group framing; auth must be inline. Frequent bug source.",
            "`exec.Command` w/ shell":    "Always inspect — Go's exec doesn't shell out unless the user did so",
            "`net/http` default client":  "Follows redirects to internal IPs by default → SSRF amplifier",
        }

    def exploit_harness_kind(self) -> str:
        return "go_httptest"


register(WebGoAdapter())
