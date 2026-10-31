"""Swift web backend adapter (Vapor, Hummingbird).

Less common in audit/bounty space than the others, but increasingly
used for iOS app backends. Vapor's middleware model is the canonical
auth pattern.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_SWIFT_ROUTE = re.compile(
    r"\b(?:app|router|routes|grouped)\.(?:get|post|put|delete|patch|on)\s*\(|"
    r"\.grouped\("
)
_RE_SWIFT_AUTH = re.compile(
    r"\.grouped\s*\(\s*[A-Z]\w*Authenticator\b|"
    r"\.guardMiddleware\b|"
    r"\bUserAuthenticator\b|"
    r"\breq\.auth\.require\("
)


def _swift_access_seed(key: str, body: str, ac: dict) -> bool:
    return bool(_RE_SWIFT_ROUTE.search(body) and not _RE_SWIFT_AUTH.search(body))


class WebSwiftAdapter(PlatformAdapter):
    name = "web_swift"
    label = "Web — Swift (Vapor, Hummingbird)"
    file_extensions = (".swift",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".swift"):
            return 0.0
        score = 0.0
        if re.search(r"\bimport\s+Vapor\b", content):
            score += 0.7
        if re.search(r"\bimport\s+Hummingbird\b", content):
            score += 0.6
        if _RE_SWIFT_ROUTE.search(content):
            score += 0.2
        if re.search(r"\bRouteCollection\b|\bMiddleware\b", content):
            score += 0.2
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check":     QuerySpec(enabled=False, notes="Not applicable."),
            "flash_loan_exposure":  QuerySpec(enabled=False, notes="Not applicable."),

            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Swift web (Vapor / Hummingbird). "
                    "Vapor auth: `routes.grouped(UserAuthenticator(), User.guardMiddleware()).post(...)` "
                    "or `req.auth.require(User.self)` inside a handler. "
                    "Flag handlers that perform `req.db` mutations without either pattern."
                ),
                seed_matcher=_swift_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Swift web. Trust risks: "
                    "(a) `Process.run(userStr, ...)` → command injection; "
                    "(b) URLSession requests to user-controlled URLs → SSRF; "
                    "(c) raw SQL via Fluent's `.raw(SQLQueryString)` with concat → SQLi; "
                    "(d) JSON decoding into types with embedded raw `Any` payloads."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "`routes.grouped(...)`":            "Middleware-scoped routes; auth lives at the group",
            "`req.auth.require(User.self)`":    "In-handler auth assertion",
            "Fluent ORM queries":               "Parameterised by default; raw queries are not",
        }

    def exploit_harness_kind(self) -> str:
        return "xctest_vapor"


register(WebSwiftAdapter())
