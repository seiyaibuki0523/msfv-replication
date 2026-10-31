"""C# / .NET web backend adapter.

Covers ASP.NET Core (controllers + minimal APIs), Razor Pages, Blazor
Server. Authentication = `[Authorize]` attribute or middleware policy
on the endpoint. Authorization policies live in `Program.cs` /
`Startup.cs`.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_CS_ROUTE = re.compile(
    r"\[(?:Http(?:Get|Post|Put|Delete|Patch))\b|"
    r"\bMap(?:Get|Post|Put|Delete|Patch|Methods)\s*\(|"
    r"\[Route\b"
)
_RE_CS_AUTH = re.compile(
    r"\[Authorize\b|\bRequireAuthorization\s*\(|"
    r"\bUser\.Identity\?\.IsAuthenticated\b|"
    r"\bIPrincipal\b|\bClaimsPrincipal\b"
)


def _cs_access_seed(key: str, body: str, ac: dict) -> bool:
    return bool(_RE_CS_ROUTE.search(body) and not _RE_CS_AUTH.search(body))


class WebCSharpAdapter(PlatformAdapter):
    name = "web_csharp"
    label = "Web — C# / .NET (ASP.NET Core, Minimal APIs)"
    file_extensions = (".cs",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".cs"):
            return 0.0
        score = 0.0
        if re.search(r"\busing\s+Microsoft\.AspNetCore\.", content):
            score += 0.6
        if re.search(r"\bControllerBase\b|\b: Controller\b", content):
            score += 0.3
        if _RE_CS_ROUTE.search(content):
            score += 0.3
        if re.search(r"\bWebApplication\.CreateBuilder\b|\bvar app\s*=\s*builder\.Build\(\)", content):
            score += 0.2
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check":     QuerySpec(enabled=False, notes="Not applicable."),
            "flash_loan_exposure":  QuerySpec(enabled=False, notes="Not applicable."),

            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: C# / ASP.NET Core (controllers + minimal APIs). "
                    "Auth = `[Authorize]` attribute on controller or action, OR "
                    "`.RequireAuthorization()` chained on a minimal-API endpoint, OR "
                    "middleware policies in `Program.cs` (`app.UseAuthentication(); "
                    "app.UseAuthorization();`) WITH per-endpoint policy. "
                    "Flag controllers/actions that mutate state and have no "
                    "`[Authorize]` AND no policy chain. "
                    "Note `[AllowAnonymous]` overrides `[Authorize]` — flag if it's "
                    "on a state-mutating action. "
                    "IDOR: actions taking `int id` and calling `_db.X.Find(id)` "
                    "without checking ownership against `User.FindFirstValue(...)`."
                ),
                seed_matcher=_cs_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: C# / .NET. Trust risks: "
                    "(a) `BinaryFormatter.Deserialize` on untrusted bytes → RCE "
                    "(deprecated for this reason); "
                    "(b) `JavaScriptSerializer` with `SimpleTypeResolver` → RCE; "
                    "(c) `XmlSerializer` with type-discriminator XML → potential RCE; "
                    "(d) `Process.Start(userStr, ...)` with `UseShellExecute = true` → cmd injection; "
                    "(e) `HttpClient.GetAsync(userURL)` → SSRF (denylist private CIDRs); "
                    "(f) raw `SqlCommand` with `CommandText = \"...\" + x` → SQLi "
                    "(use parameters); "
                    "(g) `Path.Combine(rootDir, userPath)` without `Path.GetFullPath` "
                    "+ `StartsWith(rootDir)` check → traversal; "
                    "(h) Razor `@Html.Raw(userStr)` → XSS."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "`[Authorize]` attribute":         "Action/controller-level gate; missing on write = candidate",
            "`.RequireAuthorization()`":        "Minimal-API endpoint gate; chain it on the MapPost",
            "`[AllowAnonymous]`":              "Overrides [Authorize] — flag on state-mutating action",
            "`BinaryFormatter`":               "Deprecated; presence is almost certainly a bug",
            "EF Core `FromSqlRaw`":            "Not parameterised; SQLi candidate when concatenated",
        }

    def exploit_harness_kind(self) -> str:
        return "aspnet_test"


register(WebCSharpAdapter())
