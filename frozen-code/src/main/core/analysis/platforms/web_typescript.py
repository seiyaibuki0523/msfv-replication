"""TypeScript / JavaScript web backend adapter.

Covers Express, NestJS, Next.js (route handlers + middleware), Fastify,
Koa, Hono. Threat model = standard web app: auth on routes, SSRF, SQLi
through ORM tag templates, prototype pollution, JSON.parse(eval'd) traps,
NoSQL injection.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_TS_ROUTE = re.compile(
    r"\b(?:app|router|fastify|koa)\.(?:get|post|put|delete|patch|use|all|options|head)\s*\(|"
    r"@(?:Get|Post|Put|Delete|Patch|All)\s*\(|"  # NestJS
    r"export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|DELETE|PATCH)\b"  # Next.js route handler
)
_RE_TS_AUTH = re.compile(
    r"\b(?:authenticate|requireAuth|isAuthenticated|requireUser|protectedRoute)\b|"
    r"\bjwt\.verify\b|\bpassport\.authenticate\b|"
    r"@(?:UseGuards|Roles|UseInterceptors)\b|"
    r"\bgetServerSession\b|\bauth\(\)|"
    r"\bcsrf\b"
)


def _ts_access_seed(key: str, body: str, ac: dict) -> bool:
    return bool(_RE_TS_ROUTE.search(body) and not _RE_TS_AUTH.search(body))


class WebTypeScriptAdapter(PlatformAdapter):
    name = "web_typescript"
    label = "Web — TypeScript / JavaScript (Express / NestJS / Next.js)"
    file_extensions = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs")

    def detect(self, file_path: str, content: str) -> float:
        ext = "." + file_path.lower().rsplit(".", 1)[-1] if "." in file_path else ""
        if ext not in self.file_extensions:
            return 0.0
        score = 0.0
        if re.search(r"\bfrom\s+['\"](?:express|fastify|koa|hono|@nestjs/common)['\"]", content):
            score += 0.6
        if re.search(r"['\"]next/server['\"]|next/headers", content):
            score += 0.5
        if re.search(r"\brequire\s*\(\s*['\"]express['\"]\s*\)", content):
            score += 0.5
        if _RE_TS_ROUTE.search(content):
            score += 0.3
        if re.search(r"\bres\.(?:json|send|status|cookie)\b", content):
            score += 0.1
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check":     QuerySpec(enabled=False, notes="Not applicable to JS/TS web."),
            "flash_loan_exposure":  QuerySpec(enabled=False, notes="Not applicable."),

            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: TypeScript/JavaScript web (Express, NestJS, Next.js, Fastify, Koa). "
                    "Auth mechanisms: middleware (`app.use(authMiddleware)` or per-route "
                    "`router.post(path, authMiddleware, handler)`), Passport, NestJS "
                    "`@UseGuards(AuthGuard)`, Next.js server-side `getServerSession()` / "
                    "`auth()`. For each handler that mutates state — check upstream "
                    "for guard. A handler that does `await db.users.update(req.body)` "
                    "with no auth check is the bug. Also flag IDOR: handlers reading/"
                    "writing by an ID from req.params / req.query / req.body without "
                    "checking ownership against req.user.id."
                ),
                seed_matcher=_ts_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: TS/JS web. Trust risks: "
                    "(a) `eval()`, `Function(...)`, `vm.runInNewContext` on user data → RCE; "
                    "(b) `JSON.parse` is generally safe, but `yaml.load` w/o safe schema isn't; "
                    "(c) `axios.get(req.body.url)` / `fetch(req.body.url)` → SSRF (denylist "
                    "private CIDRs); "
                    "(d) tagged-template / string concat into `db.query(...)` → SQLi; "
                    "(e) `Object.assign(target, req.body)` → prototype pollution / mass assignment; "
                    "(f) `child_process.exec(userStr)` → command injection; "
                    "(g) `dangerouslySetInnerHTML` with unescaped user content → XSS."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "Express middleware order":   "`app.use(authMiddleware)` BEFORE the routes is what gates them",
            "NestJS `@UseGuards`":        "Decorator-mounted guard; missing means handler is open",
            "Next.js Route Handlers":     "`app/api/.../route.ts` files — server-side; auth via `getServerSession()`",
            "Zod / Joi validation":       "Body validation, NOT authorisation",
            "Prisma / Drizzle queries":   "Parameterised by default — but `$queryRaw` / `sql.unsafe` is not",
        }

    def exploit_harness_kind(self) -> str:
        return "jest_supertest"


register(WebTypeScriptAdapter())
