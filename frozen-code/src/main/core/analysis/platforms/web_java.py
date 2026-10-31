"""Java / Kotlin web backend adapter.

Covers Spring Boot (annotation-driven), Micronaut, Quarkus, Ktor (Kotlin),
JAX-RS, and bare Servlets. Spring's `@PreAuthorize` / Spring Security
filter chain is the canonical access pattern.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_JAVA_ROUTE = re.compile(
    r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(|"
    r"@(?:Path|GET|POST|PUT|DELETE|PATCH)\s*\(|"
    r"\brouting\s*\{|\broute\s*\(\s*HttpMethod"  # Ktor
)
_RE_JAVA_AUTH = re.compile(
    r"@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|RequiresAuthentication)\b|"
    r"\bSecurityContextHolder\.|@AuthenticationPrincipal\b|"
    r"\bauthenticate\b|\bauthentication\.isAuthenticated\(\)|"
    r"\bcall\.principal<.*>\(\)"  # Ktor
)


def _java_access_seed(key: str, body: str, ac: dict) -> bool:
    return bool(_RE_JAVA_ROUTE.search(body) and not _RE_JAVA_AUTH.search(body))


class WebJavaAdapter(PlatformAdapter):
    name = "web_java"
    label = "Web — Java / Kotlin (Spring Boot, Micronaut, Quarkus, Ktor)"
    file_extensions = (".java", ".kt", ".kts")

    def detect(self, file_path: str, content: str) -> float:
        ext = "." + file_path.lower().rsplit(".", 1)[-1] if "." in file_path else ""
        if ext not in self.file_extensions:
            return 0.0
        score = 0.0
        if re.search(r"\borg\.springframework\.", content):
            score += 0.6
        if re.search(r"\bio\.micronaut\.|\bjakarta\.ws\.rs\.|\bjavax\.ws\.rs\.", content):
            score += 0.5
        if re.search(r"\bio\.ktor\.", content):
            score += 0.5
        if re.search(r"\bio\.quarkus\.", content):
            score += 0.5
        if _RE_JAVA_ROUTE.search(content):
            score += 0.2
        if re.search(r"@(?:RestController|Controller|Path|ApplicationScoped)\b", content):
            score += 0.2
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check":     QuerySpec(enabled=False, notes="Not applicable."),
            "flash_loan_exposure":  QuerySpec(enabled=False, notes="Not applicable."),

            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Java/Kotlin web (Spring Boot / Micronaut / Quarkus / Ktor / JAX-RS). "
                    "Spring's auth model: `@PreAuthorize(\"hasRole('ADMIN')\")` on the method, "
                    "OR a `SecurityFilterChain` bean that gates `/api/admin/**` URLs. "
                    "Note that the FILTER CHAIN is global config — a method without "
                    "@PreAuthorize might still be safe if the chain covers its URL. "
                    "Conversely, `permitAll()` for an admin URL pattern is a bug. "
                    "Ktor: check `authenticate { route(...) }` blocks. "
                    "Flag handlers that mutate state and have neither a method-level "
                    "annotation nor (according to a SecurityConfig you can identify) "
                    "URL-level coverage. "
                    "IDOR: any @PathVariable Long id passed to repository.findById without "
                    "an ownership check is a classic Spring bug."
                ),
                seed_matcher=_java_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Java/Kotlin web. Trust risks: "
                    "(a) `ObjectInputStream.readObject()` on untrusted bytes → RCE "
                    "(Java deserialisation gadgets); "
                    "(b) Jackson `enableDefaultTyping()` / `@JsonTypeInfo` polymorphism "
                    "with untrusted JSON → RCE; "
                    "(c) SnakeYAML default constructor → RCE; "
                    "(d) `Runtime.getRuntime().exec(userStr)` / `ProcessBuilder` shell-split → command injection; "
                    "(e) `RestTemplate.getForObject(userURL, ...)` / `WebClient` → SSRF; "
                    "(f) raw JDBC string concat → SQLi (use PreparedStatement); "
                    "(g) JPA `@Query(\"... :param\")` is parameterised; "
                    "`createQuery(\"... \" + userStr)` is NOT; "
                    "(h) XXE: `DocumentBuilderFactory` without "
                    "`setFeature(\"disallow-doctype-decl\", true)`; "
                    "(i) Spring `@RequestMapping(...)` returning HTML with model attributes "
                    "from request → reflected XSS unless Thymeleaf escaping is on."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "`@PreAuthorize` annotation":     "Method-level Spring Security gate; missing on a write-method = candidate",
            "`SecurityFilterChain` bean":     "Global URL-level rules; check there before flagging method-level absence",
            "`permitAll()` in security cfg":  "Always inspect; common mis-config is to permitAll on /api/**",
            "Jackson `enableDefaultTyping`":  "Kills polymorphic safety — almost always wrong on untrusted input",
            "JPA repositories":               "`findById` is fine for read; ownership must be enforced manually",
        }

    def exploit_harness_kind(self) -> str:
        return "spring_test"


register(WebJavaAdapter())
