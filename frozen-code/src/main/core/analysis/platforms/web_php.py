"""PHP web backend adapter.

Covers Laravel, Symfony, Slim, CodeIgniter, WordPress (themes + plugins),
and bare PHP scripts. PHP has the most varied auth surface — modern
Laravel/Symfony are middleware-driven; legacy code still has session
checks scattered through bare scripts.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_PHP_ROUTE = re.compile(
    r"\bRoute::(?:get|post|put|delete|patch|any|match)\s*\(|"
    r"#\[Route\b|"  # Symfony attributes
    r"\$app->(?:get|post|put|delete|patch|map)\s*\(|"  # Slim
    r"add_action\s*\(\s*['\"](?:wp_ajax|admin_post)|"  # WordPress AJAX
    r"^\s*function\s+\w+\s*\(\s*\$request\b",
    re.MULTILINE,
)
_RE_PHP_AUTH = re.compile(
    r"\bAuth::check\(\)|\bAuth::user\(\)|\bauth\(\)->check\(\)|"
    r"middleware\s*\(\s*['\"]auth|"  # Laravel
    r"->getUser\(\)|\bIsGranted\b|"  # Symfony
    r"current_user_can\s*\(|wp_verify_nonce\s*\(|"  # WordPress
    r"\$_SESSION\s*\[\s*['\"](?:user|auth|logged)"  # legacy session
)


def _php_access_seed(key: str, body: str, ac: dict) -> bool:
    return bool(_RE_PHP_ROUTE.search(body) and not _RE_PHP_AUTH.search(body))


class WebPHPAdapter(PlatformAdapter):
    name = "web_php"
    label = "Web — PHP (Laravel, Symfony, WordPress, Slim)"
    file_extensions = (".php",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".php"):
            return 0.0
        score = 0.4
        if re.search(r"\buse\s+Illuminate\\\\", content):
            score += 0.4
        if re.search(r"\buse\s+Symfony\\\\Component\\\\", content):
            score += 0.4
        if re.search(r"\bdefined\s*\(\s*['\"]ABSPATH['\"]\s*\)|wp_enqueue|add_action", content):
            score += 0.4  # WordPress
        if re.search(r"\bSlim\\\\App\b", content):
            score += 0.3
        if _RE_PHP_ROUTE.search(content):
            score += 0.2
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check":     QuerySpec(enabled=False, notes="Not applicable."),
            "flash_loan_exposure":  QuerySpec(enabled=False, notes="Not applicable."),

            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: PHP web (Laravel, Symfony, WordPress, Slim, bare PHP). "
                    "Per framework: "
                    "Laravel — `Route::post(..., [Ctrl::class, 'm'])->middleware('auth')` "
                    "OR `$this->middleware('auth')` in controller __construct(); "
                    "Symfony — `#[IsGranted('ROLE_USER')]` or `denyAccessUnlessGranted(...)`; "
                    "WordPress — `current_user_can('capability')` AND `wp_verify_nonce(...)` "
                    "for state-mutating AJAX/admin-post handlers; "
                    "legacy — `$_SESSION['user']` checks scattered ad-hoc. "
                    "Flag handlers that mutate DB or filesystem without any of these. "
                    "WordPress specifically: `add_action('wp_ajax_nopriv_...')` (note `_nopriv_`) "
                    "exposes the action to UNAUTHENTICATED users — flag if it does anything "
                    "more than read public data. "
                    "IDOR: `User::find($request->id)` / `$em->find(Entity::class, $id)` "
                    "without ownership scoping."
                ),
                seed_matcher=_php_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: PHP web. Trust risks: "
                    "(a) `unserialize($_POST['data'])` → object-injection / RCE via PHP gadgets "
                    "(POP chains in PHPGGC); "
                    "(b) `eval($userStr)`, `assert($userStr)`, `create_function` → RCE; "
                    "(c) `system`, `exec`, `shell_exec`, backticks with user input → command injection; "
                    "(d) `file_get_contents($userURL)`, `curl_exec` → SSRF "
                    "(PHP wrappers like `phar://`, `expect://`, `file://` add file-read paths); "
                    "(e) raw SQL via `mysqli_query(\"... \" . $x)` → SQLi (use prepared); "
                    "(f) `include $userPath` / `require $userPath` → LFI / RFI (RFI if "
                    "`allow_url_include = On`); "
                    "(g) `Smarty::display(userTemplate)` / Twig with ENV access → SSTI; "
                    "(h) WordPress `update_option`, `update_user_meta`, `wp_insert_post` "
                    "called without capability + nonce; "
                    "(i) XXE in `simplexml_load_string` if `LIBXML_NOENT` is passed."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "Laravel `middleware('auth')`":     "Route-/controller-level gate; absence on write = candidate",
            "Symfony `#[IsGranted(...)]`":      "Method-level gate; required on protected actions",
            "WP `_nopriv_` actions":            "Public AJAX endpoints; almost always over-permissioned",
            "WP `wp_verify_nonce`":             "CSRF token check; missing on write = bug",
            "`unserialize()`":                  "Always inspect — PHP object injection is endemic",
            "`include $var`":                   "LFI primitive; especially dangerous on legacy hosting",
        }

    def exploit_harness_kind(self) -> str:
        return "phpunit"


register(WebPHPAdapter())
