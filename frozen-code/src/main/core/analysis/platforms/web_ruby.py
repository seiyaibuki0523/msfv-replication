"""Ruby web backend adapter.

Covers Rails (controllers + actions), Sinatra, Hanami, Grape. Auth
= before_action filters, Devise / Pundit / CanCanCan helpers.
"""

from __future__ import annotations

import re

from .base import PlatformAdapter, QuerySpec, register


_RE_RB_ACTION = re.compile(
    r"^\s*def\s+\w+\b|"
    r"\b(?:get|post|put|delete|patch)\s+['\"]/[^'\"]+['\"]\s+do\b",
    re.MULTILINE,
)
_RE_RB_AUTH = re.compile(
    r"\bbefore_action\s+:authenticate|"
    r"\bauthenticate_user!|\brequire_login\b|\bskip_before_action\b|"
    r"\bauthorize\s*[!\(]|\bcan\?\s*\(|\bload_and_authorize_resource\b"
)


def _rb_access_seed(key: str, body: str, ac: dict) -> bool:
    return bool(_RE_RB_ACTION.search(body) and not _RE_RB_AUTH.search(body))


class WebRubyAdapter(PlatformAdapter):
    name = "web_ruby"
    label = "Web — Ruby (Rails, Sinatra, Hanami, Grape)"
    file_extensions = (".rb",)

    def detect(self, file_path: str, content: str) -> float:
        if not file_path.lower().endswith(".rb"):
            return 0.0
        score = 0.0
        if re.search(r"\bclass\s+\w+\s*<\s*ApplicationController\b", content):
            score += 0.7
        if re.search(r"\brequire\s+['\"]sinatra['\"]", content):
            score += 0.6
        if re.search(r"\bGrape::API\b|\bclass\s+\w+\s*<\s*Hanami::Action\b", content):
            score += 0.6
        if re.search(r"\bRails\.application\b|\bActiveRecord::Base\b", content):
            score += 0.3
        if _RE_RB_ACTION.search(content):
            score += 0.1
        return min(score, 1.0)

    def applicable_queries(self) -> dict[str, QuerySpec]:
        return {
            "reentrancy_check":     QuerySpec(enabled=False, notes="Not applicable."),
            "flash_loan_exposure":  QuerySpec(enabled=False, notes="Not applicable."),

            "access_control_gaps": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Ruby web (Rails, Sinatra, Hanami, Grape). "
                    "Auth in Rails: `before_action :authenticate_user!` (Devise) at the "
                    "controller class level, or per-action with `before_action :name, only: [...]`. "
                    "Authorisation: Pundit `authorize @post`, CanCanCan `load_and_authorize_resource`. "
                    "Flag controllers/actions that mutate state without ANY of these. "
                    "`skip_before_action :authenticate_user!` on a write-action is a bug magnet. "
                    "IDOR: `Post.find(params[:id])` without scoping by `current_user.posts.find(...)`."
                ),
                seed_matcher=_rb_access_seed,
            ),
            "trust_boundary_violations": QuerySpec(
                enabled=True,
                prompt_addendum=(
                    "PLATFORM: Ruby web. Trust risks: "
                    "(a) `Marshal.load` / `YAML.load` (without `safe_load`) on untrusted "
                    "bytes → RCE; "
                    "(b) `eval(userStr)`, `instance_eval`, `class_eval`, `send(userStr, ...)` "
                    "with user-controlled symbol → RCE; "
                    "(c) `system(userStr)`, backticks, `Open3.popen3(userStr)` → command injection; "
                    "(d) `Net::HTTP.get(URI(userURL))` / `open(userURL)` (open-uri) → SSRF; "
                    "(e) raw SQL: `Post.where(\"name = '#{x}'\")` → SQLi (use placeholders); "
                    "(f) `params.permit!` → mass assignment / privilege escalation; "
                    "(g) `render inline: userStr` / `<%= raw user %>` in ERB → XSS."
                ),
            ),
        }

    def codebase_signals(self) -> dict[str, str]:
        return {
            "`before_action :authenticate_user!`":   "Devise — auth gate; absence on a write controller = candidate",
            "`skip_before_action`":                  "Always inspect — easy to over-skip",
            "Pundit `authorize @x`":                 "Authorisation gate — missing call = privilege bug",
            "`params.permit(:x, :y)`":               "Mass-assignment whitelist; `permit!` opens the floodgates",
            "ActiveRecord `where(\"... #{x}\")`":    "String interp into SQL = SQLi",
        }

    def exploit_harness_kind(self) -> str:
        return "rspec_rack_test"


register(WebRubyAdapter())
