"""
Layer 2 — Semgrep static analysis.

Near-zero LLM cost. Runs semgrep CLI and returns structured findings
sorted by severity. Supports Solidity-specific rule sets.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


# Severity order for sorting
_SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2, "INVENTORY": 3}

# Language → extra Semgrep registry configs. Stacking ``p/security-audit``
# alongside the language pack consistently raises recall — the language
# packs miss many cross-language patterns (hardcoded creds, weak crypto,
# obvious SSRF) that the security-audit pack catches.
_LANG_CONFIGS: dict[str, list[str]] = {
    ".sol": ["p/smart-contracts", "p/security-audit"],
    ".py":  ["p/python", "p/security-audit"],
    # JS/TS: p/javascript alone misses Node-specific sinks (NoSQL, SSRF via
    # needle/request, plaintext-password, eval-on-req). Stacking p/nodejs +
    # p/nodejsscan raised nodegoat coverage 1/8 -> 3/8 GT files and 5 -> 24
    # findings. (p/express does NOT exist in the registry — adding it returns
    # exit 7 and zeroes the whole pass; do not add it.)
    ".js":  ["p/javascript", "p/nodejs", "p/nodejsscan", "p/security-audit"],
    ".ts":  ["p/typescript", "p/nodejs", "p/nodejsscan", "p/security-audit"],
    ".jsx": ["p/javascript", "p/nodejs", "p/security-audit"],
    ".tsx": ["p/typescript", "p/nodejs", "p/security-audit"],
    ".mjs": ["p/javascript", "p/nodejs", "p/nodejsscan", "p/security-audit"],
    ".cjs": ["p/javascript", "p/nodejs", "p/nodejsscan", "p/security-audit"],
    ".go":  ["p/golang", "p/security-audit"],
    ".java":["p/java", "p/security-audit"],
    ".kt":  ["p/kotlin", "p/security-audit"],
    ".rs":  ["p/rust", "p/security-audit"],
    ".php": ["p/php", "p/security-audit"],
    ".rb":  ["p/ruby", "p/security-audit"],
    ".cs":  ["p/csharp", "p/security-audit"],
    # C / C++ — p/cwe-top-25 + p/c gives much better recall on buffer
    # overflows / use-after-free than p/c alone.
    ".c":   ["p/c", "p/cwe-top-25", "p/security-audit"],
    ".cpp": ["p/c", "p/cwe-top-25", "p/security-audit"],
    ".cc":  ["p/c", "p/cwe-top-25", "p/security-audit"],
    ".cxx": ["p/c", "p/cwe-top-25", "p/security-audit"],
    ".h":   ["p/c", "p/cwe-top-25"],
    ".hpp": ["p/c", "p/cwe-top-25"],
    ".hxx": ["p/c", "p/cwe-top-25"],
    ".ipp": ["p/c", "p/cwe-top-25"],
    # Lua — Semgrep registry has no `p/lua` yet (as of 2026-05). Fall back
    # to the language-agnostic ``p/security-audit`` so we at least catch
    # hardcoded creds / SSRF patterns. Custom Lua rules go in
    # custom_rules/lua_security.yaml (Layer 5 LLM query pack covers the rest).
    ".lua": ["p/security-audit"],
    # Perl, Erlang/Elixir, R, Clojure, Dart, Swift, Move etc. fall through
    # to the language-agnostic security-audit pack.
    ".pl":  ["p/security-audit"],
    ".pm":  ["p/security-audit"],
    ".swift": ["p/security-audit"],
    ".dart": ["p/security-audit"],
    ".erl": ["p/security-audit"],
    ".ex":  ["p/security-audit"],
    ".exs": ["p/security-audit"],
}

# Custom rule files bundled with AISecTool, keyed by extension
_CUSTOM_RULES_DIR = Path(__file__).parent / "custom_rules"
_CUSTOM_RULES_BY_EXT: dict[str, str] = {
    ".sol": str(_CUSTOM_RULES_DIR / "solidity_security.yaml"),
    ".cpp": str(_CUSTOM_RULES_DIR / "cpp_security.yaml"),
    ".cc":  str(_CUSTOM_RULES_DIR / "cpp_security.yaml"),
    ".cxx": str(_CUSTOM_RULES_DIR / "cpp_security.yaml"),
    ".h":   str(_CUSTOM_RULES_DIR / "cpp_security.yaml"),
    ".hpp": str(_CUSTOM_RULES_DIR / "cpp_security.yaml"),
    # Common-language packs (registry misses framework/semantic sinks —
    # NoSQL $where, needle SSRF, pickle/yaml, Runtime.exec, unserialize, etc.).
    ".py":  str(_CUSTOM_RULES_DIR / "python_security.yaml"),
    ".js":  str(_CUSTOM_RULES_DIR / "nodejs_security.yaml"),
    ".jsx": str(_CUSTOM_RULES_DIR / "nodejs_security.yaml"),
    ".mjs": str(_CUSTOM_RULES_DIR / "nodejs_security.yaml"),
    ".cjs": str(_CUSTOM_RULES_DIR / "nodejs_security.yaml"),
    ".ts":  str(_CUSTOM_RULES_DIR / "nodejs_security.yaml"),
    ".tsx": str(_CUSTOM_RULES_DIR / "nodejs_security.yaml"),
    ".go":  str(_CUSTOM_RULES_DIR / "go_security.yaml"),
    ".java": str(_CUSTOM_RULES_DIR / "java_security.yaml"),
    ".php": str(_CUSTOM_RULES_DIR / "php_security.yaml"),
    ".rs":  str(_CUSTOM_RULES_DIR / "rust_security.yaml"),
    # HTML/template XSS (Django/Jinja |safe, autoescape off, script-context,
    # EJS unescaped) — registry packs don't scan templates; these are the
    # only rules covering template-injection XSS sinks.
    ".html": str(_CUSTOM_RULES_DIR / "template_security.yaml"),
    ".htm": str(_CUSTOM_RULES_DIR / "template_security.yaml"),
}


def run_semgrep(
    source_root: str,
    selected_files: list[str] | None = None,
    extra_configs: list[str] | None = None,
    timeout: int = 300,
) -> list[dict]:
    """
    Run semgrep on source_root and return a sorted list of findings.

    Args:
        source_root:    Root directory to scan.
        selected_files: If provided, pass as explicit targets instead of root.
        extra_configs:  Additional --config values (e.g. custom rule files).
        timeout:        Max seconds for semgrep to run.

    Returns:
        List of finding dicts sorted by severity (ERROR first).
    """
    if not _semgrep_available():
        return []

    # Detect which languages are present to add registry packs + custom rules
    exts = {Path(f).suffix.lower() for f in (selected_files or [])}
    lang_configs: list[str] = []
    for ext, configs in _LANG_CONFIGS.items():
        if ext in exts:
            lang_configs.extend(configs)

    # Inject custom AISecTool rules for detected languages
    custom_configs: list[str] = []
    for ext, rule_file in _CUSTOM_RULES_BY_EXT.items():
        if ext in exts and Path(rule_file).exists():
            custom_configs.append(rule_file)

    # Targets: prefer explicit file list to avoid scanning the whole repo
    targets = selected_files if selected_files else [source_root]

    # Two independent passes so a flaky network can't zero out the whole scan:
    #   LOCAL  — custom AISecTool rule files (on-disk YAML). Network-free,
    #            always succeeds. On Solidity this is the bulk of findings.
    #   REGISTRY — ``--config auto`` + registry language packs. These fetch
    #            from the Semgrep registry and FAIL ("requires login" / empty)
    #            during network blips. Best-effort: merged when it works,
    #            skipped when it doesn't. Previously a single combined command
    #            meant one registry hiccup returned 0 findings → degenerate
    #            detection (0 L4 candidates). See RUN 2026-06-10 network forensics.
    def _run(cfgs: list[str]) -> list[dict]:
        if not cfgs:
            return []
        # --metrics=off + --disable-version-check stop semgrep phoning home
        # to the public internet at startup. On a flaky public link those
        # calls hang/fail and can take the whole subprocess down (even the
        # network-free local-rules pass), which is how the LOCAL pass
        # returned 0 during a blip. With these flags the local pass is truly
        # offline and always produces its findings.
        cmd = ["semgrep", "--json", "--no-git-ignore",
               "--metrics=off", "--disable-version-check"]
        for c in cfgs:
            cmd += ["--config", c]
        cmd += targets
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        if proc.returncode not in (0, 1):
            return []
        return _parse_output(proc.stdout, source_root)

    local_cfgs = list(custom_configs) + list(extra_configs or [])
    # NOTE: do NOT add "auto" here. `--config auto` requires `--metrics=on`
    # (semgrep refuses with returncode 2: "Cannot create auto config when
    # metrics are off"), but we run with `--metrics=off` to keep the pass
    # network-quiet. The non-zero exit made `_run` discard the ENTIRE
    # registry pass — catastrophic for Python/JS, which have no custom local
    # rules (0 findings → degenerate detection). Solidity survived only
    # because its custom rule pack carried the local pass. The explicit
    # language packs in `_LANG_CONFIGS` already give full coverage (auto just
    # re-derives the same language→pack mapping), so drop auto entirely.
    registry_cfgs = list(set(lang_configs))

    findings = _run(local_cfgs)              # network-free, must-have
    findings += _run(registry_cfgs)          # best-effort, network-dependent

    # Dedup by (rule, file, line) since the two passes can overlap.
    seen = set()
    deduped = []
    for f in findings:
        key = (f.get("rule_id") or f.get("check_id"), f.get("file"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(f)
    return deduped


def _parse_output(stdout: str, source_root: str) -> list[dict]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    findings: list[dict] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        raw_path = r.get("path", "")
        start_line = r.get("start", {}).get("line", 0)
        end_line = r.get("end", {}).get("line", 0)
        raw_lines = extra.get("lines", "")

        # Normalise file path to repo-relative — Semgrep emits absolute
        # paths when given absolute targets, but global_map keys (used by
        # context_bundle._lookup_function_body) are always relative. A
        # mismatch silently fails the lookup, the LLM gets an empty
        # bundle, and answers "Confirmed: no" on every finding. RUN
        # MAC-19c showed Layer 4 produced zero confirmed findings
        # because of this. Compare commit pending.
        try:
            file_rel = os.path.relpath(raw_path, source_root)
            # If the file is outside source_root, relpath stays absolute-
            # looking with "../" prefix — keep raw_path then.
            if file_rel.startswith(".."):
                file_rel = raw_path
        except ValueError:
            file_rel = raw_path

        # Reconstitute the matched source when Semgrep redacts it.
        # Semgrep's registry / cloud rules return ``lines: "requires login"``
        # when the caller isn't authenticated to the Semgrep AppSec
        # Platform (anti-piracy mark on Pro-tier rules). The redaction
        # destroys downstream Layer 4 analysis because context_bundle's
        # carry-forward path uses this field. We replace it from disk.
        code_field = (raw_lines or "").strip()
        if not code_field or code_field == "requires login":
            code_field = _read_code_lines(raw_path, start_line, end_line) or raw_lines

        findings.append({
            "rule_id":  r.get("check_id", ""),
            "message":  extra.get("message", ""),
            "severity": extra.get("severity", "INFO").upper(),
            "file":     file_rel,
            "line":     start_line,
            "col":      r.get("start", {}).get("col", 0),
            "end_line": end_line,
            "code":     code_field,
            "cwe":      extra.get("metadata", {}).get("cwe", ""),
            "owasp":    extra.get("metadata", {}).get("owasp", ""),
            "confidence": extra.get("metadata", {}).get("confidence", ""),
        })

    return sorted(findings, key=lambda x: _SEVERITY_ORDER.get(x["severity"], 9))


def _read_code_lines(file_path: str, start_line: int, end_line: int) -> str:
    """Best-effort: read the matched line range from disk.

    Returns empty string on any I/O failure so the caller can fall back
    to whatever Semgrep originally provided. Adds 2 lines of context
    before/after for readability.
    """
    if not file_path or start_line <= 0:
        return ""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as fh:
            all_lines = fh.readlines()
    except OSError:
        return ""
    if end_line <= 0 or end_line < start_line:
        end_line = start_line
    # Pad slightly so the LLM sees a fence around the matched line.
    lo = max(0, start_line - 1 - 2)
    hi = min(len(all_lines), end_line + 2)
    return "".join(all_lines[lo:hi]).rstrip("\n")


def _semgrep_available() -> bool:
    try:
        subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def semgrep_summary(findings: list[dict]) -> str:
    """Compact human-readable summary for logging."""
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return ", ".join(f"{sev}: {n}" for sev, n in counts.items()) or "no findings"
