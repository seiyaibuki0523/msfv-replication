"""LLM PoC recipe generator (Layer 4.5, non-Solidity languages).

Produces a self-contained *execution recipe* for a single finding: a runnable
PoC file plus the build/run commands and the trigger oracle. The recipe is
executed by ``poc_sandbox.PocSandbox`` in an ephemeral, network-less
container.

Solidity does NOT go through here — its PoC already comes from Layer 4's
``poc_solidity`` field and runs via the existing host-forge path. This module
covers the self-contained languages (C/C++, Python, JS/TS, Go, Rust) where a
PoC can import the vulnerable function directly and prove the bug with a
benign-but-observable payload (or, for C/C++, a sanitizer fault).

Output fields (single-file PoC — far more parse-robust on vLLM than a
JSON-escaped code blob):

    poc_filename    e.g. "poc.cpp", "poc.py"
    poc_code        the complete runnable file
    build_command   compile step, or "" when none (Python/JS)
    run_command     how to run it
    trigger_on      "sanitizer_report" | "marker" | "nonzero_exit"
    assert_marker   the observable token proving the exploit fired
"""
from __future__ import annotations

import os

import dspy


# Language → toolchain hint injected into the prompt so the model picks a
# command set that exists in the sandbox image. Empty build for interpreted
# languages. The model still writes the exact command; this just anchors it.
_LANG_TOOLCHAIN: dict[str, str] = {
    "python": "build: (none).  run: python3 poc.py",
    "javascript": "build: (none).  run: node poc.js",
    "typescript": "build: (none).  run: node poc.mjs  (write plain JS)",
    "go": "build: go build -o poc poc.go   run: ./poc   (or: go run poc.go)",
    "c": "build: clang -fsanitize=address,undefined -g -o poc poc.c   run: ./poc",
    "cpp": "build: g++ -std=c++17 -fsanitize=address,undefined -g -o poc poc.cpp   run: ./poc",
    "rust": "build: rustc -g -o poc poc.rs   run: ./poc",
}

# Extension → canonical language key.
_EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
    ".rs": "rust",
}


def lang_for_file(file_path: str) -> str | None:
    """Map a finding's file to a sandbox language key, or None if the file is
    Solidity / unsupported (those skip this generator)."""
    _, ext = os.path.splitext((file_path or "").lower())
    return _EXT_LANG.get(ext)


class GeneratePoC(dspy.Signature):
    """You write a SELF-CONTAINED proof-of-concept that proves — by ACTUAL
    EXECUTION — whether the flagged vulnerability is real.

    The PoC runs in a locked-down container: no network, no host access,
    destroyed after the run. It must be a single runnable file that needs
    nothing but the toolchain (no live server, no database, no package
    install — there is no network to install from).

    ====================================================================
    HOW TO PROVE THE BUG (pick what fits the vulnerability class)
    ====================================================================

    * Memory-safety (C/C++/Rust/Go): compile WITH the sanitizer flags from
      the toolchain hint and drive the vulnerable function with the
      overflowing / use-after-free / OOB input. The sanitizer's runtime
      report IS the proof — set trigger_on="sanitizer_report". You do NOT
      need a marker; a clean run (no sanitizer fault) means the bug did not
      fire.

    * Injection / RCE (command injection, eval, deserialization): drive the
      vulnerable function with a payload whose ONLY effect is to print a
      unique marker, e.g. echo/print "PWNED_<uuid>". trigger_on="marker",
      assert_marker="PWNED_<uuid>". NEVER use a destructive payload (no rm,
      no network, no real secrets) — a benign observable marker is full proof.

    * Logic / auth / path-traversal: exercise the function so the exploit
      condition holds, then `assert` it (or read a sentinel file you planted
      under the working dir). On exploit, exit non-zero (assert/raise/panic)
      → trigger_on="nonzero_exit". A clean exit 0 means the code was safe.

    ====================================================================
    HARD RULES
    ====================================================================

    1. Reproduce the vulnerable function's logic faithfully: copy the
       relevant code from the provided source into the PoC (you cannot import
       the real project — there is no network and the repo is not mounted).
       Keep the vulnerable construct EXACTLY as written; only add the
       harness that drives it.
    2. Single file. No external packages. Only the standard library / built-in
       toolchain.
    3. Benign payloads only. The proof is an observable marker or a sanitizer
       fault — never real damage.
    4. If you genuinely cannot construct a deterministic PoC for this finding,
       set poc_code to the single line  SKIP  and leave the commands empty —
       do not fabricate a PoC that always passes.

    ====================================================================
    OUTPUT FORMAT
    ====================================================================
    The downstream parser reads the DSPy field markers. Always emit them.
    poc_filename / poc_code / build_command / run_command / trigger_on /
    assert_marker.
    """
    language: str = dspy.InputField()
    toolchain_hint: str = dspy.InputField()
    file_path: str = dspy.InputField()
    function_name: str = dspy.InputField()
    function_source: str = dspy.InputField()
    vulnerability: str = dspy.InputField()
    expected_outcome: str = dspy.InputField()

    poc_filename: str = dspy.OutputField(desc="e.g. poc.cpp / poc.py / poc.go")
    poc_code: str = dspy.OutputField(desc="complete runnable single file, or 'SKIP'")
    build_command: str = dspy.OutputField(desc="compile step, or empty for python/js")
    run_command: str = dspy.OutputField(desc="how to run, e.g. ./poc or python3 poc.py")
    trigger_on: str = dspy.OutputField(
        desc="one of: sanitizer_report | marker | nonzero_exit")
    assert_marker: str = dspy.OutputField(
        desc="the unique observable token proving the exploit fired (empty for sanitizer_report)")


class PocGenerator:
    """Wraps the GeneratePoC signature behind the configured backend chain."""

    def __init__(self):
        self._predict = dspy.Predict(GeneratePoC)

    def generate(
        self,
        *,
        language: str,
        file_path: str,
        function_name: str,
        function_source: str,
        vulnerability: str,
        expected_outcome: str = "",
    ) -> dict | None:
        """Return an execution recipe dict, or None when the model declines
        (SKIP) or the call fails. None → that finding gets no PoC signal
        (verify falls back to source-only, same as a forge compile failure)."""
        toolchain = _LANG_TOOLCHAIN.get(language, "")
        gen_lm = None
        try:
            from core.ai_engine.local_llm import resolve_task_chain
            gen_lm = resolve_task_chain("AISEC_POC_GEN_BACKEND", default_lm=None)
        except Exception:
            gen_lm = None

        try:
            if gen_lm is not None:
                with dspy.context(lm=gen_lm):
                    out = self._predict(
                        language=language, toolchain_hint=toolchain,
                        file_path=file_path, function_name=function_name,
                        function_source=function_source[:6000],
                        vulnerability=vulnerability[:2000],
                        expected_outcome=expected_outcome,
                    )
            else:
                out = self._predict(
                    language=language, toolchain_hint=toolchain,
                    file_path=file_path, function_name=function_name,
                    function_source=function_source[:6000],
                    vulnerability=vulnerability[:2000],
                    expected_outcome=expected_outcome,
                )
        except Exception:  # noqa: BLE001
            return None

        code = (getattr(out, "poc_code", "") or "").strip()
        if not code or code.strip() == "SKIP":
            return None
        # Strip an accidental ```lang fence the model may wrap the code in.
        code = _strip_fence(code)
        filename = (getattr(out, "poc_filename", "") or "").strip() or _default_name(language)
        trigger_on = (getattr(out, "trigger_on", "") or "").strip() or "nonzero_exit"
        if trigger_on not in ("sanitizer_report", "marker", "nonzero_exit"):
            trigger_on = "nonzero_exit"
        return {
            "files": [{"name": filename, "content": code}],
            "build_command": (getattr(out, "build_command", "") or "").strip(),
            "build_cmd": (getattr(out, "build_command", "") or "").strip(),
            "run_cmd": (getattr(out, "run_command", "") or "").strip() or _default_run(language, filename),
            "trigger_on": trigger_on,
            "assert_marker": (getattr(out, "assert_marker", "") or "").strip(),
            "poc_method": _method_for(language),
        }


def _strip_fence(code: str) -> str:
    s = code.strip()
    if s.startswith("```"):
        lines = s.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines)
    return code


def _default_name(language: str) -> str:
    return {
        "python": "poc.py", "javascript": "poc.js", "typescript": "poc.mjs",
        "go": "poc.go", "c": "poc.c", "cpp": "poc.cpp", "rust": "poc.rs",
    }.get(language, "poc.txt")


def _default_run(language: str, filename: str) -> str:
    if language == "python":
        return f"python3 {filename}"
    if language in ("javascript", "typescript"):
        return f"node {filename}"
    return "./poc"


def _method_for(language: str) -> str:
    return {
        "python": "pytest", "javascript": "node", "typescript": "node",
        "go": "gotest", "c": "cpp-asan", "cpp": "cpp-asan", "rust": "rustc",
    }.get(language, "container")


__all__ = ["PocGenerator", "GeneratePoC", "lang_for_file"]
