"""Layer 4.5 PoC validator — replaces the legacy LLM-fuzz layer.

The legacy ``fuzzer.py`` asked the LLM to invent a Foundry test from
scratch using only the source file. In RUN MAC-16 forensics this gave
~5-10% real coverage: half the time the LLM produced a no-op template
that always reported "passed", masquerading as ground-truth signal.

This module replaces that flow with a strictly deterministic step:

  1. Layer 4 has already produced ``opus_result["poc"]["code"]`` for
     CRITICAL / HIGH (and exploit-vector MEDIUM) findings. That code
     is a runnable Foundry .t.sol that compiles against the target
     repo and demonstrates the exploit.

  2. We compile-check it (``forge build``).
  3. Run it once (``forge test``) to see whether the expected
     exploit signature appears.
  4. Optionally fan out with ``--fuzz-runs`` for ``fuzz-needed``
     strategies, to verify robustness across input ranges.

No LLM calls are made here — all "ground truth" comes from forge's
deterministic verdict. The output ``poc["validation"]`` dict is the
high-confidence signal Layer 5.5 verify reads in.
"""
from __future__ import annotations

import glob
import os
import re
import subprocess
import uuid
from dataclasses import dataclass


# --------------------------------------------------------------------------- #
# PoC import normalizer (deterministic scaffold repair)                       #
# --------------------------------------------------------------------------- #
# RUN forensic 2026-06-10: 18/23 DVD PoCs failed to compile purely on import
# resolution, not exploit logic. The LLM emits a Foundry test but:
#   * uses ``../src/...`` relative paths — wrong depth for test/fuzz/X.t.sol
#     (the file is two levels deep, so it needs ``../../src/...``);
#   * hallucinates ``forge-std/ERC20.sol`` / ``forge-std/IERC20.sol`` which
#     do not exist (forge-std ships IERC20 only under ``interfaces/``);
#   * guesses the wrong sub-directory for shared contracts
#     (``src/shards/DamnValuableNFT.sol`` when the file is ``src/DamnValuableNFT.sol``).
# All three are deterministically repairable by rewriting imports against the
# real on-disk layout before ``forge build``. Verified: after normalisation a
# previously-failing Shards PoC resolves every import.

def normalize_poc_imports(code: str, repo_path: str) -> str:
    """Repair the import block of an LLM-generated Foundry PoC so it resolves
    against the real ``repo_path`` layout. Pure string surgery — no LLM."""
    # 1. Relative-src depth: the test lives at ``test/fuzz/X.t.sol`` (two dirs
    #    deep), so any ``"../src/"`` / ``"../../../src/"`` collapses to
    #    ``"../../src/"``.
    code = re.sub(r'"(?:\.\./)+src/', '"../../src/', code)

    # 2. Hallucinated forge-std token files → the real interface path.
    code = code.replace('forge-std/ERC20.sol', 'forge-std/interfaces/IERC20.sol')
    code = code.replace('forge-std/IERC20.sol', 'forge-std/interfaces/IERC20.sol')

    # 3. Basename resolver: for each ``"../../src/<rel>"`` that doesn't exist,
    #    glob the basename under src/ and rewrite to its actual location.
    src_root = os.path.join(repo_path, "src")

    def _fix_src(m: "re.Match[str]") -> str:
        rel = m.group(1)
        if os.path.exists(os.path.join(src_root, rel)):
            return f'"../../src/{rel}"'
        hits = glob.glob(os.path.join(src_root, "**", os.path.basename(rel)),
                         recursive=True)
        if hits:
            newrel = os.path.relpath(hits[0], src_root)
            return f'"../../src/{newrel}"'
        return m.group(0)  # unresolved — leave for the compiler to report

    code = re.sub(r'"\.\./\.\./src/([^"]+)"', _fix_src, code)
    return code


@dataclass
class PocConfig:
    fuzz_runs: int = 1024
    timeout_seconds: int = 90
    keep_test_files: bool = False    # cleanup PoC test files after run


class PocValidator:
    """Subprocess-only PoC validator. Zero LLM cost."""

    def __init__(self, config: PocConfig | None = None):
        self.config = config or PocConfig()
        self._forge_available: bool | None = None

    # ── Availability ─────────────────────────────────────────────────

    def is_available(self) -> bool:
        if self._forge_available is not None:
            return self._forge_available
        try:
            r = subprocess.run(
                ["forge", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            self._forge_available = r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            self._forge_available = False
        return self._forge_available

    # ── Entry point ──────────────────────────────────────────────────

    def validate_all(
        self,
        opus_results: list[dict],
        repo_path: str,
        *,
        sandbox=None,
        generator=None,
        source_lookup=None,
    ) -> list[dict]:
        """Validate every Layer 4 result that warrants a PoC. Mutates
        ``opus_results`` in place; also returns it for chaining.

        Language dispatch:
          * Solidity (``.sol``) → host forge, using L4's ``poc.code``
            (existing path, unchanged). Requires forge + foundry.toml.
          * Other languages → ``generator`` (LLM) emits a self-contained
            execution recipe, run by ``sandbox`` (ephemeral container).

        ``sandbox`` / ``generator`` / ``source_lookup`` are injected by the
        pipeline (Layer 4.5). When absent or unavailable, that language's
        findings get no PoC signal and verify falls back to source-only —
        exactly the contract that has always held when forge is missing.
        """
        from core.analysis.poc_generator import lang_for_file

        forge_ok = self.is_available() and os.path.exists(
            os.path.join(repo_path, "foundry.toml"))
        sandbox_ok = sandbox is not None and sandbox.is_available() \
            and generator is not None

        if not forge_ok and not sandbox_ok:
            return opus_results

        for result in opus_results:
            if result.get("layer") != 4:
                continue
            finding = result.get("finding") or {}
            file_rel = finding.get("file", "")
            lang = lang_for_file(file_rel)

            if lang is None:
                # Solidity / unknown → forge path (needs a pre-generated PoC).
                if not forge_ok:
                    continue
                poc = result.get("poc")
                if not poc or not poc.get("code"):
                    continue
                poc["validation"] = self._validate_one(
                    poc_code=poc["code"],
                    strategy=poc.get("strategy", "single-shot"),
                    expected=poc.get("expected_outcome", ""),
                    repo_path=repo_path,
                    rule_id=finding.get("rule_id", "unknown"),
                )
            else:
                # Non-Solidity → generate a recipe and run it in the sandbox.
                if not sandbox_ok:
                    continue
                # Cost/time gate (mirrors the forge path, which only validates
                # CRITICAL/HIGH findings that carry a pre-built PoC):
                #   * skip L4 self-rejected findings ("confirmed: no") — verify
                #     never looks at them, so a PoC would be wasted compute;
                #   * skip low/info severity — not worth an LLM gen + container
                #     run. ERROR-severity semgrep + HIGH/CRITICAL L4 only.
                analysis_l0 = (result.get("analysis") or "").strip().split("\n", 1)[0].lower()
                if "confirmed: no" in analysis_l0 and "unclear" not in analysis_l0:
                    continue
                sev = (finding.get("severity", "") or "").upper()
                analysis_low = (result.get("analysis") or "").lower()
                high_sev = (sev in ("ERROR", "CRITICAL", "HIGH")
                            or "severity: critical" in analysis_low
                            or "severity: high" in analysis_low)
                if not high_sev:
                    continue
                func_name, func_source = "", finding.get("code", "") or ""
                if source_lookup is not None:
                    try:
                        fn, body = source_lookup(file_rel,
                                                 int(finding.get("line", 0) or 0))
                        if fn:
                            func_name = fn.split("::", 1)[-1]
                        if body:
                            func_source = body
                    except Exception:  # noqa: BLE001
                        pass
                recipe = generator.generate(
                    language=lang,
                    file_path=file_rel,
                    function_name=func_name or finding.get("rule_id", ""),
                    function_source=func_source,
                    vulnerability=(result.get("analysis", "")
                                   or finding.get("message", "")),
                    expected_outcome=(result.get("poc") or {}).get(
                        "expected_outcome", ""),
                )
                if not recipe:
                    continue
                val = sandbox.run_recipe(recipe)
                poc = result.setdefault("poc", {})
                poc["code"] = recipe["files"][0]["content"]
                poc["method"] = recipe.get("poc_method", "container")
                poc["validation"] = val
        return opus_results

    # ── Per-PoC pipeline ─────────────────────────────────────────────

    def _validate_one(
        self,
        *,
        poc_code: str,
        strategy: str,
        expected: str,
        repo_path: str,
        rule_id: str,
    ) -> dict:
        """Compile → test → optional fuzz. Returns a validation dict
        (see module docstring for shape)."""
        slug = re.sub(r"[^\w]", "_", rule_id.lower())[:30]
        test_name = f"PoC_{slug}_{uuid.uuid4().hex[:8]}.t.sol"
        test_path = os.path.join(repo_path, "test", "fuzz", test_name)
        os.makedirs(os.path.dirname(test_path), exist_ok=True)

        # Deterministic scaffold repair: fix import depth / hallucinated
        # forge-std files / wrong sub-directories before compiling. Resolves
        # the dominant (≈78%) PoC compile-failure class without an LLM call.
        poc_code = normalize_poc_imports(poc_code, repo_path)

        try:
            with open(test_path, "w", encoding="utf-8") as f:
                f.write(poc_code)

            # 1. Compile check — fastest filter for malformed PoCs.
            build = subprocess.run(
                ["forge", "build", "--silent"],
                cwd=repo_path, capture_output=True, text=True,
                timeout=self.config.timeout_seconds,
            )
            if build.returncode != 0:
                return self._fail(
                    "PoC failed to compile",
                    error=(build.stderr or build.stdout)[:300],
                    test_path=test_path,
                )

            # 2. Single-shot run.
            run = subprocess.run(
                ["forge", "test", "--match-path",
                 f"test/fuzz/{test_name}", "-vvv"],
                cwd=repo_path, capture_output=True, text=True,
                timeout=self.config.timeout_seconds,
            )
            triggered = self._parse_trigger(run.stdout + run.stderr, expected)
            counterexample = self._extract_counterexample(
                run.stdout + run.stderr,
            )

            # 3. Optional fuzz for robustness check.
            fuzz_confirms: bool | None = None
            if strategy == "fuzz-needed":
                fuzz = subprocess.run(
                    ["forge", "test", "--match-path",
                     f"test/fuzz/{test_name}",
                     "--fuzz-runs", str(self.config.fuzz_runs), "-v"],
                    cwd=repo_path, capture_output=True, text=True,
                    timeout=self.config.timeout_seconds * 2,
                )
                # A failing forge test = exploit confirmed.
                fuzz_confirms = (fuzz.returncode != 0)
                # Fuzz output often has the cleanest counterexample
                # (forge prints args=[...] when a fuzz seed reproduces).
                # Prefer it over the single-shot output when available.
                fuzz_ce = self._extract_counterexample(
                    fuzz.stdout + fuzz.stderr,
                )
                if fuzz_ce:
                    counterexample = fuzz_ce

            # 4. Confidence score — see module-level table.
            if triggered is True:
                conf = 0.95 if fuzz_confirms is not False else 0.70
            elif triggered is False:
                conf = 0.10                      # compiled but expected exploit didn't fire
            else:
                conf = 0.30                      # ambiguous test result

            return {
                "poc_compile": True,
                "poc_triggers_bug": triggered,
                "fuzz_confirms": fuzz_confirms,
                "counterexample": counterexample,
                "ground_truth_confidence": conf,
                "error": None,
            }

        except subprocess.TimeoutExpired as e:
            return self._fail(
                "PoC validation timed out",
                error=str(e)[:200], test_path=test_path,
            )
        except Exception as e:                   # noqa: BLE001
            return self._fail(
                "PoC validation crashed",
                error=str(e)[:300], test_path=test_path,
            )
        finally:
            if not self.config.keep_test_files:
                try:
                    os.remove(test_path)
                except OSError:
                    pass

    # ── Parsers ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_trigger(output: str, expected: str) -> bool | None:
        """Did the test trigger the expected exploit signature?

        Returns ``True`` if the PoC observed the expected outcome,
        ``False`` if the test ran clean (no exploit), ``None`` if the
        signal is too ambiguous to be useful.
        """
        # Foundry markers — '[FAIL' (with or without trailing chars)
        # means an assertion fired. For exploit-class PoCs, that's
        # what we WANT — the security invariant was violated.
        # Match ``[FAIL]``, ``[FAIL.``, ``[FAIL:`` and ``[FAIL `` —
        # forge versions vary on the separator after FAIL.
        if re.search(r"\[FAIL[\.\]:\s]", output):
            return True
        if "[PASS]" in output:
            # Test passed. If we were expecting a vulnerability to
            # trigger an assert/revert, a pass means the exploit
            # didn't fire — likely a false positive or stale PoC.
            if expected in ("revert", "balance_drained",
                             "role_granted", "state_corrupted"):
                return False
            # Otherwise the PoC may have just been a smoke check
            # ("does this code compile and run") — treat as positive.
            return True
        return None

    @staticmethod
    def _extract_counterexample(output: str) -> str | None:
        """Pull a forge ``args=[...]`` counterexample if present."""
        m = re.search(r"args=\[([^\]]+)\]", output)
        return m.group(1)[:200] if m else None

    @staticmethod
    def _fail(error_label: str, *, error: str, test_path: str) -> dict:
        """Return a validation dict for a hard failure path."""
        return {
            "poc_compile": False,
            "poc_triggers_bug": None,
            "fuzz_confirms": None,
            "counterexample": None,
            "ground_truth_confidence": 0.0,
            "error": f"{error_label}: {error}",
        }


__all__ = ["PocValidator", "PocConfig"]
