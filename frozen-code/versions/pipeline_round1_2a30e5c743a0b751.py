"""
CheckpointedPipeline — orchestrates Layers 0-5.5 for whitebox analysis.

Every phase saves state before moving on.  If the process is killed,
the next run resumes from the last completed phase automatically.

Usage:
    state = ScanState.load(target_id)          # resumes or creates fresh
    pipeline = CheckpointedPipeline(state)
    report = pipeline.run_whitebox(repo_path)
    # state is auto-saved throughout; cost tracked in state.total_cost_usd
"""

from __future__ import annotations

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import dspy

from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

# Side-effect import: triggers dspy.configure(lm=...) before any Predict runs.
import core.ai_engine.mixed_router  # type: ignore[import]  # noqa: F401

from core.analysis.scan_state import ScanState
from core.analysis.file_filter import filter_files
from core.analysis.global_map import build_global_map
from core.analysis.semgrep_runner import run_semgrep, semgrep_summary
from core.analysis.local_filter import filter_findings
from core.analysis.context_bundle import (
    build_context_bundle,
    format_bundle_for_prompt,
    GLOBAL_PATTERN_QUERIES,
    format_global_query_prompt,
)
from core.analysis.result_cache import get_cache
from core import hooks
from core.ui import tui
# NOTE: FoundryFuzzer (LLM-generates-test-from-scratch) was replaced by
# core.analysis.poc_validator in 2026-06. The legacy module is kept on
# disk for reference but no longer imported here. Restore by reverting
# the Layer 4.5 block change if needed.
# from core.analysis.fuzzer import FoundryFuzzer, FuzzConfig  # deprecated
from core.vault.prompts import render_finding_hint, render_patterns_for_query


# ---------------------------------------------------------------------------
# DSPy signatures for Opus deep-analysis calls
# ---------------------------------------------------------------------------

class AnalyseFinding(dspy.Signature):
    """You are a senior security auditor writing a Trail-of-Bits / Spearbit
    / FYEO-calibre deliverable. Every finding you confirm will appear in a
    paid client report — your ceiling is "the client should not need a
    second opinion on whether to fix this".

    Analyse the provided context bundle.

    ====================================================================
    CODEBASE LANGUAGE — read before anything else
    ====================================================================

    The context bundle may be ANY language: Solidity, Python, JavaScript /
    TypeScript, Go, Rust, Java, C/C++, PHP, Ruby, and others. Judge the
    finding strictly in the security context of the language and framework
    actually present in the bundle.

    Do NOT reject a finding because it "is not a smart-contract
    vulnerability" or "is a web-application issue, not Solidity". That is a
    domain mismatch in your own framing, not a property of the code. An OS
    command injection in a Django view, an insecure deserialization in a
    Flask app, an SSRF in an Express handler, a path traversal in Go — each
    is a real, confirmable vulnerability and must be analysed on its own
    terms exactly as you would a reentrancy bug in Solidity. The examples
    elsewhere in this prompt happen to be Solidity for historical reasons;
    translate them to the language at hand, never use them to narrow scope.

    ====================================================================
    HARD RULES — violations are caught downstream
    ====================================================================

    1.  Base your analysis strictly on the code in the context bundle.
        NEVER speculate beyond what the bundle shows. If the bundle only
        contains a function signature or a summary without the body, say
        so explicitly and rate the finding "informational".

    2.  NEVER emit a ``## Recommendation`` block unless you actually
        traced the vulnerability through real code. Generic boilerplate
        ("apply a reentrancy guard", "add input validation") with no
        line reference is not a recommendation — it is a guess.

    3.  Start the answer with a single line of the form::

            Confirmed: yes | no | unclear

        "unclear" means you saw the code but cannot determine
        exploitability without more context; treat it like a low-severity
        defensive suggestion, not a vulnerability.

    4.  If you write "Confirmed: no" or "Confirmed: unclear", do NOT
        follow up with a high/critical severity rating — that would
        contradict your own confidence signal.

    ====================================================================
    Required output sections (in this order, when Confirmed: yes)
    ====================================================================

    ``Confirmed: yes``
    ``Severity: <critical|high|medium|low|info>``    (Cevanex rubric —
        do NOT include a CVSS score; pipeline omits the field entirely.)

    ## Impact
    One paragraph explaining what an attacker can actually achieve.
    Frame it in CIA terms (Confidentiality / Integrity / Availability /
    Funds-at-risk) and quote the specific asset or invariant at risk in
    the language at hand — e.g. "drains USDC reserves of Vault.sol",
    "executes arbitrary shell commands via the delete() Django view",
    "leaks every user's session cookie through the reflected XSS in
    profile.ejs", "reads /etc/passwd via the path-traversal in the Go
    file handler" — not vague prose like "breaks the app".

    Description prose constraint — do NOT echo any of these patterns
    (they are our prompt scaffolding, not findings):
      *  "Audit-wide review for X-vulnerable patterns"
      *  "This finding relates to the Y class of vulnerabilities"
      *  "functions that perform external calls before state updates"
      *  Any sentence that doesn't reference at least one function name,
         file path, or specific code construct from the bundle.

    Title constraint — plain text only, ≤ 80 chars, NO markdown
    delimiters (no backticks, asterisks, underscores, brackets). Write
    "the _buyOne function" not "`_buyOne`".

    ## Attack Scenario
    Step-by-step exploitation walk-through. Each step cites a line
    number from the bundle. End with the post-condition the attacker
    achieves.

    State-mechanism bugs — when the bug involves multiple state
    variables or mechanisms running on different timing (e.g. a per-
    iteration transfer plus a batched bitmap write), trace each
    mechanism separately BEFORE describing the exploit, using exactly
    this structure:

        **Mechanism A** — what happens per iteration / per call
        **Mechanism B** — what happens at boundaries / on completion
        **Interaction** — how the attacker exploits the timing gap

    When tracing iterations, explicitly note for each step which values
    live in storage and which live in local / memory variables — never
    mix them in the same sentence without marking which is which.

    Do NOT include a ``## Proof-of-Concept`` section in
    vulnerability_analysis. The runnable PoC goes in ``poc_solidity``
    (a separate output field) — the report renderer stitches it back
    in so the client report has both prose and runnable code without
    you having to write the exploit twice.

    ## Recommendation
    Pick the structure that fits the bug. Do NOT default to the same
    "Primary fix / Defense in depth / References" triple every time.

      A) Simple bug (typo, missing check): one-line fix + (optional) why
         this class recurs.
      B) Logic flaw: primary fix (code change) + the invariant being
         restored + the risk of a partial fix.
      C) Architectural flaw: short-term mitigation (deployable today),
         medium-term refactor, long-term architectural change.
      D) Cross-contract / protocol-level: code-level fix in this
         contract, protocol-level consideration, operational mitigation.

    References — ONLY cite standard-ID sources: SWC-XXX, CWE-XXX,
    ERC-XXX, EIP-XXX, OWASP A##:YYYY, SCSVS-XXX. NEVER cite
    advisory-by-title ("ChainSecurity advisory on X"), blog post titles,
    or year-stamped writeup names — the pipeline strips anything that
    doesn't match a whitelisted ID format.

    When Confirmed: no / unclear, stop after ``## Impact`` and explain
    why the concern is not exploitable as flagged — do NOT emit the
    other sections. That is how a good auditor rejects a false positive:
    they explain the reasoning, not the fix.

    ====================================================================
    OUTPUT FORMAT — required even when answering "no issues"
    ====================================================================

    The downstream parser locates your answer by the
    ``[[ ## vulnerability_analysis ## ]]`` marker that DSPy wraps
    around the output field. Always emit the marker — even when the
    answer is "Confirmed: no" or "no issues found", your response
    MUST include the marker block so the parser can extract it.
    """
    context_bundle: str = dspy.InputField()
    vulnerability_analysis: str = dspy.OutputField(
        desc=(
            "Line 1: 'Confirmed: yes|no|unclear'. Line 2: 'Severity: ...'. "
            "Then '## Impact', '## Attack Scenario', '## Recommendation' "
            "(Primary fix / Defense in depth / References). DO NOT include "
            "'## Proof-of-Concept' — the runnable PoC goes in poc_solidity. "
            "If Confirmed: no|unclear, stop after '## Impact' with the rejection reason."
        )
    )
    # ── PoC fields(populated for CRITICAL+HIGH; empty otherwise)──
    poc_solidity: str = dspy.OutputField(
        desc=(
            "Populate ONLY when the context bundle's finding is CRITICAL or "
            "HIGH severity AND has a concrete attack path. A complete, "
            "self-contained Foundry .t.sol contract that compiles against "
            "the target repo and demonstrates the exploit. setUp() must do "
            "real contract deployment (use the constructor signature visible "
            "in the source). Keep under 100 lines. Empty string for findings "
            "without a concrete exploit vector."
        )
    )
    poc_strategy: str = dspy.OutputField(
        desc=(
            "One of: 'single-shot' (deterministic exploit, one call), "
            "'fuzz-needed' (needs varied input), 'stateful' (requires "
            "multi-tx setup), or 'none' (no PoC — abstract/defensive finding)."
        )
    )
    expected_outcome: str = dspy.OutputField(
        desc=(
            "What forge test should observe to confirm the exploit: "
            "'revert', 'balance_drained', 'role_granted', 'state_corrupted', "
            "or 'none' (when poc_strategy='none')."
        )
    )


class GlobalPatternQuery(dspy.Signature):
    """You are a senior security auditor writing a Trail-of-Bits /
    Spearbit / FYEO-calibre deliverable. Findings that survive into the
    client PDF must be defensible in a technical debrief — no "candidate
    functions that might be vulnerable if someone looked at them" filler.

    Answer the security query based ONLY on the actual function
    implementations supplied under ``## Function Implementations`` — i.e.
    code with visible bodies, not the plain function-name list in the
    global map. Reference specific function names, file paths, and
    literal lines of code.

    ====================================================================
    HARD RULES — non-negotiable, violations are caught downstream
    ====================================================================

    1.  NEVER speculate from function names or file structure. If the
        relevant code was not supplied, state "no function bodies provided
        for this query" and mark ``status: "no_evidence"``. Do NOT list
        "candidate functions that MUST be audited once their
        implementations are available" — that is not an audit finding.

    2.  NEVER emit a ``## Recommendation`` block for a finding you did
        not trace in actual code. Generic advice ("apply OpenZeppelin
        ReentrancyGuard", "add require_auth()") is only acceptable when
        it is paired with a specific line you cited.

    3.  NEVER invent a vulnerability title for a function whose body you
        could not inspect. If you can only see the name
        ``increment_token_id``, you cannot claim it has an access-control
        gap — you can only claim that its body was not supplied.

    4.  If the ``## Function Implementations`` section is empty, or
        every snippet it contains is test-only code, your answer MUST be
        exactly "No issues found — insufficient source code was supplied
        to this review stage for the requested vulnerability class." +
        a CONFIDENCE block with ``status: "no_evidence"``.

    ====================================================================
    Required structure per confirmed finding — ONE block per distinct issue
    ====================================================================

    CRITICAL: emit ONE ``###`` block per distinct vulnerability, even when
    several share a vulnerability *class*. ``cast_vote`` missing
    ``require_auth`` and ``count_vote`` accepting attacker-supplied weight
    are TWO findings — do NOT merge them into one.

    Use this exact template for every block:

    ### <one-line vulnerability title> — <path/to/file.ext>:<line>

    Title constraint: plain text only, ≤ 80 chars, NO markdown delimiters
    (no backticks, asterisks, underscores, brackets). The pipeline
    sanitises titles defensively — anything you write that looks like
    inline code is stripped.

    **Severity:** critical | high | medium | low | info
    (Cevanex rubric — do NOT include a CVSS score; pipeline drops it.)

    **Impact**  one paragraph in CIA terms. Name the asset / invariant
    at risk (e.g. "lets any caller burn another user's tokens",
    "permanently bricks the pause mechanism"). Do not pad with generic
    framing — every sentence should add information.

    Description prose constraint — never echo any of these scaffolding
    fragments (they are query templates, NOT findings):
      *  "Audit-wide review for ..."
      *  "Cross-function audit for the X vulnerability class"
      *  "functions that perform external calls before state updates"
      *  Any sentence without a function name / file path / specific
         code construct from the bundle.

    **Attack Scenario**  step-by-step exploitation, each step citing a
    line number. End with the post-condition the attacker achieves.

    State-mechanism bugs — when the bug spans multiple state variables
    or mechanisms on different timing (per-iteration loop transfer +
    batched bitmap write, etc.), trace each mechanism separately first
    using this exact structure:

        **Mechanism A** — what happens per iteration / per call
        **Mechanism B** — what happens at boundaries / on completion
        **Interaction** — how the attacker exploits the timing gap

    For iteration traces, mark each value as storage vs local / memory
    explicitly — do not mix them in the same sentence without saying so.

    **Recommendation**
    Pick the structure that fits the bug. Do NOT default to the same
    "Primary fix / Defense in depth / References" triple every time.

      A) Simple bug: one-line fix + why this class recurs (optional).
      B) Logic flaw: primary fix + invariant being restored + risk of
         partial fix.
      C) Architectural flaw: short-term mitigation, medium-term
         refactor, long-term architectural change.
      D) Cross-contract / protocol-level: code-level fix in this
         contract, protocol-level consideration, operational mitigation.

    - **Primary fix** — code-anchored, e.g. "Insert
      `admin.require_auth()` at line 48 of set_cap/storage.rs before
      the `env.storage().instance().set(...)` at line 51."
    - **References** — ONLY standard-ID sources: SWC-XXX, CWE-XXX,
      ERC-XXX, EIP-XXX, OWASP A##:YYYY, SCSVS-XXX. The pipeline strips
      anything else (advisory titles, blog names) as hallucination risk.

    ====================================================================
    Tone reference (one line per section — do not copy literally):
    ====================================================================

    ### Missing admin auth in `set_cap` — capped/storage.rs:48
    **Severity:** high
    **Impact** Any caller can raise the supply cap and mint freely
        (Integrity + Funds-at-risk).
    **Attack Scenario** Attacker calls `set_cap(env, u128::MAX)` at
        line 48, then mints arbitrarily.
    **Recommendation**
    - **Primary fix** Add `admin.require_auth()` at line 47, before
        the `storage().instance().set(&CAP, ...)` at line 51.
    - **Defense in depth** Add a `CAP_UPPER_BOUND` constant validated
        against `cap`.
    - **References** Soroban Authorization guide.

    ====================================================================
    Machine-parseable confidence block (MANDATORY, appears once at end)
    ====================================================================

    ---CONFIDENCE---
    {"status": "confirmed" | "speculative" | "no_evidence",
     "confirmed_count": <int: vulnerabilities you cited with line refs>,
     "severity_ceiling": "critical" | "high" | "medium" | "low" | "info",
     "reason": "<one sentence>"}
    ---END---

    Status values:
      - ``"confirmed"``   — you traced specific code and line numbers.
      - ``"speculative"`` — you saw relevant code but could not fully
        confirm exploitability; cap severity at "medium".
      - ``"no_evidence"`` — no usable bodies were supplied; severity "info".

    ====================================================================
    OUTPUT FORMAT — required even when answering "no issues"
    ====================================================================

    The downstream parser locates your answer by the
    ``[[ ## findings ## ]]`` marker that DSPy wraps around this output
    field. Always emit the marker — even when answering "No issues
    found", your response MUST be wrapped in the marker block. Some
    open-weight models (Nemotron, Gemma) use their own format
    conventions like ``---CONFIDENCE---`` — those are NOT recognised
    by the parser. The literal text ``[[ ## findings ## ]]`` is the
    only marker that works.
    """
    global_map_with_query: str = dspy.InputField()
    findings: str = dspy.OutputField(
        desc=(
            "Per-finding: '### title — path:line', then **Impact**, "
            "**Attack Scenario**, **Recommendation** (Primary fix / Defense in "
            "depth / References). Followed by a ---CONFIDENCE--- JSON block. "
            "Or 'No issues found — insufficient source code …' when no bodies "
            "were available."
        )
    )


class VerifyFinding(dspy.Signature):
    """You are verifying whether a previously-flagged security concern is valid
    against the actual source code of a specific function.

    Only answer based on the source code provided. Do NOT invent assumptions.
    Output strict JSON with one of three verdicts:
      {"verdict": "confirmed",   "severity": "high|medium|low", "reason": "..."}
      {"verdict": "downgraded",  "severity": "low|info",        "reason": "..."}
      {"verdict": "false_positive",                              "reason": "..."}

    Use "downgraded" when the concern has some merit (e.g. defense-in-depth
    suggestion, theoretical risk under unusual conditions) but is NOT a
    directly exploitable vulnerability at the originally flagged severity.

    ====================================================================
    OUTPUT FORMAT — strict marker required
    ====================================================================

    Wrap your JSON in the ``[[ ## verdict_json ## ]]`` marker that DSPy
    expects. Plain prose ("This is confirmed because…") or your own
    format conventions are NOT parsed. Even when uncertain, emit the
    marker block with your best-guess verdict — the verifier downstream
    handles ``verdict="error"`` separately.
    """
    verification_prompt: str = dspy.InputField()
    verdict_json: str = dspy.OutputField(
        desc='JSON: {"verdict": "confirmed"|"downgraded"|"false_positive", "severity": str, "reason": str}'
    )


class RepairPoC(dspy.Signature):
    """Repair a Foundry proof-of-concept test that failed to compile.

    You are given the original PoC source and the exact ``forge build``
    error. Fix ONLY what the compiler complains about — undeclared
    identifiers / typos, wrong type conversions, bad address checksums
    (use ``makeAddr("name")`` or ``vm.addr(uint)`` instead of hand-written
    hex), duplicate declarations, missing variables. Preserve the exploit
    logic and the contract/function under test.

    Import paths are already normalised by the harness — do NOT change
    import lines. The test file lives at ``test/fuzz/PoC.t.sol`` (two dirs
    deep); target contracts are imported via ``../../src/...``.

    ====================================================================
    OUTPUT FORMAT — strict marker required
    ====================================================================
    Emit ONLY the corrected, complete .t.sol source inside the
    ``[[ ## repaired_poc ## ]]`` marker. No prose, no markdown fences.
    """
    broken_poc: str = dspy.InputField(desc="The PoC source that failed to compile.")
    forge_error: str = dspy.InputField(desc="The forge build error output.")
    repaired_poc: str = dspy.OutputField(desc="Complete corrected .t.sol source.")


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class CheckpointedPipeline:
    """
    Runs the whitebox analysis pipeline (Layers 0-5) with full checkpointing.
    Each layer saves state before advancing so any interruption is resumable.
    """

    def __init__(
        self,
        state: ScanState,
        skill_context: str = "",
        custom_queries: list[dict] | None = None,
        file_scope: list[str] | None = None,
        parallel_workers: int = 1,
    ):
        self.state = state
        self.skill_context = skill_context
        self.custom_queries = custom_queries
        self.file_scope = file_scope
        # Concurrency cap for Opus calls in Layers 4 / 5 / 5.5. Set to 1 for
        # the legacy serial behaviour. Each call is independent so 3-4 is a
        # safe default; Anthropic tier-2 accounts handle that comfortably.
        self.parallel_workers = max(1, int(parallel_workers))
        self._analyser = dspy.Predict(AnalyseFinding)
        self._querier = dspy.Predict(GlobalPatternQuery)
        self._verifier = dspy.Predict(VerifyFinding)
        self._poc_repairer = dspy.Predict(RepairPoC)
        self._save_lock = threading.Lock()

    def run_whitebox(self, repo_path: str) -> list[dict]:
        """
        Execute all layers for a whitebox (source code) scan.
        Returns the list of confirmed/suspected vulnerability dicts.
        """
        s = self.state

        # ------------------------------------------------------------------
        # Layer 0: File selection
        # ------------------------------------------------------------------
        if s.current_phase == "init":
            tui.info("[Layer 0] Filtering files...")
            if self.file_scope:
                files = self.file_scope
                root = repo_path
                tui.info(f"[Layer 0] Using pre-scoped file list ({len(files)} files).")
            else:
                files, root = filter_files(repo_path)
            new_files = [f for f in files if s.file_changed(f, open(f, "rb").read())]
            s.selected_files = files
            tui.info(f"[Layer 0] Selected {len(files)} files ({len(new_files)} changed).")
            s.current_phase = "global_map"
            s.save()
        else:
            root = repo_path

        # ------------------------------------------------------------------
        # Layer 1: Global map (skip if already built for unchanged files)
        # ------------------------------------------------------------------
        if s.current_phase == "global_map":
            if not s.global_map:
                tui.info("[Layer 1] Building global map (AST analysis)...")
                s.global_map = build_global_map(s.selected_files, root)
                tui.info(
                    f"[Layer 1] Map: {len(s.global_map.get('function_summaries', {}))} functions, "
                    f"{len(s.global_map.get('state_variables', []))} state vars."
                )
            else:
                tui.info("[Layer 1] Global map already built — skipping.")
            s.current_phase = "semgrep"
            s.save()

        # ------------------------------------------------------------------
        # Layer 2: Semgrep
        # ------------------------------------------------------------------
        if s.current_phase == "semgrep":
            if not s.semgrep_results:
                tui.info("[Layer 2] Running Semgrep...")
                semgrep_findings = run_semgrep(root, selected_files=s.selected_files)
                tui.info(f"[Layer 2] Semgrep: {semgrep_summary(semgrep_findings)}")

                # Boundary validation: drop findings without a file
                # before any downstream layer sees them. Keeps Layer 3+
                # from ever seeing the empty-file_path edge that produced
                # placeholder noise findings in earlier experiments.
                pre_validate = len(semgrep_findings)
                semgrep_findings = [
                    f for f in semgrep_findings
                    if (f.get("file") or "").strip()
                ]
                dropped = pre_validate - len(semgrep_findings)
                if dropped:
                    tui.info(
                        f"[Layer 2] Dropped {dropped} findings with empty "
                        "file path before Layer 3"
                    )

                s.semgrep_results = semgrep_findings
            else:
                tui.info(f"[Layer 2] Layer-2 results cached ({len(s.semgrep_results)} findings).")
            s.current_phase = "local_filter"
            s.save()

        # ------------------------------------------------------------------
        # Layer 3: Local model false-positive filter
        # ------------------------------------------------------------------
        if s.current_phase == "local_filter":
            if not s.filtered_findings:
                # Cluster-mode opt-in: ``AISEC_CLUSTER_MODE=1`` switches
                # to the batched-cluster + 3-tier retry-ladder path with
                # linkage detection. Legacy per-finding ``filter_findings``
                # stays as the default for safety.
                try:
                    from core.analysis import cluster_filter
                    use_cluster = cluster_filter.is_enabled()
                except Exception:
                    use_cluster = False

                if use_cluster:
                    tui.info("[Layer 3] Cluster mode (3-tier ladder)...")
                    s.filtered_findings = cluster_filter.cluster_filter_findings(
                        s.semgrep_results, root, global_map=s.global_map,
                    )
                else:
                    tui.info("[Layer 3] Local model filtering (per-finding)...")
                    s.filtered_findings = filter_findings(
                        s.semgrep_results, root, global_map=s.global_map
                    )
                s.pending_findings = list(s.filtered_findings)
                tui.info(
                    f"[Layer 3] {len(s.filtered_findings)}/{len(s.semgrep_results)} "
                    "findings passed filter."
                )
            else:
                tui.info(f"[Layer 3] Using cached filtered findings ({len(s.filtered_findings)}).")

            # Skill-based fallback: when Layers 1-3 produce nothing but
            # skills are loaded, promote every scoped file into a synthetic
            # finding so Layer 4 can perform skill-guided deep analysis.
            if not s.filtered_findings and self.skill_context and s.selected_files:
                tui.info(
                    "[Layer 3] No Semgrep findings — generating per-file "
                    f"entries for skill-based Opus analysis ({len(s.selected_files)} files)."
                )
                synthetic = []
                for fpath in s.selected_files:
                    rel = os.path.relpath(fpath, root).replace("\\", "/")
                    synthetic.append({
                        "rule_id": "skill_audit",
                        "file": rel,
                        "line": 1,
                        "message": f"Skill-based deep audit of {rel}",
                        "severity": "info",
                        "synthetic": True,
                    })
                s.filtered_findings = synthetic
                s.pending_findings = list(synthetic)

            # Huff fallback: Semgrep / static analyzers don't speak Huff,
            # so any .huff file would otherwise be invisible to the
            # pipeline. Promote them unconditionally so Layer 4 sees the
            # source directly (Opus reads Huff fine).
            huff_files = [f for f in (s.selected_files or [])
                          if f.lower().endswith(".huff")]
            already_covered = {(fnd.get("file") or "") for fnd in s.filtered_findings}
            huff_synth = []
            for fpath in huff_files:
                rel = os.path.relpath(fpath, root).replace("\\", "/")
                if rel in already_covered:
                    continue
                huff_synth.append({
                    "rule_id": "huff_audit",
                    "file": rel,
                    "line": 1,
                    "message": (
                        f"Huff source — Semgrep cannot analyse; routing {rel} "
                        "to Layer 4 deep analysis. Watch for stack-residue / "
                        "uninitialized-stack bugs (macros that call() or "
                        "staticcall() and leave success bool on stack)."
                    ),
                    "severity": "info",
                    "synthetic": True,
                    "huff": True,
                })
            if huff_synth:
                tui.info(f"[Layer 3] Promoting {len(huff_synth)} .huff files to Layer 4.")
                s.filtered_findings = list(s.filtered_findings) + huff_synth
                s.pending_findings = list(s.pending_findings) + huff_synth

            s.current_phase = "opus_analysis"
            s.save()

        # ------------------------------------------------------------------
        # Layer 4: Opus deep analysis (resumable; concurrent when
        # parallel_workers > 1). Each finding's call is independent — the
        # only shared state is ScanState mutation, guarded by _save_lock.
        # ------------------------------------------------------------------
        if s.current_phase == "opus_analysis":
            total = len(s.filtered_findings)
            done = total - len(s.pending_findings)
            workers = min(self.parallel_workers, max(1, len(s.pending_findings)))
            tui.info(
                f"[Layer 4] Opus analysis: {done}/{total} findings done, "
                f"resuming with {workers} concurrent worker(s)..."
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan][Layer 4][/bold cyan] {task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task("Analysing findings...", total=total, completed=done)
                snapshot = list(s.pending_findings)
                first_exc: Exception | None = None

                # Warm Anthropic prompt cache once before fan-out so parallel
                # workers don't all incur cache-write overhead.
                self._prewarm("analyse")

                with ThreadPoolExecutor(max_workers=workers) as pool:
                    future_map = {
                        pool.submit(self._analyse_finding_worker, finding, root): finding
                        for finding in snapshot
                    }
                    for future in as_completed(future_map):
                        finding = future_map[future]
                        try:
                            (opus_result, prompt_toks, completion_toks,
                             cache_read_toks, cache_write_toks,
                             served_model) = future.result()
                        except Exception as e:
                            tui.error(f"[Layer 4] Opus call failed for "
                                      f"{finding.get('rule_id','?')} @ "
                                      f"{finding.get('file','?')}: {e}")
                            if first_exc is None:
                                first_exc = e
                            with self._save_lock:
                                s.save()
                            continue

                        # Round counter — increment based on cache hit vs
                        # real API call. Cache hits return zero tokens; the
                        # worker stamps ``cached: True`` on the result dict.
                        if opus_result.get("cached"):
                            with self._save_lock:
                                s.layer4_cache_hits += 1
                        elif prompt_toks or completion_toks:
                            with self._save_lock:
                                s.layer4_call_count += 1

                        # Drop Opus outputs that admit having insufficient
                        # context — these appear in the customer report as
                        # bare ``Confirmed: unclear`` placeholder findings
                        # with no analytical content (see RUN 10 forensics).
                        analysis_text = opus_result.get("analysis", "")
                        if _is_placeholder_analysis(analysis_text):
                            tui.info(
                                f"[Layer 4] dropped placeholder analysis for "
                                f"{finding.get('rule_id','?')} @ "
                                f"{finding.get('file','?')} "
                                "(insufficient-context response)"
                            )
                            with self._save_lock:
                                try:
                                    s.pending_findings.remove(finding)
                                except ValueError:
                                    pass
                                if prompt_toks or completion_toks:
                                    s.track_opus_usage(
                                        prompt_toks, completion_toks,
                                        model=served_model or "claude-opus-4-8",
                                        cache_read_tokens=cache_read_toks,
                                        cache_write_tokens=cache_write_toks,
                                    )
                                s.save()
                            progress.advance(task)
                            continue

                        with self._save_lock:
                            s.opus_results.append(opus_result)
                            try:
                                s.pending_findings.remove(finding)
                            except ValueError:
                                pass
                            if prompt_toks or completion_toks:
                                s.track_opus_usage(
                                    prompt_toks, completion_toks,
                                    model=served_model or "claude-opus-4-8",
                                    cache_read_tokens=cache_read_toks,
                                    cache_write_tokens=cache_write_toks,
                                )
                            s.save()

                        hooks.trigger("on_finding", {
                            "finding": finding,
                            "analysis": opus_result["analysis"],
                            "layer": 4,
                            "target_id": s.target_id,
                        })
                        short = f"{finding.get('rule_id','unknown')} @ {finding.get('file','')}"
                        progress.update(task, description=short[:60])
                        progress.advance(task)

                if first_exc is not None:
                    # Paper ablation knob: AISEC_TOLERANT_LAYER_ERRORS=1
                    # keeps successful per-finding results when a single
                    # LM call fails (e.g. open-weight model returning an
                    # empty response). Without this, one failed call in
                    # ~200 wastes 90% completed work — production keeps
                    # the strict behaviour for safety; paper experiments
                    # need the partial completion to measure FP rate.
                    if os.getenv("AISEC_TOLERANT_LAYER_ERRORS", "0") == "1":
                        tui.warning(
                            f"[Layer 4] tolerated per-call failure "
                            f"(AISEC_TOLERANT_LAYER_ERRORS=1): "
                            f"{type(first_exc).__name__}: {first_exc}"
                        )
                    else:
                        raise first_exc

            tui.info(f"[Layer 4] Complete. {s.status_line()}")
            s.current_phase = "fuzz"
            s.save()

        # ------------------------------------------------------------------
        # Layer 4.5: PoC validator (replaces legacy LLM-fuzz)
        #
        # Layer 4 emits ``opus_result["poc"]`` for CRITICAL/HIGH (and
        # exploit-vector MEDIUM) findings. We compile-check and run each
        # PoC against the target repo, no LLM calls. The ``poc.validation``
        # dict is read by Layer 5.5 as the strongest ground-truth signal.
        # Auto-skips when forge or foundry.toml are absent.
        # ------------------------------------------------------------------
        if s.current_phase == "fuzz":
            # Ablation knob (paper experiments): AISEC_DISABLE_POC_VALIDATOR=1
            # skips Layer 4.5 entirely. Used for the "detection only" baseline
            # in §4 to measure the FP rate without execution-based verification.
            if os.getenv("AISEC_DISABLE_POC_VALIDATOR", "0") == "1":
                tui.info("[Layer 4.5] disabled via AISEC_DISABLE_POC_VALIDATOR=1")
            else:
                from core.analysis.poc_validator import PocValidator, PocConfig
                from core.analysis.poc_sandbox import PocSandbox, SandboxConfig
                from core.analysis.poc_generator import PocGenerator
                from core.analysis.context_bundle import _lookup_function_body
                validator = PocValidator(PocConfig())
                sandbox = PocSandbox(SandboxConfig())
                generator = PocGenerator()
                forge_ok = validator.is_available()
                sandbox_ok = sandbox.is_available()
                if forge_ok or sandbox_ok:
                    # forge PoCs are pre-generated by L4 (poc.code); sandbox
                    # PoCs are generated on demand per non-Solidity finding.
                    forge_pocs = sum(
                        1 for r in s.opus_results
                        if r.get("layer") == 4
                        and (r.get("poc") or {}).get("code")
                    )
                    tui.info(
                        f"[Layer 4.5] PoC: forge={'on' if forge_ok else 'off'} "
                        f"({forge_pocs} pre-built), "
                        f"sandbox={'on' if sandbox_ok else 'off'} (LLM-generated)..."
                    )

                    def _src_lookup(file_rel: str, line: int):
                        return _lookup_function_body(s.global_map, file_rel, line)

                    s.opus_results = validator.validate_all(
                        s.opus_results, root,
                        sandbox=sandbox if sandbox_ok else None,
                        generator=generator if sandbox_ok else None,
                        source_lookup=_src_lookup,
                    )

                    # Compile-error repair retry (paper §IV — PoC signal
                    # rescue). forge-only: the normalizer fixes import-path
                    # failures deterministically; the residual ~22% are genuine
                    # LLM code bugs. Feed the forge error back to the LLM once
                    # for a focused repair. Disabled with AISEC_POC_NO_REPAIR=1.
                    if forge_ok and os.getenv("AISEC_POC_NO_REPAIR", "0") != "1":
                        self._repair_failed_pocs(s, validator, root)

                    triggered = sum(
                        1 for r in s.opus_results
                        if ((r.get("poc") or {}).get("validation") or {})
                                              .get("poc_triggers_bug") is True
                    )
                    compiled = sum(
                        1 for r in s.opus_results
                        if ((r.get("poc") or {}).get("validation") or {})
                                              .get("poc_compile") is True
                    )
                    tui.info(
                        f"[Layer 4.5] {compiled} PoCs compiled/ran, "
                        f"{triggered} triggered expected exploit"
                    )
                else:
                    tui.info("[Layer 4.5] no forge and no docker sandbox — skipping PoC.")
            s.current_phase = "global_queries"
            s.save()

        # ------------------------------------------------------------------
        # Layer 5: Global pattern queries (concurrent — each query is
        # independent, all read the immutable global_map snapshot).
        # ------------------------------------------------------------------
        if s.current_phase == "global_queries":
            queries = self.custom_queries if self.custom_queries else GLOBAL_PATTERN_QUERIES
            remaining = [q for q in queries if q["name"] not in s.global_queries_done]
            workers = min(self.parallel_workers, max(1, len(remaining)))
            tui.info(
                f"[Layer 5] Running {len(remaining)} global pattern queries "
                f"with {workers} concurrent worker(s)..."
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan][Layer 5][/bold cyan] {task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "Global queries...",
                    total=len(queries),
                    completed=len(s.global_queries_done),
                )

                first_exc: Exception | None = None
                if remaining:
                    self._prewarm("query")
                    with ThreadPoolExecutor(max_workers=workers) as pool:
                        future_map = {
                            pool.submit(self._global_query_worker, q): q
                            for q in remaining
                        }
                        for future in as_completed(future_map):
                            query = future_map[future]
                            try:
                                (findings_text, prompt_toks, completion_toks,
                                 cache_read_toks, cache_write_toks,
                                 served_model) = future.result()
                            except Exception as e:
                                tui.error(f"[Layer 5] Query '{query['name']}' failed: {e}")
                                if first_exc is None:
                                    first_exc = e
                                with self._save_lock:
                                    s.save()
                                continue

                            # Round counter — count real Opus calls only.
                            # Token presence is the cleanest signal for
                            # "hit the API" vs "served from cache".
                            if prompt_toks or completion_toks:
                                with self._save_lock:
                                    s.layer5_call_count += 1
                            else:
                                with self._save_lock:
                                    s.layer5_cache_hits += 1

                            # Skip Layer-5 placeholder responses where Opus
                            # echoed back the global_map sentinel
                            # (``_(No function bodies — re-run Layer 1.)_``)
                            # or otherwise said it had nothing to analyse.
                            if _is_placeholder_analysis(findings_text):
                                tui.info(
                                    f"[Layer 5] dropped placeholder result for "
                                    f"'{query['name']}' (sentinel/insufficient-context)"
                                )
                                with self._save_lock:
                                    s.global_queries_done.append(query["name"])
                                    if prompt_toks or completion_toks:
                                        s.track_opus_usage(
                                            prompt_toks, completion_toks,
                                            model=served_model or "claude-opus-4-8",
                                            cache_read_tokens=cache_read_toks,
                                            cache_write_tokens=cache_write_toks,
                                        )
                                    s.save()
                                progress.update(task, description=query["name"])
                                progress.advance(task)
                                continue

                            with self._save_lock:
                                s.opus_results.append({
                                    "query": query["name"],
                                    "findings": findings_text,
                                    "layer": 5,
                                })
                                s.global_queries_done.append(query["name"])
                                if prompt_toks or completion_toks:
                                    s.track_opus_usage(
                                        prompt_toks, completion_toks,
                                        model=served_model or "claude-opus-4-8",
                                        cache_read_tokens=cache_read_toks,
                                        cache_write_tokens=cache_write_toks,
                                    )
                                s.save()

                            progress.update(task, description=query["name"])
                            progress.advance(task)

                if first_exc is not None:
                    if os.getenv("AISEC_TOLERANT_LAYER_ERRORS", "0") == "1":
                        tui.warning(
                            f"[Layer 5] tolerated per-call failure "
                            f"(AISEC_TOLERANT_LAYER_ERRORS=1): "
                            f"{type(first_exc).__name__}: {first_exc}"
                        )
                    else:
                        raise first_exc

            s.current_phase = "verify_global"
            s.save()

        # ------------------------------------------------------------------
        # Layer 5.5: Verify Layer 5 findings against actual source code
        # ------------------------------------------------------------------
        if s.current_phase == "verify_global":
            # Ablation knob (paper experiments): AISEC_DISABLE_VERIFY=1 skips
            # Layer 5.5 entirely so the run terminates with raw Layer-4/5
            # output unverified. Used for the "detection only" baseline in §4
            # against which the paper measures verify's FP reduction.
            if os.getenv("AISEC_DISABLE_VERIFY", "0") == "1":
                tui.info("[Layer 5.5] disabled via AISEC_DISABLE_VERIFY=1")
                s.current_phase = "done"
                s.save()
                tui.info(f"[Done] {s.status_line()}")
                return s.opus_results

            # ── L4 verification (paper-aligned scope expansion) ───────────
            # Original v0.1 design only verified L5 prose findings. Paper
            # §III-B claims "each candidate" is verified. This block extends
            # the scope to L4 per-finding output too — every L4 result that
            # the model self-flagged as plausibly real (Confirmed: yes /
            # unclear) is re-evaluated with the same 4 signals (identity,
            # source, concern, PoC verdict) used for L5 findings.
            #
            # L4 self-rejected findings ("Confirmed: no" with reasoning)
            # are skipped — verifying a self-rejection is redundant and
            # would inflate L5.5 cost ~3× without changing outcomes.
            from core.analysis.context_bundle import _lookup_function_body

            l4_to_verify = []
            for r in s.opus_results:
                if r.get("layer") != 4:
                    continue
                if "verification" in r:
                    continue  # resume-safe
                a = (r.get("analysis") or "").strip()
                if _is_placeholder_analysis(a):
                    continue
                # Skip L4 self-rejected; only verify "yes" / "unclear"
                first_line = a.split("\n", 1)[0].lower()
                if "confirmed: no" in first_line and "unclear" not in first_line:
                    continue
                l4_to_verify.append(r)

            if l4_to_verify:
                tui.info(
                    f"[Layer 5.5] Verifying {len(l4_to_verify)} L4 findings "
                    f"(self-confirmed yes/unclear) against source + PoC signals..."
                )
                l4_targets: list[tuple[dict, str, str, str]] = []
                for L4_result in l4_to_verify:
                    finding = L4_result.get("finding") or {}
                    file_rel = finding.get("file", "")
                    line = int(finding.get("line", 0) or 0)
                    if not file_rel:
                        continue
                    func_key, func_body = _lookup_function_body(
                        s.global_map, file_rel, line,
                    )
                    if not func_key or not func_body:
                        # Finding fires outside any function body (pragma /
                        # import / file-level decl). Per the source-signal
                        # axiom — a vulnerability that cannot be anchored
                        # to executable code is necessarily a false
                        # positive. Mark it verified so the paper §III-D
                        # "each candidate verified" claim holds.
                        vr = [{
                            "function": file_rel,
                            "file": file_rel,
                            "verdict": "false_positive",
                            "severity": "info",
                            "reason": (
                                "no_function_body: Semgrep rule fired on a "
                                f"pragma/import/global decl at line {line} — "
                                "no executable code to anchor the concern."
                            ),
                        }]
                        with self._save_lock:
                            L4_result["verification"] = vr
                            _apply_verification_severity(L4_result, vr)
                            s.save()
                        continue
                    func_name = func_key.split("::", 1)[1] if "::" in func_key else func_key
                    l4_targets.append((L4_result, file_rel, func_name, func_body))

                if l4_targets:
                    verify_workers = min(self.parallel_workers, len(l4_targets))
                    self._prewarm("verify")
                    with ThreadPoolExecutor(max_workers=verify_workers) as vpool:
                        future_map = {
                            vpool.submit(
                                self._verify_function_worker,
                                file_rel, func_name, snippet,
                                L4_result.get("analysis", ""),
                            ): (L4_result, file_rel, func_name)
                            for (L4_result, file_rel, func_name, snippet) in l4_targets
                        }
                        for future in as_completed(future_map):
                            L4_result, file_rel, func_name = future_map[future]
                            try:
                                (parsed, prompt_toks, completion_toks,
                                 cache_read_toks, cache_write_toks,
                                 served_model) = future.result()
                                vr = [{
                                    "function": f"{file_rel}::{func_name}",
                                    "file": file_rel,
                                    "verdict": parsed["verdict"],
                                    "severity": parsed["severity"],
                                    "reason": parsed["reason"],
                                }]
                                if prompt_toks or completion_toks:
                                    with self._save_lock:
                                        s.track_opus_usage(
                                            prompt_toks, completion_toks,
                                            model=served_model or "claude-opus-4-8",
                                            cache_read_tokens=cache_read_toks,
                                            cache_write_tokens=cache_write_toks,
                                        )
                                        s.layer55_call_count += 1
                            except Exception as e:  # noqa: BLE001
                                tui.error(
                                    f"[Layer 5.5] L4 verify '{func_name}' failed: {e}"
                                )
                                vr = [{
                                    "function": f"{file_rel}::{func_name}",
                                    "file": file_rel,
                                    "verdict": "error",
                                    "severity": "",
                                    "reason": f"verify_error: {e}",
                                }]
                            with self._save_lock:
                                L4_result["verification"] = vr
                                _apply_verification_severity(L4_result, vr)
                                s.save()

            layer5_results = [r for r in s.opus_results if r.get("layer") == 5]
            pending = [r for r in layer5_results if "verification" not in r]
            tui.info(
                f"[Layer 5.5] Verifying {len(pending)} L5 findings against source code..."
            )

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan][Layer 5.5][/bold cyan] {task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task(
                    "Verifying...",
                    total=len(layer5_results),
                    completed=len(layer5_results) - len(pending),
                )

                for result in pending:
                    query_name = result.get("query", "unknown")
                    progress.update(task, description=query_name)
                    analysis_text = result.get("findings", "")

                    mentioned = _extract_mentioned_functions(analysis_text)
                    # Pre-resolve sources serially (cheap I/O) so the
                    # concurrent stage only does the Opus calls.
                    targets: list[tuple[str, str, str]] = []  # (file_rel, func_name, snippet)
                    for file_rel, func_name in mentioned:
                        snippet = _extract_function_source(root, file_rel, func_name)
                        if snippet:
                            targets.append((file_rel, func_name, snippet))

                    verification_results: list[dict] = []
                    if targets:
                        verify_workers = min(self.parallel_workers, len(targets))
                        # Warm verifier cache once per finding (cheap; the
                        # signature prompt is shared across all targets).
                        self._prewarm("verify")
                        with ThreadPoolExecutor(max_workers=verify_workers) as vpool:
                            future_map = {
                                vpool.submit(
                                    self._verify_function_worker,
                                    file_rel, func_name, snippet, analysis_text,
                                ): (file_rel, func_name)
                                for file_rel, func_name, snippet in targets
                            }
                            for future in as_completed(future_map):
                                file_rel, func_name = future_map[future]
                                try:
                                    (parsed, prompt_toks, completion_toks,
                                     cache_read_toks, cache_write_toks,
                                     served_model) = future.result()
                                    verification_results.append({
                                        "function": f"{file_rel}::{func_name}",
                                        "file": file_rel,
                                        "verdict": parsed["verdict"],
                                        "severity": parsed["severity"],
                                        "reason": parsed["reason"],
                                    })
                                    if prompt_toks or completion_toks:
                                        with self._save_lock:
                                            s.track_opus_usage(
                                                prompt_toks, completion_toks,
                                                model=served_model or "claude-opus-4-8",
                                                cache_read_tokens=cache_read_toks,
                                                cache_write_tokens=cache_write_toks,
                                            )
                                            s.layer55_call_count += 1
                                except Exception as e:
                                    # A crashed verify call previously
                                    # defaulted to ``verdict="confirmed"``,
                                    # which let LLM failures masquerade as
                                    # positive verification. Use ``error``
                                    # so ``_apply_verification_severity``
                                    # excludes it from the severity vote
                                    # instead of biasing the finding upward.
                                    tui.error(f"[Layer 5.5] Verify '{func_name}' failed: {e}")
                                    verification_results.append({
                                        "function": f"{file_rel}::{func_name}",
                                        "file": file_rel,
                                        "verdict": "error",
                                        "severity": "",
                                        "reason": f"verify_error: {e}",
                                    })

                    result["verification"] = verification_results
                    _apply_verification_severity(result, verification_results)
                    progress.advance(task)
                    s.save()

            s.current_phase = "done"
            s.save()
            tui.info(f"[Done] {s.status_line()}")

        return s.opus_results


# ---------------------------------------------------------------------------
# Layer 4 helpers
# ---------------------------------------------------------------------------

def _analyse_finding_worker(
    self, finding: dict, root: str
) -> tuple[dict, int, int, int, int, str]:
    """Run a single Layer-4 Opus analysis. Pure function over inputs —
    no shared mutable state. Returns ``(opus_result, prompt_tokens,
    completion_tokens, cache_read_tokens, cache_write_tokens,
    served_model)`` so the main thread can record usage atomically
    with Anthropic's three-tier prompt-cache billing — and attribute
    pricing to the actual backend (Opus vs Sonnet vs vLLM) under
    severity-aware routing.

    Content-hash cache: identical prompt text returns the cached
    analysis without calling Opus and reports zero token usage.

    Two-tier context (B-P1-1): when ``AISEC_TWO_TIER_CONTEXT=1`` and
    the reachable call surface is large enough to benefit, swap the
    eager bundle for the shallow rendering from ``two_tier_context``.
    """
    bundle = build_context_bundle(self.state.global_map, finding, root)

    # Two-tier path — currently text-mode only (no ReAct tool calls).
    # See ``two_tier_context.py`` module docstring for the activation
    # caveat. The shallow renderer still cuts ~30-50% of callee tokens
    # by replacing full bodies with one-line summaries, which is the
    # majority of the win when the chain is large.
    prompt_text = format_bundle_for_prompt(bundle)
    try:
        from core.analysis import two_tier_context
        if two_tier_context.is_enabled():
            from core.analysis.context_bundle import _resolve_callee  # noqa: PLC0415
            flagged_key = bundle.get("target_function_key", "")
            callee_count = len(bundle.get("callee_chain") or {})
            if flagged_key and callee_count >= two_tier_context.SMALL_CHAIN_THRESHOLD:
                shallow = two_tier_context.build_shallow(
                    flagged_key,
                    global_map=self.state.global_map,
                    resolve_callee=_resolve_callee,
                )
                shallow_md = two_tier_context.render_shallow(shallow)
                # Combine: keep the finding header from the eager bundle
                # (rule_id, severity, line cite) and replace only the
                # bulky callee chain section with the shallow rendering.
                finding_header = prompt_text.split("## Callee Chain", 1)[0] \
                    if "## Callee Chain" in prompt_text else prompt_text.split("## ", 1)[0]
                prompt_text = finding_header + "\n\n" + shallow_md
    except Exception:
        # Two-tier is best-effort; never let it break the worker.
        pass

    if self.skill_context:
        prompt_text = self.skill_context + "\n\n" + prompt_text

    vault_hint = render_finding_hint(
        finding,
        lang_hint=_lang_hint_from_path(finding.get("file", "")),
    )
    if vault_hint:
        prompt_text = vault_hint + "\n\n" + prompt_text

    cache = get_cache()
    if cache is not None:
        hit = cache.lookup("layer4", prompt_text)
        if hit is not None:
            cached = hit["result"]
            # Re-stamp the original finding dict so caller bookkeeping
            # (pending_findings list, hooks) keys against the live object.
            cached_result = {
                "finding": finding,
                "analysis": cached.get("analysis", ""),
                "layer": 4,
                "cached": True,
            }
            # Restore PoC if it was cached
            if cached.get("poc"):
                cached_result["poc"] = cached["poc"]
            return cached_result, 0, 0, 0, 0, ""

    # Severity-aware Layer 4 backend routing.
    # CRITICAL findings warrant Opus-level reasoning (audit-grade calls
    # about pass/fail). HIGH and MEDIUM are dominated by well-known
    # patterns (reentrancy, missing access control) that Sonnet handles
    # reliably and at ~40% the cost; Layer 5.5 verify still re-validates
    # using Nemotron, so the safety net for any Sonnet misses is intact.
    #
    # Backward compat: AISEC_ANALYSE_BACKEND (unscoped) still wins if set
    # — useful for one-off A/B tests where the operator wants every L4
    # call to hit the same backend.
    _severity_raw = (finding.get("severity") or "").lower()
    _severity_norm = {
        "critical": "critical", "high": "high", "medium": "medium",
        "error": "high", "warning": "medium", "info": "info",
    }.get(_severity_raw, _severity_raw)

    if _severity_norm == "critical":
        _analyse_env = "AISEC_ANALYSE_CRITICAL_BACKEND"
    else:
        _analyse_env = "AISEC_ANALYSE_HIGH_BACKEND"

    try:
        from core.ai_engine.local_llm import resolve_task_chain, resolve_task_lm
        # ``opus`` in a chain spec resolves via ``default_lm`` (it's the
        # global LM — already Opus by default). Without this, an
        # AISEC_ANALYSE_CRITICAL_BACKEND=opus,sonnet chain would silently
        # drop the opus link and fall to sonnet — which would defeat the
        # entire severity-aware routing.
        _global_lm = dspy.settings.lm
        # AISEC_ANALYSE_BACKEND (unscoped) is the legacy override and
        # takes precedence when set, so existing deploys keep working.
        if os.environ.get("AISEC_ANALYSE_BACKEND"):
            custom_lm = resolve_task_lm(
                "AISEC_ANALYSE_BACKEND", default_lm=_global_lm,
            )
        else:
            custom_lm = resolve_task_chain(
                _analyse_env, default_lm=_global_lm,
            )
    except Exception:
        custom_lm = None

    if custom_lm is not None:
        with dspy.context(lm=custom_lm):
            result = self._analyser(context_bundle=prompt_text)
    else:
        result = self._analyser(context_bundle=prompt_text)

    lm = custom_lm if custom_lm is not None else dspy.settings.lm
    prompt_toks = getattr(lm, "last_prompt_tokens", 0) or 0
    completion_toks = getattr(lm, "last_completion_tokens", 0) or 0
    cache_read_toks = getattr(lm, "last_cache_read_tokens", 0) or 0
    cache_write_toks = getattr(lm, "last_cache_creation_tokens", 0) or 0
    # ``served_model`` (FallbackLM) reflects the backend that ACTUALLY
    # answered; ``model`` would always name the chain's primary. Without
    # this, Sonnet calls under severity-aware routing get billed as Opus.
    served_model = (
        getattr(lm, "served_model", None)
        or getattr(lm, "model", "")
        or "claude-opus-4-8"
    )

    opus_result = {
        "finding": finding,
        "analysis": result.vulnerability_analysis,
        "layer": 4,
    }

    # ── PoC capture ───────────────────────────────────────────────────
    # CRITICAL/HIGH: accept the PoC whenever ``poc_solidity`` is non-
    # empty, even if the model also wrote ``poc_strategy='none'``. RUN
    # MAC-17v6 produced 0 PoCs across 30 high-severity findings because
    # the prior gate required ``strategy != 'none'`` for everyone —
    # models routinely return working exploit code alongside a defensive-
    # sounding strategy label, and gating on the label discarded the
    # code. The downstream forge runner only needs the code + a strategy
    # hint; an explicit ``'single-shot'`` fallback is safer than dropping
    # the whole PoC.
    #
    # MEDIUM: keep the stricter gate (``strategy != 'none'``) to filter
    # out abstract/defensive medium findings that don't deserve a PoC.
    severity_norm = _severity_norm

    if severity_norm in ("critical", "high", "medium"):
        poc_code = (getattr(result, "poc_solidity", "") or "").strip()
        poc_strategy = (getattr(result, "poc_strategy", "none") or "none").strip().lower()
        expected = (getattr(result, "expected_outcome", "none") or "none").strip().lower()

        # Strip markdown code fences if the LLM wrapped the contract
        if poc_code.startswith("```"):
            m = re.search(r"```(?:solidity)?\s*\n(.*?)```", poc_code, re.DOTALL)
            if m:
                poc_code = m.group(1).strip()

        accepts_poc = bool(poc_code) and (
            severity_norm in ("critical", "high")
            or poc_strategy != "none"
        )
        if accepts_poc:
            # Backfill a sane strategy when the model produced exploit
            # code but labelled it 'none' (common LLM consistency error).
            if poc_strategy == "none":
                poc_strategy = "single-shot"
            opus_result["poc"] = {
                "code": poc_code[:6000],          # hard cap on output bloat
                "strategy": poc_strategy,
                "expected_outcome": expected,
                "validation": None,                # filled by Layer 4.5
            }

    if cache is not None:
        cache.store("layer4", prompt_text,
                    {"analysis": opus_result["analysis"],
                     "poc": opus_result.get("poc")},
                    prompt_toks, completion_toks)

    return (
        opus_result, prompt_toks, completion_toks,
        cache_read_toks, cache_write_toks, served_model,
    )


# Register as method on CheckpointedPipeline (defined above) so the worker
# closes over per-instance state (analyser, skill_context, state).
CheckpointedPipeline._analyse_finding_worker = _analyse_finding_worker


def _global_query_worker(
    self, query: dict
) -> tuple[str, int, int, int, int, str]:
    """Run a single Layer-5 pattern query. Returns
    ``(findings_text, prompt_tokens, completion_tokens,
    cache_read_tokens, cache_write_tokens, served_model)``.
    """
    prompt_text = format_global_query_prompt(self.state.global_map, query)
    vault_patterns = render_patterns_for_query(query["name"])
    if vault_patterns:
        prompt_text = vault_patterns + "\n\n" + prompt_text

    cache = get_cache()
    if cache is not None:
        hit = cache.lookup("layer5", prompt_text)
        if hit is not None:
            return hit["result"].get("findings", ""), 0, 0, 0, 0, ""

    # Layer 5 backend: chain-aware so a vLLM outage falls through to
    # Sonnet/Opus instead of crashing the worker — matches Layers 4 and
    # 5.5. Previously ``resolve_task_lm`` only used the first link of a
    # comma-separated spec, defeating the FallbackLM safety net.
    try:
        from core.ai_engine.local_llm import resolve_task_chain
        custom_lm = resolve_task_chain(
            "AISEC_QUERY_BACKEND", default_lm=dspy.settings.lm,
        )
    except Exception:
        custom_lm = None

    if custom_lm is not None:
        with dspy.context(lm=custom_lm):
            result = self._querier(global_map_with_query=prompt_text)
    else:
        result = self._querier(global_map_with_query=prompt_text)

    lm = custom_lm if custom_lm is not None else dspy.settings.lm
    prompt_toks = getattr(lm, "last_prompt_tokens", 0) or 0
    completion_toks = getattr(lm, "last_completion_tokens", 0) or 0
    cache_read_toks = getattr(lm, "last_cache_read_tokens", 0) or 0
    cache_write_toks = getattr(lm, "last_cache_creation_tokens", 0) or 0
    served_model = (
        getattr(lm, "served_model", None)
        or getattr(lm, "model", "")
        or "claude-opus-4-8"
    )

    if cache is not None:
        cache.store("layer5", prompt_text,
                    {"findings": result.findings},
                    prompt_toks, completion_toks)

    return (
        result.findings, prompt_toks, completion_toks,
        cache_read_toks, cache_write_toks, served_model,
    )


CheckpointedPipeline._global_query_worker = _global_query_worker


def _verify_function_worker(
    self,
    file_rel: str,
    func_name: str,
    snippet: str,
    analysis_text: str,
) -> tuple[dict, int, int, int, int, str]:
    """Run a single Layer-5.5 verification call. Returns
    ``(parsed_verdict_dict, prompt_tokens, completion_tokens,
    cache_read_tokens, cache_write_tokens, served_model)``.
    """
    concern = _summarize_concern(analysis_text, func_name)

    # PoC ground-truth signal — pulled from the matching Layer 4
    # result's ``poc.validation`` block (populated by PocValidator).
    # When present, it's the strongest evidence Layer 5.5 can ground
    # its verdict on: forge actually ran the PoC and reported.
    poc_section = _render_poc_signal(self, file_rel, func_name)

    # ── Per-signal assembly (ablation support) ─────────────────────────
    # AISEC_VERIFY_SIGNALS is a comma-separated allow-list of the signals
    # that may enter the verify prompt. Default = all four. ``identity``
    # and ``concern`` are structurally load-bearing (the verifier must know
    # *what* function and *what* concern it is judging), so they are always
    # present even if omitted from the env — the ablation paper only removes
    # ``source`` and ``poc`` one at a time. Used by the §IV signal-ablation
    # experiment to measure each signal's marginal contribution.
    _sig_env = (os.getenv("AISEC_VERIFY_SIGNALS", "") or "").strip()
    if _sig_env:
        _signals = {s.strip().lower() for s in _sig_env.split(",") if s.strip()}
    else:
        _signals = {"identity", "source", "concern", "poc"}
    # Full 4-signal ablation (paper §IV): every signal is independently
    # removable — identity (file + function name), concern (the flagged
    # pattern), source (code snippet) and poc (forge ground truth). The
    # output verification entry still records (file, function) regardless of
    # what enters the prompt, so a finding's per-signal contribution is
    # recovered by joining the only_* configs on (file, function).
    use_identity = "identity" in _signals
    use_source = "source" in _signals
    use_concern = "concern" in _signals
    use_poc = "poc" in _signals and bool(poc_section)

    parts = ["A global security pattern analysis flagged this function.\n"]
    if use_identity:
        parts.append(f"File: {file_rel}\nFunction: {func_name}\n")
    if use_concern:
        parts.append(f"\nFlagged concern:\n{concern}\n")
    if use_source:
        parts.append(f"\nActual source code:\n```\n{snippet}\n```")
    if use_poc:
        parts.append(f"{poc_section}")

    instruction = [
        "\n\nBased on the evidence above, choose one verdict:\n"
        '- "confirmed": the vulnerability is real and exploitable at the flagged severity\n'
        '- "downgraded": there is some merit (defense-in-depth, theoretical risk) but not exploitable at the flagged severity\n'
        '- "false_positive": the concern is invalid, the code is safe\n'
    ]
    if use_poc:
        instruction.append(
            "\nWeight the PoC signal heavily — ``poc_triggers_bug=true`` "
            "with a ``ground_truth_confidence`` ≥ 0.7 is strong evidence "
            "FOR the finding. ``poc_triggers_bug=false`` is evidence AGAINST. "
            "PoC compile failure means no ground truth — fall back to "
            "source-only judgment.\n"
        )
    instruction.append(
        '\nRespond with strict JSON:\n'
        '{"verdict": "confirmed"|"downgraded"|"false_positive", '
        '"severity": "critical"|"high"|"medium"|"low"|"info", '
        '"reason": "one sentence"}'
    )
    verify_prompt = "".join(parts) + "".join(instruction)

    cache = get_cache()
    if cache is not None:
        hit = cache.lookup("layer5_5", verify_prompt)
        if hit is not None:
            return hit["result"], 0, 0, 0, 0, ""

    # Chain-aware verifier backend. ``AISEC_VERIFY_BACKEND`` accepts:
    #   - empty → use default LM (Opus)
    #   - "sonnet" / "vllm:nemotron-120b" → single-model
    #   - comma-separated chain (e.g.
    #     "vllm:nemotron-120b,vllm:gemma-4-31b,sonnet") → wrapped
    #     in FallbackLM so a server outage falls through to the
    #     next link instead of crashing the verify worker.
    verify_lm = None
    try:
        from core.ai_engine.local_llm import resolve_task_chain
        verify_lm = resolve_task_chain(
            "AISEC_VERIFY_BACKEND", default_lm=None,
        )
    except Exception:
        verify_lm = None

    try:
        if verify_lm is not None:
            with dspy.context(lm=verify_lm):
                verify_out = self._verifier(verification_prompt=verify_prompt)
        else:
            verify_out = self._verifier(verification_prompt=verify_prompt)
        parsed = _parse_verification(verify_out.verdict_json)
    except Exception as parse_exc:  # noqa: BLE001
        # Raw-response recovery (paper §IV — Nemotron format mitigation).
        #
        # DSPy's JSONAdapter raises ``AdapterParseError`` when the model's
        # output is missing the ``[[ ## verdict_json ## ]]`` marker or has
        # truncated JSON. The underlying LM still produced text — Nemotron
        # often writes a plain ``{"verdict": "...", "severity": ...}``
        # block without the DSPy wrapper, or returns it truncated by an
        # upstream max_tokens / token-stream cutoff.
        #
        # ``_parse_verification`` already has a regex / keyword-scan
        # fallback that recovers the verdict from malformed JSON. We just
        # need the raw text — pull it from the LM's history.
        target = verify_lm if verify_lm is not None else dspy.settings.lm
        inner = getattr(target, "_last_used", target)  # FallbackLM unwrap
        hist = getattr(inner, "history", None) or []
        raw = ""
        if hist and isinstance(hist[-1], dict):
            raw = str(hist[-1].get("response") or "")
        if not raw:
            # No usable raw — re-raise so the caller logs verdict=error
            # (better than silent fabrication).
            raise
        parsed = _parse_verification(raw)

    lm = verify_lm if verify_lm is not None else dspy.settings.lm
    prompt_toks = getattr(lm, "last_prompt_tokens", 0) or 0
    completion_toks = getattr(lm, "last_completion_tokens", 0) or 0
    cache_read_toks = getattr(lm, "last_cache_read_tokens", 0) or 0
    cache_write_toks = getattr(lm, "last_cache_creation_tokens", 0) or 0
    served_model = (
        getattr(lm, "served_model", None)
        or getattr(lm, "model", "")
        or "claude-opus-4-8"
    )

    if cache is not None:
        cache.store("layer5_5", verify_prompt, parsed, prompt_toks, completion_toks)

    return (
        parsed, prompt_toks, completion_toks,
        cache_read_toks, cache_write_toks, served_model,
    )


CheckpointedPipeline._verify_function_worker = _verify_function_worker


def _repair_failed_pocs(self, s, validator, root: str) -> None:
    """One-shot LLM repair of PoCs that failed to compile after import
    normalisation. Feeds the forge error back to the model, then
    re-validates. Mutates ``s.opus_results`` in place.

    The deterministic import normalizer (poc_validator.normalize_poc_imports)
    already fixes path-resolution failures; this catches the residual
    genuine-code-bug class (typos, bad address checksums, type errors).
    """
    failed = []
    for r in s.opus_results:
        if r.get("layer") != 4:
            continue
        poc = r.get("poc")
        if not isinstance(poc, dict) or not poc.get("code"):
            continue
        val = poc.get("validation") or {}
        if val.get("poc_compile") is False:
            failed.append(r)

    if not failed:
        return

    tui.info(f"[Layer 4.5] repairing {len(failed)} PoCs that failed to compile...")

    # Repair backend: reuse the HIGH analysis chain (same model family that
    # wrote the PoC). Falls back to default LM.
    repair_lm = None
    try:
        from core.ai_engine.local_llm import resolve_task_chain
        repair_lm = resolve_task_chain(
            "AISEC_ANALYSE_HIGH_BACKEND", default_lm=dspy.settings.lm,
        )
    except Exception:
        repair_lm = None

    repaired_count = 0
    for r in failed:
        poc = r["poc"]
        val = poc.get("validation") or {}
        forge_error = str(val.get("error") or "")[:1500]
        broken = poc.get("code", "")
        if not forge_error or not broken:
            continue
        try:
            if repair_lm is not None:
                with dspy.context(lm=repair_lm):
                    out = self._poc_repairer(broken_poc=broken, forge_error=forge_error)
            else:
                out = self._poc_repairer(broken_poc=broken, forge_error=forge_error)
            fixed = (getattr(out, "repaired_poc", "") or "").strip()
            # Strip accidental markdown fences.
            fixed = re.sub(r"^```[a-z]*\n|\n```$", "", fixed).strip()
            if not fixed or "contract" not in fixed:
                continue
        except Exception as e:  # noqa: BLE001
            tui.warning(f"[Layer 4.5] PoC repair LLM failed: {e}")
            continue

        # Re-validate the repaired PoC (normalizer runs again inside).
        new_val = validator._validate_one(
            poc_code=fixed,
            strategy=poc.get("strategy", "single-shot"),
            expected=poc.get("expected_outcome", ""),
            repo_path=root,
            rule_id=(r.get("finding") or {}).get("rule_id", "unknown"),
        )
        # Keep the repair only if it improved the outcome.
        if new_val.get("poc_compile") is True:
            poc["code"] = fixed
            poc["validation"] = new_val
            poc["repaired"] = True
            repaired_count += 1

    tui.info(f"[Layer 4.5] PoC repair: {repaired_count}/{len(failed)} now compile")
    with self._save_lock:
        s.save()


CheckpointedPipeline._repair_failed_pocs = _repair_failed_pocs


def _render_poc_signal(self, file_rel: str, func_name: str) -> str:
    """Render the PoC validation result for the matching Layer 4 finding.

    Returns a multi-line ``═══ PoC Validation Signal ═══`` block when a
    matching PoC validation was performed by ``PocValidator``; returns
    an empty string when no match exists (so verify falls back to the
    source-only judgment that has always worked).
    """
    matching = None
    for r in self.state.opus_results:
        if r.get("layer") != 4:
            continue
        f = r.get("finding", {})
        if f.get("file") != file_rel:
            continue
        # Fuzzy match: function name in message OR in analysis prose
        if (
            func_name in str(f.get("message", "")) or
            func_name in str(r.get("analysis", ""))
        ):
            matching = r
            break

    if not matching:
        return ""
    poc = matching.get("poc") or {}
    v = poc.get("validation") or {}
    if not v:
        return ""

    # Runner label — forge for Solidity, else the sandbox method (cpp-asan,
    # pytest, node, gotest, rustc). The verdict semantics are identical; only
    # the wording differs so the verifier knows what produced the evidence.
    method = (v.get("poc_method") or poc.get("method") or "forge")
    runner = "forge" if method == "forge" else f"sandbox/{method}"

    lines = ["", "", "═══════ PoC Validation Signal ═══════"]
    if v.get("poc_compile") is True:
        lines.append(f"{runner} build: PASS")
        triggered = v.get("poc_triggers_bug")
        conf = v.get("ground_truth_confidence", 0)
        if triggered is True:
            lines.append(
                f"{runner} run: TRIGGERED expected exploit "
                f"(confidence {conf:.2f})"
            )
            if v.get("counterexample"):
                lines.append(f"evidence: {v['counterexample']}")
            if v.get("fuzz_confirms") is True:
                lines.append("fuzz (1024 runs): CONFIRMED robust exploit")
            elif v.get("fuzz_confirms") is False:
                lines.append("fuzz (1024 runs): not confirmed across random inputs")
        elif triggered is False:
            lines.append(
                f"{runner} run: PoC did NOT trigger expected outcome — "
                "the flagged vulnerability may not be exploitable as described"
            )
        else:
            lines.append(f"{runner} run: result ambiguous (no clear signal)")
    else:
        lines.append(f"{runner} build: FAIL — PoC could not be compiled/run")
        if v.get("error"):
            lines.append(f"error: {v['error'][:140]}")
        lines.append("(no ground truth available — judge from source alone)")
    lines.append("═══════════════════════════════════════")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Prompt-cache pre-warm
# ---------------------------------------------------------------------------
#
# Anthropic prompt caching keys on the system prompt prefix marked with
# ``cache_control: ephemeral``. When N parallel workers all fire before the
# cache has any entries, all N pay the cache-write surcharge. A single
# minimal serial call up-front turns those N writes into N-1 reads. Cost
# of the prewarm: ~$0.025 (one cache write of the system prompt). Saving:
# ~$0.05 (2-3 avoided writes for parallel-3). Net win ~$0.02/scan/layer
# plus slightly faster median latency on the parallel batch.
#
# Disable with AISEC_PROMPT_PREWARM=0.

_PREWARM_DISABLED = os.getenv("AISEC_PROMPT_PREWARM", "1").lower() in {"0", "false", "no", "off"}


def _prewarm(self, signature: str) -> None:
    """Fire one tiny call against the chosen DSPy predictor to warm
    Anthropic's ephemeral prompt cache before the parallel batch runs.

    Persistent registry (B-cache-3): if a previous scan / process sent
    a matching system prompt within ``TTL - safety_margin`` seconds,
    skip the prewarm — the cache upstream should still be hot and the
    parallel batch will hit it on first call. Saves one full system-
    prompt cache-write per layer per scan when re-running within the
    cache lifetime.

    Failures are swallowed — prewarm is an optimisation, not a
    correctness requirement.
    """
    if _PREWARM_DISABLED or self.parallel_workers <= 1:
        return

    # Skip-when-warm: look up the active DSPy LM's system prompt and
    # consult the persistent registry. We don't have direct access to
    # the formatted system prompt before sending, but DSPy uses a
    # stable system message per signature, so the *previous* call's
    # system prompt is what's in the registry.
    try:
        import time as _t
        from core.ai_engine.prompt_cache_registry import (
            SAFETY_MARGIN_SEC, get_registry,
        )
        registry = get_registry()
        # Approximate: if *any* recent claude_adapter entry is within
        # its own ttl - safety margin, the upstream cache is probably
        # still hot for the system prompt our parallel batch will use.
        # The keys are sha256(system_prompt), and DSPy reuses the same
        # system prompt per signature, so this is conservative but
        # tight enough to make the skip worthwhile.
        warm = False
        now = _t.time()
        for entry in list(registry._entries.values()):  # noqa: SLF001
            if entry.signature != "claude_adapter" or not entry.ttl_seconds:
                continue
            if now - entry.last_sent_at < (entry.ttl_seconds - SAFETY_MARGIN_SEC):
                warm = True
                break
        if warm:
            from core.ui import tui
            tui.info(f"[Cache] {signature} prewarm skipped — cache should still be warm")
            return
    except Exception:
        pass

    # Prewarm must use the LM the actual phase will use, not the global
    # LM. Without this alignment, a phase routed to Sonnet would prewarm
    # Opus's cache instead — wasted call, the actual Sonnet calls would
    # hit a cold cache. vLLM routing has no Anthropic cache to warm, so
    # we skip the prewarm entirely for those.
    try:
        from core.ai_engine.local_llm import resolve_task_lm
        sig_to_env = {
            "analyse": "AISEC_ANALYSE_BACKEND",
            "query":   "AISEC_QUERY_BACKEND",
            "verify":  "AISEC_VERIFY_BACKEND",
        }
        env_var = sig_to_env.get(signature, "")
        prewarm_lm = resolve_task_lm(env_var) if env_var else None
        if prewarm_lm is not None:
            cls_name = type(prewarm_lm).__name__
            if "Nvidia" in cls_name or "Vllm" in cls_name:
                # Local vLLM — Anthropic prompt cache doesn't apply.
                return
    except Exception:
        prewarm_lm = None

    def _do_prewarm() -> None:
        if signature == "analyse":
            self._analyser(context_bundle="ping (prewarm; ignore).")
        elif signature == "query":
            self._querier(global_map_with_query="ping (prewarm; ignore).")
        elif signature == "verify":
            self._verifier(verification_prompt="ping (prewarm; ignore).")

    try:
        if prewarm_lm is not None:
            with dspy.context(lm=prewarm_lm):
                _do_prewarm()
        else:
            _do_prewarm()
    except Exception:
        # Cache prewarm should never fail a scan
        pass


CheckpointedPipeline._prewarm = _prewarm


_EXT_TO_LANG = {
    ".sol": "solidity", ".vy": "vyper", ".rs": "rust",
    ".py": "python", ".go": "go", ".java": "java",
    ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".rb": "ruby", ".php": "php", ".cs": "csharp",
    ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    ".move": "move", ".cairo": "cairo",
}


_PLACEHOLDER_PATTERNS = (
    "no function body available",
    "no function body is available",
    "context bundle does not include",
    "context bundle is empty",
    "the bundle does not contain",
    "only shows the file header",
    "only contains the file header",
    "spdx license identifier",  # bundle returned just the SPDX header
    "no body for the function",
    "no source code available",
    "no matching functions for this query",
    "no function bodies",
    "re-run layer 1",            # explicit "go back to Layer 1" sentinel
    "i cannot determine",
    "cannot be determined from",
    # New patterns observed in RUN MAC-16 — Layer 4 occasionally
    # returns these phrasings when the context bundle contains
    # redaction sentinels (server-side noise we can't always block).
    "is entirely redacted",
    "requires login",                           # redaction sentinel echoed back
    "is not visible in the context bundle",
    "flagged function body is not available",
    "function body and name are both redacted",
    "<unknown>",                                # placeholder name leaked from context
)


def _is_placeholder_analysis(analysis_text: str) -> bool:
    """Detect Opus output that admits to having insufficient context.

    Used to drop Layer-4 / Layer-5 results that would otherwise persist
    as ``INFO``-severity findings with rule_ids like ``interest_*`` and
    bodies that read ``Confirmed: unclear … context bundle does not
    contain the function body``. These add no value to the report and
    were the residual noise after the BFS-no-body and code-field fixes.
    """
    if not analysis_text:
        return True
    lowered = analysis_text.lower()
    # Strong signal: starts with "Confirmed: no" or "Confirmed: unclear"
    # AND has a placeholder pattern in the body.
    confirmed_negative = (
        lowered.startswith("confirmed: no")
        or lowered.startswith("confirmed: unclear")
    )
    has_placeholder_phrase = any(p in lowered for p in _PLACEHOLDER_PATTERNS)
    if confirmed_negative and has_placeholder_phrase:
        return True
    # Or just a bare sentinel without any analysis (very short responses)
    if len(analysis_text.strip()) < 120 and has_placeholder_phrase:
        return True
    return False


def _lang_hint_from_path(file_path: str) -> str:
    if not file_path or "." not in file_path:
        return ""
    ext = "." + file_path.rsplit(".", 1)[-1].lower()
    return _EXT_TO_LANG.get(ext, "")


# ---------------------------------------------------------------------------
# Layer 5.5 helpers
# ---------------------------------------------------------------------------

def _extract_mentioned_functions(analysis_text: str) -> list[tuple[str, str]]:
    r"""Extract (file_rel, func_name) pairs mentioned in Layer 5 analysis text.

    Layer 5 prose uses several common citation formats. We try the
    cleanest first and fall back to looser matches if nothing hits:

      Format A — explicit double colon (legacy DSPy template style)::
          GPv2Settlement.sol::settle
          `libraries/GPv2Interaction.sol::execute`

      Format B — markdown header dash-separator (file with funcname)::
          ### <title> — src/Path.sol:funcName
          ### <title> — src/Path.sol:42       (line, skipped)

      Format E — markdown title with funcname inside backticks then dash::
          ### Reentrancy in `_closeOffer` ... — src/Shards.sol

      Format C — backtick pair: ``funcName`` ... ``src/path.sol`` within
          80 chars of each other (paren-tolerant for ``fn()``).

      Format D — prose "in <file>": "calls ``foo()`` ... in ``src/Bar.sol``".
          Cheapest signal, only triggered when A/B/C/E found nothing.

    Returns ``[(file_rel, func_name), ...]`` deduped, capped at 50.
    """
    EXT = r"(?:sol|py|js|ts|jsx|tsx|go|rs|vy|move|cairo|cpp|c|h|hpp|java|rb|php|lua)"
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(file_rel: str, func: str) -> None:
        if not func.isidentifier() or len(func) < 2 or len(func) > 60:
            return
        # Skip obvious non-functions (variables / keywords / pragma)
        if func.lower() in {"the", "this", "that", "where", "when", "memory",
                            "storage", "calldata", "external", "public",
                            "private", "internal", "view", "pure", "payable",
                            "uint256", "uint", "int", "bool", "address",
                            "true", "false", "null", "none"}:
            return
        key = (file_rel, func)
        if key not in seen:
            seen.add(key); out.append(key)

    # Format A — explicit `file::func`
    for m in re.finditer(
        rf"[`*]*([A-Za-z0-9_./\\-]+\.{EXT})::(\w+)[`*]*",
        analysis_text,
    ):
        _add(m.group(1), m.group(2))

    # Format B — markdown header dash with file:funcName
    for m in re.finditer(
        rf"[—–-]\s+`?([A-Za-z0-9_./\\-]+\.{EXT})`?:([A-Za-z_]\w{{1,59}})",
        analysis_text,
    ):
        _add(m.group(1), m.group(2))

    # Format E — markdown title: ``` `funcName` ... — file.sol ```
    # (function name in backticks within the title text, before em-dash)
    for m in re.finditer(
        rf"`([A-Za-z_]\w{{1,59}})`[^—–\n]{{0,200}}?\s+[—–-]\s+[`*]*([A-Za-z0-9_./\\-]+\.{EXT})",
        analysis_text,
    ):
        _add(m.group(2), m.group(1))

    # Format F — markdown title: ### <bare-text funcname ... — file>
    # (RUN MAC-16 dominant — Layer 5 sometimes writes funcname as plain
    # text in the title, no backticks. Limit to identifiers starting
    # with ``_`` or lowercase to skip ContractNames/TypeNames.)
    for m in re.finditer(
        rf"###[^\n]*?\b([_a-z]\w{{2,40}})\b[^—–\n]*?\s+[—–-]\s+[`*]*([A-Za-z0-9_./\\-]+\.{EXT})",
        analysis_text,
    ):
        _add(m.group(2), m.group(1))

    # Format C — backtick pair within 80 chars (paren-tolerant for fn())
    for m in re.finditer(
        rf"`([A-Za-z_]\w{{1,59}})(?:\(\))?`[^`]{{0,80}}?`([A-Za-z0-9_./\\-]+\.{EXT})`",
        analysis_text,
    ):
        _add(m.group(2), m.group(1))

    # Format D — bare `funcName()` ... in `file_path` (fallback)
    if not out:
        for m in re.finditer(
            rf"`([A-Za-z_]\w{{1,59}})(?:\(\))?`.{{0,120}}?\bin\s+`?([A-Za-z0-9_./\\-]+\.{EXT})`?",
            analysis_text,
        ):
            _add(m.group(2), m.group(1))

    # Format G — Nemotron-120B ### title heuristic (paper §IV)
    # Nemotron emits L5 findings as bare-prose markdown with no backticks:
    #   ### Spot price manipulation in borrow function — src/Pool.sol:3
    #   ### Price oracle manipulation in PuppetPool.borrow — src/PuppetPool.sol:1
    # Format F caught these but picked the FIRST lowercase identifier
    # (typically a non-function word like `price`/`oracle`). Here we
    # enumerate ALL plausible function-name candidates from the title
    # AND the first 800 chars of the body (Severity/Impact sections —
    # where Nemotron repeats the actual function name). The caller's
    # `_extract_function_source` filter discards non-existent names,
    # so over-generation here costs nothing but extra regex work.
    for sect_m in re.finditer(
        rf"###[^\n]+?\s+[—–-]\s+[`*]*([A-Za-z0-9_./\\-]+\.{EXT})",
        analysis_text,
    ):
        file_rel = sect_m.group(1)
        # Pull title text plus ~800 chars of body for identifier scan.
        sect_start = sect_m.start()
        sect_end = min(len(analysis_text), sect_start + 800)
        sect_text = analysis_text[sect_start:sect_end]
        # Capture `Contract.func` AND bare `func` identifiers.
        for ident_m in re.finditer(
            r"\b(?:[A-Z][A-Za-z0-9_]*\.)?([_a-z][A-Za-z0-9_]{2,40})\b",
            sect_text,
        ):
            _add(file_rel, ident_m.group(1))

    return out[:50]


def _extract_function_source(root: str, file_rel: str, func_name: str) -> str:
    """Extract the complete source of ``func_name`` in ``file_rel``.

    Handles Solidity, Python, and generic brace languages via brace counting.
    """
    candidates: list[str] = []
    full_path = os.path.join(root, file_rel)
    if os.path.exists(full_path):
        candidates.append(full_path)
    else:
        basename = os.path.basename(file_rel)
        for dirpath, _, filenames in os.walk(root):
            for fname in filenames:
                if fname == basename:
                    candidates.append(os.path.join(dirpath, fname))

    for path in candidates:
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError:
            continue

        ext = os.path.splitext(path)[1].lower()
        if ext == ".py":
            body = _extract_py_func(content, func_name)
        else:
            body = _extract_brace_func(content, func_name)
        if body:
            return body

    return ""


def _extract_brace_func(content: str, func_name: str) -> str:
    """Brace-counted extraction for Solidity/JS/TS/Go/Rust/C++."""
    pattern = rf"(?:function|fn|void|TER|NotTEC|bool|int|auto|std::\w+|Expected\w*)\s+(?:\w+::)?{re.escape(func_name)}\s*\("
    m = re.search(pattern, content)
    if not m:
        return ""
    start = m.start()
    brace_pos = content.find("{", m.end())
    if brace_pos == -1:
        end = content.find(";", m.end())
        return content[start: end + 1] if end != -1 else content[start: start + 300]

    depth = 0
    for i in range(brace_pos, len(content)):
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return content[start: i + 1]
    return content[start: start + 5000]


def _extract_py_func(content: str, func_name: str) -> str:
    """Indent-based extraction for Python."""
    import ast as _ast
    try:
        tree = _ast.parse(content)
    except SyntaxError:
        return ""
    lines = content.splitlines()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == func_name:
            start = node.lineno - 1
            end = getattr(node, "end_lineno", len(lines))
            return "\n".join(lines[start:end])
    return ""


def _summarize_concern(analysis_text: str, func_name: str) -> str:
    """Pull out the lines in ``analysis_text`` that mention ``func_name``."""
    lines = analysis_text.splitlines()
    captured: list[str] = []
    capturing = False
    for line in lines:
        if func_name in line:
            capturing = True
        if capturing:
            captured.append(line)
            if len(captured) > 8:
                break
            if not line.strip() and len(captured) > 2:
                break
    text = "\n".join(captured).strip()
    return text[:500] if text else f"Potential vulnerability in {func_name}"


def _parse_verification(text: str) -> dict:
    """Parse the verifier's three-state JSON output.

    Returns {"verdict": "confirmed"|"downgraded"|"false_positive",
             "severity": str, "reason": str}.
    Defaults to confirmed on parse failure (conservative).
    """
    default = {"verdict": "confirmed", "severity": "", "reason": text[:200] if text else ""}

    if not text:
        return default

    data = None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        m = re.search(r"\{.*?\}", text, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group())
            except json.JSONDecodeError:
                pass

    if not isinstance(data, dict):
        # Fallback: keyword scan
        lower = text.lower()
        if "false_positive" in lower or "false positive" in lower:
            return {"verdict": "false_positive", "severity": "info", "reason": text[:200]}
        if "downgrade" in lower:
            return {"verdict": "downgraded", "severity": "info", "reason": text[:200]}
        return default

    verdict = str(data.get("verdict", "confirmed")).lower().strip()
    if verdict not in ("confirmed", "downgraded", "false_positive"):
        # Legacy format: {"confirmed": bool}
        if data.get("confirmed") is False:
            verdict = "false_positive"
        elif "downgrad" in str(data.get("reason", "")).lower():
            verdict = "downgraded"
        else:
            verdict = "confirmed"

    return {
        "verdict": verdict,
        "severity": str(data.get("severity", "")).lower().strip(),
        "reason": str(data.get("reason", ""))[:300],
    }


def _apply_verification_severity(result: dict, verification_results: list[dict]) -> None:
    """Compute the final severity_override from three-state verification results.

    Logic:
      - All false_positive → severity_override="info", status will be "False Positive"
      - Mix of confirmed + downgraded/FP → use the highest confirmed severity
      - All downgraded (no confirmed) → use the highest downgraded severity
    """
    if not verification_results:
        return

    confirmed  = [v for v in verification_results if v["verdict"] == "confirmed"]
    downgraded = [v for v in verification_results if v["verdict"] == "downgraded"]
    fp_count   = sum(1 for v in verification_results if v["verdict"] == "false_positive")

    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    if confirmed:
        # At least one confirmed — use highest confirmed severity
        best = min(confirmed, key=lambda v: sev_rank.get(v["severity"], 2))
        result["severity_override"] = best["severity"] or None
        # Don't override if same or higher than original
        if not result.get("severity_override"):
            result.pop("severity_override", None)
    elif downgraded:
        # No confirmed, but some downgraded — keep as informational/low
        best = min(downgraded, key=lambda v: sev_rank.get(v["severity"], 4))
        result["severity_override"] = best["severity"] or "low"
        result["note"] = (
            f"No sub-findings fully confirmed. "
            f"{len(downgraded)} downgraded to defense-in-depth / informational."
        )
    elif fp_count == len(verification_results):
        # All false positive
        result["severity_override"] = "info"
        result["note"] = "All sub-findings verified as false positive against actual source code."
