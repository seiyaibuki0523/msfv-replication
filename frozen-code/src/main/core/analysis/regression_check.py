"""Differential recall check across consecutive scans of the same target.

Premise: when a customer re-scans the same repo, every finding that
*was* there last time but is *not* in the new scan output falls into
exactly one of two buckets:

  * **Patched** — the bug was fixed between scans. Expected, valid.
  * **Recall regression** — the scanner missed it this time. Bug.

A small local LLM call disambiguates: read the current code at the
old finding's location, ask "is this bug still present?". The answer
either confirms a clean fix or surfaces a regression we'd otherwise
silently swallow.

Operational value (why this matters more than a benchmark suite for
day-to-day production):

  * **Production-realistic ground truth** — uses the customer's actual
    repo, not a curated corpus. No labelling cost.
  * **Self-reinforcing** — every scan creates baseline for the next.
  * **Customer-facing UX win** — "you patched 3 of 5 findings ✅,
    1 is still present ⚠" is a far stronger story than "we scanned
    again and here are some findings".
  * **Catches drift** — model upgrades, prompt edits, env regressions
    that silently degrade recall.

What this *doesn't* solve:

  * Cold-start customer (first scan ever — no baseline to compare).
  * Systematic blind spot in the scanner itself (the LLM that detects
    is the same one that verifies, so a category it never sees
    detection-side also won't surface verification-side).

Those gaps belong to the external benchmark suite (Phase B).

Entry point: :func:`find_recall_regressions`. Returns a list of
findings annotated with ``regression_verdict`` ∈
``{"still_present", "patched", "moved", "unknown"}``.
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from core.ai_engine.local_llm import log_triage_event


# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #

def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def is_enabled() -> bool:
    """``AISEC_REGRESSION_CHECK=1`` enables the regression pass. Off by
    default — many scans have no prior baseline to diff against."""
    return os.getenv("AISEC_REGRESSION_CHECK", "0").strip().lower() in {
        "1", "true", "yes", "on",
    }


# Line-number tolerance when matching findings across scans. Code drift,
# refactor, or a one-line insertion above the finding shouldn't count as
# "missing". 5 lines is loose enough to absorb common churn.
LINE_FUZZ          = _env_int("AISEC_REGRESSION_LINE_FUZZ", 5)

# Max parallel LLM verify calls. Each call hits the local vLLM, so this
# is bound by vLLM scheduler not Anthropic.
PARALLEL_VERIFY    = _env_int("AISEC_PARALLEL_VLLM", 16)

# Cap how much current-code we send to the LLM per verify. The bug,
# if still present, should be at or near the original line; ±40 lines
# is plenty of context without inflating the prompt to where attention
# disperses.
CODE_WINDOW_LINES  = _env_int("AISEC_REGRESSION_CODE_WINDOW", 40)


# --------------------------------------------------------------------------- #
# Matching previous findings to new findings                                  #
# --------------------------------------------------------------------------- #

def _matches_any(old: dict, candidates: list[dict]) -> bool:
    """A previous-scan finding is 'still found' if some candidate in
    the new scan has the same file + nearby line + same/similar
    rule_id. We deliberately fuzz line to absorb refactor drift."""
    old_file = old.get("file") or ""
    old_line = int(old.get("line", 0) or 0)
    old_rule = (old.get("rule_id") or "").lower()

    for c in candidates:
        c_file = c.get("file") or ""
        if c_file != old_file:
            continue
        c_line = int(c.get("line", 0) or 0)
        if abs(c_line - old_line) > LINE_FUZZ:
            continue
        c_rule = (c.get("rule_id") or "").lower()
        # Rule may have been renamed across versions; also accept if
        # the title/message overlaps significantly. Keep this loose
        # to err on "we did re-find it" — better a miss than a false
        # regression alarm.
        if c_rule and old_rule and (c_rule == old_rule or
                                     c_rule.startswith(old_rule.split(".")[0])):
            return True
        old_msg = (old.get("message") or "").lower()
        c_msg = (c.get("message") or "").lower()
        if old_msg and c_msg:
            overlap = _word_overlap(old_msg, c_msg)
            if overlap >= 0.4:
                return True
    return False


def _word_overlap(a: str, b: str) -> float:
    """Cheap Jaccard-on-words. Good enough for "did we find a similar
    finding" — not trying to be a semantic match."""
    aw = set(w for w in a.split() if len(w) > 3)
    bw = set(w for w in b.split() if len(w) > 3)
    if not aw or not bw:
        return 0.0
    inter = aw & bw
    union = aw | bw
    return len(inter) / len(union)


# --------------------------------------------------------------------------- #
# Code window extraction                                                      #
# --------------------------------------------------------------------------- #

def _read_window(repo_path: str, file_rel: str, line: int) -> str:
    """Read a ±CODE_WINDOW_LINES window around the target line. Returns
    empty string on any IO error (caller will mark verdict 'unknown')."""
    try:
        full = os.path.join(repo_path, file_rel)
        with open(full, "rb") as f:
            data = f.read().decode("utf-8", errors="replace")
    except OSError:
        return ""
    lines = data.splitlines()
    if not lines:
        return ""
    start = max(0, line - CODE_WINDOW_LINES - 1)
    end   = min(len(lines), line + CODE_WINDOW_LINES)
    window = lines[start:end]
    # Prefix each line with its 1-based number so the LLM can reason
    # about which line we cared about.
    out = []
    for i, content in enumerate(window, start=start + 1):
        marker = " >>>" if i == line else "    "
        out.append(f"{i:5d}{marker} {content}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# DSPy signature                                                              #
# --------------------------------------------------------------------------- #

def _build_signature():
    import dspy

    class VerifyFindingStillPresent(dspy.Signature):
        """A previous scan reported a security finding. The current
        scan did *not* re-report it. Read the current code at the
        original location and decide whether the bug is gone (the
        developer patched it) or whether the new scan missed it.

        Resolution categories:

        * ``still_present`` — the same vulnerability is visible in
          the current code, possibly at a slightly different line.
          The new scan regressed.
        * ``patched`` — the code at and around the original line
          has been changed in a way that resolves the issue. Be
          conservative: only call patched if the fix is clearly
          present (e.g. nonReentrant added, input validation added,
          unchecked path now checked).
        * ``moved`` — the function/code seems to have moved
          elsewhere; can't decide from this window alone. (Treat
          ``moved`` as "needs human review", not "patched".)
        * ``unknown`` — the window doesn't have enough information.
        """

        original_rule_id: str    = dspy.InputField()
        original_severity: str   = dspy.InputField()
        original_message: str    = dspy.InputField(
            desc="The previous scan's description of the finding",
        )
        file_path: str           = dspy.InputField()
        original_line: int       = dspy.InputField()
        current_code_window: str = dspy.InputField(
            desc="Numbered code window around the original line. The "
                 "target line is marked with `>>>`.",
        )

        verdict: str             = dspy.OutputField(
            desc="One of: still_present | patched | moved | unknown",
        )
        confidence: float        = dspy.OutputField(desc="0.0 - 1.0")
        rationale: str           = dspy.OutputField(
            desc="One sentence explaining the call",
        )

    return VerifyFindingStillPresent


# --------------------------------------------------------------------------- #
# LM resolution                                                               #
# --------------------------------------------------------------------------- #

def _get_verifier_lm():
    """Resolve the verifier LM for regression-check via the multi-model
    chain helper. ``AISEC_REGRESSION_BACKEND`` accepts a single spec
    or a comma-separated chain; default chain is Nemotron → Gemma →
    Qwen3-Coder so the verifier runs entirely on local hosts.
    """
    try:
        from core.ai_engine.local_llm import resolve_task_chain
        return resolve_task_chain("AISEC_REGRESSION_BACKEND", default_lm=None)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Single-finding verification                                                 #
# --------------------------------------------------------------------------- #

def _verify_one(
    previous_finding: dict,
    repo_path: str,
    signature,
    lm,
) -> dict[str, Any]:
    """Return ``previous_finding`` annotated with regression_verdict."""
    import dspy

    started = time.monotonic()
    file_rel = previous_finding.get("file") or ""
    line     = int(previous_finding.get("line", 0) or 0)

    window = _read_window(repo_path, file_rel, line)
    if not window:
        annotated = {
            **previous_finding,
            "regression_verdict": "unknown",
            "regression_confidence": 0.0,
            "regression_rationale": "file unreadable or empty window",
            "regression_latency_ms": int((time.monotonic() - started) * 1000),
        }
        log_triage_event({
            "tag": "regression_verify",
            "file": file_rel,
            "line": line,
            "verdict": "unknown",
            "reason": "no_window",
        })
        return annotated

    try:
        predictor = dspy.Predict(signature)
        kwargs = dict(
            original_rule_id=str(previous_finding.get("rule_id", "")),
            original_severity=str(previous_finding.get("severity", "")),
            original_message=str(previous_finding.get("message", ""))[:1000],
            file_path=file_rel,
            original_line=line,
            current_code_window=window[:12_000],
        )
        if lm is not None:
            with dspy.context(lm=lm):
                pred = predictor(**kwargs)
        else:
            pred = predictor(**kwargs)

        # Surface cost to ScanState. With chain LMs, the served model
        # is exposed via the LM's ``model`` attr; if it starts with a
        # vllm-resolvable prefix, log as vllm so PRICING dict applies
        # the local (zero) rate.
        try:
            from core.cost_tracker import record_cevanex_call
            _lm = lm if lm is not None else dspy.settings.lm
            model_attr = (getattr(_lm, "model", "") or "").lower()
            local_target = None
            if any(k in model_attr for k in ("nemotron", "gemma", "qwen")):
                local_target = model_attr  # rate routes via vllm prefix
            record_cevanex_call(local_target, _lm)
        except Exception:
            pass

        verdict = (getattr(pred, "verdict", "") or "unknown").strip().lower()
        if verdict not in {"still_present", "patched", "moved", "unknown"}:
            verdict = "unknown"
        try:
            confidence = float(getattr(pred, "confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5
        confidence = max(0.0, min(1.0, confidence))
        rationale = str(getattr(pred, "rationale", "")).strip()[:300]

        annotated = {
            **previous_finding,
            "regression_verdict": verdict,
            "regression_confidence": confidence,
            "regression_rationale": rationale,
            "regression_latency_ms": int((time.monotonic() - started) * 1000),
        }
        log_triage_event({
            "tag": "regression_verify",
            "file": file_rel,
            "line": line,
            "rule_id": previous_finding.get("rule_id"),
            "verdict": verdict,
            "confidence": confidence,
            "latency_ms": annotated["regression_latency_ms"],
        })
        return annotated

    except Exception as exc:  # noqa: BLE001
        log_triage_event({
            "tag": "regression_verify",
            "file": file_rel,
            "line": line,
            "verdict": "unknown",
            "error": f"{type(exc).__name__}: {exc}",
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
        return {
            **previous_finding,
            "regression_verdict": "unknown",
            "regression_confidence": 0.0,
            "regression_rationale": f"verify failed: {exc}",
            "regression_latency_ms": int((time.monotonic() - started) * 1000),
        }


# --------------------------------------------------------------------------- #
# Public API                                                                  #
# --------------------------------------------------------------------------- #

def find_recall_regressions(
    new_findings: list[dict],
    previous_findings: list[dict],
    repo_path: str,
) -> dict[str, Any]:
    """Diff two scans and verify the missing ones against the current code.

    Args:
        new_findings:      Output of the just-completed scan.
        previous_findings: Output of the most recent prior scan for the
                           same project / target. May be empty (cold
                           start) — in which case this function is a
                           no-op and returns an empty result.
        repo_path:         Local path to the current repo source so we
                           can read the window at the previous-finding
                           line.

    Returns a dict::

        {
            "checked":        int,     # how many previous findings we examined
            "regressions":    list,    # findings the new scan missed but
                                       # are still in the code (RED FLAG)
            "patched":        list,    # findings the dev legitimately fixed
            "unknown":        list,    # couldn't determine
            "still_matched":  int,     # previous findings re-found by new scan
        }

    Empty/cold-start case returns zeros without making any LLM calls.
    """
    if not previous_findings:
        return {
            "checked": 0, "regressions": [], "patched": [],
            "unknown": [], "still_matched": 0,
        }
    if not new_findings:
        # New scan found nothing — every previous finding is either patched
        # or a regression. Still need to verify each.
        new_findings = []

    # Bucket previous findings into "re-found" vs "missing"
    re_found = 0
    missing: list[dict] = []
    for old in previous_findings:
        if _matches_any(old, new_findings):
            re_found += 1
        else:
            missing.append(old)

    if not missing:
        log_triage_event({
            "tag": "regression_check_summary",
            "previous": len(previous_findings),
            "still_matched": re_found,
            "missing": 0,
            "regressions": 0,
            "patched": 0,
            "unknown": 0,
        })
        return {
            "checked": 0, "regressions": [], "patched": [],
            "unknown": [], "still_matched": re_found,
        }

    # Verify each missing finding in parallel
    signature = _build_signature()
    lm = _get_verifier_lm()
    annotated: list[dict] = []
    workers = max(1, min(PARALLEL_VERIFY, len(missing)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_verify_one, m, repo_path, signature, lm): m
            for m in missing
        }
        for fut in as_completed(futures):
            try:
                annotated.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                original = futures[fut]
                annotated.append({
                    **original,
                    "regression_verdict": "unknown",
                    "regression_confidence": 0.0,
                    "regression_rationale": f"verify crashed: {exc}",
                })

    # Bucket the verified findings
    regressions = [f for f in annotated if f.get("regression_verdict") == "still_present"]
    patched     = [f for f in annotated if f.get("regression_verdict") == "patched"]
    unknown     = [f for f in annotated if f.get("regression_verdict") in ("unknown", "moved")]

    log_triage_event({
        "tag": "regression_check_summary",
        "previous": len(previous_findings),
        "still_matched": re_found,
        "missing": len(missing),
        "regressions": len(regressions),
        "patched": len(patched),
        "unknown": len(unknown),
    })

    return {
        "checked":       len(missing),
        "regressions":   regressions,
        "patched":       patched,
        "unknown":       unknown,
        "still_matched": re_found,
    }


__all__ = [
    "is_enabled",
    "find_recall_regressions",
]
