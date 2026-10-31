"""LLM fallback classifier for files that ``language_router`` marked ambiguous.

Sends a batch of ``(path, head_snippet)`` pairs to the same frontier LLM
used by the verification layer and asks it to label each file's analysis
mode. Conservatively rejects hallucinated labels.

Failure handling is the caller's responsibility — this module surfaces
``RouterDegraded`` after three consecutive failures so the engine can
decide whether to lock the scan (Enterprise default) or fall back to
rule-only mode (Pro/Team default).
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from cevanex.adapters.language_router import FileClassification

#: Labels the LLM is allowed to return. Anything else is rejected.
_ALLOWED_LABELS: frozenset[str] = frozenset({
    "solidity", "general", "config", "skipped", "unknown",
})

#: Module-level failure counter, reset on success. Three consecutive
#: failures put the classifier into a degraded state for ``_COOLDOWN_S``.
_consecutive_failures: int = 0
_degraded_until: float = 0.0
_FAILURE_THRESHOLD: int = 3
_COOLDOWN_S: int = 300


class RouterDegraded(RuntimeError):
    """The LLM router has failed enough times that callers should degrade."""


@dataclass(frozen=True)
class LLMRouterResult:
    classifications: list[FileClassification]
    fallback_used: bool  # True if we forced classifications because LLM was unavailable


def _is_degraded(now: float) -> bool:
    return _degraded_until > now


def _on_success() -> None:
    global _consecutive_failures, _degraded_until
    _consecutive_failures = 0
    _degraded_until = 0.0


def _on_failure() -> None:
    global _consecutive_failures, _degraded_until
    _consecutive_failures += 1
    if _consecutive_failures >= _FAILURE_THRESHOLD:
        _degraded_until = time.time() + _COOLDOWN_S


def classify_ambiguous(
    candidates: list[FileClassification],
    *,
    read_head: callable,  # type: ignore[type-arg]
    max_retries: int = 1,
) -> LLMRouterResult:
    """Classify ambiguous files via LLM batch call.

    Args:
        candidates: ambiguous files from ``language_router.classify_repo``.
        read_head: callable ``(path) -> str`` returning file head content
                   for the LLM to inspect.
        max_retries: how many times to retry transient failures.

    Returns:
        LLMRouterResult with re-classified files. On hard failure all
        candidates are returned with language ``"unknown"`` and
        ``fallback_used=True`` so the engine can decide what to do.

    Raises:
        RouterDegraded if the classifier is in cooldown.
    """
    if not candidates:
        return LLMRouterResult(classifications=[], fallback_used=False)

    now = time.time()
    if _is_degraded(now):
        raise RouterDegraded(
            f"LLM router in cooldown until {_degraded_until - now:.0f}s from now",
        )

    # Build the prompt input
    items = [
        {"path": c.path, "head": read_head(c.path)[:2000]}
        for c in candidates
    ]

    attempts = 0
    last_exc: Exception | None = None
    while attempts <= max_retries:
        try:
            raw = _call_llm(items)
            results = _parse_and_validate(raw, candidates)
            _on_success()
            return LLMRouterResult(classifications=results, fallback_used=False)
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            attempts += 1
            if attempts <= max_retries:
                time.sleep(0.5 * (2 ** attempts))

    _on_failure()
    if _is_degraded(time.time()):
        raise RouterDegraded(
            f"LLM router classifier failed {_FAILURE_THRESHOLD} times; "
            f"last error: {last_exc!r}",
        )

    # Soft failure — return fallback so caller can decide degradation policy.
    fallback = [
        FileClassification(c.path, "unknown", "llm_failed")
        for c in candidates
    ]
    return LLMRouterResult(classifications=fallback, fallback_used=True)


# --------------------------------------------------------------------------- #
# LLM call + parsing — kept separate so tests can mock                        #
# --------------------------------------------------------------------------- #

def _call_llm(items: list[dict[str, str]]) -> str:
    """Calls the same frontier LLM as the verification layer.

    Uses DSPy if available; raises if not (the caller treats this as a
    transient failure and may retry or fall back).
    """
    try:
        import dspy  # type: ignore[import]
        import core.ai_engine.mixed_router  # noqa: F401
    except Exception as exc:
        raise RuntimeError(
            "DSPy / LLM router not installed in this environment",
        ) from exc

    class ClassifyFiles(dspy.Signature):
        """Classify each file's analysis mode.

        For each file in ``files_json``, decide the analysis mode:
          - "solidity"  : Solidity smart contract code (any extension)
          - "general"   : general application source (Python / Go / TS / Java / Rust etc.)
          - "config"    : configuration file (no deep analysis required)
          - "skipped"   : build artefact / vendored dep / generated code
          - "unknown"   : you cannot tell from the head snippet provided

        Return strict JSON: ``[{"path": "...", "language": "..."}]`` —
        one entry per input file in the same order.
        """
        files_json: str = dspy.InputField()
        classifications_json: str = dspy.OutputField(
            desc='Strict JSON array of {"path","language"}.',
        )

    gen = dspy.Predict(ClassifyFiles)

    # Optional offload: ``AISEC_ROUTER_BACKEND=vllm:<model>`` routes the
    # ambiguous-file classification to the local vLLM Nemotron. The label
    # space is tiny (5 values) + the validator drops hallucinated labels,
    # so a lower-grade model is safe and saves ~$0.05 per scan.
    try:
        from core.ai_engine.local_llm import (  # type: ignore[import]
            get_vllm_dspy_lm,
            use_local_for,
        )
        local_target = use_local_for("AISEC_ROUTER_BACKEND")
    except Exception:
        local_target = ""

    if local_target:
        with dspy.context(lm=get_vllm_dspy_lm(local_target)):
            res = gen(files_json=json.dumps(items))
    else:
        res = gen(files_json=json.dumps(items))
    return getattr(res, "classifications_json", "") or ""


def _parse_and_validate(
    raw: str,
    candidates: list[FileClassification],
) -> list[FileClassification]:
    """Parse LLM JSON output and reject hallucinated labels."""
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"LLM returned non-JSON: {exc}") from exc

    if not isinstance(parsed, list):
        raise RuntimeError("LLM did not return a JSON array")

    by_path = {item.get("path"): item.get("language") for item in parsed if isinstance(item, dict)}
    out: list[FileClassification] = []
    for c in candidates:
        label = by_path.get(c.path)
        if label not in _ALLOWED_LABELS:
            # Hallucination — fall back to "unknown" rather than trust it.
            out.append(FileClassification(c.path, "unknown", "llm_hallucinated_label"))
        elif label == "unknown":
            out.append(FileClassification(c.path, "unknown", "llm_could_not_decide"))
        else:
            out.append(FileClassification(c.path, label, "llm_classified"))
    return out
