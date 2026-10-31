"""
Layer 3 — Local model false-positive filter.

Two backends available, selected via ``AISEC_LOCAL_FILTER_MODEL``:

    AISEC_LOCAL_FILTER_MODEL=ollama:qwen2.5-coder:7b
        Original 7-8B path. Plain-text CoT prompt over /api/generate.

    AISEC_LOCAL_FILTER_MODEL=vllm:nemotron-120b
        Self-hosted vLLM (Nemotron-3-Super-120B by default). DSPy-managed
        structured signature over OpenAI-shape /v1/chat/completions.
        ``VLLM_URL`` must be set (no built-in default — vllm path raises a
        clear error if unset). Friendly aliases (nemotron-120b, nemotron-49b)
        resolve from ``core.ai_engine.local_llm``; pass a full model id
        (anything with a ``/``) to bypass.

Falls back to ``AISEC_LOCAL_MODEL`` for backward compatibility. Without
either env var every finding passes through unfiltered.

Concurrency:
    AISEC_PARALLEL_LOCAL  ollama worker count   (default 4)
    AISEC_PARALLEL_VLLM   vllm worker count     (default 16)

Observability:
    Set ``AISEC_TRIAGE_LOG=/path/to/log.jsonl`` to emit one JSON record
    per finding (backend, verdict, confidence, latency, finding metadata).
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.analysis.context_bundle import build_context_bundle, format_bundle_for_prompt
from core.ai_engine.local_llm import (
    log_triage_event,
    parse_spec,
    vllm_resolve_model,
    vllm_url,
)

_LOCAL_MODEL_ENV = os.getenv("AISEC_LOCAL_FILTER_MODEL") or os.getenv("AISEC_LOCAL_MODEL", "")


def _ollama_url() -> str:
    """Lazy resolver so a VPN that came up after import still gets the
    auto-detect path on the next request.
    """
    from core.ai_engine.ollama_url import resolve
    return resolve()


def filter_findings(
    findings: list[dict],
    source_root: str,
    global_map: dict | None = None,
    confidence_threshold: float = 0.0,
    parallel_workers: int | None = None,
) -> list[dict]:
    """Layer 3: filter Semgrep findings using a local model.

    Returns the subset of findings classified as true positives, in the
    same order they appeared in *findings*. Falls back to returning all
    findings when no local model is configured.

    Concurrency:
        Calls dispatch via ``ThreadPoolExecutor`` so a slow Ollama queue
        doesn't serialise N findings × per-call latency. Default worker
        count is ``min(4, len(findings))``; override with the
        ``parallel_workers`` arg or ``AISEC_PARALLEL_LOCAL`` env var.
        Local inference shares one GPU so 3-4 is usually the sweet spot.

    Args:
        findings:             List of Semgrep finding dicts.
        source_root:          Root directory of the scanned codebase.
        global_map:           Output of build_global_map() — used to build
                              complete function-body context for the local model.
                              If None, falls back to the raw code snippet.
        confidence_threshold: Minimum confidence to accept a TRUE_POSITIVE.
        parallel_workers:     Concurrent Ollama calls. ``None`` reads from
                              ``AISEC_PARALLEL_LOCAL`` (default 4).
    """
    if not _LOCAL_MODEL_ENV:
        return findings
    if not findings:
        return []

    if parallel_workers is None:
        backend, _ = parse_spec(_LOCAL_MODEL_ENV)
        if backend == "vllm":
            parallel_workers = int(os.getenv("AISEC_PARALLEL_VLLM", "16"))
        else:
            parallel_workers = int(os.getenv("AISEC_PARALLEL_LOCAL", "4"))
    workers = max(1, min(parallel_workers, len(findings)))

    # Map original index → verdict so we can reassemble in input order
    verdicts: dict[int, tuple[str, float]] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(_classify_one, f, source_root, global_map): i
            for i, f in enumerate(findings)
        }
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                verdicts[idx] = future.result()
            except Exception:
                # Conservative fallback — if the local model errored, let
                # this finding through so Opus can still examine it.
                verdicts[idx] = ("TRUE_POSITIVE", 1.0)

    filtered: list[dict] = []
    dropped_records: list[dict] = []
    for i, finding in enumerate(findings):
        verdict, confidence = verdicts.get(i, ("TRUE_POSITIVE", 1.0))
        if verdict == "TRUE_POSITIVE" and confidence >= confidence_threshold:
            finding["local_filter_confidence"] = confidence
            filtered.append(finding)
        else:
            # Capture a redacted snapshot for the FP audit script.
            # We log each drop reason so the audit tool can sample
            # them and a human can verify the filter isn't too eager.
            dropped_records.append({
                "tag": "layer3_dropped",
                "rule_id": finding.get("rule_id", ""),
                "file": finding.get("file", ""),
                "line": int(finding.get("line", 0) or 0),
                "severity": (finding.get("severity") or "").lower(),
                "verdict": verdict,
                "confidence": float(confidence),
                "threshold": float(confidence_threshold),
                "message": (finding.get("message") or "")[:300],
                "code_snippet": (
                    finding.get("code") or finding.get("snippet") or ""
                )[:200],
            })

    # Batch-emit dropped records to the triage log (one per line) so a
    # nightly audit job can sample N and render a human-reviewable
    # markdown report. Best-effort — never let logging failure block
    # the scan.
    if dropped_records:
        try:
            from core.ai_engine.local_llm import log_triage_event
            for rec in dropped_records:
                log_triage_event(rec)
        except Exception:
            pass

    return filtered


def _classify_one(
    finding: dict,
    source_root: str,
    global_map: dict | None,
) -> tuple[str, float]:
    """Single-finding classification — runs in a worker thread.

    Wallclock latency, verdict, and finding metadata are emitted to
    AISEC_TRIAGE_LOG (if configured) so we can build offline analytics
    over backend performance without instrumenting every call site.
    """
    context = _build_context(finding, source_root, global_map)
    backend, _ = parse_spec(_LOCAL_MODEL_ENV)

    started = time.monotonic()
    extras: dict = {}
    try:
        verdict, confidence = _local_predict(finding, context, extras=extras)
    except Exception as exc:  # noqa: BLE001 — outer worker has its own fallback
        log_triage_event({
            "tag": "layer3_filter",
            "backend": backend,
            "rule_id": finding.get("rule_id", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line", -1),
            "error": f"{type(exc).__name__}: {exc}",
            "latency_ms": int((time.monotonic() - started) * 1000),
        })
        raise

    log_triage_event({
        "tag": "layer3_filter",
        "backend": backend,
        "rule_id": finding.get("rule_id", ""),
        "severity": finding.get("severity", ""),
        "cwe": finding.get("cwe", ""),
        "file": finding.get("file", ""),
        "line": finding.get("line", -1),
        "verdict": verdict,
        "confidence": confidence,
        "context_chars": len(context),
        "latency_ms": int((time.monotonic() - started) * 1000),
        **extras,
    })
    return verdict, confidence


# ---------------------------------------------------------------------------
# Context builder
# ---------------------------------------------------------------------------

def _build_context(
    finding: dict,
    source_root: str,
    global_map: dict | None,
) -> str:
    """Return the best available code context for the local model to reason over."""
    if global_map:
        try:
            bundle = build_context_bundle(global_map, finding, source_root)
            return format_bundle_for_prompt(bundle)
        except Exception:
            pass

    # Fallback: raw snippet from source file
    return _get_raw_snippet(source_root, finding)


def _get_raw_snippet(source_root: str, finding: dict) -> str:
    full_path = os.path.join(source_root, finding.get("file", ""))
    try:
        with open(full_path, encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        line = finding.get("line", 1)
        start = max(0, line - 15)
        end   = min(len(lines), line + 15)
        return "".join(lines[start:end])
    except OSError:
        return finding.get("code", "")


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def _local_predict(
    finding: dict,
    context: str,
    extras: dict | None = None,
) -> tuple[str, float]:
    """Dispatch to the configured backend. ``extras`` is filled in-place
    with backend-specific telemetry (model id, hint fields, etc.) that
    the caller can fold into the JSONL log.

    Chain-aware: when ``AISEC_LOCAL_FILTER_MODEL`` carries a
    comma-separated chain, we use ``resolve_task_chain`` to get a
    FallbackLM so the filter survives a single server going down —
    the previous implementation silently defaulted every finding to
    TRUE_POSITIVE 1.0 on any backend failure, which let 317 unfiltered
    findings flood Layer 4 in RUN MAC-17 forensics.
    """
    backend, model_spec = parse_spec(_LOCAL_MODEL_ENV)

    if backend == "ollama":
        return _predict_ollama(finding, context)
    if backend == "vllm":
        return _predict_vllm_chain(finding, context, extras=extras)

    # Unknown backend → pass through conservatively
    return "TRUE_POSITIVE", 1.0


def _predict_ollama(finding: dict, context: str) -> tuple[str, float]:
    """Call Ollama REST API with a chain-of-thought classification prompt."""
    try:
        import requests

        model_name = (
            _LOCAL_MODEL_ENV.split(":", 1)[1]
            if ":" in _LOCAL_MODEL_ENV
            else "mistral"
        )
        prompt = _build_prompt(finding, context)

        resp = requests.post(
            f"{_ollama_url()}/api/generate",
            json={"model": model_name, "prompt": prompt, "stream": False},
            timeout=60,
        )
        if resp.status_code != 200:
            return "TRUE_POSITIVE", 1.0

        text = resp.json().get("response", "")
        return _parse_verdict(text)

    except Exception:
        return "TRUE_POSITIVE", 1.0


def _build_prompt(finding: dict, context: str) -> str:
    """Chain-of-thought prompt that walks the model through the analysis steps."""
    rule    = finding.get("rule_id", "")
    msg     = finding.get("message", "")
    sev     = finding.get("severity", "")
    cwe     = finding.get("cwe", "")

    # Cap context at ~6000 chars to stay within small-model limits
    ctx = context[:6000] if len(context) > 6000 else context

    return f"""You are a security code reviewer. Decide whether a Semgrep finding is worth keeping in the report.

## Semgrep Finding
Rule: {rule}
Severity: {sev}
CWE: {cwe}
Message: {msg}

## Code Context (complete function + call chain)
{ctx}

## Analysis Steps
Work through these steps before giving your verdict:

1. TRIGGER: What exact code pattern triggered the rule?
2. DATA FLOW: Can the pattern actually be reached, exercised, or
   misused as the rule suggests?
3. GUARDS: Are there checks that fully prevent the concern?
4. IMPACT: Even if it's not Critical/High, does it still carry value
   for the development team — gas inefficiency, missing event, dead
   code, magic number, stale comment, hardening gap, best-practice
   miss, etc.? Real audits include Low / Info findings; we want them.
5. VERDICT: Only mark FALSE_POSITIVE when the code clearly does NOT
   exhibit the issue the rule describes (rule misfired). Default to
   TRUE_POSITIVE for anything informational — let the downstream
   pipeline classify severity.

## Output Format
After your analysis, end with exactly one of:
VERDICT: TRUE_POSITIVE
or
VERDICT: FALSE_POSITIVE
"""


def _parse_verdict(text: str) -> tuple[str, float]:
    """Extract verdict from the model's chain-of-thought response."""
    upper = text.upper()

    # Look for the explicit VERDICT: line first
    for line in reversed(text.splitlines()):
        stripped = line.strip().upper()
        if stripped.startswith("VERDICT:"):
            if "FALSE_POSITIVE" in stripped:
                return "FALSE_POSITIVE", 0.9
            if "TRUE_POSITIVE" in stripped:
                return "TRUE_POSITIVE", 0.9

    # Fallback: count keyword occurrences in the full response
    fp_count = upper.count("FALSE_POSITIVE")
    tp_count = upper.count("TRUE_POSITIVE")

    if fp_count > tp_count:
        return "FALSE_POSITIVE", 0.7
    if tp_count > 0:
        return "TRUE_POSITIVE", 0.7

    # Ambiguous → let Opus decide
    return "TRUE_POSITIVE", 0.5


# ---------------------------------------------------------------------------
# vLLM / Nemotron path (DSPy-managed structured signature)
# ---------------------------------------------------------------------------
#
# Why DSPy instead of raw HTTP like the ollama path:
#   - Nemotron-120B can emit richer per-finding fields (severity hint,
#     attack path, opus-ready brief) that we want structured. DSPy handles
#     JSON shape + parsing + retries so we don't reinvent that.
#   - Reuses the existing DSPyNvidiaAdapter (same OpenAI shape as cloud NIM
#     just pointed at a different base_url).

_vllm_lm_cache: dict[str, object] = {}
_vllm_predictor = None
_NEMOTRON_TRIAGE_SIGNATURE = None


def _get_nemotron_signature():
    """Lazy: build the DSPy Signature class on first use to avoid paying the
    dspy import cost when the vllm backend isn't selected."""
    global _NEMOTRON_TRIAGE_SIGNATURE
    if _NEMOTRON_TRIAGE_SIGNATURE is not None:
        return _NEMOTRON_TRIAGE_SIGNATURE

    import dspy

    class NemotronFindingTriage(dspy.Signature):
        """Coarse pre-filter for a Semgrep finding — recall-preserving.

        Your ONLY job is to discard OBVIOUS scanner noise so the expensive
        downstream layers don't waste budget on it. You are NOT the
        precision stage: a later multi-signal verification layer rigorously
        eliminates false positives with full source + PoC evidence. So when
        in any doubt, KEEP the finding (TRUE_POSITIVE) — dropping a real
        vulnerability here is unrecoverable, whereas a surviving false
        positive is cheaply removed later.

        Mark FALSE_POSITIVE ONLY when the finding is CLEARLY not a
        vulnerability — i.e. you are confident it is scanner noise:
          - rule matched a logging string / comment / doc-string
          - rule matched test-only or mock code with no production reach
          - the flagged token is plainly not the construct the rule targets
            (e.g. a variable named "execute", not an exec call)

        Otherwise — including every case where the finding is plausible,
        borderline, or you are unsure — return TRUE_POSITIVE. Do NOT require
        proof of exploitability; that is the verification layer's job, not
        this filter's. Err strongly toward keeping.

        Output ONLY verdict + confidence. Do not produce attack paths,
        severity refinements, or summaries — those are downstream layers'
        responsibility and asking for them here wastes tokens.
        """

        rule_id: str       = dspy.InputField(desc="Semgrep rule identifier")
        severity: str      = dspy.InputField(desc="Original rule severity")
        cwe: str           = dspy.InputField(desc="CWE classification, may be empty")
        message: str       = dspy.InputField(desc="Rule's description of the issue")
        code_context: str  = dspy.InputField(
            desc="Full function body and call-chain context for the flagged line"
        )

        verdict: str       = dspy.OutputField(
            desc="Exactly 'TRUE_POSITIVE' or 'FALSE_POSITIVE'. "
                 "Default to FALSE_POSITIVE when the rule's claim is not "
                 "concretely supported by the function body."
        )
        confidence: float  = dspy.OutputField(
            desc="0.0 to 1.0 — how sure are you of the verdict"
        )

    _NEMOTRON_TRIAGE_SIGNATURE = NemotronFindingTriage
    return NemotronFindingTriage


def _get_vllm_lm(model_id: str):
    """Cache one DSPy LM per resolved model id so we reuse the HTTP client
    across calls instead of paying connection setup every finding."""
    lm = _vllm_lm_cache.get(model_id)
    if lm is not None:
        return lm
    from core.ai_engine.nvidia_adapter import DSPyNvidiaAdapter
    lm = DSPyNvidiaAdapter(model=model_id, base_url=vllm_url())
    _vllm_lm_cache[model_id] = lm
    return lm


def _get_vllm_predictor():
    """One predictor instance for the whole process. dspy.Predict is a
    stateless functor so thread-safe for our concurrent workers."""
    global _vllm_predictor
    if _vllm_predictor is None:
        import dspy
        _vllm_predictor = dspy.Predict(_get_nemotron_signature())
    return _vllm_predictor


def _predict_vllm_chain(
    finding: dict,
    context: str,
    extras: dict | None = None,
) -> tuple[str, float]:
    """Chain-aware vLLM verdict — uses ``resolve_task_chain`` so a
    server-down primary auto-falls-through to the next chain link
    (Nemotron → Gemma) rather than silently defaulting the finding to
    TRUE_POSITIVE 1.0.

    Falls back conservatively to TRUE_POSITIVE on any error after the
    full chain is exhausted — same policy as the ollama path. Errors
    are recorded into ``extras`` so the caller's triage log captures
    them.
    """
    try:
        import dspy
        from core.ai_engine.local_llm import resolve_task_chain

        chain_lm = resolve_task_chain(
            "AISEC_LOCAL_FILTER_MODEL",
            default_lm=None,
        )
        if chain_lm is None:
            # No vLLM chain resolvable — fall back to default TP
            return "TRUE_POSITIVE", 1.0

        predictor = _get_vllm_predictor()

        # Cap context for sanity — 1M ctx model means we *could* feed huge,
        # but per-finding 30K is plenty of function-body + call-chain.
        ctx = context[:30_000] if len(context) > 30_000 else context

        with dspy.context(lm=chain_lm):
            pred = predictor(
                rule_id=str(finding.get("rule_id", "")),
                severity=str(finding.get("severity", "")),
                cwe=str(finding.get("cwe", "")),
                message=str(finding.get("message", "")),
                code_context=ctx,
            )

        verdict_raw = str(getattr(pred, "verdict", "")).upper().strip()
        if "FALSE_POSITIVE" in verdict_raw:
            verdict = "FALSE_POSITIVE"
        elif "TRUE_POSITIVE" in verdict_raw:
            verdict = "TRUE_POSITIVE"
        else:
            # Model gave us something unexpected — default conservative
            verdict = "TRUE_POSITIVE"

        try:
            confidence = float(getattr(pred, "confidence", 0.7))
        except (TypeError, ValueError):
            confidence = 0.7
        confidence = max(0.0, min(1.0, confidence))

        # Resolve the model that actually served (chain may have
        # fallen through to a non-primary link). ``served_model`` is a
        # FallbackLM property that reports the last-used backend;
        # ``model`` would always name the primary, hiding fallbacks
        # from the triage log.
        served_model = (
            getattr(chain_lm, "served_model", None)
            or getattr(chain_lm, "model", "")
            or "vllm:chain"
        )

        if extras is not None:
            extras["model"] = served_model
            # Removed in paper §4 ablation: severity_hint / attack_path /
            # brief enrichment fields were never read downstream and
            # induced a positivity bias on the L3 verdict (model would
            # commit to filling attack_path → set verdict=TP).

        # No enrichment stored on the finding — verdict + confidence
        # are the only outputs of this filter.

        return verdict, confidence

    except Exception as exc:  # noqa: BLE001
        if extras is not None:
            extras["error"] = f"{type(exc).__name__}: {exc}"
            extras["model"] = "vllm:chain"
        # Conservative on error: KEEP the finding (TRUE_POSITIVE) but
        # mark low confidence so downstream layers can de-prioritise.
        # NOTE: this used to return confidence=1.0 which hid filter
        # failures behind perfect confidence stamps.
        return "TRUE_POSITIVE", 0.5
