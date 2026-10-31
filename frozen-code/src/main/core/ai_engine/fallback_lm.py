"""DSPy LM wrapper that retries across multiple backends.

Used to wrap the global LM so Layer 4 / 5 / 5.5 callers don't have to
implement their own fallback logic. Each transient failure escalates
to the next backend in the chain; non-transient failures propagate
immediately (otherwise a bad prompt would re-fire on every fallback).

Convention chain — primary Opus → Sonnet → vLLM Nemotron:

  * Opus: best quality, costliest, may rate-limit during global incidents
  * Sonnet: same provider, ~5× cheaper, different infra so 5xx doesn't
    always hit both
  * vLLM Nemotron: self-hosted, free, immune to Anthropic outages

The wrapper preserves each underlying LM's per-thread token attributes
(``last_prompt_tokens`` etc.) — callers reading those see whichever
backend actually served the request.
"""
from __future__ import annotations

from typing import Any

import dspy


class FallbackLM(dspy.LM):
    """LM that tries primary, then sequentially falls back to alternates.

    Failures classified as ``transient`` trigger fallback:

      * ``httpx.TimeoutException`` / any class with "timeout" in name
      * ``anthropic.APIStatusError`` with status >= 500 or status == 429
      * ``anthropic.APIConnectionError``
      * Any exception whose message matches the known transient phrases
        (overloaded, rate limit, gateway, etc.)

    Non-transient errors (400 BadRequest, auth errors) raise
    immediately — fallback there would just paper over a real bug.
    """

    def __init__(self, primary: dspy.LM, fallbacks: list[dspy.LM]) -> None:
        super().__init__(model=primary.model)
        self.primary = primary
        self.fallbacks = fallbacks
        self._last_used: dspy.LM = primary

    # ── Token-attr proxies (whichever backend just served the call) ────

    @property
    def last_prompt_tokens(self) -> int:
        return int(getattr(self._last_used, "last_prompt_tokens", 0) or 0)

    @property
    def last_completion_tokens(self) -> int:
        return int(getattr(self._last_used, "last_completion_tokens", 0) or 0)

    @property
    def last_cache_read_tokens(self) -> int:
        return int(getattr(self._last_used, "last_cache_read_tokens", 0) or 0)

    @property
    def last_cache_creation_tokens(self) -> int:
        return int(getattr(self._last_used, "last_cache_creation_tokens", 0) or 0)

    @property
    def served_model(self) -> str:
        """The model id of whichever backend actually served the last call.

        Distinct from ``self.model`` (set to the *primary* at __init__ and
        never updated) so the cost tracker can attribute pricing to the
        correct backend after a transient-error fallback. Without this,
        a vLLM-served call would be billed as Opus because the chain's
        ``model`` attribute still names the primary.
        """
        return str(getattr(self._last_used, "model", self.model) or self.model)

    # ── Call dispatch ─────────────────────────────────────────────────

    def __call__(self, *args, **kwargs) -> Any:
        chain: list[dspy.LM] = [self.primary, *self.fallbacks]
        last_exc: Exception | None = None
        parse_error_seen = False
        for i, lm in enumerate(chain):
            # Parse-error fast path: once any open-weight model has
            # produced a DSPy AdapterParseError, skip further local
            # backends in the chain — they're likely to parse-fail on
            # the same prompt (same format weakness) and serially
            # walking 3 vLLMs before reaching Sonnet adds ~3-4× wall
            # latency per call. Jump straight to the first
            # format-reliable (Anthropic) link.
            if parse_error_seen and _is_local_backend(lm):
                continue
            try:
                result = lm(*args, **kwargs)
                self._last_used = lm
                if i > 0:
                    # Best-effort warn — never let a logging failure
                    # surface a fallback as a real error.
                    try:
                        from core.ui import tui  # type: ignore[import]
                        tui.warn(
                            f"[FallbackLM] Primary failed, served by "
                            f"fallback #{i}: {getattr(lm, 'model', '?')}"
                        )
                    except Exception:
                        pass
                return result
            except Exception as exc:  # noqa: BLE001
                if _is_parse_error(exc):
                    parse_error_seen = True
                if not _is_transient(exc):
                    raise
                last_exc = exc
        raise RuntimeError(
            f"All {len(chain)} LM backends failed. "
            f"Last error: {type(last_exc).__name__}: {last_exc}"
        ) from last_exc


# --------------------------------------------------------------------------- #
# Transient classification                                                    #
# --------------------------------------------------------------------------- #

_TRANSIENT_PHRASES = (
    "timeout", "timed out", "connection reset", "connection aborted",
    "overloaded", "rate limit", "too many requests",
    "service unavailable", "bad gateway", "gateway timeout",
    "internal server error", "peer closed connection",
    "incomplete chunked read",
    # DSPy adapter parse failures — model returned content but missed
    # the ``[[ ## field ## ]]`` marker convention. Treated as transient
    # because a stronger / RLHF'd backend (typically Sonnet at the tail
    # of a vLLM chain) recovers the call. See docs/BACKEND_CHAINS.md.
    "failed to parse the lm response",
    "expected to find output fields",
)


# DSPy raises ``AdapterParseError`` (a ``ValueError`` subclass) when an
# adapter can't extract the expected output fields from the model
# response. Class-name match catches the error without importing DSPy
# at module load.
_TRANSIENT_CLASS_NAMES = (
    "adapterparseerror",
    "parseerror",
)


def _is_parse_error(exc: Exception) -> bool:
    """Detect a DSPy AdapterParseError (or look-alike) — model returned
    content but the adapter couldn't extract the expected output field.

    Used by FallbackLM's parse-error fast path to skip remaining local
    backends in the chain (same prompt, similar format weakness — all
    vLLM links are likely to fail in the same way; jump straight to
    Sonnet / Opus).
    """
    cls_name = type(exc).__name__.lower()
    if any(name in cls_name for name in _TRANSIENT_CLASS_NAMES):
        return True
    msg = str(exc).lower()
    return (
        "failed to parse the lm response" in msg
        or "expected to find output fields" in msg
    )


def _is_local_backend(lm: Any) -> bool:
    """Identify a vLLM / Ollama / other self-hosted backend by model id.

    Used by FallbackLM's parse-error fast path. Anthropic adapters
    expose ``model`` values starting with ``claude-...``; the legacy
    family aliases (``opus`` / ``sonnet`` / ``haiku``) resolve to
    DSPyClaudeAdapter instances whose ``model`` also starts with
    ``claude-...``. Anything else (vLLM server paths, raw HF ids) is
    treated as local.
    """
    model = (getattr(lm, "model", "") or "").lower()
    if model.startswith("claude-"):
        return False
    if any(tok in model for tok in ("/model/", "nemotron", "qwen", "gemma",
                                    "llama", "deepseek", "mistral", "ollama")):
        return True
    # Conservative default: unknown id → treat as Anthropic-class so a
    # rare custom model gets a chance to serve (worst case: parse-fail
    # again, walks the rest of the chain normally).
    return False


def _is_transient(exc: Exception) -> bool:
    """Conservative classifier — only treat as transient when we have
    a strong signal. Errs on the side of NOT falling back so a real
    400/401 bubbles up immediately and the caller sees the real cause.
    """
    cls_name = type(exc).__name__.lower()
    if "timeout" in cls_name or "connection" in cls_name:
        return True
    if any(name in cls_name for name in _TRANSIENT_CLASS_NAMES):
        return True
    # anthropic.APIStatusError stores HTTP status
    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and (status >= 500 or status == 429):
        return True
    msg = str(exc).lower()
    return any(p in msg for p in _TRANSIENT_PHRASES)


# --------------------------------------------------------------------------- #
# Default chain                                                                #
# --------------------------------------------------------------------------- #

def build_default_fallback_chain() -> FallbackLM:
    """Build the convention chain: Opus → Sonnet → vLLM Nemotron.

    Each fallback is constructed lazily and silently dropped if the
    backend isn't available on this host (e.g. vLLM URL unreachable).
    """
    from core.ai_engine.claude_adapter import DSPyClaudeAdapter

    primary = DSPyClaudeAdapter(model="claude-opus-4-8")
    fallbacks: list[dspy.LM] = []

    # Tier 1 — same provider, cheaper model
    try:
        fallbacks.append(DSPyClaudeAdapter(model="claude-sonnet-4-6"))
    except Exception:  # noqa: BLE001
        pass

    # Tier 2 — different provider entirely (immune to Anthropic-wide outage)
    try:
        from core.ai_engine.local_llm import (
            get_vllm_dspy_lm, vllm_resolve_model,
        )
        fallbacks.append(get_vllm_dspy_lm(vllm_resolve_model("nemotron-120b")))
    except Exception:  # noqa: BLE001
        pass  # vLLM unreachable on this host — no Tier-2 fallback

    return FallbackLM(primary=primary, fallbacks=fallbacks)


__all__ = ["FallbackLM", "build_default_fallback_chain"]
