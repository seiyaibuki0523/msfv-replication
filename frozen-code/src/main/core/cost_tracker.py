"""
Centralised cost tracker — single source of truth for LLM spend.

Existing code scattered cost across ScanState (``total_cost_usd``,
``total_opus_input_tokens``, etc.) which led to naming bugs (we recently
fixed ``total_opus_cost_usd`` vs ``total_cost_usd``). All call sites should
now go through :class:`CostTracker`, then mirror the rolled-up totals back
into ``ScanState`` if persistence is needed.

Pricing tables reflect public USD/MTok rates as of 2026-04. Update the
``PRICING`` dict when models change.

Threshold hooks fire ``on_cost_threshold`` once per crossed level so users
can attach a Slack alert or hard-cap the scan.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable

from core import hooks

# --------------------------------------------------------------------------- #
#   Pricing table (USD per 1M tokens)                                         #
# --------------------------------------------------------------------------- #

# (input_per_mtok, output_per_mtok)
PRICING: dict[str, tuple[float, float]] = {
    # Anthropic Claude — current generation
    "claude-opus-4-8":   (5.0,  25.0),
    "claude-opus-4-7":   (5.0,  25.0),
    "claude-opus-4-6":   (5.0,  25.0),
    "claude-sonnet-4-6": (3.0,  15.0),
    "claude-sonnet-4-5": (3.0,  15.0),
    "claude-haiku-4-5":  (0.25, 1.25),
    # Family aliases — used by ``_normalize`` as fallback when the
    # specific version isn't in the table. Keeps pricing accurate even
    # when a future Claude variant lands before we update this map.
    "opus":   (5.0,  25.0),
    "sonnet": (3.0,  15.0),
    "haiku":  (0.25, 1.25),
    # OpenAI (rough — adjust to actual project usage)
    "gpt-4o":      (2.5,  10.0),
    "gpt-4o-mini": (0.15, 0.60),
    # Google Gemini
    "gemini-2.5-pro":   (1.25, 10.0),
    "gemini-2.5-flash": (0.075, 0.30),
    # Local / self-hosted backends — electricity-only, zero billable cost
    "local":   (0.0, 0.0),
    "ollama":  (0.0, 0.0),
    "vllm":    (0.0, 0.0),
}

USD_TO_NTD = 32.0


# --------------------------------------------------------------------------- #
#   Per-model entry                                                           #
# --------------------------------------------------------------------------- #

@dataclass
class ModelUsage:
    input_tokens:  int = 0
    output_tokens: int = 0
    cost_usd:      float = 0.0
    calls:         int = 0


# --------------------------------------------------------------------------- #
#   Tracker                                                                   #
# --------------------------------------------------------------------------- #

class CostTracker:
    """Singleton-style cost ledger.

    Use the module-level :data:`tracker` for global access; instantiate
    directly only if you need a sandboxed tracker (e.g. tests).
    """

    def __init__(self) -> None:
        self._by_model: dict[str, ModelUsage] = {}
        self._thresholds: list[float] = [1.0, 5.0, 10.0, 25.0, 50.0, 100.0]
        self._fired: set[float] = set()
        self._lock = threading.Lock()
        self._sinks: list[Callable[[dict], None]] = []

    # ---------------- core ledger -----------------------------------------

    def record(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> float:
        """Record a single LLM call. Returns the USD cost of this call.

        Anthropic prompt-cache billing applies three distinct rates to
        the three input segments (which are mutually exclusive — together
        they partition the request's full input):

          input_tokens         (fresh)   → 1.0× rate
          cache_read_tokens    (hit)     → 0.1× rate (90% discount)
          cache_write_tokens   (created) → 1.25× rate (25% premium)

        Callers that don't care about cache pricing can omit the cache
        args; the call collapses to the original behaviour and is
        backwards-compatible.
        """
        key = self._normalize(model)
        in_rate, out_rate = PRICING.get(key, PRICING.get("opus", (5.0, 25.0)))

        fresh_cost = (input_tokens / 1_000_000) * in_rate
        cache_read_cost = (cache_read_tokens / 1_000_000) * in_rate * 0.1
        cache_write_cost = (cache_write_tokens / 1_000_000) * in_rate * 1.25
        output_cost = (output_tokens / 1_000_000) * out_rate
        cost = fresh_cost + cache_read_cost + cache_write_cost + output_cost

        with self._lock:
            entry = self._by_model.setdefault(model, ModelUsage())
            entry.input_tokens  += input_tokens + cache_read_tokens + cache_write_tokens
            entry.output_tokens += output_tokens
            entry.cost_usd      += cost
            entry.calls         += 1
            for sink in self._sinks:
                try:
                    sink({
                        "model": model, "cost_usd": cost,
                        "input_tokens": input_tokens,
                        "cache_read_tokens": cache_read_tokens,
                        "cache_write_tokens": cache_write_tokens,
                        "output_tokens": output_tokens,
                    })
                except Exception:  # noqa: BLE001
                    pass

        self._check_thresholds()
        return cost

    # ---------------- read API --------------------------------------------

    @property
    def total_cost_usd(self) -> float:
        with self._lock:
            return sum(e.cost_usd for e in self._by_model.values())

    @property
    def total_cost_ntd(self) -> float:
        return self.total_cost_usd * USD_TO_NTD

    @property
    def total_input_tokens(self) -> int:
        with self._lock:
            return sum(e.input_tokens for e in self._by_model.values())

    @property
    def total_output_tokens(self) -> int:
        with self._lock:
            return sum(e.output_tokens for e in self._by_model.values())

    def by_model(self) -> dict[str, ModelUsage]:
        with self._lock:
            return dict(self._by_model)

    def status_line(self) -> str:
        return (
            f"LLM spend: ${self.total_cost_usd:.4f} (NT${self.total_cost_ntd:.1f}) "
            f"across {sum(e.calls for e in self._by_model.values())} calls"
        )

    # ---------------- config ----------------------------------------------

    def set_thresholds(self, thresholds: list[float]) -> None:
        with self._lock:
            self._thresholds = sorted(thresholds)
            self._fired.clear()

    def add_sink(self, sink: Callable[[dict], None]) -> None:
        """Register a per-call callback (used by tests, dashboards, etc.)."""
        with self._lock:
            self._sinks.append(sink)

    def reset(self) -> None:
        with self._lock:
            self._by_model.clear()
            self._fired.clear()

    # ---------------- helpers ---------------------------------------------

    # Tokens that, when present in a normalised model string, identify
    # a self-hosted vLLM-served model (server-reported paths look like
    # ``/model/NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4`` or bare ids
    # like ``Qwen3-Coder-Next-AWQ-4bit``). Without this match, those
    # ids fall through to the Opus default and a free vLLM call gets
    # billed as if it cost $0.05 — destroying cost attribution under
    # the multi-model fallback chain.
    _VLLM_MODEL_TOKENS = (
        "nemotron", "qwen", "gemma", "llama-3", "deepseek", "mistral",
    )

    @staticmethod
    def _normalize(model: str) -> str:
        m = (model or "").strip().lower()
        # Spec-prefixed locals: ``vllm:nemotron-120b``, ``ollama:qwen2.5-7b``
        if m.startswith("vllm:") or m.startswith("vllm/"):
            return "vllm"
        if m.startswith("ollama:") or m.startswith("ollama/"):
            return "ollama"
        # vLLM server-reported model paths/ids — match by characteristic
        # substring so different deployments (HF path vs custom alias)
        # all bill at the local rate.
        if m.startswith("/model/") or any(
            tok in m for tok in CostTracker._VLLM_MODEL_TOKENS
        ):
            return "vllm"
        # Trim provider prefixes ("anthropic/claude-opus-4-6")
        if "/" in m:
            m = m.split("/", 1)[1]
        # Strip date suffix ("claude-haiku-4-5-20251001")
        if m.startswith("claude-haiku-4-5"):
            return "claude-haiku-4-5"
        # Family-level fallback so a not-yet-tabulated version still
        # bills at the right tier (claude-sonnet-4-9 → sonnet pricing,
        # claude-opus-4-9 → opus pricing).
        if m.startswith("claude-opus-"):
            return "opus"
        if m.startswith("claude-sonnet-"):
            return "sonnet"
        if m.startswith("claude-haiku-"):
            return "haiku"
        return m

    def _check_thresholds(self) -> None:
        total = self.total_cost_usd
        for threshold in self._thresholds:
            if total >= threshold and threshold not in self._fired:
                self._fired.add(threshold)
                hooks.trigger("on_cost_threshold", {
                    "total_cost_usd": total,
                    "threshold": threshold,
                })


# Module-level singleton
tracker = CostTracker()


# --------------------------------------------------------------------------- #
#   Convenience helpers                                                       #
# --------------------------------------------------------------------------- #

def infer_model_name(local_target: str | None = None) -> str:
    """Infer the model name to record against for cost-tracking purposes.

    ``local_target`` is the value returned by ``use_local_for(env_var)``:
      - non-empty → vLLM call, return ``vllm:<spec>`` (tracker rate 0)
      - empty/None → fell through to global LM,
        whose backend is controlled by ``DEFAULT_LLM_BACKEND``

    Cevanex-layer adapters call this right before ``tracker.record(...)``
    so cevanex-layer Opus calls are accounted for the same way the
    pipeline.py callers already are.
    """
    import os
    if local_target:
        return f"vllm:{local_target}"
    backend = (os.getenv("DEFAULT_LLM_BACKEND", "") or "").strip().lower()
    if backend == "claude":
        return "claude-opus-4-6"
    if backend == "sonnet":
        return "claude-sonnet-4-6"
    if backend == "haiku":
        return "claude-haiku-4-5"
    if backend == "gemini":
        return "gemini-2.5-pro"
    if backend == "openai":
        return "gpt-4o"
    if backend == "nvidia":
        return "vllm"   # treated as local-equivalent rate
    return "opus"  # safest assumption — falls to Opus alias rate


def record_cevanex_call(
    local_target: str | None,
    lm,
) -> float:
    """One-call helper for cevanex-layer adapters.

    Reads the four token fields off ``lm`` (set by claude_adapter or the
    vLLM adapter), figures out the right model name, and records to the
    global tracker. Returns the USD cost of this call (0 if no tokens).

    Usage at any cevanex-layer DSPy call site::

        from core.cost_tracker import record_cevanex_call
        result = predictor(**kwargs)
        record_cevanex_call(local_target, dspy.settings.lm if not local_target
                            else custom_lm)
    """
    prompt_toks = getattr(lm, "last_prompt_tokens", 0) or 0
    completion_toks = getattr(lm, "last_completion_tokens", 0) or 0
    cache_read = getattr(lm, "last_cache_read_tokens", 0) or 0
    cache_write = getattr(lm, "last_cache_creation_tokens", 0) or 0
    if not (prompt_toks or completion_toks or cache_read or cache_write):
        return 0.0
    return tracker.record(
        infer_model_name(local_target),
        prompt_toks, completion_toks,
        cache_read, cache_write,
    )


def record_lm_call(model: str, input_tokens: int, output_tokens: int) -> float:
    """Record one LLM call against the global tracker."""
    return tracker.record(model, input_tokens, output_tokens)


def sync_to_scan_state(state) -> None:  # type: ignore[no-untyped-def]
    """Mirror tracker totals into a :class:`ScanState`-like object."""
    if state is None:
        return
    state.total_cost_usd = tracker.total_cost_usd
    state.total_opus_input_tokens  = tracker.total_input_tokens
    state.total_opus_output_tokens = tracker.total_output_tokens
