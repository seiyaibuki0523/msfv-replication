"""DSPy adapter for NVIDIA NIM (build.nvidia.com).

NVIDIA NIM hosts frontier open models behind an OpenAI-compatible endpoint at
``https://integrate.api.nvidia.com/v1``. Currently live picks for
security-analysis work (verified against build.nvidia.com catalog 2026-04-24):

    moonshotai/kimi-k2.5                256K ctx, best JSON/tool compliance (default)
    moonshotai/kimi-k2.6                Newer Kimi K2 (2026)
    nvidia/llama-3.3-nemotron-super-49b-v1.5   Nemotron v1.5, fewer access gates
    z-ai/glm5.1                         Agentic coding flagship (2026-04-17)
    nvidia/nemotron-3-super-120b-a12b   120B MoE / 12B active, 1M ctx — gated access

Deprecated / gone (do not use):
    deepseek-ai/deepseek-r1             EOL 2026-01-26
    z-ai/glm4.7                         older generation

Model catalog: https://build.nvidia.com/models
API docs:      https://docs.api.nvidia.com/nim/reference/llm-apis
"""

from __future__ import annotations

import os
import re

import dspy
import openai

from core.config import settings


def _default_max_tokens(model: str) -> int:
    """Token budget by model family. Reasoning models (Nemotron) need room
    for <think>; non-reasoning coder models (qwen3-coder) over-generate to
    fill a large budget on short tasks, so cap them. Env override wins."""
    env = os.getenv("AISEC_LLM_MAX_TOKENS")
    if env:
        return int(env)
    m = (model or "").lower()
    if "qwen" in m or "coder" in m or "gemma" in m:
        return 2048
    return 16000


# Inline thinking-tag patterns emitted by reasoning models (DeepSeek, Qwen3,
# Nemotron-3 Super, QwQ, …). DSPy's JSONAdapter chokes on these, so we strip
# them from the returned content and expose reasoning separately via the
# `reasoning_content` field.
_THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class DSPyNvidiaAdapter(dspy.LM):
    """DSPy-compatible adapter backed by NVIDIA NIM's OpenAI-shaped API."""

    DEFAULT_MODEL = "moonshotai/kimi-k2.5"
    BASE_URL = "https://integrate.api.nvidia.com/v1"

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        **kwargs,
    ):
        resolved_model = model or settings.NVIDIA_MODEL or self.DEFAULT_MODEL
        super().__init__(resolved_model)

        # Resolution order: explicit constructor arg → env (NVIDIA_BASE_URL)
        # → class default (cloud NIM). Empty NVIDIA_API_KEY is fine for
        # self-hosted vLLM, but the OpenAI SDK rejects empty strings — fall
        # back to a literal "dummy" so vLLM (which ignores the header) works.
        resolved_base = base_url or settings.NVIDIA_BASE_URL or self.BASE_URL
        # Explicit api_key arg wins (e.g. OpenRouter's OPENROUTER_API_KEY);
        # else NVIDIA_API_KEY; else "dummy" for self-hosted vLLM.
        resolved_key  = api_key or settings.NVIDIA_API_KEY or "dummy"

        # Hard timeout + bounded retries. Without this the OpenAI SDK can
        # block indefinitely on a half-open TCP connection to a self-hosted
        # vLLM endpoint — a single hung L3/L4 worker then deadlocks the whole
        # ThreadPool (observed: a cold DVD L3 stuck 70 min at 0% CPU on a
        # pthread lock wait). A bounded timeout makes the call fail fast so
        # FallbackLM treats it as transient and AISEC_TOLERANT_LAYER_ERRORS
        # lets the run continue. Override via AISEC_LLM_TIMEOUT.
        _timeout = float(os.getenv("AISEC_LLM_TIMEOUT", "120"))
        # High-concurrency headroom: OpenRouter upstream providers (Nemotron)
        # throttle with transient 429s above ~50 in-flight; the SDK's backoff
        # retry clears them (measured: 400 concurrent → 0 fail at retries=5).
        _retries = int(os.getenv("AISEC_LLM_RETRIES", "4"))
        self.client = openai.OpenAI(
            api_key=resolved_key,
            base_url=resolved_base,
            timeout=_timeout,
            max_retries=_retries,
        )
        self.base_url = resolved_base
        self.kwargs = kwargs
        self.history: list[dict] = []

        self.last_prompt_tokens: int = 0
        self.last_completion_tokens: int = 0

    def __call__(
        self,
        prompt: str | None = None,
        messages: list[dict] | None = None,
        **kwargs,
    ) -> list[str]:
        api_messages: list[dict] = []
        if messages:
            for m in messages:
                api_messages.append(
                    {"role": m.get("role", "user"), "content": m.get("content", "")}
                )
        if not api_messages:
            api_messages = [{"role": "user", "content": prompt or ""}]

        combined = {**self.kwargs, **kwargs}
        request_params: dict = {
            "model": self.model,
            "messages": api_messages,
            "temperature": combined.pop("temperature", 0.2),
            "top_p": combined.pop("top_p", 0.7),
            # Oversize budget — reasoning models can spend 4-8K tokens in
            # <think> before writing the structured answer. If this truncates
            # mid-generation DSPy's JSONAdapter will fail to parse.
            # Per-model token budget. Reasoning models (Nemotron) need a big
            # budget — they spend 4-8K tokens in <think> before the answer.
            # A non-reasoning coder model (qwen3-coder) given the same 16000
            # budget for a short verdict RAMBLES to fill it (a single L3
            # verdict took 905s!). So cap coder/qwen models low; keep
            # reasoning models high. Override via AISEC_LLM_MAX_TOKENS.
            "max_tokens": combined.pop("max_tokens", _default_max_tokens(self.model)),
        }

        if "stop" in combined:
            request_params["stop"] = combined.pop("stop")

        # Reproducibility seed (paper §IV replicates). AISEC_LLM_SEED pins the
        # sampler when the provider honors it; providers that ignore it fall
        # back to temperature-sampling nondeterminism (recorded in manifest).
        _seed_env = os.getenv("AISEC_LLM_SEED", "").strip()
        if _seed_env and "seed" not in combined:
            try:
                request_params["seed"] = int(_seed_env)
            except ValueError:
                pass

        for k, v in combined.items():
            if k in ("stream", "response_format", "seed", "tools", "tool_choice"):
                request_params[k] = v

        response = self.client.chat.completions.create(**request_params)

        raw = response.choices[0].message.content or ""

        # Strip inline <think>...</think> blocks before handing to DSPy. Some
        # reasoning NIMs (Nemotron-3 thinking mode, Qwen3-Thinking, QwQ) inline
        # them in `content` instead of routing to `reasoning_content`.
        stripped = _THINK_TAG_RE.sub("", raw).strip()

        # A few reasoning NIMs expose thinking through `reasoning_content`
        # (DeepSeek-style). Wrap it in DSPy-friendly tags so JSONAdapter skips
        # over it when scanning for output fields.
        reasoning = getattr(response.choices[0].message, "reasoning_content", None)
        if reasoning:
            text = f"<thinking>\n{reasoning}\n</thinking>\n{stripped}"
        else:
            text = stripped

        try:
            self.last_prompt_tokens = response.usage.prompt_tokens
            self.last_completion_tokens = response.usage.completion_tokens
        except AttributeError:
            self.last_prompt_tokens = 0
            self.last_completion_tokens = 0

        self.history.append(
            {"prompt": prompt, "messages": messages, "response": text}
        )
        return [text]

    def basic_request(self, prompt: str, **kwargs) -> dict:
        outputs = self(prompt=prompt, **kwargs)
        return {"choices": [{"message": {"content": outputs[0]}}]}
