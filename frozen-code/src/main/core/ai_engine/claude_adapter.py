import anthropic
import dspy
import threading

import core.config


class DSPyClaudeAdapter(dspy.LM):
    """
    DSPy-compatible adapter for Claude (Anthropic API).
    Mirrors the interface expected by DSPy's LM base class.

    Opus 4.8 notes (same request surface as 4.7 — no new breaking changes):
      - `temperature` / `top_p` / `top_k` are rejected (HTTP 400); do not send them.
      - Adaptive thinking is the only supported thinking mode.
      - System prompt is wrapped with `cache_control: ephemeral` so DSPy's
        repeated signatures benefit from prompt caching (5-minute TTL).

    Concurrency:
      Token counters (``last_prompt_tokens`` etc.) are kept in
      ``threading.local`` so concurrent ``__call__`` invocations from a
      ThreadPoolExecutor don't clobber each other. Each calling thread
      reads back its own usage from the same attribute names — the
      callsite code in ``pipeline.py`` doesn't change. ``history`` is
      append-only and protected by a lock.
    """

    def __init__(self, model: str = "claude-opus-4-8", **kwargs):
        super().__init__(model)
        # Explicit timeout — without it, streaming reads can hang
        # indefinitely if Anthropic stalls mid-response (observed on
        # MAC-14: 3h 17m hung run, eventually surfaced as "peer closed
        # connection without sending complete message body").
        self.client = anthropic.Anthropic(
            api_key=core.config.settings.ANTHROPIC_API_KEY,
            timeout=300.0,  # 5 minutes per call
            max_retries=2,
        )
        self.kwargs = kwargs
        self._tls = threading.local()
        self._history_lock = threading.Lock()
        self.history: list[dict] = []

    # Per-thread token counters, exposed as plain attributes for
    # backwards-compat with callers that read ``adapter.last_prompt_tokens``
    # directly. Each thread's reads return that thread's own write.

    @property
    def last_prompt_tokens(self) -> int:
        return getattr(self._tls, "last_prompt_tokens", 0)

    @last_prompt_tokens.setter
    def last_prompt_tokens(self, value: int) -> None:
        self._tls.last_prompt_tokens = value

    @property
    def last_completion_tokens(self) -> int:
        return getattr(self._tls, "last_completion_tokens", 0)

    @last_completion_tokens.setter
    def last_completion_tokens(self, value: int) -> None:
        self._tls.last_completion_tokens = value

    @property
    def last_cache_read_tokens(self) -> int:
        return getattr(self._tls, "last_cache_read_tokens", 0)

    @last_cache_read_tokens.setter
    def last_cache_read_tokens(self, value: int) -> None:
        self._tls.last_cache_read_tokens = value

    @property
    def last_cache_creation_tokens(self) -> int:
        return getattr(self._tls, "last_cache_creation_tokens", 0)

    @last_cache_creation_tokens.setter
    def last_cache_creation_tokens(self, value: int) -> None:
        self._tls.last_cache_creation_tokens = value

    def __call__(
        self, prompt: str | None = None, messages: list[dict] | None = None, **kwargs
    ) -> list[str]:
        system_msg = ""
        api_messages: list[dict] = []

        if messages:
            for m in messages:
                if m.get("role") == "system":
                    system_msg = m.get("content", "")
                else:
                    api_messages.append(
                        {"role": m["role"], "content": m.get("content", "")}
                    )
        if not api_messages:
            api_messages = [{"role": "user", "content": prompt or ""}]

        # User-message cache control — split long user prompts at the
        # last markdown section boundary so Anthropic can cache the
        # shared prefix across calls that vary only in their tail.
        #
        # Scope: Layer 5 only. Layer 5 sends 6 different queries that
        # share the same ``## Function Implementations`` prefix —
        # caching it saves ~80% on the 6 calls' input cost after the
        # first.
        #
        # Why NOT Layer 4: L4 runs sequentially (one finding at a time,
        # ~45-90s each), so the >5-minute cache TTL elapses between
        # calls. Splitting Layer 4 prompts incurs the 1.25× cache-write
        # premium WITHOUT achieving any cache-read hits — net negative.
        # RUN MAC-17v6 showed this regressed scan cost by ~$3.
        #
        # Threshold: 4,000 chars (~1,000 tokens). Below that Anthropic
        # rejects cache_control as too short to be useful.
        _CACHE_SPLIT_MIN_CHARS = 4_000
        _CACHE_SPLIT_MARKERS = (
            "\n## Security Analysis Query",   # Layer 5 query boundary
        )
        for am in api_messages:
            content = am.get("content", "")
            if not isinstance(content, str) or len(content) < _CACHE_SPLIT_MIN_CHARS:
                continue
            split_idx = -1
            for marker in _CACHE_SPLIT_MARKERS:
                idx = content.rfind(marker)
                if idx > 0 and idx > _CACHE_SPLIT_MIN_CHARS // 2:
                    split_idx = idx
                    break
            if split_idx < 0:
                # No L5 marker found — don't split. Random 75% fallback
                # cached Layer 4 prompts unnecessarily and was a net
                # negative on sequential-worker scans.
                continue
            prefix = content[:split_idx]
            tail = content[split_idx:]
            am["content"] = [
                {"type": "text", "text": prefix,
                 "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": tail},
            ]

        # Wrap system prompt as a cacheable block when present.
        # DSPy reuses the same system prompt across calls, so this yields
        # high cache-hit rates on Opus 4.8 (min cacheable prefix: 4096 tokens).
        # When AISEC_CACHE_TTL=1h, ask Anthropic for the 1-hour TTL —
        # otherwise omit the ttl marker so we get the default 5-minute
        # ephemeral lifetime (works on all tiers).
        system_param: list[dict] | str
        if system_msg:
            try:
                from core.ai_engine.prompt_cache_registry import (
                    ttl_marker, get_registry,
                )
                ttl = ttl_marker()
            except Exception:
                ttl = None
                get_registry = None  # type: ignore[assignment]
            cache_ctrl: dict = {"type": "ephemeral"}
            if ttl:
                cache_ctrl["ttl"] = ttl
            system_param = [
                {
                    "type": "text",
                    "text": system_msg,
                    "cache_control": cache_ctrl,
                }
            ]
            # Record into the persistent registry so the next scan can
            # skip prewarm when this prompt's cache should still be hot.
            if get_registry is not None:
                try:
                    get_registry().record(
                        system_msg, model=self.model, signature="claude_adapter",
                    )
                except Exception:
                    pass
        else:
            system_param = ""

        combined_kwargs = {**self.kwargs, **kwargs}
        
        # Opus 4.8 rejects temperature, top_p, top_k
        for bad_key in ["temperature", "top_p", "top_k"]:
            combined_kwargs.pop(bad_key, None)

        request_params = {
            "model": self.model,
            # Bumped from 16K to 32K because adaptive thinking can consume
            # the full output budget on long Layer-5 prompts (HARD RULES +
            # few-shot example + per-block structure) and leave nothing
            # for the actual answer — DSPy then sees only a `<thinking>`
            # block and JSONAdapter fails to parse.
            "max_tokens": combined_kwargs.pop("max_tokens", 32000),
            "messages": api_messages,
        }

        # Adaptive thinking is an Opus-4.x-only feature — Sonnet / Haiku
        # currently reject it with ``invalid_request_error``. RUN MAC-17v4
        # crashed at Layer 5 because AISEC_QUERY_BACKEND=sonnet sent the
        # adaptive thinking config Opus expects. Gate it by model family.
        model_lower = (self.model or "").lower()
        supports_thinking = "opus" in model_lower
        thinking_override = combined_kwargs.pop("thinking", None)
        if thinking_override is not None:
            # Explicit caller override — trust them, even on Sonnet (a
            # power user might want to test future Sonnet thinking support).
            request_params["thinking"] = thinking_override
        elif supports_thinking:
            request_params["thinking"] = {"type": "adaptive"}
        # else: omit ``thinking`` entirely so Sonnet/Haiku stay happy

        if system_param:
            request_params["system"] = system_param

        # Handle DSPy's stop sequences
        if "stop" in combined_kwargs:
            stop_val = combined_kwargs.pop("stop")
            request_params["stop_sequences"] = [stop_val] if isinstance(stop_val, str) else stop_val

        # Pass any other valid Anthropic kwargs. ``stream`` is intentionally
        # excluded — we always use the streaming context manager below, and
        # ``client.messages.stream()`` would raise on a redundant
        # ``stream=True`` argument.
        for k, v in combined_kwargs.items():
            if k in ["stop_sequences", "tool_choice", "tools", "metadata"]:
                request_params[k] = v

        # Use the streaming context manager unconditionally. With
        # ``max_tokens=32000`` + adaptive thinking, a single response can
        # exceed Anthropic's 10-minute non-streaming ceiling and the SDK
        # raises ``Streaming is required for operations that may take
        # longer than 10 minutes``. Streaming has no downside — we drain
        # the stream and reconstruct the same Message object via
        # ``get_final_message()``.
        with self.client.messages.stream(**request_params) as stream:
            # Drain text chunks so the request actually completes.
            # (We don't surface incremental output here — DSPy callers
            #  consume the final string in one shot.)
            for _chunk in stream.text_stream:
                pass
            response = stream.get_final_message()

        # Separate thinking blocks (internal reasoning) from text blocks
        # (the actual answer). DSPy's JSONAdapter parses the answer for
        # ``[[ ## field_name ## ]]`` markers — feeding it ``<thinking>``
        # output makes parsing brittle and confuses the regex.
        text_parts: list[str] = []
        thinking_parts: list[str] = []
        for block in response.content:
            if block.type == "thinking":
                thinking_parts.append(block.thinking)
            elif block.type == "text":
                text_parts.append(block.text)

        text = "\n".join(text_parts)

        self.last_prompt_tokens = response.usage.input_tokens
        self.last_completion_tokens = response.usage.output_tokens
        self.last_cache_read_tokens = getattr(
            response.usage, "cache_read_input_tokens", 0
        ) or 0
        self.last_cache_creation_tokens = getattr(
            response.usage, "cache_creation_input_tokens", 0
        ) or 0

        # Defensive: if max_tokens was exhausted by thinking and Claude
        # never reached the text-block stage, surface a clearer error
        # than the silent ``Adapter JSONAdapter failed to parse the LM
        # response`` that DSPy would emit otherwise.
        if not text:
            raise RuntimeError(
                "Claude returned only thinking content (no text answer). "
                "max_tokens budget was likely consumed by adaptive "
                "thinking on a long prompt. Either bump max_tokens, or "
                "pass ``thinking={'type': 'disabled'}`` for queries that "
                "don't need reasoning."
            )

        # Keep thinking in history for debug / audit, but do NOT forward
        # it to DSPy — it would just confuse the parser.
        with self._history_lock:
            self.history.append({
                "prompt": prompt,
                "messages": messages,
                "response": text,
                "thinking": "\n\n".join(thinking_parts),
            })
        return [text]

    def basic_request(self, prompt: str, **kwargs) -> dict:
        """Compatibility shim for DSPy internals that call basic_request."""
        outputs = self(prompt=prompt, **kwargs)
        return {"choices": [{"message": {"content": outputs[0]}}]}
