"""Local LLM helpers shared by Layer 3 / compact / parsers.

This module isolates the "spec → backend → URL → call" plumbing so that
``local_filter.py``, ``compact.py``, and ``parsers.py`` don't each
re-implement env parsing, alias resolution, and OpenAI/Ollama shape
selection.

Spec format (compatible with the legacy ``AISEC_LOCAL_FILTER_MODEL`` etc.):

    ollama:<model_name>     e.g. ollama:qwen2.5-coder:7b
    vllm:<alias_or_id>      e.g. vllm:nemotron-120b
                                  vllm:/model/NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4

JSONL triage log:

    Set ``AISEC_TRIAGE_LOG=/path/to/log.jsonl`` (or via config) to enable.
    Each record contains backend, model, latency_ms, prompt/completion
    tokens (when known), and a caller-supplied tag + payload.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

# Friendly aliases for vLLM-hosted models. Add new entries here as the
# inventory grows; full model IDs (anything with a "/") pass through
# untouched.
_VLLM_ALIASES: dict[str, str] = {
    "nemotron-120b": "/model/NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4",
    "nemotron-49b":  "nvidia/llama-3.3-nemotron-super-49b-v1.5",
    # NOTE: Model IDs are what the vLLM server reports at /v1/models —
    # not the upstream HuggingFace path. Confirmed live against the
    # three Tailscale hosts on 2026-06-04. gemma host moved 2026-07-22 to
    # <gemma-host-2>:8001, which serves the model as "gemma-4-31B-it"
    # (no "/model/" prefix the old host used) — updated below.
    "gemma-4-31b":   "gemma-4-31B-it",
    "qwen3-coder":   "Qwen3-Coder-Next-AWQ-4bit",
}


# Multi-server vLLM routing: each model alias maps to the env var
# carrying its server URL. Server picked by substring match against
# the model spec (case-insensitive). Unknown specs fall back to the
# default ``VLLM_URL`` for backwards compat.
#
# Example layout — three Tailscale-internal vLLM hosts:
#   VLLM_URL=http://<nemotron-host>:8000/v1            # Nemotron-120B
#   VLLM_GEMMA_URL=http://<gemma-host>:8000/v1       # Gemma 4 31B
#   VLLM_QWEN_URL=http://<qwen-host>:8000/v1        # Qwen3-Coder
_VLLM_SERVER_ROUTES: list[tuple[str, str]] = [
    # Ordered: most-specific prefix first (so "qwen3" hits before "qwen")
    ("qwen3-coder", "VLLM_QWEN_URL"),
    ("qwen",        "VLLM_QWEN_URL"),
    ("gemma",       "VLLM_GEMMA_URL"),
    ("nemotron",    "VLLM_URL"),
]


# --------------------------------------------------------------------------- #
#   Resolvers                                                                 #
# --------------------------------------------------------------------------- #

def vllm_url() -> str:
    """Return the configured vLLM base URL (no trailing slash).

    Reads the live ``VLLM_URL`` env var first (so tests / runtime
    overrides win), falling back to the pydantic settings value
    captured at startup. Raises ``RuntimeError`` if neither is set —
    we intentionally do **not** fall back to any hardcoded host.
    """
    url = (os.getenv("VLLM_URL", "") or "").strip()
    if not url:
        try:
            from core.config import settings
            url = (settings.VLLM_URL or "").strip()
        except Exception:
            url = ""
    if not url:
        raise RuntimeError(
            "VLLM_URL is not configured. Set it (e.g. "
            "VLLM_URL=http://your-vllm-host:8000/v1) before using the "
            "vllm:* backend selector."
        )
    return url.rstrip("/")


def vllm_server_for(model_spec: str) -> str:
    """Route a vLLM model spec to its server URL.

    Looks up the model alias prefix in ``_VLLM_SERVER_ROUTES`` and
    reads the corresponding env var. Falls back to ``VLLM_URL`` for
    aliases that aren't multi-server routed yet (so single-server
    deployments keep working with one env var).
    """
    spec_low = (model_spec or "").lower()
    for prefix, env_var in _VLLM_SERVER_ROUTES:
        if prefix in spec_low:
            url = (os.getenv(env_var, "") or "").strip()
            if url:
                return url.rstrip("/")
    return vllm_url()


def vllm_resolve_model(spec: str) -> str:
    """``vllm:<spec>`` → full model id. Unknown aliases pass through."""
    return _VLLM_ALIASES.get(spec, spec)


def parse_spec(spec: str) -> tuple[str, str]:
    """Return ``(backend, model_spec)`` for the FIRST link of a chain spec.

    Chain support: env vars may now carry comma-separated fallback
    chains (e.g. ``vllm:qwen3-coder,vllm:nemotron-120b,vllm:gemma-4-31b``).
    Legacy callers that haven't yet migrated to ``resolve_task_chain``
    parse via ``parse_spec`` — those should still get a usable single
    spec, so we take the first link. A future migration moves them
    onto the FallbackLM chain proper.
    """
    if not spec:
        return "", ""
    first_link = spec.split(",", 1)[0].strip()
    backend, _, model_spec = first_link.partition(":")
    return backend.lower(), model_spec


# --------------------------------------------------------------------------- #
#   Backend-agnostic generation                                               #
# --------------------------------------------------------------------------- #

def local_generate(
    spec: str,
    prompt: str,
    *,
    max_tokens: int = 4096,
    temperature: float = 0.2,
    timeout: int = 60,
    tag: str = "",
) -> str:
    """Call the local LLM identified by ``spec`` and return raw response text.

    Returns ``""`` on any failure (network, non-200, missing key in response).
    Errors are swallowed by design — callers fall back to FSM / passthrough.

    ``tag`` is recorded in the JSONL log (if enabled) so you can attribute
    calls to specific call sites (``"compact"``, ``"cmd_parse"``, etc.).
    """
    backend, model_spec = parse_spec(spec)
    if not backend:
        return ""

    started = time.monotonic()
    response_text = ""
    prompt_tokens = 0
    completion_tokens = 0
    status: int | None = None
    error_msg: str | None = None

    try:
        import requests  # type: ignore

        if backend == "ollama":
            from core.ai_engine.ollama_url import resolve as resolve_ollama
            url = f"{resolve_ollama()}/api/generate"
            payload = {
                "model": model_spec or "mistral",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }
            resp = requests.post(url, json=payload, timeout=timeout)
            status = resp.status_code
            if resp.status_code == 200:
                response_text = resp.json().get("response", "") or ""

        elif backend == "vllm":
            model_id = vllm_resolve_model(model_spec)
            url = f"{vllm_url()}/chat/completions"
            payload = {
                "model": model_id,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
                "temperature": temperature,
                "stream": False,
            }
            resp = requests.post(url, json=payload, timeout=timeout)
            status = resp.status_code
            if resp.status_code == 200:
                data = resp.json()
                response_text = (
                    data.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                    or ""
                )
                usage = data.get("usage") or {}
                prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
                completion_tokens = int(usage.get("completion_tokens", 0) or 0)

        # Unknown backend: response_text stays "" → caller falls back.

    except Exception as exc:  # noqa: BLE001 — best-effort, caller falls back
        error_msg = f"{type(exc).__name__}: {exc}"

    elapsed_ms = int((time.monotonic() - started) * 1000)
    log_triage_event(
        {
            "tag": tag,
            "backend": backend,
            "model": vllm_resolve_model(model_spec) if backend == "vllm" else model_spec,
            "latency_ms": elapsed_ms,
            "http_status": status,
            "prompt_chars": len(prompt),
            "response_chars": len(response_text),
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "cost_usd": 0.0,
            "error": error_msg,
        }
    )
    return response_text


# --------------------------------------------------------------------------- #
#   JSONL logging (best-effort, never raises)                                 #
# --------------------------------------------------------------------------- #

def log_triage_event(record: dict[str, Any]) -> None:
    """Append a JSONL line to ``AISEC_TRIAGE_LOG`` if configured.

    Best-effort: silently ignores IO errors so logging never breaks a scan.
    Adds a ``ts`` field automatically (unix seconds, float).
    """
    try:
        from core.config import settings
        log_path = settings.AISEC_TRIAGE_LOG
    except Exception:
        log_path = os.getenv("AISEC_TRIAGE_LOG", "")

    if not log_path:
        return

    record = {**record, "ts": time.time()}
    try:
        parent = os.path.dirname(log_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


__all__ = [
    "vllm_url",
    "vllm_server_for",
    "resolve_task_chain",
    "DEFAULT_TASK_CHAINS",
    "vllm_resolve_model",
    "parse_spec",
    "local_generate",
    "log_triage_event",
    "get_vllm_dspy_lm",
    "get_sonnet_dspy_lm",
    "resolve_task_lm",
    "use_local_for",
]


# --------------------------------------------------------------------------- #
#   DSPy LM helper for per-task offloading                                    #
# --------------------------------------------------------------------------- #
#
# Used by call sites that want to route a specific task (auto-patch, PoC
# self-critique, ...) to the local vLLM Nemotron instead of the global
# DSPy LM (Anthropic Opus). Wrap with ``dspy.context(lm=get_vllm_dspy_lm())``
# at the call site.

_vllm_dspy_lm_cache: dict[str, Any] = {}


def get_vllm_dspy_lm(model_id: str | None = None) -> Any:
    """Return a DSPy LM pointed at the local vLLM. Cached per resolved model.

    Reuses ``DSPyNvidiaAdapter`` since vLLM and cloud NIM share the OpenAI
    chat-completions shape; we override ``base_url`` per model via
    ``vllm_server_for`` so a single process can drive multiple vLLM
    hosts in parallel (one server per model family).
    """
    raw = model_id or "nemotron-120b"
    resolved = vllm_resolve_model(raw)
    lm = _vllm_dspy_lm_cache.get(resolved)
    if lm is not None:
        return lm
    from core.ai_engine.nvidia_adapter import DSPyNvidiaAdapter
    # Pick the right server URL by alias/prefix — gemma → gemma host,
    # qwen → qwen host, nemotron → primary. ``raw`` carries the alias
    # before resolution so the prefix lookup works on friendly names.
    lm = DSPyNvidiaAdapter(model=resolved, base_url=vllm_server_for(raw))
    _vllm_dspy_lm_cache[resolved] = lm
    return lm


# Cloud NVIDIA NIM (build.nvidia.com) — fallback when self-hosted vLLM is down/
# hung. Same DSPyNvidiaAdapter, cloud base URL + NVIDIA_API_KEY. Rate-limited
# (429 at high concurrency) so use only at low parallelism.
_nvidia_cloud_cache: dict[str, Any] = {}
_NVIDIA_CLOUD_ALIASES: dict[str, str] = {
    "nemotron-120b": "nvidia/nemotron-3-super-120b-a12b",
    "nemotron": "nvidia/nemotron-3-super-120b-a12b",
    "nemotron-49b": "nvidia/llama-3.3-nemotron-super-49b-v1.5",
}


def get_nvidia_cloud_dspy_lm(model_id: str | None = None) -> Any:
    raw = model_id or "nemotron-120b"
    resolved = _NVIDIA_CLOUD_ALIASES.get(raw, raw)
    lm = _nvidia_cloud_cache.get(resolved)
    if lm is not None:
        return lm
    from core.ai_engine.nvidia_adapter import DSPyNvidiaAdapter
    lm = DSPyNvidiaAdapter(model=resolved,
                           base_url="https://integrate.api.nvidia.com/v1")
    _nvidia_cloud_cache[resolved] = lm
    return lm


# OpenRouter (openrouter.ai) — OpenAI-compatible aggregator hosting the SAME
# Nemotron-3-Super-120B model. Used after the self-hosted nemotron cluster was
# repurposed (2026-07-22) and NVIDIA cloud NIM free-tier credits ran out.
# OpenRouter load-balances across providers → handles very high concurrency
# with no 429 (tested to conc 1024). Auth via OPENROUTER_API_KEY.
_openrouter_cache: dict[str, Any] = {}
_OPENROUTER_ALIASES: dict[str, str] = {
    "nemotron-120b": "nvidia/nemotron-3-super-120b-a12b",
    "nemotron": "nvidia/nemotron-3-super-120b-a12b",
    "nemotron-49b": "nvidia/llama-3.3-nemotron-super-49b-v1.5",
    # Detection arms — same weights as the self-hosted vLLM models, moved to
    # OpenRouter so the experiment can run at high concurrency (self-hosted
    # single-node vLLM caps out; OpenRouter tested to conc 1024 with no 429).
    "qwen3-coder": "qwen/qwen3-coder-next",
    "gemma-4-31b": "google/gemma-4-31b-it",
}


def get_openrouter_dspy_lm(model_id: str | None = None) -> Any:
    raw = model_id or "nemotron-120b"
    resolved = _OPENROUTER_ALIASES.get(raw, raw)
    lm = _openrouter_cache.get(resolved)
    if lm is not None:
        return lm
    from core.ai_engine.nvidia_adapter import DSPyNvidiaAdapter
    lm = DSPyNvidiaAdapter(model=resolved,
                           base_url="https://openrouter.ai/api/v1",
                           api_key=os.getenv("OPENROUTER_API_KEY"))
    _openrouter_cache[resolved] = lm
    return lm


def use_local_for(env_var: str) -> str:
    """Read ``env_var`` and return the vLLM model id if its FIRST chain
    link is a ``vllm:*`` selector; otherwise return an empty string
    (caller falls back to the global LM).

    Chain-aware: ``vllm:qwen3-coder,vllm:nemotron-120b,sonnet`` returns
    ``"qwen3-coder"`` so legacy callers that haven't migrated to
    ``resolve_task_chain`` still get a working primary. Real
    chain-of-fallback behaviour requires ``resolve_task_chain``.

    Lets us write call sites like::

        target = use_local_for("AISEC_PATCH_BACKEND")
        if target:
            with dspy.context(lm=get_vllm_dspy_lm(target)):
                result = predictor(...)
        else:
            result = predictor(...)   # global LM (Opus)
    """
    spec = (os.getenv(env_var, "") or "").strip()
    if not spec:
        return ""
    first_link = spec.split(",", 1)[0].strip()
    backend, _, model_spec = first_link.partition(":")
    if backend.lower() != "vllm":
        return ""
    return model_spec or "nemotron-120b"


# --------------------------------------------------------------------------- #
#   Sonnet LM (Anthropic, 5× cheaper than Opus on input)                      #
# --------------------------------------------------------------------------- #

_sonnet_dspy_lm_cache: Any = None
_SONNET_MODEL_DEFAULT = "claude-sonnet-4-5"


def get_sonnet_dspy_lm(model: str | None = None) -> Any:
    """Return a cached ``DSPyClaudeAdapter`` pointed at Sonnet.

    Sonnet is ~5× cheaper than Opus on input tokens with comparable
    structured-output quality for verification / pattern-query tasks.
    """
    global _sonnet_dspy_lm_cache
    if _sonnet_dspy_lm_cache is not None and (model is None or model == _SONNET_MODEL_DEFAULT):
        return _sonnet_dspy_lm_cache
    from core.ai_engine.claude_adapter import DSPyClaudeAdapter
    lm = DSPyClaudeAdapter(model=model or _SONNET_MODEL_DEFAULT)
    if model is None or model == _SONNET_MODEL_DEFAULT:
        _sonnet_dspy_lm_cache = lm
    return lm


# --------------------------------------------------------------------------- #
#   Generic task-LM resolver                                                  #
# --------------------------------------------------------------------------- #

def resolve_task_lm(env_var: str, default_lm: Any = None) -> Any:
    """Map an env var value to a DSPy LM instance.

    Supported values:
        ""  or  "opus"          → return ``default_lm`` (typically the
                                  global DSPy LM, i.e. Opus)
        "sonnet"                → cached Sonnet adapter
        "sonnet:<model_id>"     → Sonnet with a non-default model id
        "vllm:<alias_or_id>"    → cached vLLM Nemotron adapter
                                  (alias defaults to ``nemotron-120b``)

    Used at call sites that want to offload a specific phase without
    touching the global LM:

        custom_lm = resolve_task_lm("AISEC_QUERY_BACKEND")
        if custom_lm is not None:
            with dspy.context(lm=custom_lm):
                ...

    Returns ``None`` if the env var is empty or set to ``opus``, so the
    caller knows to fall through to the global LM.
    """
    val = (os.getenv(env_var, "") or "").strip()
    if not val:
        return default_lm
    # Chain-aware: legacy callers that use ``resolve_task_lm`` (vs the
    # newer ``resolve_task_chain``) just get the first link as a bare LM.
    # Real FallbackLM-wrapped chains require the chain helper.
    first_link = val.split(",", 1)[0].strip().lower()
    if not first_link or first_link == "opus":
        return default_lm
    if first_link.startswith("sonnet"):
        _, _, model_spec = first_link.partition(":")
        return get_sonnet_dspy_lm(model_spec or None)
    if first_link.startswith("openrouter"):
        _, _, model_spec = first_link.partition(":")
        return get_openrouter_dspy_lm(model_spec or "nemotron-120b")
    if first_link.startswith("nvidia"):
        _, _, model_spec = first_link.partition(":")
        return get_nvidia_cloud_dspy_lm(model_spec or "nemotron-120b")
    if first_link.startswith("vllm"):
        _, _, model_spec = first_link.partition(":")
        return get_vllm_dspy_lm(model_spec or "nemotron-120b")
    return default_lm


# --------------------------------------------------------------------------- #
#   Chain-aware resolution (multi-model fallback)                              #
# --------------------------------------------------------------------------- #

#: Per-task default chains used when the env var is empty. The chain
#: lists primary first, fallbacks in escalation order. Each entry is
#: a backend spec parseable by ``_resolve_one_spec``:
#:    "vllm:<alias>"   → local vLLM
#:    "sonnet[:id]"    → Anthropic Sonnet
#:    "opus"           → global LM (whatever DSPy is configured with)
#:    "claude-opus-4-8" / "claude-sonnet-4-6" → direct adapter
#:
#: Designed so that on a fresh deployment with no env overrides, each
#: task lands on the strongest local model for that workload and
#: degrades through alternates before hitting paid Opus.
DEFAULT_TASK_CHAINS: dict[str, list[str]] = {
    # Layer 3 finding triage — coder-tuned model wins on
    # "is this code actually vulnerable" classification.
    "AISEC_LOCAL_FILTER_MODEL":
        ["vllm:qwen3-coder", "vllm:nemotron-120b", "vllm:gemma-4-31b"],
    "AISEC_CLUSTER_MODEL":
        ["vllm:qwen3-coder", "vllm:nemotron-120b", "vllm:gemma-4-31b"],

    # Auto-patch — unified diff format compliance + code repair.
    "AISEC_PATCH_BACKEND":
        ["vllm:qwen3-coder", "vllm:nemotron-120b"],

    # Language router classify — small classification task.
    "AISEC_ROUTER_BACKEND":
        ["vllm:qwen3-coder", "vllm:gemma-4-31b"],

    # PoC verify — arithmetic + scenario reasoning.
    "AISEC_POC_VERIFY_BACKEND":
        ["vllm:nemotron-120b", "vllm:gemma-4-31b", "vllm:qwen3-coder"],

    # Regression check — text comparison + judgment.
    "AISEC_REGRESSION_BACKEND":
        ["vllm:nemotron-120b", "vllm:gemma-4-31b", "vllm:qwen3-coder"],

    # IaC analysis — structured config reasoning.
    "AISEC_IAC_BACKEND":
        ["vllm:gemma-4-31b", "vllm:nemotron-120b", "vllm:qwen3-coder"],

    # Compact / summarisation — short prompts, small model wins.
    "AISEC_SUMMARY_MODEL":
        ["vllm:gemma-4-31b", "vllm:qwen3-coder"],
}


def _resolve_one_spec(spec: str, default_lm: Any = None) -> Any:
    """Resolve a single spec string (one link in a chain) to an LM.

    Returns ``None`` on unknown spec / unavailable backend, which the
    chain builder treats as "skip this link".
    """
    s = (spec or "").strip().lower()
    if not s or s == "opus":
        # ``default_lm`` is whatever DSPy's global LM is — caller
        # passes it through so the chain has a paid-tier endpoint.
        return default_lm
    if s.startswith("sonnet"):
        _, _, model_spec = s.partition(":")
        try:
            return get_sonnet_dspy_lm(model_spec or None)
        except Exception:
            return None
    if s.startswith("openrouter"):    # OpenRouter (openrouter.ai) — same model
        _, _, model_spec = s.partition(":")
        try:
            return get_openrouter_dspy_lm(model_spec or "nemotron-120b")
        except Exception:
            return None
    if s.startswith("nvidia"):    # cloud NIM (self-hosted-down fallback)
        _, _, model_spec = s.partition(":")
        try:
            return get_nvidia_cloud_dspy_lm(model_spec or "nemotron-120b")
        except Exception:
            return None
    if s.startswith("vllm"):
        _, _, model_spec = s.partition(":")
        try:
            return get_vllm_dspy_lm(model_spec or "nemotron-120b")
        except Exception:
            return None
    if s.startswith("claude-"):
        # Direct Anthropic model — bypass the alias system
        try:
            from core.ai_engine.claude_adapter import DSPyClaudeAdapter
            return DSPyClaudeAdapter(model=spec)
        except Exception:
            return None
    return None


def resolve_task_chain(
    env_var: str,
    *,
    default_chain: list[str] | None = None,
    default_lm: Any = None,
) -> Any:
    """Resolve an env var to a multi-model fallback chain.

    Env-var formats accepted:

      * Unset / empty → use ``default_chain`` (or, if that's empty,
        the entry in :data:`DEFAULT_TASK_CHAINS` for ``env_var``).
      * Single spec ("vllm:qwen3-coder") → single-model chain
        with no fallback (preserves the old ``use_local_for`` behaviour
        for test environments that only have one server up).
      * Comma-separated specs ("vllm:qwen3-coder,vllm:nemotron-120b,opus")
        → ordered chain. Primary first, fallbacks in escalation order.

    Returns a :class:`FallbackLM` wrapping the chain, or a bare LM if
    the chain collapses to a single resolvable link, or ``None`` if
    nothing resolved (caller falls through to the global LM).

    Unreachable backends in the chain are auto-skipped — the runtime
    fallback (transient errors) handles servers that come up but die
    mid-call; this function handles servers we can't even instantiate
    (e.g. ``vllm:gemma-4-31b`` when ``VLLM_GEMMA_URL`` is unset).
    """
    val = (os.getenv(env_var, "") or "").strip()
    if val:
        specs = [s.strip() for s in val.split(",") if s.strip()]
    elif default_chain is not None:
        specs = list(default_chain)
    else:
        specs = DEFAULT_TASK_CHAINS.get(env_var, [])
    if not specs:
        return default_lm

    resolved: list[Any] = []
    for spec in specs:
        lm = _resolve_one_spec(spec, default_lm=default_lm)
        if lm is not None:
            resolved.append(lm)

    if not resolved:
        return default_lm
    if len(resolved) == 1:
        return resolved[0]
    # Multi-link chain — wrap in FallbackLM
    from core.ai_engine.fallback_lm import FallbackLM
    return FallbackLM(primary=resolved[0], fallbacks=resolved[1:])
