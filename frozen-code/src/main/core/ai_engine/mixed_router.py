from core.config import settings
import dspy


class AIEngineRouter:
    def __init__(self):
        self.default_backend = settings.DEFAULT_LLM_BACKEND
        self.lm = None
        self._setup_dspy()

    def _setup_dspy(self):
        backend = self.default_backend

        # "mixed" falls back to the first available key
        # Priority: Claude Opus → NVIDIA NIM (frontier open) → Gemini → OpenAI
        if backend == "mixed":
            if settings.ANTHROPIC_API_KEY:
                backend = "claude"
            elif settings.NVIDIA_API_KEY:
                backend = "nvidia"
            elif settings.GEMINI_API_KEY:
                backend = "gemini"
            else:
                backend = "openai"

        if backend == "claude":
            # Wrap the primary Opus adapter in FallbackLM so transient
            # Anthropic outages (5xx / 429 / streaming hang) trigger
            # auto-fallback to Sonnet → vLLM Nemotron instead of
            # crashing the entire scan. RUN MAC-14 spent 3h 17m on
            # a streaming-read stall before surfacing the error —
            # the wrapper fails fast and recovers from a same-provider
            # blip via the Sonnet fallback.
            from core.ai_engine.fallback_lm import build_default_fallback_chain
            self.lm = build_default_fallback_chain()

        elif backend == "nvidia":
            from core.ai_engine.nvidia_adapter import DSPyNvidiaAdapter
            self.lm = DSPyNvidiaAdapter()

        elif backend == "gemini":
            from core.ai_engine.gemini_adapter import DSPyGeminiAdapter
            self.lm = DSPyGeminiAdapter(model="gemini-2.5-pro-preview-05-06")

        else:  # openai
            self.lm = dspy.LM(model="gpt-4o", api_key=settings.OPENAI_API_KEY)

        dspy.configure(lm=self.lm)

    @property
    def total_prompt_tokens(self) -> int:
        if hasattr(self.lm, "last_prompt_tokens"):
            return self.lm.last_prompt_tokens
        return getattr(self.lm, "usage", {}).get("prompt_tokens", 0)

    @property
    def total_completion_tokens(self) -> int:
        if hasattr(self.lm, "last_completion_tokens"):
            return self.lm.last_completion_tokens
        return getattr(self.lm, "usage", {}).get("completion_tokens", 0)


engine = AIEngineRouter()
