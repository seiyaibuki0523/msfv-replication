import os
from dotenv import load_dotenv
from pydantic_settings import BaseSettings

load_dotenv()


def _default_workspace() -> str:
    import tempfile
    return os.getenv("AISEC_WORKSPACE", os.path.join(tempfile.gettempdir(), "aisec"))


class Settings(BaseSettings):
    # API Keys
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
    NVIDIA_API_KEY: str = os.getenv("NVIDIA_API_KEY", "")
    PROJECT_ID: str = os.getenv("PROJECT_ID", "")
    TIME_OUT: int = 600

    WORKSPACE: str = _default_workspace()

    # Concurrency cap for Opus calls in Layers 4 / 5 / 5.5. Set to 1 for
    # the legacy serial behaviour. Anthropic tier-2 accounts comfortably
    # handle 3-4 concurrent. Tokens consumed are unchanged; wall-clock
    # drops by ~60%. Override per-run via the ``--parallel-opus`` CLI flag.
    PARALLEL_OPUS: int = int(os.getenv("AISEC_PARALLEL_OPUS", "3"))

    # Local test mode — when set, SecureCommandExecutor allows commands that
    # target 127.0.0.1 / localhost / 0.0.0.0. Off by default so the agent
    # cannot accidentally attack the operator's own machine. Loopback
    # commands while this is on are tagged ``ALLOWED_LOCAL_TEST`` in the
    # audit log so the trail is unambiguous.
    ALLOW_LOOPBACK: bool = os.getenv("AISEC_ALLOW_LOOPBACK", "").lower() in {"1", "true", "yes", "on"}

    # Vault knowledge base — backed by the ClaudeVault FastAPI service.
    # Set VAULT_API_URL (e.g. http://127.0.0.1:8765) to enable. When unset,
    # all vault hooks are no-ops. VAULT_API_TOKEN is sent as bearer auth
    # when set (the API treats absence as dev-mode).
    VAULT_API_URL: str = os.getenv("VAULT_API_URL", "")
    VAULT_API_TOKEN: str = os.getenv("VAULT_API_TOKEN", "")
    VAULT_API_TIMEOUT: float = float(os.getenv("VAULT_API_TIMEOUT", "20.0"))

    # AI Engine Routing Priority — choose: gemini, openai, claude, nvidia, mixed
    DEFAULT_LLM_BACKEND: str = os.getenv("DEFAULT_LLM_BACKEND", "claude")

    # NVIDIA NIM model ID (see https://build.nvidia.com/models)
    NVIDIA_MODEL: str = os.getenv("NVIDIA_MODEL", "deepseek-ai/deepseek-r1")

    # NVIDIA NIM base URL override. Empty = use cloud
    # (https://integrate.api.nvidia.com/v1). Set to a self-hosted vLLM URL
    # to point the whole nvidia backend at a local model — affects
    # DEFAULT_LLM_BACKEND=nvidia paths globally. For local triage *only*
    # (Layer 3 filter, compaction, command parsing) use VLLM_URL instead.
    NVIDIA_BASE_URL: str = os.getenv("NVIDIA_BASE_URL", "")

    # Self-hosted vLLM endpoint for the local-only paths (Layer 3 FP filter,
    # context compaction, command parsing). Independent from NVIDIA_BASE_URL
    # so you can mix cloud NIM + local vLLM in the same run. No default —
    # must be set explicitly when using a vllm:* backend selector, otherwise
    # the vllm code path raises a clear error rather than silently calling
    # an arbitrary IP.
    VLLM_URL: str = os.getenv("VLLM_URL", "")

    # JSONL log path for triage events (verdict, confidence, latency, tokens).
    # Empty = logging disabled.
    AISEC_TRIAGE_LOG: str = os.getenv("AISEC_TRIAGE_LOG", "")

    # CTF Settings
    CTFD_URL: str = os.getenv("CTFD_URL", "")
    CTFD_TOKEN: str = os.getenv("CTFD_TOKEN", "")
    CTFD_USERNAME: str = os.getenv("CTFD_USERNAME", "")
    CTFD_PASSWORD: str = os.getenv("CTFD_PASSWORD", "")

    # Bounty Settings
    HACKERONE_USERNAME: str = os.getenv("HACKERONE_USERNAME", "")
    HACKERONE_API_TOKEN: str = os.getenv("HACKERONE_API_TOKEN", "")


settings = Settings()


def get_project_dir(project_name: str) -> str:
    """Return ``<WORKSPACE>/<project_name>/``, creating it if needed."""
    d = os.path.join(settings.WORKSPACE, project_name)
    os.makedirs(d, exist_ok=True)
    return d
