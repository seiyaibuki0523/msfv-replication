"""Platform adapter ABC, registry, and shared types.

A *platform* is the runtime/framework a piece of code targets. It is finer-grained
than language: Solidity is one platform; Soroban (Rust + soroban-sdk) and Solana
(Rust + anchor_lang) are two distinct platforms even though both are Rust.

Adapters declare, per Layer-5 vuln-class query:
  - whether the query is applicable on this platform at all
  - a prompt addendum that injects platform-specific HARD RULES
  - a severity cap (in case the query produces a finding that the platform's
    runtime would partially mitigate)
  - an optional seed-matcher override (overrides the language-level default
    in seed_matchers.py)

Adapters also publish:
  - codebase_signals(): facts the prompt should know (intentional naming
    conventions, doc-comment disclaimers, framework-level guarantees)
  - exploit_harness_kind(): which harness scaffold to spin up at Layer 4.5

Detection is per-file. A repo can mix platforms (Python backend + Solidity
contracts + TS frontend) — each file routes to its own adapter independently.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Optional


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _norm(sev: str) -> str:
    return (sev or "").strip().lower()


def cap_severity(current: str, ceiling: str) -> str:
    """Return the lower of (current, ceiling) by rank.

    Severity ordering: critical > high > medium > low > info.
    """
    cur = _norm(current)
    cap = _norm(ceiling)
    if cur not in _SEVERITY_RANK or cap not in _SEVERITY_RANK:
        return current
    if _SEVERITY_RANK[cur] < _SEVERITY_RANK[cap]:
        return ceiling
    return current


# Seed-matcher signature: (function_key, body, access_control_map) -> bool
SeedMatcher = Callable[[str, str, dict], bool]


@dataclass
class QuerySpec:
    """Per-platform configuration for a Layer-5 query."""

    enabled: bool = True

    # Appended to the base query prompt as additional HARD RULES. Use this
    # to teach the LLM about runtime-level mitigations, intentional library
    # patterns, doc-comment disclaimers, or framework-specific idioms it
    # should not flag as bugs.
    prompt_addendum: str = ""

    # Caps the severity the LLM is allowed to assign. e.g. a CEI violation
    # on Soroban is structurally a bug but the host blocks reentry, so cap
    # at "medium". Set to None for no cap.
    severity_cap: Optional[str] = None

    # Overrides the default seed matcher in seed_matchers.py. Use when the
    # platform has unusual idioms (e.g. Solana's Account model, Move's
    # capability tokens) that the language-level matcher cannot recognise.
    seed_matcher: Optional[SeedMatcher] = None

    # Free-form notes for human readers / future contributors.
    notes: str = ""


@dataclass
class PlatformDetection:
    adapter: "PlatformAdapter"
    confidence: float
    reasons: list[str] = field(default_factory=list)


class PlatformAdapter(ABC):
    """Base class for platform adapters.

    Subclasses MUST set ``name`` and implement ``detect`` and
    ``applicable_queries``. Everything else has sensible defaults.
    """

    # Unique short identifier (snake_case). Used in logs, metadata, and the
    # client-facing report's per-finding "platform" field.
    name: str = ""

    # Human-readable label for the report.
    label: str = ""

    # File extensions this adapter cares about. Detection short-circuits to 0.0
    # for files with extensions outside this set, so adapters can stay cheap.
    file_extensions: tuple[str, ...] = ()

    @abstractmethod
    def detect(self, file_path: str, content: str) -> float:
        """Return confidence in [0.0, 1.0] that ``file_path`` targets this
        platform. ``content`` is the full file text.

        Use multiple corroborating signals (imports + macros + idioms) so
        that two distinct platforms sharing a language (e.g. Soroban vs
        Solana, both Rust) can be distinguished reliably.
        """

    @abstractmethod
    def applicable_queries(self) -> dict[str, QuerySpec]:
        """Map of Layer-5 query name → QuerySpec.

        Queries NOT in this map are skipped on this platform.
        """

    def codebase_signals(self) -> dict[str, str]:
        """Codebase-level facts the prompt should be aware of.

        Keys are short identifiers, values are one-line explanations of what
        the signal means and how it should affect triage. The pipeline turns
        this into an "Codebase signals" block in the Layer-5 prompt.
        """
        return {}

    def exploit_harness_kind(self) -> str:
        """Identifier for the Layer-4.5 exploit harness to use.

        Examples: "foundry", "soroban_test", "anchor_test", "pytest_httpx",
        "jest_supertest". Empty string disables Layer 4.5 for this platform.
        """
        return ""

    def severity_adjust(self, query_name: str, severity: str) -> str:
        """Apply this adapter's severity cap (if any) for the given query."""
        spec = self.applicable_queries().get(query_name)
        if spec and spec.severity_cap:
            return cap_severity(severity, spec.severity_cap)
        return severity


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_REGISTRY: list[PlatformAdapter] = []


def register(adapter: PlatformAdapter) -> PlatformAdapter:
    """Register an adapter. Idempotent on ``name``."""
    for existing in _REGISTRY:
        if existing.name == adapter.name:
            return existing
    _REGISTRY.append(adapter)
    return adapter


def all_adapters() -> list[PlatformAdapter]:
    return list(_REGISTRY)


def detect_for_file(file_path: str, content: str) -> list[PlatformDetection]:
    """Score every registered adapter against the file. Returns matches with
    confidence > 0, sorted by confidence descending.
    """
    out: list[PlatformDetection] = []
    for a in _REGISTRY:
        if a.file_extensions:
            ext = "." + file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
            if ext not in a.file_extensions:
                continue
        score = a.detect(file_path, content)
        if score > 0:
            out.append(PlatformDetection(adapter=a, confidence=score))
    out.sort(key=lambda d: -d.confidence)
    return out


def primary_for_file(file_path: str, content: str) -> Optional[PlatformAdapter]:
    """Single best adapter for a file, or None if nothing matches."""
    matches = detect_for_file(file_path, content)
    return matches[0].adapter if matches else None


def by_name(name: str) -> Optional[PlatformAdapter]:
    for a in _REGISTRY:
        if a.name == name:
            return a
    return None


def format_codebase_signals_block(adapter: PlatformAdapter) -> str:
    """Render the adapter's codebase signals as a markdown block for inclusion
    in the Layer-5 prompt. Returns empty string if the adapter has no signals.
    """
    signals = adapter.codebase_signals()
    if not signals:
        return ""
    lines = ["## Codebase signals (platform-specific)"]
    for name, desc in signals.items():
        lines.append(f"  - **{name}**: {desc}")
    return "\n".join(lines)
