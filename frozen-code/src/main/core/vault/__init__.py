"""
Vault — queryable knowledge base over the ClaudeVault FastAPI service.

When ``VAULT_API_URL`` is set, AISecTool reaches into the ClaudeVault REST
API for keyword + semantic search, single-note read, related-note traversal,
and pre-engagement context bundles. Layer 4 and Layer 5 inject hints/patterns
into Opus prompts via ``core.vault.prompts``; AutoSecAgent fetches a full
``/v1/context-bundle`` once at recon time.

When the API is unset or unreachable, every entry point returns a no-op
(empty list / None / empty string) so the rest of AISecTool keeps running.
"""

from __future__ import annotations

from core.vault.search import (
    VaultContextBundle,
    VaultNote,
    VaultSearchResult,
    available,
    hint_for_finding,
    hint_for_recon,
    patterns_for_query,
    read,
    related,
    search,
    semantic,
)

__all__ = [
    "VaultContextBundle",
    "VaultNote",
    "VaultSearchResult",
    "available",
    "hint_for_finding",
    "hint_for_recon",
    "patterns_for_query",
    "read",
    "related",
    "search",
    "semantic",
]
