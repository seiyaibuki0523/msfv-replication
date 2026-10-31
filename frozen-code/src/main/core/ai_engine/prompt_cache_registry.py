"""Persistent registry for Anthropic's ephemeral prompt cache.

Anthropic ``cache_control: ephemeral`` blocks survive for 5 minutes
(default) or 1 hour (when ``ttl: 1h`` is passed and the account is on
the tier that supports it). Across multiple ``aisec`` invocations or
``aisec serve`` worker processes we *can't* keep the cache hot just
by being smart in-process — but we *can* avoid paying for a re-warm
when the cache should still be hot upstream.

This module tracks: for each ``(model, system_prompt_hash)`` pair,
the wall-clock time of the last request that wrote / read it. The
pipeline consults the registry before calling ``_prewarm`` — if a
warmed cache key for this signature was used within ``TTL - safety_
margin`` seconds, prewarm is skipped (the parallel batch will see
cache hits anyway).

Storage: a single JSON file under ``<workspace>/cache/prompt_cache_
registry.json``. Lock-free reads / single-writer writes — the file
is small (≤ 1 KB typically) and the worst case on race is an extra
prewarm call.

Disable with ``AISEC_PROMPT_CACHE_REGISTRY=0``. TTL knob:
``AISEC_CACHE_TTL=5m | 1h`` (default 5m for safety).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #

# Safety margin: pretend the cache expires N seconds early so a request
# that fires "right at the edge" doesn't slip past the real expiry.
SAFETY_MARGIN_SEC = 30


def _ttl_seconds() -> int:
    """Parse ``AISEC_CACHE_TTL`` (e.g. ``5m`` / ``1h``). Default 5m
    matches Anthropic's free-tier ephemeral lifetime.
    """
    raw = (os.getenv("AISEC_CACHE_TTL", "5m") or "5m").strip().lower()
    try:
        if raw.endswith("h"):
            return int(float(raw[:-1]) * 3600)
        if raw.endswith("m"):
            return int(float(raw[:-1]) * 60)
        if raw.endswith("s"):
            return int(float(raw[:-1]))
        return int(raw)
    except (TypeError, ValueError):
        return 300


def ttl_seconds() -> int:
    return _ttl_seconds()


def ttl_marker() -> str | None:
    """The string Anthropic expects in ``cache_control.ttl``. Returns
    ``None`` when the configured TTL is the default 5 minutes — in
    that case we omit the marker entirely so old SDKs still work.
    """
    t = _ttl_seconds()
    if t >= 3000:               # 50+ minutes → use 1h marker
        return "1h"
    return None                  # default ephemeral (5m)


def is_enabled() -> bool:
    return os.getenv("AISEC_PROMPT_CACHE_REGISTRY", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }


# --------------------------------------------------------------------------- #
# Registry                                                                    #
# --------------------------------------------------------------------------- #

@dataclass
class CacheEntry:
    last_sent_at: float
    ttl_seconds: int
    model: str = ""
    signature: str = ""


class PromptCacheRegistry:
    """Per-workspace persistent cache-warm tracker."""

    def __init__(self, workspace: str | None = None):
        if workspace is None:
            try:
                from core.config import settings
                workspace = settings.WORKSPACE
            except Exception:
                workspace = "."
        cache_dir = os.path.join(workspace, "cache")
        os.makedirs(cache_dir, exist_ok=True)
        self.path = os.path.join(cache_dir, "prompt_cache_registry.json")
        self._lock = threading.Lock()
        self._entries: dict[str, CacheEntry] = {}
        self._load()

    # ---- I/O ---------------------------------------------------------- #

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except (OSError, json.JSONDecodeError):
            return
        for key, raw in (data.get("entries") or {}).items():
            try:
                self._entries[key] = CacheEntry(**raw)
            except (TypeError, ValueError):
                continue

    def _save(self) -> None:
        # Prune stale entries before writing so the file doesn't grow.
        now = time.time()
        self._entries = {
            k: e for k, e in self._entries.items()
            if now - e.last_sent_at < e.ttl_seconds + 600   # +10min buffer
        }
        payload = {
            "_schema_note": "managed by core.ai_engine.prompt_cache_registry",
            "entries": {k: e.__dict__ for k, e in self._entries.items()},
        }
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass

    # ---- Public API --------------------------------------------------- #

    @staticmethod
    def key_for(system_prompt: str, model: str = "") -> str:
        h = hashlib.sha256()
        h.update(model.encode("utf-8", errors="replace"))
        h.update(b"\x00")
        h.update((system_prompt or "").encode("utf-8", errors="replace"))
        return h.hexdigest()

    def is_warm(self, system_prompt: str, model: str = "") -> bool:
        """Returns True when the cache for this prompt should still
        survive at Anthropic. Conservative: respects ``SAFETY_MARGIN_SEC``.
        """
        if not is_enabled():
            return False
        key = self.key_for(system_prompt, model)
        with self._lock:
            entry = self._entries.get(key)
        if entry is None:
            return False
        age = time.time() - entry.last_sent_at
        return age < (entry.ttl_seconds - SAFETY_MARGIN_SEC)

    def record(
        self,
        system_prompt: str,
        *,
        model: str = "",
        signature: str = "",
        ttl: int | None = None,
    ) -> None:
        """Record that we just sent a request with this system prompt."""
        if not is_enabled():
            return
        key = self.key_for(system_prompt, model)
        ttl = ttl if ttl is not None else _ttl_seconds()
        with self._lock:
            self._entries[key] = CacheEntry(
                last_sent_at=time.time(),
                ttl_seconds=ttl,
                model=model,
                signature=signature,
            )
            self._save()

    def stats(self) -> dict:
        now = time.time()
        warm = sum(
            1 for e in self._entries.values()
            if now - e.last_sent_at < e.ttl_seconds - SAFETY_MARGIN_SEC
        )
        return {
            "enabled":     is_enabled(),
            "ttl_seconds": _ttl_seconds(),
            "total":       len(self._entries),
            "warm":        warm,
            "path":        self.path,
        }


# --------------------------------------------------------------------------- #
# Singleton helpers                                                           #
# --------------------------------------------------------------------------- #

_registry: PromptCacheRegistry | None = None
_registry_lock = threading.Lock()


def get_registry(workspace: str | None = None) -> PromptCacheRegistry:
    global _registry
    if _registry is not None:
        return _registry
    with _registry_lock:
        if _registry is None:
            _registry = PromptCacheRegistry(workspace=workspace)
        return _registry


def reset_registry_for_tests() -> None:
    global _registry
    with _registry_lock:
        _registry = None


__all__ = [
    "PromptCacheRegistry",
    "CacheEntry",
    "get_registry",
    "ttl_marker",
    "ttl_seconds",
    "is_enabled",
]
