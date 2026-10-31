"""Content-addressed cache for Layer 4 / 5 / 5.5 Opus results.

Same prompt → same answer. We hash the exact text we'd send to Opus,
look it up in ``<workspace>/cache/findings/<sha>.json``, and skip the
API call on a hit. A miss runs Opus normally and stores the answer.

Why this is safe to enable by default:

* The hash includes the entire prompt text. Any change to the source
  code, global map, vault hint, skill context, or signature wording
  perturbs the hash → cache miss → fresh call.
* The cache is per-workspace. Different repos / different scans on the
  same machine never collide because they sit under different
  workspaces.
* Wipe with ``rm -rf <workspace>/cache`` whenever you want a clean run.

Cost picture: a cache hit returns in ~1ms and skips a ~$0.03–$0.10 Opus
call. On a re-scan of an unchanged repo, hit rate is effectively 100%
for the layers that touch unchanged code; on a re-scan after edits,
only the touched code regenerates.

Disable with ``AISEC_RESULT_CACHE=0``.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------- #
# Hashing                                                                     #
# --------------------------------------------------------------------------- #

def _hash_prompt(layer: str, prompt_text: str) -> str:
    h = hashlib.sha256()
    # Layer prefix prevents accidental cross-layer collisions if two
    # layers ever produce identical prompt text by coincidence.
    h.update(layer.encode("utf-8", errors="replace"))
    h.update(b"\x00")
    h.update(prompt_text.encode("utf-8", errors="replace"))
    return h.hexdigest()


# --------------------------------------------------------------------------- #
# Cache storage                                                               #
# --------------------------------------------------------------------------- #

@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    writes: int = 0
    # Estimated dollars saved by hits. We bill 0.0 for the actual call
    # since we don't have the live LM here; the caller passes the
    # avoided token counts on store, and we credit them on hit.
    saved_prompt_tokens: int = 0
    saved_completion_tokens: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "writes": self.writes,
            "saved_prompt_tokens": self.saved_prompt_tokens,
            "saved_completion_tokens": self.saved_completion_tokens,
        }


class ResultCache:
    """A simple per-workspace file cache."""

    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.stats = CacheStats()

    def _path(self, key: str) -> str:
        return os.path.join(self.root, key + ".json")

    def lookup(self, layer: str, prompt_text: str) -> dict | None:
        key = _hash_prompt(layer, prompt_text)
        path = self._path(key)
        if not os.path.exists(path):
            with self.stats._lock:
                self.stats.misses += 1
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            # Corrupted cache entry — treat as a miss; the next store
            # overwrites it.
            with self.stats._lock:
                self.stats.misses += 1
            return None
        with self.stats._lock:
            self.stats.hits += 1
            self.stats.saved_prompt_tokens += int(data.get("prompt_tokens") or 0)
            self.stats.saved_completion_tokens += int(data.get("completion_tokens") or 0)
        return data

    def store(
        self,
        layer: str,
        prompt_text: str,
        result: dict,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
    ) -> str:
        key = _hash_prompt(layer, prompt_text)
        payload = {
            "layer": layer,
            "result": result,
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            "stored_at": int(time.time()),
        }
        # Best-effort: write to a temp file and atomically rename so a
        # crashed scan can never leave a half-written JSON behind.
        tmp = self._path(key) + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self._path(key))
        except OSError:
            try:
                os.remove(tmp)
            except OSError:
                pass
            return key
        with self.stats._lock:
            self.stats.writes += 1
        return key


# --------------------------------------------------------------------------- #
# Module-level singleton                                                      #
# --------------------------------------------------------------------------- #

_cache: ResultCache | None = None
_cache_lock = threading.Lock()


def _is_enabled() -> bool:
    v = os.getenv("AISEC_RESULT_CACHE", "1").strip().lower()
    return v not in {"0", "false", "no", "off"}


def get_cache(workspace: str | None = None) -> ResultCache | None:
    """Return the global cache. Lazily creates it under the workspace.

    Returns ``None`` when caching is disabled, so callers can short-circuit
    with ``cache := get_cache(...); cache and cache.lookup(...)`` without
    needing a feature flag check at every call site.
    """
    if not _is_enabled():
        return None
    global _cache
    if _cache is not None:
        return _cache
    if not workspace:
        try:
            from core.config import settings  # local import — avoid cycles
            workspace = settings.WORKSPACE
        except Exception:
            workspace = "."
    root = os.path.join(workspace, "cache", "findings")
    with _cache_lock:
        if _cache is None:
            _cache = ResultCache(root)
    return _cache


def reset_cache() -> None:
    """Test hook — forget the singleton so the next get_cache rebuilds it."""
    global _cache
    with _cache_lock:
        _cache = None
