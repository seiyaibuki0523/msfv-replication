"""Public vault query API — thin wrapper around the FastAPI service.

Layer 4 / Layer 5 / AutoSecAgent reach the vault through these helpers, not
through the raw HTTP client. Returning empty lists/None on any failure keeps
vault outages invisible to the rest of the pipeline.

``read()`` is wrapped in a small TTL cache so repeated reads of the same
note within a scan don't hammer the API. TTL defaults to 60s; set
``AISEC_VAULT_READ_CACHE_TTL=0`` to disable. Cache is process-local and
resets on each scan invocation.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass

from core.vault.client import get_client


# --------------------------------------------------------------------------- #
# Read cache (TTL-bound, thread-safe)                                         #
# --------------------------------------------------------------------------- #

_READ_CACHE_TTL = float(os.getenv("AISEC_VAULT_READ_CACHE_TTL", "60.0"))
_READ_CACHE_MAX = 256
_read_cache: dict[str, tuple[float, "VaultNote | None"]] = {}
_read_cache_lock = threading.Lock()


def _cache_get(key: str) -> "VaultNote | None | _Sentinel":
    """Return the cached note, ``None`` if cached as a miss, or
    ``_MISS`` if the entry is absent or expired.
    """
    if _READ_CACHE_TTL <= 0:
        return _MISS
    now = time.monotonic()
    with _read_cache_lock:
        entry = _read_cache.get(key)
        if entry is None:
            return _MISS
        ts, note = entry
        if now - ts > _READ_CACHE_TTL:
            _read_cache.pop(key, None)
            return _MISS
        return note


def _cache_set(key: str, note: "VaultNote | None") -> None:
    if _READ_CACHE_TTL <= 0:
        return
    now = time.monotonic()
    with _read_cache_lock:
        if len(_read_cache) >= _READ_CACHE_MAX:
            # Cheap eviction: drop a quarter of the oldest entries
            keep = _READ_CACHE_MAX - (_READ_CACHE_MAX // 4)
            sorted_keys = sorted(_read_cache, key=lambda k: _read_cache[k][0])
            for stale in sorted_keys[:-keep]:
                _read_cache.pop(stale, None)
        _read_cache[key] = (now, note)


def clear_read_cache() -> None:
    """Public hook for callers (e.g. CLI ``aisec vault refresh``) to flush."""
    with _read_cache_lock:
        _read_cache.clear()


class _Sentinel:
    """Marker for `cache miss vs. cached-as-None`."""
    __slots__ = ()


_MISS = _Sentinel()


# --------------------------------------------------------------------------- #
# Result types — kept stable so prompts.py / pipeline.py don't churn          #
# --------------------------------------------------------------------------- #

@dataclass
class VaultSearchResult:
    path: str
    title: str
    note_type: str
    domain: str
    severity: str
    tags: list[str]
    score: float                     # higher = more relevant for semantic; 0 for keyword
    snippet: str = ""


@dataclass
class VaultNote:
    path: str
    title: str
    note_type: str
    domain: str
    severity: str
    tags: list[str]
    body: str


@dataclass
class VaultContextBundle:
    """Pre-engagement bundle from /v1/context-bundle."""
    query: str
    patterns: list[VaultSearchResult]
    cves: list[VaultSearchResult]
    techniques: list[VaultSearchResult]
    chains: list[VaultSearchResult]
    mental_models: list[VaultSearchResult]
    audit_walk: list[str]


# --------------------------------------------------------------------------- #
# Top-level helpers                                                           #
# --------------------------------------------------------------------------- #

def available() -> bool:
    """True when a vault API is configured and reachable."""
    client = get_client()
    if client is None:
        return False
    return client.health() is not None


def search(query: str, *, k: int = 10) -> list[VaultSearchResult]:
    """Keyword search via /v1/search (LIKE-based)."""
    client = get_client()
    if client is None or not query.strip():
        return []
    rows = client.search(query, limit=k)
    return [_row_to_result(r) for r in rows]


def semantic(
    query: str,
    *,
    k: int = 10,
    note_type: str | None = None,
    domain: str | None = None,
) -> list[VaultSearchResult]:
    """Semantic search via /v1/semantic-search (sentence-transformer embeddings)."""
    client = get_client()
    if client is None or not query.strip():
        return []
    hits = client.semantic_search(query, k=k, note_type=note_type, domain=domain)
    return [_hit_to_result(h) for h in hits]


def read(identifier: str) -> VaultNote | None:
    """Fetch a single note by stem, path, or wikilink target.

    Results are cached for ``AISEC_VAULT_READ_CACHE_TTL`` seconds (default
    60). The same scan typically inlines the same patterns into many L4
    findings; the cache turns those repeats into local lookups instead
    of HTTP round-trips.
    """
    client = get_client()
    if client is None:
        return None
    needle = _identifier_to_stem(identifier)
    if not needle:
        return None

    cached = _cache_get(needle)
    if cached is not _MISS:
        return cached  # type: ignore[return-value]

    row = client.get_note(needle)
    if not row:
        _cache_set(needle, None)
        return None
    note = VaultNote(
        path=row.get("path", ""),
        title=row.get("title", "") or row.get("stem", ""),
        note_type=row.get("note_type", ""),
        domain=row.get("domain", "") or "",
        severity=row.get("severity", "") or "",
        tags=list(row.get("tags") or []),
        body=row.get("body", "") or "",
    )
    _cache_set(needle, note)
    return note


def related(identifier: str) -> list[dict]:
    """Wikilink graph neighbours.

    Each entry: {path, title, via} where via is 'outbound' or 'inbound'.
    """
    client = get_client()
    if client is None:
        return []
    needle = _identifier_to_stem(identifier)
    if not needle:
        return []
    payload = client.get_related(needle)
    if not payload:
        return []

    out: list[dict] = []
    for direction in ("outbound", "inbound"):
        for o in payload.get(direction, []) or []:
            path = o.get("path") or ""
            title = o.get("title") or ""
            if not (path or title):
                continue
            out.append({
                "path": path,
                "title": title,
                "via": direction,
                "field": o.get("field") or "",
            })
    return out


# --------------------------------------------------------------------------- #
# Layer-specific helpers                                                      #
# --------------------------------------------------------------------------- #

def hint_for_finding(
    finding: dict,
    *,
    lang_hint: str = "",
    k: int = 8,
) -> list[VaultSearchResult]:
    """Layer 4 — semantic search for vault notes relevant to a single finding."""
    if not _api_configured():
        return []

    query = _finding_to_query(finding, lang_hint)
    if not query:
        return []
    domain = _infer_domain(lang_hint, str(finding.get("file", "")), str(finding.get("rule_id", "")))

    hits = semantic(query, k=k, domain=domain or None)
    if hits:
        return hits
    return semantic(query, k=k)


def hint_for_recon(
    recon_summary: str,
    target_description: str,
    *,
    k_patterns: int = 6,
    k_cves: int = 4,
    k_techniques: int = 6,
    k_chains: int = 3,
) -> VaultContextBundle | None:
    """AutoSecAgent — fetch a full context bundle for a target via /v1/context-bundle."""
    client = get_client()
    if client is None:
        return None

    description = (target_description.strip() + "\n\n" + recon_summary.strip()).strip()
    if not description:
        return None

    payload = client.context_bundle(
        description,
        k_patterns=k_patterns,
        k_cves=k_cves,
        k_techniques=k_techniques,
        k_chains=k_chains,
    )
    if not payload:
        return None

    return VaultContextBundle(
        query=payload.get("query", description),
        patterns=[_hit_to_result(h) for h in payload.get("patterns", [])],
        cves=[_hit_to_result(h) for h in payload.get("cves", [])],
        techniques=[_hit_to_result(h) for h in payload.get("techniques", [])],
        chains=[_hit_to_result(h) for h in payload.get("chains", [])],
        mental_models=[_hit_to_result(h) for h in payload.get("mental_models", [])],
        audit_walk=list(payload.get("audit_walk", [])),
    )


def patterns_for_query(query_name: str, *, k: int = 5) -> list[VaultNote]:
    """Layer 5 — fetch full pattern bodies relevant to a global query topic."""
    if not _api_configured():
        return []

    topic = _QUERY_TO_TOPIC.get(query_name) or _split_query_name(query_name)
    if not topic:
        return []

    hits = semantic(topic, k=k, note_type="pattern")
    notes: list[VaultNote] = []
    for hit in hits:
        note = read(hit.path)
        if note and note.body:
            notes.append(note)
    return notes


# --------------------------------------------------------------------------- #
# Internal                                                                    #
# --------------------------------------------------------------------------- #

def _identifier_to_stem(identifier: str) -> str:
    """Normalise a path / wikilink / bare stem into the stem form the API expects."""
    raw = identifier.strip().strip("[]")
    if not raw:
        return ""
    if "|" in raw:
        raw = raw.split("|", 1)[0].strip()
    if "/" in raw or "\\" in raw:
        raw = raw.replace("\\", "/").rsplit("/", 1)[-1]
    if raw.lower().endswith(".md"):
        raw = raw[:-3]
    return raw


_QUERY_TO_TOPIC: dict[str, str] = {
    "reentrancy_check": "reentrancy vulnerability external call before state update",
    "access_control_gaps": "missing access control authorization gap public state-modifying function",
    "flash_loan_exposure": "flash loan price oracle manipulation single-block spot price",
    "trust_boundary_violations": "trust boundary unchecked external call return value",
}


def _split_query_name(query_name: str) -> str:
    return " ".join(p for p in re.split(r"[_\-]", query_name) if len(p) > 2)


_KEYWORD_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{2,}")
_STOPWORDS = {
    "the", "and", "for", "with", "this", "that", "from", "into",
    "have", "are", "was", "were", "use", "uses", "using", "should",
    "must", "may", "any", "all", "not", "but", "out", "via", "per",
    "function", "method", "class", "module", "file", "line", "code",
    "rule", "found", "finding", "audit", "scan", "check", "test",
}


def _finding_to_query(finding: dict, lang_hint: str) -> str:
    parts = [
        str(finding.get("rule_id", "")),
        str(finding.get("message", "")),
        str(finding.get("code", ""))[:600],
    ]
    if lang_hint:
        parts.append(lang_hint)
    raw = " ".join(p for p in parts if p)
    if not raw.strip():
        return ""

    tokens = []
    seen = set()
    for tok in _KEYWORD_TOKEN_RE.findall(raw):
        t = tok.lower()
        if t in _STOPWORDS or t in seen or len(t) < 3:
            continue
        seen.add(t)
        tokens.append(tok)
        if len(tokens) >= 18:
            break
    return " ".join(tokens)


_TECH_TO_DOMAIN = [
    (re.compile(r"\b(?:solidity|sol|evm|ethereum|defi|erc20|erc721|vyper|move|cairo|soroban)\b", re.I), "web3"),
    (re.compile(r"\b(?:xss|csrf|sqli|ssrf|jsonp|cors|xxe|graphql)\b", re.I), "web2"),
    (re.compile(r"\b(?:gadget|rop|heap|pwn|kernel|stack)\b", re.I), "pwn"),
    (re.compile(r"\b(?:github|gitlab|gha|workflow|circleci|jenkins)\b", re.I), "cicd"),
    (re.compile(r"\b(?:aws|gcp|azure|s3|lambda|kms|iam)\b", re.I), "cloud"),
    (re.compile(r"\b(?:rsa|ecdsa|aes|sha|ecc|crypto|nonce)\b", re.I), "crypto"),
]

_EXT_TO_DOMAIN = {
    "sol": "web3", "vy": "web3", "rs": "web3", "move": "web3", "cairo": "web3",
    "js": "web2", "ts": "web2", "jsx": "web2", "tsx": "web2",
    "py": "web2", "go": "web2", "java": "web2", "php": "web2", "rb": "web2",
    "c": "pwn", "cpp": "pwn", "h": "pwn", "hpp": "pwn",
}


def _infer_domain(lang_hint: str, file_path: str, rule_id: str) -> str:
    blob = " ".join([lang_hint, file_path, rule_id])
    for pattern, dom in _TECH_TO_DOMAIN:
        if pattern.search(blob):
            return dom
    if "." in file_path:
        ext = file_path.rsplit(".", 1)[-1].lower()
        if ext in _EXT_TO_DOMAIN:
            return _EXT_TO_DOMAIN[ext]
    return ""


def _api_configured() -> bool:
    return get_client() is not None


def _row_to_result(row: dict) -> VaultSearchResult:
    return VaultSearchResult(
        path=row.get("path", ""),
        title=row.get("title", "") or row.get("stem", ""),
        note_type=row.get("note_type", ""),
        domain=row.get("domain", "") or "",
        severity=row.get("severity", "") or "",
        tags=list(row.get("tags") or []),
        score=0.0,
        snippet="",
    )


def _hit_to_result(hit: dict) -> VaultSearchResult:
    return VaultSearchResult(
        path=hit.get("path", ""),
        title=hit.get("title", "") or hit.get("stem", ""),
        note_type=hit.get("note_type", ""),
        domain=hit.get("domain", "") or "",
        severity=hit.get("severity", "") or "",
        tags=list(hit.get("tags") or []),
        score=float(hit.get("score", 0.0)),
        snippet="",
    )
