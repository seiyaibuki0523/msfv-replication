"""HTTP client for the ClaudeVault FastAPI service.

The vault is exposed as a RESTful service (see d:/ClaudeVault/tools/api/).
Failures (server down, auth rejected, timeout) degrade gracefully to empty
results so vault outages never fail a scan.
"""

from __future__ import annotations

import threading
from typing import Any

import httpx


class VaultAPIClient:
    """Thin wrapper around ClaudeVault's REST API. Constructor never blocks."""

    def __init__(self, base_url: str, token: str = "", timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._client: httpx.Client | None = None
        self._unhealthy_logged = False

    # ------------------------------------------------------------------ #
    # Internal HTTP                                                      #
    # ------------------------------------------------------------------ #

    def _http(self) -> httpx.Client:
        if self._client is None:
            headers = {"Accept": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"
            self._client = httpx.Client(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._client

    def _get(self, path: str, **params) -> Any:
        try:
            r = self._http().get(path, params={k: v for k, v in params.items() if v is not None})
            if r.status_code >= 400:
                self._note_unhealthy(_describe_http_error("GET", path, r.status_code, self.token))
                return None
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            self._note_unhealthy(f"GET {path} failed: {type(e).__name__}")
            return None

    def _post(self, path: str, json_body: dict) -> Any:
        try:
            r = self._http().post(path, json=json_body)
            if r.status_code >= 400:
                self._note_unhealthy(_describe_http_error("POST", path, r.status_code, self.token))
                return None
            return r.json()
        except (httpx.HTTPError, ValueError) as e:
            self._note_unhealthy(f"POST {path} failed: {type(e).__name__}")
            return None

    def _note_unhealthy(self, msg: str) -> None:
        if self._unhealthy_logged:
            return
        self._unhealthy_logged = True
        try:
            from core.ui import tui
            tui.info(f"[Vault] degraded: {msg} (further failures suppressed)")
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Endpoints                                                          #
    # ------------------------------------------------------------------ #

    def health(self) -> dict | None:
        return self._get("/v1/health")

    def search(self, q: str, *, limit: int = 10) -> list[dict]:
        result = self._get("/v1/search", q=q, limit=limit)
        return result if isinstance(result, list) else []

    def semantic_search(
        self,
        query: str,
        *,
        k: int = 10,
        note_type: str | None = None,
        domain: str | None = None,
    ) -> list[dict]:
        body = {"query": query, "k": k}
        if note_type:
            body["note_type"] = note_type
        if domain:
            body["domain"] = domain
        result = self._post("/v1/semantic-search", body)
        return result if isinstance(result, list) else []

    def context_bundle(
        self,
        target_description: str,
        *,
        domain: str | None = None,
        stack: dict | None = None,
        k_patterns: int = 15,
        k_cves: int = 10,
        k_techniques: int = 10,
        k_chains: int = 5,
    ) -> dict | None:
        body: dict[str, Any] = {
            "target_description": target_description,
            "k_patterns": k_patterns,
            "k_cves": k_cves,
            "k_techniques": k_techniques,
            "k_chains": k_chains,
        }
        if domain:
            body["domain"] = domain
        if stack:
            body["stack"] = stack
        return self._post("/v1/context-bundle", body)

    def get_note(self, identifier: str) -> dict | None:
        return self._get(f"/v1/notes/{identifier}")

    def get_related(self, identifier: str) -> dict | None:
        return self._get(f"/v1/notes/{identifier}/related")

    def list_patterns(self, *, domain: str | None = None, limit: int = 200) -> list[dict]:
        result = self._get("/v1/patterns", domain=domain, limit=limit)
        return result if isinstance(result, list) else []

    def list_cves(
        self,
        *,
        domain: str | None = None,
        severity: str | None = None,
        since: str | None = None,
        min_loss: int | None = None,
        limit: int = 200,
    ) -> list[dict]:
        result = self._get(
            "/v1/cve",
            domain=domain,
            severity=severity,
            since=since,
            min_loss=min_loss,
            limit=limit,
        )
        return result if isinstance(result, list) else []


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _describe_http_error(method: str, path: str, status: int, token: str) -> str:
    if status in (401, 403):
        if not token:
            return f"{method} {path} → {status} (no VAULT_API_TOKEN set; API requires auth)"
        return f"{method} {path} → {status} (token rejected — check VAULT_API_TOKEN)"
    if status == 503:
        return f"{method} {path} → 503 (service unavailable; embeddings may not be built)"
    return f"{method} {path} → {status}"


# --------------------------------------------------------------------------- #
# Module-level singleton                                                      #
# --------------------------------------------------------------------------- #

_singleton: VaultAPIClient | None = None
_singleton_lock = threading.Lock()


def get_client() -> VaultAPIClient | None:
    """Return the shared client, or None when no API is configured."""
    global _singleton
    if _singleton is not None:
        return _singleton

    with _singleton_lock:
        if _singleton is not None:
            return _singleton

        from core.config import settings

        if not settings.VAULT_API_URL:
            return None

        _singleton = VaultAPIClient(
            base_url=settings.VAULT_API_URL,
            token=settings.VAULT_API_TOKEN,
            timeout=settings.VAULT_API_TIMEOUT,
        )
        return _singleton


def reset_client_for_tests() -> None:
    global _singleton
    with _singleton_lock:
        if _singleton is not None and _singleton._client is not None:
            try:
                _singleton._client.close()
            except Exception:
                pass
        _singleton = None
