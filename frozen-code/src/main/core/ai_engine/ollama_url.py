"""Resolve the Ollama base URL with WSL + VPN escape hatches.

WSL2's *mirrored* networking lets the WSL guest reach Windows-side
services on ``localhost``. But once a VPN client (Cisco AnyConnect,
Tailscale, OpenVPN with default route) takes over the host's routing
table, mirrored mode breaks: ``localhost:11434`` inside WSL either
hangs or returns ``connection refused``, and the user has to talk to
Windows-side Ollama via the *Windows host's LAN IP* instead.

Resolution order (most-specific wins):

  1. ``OLLAMA_URL``                — explicit override, used verbatim.
  2. ``AISEC_OLLAMA_USE_WIN_IP=1`` + ``WIN_IP`` set
     → returns ``http://$WIN_IP:11434``. Manual switch.
  3. Auto-detect: in WSL, ``WIN_IP`` set, and ``localhost:11434``
     does not respond within ``AISEC_OLLAMA_PROBE_MS`` (default 250ms)
     → returns ``http://$WIN_IP:11434``.
  4. Fallback:                    ``http://localhost:11434``.

Env knobs:

    OLLAMA_URL                     full URL override (wins everything)
    AISEC_OLLAMA_USE_WIN_IP=1      force WIN_IP path
    AISEC_OLLAMA_USE_WIN_IP=0      force localhost path (skip auto-detect)
    AISEC_OLLAMA_PROBE_MS=250      auto-detect probe timeout (ms)
    WIN_IP=192.168.x.y             Windows host IP from WSL's PoV

The resolver is process-cached (auto-detect probe happens once),
re-importable via ``reset_for_tests()``.
"""

from __future__ import annotations

import os
import socket
import threading


# --------------------------------------------------------------------------- #
# Cache                                                                       #
# --------------------------------------------------------------------------- #

_cached_url: str | None = None
_cache_lock = threading.Lock()


def reset_for_tests() -> None:
    """Clear the per-process cache. Used by smoke tests."""
    global _cached_url
    with _cache_lock:
        _cached_url = None


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #

def _is_wsl() -> bool:
    """True when running inside Windows Subsystem for Linux."""
    if not os.path.exists("/proc/version"):
        return False
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="ignore") as f:
            return "microsoft" in f.read().lower()
    except OSError:
        return False


def _probe_ms() -> int:
    raw = os.getenv("AISEC_OLLAMA_PROBE_MS", "250")
    try:
        return max(50, min(5000, int(raw)))
    except (TypeError, ValueError):
        return 250


def _is_reachable(host: str, port: int, timeout_ms: int) -> bool:
    """Cheap TCP connect probe. No HTTP semantics — just whether the
    port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout_ms / 1000.0):
            return True
    except (OSError, socket.timeout):
        return False


# --------------------------------------------------------------------------- #
# Resolver                                                                    #
# --------------------------------------------------------------------------- #

def resolve() -> str:
    """Return the Ollama base URL to use right now. Cached per process."""
    global _cached_url
    if _cached_url is not None:
        return _cached_url

    with _cache_lock:
        if _cached_url is not None:
            return _cached_url

        url = _resolve_uncached()
        _cached_url = url.rstrip("/")
        return _cached_url


def _resolve_uncached() -> str:
    # 1. Explicit override
    explicit = (os.getenv("OLLAMA_URL") or "").strip()
    if explicit:
        return explicit

    win_ip = (os.getenv("WIN_IP") or "").strip()
    use_win_ip = (os.getenv("AISEC_OLLAMA_USE_WIN_IP") or "").strip().lower()

    # 2. Manual switch — force one side
    if use_win_ip in {"1", "true", "yes", "on"}:
        if win_ip:
            return f"http://{win_ip}:11434"
        # Asked for WIN_IP path but no WIN_IP set — fall through to local.
    if use_win_ip in {"0", "false", "no", "off"}:
        return "http://localhost:11434"

    # 3. Auto-detect — only in WSL, only when WIN_IP is configured
    if _is_wsl() and win_ip:
        timeout = _probe_ms()
        if not _is_reachable("127.0.0.1", 11434, timeout):
            # Localhost dead — try the Windows host. If that's also dead
            # we still return it so the caller's error message points at
            # something useful (not "localhost refused" when the user is
            # clearly on VPN).
            return f"http://{win_ip}:11434"

    # 4. Default
    return "http://localhost:11434"


# --------------------------------------------------------------------------- #
# Diagnostics                                                                 #
# --------------------------------------------------------------------------- #

def describe() -> dict:
    """Return a debug snapshot — used by the dashboard's settings card
    and by the CLI for a quick ``aisec ollama-where`` style command.
    """
    win_ip = os.getenv("WIN_IP") or ""
    return {
        "url":               resolve(),
        "explicit_env":      bool(os.getenv("OLLAMA_URL")),
        "is_wsl":            _is_wsl(),
        "win_ip":            win_ip,
        "use_win_ip_env":    os.getenv("AISEC_OLLAMA_USE_WIN_IP") or "",
        "probe_ms":          _probe_ms(),
        "localhost_reachable": _is_reachable("127.0.0.1", 11434, _probe_ms()),
        "win_ip_reachable":  _is_reachable(win_ip, 11434, _probe_ms()) if win_ip else False,
    }


__all__ = ["resolve", "describe", "reset_for_tests"]
