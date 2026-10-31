"""
Hook system — register and trigger callbacks for security pipeline events.

Two registration paths:

1. **Python callables** — modules call ``hooks.register("on_finding", fn)``.
   Useful for in-process integrations.

2. **Shell commands** — declared in ``settings.json`` (``hooks`` section) or
   ``$AISEC_HOOKS_FILE``. JSON gets the event ``context`` piped to stdin.
   Useful for end users who want Slack/Jira/PagerDuty without writing Python.

Configuration example (``~/.aisec/hooks.json``)::

    {
        "on_finding": [
            {"when": "severity in ('high','critical')",
             "run": "curl -X POST $SLACK_WEBHOOK -d @-"}
        ],
        "on_scan_complete": [
            {"run": "python notify.py"}
        ],
        "on_cost_threshold": [
            {"when": "total_cost_usd >= 5.0",
             "run": "echo cost-cap-hit"}
        ]
    }

Supported events (informal contract):

    on_scan_start        → {target_id, mode, target}
    on_scan_complete     → {target_id, mode, findings, cost_usd}
    on_finding           → {finding}  (one fire per confirmed finding)
    on_critical_finding  → {finding}  (CVSS >= 9 or severity == 'critical')
    on_waf_blocked       → {target, payload, attempt}
    on_cost_threshold    → {total_cost_usd, threshold}
    pre_tool_execution   → {command, tool}     # may set context['cancel'] = True
    post_tool_execution  → {command, status, exit_code}
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

# --------------------------------------------------------------------------- #
#   Types                                                                     #
# --------------------------------------------------------------------------- #

HookFn = Callable[[dict], None]


@dataclass
class _ShellHook:
    """A hook backed by a shell command."""
    run: str
    when: str | None = None  # optional Python-eval gate over the context dict


@dataclass
class _Registry:
    python: dict[str, list[HookFn]] = field(default_factory=dict)
    shell: dict[str, list[_ShellHook]] = field(default_factory=dict)


_REGISTRY = _Registry()
_LOCK = threading.Lock()
_LOADED_FROM_DISK = False


# --------------------------------------------------------------------------- #
#   Public API                                                                #
# --------------------------------------------------------------------------- #

def register(event: str, handler: HookFn) -> None:
    """Register a Python callable for ``event``."""
    with _LOCK:
        _REGISTRY.python.setdefault(event, []).append(handler)


def trigger(event: str, context: dict | None = None) -> dict:
    """Fire all registered handlers for ``event``.

    Returns the (possibly mutated) ``context`` so callers can inspect e.g.
    ``context['cancel']`` from pre-execution hooks.
    """
    _ensure_loaded()
    ctx = dict(context or {})

    # Python hooks first — cheap, in-process, may mutate context
    for fn in _REGISTRY.python.get(event, []):
        try:
            fn(ctx)
        except Exception as exc:  # noqa: BLE001
            _safe_warn(f"[hooks] python handler for '{event}' raised: {exc}")

    # Shell hooks second — async-safe, never crash the pipeline
    for sh in _REGISTRY.shell.get(event, []):
        if sh.when and not _eval_when(sh.when, ctx):
            continue
        _run_shell(sh.run, ctx, event)

    return ctx


def reset() -> None:
    """Clear all registrations (mainly for tests)."""
    global _LOADED_FROM_DISK
    with _LOCK:
        _REGISTRY.python.clear()
        _REGISTRY.shell.clear()
        _LOADED_FROM_DISK = False


def load_from_file(path: str) -> int:
    """Load shell hooks from a JSON file. Returns count loaded."""
    if not os.path.isfile(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        _safe_warn(f"[hooks] failed to read {path}: {exc}")
        return 0

    loaded = 0
    with _LOCK:
        for event, entries in (data.get("hooks") or data).items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict) or "run" not in entry:
                    continue
                _REGISTRY.shell.setdefault(event, []).append(
                    _ShellHook(run=entry["run"], when=entry.get("when"))
                )
                loaded += 1
    return loaded


# --------------------------------------------------------------------------- #
#   Internals                                                                 #
# --------------------------------------------------------------------------- #

def _ensure_loaded() -> None:
    global _LOADED_FROM_DISK
    if _LOADED_FROM_DISK:
        return
    with _LOCK:
        if _LOADED_FROM_DISK:
            return
        _LOADED_FROM_DISK = True
    # Search order: env var → workspace → home
    candidates = [
        os.getenv("AISEC_HOOKS_FILE", ""),
        _workspace_hooks_path(),
        os.path.expanduser("~/.aisec/hooks.json"),
    ]
    for path in candidates:
        if path and load_from_file(path):
            break


def _workspace_hooks_path() -> str:
    try:
        from core.config import settings
        return os.path.join(settings.WORKSPACE, "hooks.json")
    except Exception:
        return ""


_SAFE_WHEN_NAMES = {
    "True": True, "False": False, "None": None,
    "abs": abs, "min": min, "max": max, "len": len,
    "int": int, "float": float, "str": str, "bool": bool,
}


def _eval_when(expr: str, ctx: dict) -> bool:
    """Evaluate a ``when`` predicate over the event context.

    Restricted to a small builtin allow-list — no imports, no attribute
    access on functions, no I/O. Raising counts as False.
    """
    try:
        return bool(eval(expr, {"__builtins__": _SAFE_WHEN_NAMES}, dict(ctx)))
    except Exception as exc:  # noqa: BLE001
        _safe_warn(f"[hooks] when='{expr}' eval failed: {exc}")
        return False


def _run_shell(cmd: str, ctx: dict, event: str) -> None:
    """Run a shell hook with the JSON context piped to stdin."""
    payload = json.dumps({"event": event, **ctx}, default=str)
    env = dict(os.environ, AISEC_HOOK_EVENT=event)
    try:
        subprocess.Popen(
            cmd,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
        ).communicate(input=payload.encode("utf-8"), timeout=15)
    except Exception as exc:  # noqa: BLE001
        _safe_warn(f"[hooks] shell hook '{cmd[:60]}...' failed: {exc}")


def _safe_warn(msg: str) -> None:
    try:
        from core.ui import tui
        tui.error(msg)
    except Exception:
        # TUI not yet initialised — fall back to stderr
        import sys
        print(msg, file=sys.stderr)
