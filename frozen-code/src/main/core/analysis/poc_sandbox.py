"""Ephemeral-container PoC execution engine (Layer 4.5, multi-language).

Runs an LLM-emitted *execution recipe* inside a throwaway, network-less
container and destroys it. The container is the isolation boundary, so the
generated build/run commands cannot touch the host, the network, or survive
the run.

Recipe shape (produced by ``poc_generator.PocGenerator``)::

    {
      "files": [{"name": "poc.cpp", "content": "..."}],
      "build_cmd": "g++ -fsanitize=address,undefined -g -o poc poc.cpp",  # "" if none
      "run_cmd":   "./poc",
      "trigger_on": "sanitizer_report" | "marker" | "nonzero_exit",
      "assert_marker": "PWNED_<uuid>",
      "poc_method": "cpp-asan" | "pytest" | "node" | "gotest" | "rustc" | ...
    }

Returns the SAME validation dict shape forge produces, so Layer 5.5 verify
needs no changes::

    {poc_compile, poc_triggers_bug, fuzz_confirms, counterexample,
     ground_truth_confidence, error, poc_method}

Hardening (per the container-isolation requirement):
  * ``--network none``         — no network, full stop.
  * ``--rm`` + unique ``--name`` + kill-on-timeout — no surviving container.
  * ``--read-only`` rootfs, single writable bind mount ``/poc`` (the tmpdir).
  * ``--memory`` / ``--cpus`` / ``--pids-limit`` — no fork bomb / OOM.
  * tmpdir ``rmtree`` in ``finally`` — no leftover files on the host.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field


# Sanitizer / runtime-fault signatures that prove a memory-safety bug actually
# fired at runtime (the strongest ground truth we can get for C/C++/Rust/Go).
_SANITIZER_SIGNATURES = (
    "AddressSanitizer", "addresssanitizer",
    "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
    "heap-use-after-free", "use-after-free", "use-after-return",
    "attempting double-free", "double free", "double-free",
    "UndefinedBehaviorSanitizer", "runtime error:",
    "SUMMARY: AddressSanitizer", "SUMMARY: UndefinedBehaviorSanitizer",
    "ThreadSanitizer", "data race", "WARNING: DATA RACE",
    "LeakSanitizer", "detected memory leaks",
    "Segmentation fault", "SIGSEGV", "panicked at",
)


@dataclass
class SandboxConfig:
    image: str = field(
        default_factory=lambda: os.getenv(
            "AISEC_POC_SANDBOX_IMAGE", "cevanex/poc-sandbox:1"
        )
    )
    timeout_seconds: int = 90
    memory: str = "512m"
    cpus: str = "1"
    pids_limit: int = 256
    tmpfs_size: str = "64m"


class PocSandbox:
    """Runs execution recipes in ephemeral containers. Zero LLM cost here —
    the recipe is generated upstream by ``PocGenerator``."""

    # Recipe filename guard: simple basenames only — no path traversal, no
    # absolute paths. The container would contain an escape anyway, but a
    # malformed name (``../../etc/x``) would write into the host tmpdir parent
    # before the mount, so reject it early.
    _SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")

    def __init__(self, config: SandboxConfig | None = None):
        self.config = config or SandboxConfig()
        self._docker_ok: bool | None = None

    # ── Availability ─────────────────────────────────────────────────

    def is_available(self) -> bool:
        """True only when the docker daemon answers AND the sandbox image is
        present. A missing daemon/image makes Layer 4.5 fall back to
        source-only verify (same contract as forge-absent)."""
        if self._docker_ok is not None:
            return self._docker_ok
        if os.getenv("AISEC_POC_NO_EXEC", "0") == "1":
            self._docker_ok = False
            return False
        try:
            ping = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=10,
            )
            if ping.returncode != 0:
                self._docker_ok = False
                return False
            img = subprocess.run(
                ["docker", "image", "inspect", self.config.image],
                capture_output=True, text=True, timeout=10,
            )
            self._docker_ok = img.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            self._docker_ok = False
        return self._docker_ok

    # ── Entry point ──────────────────────────────────────────────────

    def run_recipe(self, recipe: dict) -> dict:
        """Materialize the recipe in a fresh tmpdir, run it in an ephemeral
        container, parse the verdict. Always returns a validation dict."""
        method = recipe.get("poc_method", "container")
        files = recipe.get("files") or []
        if not files:
            return self._fail("recipe had no files", method=method)
        for f in files:
            name = f.get("name", "")
            if not self._SAFE_NAME.match(name):
                return self._fail(f"unsafe recipe filename: {name!r}",
                                  method=method)

        build_cmd = (recipe.get("build_cmd") or "").strip()
        run_cmd = (recipe.get("run_cmd") or "").strip()
        if not run_cmd:
            return self._fail("recipe had no run_cmd", method=method)
        trigger_on = recipe.get("trigger_on", "nonzero_exit")
        marker = recipe.get("assert_marker", "")

        workdir = tempfile.mkdtemp(prefix="poc_sbx_")
        container = f"poc_{uuid.uuid4().hex[:12]}"
        try:
            for f in files:
                with open(os.path.join(workdir, f["name"]), "w",
                          encoding="utf-8") as fh:
                    fh.write(f.get("content", ""))

            shell = f"{build_cmd} && {run_cmd}" if build_cmd else run_cmd
            cmd = [
                "docker", "run", "--rm", "--name", container,
                "--network", "none",
                "--memory", self.config.memory,
                "--cpus", self.config.cpus,
                "--pids-limit", str(self.config.pids_limit),
                "--read-only",
                "--tmpfs", f"/tmp:size={self.config.tmpfs_size}",
                "-v", f"{workdir}:/poc:rw",
                "-w", "/poc",
                self.config.image,
                "sh", "-c", shell,
            ]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=self.config.timeout_seconds,
                )
            except subprocess.TimeoutExpired:
                # Container may still be alive — kill it so nothing lingers.
                subprocess.run(["docker", "kill", container],
                               capture_output=True, timeout=10)
                return self._fail("PoC execution timed out", method=method)

            out = (proc.stdout or "") + (proc.stderr or "")

            # Build failure: distinguishable only when there IS a build step.
            # forge/compile-class "no ground truth" → poc_compile False.
            if build_cmd and _looks_like_build_failure(out, proc.returncode):
                return self._fail("PoC failed to build",
                                  error=out[-300:], method=method)

            triggered = self._parse_trigger(
                out, proc.returncode, trigger_on, marker,
            )
            if triggered is True:
                # Sanitizer-confirmed memory faults are runtime proof → 0.95.
                conf = 0.95 if trigger_on == "sanitizer_report" else 0.90
            elif triggered is False:
                conf = 0.10
            else:
                conf = 0.30

            return {
                "poc_compile": True,
                "poc_triggers_bug": triggered,
                "fuzz_confirms": None,
                "counterexample": _first_signature(out) if triggered else None,
                "ground_truth_confidence": conf,
                "error": None,
                "poc_method": method,
            }
        except Exception as e:  # noqa: BLE001
            return self._fail("PoC sandbox crashed", error=str(e)[:300],
                              method=method)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    # ── Verdict parsing ──────────────────────────────────────────────

    @staticmethod
    def _parse_trigger(
        output: str, returncode: int, trigger_on: str, marker: str,
    ) -> bool | None:
        """Map runner output → triggered (True/False/None) per the recipe's
        declared oracle."""
        if trigger_on == "sanitizer_report":
            if any(sig in output for sig in _SANITIZER_SIGNATURES):
                return True
            # clean run, no sanitizer fault → exploit did not fire
            return False if returncode == 0 else None
        if trigger_on == "marker":
            if marker and marker in output:
                return True
            return False
        if trigger_on == "nonzero_exit":
            # The PoC asserts the exploit and exits non-zero when it fires
            # (assert/raise/panic). A clean exit 0 = exploit did not fire.
            if marker and marker in output:
                return True
            return returncode != 0
        # Unknown oracle — be conservative.
        return None

    @staticmethod
    def _fail(label: str, *, error: str = "", method: str = "container") -> dict:
        return {
            "poc_compile": False,
            "poc_triggers_bug": None,
            "fuzz_confirms": None,
            "counterexample": None,
            "ground_truth_confidence": 0.0,
            "error": f"{label}: {error}" if error else label,
            "poc_method": method,
        }


def _first_signature(output: str) -> str | None:
    for sig in _SANITIZER_SIGNATURES:
        i = output.find(sig)
        if i >= 0:
            return output[i:i + 160].splitlines()[0]
    return None


def _looks_like_build_failure(output: str, returncode: int) -> bool:
    """Heuristic: a compiler/linker error before the program ever ran.
    Conservative — only fires on clear compiler diagnostics so a runtime
    sanitizer abort (which also yields non-zero) is NOT mistaken for a
    build failure."""
    low = output.lower()
    compile_markers = (
        "error:", "fatal error", "cannot find", "undefined reference",
        "no such file", "expected ", "use of undeclared",
        "cannot borrow", "mismatched types", "syntaxerror",
        "modulenotfounderror", "cannot open source file",
    )
    runtime_markers = _SANITIZER_SIGNATURES
    # If a sanitizer/runtime fault is present, the program DID run → not a
    # build failure even if a compiler-ish word appears in the trace.
    if any(sig in output for sig in runtime_markers):
        return False
    return returncode != 0 and any(m in low for m in compile_markers)


__all__ = ["PocSandbox", "SandboxConfig"]
