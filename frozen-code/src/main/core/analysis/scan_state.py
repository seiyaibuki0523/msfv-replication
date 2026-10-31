"""
ScanState — persistent checkpoint for a single scan session.

Both whitebox (source code) and blackbox (URL/IP) modes share the same
state file so a session can be interrupted and resumed at any phase.
"""

import json
import os
import datetime
import hashlib
from dataclasses import dataclass, field, asdict


@dataclass
class ScanState:
    """Full lifecycle state of a scan task, persisted after every phase."""

    # Identity
    target_id: str
    mode: str = "whitebox"          # "whitebox" | "blackbox" | "full"
    created_at: str = ""
    updated_at: str = ""
    current_phase: str = "init"     # tracks which phase to resume from

    # ------------------------------------------------------------------
    # Whitebox state (source code analysis)
    # ------------------------------------------------------------------
    file_hashes: dict = field(default_factory=dict)         # path → sha256 (skip unchanged)
    selected_files: list = field(default_factory=list)      # Layer 0 output
    global_map: dict = field(default_factory=dict)          # Layer 1 output
    semgrep_results: list = field(default_factory=list)     # Layer 2 output
    filtered_findings: list = field(default_factory=list)   # Layer 3 output
    pending_findings: list = field(default_factory=list)    # Layer 4 queue
    opus_results: list = field(default_factory=list)        # Layer 4+5 results
    global_queries_done: list = field(default_factory=list) # Layer 5 completed queries

    # ------------------------------------------------------------------
    # Blackbox state (pentest / bounty)
    # ------------------------------------------------------------------
    waf_profile: dict = field(default_factory=dict)
    recon_data: dict = field(default_factory=dict)          # structured recon JSON
    scan_results: dict = field(default_factory=dict)
    attack_queue: list = field(default_factory=list)
    attack_history: list = field(default_factory=list)
    confirmed_vulns: list = field(default_factory=list)

    # ------------------------------------------------------------------
    # Cost tracking
    # ------------------------------------------------------------------
    total_opus_input_tokens: int = 0
    total_opus_output_tokens: int = 0
    total_cost_usd: float = 0.0

    # ------------------------------------------------------------------
    # Round counters — per-layer LLM call counts for cost forensics and
    # pricing calibration. Each counter increments only on a successful
    # API call (cache hits and placeholder-dropped responses do NOT
    # count, so this measures real Opus billing pressure, not just
    # invocation count).
    # ------------------------------------------------------------------
    layer4_call_count: int = 0     # deep analysis per-finding
    layer4_cache_hits: int = 0     # served from result cache (no API call)
    layer5_call_count: int = 0     # global pattern queries (typically 4)
    layer5_cache_hits: int = 0
    layer55_call_count: int = 0    # verify-against-source calls
    layer55_cache_hits: int = 0    # (Layer 5.5 currently uncached; reserved)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _state_dir() -> str:
        from core.config import settings
        return os.path.join(settings.WORKSPACE, "state")

    def save(self, state_dir: str | None = None) -> None:
        state_dir = state_dir or self._state_dir()
        os.makedirs(state_dir, exist_ok=True)
        self.updated_at = datetime.datetime.now().isoformat()
        path = os.path.join(state_dir, f"{self.target_id}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, target_id: str, state_dir: str | None = None) -> "ScanState":
        """Load from disk; create a fresh state if no checkpoint exists."""
        state_dir = state_dir or cls._state_dir()
        path = os.path.join(state_dir, f"{target_id}.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return cls(**data)
        return cls(
            target_id=target_id,
            created_at=datetime.datetime.now().isoformat(),
        )

    @classmethod
    def delete(cls, target_id: str, state_dir: str = ".aisec_state") -> None:
        path = os.path.join(state_dir, f"{target_id}.json")
        if os.path.exists(path):
            os.remove(path)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def cost_ntd(self) -> float:
        return self.total_cost_usd * 32

    def file_changed(self, path: str, content: bytes) -> bool:
        """Return True if the file has changed since last scan."""
        h = hashlib.sha256(content).hexdigest()
        if self.file_hashes.get(path) != h:
            self.file_hashes[path] = h
            return True
        return False

    def track_opus_usage(
        self,
        input_tokens: int,
        output_tokens: int,
        model: str = "claude-opus-4-6",
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> None:
        """Record an LLM call. Forwards to the global :mod:`core.cost_tracker`
        and mirrors aggregated totals back onto this state for persistence.

        Cache token args are forwarded to the tracker so cached input is
        billed at 0.1× and cache-creation tokens at 1.25× (Anthropic's
        public prompt-cache pricing). Omitting them collapses to the
        pre-cache-aware behaviour.
        """
        from core.cost_tracker import tracker
        tracker.record(model, input_tokens, output_tokens,
                       cache_read_tokens, cache_write_tokens)
        self.total_opus_input_tokens  = tracker.total_input_tokens
        self.total_opus_output_tokens = tracker.total_output_tokens
        self.total_cost_usd           = tracker.total_cost_usd

    def status_line(self) -> str:
        return (
            f"Phase: {self.current_phase} | "
            f"Findings: {len(self.opus_results)} | "
            f"Vulns confirmed: {len(self.confirmed_vulns)} | "
            f"Calls: L4={self.layer4_call_count}"
            f"(+{self.layer4_cache_hits}c) "
            f"L5={self.layer5_call_count}"
            f"(+{self.layer5_cache_hits}c) "
            f"L5.5={self.layer55_call_count} | "
            f"Cost: ${self.total_cost_usd:.3f} (NT${self.cost_ntd:.1f})"
        )
