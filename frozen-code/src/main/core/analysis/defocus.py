"""Defocus scoring for cluster-mode Layer 3 retry ladder.

The job: given a batched cluster verdict from the local LLM, decide
whether to ACCEPT it or DEGRADE to a smaller cluster / per-finding
re-run. Single-scalar defocus is fragile (one threshold can't cover
JSON-parse failure + soft attention falloff + model self-doubt at
once), so we split into:

  * **Hard signals** — any one triggers immediate degrade, with an
    attribution string. These represent "model knows it failed" or
    "model output is structurally broken" — equal-weighting them with
    soft heuristics loses information.

  * **Soft signals** — heuristic attention/confidence anomalies. Each
    on its own is noisy; require ≥2 to fire before degrading so a
    single stochastic blip doesn't waste a retry.

  * **Observation log** — every signal that fired is returned in the
    decision, so the JSONL triage log can post-hoc analyse which
    signals correlate with real downstream errors. We don't have
    ground truth yet to calibrate thresholds; treating thresholds as
    initial guesses + logging everything = data we can tune from
    after a week of production.

Confident-wrong (model uniformly high-confidence but actually
incorrect) is a real failure mode that none of these signals catch.
Mitigations exist (cross-cluster consistency vote, ground-truth
anchors) but they double the call cost — out of scope here.
"""
from __future__ import annotations

import math
import os
import statistics
from dataclasses import dataclass
from typing import Any


# --------------------------------------------------------------------------- #
# Thresholds — env-overridable, initial values are guesses pending data       #
# --------------------------------------------------------------------------- #

def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


# Hard thresholds — if breached, degrade immediately
HARD_CONF_FLOOR        = _env_float("AISEC_DEFOCUS_CONF_FLOOR", 0.20)
HARD_SELF_RATING_FLOOR = _env_int("AISEC_DEFOCUS_SELF_FLOOR", 3)

# Soft thresholds — need at least N to fire
SOFT_LOW_CONF          = _env_float("AISEC_DEFOCUS_SOFT_CONF", 0.40)
SOFT_STDEV             = _env_float("AISEC_DEFOCUS_SOFT_STDEV", 0.30)
SOFT_FRONT_BACK_DROP   = _env_float("AISEC_DEFOCUS_SOFT_FB_DROP", 0.20)
SOFT_SELF_RATING       = _env_int("AISEC_DEFOCUS_SOFT_SELF", 5)
SOFT_TRIGGER_COUNT     = _env_int("AISEC_DEFOCUS_SOFT_COUNT", 2)


# --------------------------------------------------------------------------- #
# Result type                                                                 #
# --------------------------------------------------------------------------- #

@dataclass
class DefocusDecision:
    degrade: bool
    reason: str                          # primary attribution
    signals: list[tuple[str, float]]     # every signal that fired (name, value)

    def as_log_dict(self) -> dict[str, Any]:
        return {
            "defocus_degrade": self.degrade,
            "defocus_reason": self.reason,
            "defocus_signals": [
                {"name": name, "value": value} for name, value in self.signals
            ],
        }


# --------------------------------------------------------------------------- #
# Decision                                                                    #
# --------------------------------------------------------------------------- #

def decide(
    *,
    parsed: list | None,
    expected_count: int,
    confidences: list[float],
    self_rating: int | None = None,
) -> DefocusDecision:
    """Return ACCEPT/DEGRADE plus full signal trace.

    Args:
        parsed:         The per-finding verdict list parsed from the LLM
                        output, or None if JSON parse failed.
        expected_count: How many findings we expected back.
        confidences:    Per-finding confidence values from the LLM
                        (0.0–1.0).
        self_rating:    Optional 1-10 self-rating field if the cluster
                        prompt asked for one. None if not collected.
    """
    fired: list[tuple[str, float]] = []

    # ── Hard signals — any one triggers immediate degrade ────────────────
    if parsed is None:
        fired.append(("json_parse_failed", 1.0))
        return DefocusDecision(True, "json_parse_failed", fired)

    if len(parsed) < expected_count:
        deficit = expected_count - len(parsed)
        fired.append(("count_mismatch", float(deficit)))
        return DefocusDecision(
            True, f"count_mismatch_short_by_{deficit}", fired,
        )

    if self_rating is not None and self_rating <= HARD_SELF_RATING_FLOOR:
        fired.append(("self_rating_floor", float(self_rating)))
        return DefocusDecision(
            True, f"model_self_low_rating_{self_rating}", fired,
        )

    if confidences and min(confidences) < HARD_CONF_FLOOR:
        fired.append(("conf_floor_breach", float(min(confidences))))
        return DefocusDecision(
            True, f"conf_floor_min={min(confidences):.2f}", fired,
        )

    # ── Soft signals — accumulate, need ≥ SOFT_TRIGGER_COUNT to degrade ──
    if confidences and min(confidences) < SOFT_LOW_CONF:
        fired.append(("low_min_conf", float(min(confidences))))

    if len(confidences) >= 2:
        sd = statistics.stdev(confidences)
        if sd > SOFT_STDEV:
            fired.append(("high_variance", sd))

    if len(confidences) >= 4:
        half = len(confidences) // 2
        front = statistics.mean(confidences[:half])
        back = statistics.mean(confidences[half:])
        drop = front - back
        if drop > SOFT_FRONT_BACK_DROP:
            fired.append(("attention_falloff", drop))

    if self_rating is not None and self_rating <= SOFT_SELF_RATING:
        # Hard floor already returned above; this is the borderline band.
        fired.append(("self_rating_borderline", float(self_rating)))

    soft_count = sum(
        1 for name, _ in fired
        if name in {
            "low_min_conf", "high_variance",
            "attention_falloff", "self_rating_borderline",
        }
    )

    if soft_count >= SOFT_TRIGGER_COUNT:
        return DefocusDecision(
            True, f"soft_signals_{soft_count}", fired,
        )

    return DefocusDecision(False, "passed", fired)


# --------------------------------------------------------------------------- #
# Helpers for callers                                                         #
# --------------------------------------------------------------------------- #

def safe_confidences(per_finding: list[dict]) -> list[float]:
    """Extract a clean list[float] from a list of dicts that may have
    missing / non-numeric ``confidence`` keys. Returns empty list if
    nothing usable."""
    out: list[float] = []
    for item in per_finding:
        if not isinstance(item, dict):
            continue
        raw = item.get("confidence", item.get("conf"))
        if raw is None:
            continue
        try:
            v = float(raw)
        except (TypeError, ValueError):
            continue
        if not math.isfinite(v):
            continue
        out.append(max(0.0, min(1.0, v)))
    return out
